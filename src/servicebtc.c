/**
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * This file is part of pam_pico.
 *
 * pam_pico is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * pam_pico is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with pam_pico. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *
 * @brief Provides Bluetooth Classic event support to tie to FsmService
 * @section DESCRIPTION
 *
 * FSMService provides only a framework of callbacks and events, but without
 * any way of communicating. The communication channel has to be tied to it
 * to make it work. This code provides the implementation of the callbacks to
 * allow the state machine to work with a Bluetooth Classic channel in order
 * to actually support authentication.
 *
 * On top of this, it also controls the sending of Bluetooth beacons to other
 * devices to notify them that they can authenticate.
 *
 * The execution of this code is managed by AuthThread, while this code uses
 * BeaconThread to manage the sending of beacons and FsmService from libpico
 * to manage the authentication control flow.
 *
 */

/** \addtogroup Service
 *  @{
 */

#include "config.h"

#ifdef HAVE_LIBBLUETOOTH

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdbool.h>
#include <glib.h>
#include <gio/gio.h>
#include <errno.h>
#include <unistd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include "pico/pico.h"
#include "pico/log.h"
#include "pico/keypair.h"
#include "pico/fsmservice.h"
#include "pico/keyauth.h"
#include "pico/messagestatus.h"

#include "beaconthread.h"
#include "service.h"
#include "service_private.h"
#include "servicebtc.h"

// Defines

/**
 * @brief The maximum amount of data to read in a single Bluetooth read
 *
 * We create a buffer to read the data into, and this is the size the buffer
 * takes, so no more than this should be read at a time.
 *
 */
#define INPUT_SIZE_MAX	(1024)

/**
 * @brief The format to use for a Bluetooth device URI
 *
 * This is the format to use for a Bluetooth device URI. A string of this type
 * is added to the beacon to allow other devices to authenticate to the
 * service. It's essentially the MAC of the device formatted as a URI.
 *
 */
#define URL_FORMAT "btspp://%02X%02X%02X%02X%02X%02X:%02X"

// Structure definitions

/**
 * @brief Opaque structure used for authenticating using Bluetooth Classic
 *
 * This is a subclass of the Service struct, and inherits all members of
 * Service as well as adding some more Bluetooth-Classic-specific fields.
 *
 * This opaque data structure contains the persistent data associated with the
 * authentication process.
 *
 * The lifecycle of this data is managed by AuthThread.
 *
 */
typedef struct _ServiceBtc {
	// Inheret from Service
	Service service;

	// Extend with new fields
	GSocketConnection * connection;
	GSocketService * socketservice;
	char message[INPUT_SIZE_MAX];
	int channel;
} ServiceBtc;

// Function prototypes

static int servicebtc_start_listen(ServiceBtc * servicebtc);
static void report_error(GError ** error, char const * hint);
static gboolean servicebtc_incoming_connect (GSocketService * socketservice, GSocketConnection * connection, GObject * source_object, gpointer user_data);
static void servicebtc_beaconthread_finish(BeaconThread const * beaconthread, void * user_data);
static void servicebtc_write(char const * data, size_t length, void * user_data);
static void servicebtc_set_timeout(int timeout, void * user_data);
static void servicebtc_error(void * user_data);
static void servicebtc_disconnect(void * user_data);
static void servicebtc_authenticated(int status, void * user_data);
static void servicebtc_listen(void * user_data);
static void servicebtc_session_ended(void * user_data);
static void servicebtc_status_updated(int state, void * user_data);
static gboolean servicebtc_timeout(gpointer user_data);
static void servicebtc_read (GObject * source_object, GAsyncResult *res, gpointer user_data);
static bool servicebtc_stop_check(ServiceBtc * servicebtc);
static bool servicebtc_get_url(ServiceBtc const * servicebtc, Buffer * buffer);

// Function definitions

/**
 * Deal with errors by outputting them to the log, then freeing
 * and clearning the error structure.
 *
 * This is for internal use.
 *
 * @param error the error structure to check and report if it exists
 * @param hint a human-readable hint that will be output alongside the error
 */
static void report_error(GError ** error, char const * hint) {
	if (*error) {
		LOG(LOG_ERR, "Error %s: %n", hint, (*error)->message);
		g_error_free(*error);
		*error = NULL;
	}
}

/**
 * Create a new instance of the class, which inherits from Service.
 *
 * @return The newly created object.
 */
ServiceBtc * servicebtc_new() {
	ServiceBtc * servicebtc;

	servicebtc = CALLOC(sizeof(ServiceBtc), 1);

	// Initialise the base class
	service_init(&servicebtc->service);

	// Set up the virtual functions
	servicebtc->service.service_delete = (void*)servicebtc_delete;
	servicebtc->service.service_start = (void*)servicebtc_start;
	servicebtc->service.service_stop = (void*)servicebtc_stop;

	// Initialise the extra fields
	servicebtc->connection = NULL;
	servicebtc->socketservice = g_socket_service_new ();
	servicebtc->channel = 0;

	fsmservice_set_functions(servicebtc->service.fsmservice, servicebtc_write, servicebtc_set_timeout, servicebtc_error, servicebtc_listen, servicebtc_disconnect, servicebtc_authenticated, servicebtc_session_ended, servicebtc_status_updated);
	fsmservice_set_userdata(servicebtc->service.fsmservice, servicebtc);

	return servicebtc;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param auththread The object to free.
 */
void servicebtc_delete(ServiceBtc * servicebtc) {
	if (servicebtc != NULL) {
		service_deinit(&servicebtc->service);

		if (servicebtc->connection != NULL) {
			LOG(LOG_ERR, "Should not delete service while still connected");
		}
	}
}

/**
 * Get the URI of the Bluetooth device, to allow other devices to connect to
 * it. This URI is included in the advertising beacon and QR code.
 *
 * @param servicebtc The object to get the URI for.
 * @param buffer A buffer to store the resulting URI string in.
 */
static bool servicebtc_get_url(ServiceBtc const * servicebtc, Buffer * buffer) {
	bdaddr_t bdaddr;
	int dev_id;
	int result;
	bool success;

	success = FALSE;

	if (servicebtc->channel != 0) {
		dev_id = hci_get_route(NULL);
		result = hci_devba(dev_id, & bdaddr);

		if (result == 0) {
			// TODO: Don't add a port if we're using a UUID
			buffer_clear(buffer);
			buffer_sprintf(buffer, URL_FORMAT, bdaddr.b[5], bdaddr.b[4], bdaddr.b[3], bdaddr.b[2], bdaddr.b[1], bdaddr.b[0], servicebtc->channel);
			success = TRUE;
		}
	}

	return success;
}

/**
 * Start the service to allow Pico devices to authenticate to it. Starting opens
 * a Bluetooth port for listening on, then starts sending Bluetooth beacons out
 * to potential nearby Picos. If a Pico connects, authentication can then
 * proceed.
 *
 * Care is needed with the users parameter. If this is set to NULL, any
 * well-formed attempt to authenticate will succeed.
 *
 * @param servicebtc The object to use.
 * @param shared A Shared object that contains the keys needed for
          authentication.
 * @param users The users that are allowed to authenticate, or NULL to
          allow any user to authenticate.
 * @param extraData A buffer containing any extra data to be sent to the
 *        Pico during the authentication process.
 */
void servicebtc_start(ServiceBtc * servicebtc, Shared * shared, Users const * users, Buffer const * extraData) {
	KeyAuth * keyauth;
	Buffer * address;
	KeyPair * serviceIdentityKey;
	bool result;
	size_t size;

	// We can't start if we're mid-stop
	if (servicebtc->service.stopping == FALSE) {
		g_signal_connect(servicebtc->socketservice, "incoming", G_CALLBACK(servicebtc_incoming_connect), (gpointer)servicebtc);

		// Listen for incoming connections
		servicebtc->channel = servicebtc_start_listen(servicebtc);
		servicebtc_listen((void *)servicebtc);


		address = buffer_new(0);
		result = servicebtc_get_url(servicebtc, address);

		if (result) {
			// Get the service's long-term identity key pair
			serviceIdentityKey = shared_get_service_identity_key(shared);

			// SEND
			// Generate a visual QR code for Key Pairing
			// {"sn":"NAME","spk":"PUB-KEY","sig":"B64-SIG","ed":"","sa":"URL","td":{},"t":"KP"}
			keyauth = keyauth_new();
			keyauth_set(keyauth, address, "", NULL, serviceIdentityKey);

			size = keyauth_serialize_size(keyauth);
			servicebtc->service.beacon = CALLOC(sizeof(char), size + 1);
			keyauth_serialize(keyauth, servicebtc->service.beacon, size + 1);
			servicebtc->service.beacon[size] = 0;
			keyauth_delete(keyauth);

			// Prepare the QR code to be displayed to the user
			LOG(LOG_ERR, "Pam Pico Pre Prompt");
		}
		else {
			servicebtc->service.beacon = CALLOC(sizeof(char), strlen("ERROR") + 1);
			strcpy(servicebtc->service.beacon, "ERROR");
		}

		buffer_delete(address);

		if (servicebtc->service.beacons) {
			// Send Bluetooth beacons
			beaconthread_set_code(servicebtc->service.beaconthread, servicebtc->service.beacon);
			beaconthread_set_configdir(servicebtc->service.beaconthread, servicebtc->service.configdir);
			beaconthread_set_finished_callback(servicebtc->service.beaconthread, servicebtc_beaconthread_finish, servicebtc);

			LOG(LOG_INFO, "Starting beacons");
			beaconthread_start(servicebtc->service.beaconthread, users);
		}

		fsmservice_start(servicebtc->service.fsmservice, shared, users, extraData);
	}
}

/**
 * Request that the service stops whatever it's doing and finish off. Having
 * called this, the callback set using service_set_stop_callback() will be
 * called -- potentially after a period of time -- to signify that the Service
 * has indeed completed everything, tidies up, and is ready to be deleted.
 *
 * This call is asynchronous, hence the need for the callback.
 *
 * @param servicebtc The Service to stop.
 */
void servicebtc_stop(ServiceBtc * servicebtc) {
	BEACONTHREADSTATE state;

	// If we're already stopping, we shouldn't interrupt the process
	if (servicebtc->service.stopping == FALSE) {
		servicebtc->service.stopping = TRUE;

		// Update the state machine
		fsmservice_stop(servicebtc->service.fsmservice);
		// Stop sending out beacons
		// It may take some time for this to action, if there are already broadcasts in progress
		state = beaconthread_get_state(servicebtc->service.beaconthread);

		if ((state > BEACONTHREADSTATE_INVALID) && (state < BEACONTHREADSTATE_HARVESTABLE)) {
			beaconthread_stop(servicebtc->service.beaconthread);
		}

		// Stop accepting new connections
		g_socket_service_stop(servicebtc->socketservice);

		// Close all listening sockets on this service
		g_socket_listener_close(G_SOCKET_LISTENER(servicebtc->socketservice));

		// Disconnect any connected devices
		if (servicebtc->connection != NULL) {
			servicebtc_disconnect((void *)servicebtc);
		}

		servicebtc_stop_check(servicebtc);
	}
}

/**
 * This internal callback is used to determine when the beacons have finished
 * being sent.
 *
 * If both the beacons and any authentications have completed, this signifies
 * that the Service has completed all of its tasks (and so it becomes safe to
 * delete it).
 *
 * @param beaconthread The BeaconThread to monitor.
 * @param user_data The data that's sent with the callback, which is set to
 *        the Service data structure.
 */
static void servicebtc_beaconthread_finish(BeaconThread const * beaconthread, void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;
	
	LOG(LOG_INFO, "Beaconthread finished advertising");

	servicebtc_stop_check(servicebtc);
}

/**
 * The Service performs two main tasks: sending out beacons and manaaging
 * authentications. When a caller requests the service to finish, both of these
 * tasks must end gracefully before it safe to delete the service. This
 * internal function checks whether both have completed, and if so, calls the
 * callback to signify that the service has completed and it's safe to delete
 * it.
 *
 * @param servicebtc The Service to check completion of.
 * @return TRUE if the service has completed its tasks, FALSE o/w.
 */
static bool servicebtc_stop_check(ServiceBtc * servicebtc) {
	bool stopped;
	BEACONTHREADSTATE state;

	stopped = FALSE;
	state = beaconthread_get_state(servicebtc->service.beaconthread);

	if (servicebtc->service.stopping == TRUE) {
		// Ensure we're not connected to a device
		if (servicebtc->connection == NULL) {
			// Ensure we're not still advertising
			if ((state == BEACONTHREADSTATE_HARVESTABLE) || (state == BEACONTHREADSTATE_INVALID)) {
				// Clear any waiting timeout
				if (servicebtc->service.timeoutid != 0) {
					g_source_remove(servicebtc->service.timeoutid);
					servicebtc->service.timeoutid = 0;
				}

				// We're ready to stop
				if (servicebtc->service.stop_callback != NULL) {
					servicebtc->service.stop_callback(&servicebtc->service, servicebtc->service.stop_user_data);
				}
				LOG(LOG_INFO, "Full stop");
				servicebtc->service.stopping = FALSE;
				stopped = TRUE;
			}
		}
		else {
			LOG(LOG_INFO, "Stopping, but still connected");
		}
	}

	return stopped;
}

///////////////////////////////////////////

/**
 * Internal function provided to the FsmService to perform Bluetooth writes.
 *
 * @param data The data to write on the Bluetooth channel.
 * @param length The length of data to write.
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_write(char const * data, size_t length, void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;
	GOutputStream * output;
	gssize size_send;
	gssize size_sent;
	GError * error;
	Buffer * message;

	error = NULL;

	LOG(LOG_INFO, "Sending: %d bytes", length);

	// Get the output stream to write to
	output = g_io_stream_get_output_stream(G_IO_STREAM(servicebtc->connection));

	message = buffer_new(0);
	size_send = buffer_append_lengthprepend(message, data, length);

	size_sent = g_output_stream_write (output, buffer_get_buffer(message), buffer_get_pos(message), NULL, &error);
	if (size_sent != size_send) {
		LOG(LOG_DEBUG, "Wrote %lu for data size %lu\n", size_sent, size_send);
	}
	report_error(&error, "sending");

	buffer_delete(message);
}

/**
 * Internal function provided to the FsmService to request timeouts to be set.
 *
 * Any new timeout will override any previous timeout that has yet to trigger.
 * In other words, only one timeout (the latest) can be in operation at a time.
 *
 * @param timeout The time, in milliseconds, before the timeout should trigger.
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_set_timeout(int timeout, void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;

	LOG(LOG_DEBUG, "Requesting timeout of %d", timeout);

	// Remove any previous timeout
	if (servicebtc->service.timeoutid != 0) {
		g_source_remove(servicebtc->service.timeoutid);
		servicebtc->service.timeoutid = 0;
	}

	servicebtc->service.timeoutid = g_timeout_add(timeout, servicebtc_timeout, servicebtc);
}

/**
 * Internal function provided to the FsmService that will be called if a
 * state machine error occurs. For example, this may be triggered if the Pico
 * disconnects unexpectedly mid-authentication.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_error(void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;

	LOG(LOG_DEBUG, "Error");

	servicebtc_stop(servicebtc);
}

/**
 * Internal function provided to the FsmService to request the connected
 * Bluetooth device be disconnected.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_disconnect(void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;
	GSocket * gsocket;
	GError * error;
	FSMSERVICESTATE state;

	LOG(LOG_DEBUG, "Disconnect");
	error = NULL;

	if (servicebtc->connection) {
		gsocket = g_socket_connection_get_socket (G_SOCKET_CONNECTION(servicebtc->connection));
		g_socket_close (gsocket, & error);
		report_error(&error, "disconnecting");
		g_object_unref(servicebtc->connection);
		servicebtc->connection = NULL;

		g_socket_service_stop(servicebtc->socketservice);

		state = fsmservice_get_state(servicebtc->service.fsmservice);

		if ((state > FSMSERVICESTATE_INVALID) && (state < FSMSERVICESTATE_FIN)) {
			fsmservice_disconnected(servicebtc->service.fsmservice);
		}
	}
}

/**
 * Internal function provided to the FsmService to request that the service
 * listen for incoming Bluetooth connections.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_listen(void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;

	LOG(LOG_DEBUG, "Listen");

	g_socket_service_start(servicebtc->socketservice);
}

/**
 * Internal function provided to the FsmService that the state machine will
 * call to indicate the authentication completed.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_authenticated(int status, void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;

	LOG(LOG_DEBUG, "Authenticated");

	// If we're not continuously authentication, or authentication failed, we're done
	if (status != MESSAGESTATUS_OK_CONTINUE) {
		servicebtc_stop(servicebtc);
	}
}

/**
 * Internal function provided to the FsmService that will be called to indicate
 * that the continuous authentication session has ended. The most likely cause
 * is that the Pico disconnected.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_session_ended(void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;

	LOG(LOG_DEBUG, "Session ended");

	servicebtc_stop(servicebtc);
}

/**
 * Internal function provided to the FsmService that will be called every time
 * the FSM changes stage.
 *
 * @param state The new state that the FSM has just moved to.
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_status_updated(int state, void * user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;

	LOG(LOG_DEBUG, "Update, state: %d", state);

	if (servicebtc->service.update_callback != NULL) {
		servicebtc->service.update_callback(&servicebtc->service, state, servicebtc->service.update_user_data);
	}
}

///////////////////////////////////////////


/**
 * Internal callback triggered when a timeout, that will have been requested by
 * the FSM,.occurs. The action of this function should be to let the FSM know
 * that the timeout occured.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static gboolean servicebtc_timeout(gpointer user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;

	// This timeout fires only once
	servicebtc->service.timeoutid = 0;

	LOG(LOG_DEBUG, "Calling timeout");
	fsmservice_timeout(servicebtc->service.fsmservice);

	return FALSE;
}

/**
 * Internal callback triggered when there's available data to read on the
 * Bluetooth channel. The action of this function should be to pass the data
 * on to the FSM.
 *
 * @param source_object The object that data was read on (in this case a
 *        Bluetooth connction IO stream.
 * @param res The result of the read.
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicebtc_read(GObject * source_object, GAsyncResult *res, gpointer user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;
	int count;
	GError * error;
	GInputStream * input;

	LOG(LOG_DEBUG, "Incoming data");
	error = NULL;

	input = G_INPUT_STREAM (source_object);

	count = g_input_stream_read_finish(input, res, & error);
	report_error(&error, "reading message");

	if (count > 0) {
		LOG(LOG_DEBUG, "Read %d bytes", count);
		//printf("Message: %s\n", servicebtc->message + 4);

		//g_object_unref(G_SOCKET_CONNECTION (servicebtc->connection));

		fsmservice_read(servicebtc->service.fsmservice, servicebtc->message + 4, count - 4);

		g_input_stream_read_async (input, servicebtc->message, INPUT_SIZE_MAX, G_PRIORITY_DEFAULT, NULL, servicebtc_read, (gpointer)servicebtc);
	}
}

/**
 * Internal callback triggered when a device connects to the listening Bluetooth
 * channel. The action of this function should be to let the FSM know that a
 * connection has been made.
 *
 * @param socketservice The listening service.
 * @param connection The connection that's just been made.
 * @param source_object The object that requested to listen for incoming
 *        connections.
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static gboolean servicebtc_incoming_connect(GSocketService * socketservice, GSocketConnection * connection, GObject * source_object, gpointer user_data) {
	ServiceBtc * servicebtc = (ServiceBtc *)user_data;
	GInputStream * input;

	LOG(LOG_DEBUG, "Incoming connection");

	servicebtc->connection = g_object_ref(connection);
	fsmservice_connected(servicebtc->service.fsmservice);

	input = g_io_stream_get_input_stream(G_IO_STREAM(servicebtc->connection));

	g_input_stream_read_async (input, servicebtc->message, INPUT_SIZE_MAX, G_PRIORITY_DEFAULT, NULL, servicebtc_read, (gpointer)servicebtc);

	if (servicebtc->service.beacons) {
		beaconthread_stop(servicebtc->service.beaconthread);
	}

	return false;
}

/**
 * Internal function that sets up a channel to listen for incoming connections
 * on.
 *
 * @param servicebtc The service that should listen for incoming connections.
 */
static int servicebtc_start_listen(ServiceBtc * servicebtc) {
	int sock;
	GSocket * gsocket;
	bool result;
	GSocketAddress * address;
	GError * error;
	struct sockaddr_rc loc_addr = {0};
	int check;
	int channel;

	LOG(LOG_DEBUG, "Listen");
	error = NULL;

	sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

	LOG(LOG_DEBUG, "Create socket");
	gsocket = g_socket_new_from_fd (sock, &error);
	report_error(&error, "creating socket");

	// Bind the socket to the channel (port) from the SDP record
	loc_addr.rc_family = AF_BLUETOOTH;
	loc_addr.rc_bdaddr = *BDADDR_ANY;

	LOG(LOG_DEBUG, "Bind");
	result = FALSE;
	channel = 0;
	for (check = 1; (check < 32) && (result == FALSE); check++) {
		loc_addr.rc_channel = check;

		// Bind to the local channel
		address = g_socket_address_new_from_native(&loc_addr, sizeof(loc_addr));

		// Bind to the socket
		result = g_socket_bind (gsocket, address, false, NULL);
		if (result == TRUE) {
			channel = check;
		}

		g_object_unref(address);
	}
	LOG(LOG_DEBUG, "Binding to socket: %d", channel);

	if (result) {
		LOG(LOG_DEBUG, "Listen");
		result = g_socket_listen (gsocket, & error);
		report_error(&error, "listening");
	}

	if (result) {
		LOG(LOG_DEBUG, "Add");
		result = g_socket_listener_add_socket(G_SOCKET_LISTENER(servicebtc->socketservice), gsocket, NULL, & error);
		report_error(&error, "adding socket");
	}
	
	if (!result) {
		LOG(LOG_ERR, "Errors listening for connection");
	}

	return channel;
}

#endif // ifdef HAVE_LIBBLUETOOTH

/** @} addtogroup Service */

