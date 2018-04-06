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
 * @brief Provides Bluetooth event support to tie to FsmService
 * @section DESCRIPTION
 *
 * FSMService provides only a framework of callbacks and events, but without
 * any way of communicating. The communication channel has to be tied to it
 * to make it work. This code provides the implementation of the callbacks to
 * allow the state machine to work with a Classic Bluetooth channel in order
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

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdbool.h>
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup.h>
#include <openssl/rand.h>
#include <errno.h>
#include <unistd.h>
#include "pico/pico.h"
#include "pico/log.h"
#include "pico/keypair.h"
#include "pico/fsmservice.h"
#include "pico/keyauth.h"
#include "pico/messagestatus.h"

#include "beaconthread.h"
#include "service.h"
#include "service_private.h"
#include "servicervp.h"

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
 * @brief The format to use for a Rendezvous Channel URI
 *
 * This is the format to use for a Rendezvous Point channel URI. A string of
 * this type is added to the QR code and/or beacon to allow other devices to
 * authenticate to the service. It's essentially the Rendezvous Point URL with
 * a random channel path added to the end.
 *
 * In practice, this URL will mostly be overwritten by a call to
 * servicervp_set_urlprefix().
 *
 */
#define URL_PREFIX "http://rendezvous.mypico.org/channel/"

/**
 * @brief The number of bytes to use for the random channel identifier
 *
 * A Rendezvous Point channel URL is made of the path to the Rendezvous
 * Point, with a random channel identifier added to the end. The identifier is
 * a hex representation of a random number. This define specifies the number
 * of random bytes this number should contain.
 *
 */
#define CHANNEL_NAME_BYTES 16

/**
 * @brief The duration to use for the wallclock connection timeout
 *
 * The duration, in microseconds (millionths), after which a connection will
 * be forcefully cancelled. The wall clock is used, so that if the computer
 * is suspended, the timer will continue to run.
 *
 */
#define DEFAULT_WALLCLOCK_TIMEOUT (45 * 1000000)

// Structure definitions

/**
 * @brief Opaque structure used for authenticating using the Rendezvous Point
 *
 * This is a subclass of the Service struct, and inherits all members of
 * Service as well as adding some more Rendezvous-Point-specific fields.
 *
 * This opaque data structure contains the persistent data associated with the
 * authentication process.
 *
 * The lifecycle of this data is managed by AuthThread.
 *
 */
typedef struct _ServiceRvp {
	// Inheret from Service
	Service service;

	// Extend with new fields
	char message[INPUT_SIZE_MAX];
	SoupSession * session;
	SoupMessage * msg;
	Buffer * urlprefix;
	Buffer * url;
	bool reading;
	bool writing;
	bool connected;
	guint wallclocktimerid;
	gint64 wallclockstart;
	gint64 wallclocktimeout;
	guint retryid;
	int connections;
} ServiceRvp;

// Function prototypes

static void servicervp_incoming_connect(ServiceRvp * servicervp);
static void servicervp_beaconthread_finish(BeaconThread const * beaconthread, void * user_data);
static void servicervp_write(char const * data, size_t length, void * user_data);
static void servicervp_set_timeout(int timeout, void * user_data);
static void servicervp_error(void * user_data);
static void servicervp_disconnect(void * user_data);
static void servicervp_authenticated(int status, void * user_data);
static void servicervp_listen(void * user_data);
static void servicervp_session_ended(void * user_data);
static void servicervp_status_updated(int state, void * user_data);
static gboolean servicervp_timeout(gpointer user_data);
static bool servicervp_stop_check(ServiceRvp * servicervp);
static bool servicervp_get_url(ServiceRvp const * servicervp, Buffer * buffer);

static void servicervp_write_complete(SoupSession * session, SoupMessage * msg, gpointer user_data);
static void servicervp_post(ServiceRvp * servicervp, Buffer const * data);
static void servicervp_read_complete(SoupSession * session, SoupMessage * msg, gpointer user_data);
static void servicervp_get(ServiceRvp * servicervp);

static void servicervp_wallclock_start(ServiceRvp * servicervp);
static void servicervp_wallclock_stop(ServiceRvp * servicervp);
static gboolean servicervp_wallclock_timeout(gpointer user_data);
static gboolean servicervp_retry_connection(gpointer user_data);

// Function definitions

/**
 * Create a new instance of the class, which inherits from Service.
 *
 * @return The newly created object.
 */
ServiceRvp * servicervp_new() {
	ServiceRvp * servicervp;

	servicervp = CALLOC(sizeof(ServiceRvp), 1);

	// Initialise the base class
	service_init(&servicervp->service);

	// Set up the virtual functions
	servicervp->service.service_delete = (void*)servicervp_delete;
	servicervp->service.service_start = (void*)servicervp_start;
	servicervp->service.service_stop = (void*)servicervp_stop;

	// Initialise the extra fields
	servicervp->session = soup_session_new_with_options(SOUP_SESSION_SSL_STRICT, TRUE, SOUP_SESSION_USER_AGENT, "Pico ", SOUP_SESSION_TIMEOUT, 60, NULL);
	servicervp->msg = NULL;
	servicervp->url = buffer_new(0);
	servicervp->urlprefix = buffer_new(0);
	buffer_append(servicervp->urlprefix, URL_PREFIX, sizeof(URL_PREFIX) - 1);
	servicervp->reading = FALSE;
	servicervp->writing = FALSE;
	servicervp->connected = FALSE;
	servicervp->wallclocktimerid = 0;
	servicervp->wallclockstart = 0;
	servicervp->wallclocktimeout = DEFAULT_WALLCLOCK_TIMEOUT;
	servicervp->connections = 0;
	servicervp->retryid = 0;

	fsmservice_set_functions(servicervp->service.fsmservice, servicervp_write, servicervp_set_timeout, servicervp_error, servicervp_listen, servicervp_disconnect, servicervp_authenticated, servicervp_session_ended, servicervp_status_updated);
	fsmservice_set_userdata(servicervp->service.fsmservice, servicervp);

	return servicervp;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param auththread The object to free.
 */
void servicervp_delete(ServiceRvp * servicervp) {
	if (servicervp != NULL) {
		service_deinit(&servicervp->service);

		if (servicervp->connected) {
			LOG(LOG_ERR, "Should not delete service while still connected");
		}

		if (servicervp->reading) {
			LOG(LOG_ERR, "Should not delete service while still reading");
		}

		if (servicervp->connections != 0) {
			LOG(LOG_ERR, "Should not delete service while connections are open (%d)", servicervp->connections);
		}

		if (servicervp->session) {
			soup_session_abort(servicervp->session);
			g_object_unref(servicervp->session);
			servicervp->session = NULL;
		}

		if (servicervp->url) {
			buffer_delete(servicervp->url);
			servicervp->url = NULL;
		}

		if (servicervp->urlprefix) {
			buffer_delete(servicervp->urlprefix);
			servicervp->urlprefix = NULL;
		}

		if (servicervp->wallclocktimerid != 0) {
			g_source_remove(servicervp->wallclocktimerid);
			servicervp->wallclocktimerid = 0;
		}

		if (servicervp->retryid != 0) {
			g_source_remove(servicervp->retryid);
			servicervp->retryid = 0;
		}
	}
}

/**
 * Get the URI of the Rendezvous Point channel, to allow other devices to
 * connect to it. This URI is included in the advertising beacon and QR code.
 *
 * @param service The object to get the URI for.
 * @param buffer A buffer to store the resulting URI string in.
 */
static bool servicervp_get_url(ServiceRvp const * servicervp, Buffer * buffer) {
	size_t size;
	bool success;

	success = FALSE;
	size = buffer_get_pos(servicervp->url);

	if (size > 0) {
		buffer_clear(buffer);
		buffer_append_buffer(buffer, servicervp->url);
		success = TRUE;
	}

	return success;
}

/**
 * Start the service to allow Pico devices to authenticate to it. Starting opens
 * a Rendezvous Point channel for listening on, then starts sending Bluetooth
 * beacons out to potential nearby Picos. If a Pico connects, authentication
 * can then proceed.
 *
 * Care is needed with the users parameter. If this is set to NULL, any
 * well-formed attempt to authenticate will succeed.
 *
 * @param servicervp The object to use.
 * @param shared A Shared object that contains the keys needed for
          authentication.
 * @param users The users that are allowed to authenticate, or NULL to
          allow any user to authenticate.
 * @param extraData A buffer containing any extra data to be sent to the
 *        Pico during the authentication process.
 */
void servicervp_start(ServiceRvp * servicervp, Shared * shared, Users const * users, Buffer const * extraData) {
	KeyAuth * keyauth;
	Buffer * address;
	KeyPair * serviceIdentityKey;
	bool result;
	size_t size;
	int res;
	unsigned char random[CHANNEL_NAME_BYTES];
	int count;
	char hexbyte[3];

	// We can't start if we're mid-stop
	if (servicervp->service.stopping == FALSE) {
		buffer_clear(servicervp->url);
		buffer_append_buffer(servicervp->url, servicervp->urlprefix);
		LOG(LOG_INFO, "Using Rendezvous Point")
		buffer_log(servicervp->url);

		res = RAND_bytes(random, CHANNEL_NAME_BYTES); 
		if (res) {
			for (count = 0; count < CHANNEL_NAME_BYTES; count++) {
				sprintf(hexbyte, "%02x", random[count]);
				buffer_append(servicervp->url, hexbyte, 2);
			}
		}

		// Listen for incoming connections
		servicervp_listen((void *)servicervp);

		address = buffer_new(0);
		result = servicervp_get_url(servicervp, address);

		if (result) {
			// Get the service's long-term identity key pair
			serviceIdentityKey = shared_get_service_identity_key(shared);

			// SEND
			// Generate a visual QR code for Key Pairing
			// {"sn":"NAME","spk":"PUB-KEY","sig":"B64-SIG","ed":"","sa":"URL","td":{},"t":"KP"}
			keyauth = keyauth_new();
			keyauth_set(keyauth, address, "", NULL, serviceIdentityKey);

			size = keyauth_serialize_size(keyauth);
			servicervp->service.beacon = CALLOC(sizeof(char), size + 1);
			keyauth_serialize(keyauth, servicervp->service.beacon, size + 1);
			servicervp->service.beacon[size] = 0;
			keyauth_delete(keyauth);

			// Prepare the QR code to be displayed to the user
			LOG(LOG_ERR, "Pam Pico Pre Prompt");
		}
		else {
			servicervp->service.beacon = CALLOC(sizeof(char), strlen("ERROR") + 1);
			strcpy(servicervp->service.beacon, "ERROR");
		}

		buffer_delete(address);

		if (servicervp->service.beacons) {
			// Send Bluetooth beacons
			beaconthread_set_code(servicervp->service.beaconthread, servicervp->service.beacon);
			beaconthread_set_configdir(servicervp->service.beaconthread, servicervp->service.configdir);
			beaconthread_set_finished_callback(servicervp->service.beaconthread, servicervp_beaconthread_finish, servicervp);

			LOG(LOG_INFO, "Starting beacons");
			beaconthread_start(servicervp->service.beaconthread, users);
		}

		fsmservice_start(servicervp->service.fsmservice, shared, users, extraData);
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
 * @param servicervp The Service to stop.
 */
void servicervp_stop(ServiceRvp * servicervp) {
	BEACONTHREADSTATE state;

	LOG(LOG_DEBUG, "Requesting stop");
	// If we're already stopping, we shouldn't interrupt the process
	if (servicervp->service.stopping == FALSE) {
		servicervp->service.stopping = TRUE;

		// Update the state machine
		fsmservice_stop(servicervp->service.fsmservice);
		// Stop sending out beacons
		// It may take some time for this to action, if there are already broadcasts in progress
		state = beaconthread_get_state(servicervp->service.beaconthread);

		if ((state > BEACONTHREADSTATE_INVALID) && (state < BEACONTHREADSTATE_HARVESTABLE)) {
			beaconthread_stop(servicervp->service.beaconthread);
		}

		// Stop the current connection
		// We only stop reads: if it's a write, we let it finish of its own accord
		if ((servicervp->msg != NULL) && (servicervp->reading)) {
			LOG(LOG_DEBUG, "Cancelling read");
			soup_session_cancel_message(servicervp->session, servicervp->msg, SOUP_STATUS_CANCELLED);
			servicervp->connected = FALSE;
		}
		servicervp_wallclock_stop(servicervp);
		servicervp_stop_check(servicervp);
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
static void servicervp_beaconthread_finish(BeaconThread const * beaconthread, void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	LOG(LOG_INFO, "Beaconthread finished advertising");

	servicervp_stop_check(servicervp);
}

/**
 * The Service performs two main tasks: sending out beacons and manaaging
 * authentications. When a caller requests the service to finish, both of these
 * tasks must end gracefully before it safe to delete the service. This
 * internal function checks whether both have completed, and if so, calls the
 * callback to signify that the service has completed and it's safe to delete
 * it.
 *
 * @param servicervp The Service to check completion of.
 * @return TRUE if the service has completed its tasks, FALSE o/w.
 */
static bool servicervp_stop_check(ServiceRvp * servicervp) {
	bool stopped;
	BEACONTHREADSTATE state;

	LOG(LOG_DEBUG, "Checking whether we're ready to stop");

	stopped = FALSE;
	state = beaconthread_get_state(servicervp->service.beaconthread);

	if (servicervp->service.stopping == TRUE) {
		// Ensure we're not connected to a device
		if ((servicervp->reading == FALSE) && (servicervp->writing == FALSE)) {
			if (servicervp->connections == 0) {
				// Ensure we're not still advertising
				if ((state == BEACONTHREADSTATE_HARVESTABLE) || (state == BEACONTHREADSTATE_INVALID)) {
					// Clear any waiting timeout
					if (servicervp->service.timeoutid != 0) {
						g_source_remove(servicervp->service.timeoutid);
						servicervp->service.timeoutid = 0;
					}

					// We're ready to stop
					if (servicervp->service.stop_callback != NULL) {
						servicervp->service.stop_callback(&servicervp->service, servicervp->service.stop_user_data);
					}
					LOG(LOG_INFO, "Full stop");
					servicervp->service.stopping = FALSE;
					stopped = TRUE;
				}
			}
			else {
				LOG(LOG_INFO, "Stopping, but connections still open (%d)", servicervp->connections);
			}
		}
		else {
			LOG(LOG_INFO, "Stopping, but still %s", (servicervp->reading ? "reading" : "writing"));
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
static void servicervp_write(char const * data, size_t length, void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;
	Buffer * message;

	LOG(LOG_INFO, "Sending: %d bytes", length);

	message = buffer_new(0);
	buffer_append_lengthprepend(message, data, length);

	// Perform POST request
	servicervp_post(servicervp, message);

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
static void servicervp_set_timeout(int timeout, void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	LOG(LOG_DEBUG, "Requesting timeout of %d", timeout);

	// Remove any previous timeout
	if (servicervp->service.timeoutid != 0) {
		g_source_remove(servicervp->service.timeoutid);
		servicervp->service.timeoutid = 0;
	}

	servicervp->service.timeoutid = g_timeout_add(timeout, servicervp_timeout, servicervp);
}

/**
 * Internal function provided to the FsmService that will be called if a
 * state machine error occurs. For example, this may be triggered if the Pico
 * disconnects unexpectedly mid-authentication.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicervp_error(void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	LOG(LOG_DEBUG, "Error");

	if (servicervp->msg) {
		LOG(LOG_DEBUG, "Cancelling read");
		soup_session_cancel_message(servicervp->session, servicervp->msg, SOUP_STATUS_CANCELLED);
		servicervp->connected = FALSE;
	}
	servicervp_wallclock_stop(servicervp);

	servicervp_stop(servicervp);
}

/**
 * Internal function provided to the FsmService to request the connected
 * Bluetooth device be disconnected.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicervp_disconnect(void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;
	
	LOG(LOG_DEBUG, "Disconnect");

	// Cancel any ongoing requests
	// We only stop reads: if it's a write, we let it finish of its own accord
	if ((servicervp->msg != NULL) && (servicervp->reading)) {
		soup_session_cancel_message(servicervp->session, servicervp->msg, SOUP_STATUS_CANCELLED);
	}
	servicervp_wallclock_stop(servicervp);

	servicervp->connected = FALSE;

	fsmservice_disconnected(servicervp->service.fsmservice);
}

/**
 * Internal function provided to the FsmService to request that the service
 * listen for incoming Bluetooth connections.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicervp_listen(void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	LOG(LOG_DEBUG, "Listen");

	servicervp_get(servicervp);
}

/**
 * Internal function provided to the FsmService that the state machine will
 * call to indicate the authentication completed.
 *
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicervp_authenticated(int status, void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	LOG(LOG_DEBUG, "Authenticated");

	// If we're not continuously authentication, or authentication failed, we're done
	if (status != MESSAGESTATUS_OK_CONTINUE) {
		servicervp_stop(servicervp);
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
static void servicervp_session_ended(void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	LOG(LOG_DEBUG, "Session ended");

	servicervp_stop(servicervp);
}

/**
 * Internal function provided to the FsmService that will be called every time
 * the FSM changes stage.
 *
 * @param state The new state that the FSM has just moved to.
 * @param user_data The user data, which in this case is the Service structure
 *        cast to (void *).
 */
static void servicervp_status_updated(int state, void * user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	LOG(LOG_DEBUG, "Update, state: %d", state);

	if (servicervp->service.update_callback != NULL) {
		servicervp->service.update_callback(&servicervp->service, state, servicervp->service.update_user_data);
	}
}

///////////////////////////////////////////


/**
 * Internal callback triggered when a timeout, that will have been requested by
 * the FSM,.occurs. The action of this function should be to let the FSM know
 * that the timeout occured.
 *
 * @param user_data The user data, which in this case is the ServiceRvp
 *        structure cast to (void *).
 */
static gboolean servicervp_timeout(gpointer user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;

	// This timeout fires only once
	servicervp->service.timeoutid = 0;

	LOG(LOG_DEBUG, "Calling timeout");
	fsmservice_timeout(servicervp->service.fsmservice);

	return FALSE;
}

/**
 * Internal callback triggered when there's available data to read on the
 * Rendezvous Point channel. The action of this function should be to pass the
 * data on to the FSM.
 *
 * @param session The Soup session object used to field the request..
 * @param msg The data received (e.g. hader and body of the HTTP request).
 * @param user_data The user data, which in this case is the ServiceRvp
 *        structure cast to (void *).
 */
static void servicervp_read_complete(SoupSession * session, SoupMessage * msg, gpointer user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;
	bool success;
	size_t length;
	char const * data;
	SoupMessage * msgalive;

	LOG(LOG_DEBUG, "Incoming data");

	LOG(LOG_DEBUG, "Status: %d\n", msg->status_code);

	servicervp_wallclock_stop(servicervp);

	servicervp->reading = FALSE;
	servicervp->connections--;
	msgalive = servicervp->msg;
	servicervp->msg = NULL;

	success = SOUP_STATUS_IS_SUCCESSFUL(msg->status_code);
	if (success) {
		length = msg->response_body->length;
		data = msg->response_body->data;

		if (length > 4) {
			if (data[0] == '{') {
				// Most likely the GET timed-out, to restart the GET
				LOG(LOG_DEBUG, data);
				servicervp_get(servicervp);
			}
			else {
				servicervp_incoming_connect(servicervp);

				LOG(LOG_DEBUG, "Read message size: %d\n", length);
				fsmservice_read(servicervp->service.fsmservice, data + 4, length - 4);
			}
		}
		else {
			// Dodgy response, so let's try again
			LOG(LOG_DEBUG, "Response too short; ignoring");
			servicervp_get(servicervp);
		}
	}
	else {
		switch (msg->status_code) {
		case SOUP_STATUS_IO_ERROR:
		case SOUP_STATUS_MALFORMED:
		case SOUP_STATUS_TRY_AGAIN:
			if (msgalive == msg) {
				LOG(LOG_ERR, "Error on read; retrying");
				servicervp_get(servicervp);
			}
			else {
				LOG(LOG_ERR, "Error on read; allow connection to die");
				servicervp_stop_check(servicervp);
			}
			break;
		case SOUP_STATUS_CANCELLED:
			LOG(LOG_ERR, "Cancelled read; checking stop status");
			servicervp_stop_check(servicervp);
			break;
		default:
			// Connection failed
			if (servicervp->retryid == 0) {
				LOG(LOG_ERR, "Connection failure on read: try again in a second");
				servicervp->retryid = g_timeout_add(1000.0, servicervp_retry_connection, servicervp);
			}
			break;
		}
	}
}

/**
 * Internal callback triggered when a device connects to the listening
 * Rendezvous Point channel. The action of this function should be to let the
 * FSM know that a connection has been made.
 *
 * @param servicervp The service that the connection arrived for.
 */
static void servicervp_incoming_connect(ServiceRvp * servicervp) {
	LOG(LOG_DEBUG, "Incoming connection");

	if (servicervp->connected == FALSE) {
		servicervp->connected = TRUE;
		fsmservice_connected(servicervp->service.fsmservice);

		if (servicervp->service.beacons) {
			beaconthread_stop(servicervp->service.beaconthread);
		}
	}
}

/**
 * Internal callback triggered when an HTTP POST request has completed. This
 * represents a successful write to the Pico that this service is connected
 * to. The action of this function should be to let the FSM know that a
 * connection has been made.
 *
 * @param session The Soup session object used to field the request..
 * @param msg The data received (e.g. hader and body of the HTTP request).
 * @param user_data The user data, which in this case is the ServiceRvp
 *        structure cast to (void *).
 */
static void servicervp_write_complete(SoupSession * session, SoupMessage * msg, gpointer user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;
	bool success;

	servicervp_wallclock_stop(servicervp);

	servicervp->writing = FALSE;
	servicervp->connections--;
	servicervp->msg = NULL;

	LOG(LOG_DEBUG, "Write status: %d", msg->status_code);

	success = SOUP_STATUS_IS_SUCCESSFUL(msg->status_code);
	if (success) {
		if (servicervp->connected) {
			servicervp_get(servicervp);
		}
		else {
			LOG(LOG_ERR, "Write requested while not connected");
		}
	}
	else {
		if (msg->status_code == SOUP_STATUS_CANCELLED) {
			servicervp_stop_check(servicervp);
		}
		else {
			// Connection failed
			LOG(LOG_ERR, "Connection failure on write");
			servicervp_stop(servicervp);
		}
	}
}

/**
 * Internal function used to make an HTTP (or HTTPS) POST request to the
 * Rendezvous Point. This is equivalent to a write from the Service to the
 * Pico.
 *
 * The write is asynchronous. Once completed the servicervp_write_complete()
 * function will be called to signify the result (e.g. success or failure).
 *
 * @param servicervp The service that should perform the write.
 * @param data A buffer containing the data to send.
 */
static void servicervp_post(ServiceRvp * servicervp, Buffer const * data) {
	char const * url;
	char const * send;
	size_t length;

	if ((servicervp->reading == FALSE) && (servicervp->writing == FALSE)) {
		servicervp->writing = TRUE;
		servicervp->connections++;
		url = buffer_get_buffer(servicervp->url);
		servicervp->msg = soup_message_new("POST", url);
		send = buffer_get_buffer(data);
		length = buffer_get_pos(data);
		LOG(LOG_DEBUG, "Sending message size: %d", length);

		soup_message_set_request(servicervp->msg, "application/octet-stream", SOUP_MEMORY_COPY, send, length);

		soup_session_queue_message(servicervp->session, servicervp->msg, servicervp_write_complete, servicervp);

		servicervp_wallclock_start(servicervp);
	}
	else {
		LOG(LOG_ERR, "Cannot send while a read or write is ongoing");
	}
}

/**
 * Internal function used to make an HTTP (or HTTPS) GET request to the
 * Rendezvous Point. This is equivalent to a read by the Service from the
 * Pico.
 *
 * The read is asynchronous. Once completed the servicervp_read_complete()
 * function will be called to signify the result (e.g. success or failure) so
 * that the data received can be acted upon.
 *
 * @param servicervp The service that should perform the read.
 */
static void servicervp_get(ServiceRvp * servicervp) {
	char const * url;

	if ((servicervp->reading == FALSE) && (servicervp->writing == FALSE)) {
		servicervp->reading = TRUE;	
		servicervp->connections++;
		url = buffer_get_buffer(servicervp->url);
		servicervp->msg = soup_message_new("GET", url);

		soup_session_queue_message(servicervp->session, servicervp->msg, servicervp_read_complete, servicervp);

		servicervp_wallclock_start(servicervp);
	}
	else {
		LOG(LOG_ERR, "Cannot receive while a read or write is ongoing");
	}
}

/**
 * Set the Rendezvous Point URL prefix. This should be set to
 * the full URL, including path, to use for the Rendezvous Point. The
 * randomly generated channel name will be appended to the end of this.
 *
 * For example, the standard URL is https://rendezvous.mypico.org/channel/
 * (note the trailing forward slash), which will create a channel along the
 * following lines.
 *
 * https://rendezvous.mypico.org/channel/6f4a12cb5a6f3e8974efab5c20900535
 *
 * @param servicervp The service to set the value for.
 * @param rvpurl The URL to use for the Rendezvous Point.
 *
 */
void servicervp_set_urlprefix(ServiceRvp * servicervp, char const * urlprefix) {
	buffer_clear(servicervp->urlprefix);
	buffer_append_string(servicervp->urlprefix, urlprefix);
}

/**
 * SoupSession connection timeouts use the monotoic timer, which freezes while
 * the computer is suspended. As a result, if the computer is suspended for
 * an extended period of time, the Rendezvous Point will forget the connection,
 * but SoupSession will continuue waiting for the remainder of the timeout.
 *
 * We use a one second timer, which keeps track of time using the wall clock.
 * When the timeout triggers, the connection is forcefully cancelled. As a
 * result, when the computer wakes from an extended suspend, it will cancel
 * the connection immediately.
 *
 * This function sets the timeout duration in microseconds (millionoths of
 * a second). The default value is DEFAULT_WALLCLOCK_TIMEOUT, set
 * to 45 seconds.
 *
 * @param servicervp The Service to set the value for.
 * @param wallclocktimeout The timeout duration in microseconds.
 */
void servicervp_set_wallclocktimeout(ServiceRvp * servicervp, gint64 wallclocktimeout) {
	servicervp->wallclocktimeout = wallclocktimeout;
}

/**
 * SoupSession connection timeouts use the monotoic timer, which freezes while
 * the computer is suspended. As a result, if the computer is suspended for
 * an extended period of time, the Rendezvous Point will forget the connection,
 * but SoupSession will continuue waiting for the remainder of the timeout.
 *
 * We use a one second timer, which keeps track of time using the wall clock.
 * When the timeout triggers, the connection is forcefully cancelled. As a
 * result, when the computer wakes from an extended suspend, it will cancel
 * the connection immediately.
 *
 * This function starts the timeout, or resets it if it's already runnding.
 *
 * @param servicervp The Service to use.
 */
static void servicervp_wallclock_start(ServiceRvp * servicervp) {
	LOG(LOG_DEBUG, "Starting wallclock timeout");

	if (servicervp->wallclocktimerid == 0) {
		// Tick every second
		servicervp->wallclocktimerid = g_timeout_add(1000.0, servicervp_wallclock_timeout, servicervp);
	}

	servicervp->wallclockstart = g_get_real_time();
}

/**
 * SoupSession connection timeouts use the monotoic timer, which freezes while
 * the computer is suspended. As a result, if the computer is suspended for
 * an extended period of time, the Rendezvous Point will forget the connection,
 * but SoupSession will continuue waiting for the remainder of the timeout.
 *
 * We use a one second timer, which keeps track of time using the wall clock.
 * When the timeout triggers, the connection is forcefully cancelled. As a
 * result, when the computer wakes from an extended suspend, it will cancel
 * the connection immediately.
 *
 * This function stops the timeout without cancelling the connection.
 *
 * @param servicervp The Service to use.
 */
static void servicervp_wallclock_stop(ServiceRvp * servicervp) {
	LOG(LOG_DEBUG, "Stopping wallclock timeout");

	if (servicervp->wallclocktimerid != 0) {
		g_source_remove(servicervp->wallclocktimerid);
		servicervp->wallclocktimerid = 0;
	}
}

/**
 * SoupSession connection timeouts use the monotoic timer, which freezes while
 * the computer is suspended. As a result, if the computer is suspended for
 * an extended period of time, the Rendezvous Point will forget the connection,
 * but SoupSession will continuue waiting for the remainder of the timeout.
 *
 * We use a one second timer, which keeps track of time using the wall clock.
 * When the timeout triggers, the connection is forcefully cancelled. As a
 * result, when the computer wakes from an extended suspend, it will cancel
 * the connection immediately.
 *
 * This callback function is called once per second and checks whether the
 * wallclock has reached the timeout. If it has, it cancels the connection.
 *
 * @param user_data The user data, which in this case is the ServiceRvp
 *        structure cast to (void *).
 */
static gboolean servicervp_wallclock_timeout(gpointer user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;
	gint64 timenow;
	gint64 ellapsed;
	bool more;

	timenow = g_get_real_time();
	ellapsed = timenow - servicervp->wallclockstart;
	more = TRUE;

	if (ellapsed >= servicervp->wallclocktimeout) {
		if (servicervp->msg != NULL) {
			LOG(LOG_INFO, "Wall clock timeout; cancelling request");
			soup_session_cancel_message(servicervp->session, servicervp->msg, SOUP_STATUS_IO_ERROR);
			servicervp->wallclocktimerid = 0;
			more = FALSE;

			if (servicervp->reading) {
				// Start a new GET immediately; we don't have time to wait for the previous one to finish and it's already dead
				servicervp->reading = FALSE;
				servicervp->msg = NULL;
				servicervp_get(servicervp);
			}
		}
	}

	return more;
}

/**
 * In the event a connection failes (e.g. resolver error), a timer is set to
 * retry the connection after 1 second of delay. This is the callback that's
 * fired after this delay.
 *
 * The callback will try to re-establish a connection, or check whether
 * it's time to stop in case the service is finishing.
 *
 * @param user_data The user data, which in this case is the ServiceRvp
 *        structure cast to (void *).
 */
static gboolean servicervp_retry_connection(gpointer user_data) {
	ServiceRvp * servicervp = (ServiceRvp *)user_data;
	servicervp->retryid = 0;

	if (servicervp->service.stopping == FALSE) {
		if (servicervp->msg == NULL) {
			LOG(LOG_ERR, "Retry connection");
			servicervp_get(servicervp);
		}
		else {
			LOG(LOG_ERR, "Don't retry connection after all");
			servicervp_stop_check(servicervp);
		}
	}
	else {
		servicervp_stop_check(servicervp);
	}

	return FALSE;
}

/** @} addtogroup Service */

