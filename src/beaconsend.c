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
 * @brief Send Bluetooth beacons out to a specific device
 * @section DESCRIPTION
 *
 * In order for a nearby Pico to know that there's a machine to log in to
 * there are one of two approaches. The first is for the user to scan a
 * QR code on the device using their Pico. The second is for the Pico to receive
 * a beacon from the device over a Bluetooth channel. This works for Bluetooth
 * because it's 'proximity'-based. That is, the beacon will only be received
 * if the two devices are near one another.
 *
 * This file provides support for contacting a specific device (specified
 * using a Bluetooth MAC) and sending it a beacon, which is a JSON string
 * containing enough information for the Pico to get in contact with the
 * device prior to authentication.
 *
 * This code is used by the beaconthread.c code, which provides support for
 * calling the beaconsend code for multiple devices.
 *
 * The operation of beaconsend is asynchronous and uses a GMainLoop in order to
 * operate using events.
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
#include <glib.h>
#include <gio/gio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "pico/pico.h"
#include "pico/debug.h"
#include "pico/buffer.h"

#include "log.h"
#include "beaconthread.h"
#include "beaconsend.h"

// Defines

/**
 * @brief Bluetooth service UUID to broadcast to potential authenticators
 *
 * This service UUID is used as the address for nearby Pico apps to connect to.
 *
 * It's equivalent to "ed995e5a-c7e7-4442-a6ee-7bb76df43b0d"
 *
 */
#define PICO_SERVICE_UUID 0xED, 0x99, 0x5E, 0x5A, 0xC7, 0xE7, 0x44, 0x42, 0xA6, 0xEE, 0x7B, 0xB7, 0x6D, 0xF4, 0x3B, 0x0D

/**
 * @brief Time in milliseconds between attemps to send the beacon
 *
 * Beacons are sent out on a timer, using this length of time between
 * messages sent. If a message is still being sent when the timer elapses
 * the send will be skipped until the next timeout occurs.
 *
 */
#define BEACONSEND_GAP (1000 * 2)

/**
 * @brief States that track the lifecycle of the BeaconSend event chain.
 *
 * The BeaconSend logic is managed as a series of asynchronous events. The
 * states track progress through the event cycle.
 *
 */
typedef enum _BEACONSENDSTATE {
	BEACONSENDSTATE_INVALID = -1,

	BEACONSENDSTATE_STARTING,
	BEACONSENDSTATE_READY,
	BEACONSENDSTATE_SENDING,
	BEACONSENDSTATE_STOPPING,
	BEACONSENDSTATE_STOPPED,

	BEACONSENDSTATE_NUM
} BEACONSENDSTATE;

// Structure definitions

/**
 * @brief Opaque structure used for managing the beacon send process
 *
 * The service can send out beacons via Bluetooth (if requested to by pico_pam)
 * inviting the user to authenticate.
 *
 * This opaque data structure contains the persistent data associated with an
 * event chain sending beacons to a single Bluetooth device.
 *
 * The lifecycle of this data is managed by BeaconThread.
 *
 */
struct _BeaconSend {
	uuid_t svc_uuid;
	bdaddr_t device;
	sdp_session_t * session;
	BEACONSENDSTATE state;
	int connections;
	Buffer * code;
	BeaconSendFinishCallback finish_callback;
	void * user_data;
};

// Function prototypes

static void report_error(GError ** error, char const * hint);
static void beaconsend_write_connect(GObject *connection, GAsyncResult *res, gpointer user_data);
static gboolean beaconsend_sdp_search(gpointer user_data);
static gboolean beaconsend_sdp_connect(GIOChannel * iochannel, GIOCondition condition, gpointer user_data);
static void beaconsend_finished(BeaconSend * beaconsend);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
BeaconSend * beaconsend_new() {
	BeaconSend * beaconsend;
	uint8_t svc_uuid_int[] = { PICO_SERVICE_UUID };

	beaconsend = CALLOC(sizeof(BeaconSend), 1);
	beaconsend->state = BEACONSENDSTATE_INVALID;
	beaconsend->connections = 0;
	sdp_uuid128_create(& beaconsend->svc_uuid, & svc_uuid_int);
	beaconsend->code = buffer_new(0);
	beaconsend->finish_callback = NULL;
	beaconsend->user_data = NULL;

	return beaconsend;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param beaconsend The object to free.
 */
void beaconsend_delete(BeaconSend * beaconsend) {
	if (beaconsend) {
		if (beaconsend->code) {
			buffer_delete(beaconsend->code);
			beaconsend->code = NULL;
		}

		FREE(beaconsend);
	}
}

/**
 * Set the device that beacons will be send to. this is in the form of a
 * string representation of the MAC address for the device in the format
 * XX:XX:XX:XX:XX:XX where XX represents a hexadecimal byte.
 *
 * @param beaconsend The object to set the device for.
 * @param device Textural representation of the MAC address of the device.
 */
bool beaconsend_set_device(BeaconSend * beaconsend, char const * const device) {
	int result;

	// Set up the device MAC
	result = str2ba(device, & beaconsend->device);

	return (result == 0);
}

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
		LOG(LOG_ERR, "Error %s: %s", hint, (*error)->message);
		g_error_free(*error);
		*error = NULL;
	}
}

/**
 * Event callback used as part of the beacon send process. A standard event
 * chain, in the case where the device can be successfully contacted, looks
 * like this:
 *
 * 1. beaconsend_sdp_search()
 * 2. beaconsend_sdp_connect()
 * 3. beaconsend_write_connect()
 *
 * This is the first event in the chain, triggering the initial SDP request.
 *
 * The chain may finish at any point, for example if the device can't be
 * contacted or an error occurs.
 *
 * The initial search is triggered by a periodic timer event which continues
 * until beaconsend_stop() is called from elsewhere (likely the same place that
 * kicked things off by calling beaconsend_start()).
 *
 * @param user_data Data sent to the callback, in this case a BeaconSend
 *        structure.
 */
static gboolean beaconsend_sdp_search(gpointer user_data) {
	BeaconSend * beaconsend = (BeaconSend *)user_data;
	int sdp_socket;
	uint32_t priority;
	GIOChannel * iochannel;

	priority = 1;
	if ((beaconsend->state == BEACONSENDSTATE_STARTING) || (beaconsend->state == BEACONSENDSTATE_READY)) {
		beaconsend->state = BEACONSENDSTATE_SENDING;

		// Connect to the SDP server
		beaconsend->session = sdp_connect(BDADDR_ANY, & beaconsend->device, SDP_NON_BLOCKING);
		if (beaconsend->session != NULL) {
			beaconsend->connections++;

			// Get the socket assocated with the session
			sdp_socket = sdp_get_socket(beaconsend->session);

			// Set the socket to low priority to avoid it interfering with other stuff
			setsockopt(sdp_socket, SOL_SOCKET, SO_PRIORITY, & priority, sizeof(priority));

			// Attach a watch to the socket
			iochannel = g_io_channel_unix_new(sdp_socket);
			g_io_add_watch(iochannel, G_IO_IN | G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL, beaconsend_sdp_connect, beaconsend);
			//g_io_channel_unref(iochannel);
		}
		else {
			LOG(LOG_INFO, "Failed to create session\n");
			beaconsend->state = BEACONSENDSTATE_READY;
		}
	}

	if ((beaconsend->connections == 0) && (beaconsend->state == BEACONSENDSTATE_STOPPING)) {
		beaconsend_finished(beaconsend);
	}

	return (beaconsend->state != BEACONSENDSTATE_STOPPED);
}

/**
 * Event callback used as part of the beacon send process. A standard event
 * chain, in the case where the device can be successfully contacted, looks
 * like this:
 *
 * 1. beaconsend_sdp_search()
 * 2. beaconsend_sdp_connect()
 * 3. beaconsend_write_connect()
 *
 * This is the second event in the chain, in response to a (hopefully)
 * successful SDP request. The event triggers a write to the service
 * identified.
 *
 * The chain may finish at any point, for example if the device can't be
 * contacted or an error occurs.
 *
 * The initial search is triggered by a periodic timer event which continues
 * until beaconsend_stop() is called from elsewhere (likely the same place that
 * kicked things off by calling beaconsend_start()).
 *
 * @param user_data Data sent to the callback, in this case a BeaconSend
 *        structure.
 */
static gboolean beaconsend_sdp_connect(GIOChannel * iochannel, GIOCondition condition, gpointer user_data) {
	BeaconSend * beaconsend = (BeaconSend *)user_data;
	sdp_list_t * search_list;
	sdp_list_t * attrid_list;
	sdp_list_t * response_list;
	sdp_list_t * response;
	sdp_record_t * record;
	sdp_list_t * proto_list;
	GSocket * gsocket;
	int sock;
	GError * error;
	GSocketConnection * connection;
	struct sockaddr_rc loc_addr = { 0 };
	GSocketAddress *address;
	int channel;
	int errornum;

	error = NULL;
	channel = -1;

	if ((beaconsend->state == BEACONSENDSTATE_SENDING) && ((condition & G_IO_ERR) == 0) && ((condition & G_IO_OUT) != 0)) {
		// Search for the relevant UUID
		search_list = sdp_list_append(NULL, & beaconsend->svc_uuid);
		uint32_t range = 0xffff;
		attrid_list = sdp_list_append(NULL, & range);

		// Get the list that matches the criteria
		response_list = NULL;
		sdp_service_search_attr_req(beaconsend->session, search_list, SDP_ATTR_REQ_RANGE, attrid_list, & response_list);
		response = response_list;

		// Check each service record and extract its channel (port)
		while (response != NULL) {
			record = (sdp_record_t*) response->data;
			// Extract the protocols
			errornum = sdp_get_access_protos(record, &proto_list);
			if (errornum == 0) {
				// Extract the channel
				channel = sdp_get_proto_port(proto_list, RFCOMM_UUID);
				sdp_list_free(proto_list, 0);
			}
			// Free up the record
			sdp_record_free(record);
			response = response->next;
		}
	}

	// Close the SDP connection
	beaconsend->connections--;

	if ((condition & G_IO_ERR) == 0) {
		g_io_channel_shutdown(iochannel, TRUE, NULL);
	}
	g_io_channel_unref(iochannel);
	sdp_close(beaconsend->session);

	//LOG(LOG_INFO, "Writing beacon to channel %d\n", channel);

	if (channel >= 0) {
		beaconsend->connections++;
		// Allocate socket
		sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

		// Convert to a connection glib can use
		gsocket = g_socket_new_from_fd(sock, &error);
		connection = g_socket_connection_factory_create_connection(gsocket);

		// Bind the socket to the channel (port) from the SDP record
		loc_addr.rc_family = AF_BLUETOOTH;
		loc_addr.rc_bdaddr = beaconsend->device;
		loc_addr.rc_channel = channel;

		// Connect to the remote device
		address = g_socket_address_new_from_native(&loc_addr, sizeof(loc_addr));

		// Connect asynchronously
		g_socket_connection_connect_async(connection, address, NULL, beaconsend_write_connect, beaconsend);

		g_object_unref(connection);
		g_object_unref(address);
	}
	else {
		if (beaconsend->state != BEACONSENDSTATE_STOPPING) {
			beaconsend->state = BEACONSENDSTATE_READY;
		}
	}

	return FALSE;
}

/**
 * Event callback used as part of the beacon send process. A standard event
 * chain, in the case where the device can be successfully contacted, looks
 * like this:
 *
 * 1. beaconsend_sdp_search()
 * 2. beaconsend_sdp_connect()
 * 3. beaconsend_write_connect()
 *
 * This is the third event in the chain, in response to a (hopefully)
 * successful socket write. This write represents the sending of the beacon.
 *
 * The chain may finish at any point, for example if the device can't be
 * contacted or an error occurs.
 *
 * The initial search is triggered by a periodic timer event which continues
 * until beaconsend_stop() is called from elsewhere (likely the same place that
 * kicked things off by calling beaconsend_start()).
 *
 * @param user_data Data sent to the callback, in this case a BeaconSend
 *        structure.
 */
static void beaconsend_write_connect(GObject *connection, GAsyncResult *res, gpointer user_data) {
	BeaconSend * beaconsend = (BeaconSend *)user_data;
	gboolean result;
	GError * error;
	GOutputStream * output;
	gssize size;
	GSocket * gsocket;
	char const * code;

	error = NULL;

	result = g_socket_connection_connect_finish(G_SOCKET_CONNECTION(connection), res, & error);
	report_error(&error, "connecting");

	if (result == TRUE) {
		// Get the output stream to write to
		output = g_io_stream_get_output_stream(G_IO_STREAM(connection));

		// Write the beacon to the remote device
		code = buffer_get_buffer(beaconsend->code);
		size = buffer_get_pos(beaconsend->code);

		size = g_output_stream_write (output, code, size, NULL, &error);
		report_error(&error, "writing");
		LOG(LOG_INFO, "Wrote beacon length %lu\n", size);

		g_io_stream_close(G_IO_STREAM(connection), NULL, &error);
		report_error(&error, "closing");

		gsocket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(connection));
		g_socket_close (gsocket,& error);
		report_error(&error, "closing");
	}
	else {
		LOG(LOG_ERR, "Failed to connect\n");
	}

	beaconsend->connections--;
	if (beaconsend->state != BEACONSENDSTATE_STOPPING) {
		beaconsend->state = BEACONSENDSTATE_READY;
	}
}

/**
 * Start the process of sending a beacon to a device.
 *
 * All steps in the process are asynchronous (non-blocking). A g_main_loop()
 * is used to handle the asynchronous events.
 *
 * @param beaconsend The data structure used to manage the event chain.
 */
void beaconsend_start(BeaconSend * beaconsend) {
	bool result;
	beaconsend->state = BEACONSENDSTATE_STARTING;

	result = beaconsend_sdp_search(beaconsend);

	if (result) {
		g_timeout_add (BEACONSEND_GAP, beaconsend_sdp_search, beaconsend);
	}
}

/**
 * Stop the process of sending a beacon to a device.
 *
 * All steps in the process are asynchronous (non-blocking). Consequently
 * this does not stop things immediately, as network message sends have to
 * complete, etc. Once everything has successfully completed, the
 * finish_callback will be called.
 *
 * @param beaconsend The data structure used to manage the event chain.
 */
void beaconsend_stop(BeaconSend * beaconsend) {
	if (beaconsend->state != BEACONSENDSTATE_STOPPED) {
		beaconsend->state = BEACONSENDSTATE_STOPPING;
	}
}

/**
 * Set the data sent out to other devices as a beacon.
 *
 * @param beaconsend The data structure used to manage the event chain.
 * @param code The string to use as the beacon.
 */
void beaconsend_set_code(BeaconSend * beaconsend, char const * code) {
	buffer_clear(beaconsend->code);
	buffer_append_string(beaconsend->code, code);
}

/**
 * Set the callback to be called when the BeaconSend event chain has
 * successfully completed. This will be triggered some time after
 * beaconsend_stop() has been called, once all of the remaining
 * events (e.g. Bluetooth write requests) have completed and it's safe to
 * delete the BeaconSend structure.
 *
 * @param beaconsend The data structure used to manage the event chain.
 * @param callback The function to call once all events have completed.
 * @param user_data A pointer to the user data to pass to the function on being
 *        called.
 */
void beaconsend_set_finished_callback(BeaconSend * beaconsend, BeaconSendFinishCallback callback, void * user_data) {
	beaconsend->finish_callback = callback;
	beaconsend->user_data = user_data;
}

/**
 * This internal function is called when the event chain has completed. Its
 * job is to call the finish_callback function.
 *
 * @param beaconsend The data structure used to manage the event chain.
 */
static void beaconsend_finished(BeaconSend * beaconsend) {
	beaconsend->state = BEACONSENDSTATE_STOPPED;
	if (beaconsend->finish_callback) {
		beaconsend->finish_callback(beaconsend, beaconsend->user_data);
	}
}

/** @} addtogroup Service */

