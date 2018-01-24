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
 * @brief Send Bluetooth beacons out to multiple device
 * @section DESCRIPTION
 *
 * In order for a nearby Pico to know that there's a machine to log in to
 * there are one of two approaches. The first is for the user to scan a
 * QR code on the device using their Pico. The second is for the Pico to receive
 * a beacon from the device over a Bluetooth channel. This works for Bluetooth
 * because it's 'proximity'-based. That is, the beacon will only be received
 * if the two devices are near one another.
 *
 * This file provides support for contacting a multiple device (specified
 * using a list of Bluetooth MACs) and sending periodic beacons to them all. A
 * beacon is a JSON string containing enough information for the Pico to get in
 * contact with the device prior to authentication.
 *
 * The actual transmission of beacons is handled by beaconsend.c, which this
 * code uses. Whereas beaconsend.c will only send to a single device, this
 * code manages multiple devices, using beaconsend.c to send to each.
 *
 * The operation of beaconthread is asynchronous and uses a GMainLoop in order 
 * to operate using events.
 *
 */

/** \addtogroup Service
 *  @{
 */

#include "config.h"

#include <stdio.h>
#include <malloc.h>
#include <syslog.h>
#include <picobt/bt.h>
#include <picobt/btmain.h>
#include "processstore.h"

#include "log.h"
#include "beaconsend.h"
#include "beaconthread.h"

// Defines


/**
 * @brief Maximum length of a Bluetooth MAC
 *
 * The MAC of each device to send beacons to is read in from file, each line
 * containing a single address. This is the maximum length of string that will
 * be read per line of the file.
 *
 * This assumes each MAC is represented as six two-digit hexadecimal numbers
 * separated by colons. Like this XX:XX:XX:XX:XX:XX where XX represents a
 * hexadecimal byte.
 *
 */
#define DEVICES_LINE_MAX (19)

// Structure definitions

typedef struct _Devices Devices;
typedef struct _Device Device;

/**
 * @brief Data assocated with a single device beacons are sent to
 *
 * This data structure is used to keep track of all data required by
 * BeaconSend in order to send beacons to a specific, individual device.
 * The actual event chain that sends the data is managed by the
 * BeaconSend structure contained inside.
 *
 * The data forms a single-direction linked list. In practice we only ever
 * want to cycle through the full list, so a single linked list is appropriate.
 * The list is created once when the details are loaded from file, then deleted
 * at the end, so management of the list requires minimal functionality.
 */
struct _Device {
	char * device;
	BeaconSend * beaconsend;
	Device * next;
};

/**
 * @brief A header for the linked list of Device data structures
 *
 * A header that points to the first Device data structure in the linked list.
 * The header also keeps track of the number of items in the linked list.
 *
 */
struct _Devices {
	Device * first;
	int num;
};

/**
 * @brief Opaque structure used for managing the beacon sending
 *
 * The service can send out beacons via Bluetooth (if requested to by pico_pam)
 * inviting the user to authenticate.
 *
 * This opaque data structure contains the persistent data associated with
 * beacon (potentially sent to multiple devices and over a period of time).
 * The associated functions should be used to access and manipulate the data.
 *
 * The lifecycle of this data is managed by AuthThread.
 *
 */
struct _BeaconThread {
	Buffer * code;
	BEACONTHREADSTATE state;
	Devices * devices;
	int running;
	BeaconThreadFinishCallback finish_callback;
	void * user_data;
	Buffer * configdir;
};

typedef struct _BeaconPool BeaconPool;

// Function prototypes

static void beaconthread_load_devices(BeaconThread * beaconthread, char const * filename);
static void beaconthread_finished(BeaconSend const * beaconsend, void * user_data);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
BeaconThread * beaconthread_new() {
	BeaconThread * beaconthread;

	beaconthread = CALLOC(sizeof(BeaconThread), 1);

	beaconthread->state = BEACONTHREADSTATE_INVALID;
	beaconthread->code = buffer_new(0);
	beaconthread->devices = CALLOC(sizeof(Devices), 1);
	beaconthread->devices->num = 0;
	beaconthread->devices->first = NULL;
	beaconthread->running = 0;
	beaconthread->finish_callback = NULL;
	beaconthread->user_data = NULL;
	beaconthread->configdir = buffer_new(0);

	return beaconthread;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param beaconthread The object to free.
 */
void beaconthread_delete(BeaconThread * beaconthread) {
	Device * current;
	Device * next;

	if (beaconthread) {
		if (beaconthread->code) {
			buffer_delete(beaconthread->code);
			beaconthread->code = NULL;
		}
		
		if (beaconthread->devices) {
			next = beaconthread->devices->first;
			while (next != NULL) {
				current = next;
				next = current->next;
				if (current->beaconsend) {
					beaconsend_delete(current->beaconsend);
					current->beaconsend = NULL;
				}

				FREE(current);
			}
			FREE(beaconthread->devices);
			beaconthread->devices = NULL;
		}

		if (beaconthread->configdir != NULL) {
			buffer_delete(beaconthread->configdir);
			beaconthread->configdir = NULL;
		}
		
		FREE(beaconthread);
	}
}

/**
 * Set the state for the current beacon thread. Possible values are defined by
 * the BEACONTHREADSTATE enum defined in beaconthread.h:
 *
 *  - BEACONTHREADSTATE_INVALID
 *  - BEACONTHREADSTATE_STARTED
 *  - BEACONTHREADSTATE_COMPLETED
 *  - BEACONTHREADSTATE_HARVESTABLE
 *
 * Setting the state to BEACONTHREADSTATE_COMPLETED will set the session on a 
 * path to gracefully finshing (although this may take a little bit of time).
 * The state will then automatically move to BEACONTHREADSTATE_HARVESTABLE and
 * the BeaconThread data structure will be harvested and marked for reuse by a
 * future beacon session.
 *
 * @param state The value to set the current state to.
 * @param beaconthread The object to set the state for.
 */
void beaconthread_set_state(BeaconThread * beaconthread, BEACONTHREADSTATE state) {
	beaconthread->state = state;
}

/**
 * Get the current state of the beacon thread. Possible values are defined by
 * the BEACONTHREADSTATE enum defined in beaconthread.h:
 *
 *  - BEACONTHREADSTATE_INVALID
 *  - BEACONTHREADSTATE_STARTED
 *  - BEACONTHREADSTATE_COMPLETED
 *  - BEACONTHREADSTATE_HARVESTABLE
 *
 * @param beaconthread The object to access the data from.
 * @return The current state of the thread.
 */
BEACONTHREADSTATE beaconthread_get_state(BeaconThread * beaconthread) {
	return beaconthread->state;
}

/**
 * Set the code that will be broadcast to potential authenticators. This should
 * be the same string that's displayed in the QR code.
 *
 * The string is copied and so the memory passed in can be safely freed or
 * reused after this call.
 *
 * @param beaconthread The object to set the code for.
 * @param code The invitation string to be broadcast.
 */
void beaconthread_set_code(BeaconThread * beaconthread, char const * code) {
	buffer_clear(beaconthread->code);
	buffer_append_string(beaconthread->code, code);
}

/**
 * Set the directory to read configuration files from.
 *
 * @param beaconthread The object to set the value for.
 * @param configdir The folder to set the config directory to.
 */
void beaconthread_set_configdir(BeaconThread * beaconthread, Buffer const * configdir) {
	buffer_clear(beaconthread->configdir);
	buffer_append_buffer(beaconthread->configdir, configdir);
}

/**
 * Load in a list of Bluetooth MACs from file. These are the addresses that
 * beacons will be sent to.
 *
 * MAC addresses are in the format XX:XX:XX:XX:XX:XX where XX represents a
 * hexadecimal byte. One MAC address per line.
 *
 * The resulting list of devices is stored in the beaconthread data structure.
 *
 * @param beaconthread The object to store the data in.
 * @param filename The file to read the addresses from.
 */
static void beaconthread_load_devices(BeaconThread * beaconthread, char const * filename) {
	FILE * input;
	char readLine[DEVICES_LINE_MAX + 1];
	char * start;
	bool more;
	Device * device;
	Device ** next;
	bool result;
	char const * code;

	input = fopen(filename, "r");
	if (input) {
		next = & beaconthread->devices->first;

		more = true;
		while (more) {
			more = false;
			start = fgets(readLine, DEVICES_LINE_MAX + 1, input);
			readLine[DEVICES_LINE_MAX - 2] = '\0';

			if (start != NULL) {
				if (readLine[0] != '#') {
					device = CALLOC(sizeof(Device), 1);
					*next = device;
					next = & device->next;

					device->device = MALLOC(DEVICES_LINE_MAX);
					strcpy(device->device, readLine);

					device->beaconsend = beaconsend_new();
					result = beaconsend_set_device(device->beaconsend, device->device);
					if (result == FALSE) {
						LOG(LOG_ERR, "Failed to set device: %s\n", device->device);
					}

					code = buffer_get_buffer(beaconthread->code);
					beaconsend_set_code(device->beaconsend, code);

					LOG(LOG_INFO, "Read: %s\n", device->device);
					beaconthread->devices->num++;
				}
				more = true;
			}
		}

		fclose(input);
	}
}

/**
 * Start the beacon session. This will create multiple instances of BeaconSend
 * for each device that beacons are sent to.
 *
 * This call will not block, but relies on a GMainLoop to be running for it
 * to operate correctly.
 *
 * @param beaconthread The object to use for the new session.
 */
void beaconthread_start(BeaconThread * beaconthread) {
	Device * current;
	Buffer * btlistfilename;

	btlistfilename = buffer_new(0);
	buffer_append_buffer(btlistfilename, beaconthread->configdir);
	buffer_append_string(btlistfilename, BT_LIST_FILE);

	beaconthread_load_devices(beaconthread, buffer_get_buffer(btlistfilename));

	buffer_delete(btlistfilename);

	beaconthread_set_state(beaconthread, BEACONTHREADSTATE_STARTED);

	LOG(LOG_INFO, "Sending beacons\n");

	current = beaconthread->devices->first;
	while (current != NULL) {
		if (current->beaconsend) {
			beaconthread->running++;
			beaconsend_set_finished_callback(current->beaconsend, beaconthread_finished, beaconthread);
			beaconsend_start(current->beaconsend);
		}
		current = current->next;
	}
}

/**
 * Places the beacon session into a BEACONTHREADSTATE_COMPLETED state. The
 * session will then take the next opportunity to gracefully finish, at which
 * point its status will be set as BEACONTHREADSTATE_HARVESTABLE.
 *
 * Once the session has moved into a BEACONTHREADSTATE_HARVESTABLE its resources
 * will be considered reusable by AuthThread.
 *
 * @param beaconthread The session to stop.
 */
void beaconthread_stop(BeaconThread * beaconthread) {
	Device * current;

	LOG(LOG_INFO, "Stopping beacon session\n");

	current = beaconthread->devices->first;
	while (current != NULL) {
		if (current->beaconsend) {
			beaconsend_stop(current->beaconsend);
		}
		current = current->next;
	}

	LOG(LOG_INFO, "Request stop while running: %d\n", beaconthread->running);
	beaconthread_set_state(beaconthread, BEACONTHREADSTATE_COMPLETED);

	if (beaconthread->running == 0) {
		beaconthread_set_state(beaconthread, BEACONTHREADSTATE_HARVESTABLE);
		if (beaconthread->finish_callback) {
			beaconthread->finish_callback(beaconthread, beaconthread->user_data);
		}
	}
}

/**
 * Having called beaconthread_stop(), a request is made for each sending
 * event chain to stop. If a message is mid-send this may take some time to
 * complete. This callback is used to track the finished event chains. Once
 * all chains have reached a finished state, the beaconthread will be marked
 * as harvestable, and finish_callback called if it's been set.
 *
 * Once the event chain has stopped its resourcs are automatically cleaned up
 * by ProcessStore when a new beaconthread is added.
 *
 * @param beaconsend The event chain associated with a specific device that
 *        just finished.
 * @param user_data A pointer to the user data parovided when registering the
 *        callback. In this case it will be the BeaconThread structure.
 */
static void beaconthread_finished(BeaconSend const * beaconsend, void * user_data) {
	BeaconThread * beaconthread = (BeaconThread *)user_data;

	beaconthread->running--;

	if (beaconthread->running == 0) {
		LOG(LOG_INFO, "Calling finish callback\n");
		beaconthread_set_state(beaconthread, BEACONTHREADSTATE_HARVESTABLE);
		if (beaconthread->finish_callback) {
			beaconthread->finish_callback(beaconthread, beaconthread->user_data);
		}
	}
}

/**
 * Set the callback to be called when the BeaconThread event chain has
 * successfully completed. This will be triggered some time after
 * beaconthread_stop() has been called, once all of the remaining
 * events (e.g. Bluetooth write requests) have completed and it's safe to
 * delete the BeaconThread structure.
 *
 * @param beaconthread The event chain that has completed.
 * @param callback The function to call once all events have completed.
 * @param user_data A pointer to the user data to pass to the function on being
 *        called.
 */
void beaconthread_set_finished_callback(BeaconThread * beaconthread, BeaconThreadFinishCallback callback, void * user_data) {
	beaconthread->finish_callback = callback;
	beaconthread->user_data = user_data;
}

/** @} addtogroup Service */


