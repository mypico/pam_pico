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
 * @brief Manages bundles of sessions needed for performing authentication
 * @section DESCRIPTION
 *
 * The pico-continuous service can handle multiple authentication sessions
 * running simultaneously. ProcessStore keeps track of all of these
 * sessions, ensuring any dbus messages that arrive are passed to the
 * correct session.
 *
 * Each authentication also requires the use of multiple simultaneous tasks:
 *  1. Initial authentication.
 *  2. Continuous authentication.
 *  3. Sending out Bluetooth beacons.
 *
 * In practice, these tasks are handled by the AuthThread object, so
 * ProcessStore only needs to handle the one object in order to keep track
 * of all this.
 *
 */

/** \addtogroup Service
 *  @{
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <grp.h>
#include <signal.h>
#include "pico/pico.h"
#include "pico/channel.h"
#include "pico/channel_bt.h"
#include "pico/shared.h"
#include "pico/keypair.h"
#include "pico/sigmaverifier.h"
#include "pico/cryptosupport.h"
#include "pico/continuous.h"
#include "pico/buffer.h"
#include "pico/auth.h"
#include "pico/messagepicoreauth.h"
#include "pico/messageservicereauth.h"
#include "pico/debug.h"
#include <picobt/bt.h>
#include <picobt/btmain.h>

#include "log.h"
#include "processstore.h"

// Defines

/**
 * @brief The command to call to lock the user's session
 *
 * There's no canonical way to lock a user's session. A common approach is
 * to send a dbus message to the desktop manager to trigger a lock. Given there
 * are different ways to do this, it's easiest to keep the command in a bash
 * script that can be called from this service.
 *
 * This define sets the command to use.
 */
#define LOCK_COMMAND "/usr/share/pam-pico/lock.sh"

/**
 * @brief The maximum number of simultaneous authentications suppported
 *
 * This define sets the maximum number of authentications which can be
 * simultaneously ongoing. Note that this includes continuous authentication
 * sessions, and this is a system-wide (rather than per-user) value, so the
 * number has to be adequaely large to cover all scenarios.
 *
 * Given that Bluetooth only supports up to 32 separate channels, there's not
 * much point in setting a number larger than 32.
 *
 */
#define MAX_SIMULTANEOUS_AUTHS (16)

// Structure definitions

typedef struct _ProcessItem ProcessItem;

/**
 * @brief Structure used to store data assocated with an individual sessions
 *
 * Each authentication requires an AuthThread object. This structure is used to
 * store this AuthThread in a linked list, which can also be referenced using
 * a handle.
 *
 * The lifecycle of this data is managed by ProcessStore.
 *
 */
struct _ProcessItem {
	ProcessItem * next;
	ProcessItem * prev;
	AuthThread * auththread;
	char * owner;
};

/**
 * @brief Structure used to manage multiple authentication sessions
 *
 * The ProcessStore stores all of these sessions in a sparse array combined 
 * with a linked list. This provides efficient direct access by handle (array
 * index), but also efficient iteration.
 *
 * Sessions that have completed are marked as such and harvested for
 * re-use each time a new session is added. Note that this requires a traversal
 * of all currently active sessions.
 *
 * The lifecycle of this data is managed by pico-continuous.
 *
 */
struct _ProcessStore {
	ProcessItem * first;
	ProcessItem * items[MAX_SIMULTANEOUS_AUTHS];
	int nextAvailable;
	GMainLoop * loop;
};

// Function prototypes

static void processstore_set_owner(ProcessStore * processstoredata, int handle, GDBusMethodInvocation * invocation);
static void processstore_stop_similar(ProcessStore * processstoredata, AuthThread const * auththread);

// Function definitions

/**
 * Create a new ProcessStore 'object'.
 *
 * @return the newly created data structure
 */
ProcessStore * processstore_new() {
	ProcessStore * processstoredata;
	int item;

	processstoredata = CALLOC(sizeof(ProcessStore), 1);
	processstoredata->first = NULL;
	for (item = 0; item < MAX_SIMULTANEOUS_AUTHS; item++) {
		processstoredata->items[item] = NULL;
	}
	processstoredata->nextAvailable = 0;
	
	return processstoredata;
}

/**
 * Delete a previously created ProcessStore object. The data associated
 * with the data structure and its contents will be freed.
 *
 * @param processstoredata the 'object' to free
 */
void processstore_delete(ProcessStore * processstoredata) {
	int item;

	if (processstoredata) {
		for (item = 0; item < processstoredata->nextAvailable; item++) {
			if (processstoredata->items[item] != NULL) {
				
				if (processstoredata->items[item]->auththread) {
					auththread_delete(processstoredata->items[item]->auththread);
					processstoredata->items[item]->auththread = NULL;
				}

				if (processstoredata->items[item]->owner) {
					FREE(processstoredata->items[item]->owner);
					processstoredata->items[item]->owner = NULL;
				}

				FREE(processstoredata->items[item]);
				processstoredata->items[item] = NULL;
			}
		}

		processstoredata->nextAvailable = 0;
		processstoredata->first = NULL;

		FREE(processstoredata);
	}
}

/**
 * Add a new session to the process store. This will set up the required
 * data structures and find a free handle to use if there is one.
 *
 * Before asigning a new handle, any completed processes will first be
 * harvested so they can be used again.
 *
 * @param processstoredata The object to store the new bundle in.
 * @return The handle of the new bundle if one is available, or -1 o/w.
 */
int processstore_add(ProcessStore * processstoredata) {
	int handle;
	ProcessItem * item;

	processstore_harvest(processstoredata);

	handle = processstoredata->nextAvailable;
	if (handle < MAX_SIMULTANEOUS_AUTHS) {
		LOG(LOG_INFO, "Creating thread with handle %d\n", handle);
		item = CALLOC(sizeof(ProcessItem), 1);
		item->auththread = auththread_new();
		auththread_set_handle(item->auththread, handle);
		item->owner = NULL;
		item->next = processstoredata->first;
		item->prev = NULL;
		if (item->next) {
			item->next->prev = item;
		}
		processstoredata->items[handle] = item;
		processstoredata->first = item;

		while ((processstoredata->nextAvailable < MAX_SIMULTANEOUS_AUTHS) && (processstoredata->items[processstoredata->nextAvailable])) {
			processstoredata->nextAvailable++;
		}
	}
	else {
		handle = -1;
		LOG(LOG_ERR, "Cannot create thread; pool of %d exhausted\n.", MAX_SIMULTANEOUS_AUTHS);
	}

	return handle;
}

/**
 * Remove a particular session from the store and free its resources.
 *
 * @param beaconthread The object to emove the bundle from.
 */
void processstore_remove(ProcessStore * processstoredata, int handle) {
	if ((handle >= 0) && (handle < MAX_SIMULTANEOUS_AUTHS)) {
		if (processstoredata->items[handle] != NULL) {
			if (processstoredata->first == processstoredata->items[handle]) {
				processstoredata->first = processstoredata->items[handle]->next;
			}
			if (processstoredata->items[handle]->next) {
				processstoredata->items[handle]->next->prev = processstoredata->items[handle]->prev;
			}
			if (processstoredata->items[handle]->prev) {
				processstoredata->items[handle]->prev->next = processstoredata->items[handle]->next;
			}

			if (processstoredata->items[handle]->auththread) {
				auththread_delete(processstoredata->items[handle]->auththread);
				processstoredata->items[handle]->auththread = NULL;
			}

			if (processstoredata->items[handle]->owner) {
				FREE(processstoredata->items[handle]->owner);
				processstoredata->items[handle]->owner = NULL;
			}

			FREE(processstoredata->items[handle]);
			processstoredata->items[handle] = NULL;
			if (handle < processstoredata->nextAvailable) {
				processstoredata->nextAvailable = handle;
			}
		}
	}
}

/**
 * Harvest any harvestable (completed) sessions and free up any resources
 * allocated to them, to allow the handles used by them to be re-used.
 *
 * @param processstoredata The object to harvest completed bundles from.
 */
void processstore_harvest(ProcessStore * processstoredata) {
	ProcessItem * item;
	ProcessItem * next;
	AUTHTHREADSTATE authstate;
	int handle;
	
	item = processstoredata->first;
	
	while (item != NULL) {
		next = item->next;
		authstate = auththread_get_state(item->auththread);

		if (authstate == AUTHTHREADSTATE_HARVESTABLE) {
			handle = auththread_get_handle(item->auththread);
			processstore_remove(processstoredata, handle);
		}
		item = next;
	}
}

/**
 * Get the AuthThread data for a session with a specified handle.
 *
 * @param processstoredata The object to get the AuthThread data from.
 * @param handle The handle of the session to get the AuthThread data for.
 * @return The AuthThread data for the requested session or NULL if the
 *         handle isn't currently allocaetd.
 */
AuthThread * processstore_get_auththread(ProcessStore * processstoredata, int handle) {
	AuthThread * auththread;

	auththread = NULL;
	if ((handle >= 0) && (handle < MAX_SIMULTANEOUS_AUTHS)) {
		if (processstoredata->items[handle] != NULL) {
			auththread = processstoredata->items[handle]->auththread;
		}
	}

	return auththread;
}

/**
 * Set the GMainLoop in use by the application (there can be only one). This
 * value is needed to send dbus messages and handle events.
 *
 * @param processstoredata The object to set the value of.
 * @param loop The GMainLoop value to set.
 */
void processstore_set_loop(ProcessStore * processstoredata, GMainLoop * loop) {
	processstoredata->loop = loop;
}

/**
 * Get the GMainLoop in use by the application (there can be only one). This
 * value is needed to send dbus messages and handle events.
 *
 * @param processstoredata The object to get the value from.
 * @return The GMainLoop value that was set previously.
 */
GMainLoop * processstore_get_loop(ProcessStore * processstoredata) {
	GMainLoop * loop;

	loop = processstoredata->loop;

	return loop;
}

/**
 * Set the owner's unique dbus name. The owner is the process that initiated
 * the authentication request via dbus. If the owner drops the request a
 * "NameOwnerChanged" signal will be sent, so that the authentication can be
 * terminated.
 *
 * @param processstoredata The object to get the owner name from.
 * @param handle The handle of the bundle to get the owner name for.
 * @param invocation The dbus invocation to get the owner name from.
 */
static void processstore_set_owner(ProcessStore * processstoredata, int handle, GDBusMethodInvocation * invocation) {
	char const * owner;
	GDBusMessage * message;
	size_t length;
	//char * owner_new;
	//char * owner_old;

	if ((handle >= 0) && (handle < MAX_SIMULTANEOUS_AUTHS)) {
		message = g_dbus_method_invocation_get_message(invocation);
		owner = g_dbus_message_get_sender(message);

		if (owner == NULL) {
			owner = "";
		}
		length = strlen(owner);

		if (processstoredata->items[handle] != NULL) {
			processstoredata->items[handle]->owner = REALLOC(processstoredata->items[handle]->owner, length + 1);
			strcpy(processstoredata->items[handle]->owner, owner);
		}
	}
}

/**
 * Lock the user's session.
 *
 * @param username the name of the user who's session should be locked
 */
void lock(char const * username) {
	Buffer * command;
	int result;
	
	command = buffer_new(0);
	
	buffer_append_string(command, LOCK_COMMAND);
	buffer_append_string(command, " ");
	buffer_append_string(command, username);
	buffer_append(command, "\0", 1);

	LOG(LOG_INFO, "Locking\n");
	buffer_print(command);
	result = system(buffer_get_buffer(command));
	LOG(LOG_INFO, "Lock script returned %d\n", result);

	buffer_delete(command);
}

/**
 * Start the process of authentication. This function is called in response to
 * a StartAuth dbus message being received. It sets up the authentication
 * (channels, threads, etc) and returns (via dbus) the code that should be
 * displayed to the user (as a QR code).
 *
 * The return value represents whether the authentication was set up correctly,
 * not whether authentication occurred, or was successful.
 *
 * @param processstoredata The object to store the associated thread bundle in.
 * @param object The object data needed to reply to the dbus message.
 * @param invocation The invocaion data needed to reply to the dbus message.
 * @param parameters The parameters to use for the authentication, in the form
 *        of a JSON dictionary.
 * @return TRUE if the authentication process was set up correctlt, FALSE o/w.
 */
bool start_auth(ProcessStore * processstoredata, PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, char const * username, char const * parameters) {
	bool result;
	int handle;
	AuthThread * auththread;
	gboolean success;
	gchar const * code = "";

	result = true;
	handle = processstore_add(processstoredata);

	if (handle < 0) {
		result = false;
		success = result;
		pico_uk_ac_cam_cl_pico_interface_complete_start_auth(object, invocation, handle, code, success);
	}

	if (result) {
		auththread = processstore_get_auththread(processstoredata, handle);
		result = auththread_config(auththread, parameters);
	}

	if (result) {
		auththread_set_object(auththread, object);
		auththread_set_invocation(auththread, invocation);
		auththread_set_username(auththread, username);
		auththread_set_loop(auththread, processstoredata->loop);

		LOG(LOG_INFO, "Starting authentication");

		auththread_start_auth(auththread);

		LOG(LOG_INFO, "Started authentication");

		// Stop any pre-existing AuthThreads with the same commitment and in a
		// continuously authenticating state
		processstore_stop_similar(processstoredata, auththread);
	}

	return result;
}

/**
 * Compare all existing running AuthThreads and compare their commitment
 * against the AuthThread just started. If there are any existing AuthThreads
 * that satisfy the following:
 *
 * 1. In a continuously authenticating state.
 * 2. Having the same commitment as the AuthThread just started.
 * 3. Authenticating the same user.
 * 4. Not the AuthThread being started.
 *
 * Then these existing AuthThreads will be requested to stop. The most likely
 * scenario for this to happen is that the user just locked their machine. In
 * this case, it doesn't make sense to keep the existing continuous session
 * running.
 *
 * @param processstoredata The object managing the thread bundle for the
 *        authentication.
 * @param auththread The AuthThread that was just started. This AuthThread
 *        takes precedence.
 */
static void processstore_stop_similar(ProcessStore * processstoredata, AuthThread const * auththread) {
	bool result;
	Buffer * commitment;
	Buffer * compare;
	ProcessItem * item;
	AUTHTHREADSTATE authstate;
	char const * user;
	char const * usercompare;

	// Get the commitment for the current AuthThread
	commitment = buffer_new(0);
	result = auththread_get_commitment(auththread, commitment);

	// Search through all of the existing AuthThreads and compare the commitment
	if (result == true) {
		user = auththread_get_username(auththread);
		compare = buffer_new(0);

		item = processstoredata->first;
		while (item != NULL) {
			authstate = auththread_get_state(item->auththread);

			result = false;
			if ((auththread != item->auththread) && (authstate == AUTHTHREADSTATE_CONTINUING)) {
				usercompare = auththread_get_username(item->auththread);
				result = (strcmp(user, usercompare) == 0);
			}

			if (result == true) {
				result = auththread_get_commitment(item->auththread, compare);
			}

			if (result == true) {
				result = buffer_equals(commitment, compare);
			}

			if (result == true) {
				// Stop the AuthThread; the new AuthThread takes priority
				LOG(LOG_INFO, "Already continuously authenticating with this service");
				auththread_stop(item->auththread);
			}

			item = item->next;
		}

		buffer_delete(compare);
	}

	buffer_delete(commitment);
}

/**
 * Complete the process of authentication. This function is called in response
 * to a CompleteAuth dbus message being received. It waits for a Pico app to
 * connect and then performs the authentication protocol with it.
 *
 * The return value represents whether the authentication was set up correctly,
 * not whether authentication occurred, or was successfuk.
 *
 * @param processstoredata The object managing the thread bundle for the
 *        authentication.
 * @param object The object data needed to reply to the dbus message.
 * @param invocation The invocaion data needed to reply to the dbus message.
 * @param handle The handle of the authentication bundle (for tieing together
 *        the StartAuth with the right CompleteAuth).
 * @return TRUE if the authentication process was established correctly, FALSE o/w.
 */
bool complete_auth(ProcessStore * processstoredata, PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, int handle) {
	bool result;
	AuthThread * auththread;
	AUTHTHREADSTATE state;
	gboolean success;
	gchar const * username;
	gchar const * password;

	result = true;

	if (handle >= 0) {
		// Set the owner name
		processstore_set_owner(processstoredata, handle, invocation);

		auththread = processstore_get_auththread(processstoredata, handle);

		if (auththread) {
			state = auththread_get_state(auththread);

			if (state >= AUTHTHREADSTATE_COMPLETED) {
				auththread_set_object(auththread, NULL);
				auththread_set_invocation(auththread, NULL);
				success = auththread_get_result(auththread);
				username = auththread_get_username(auththread);
				password = auththread_get_password(auththread);
				LOG(LOG_INFO, "Returning immediately with success %d\n", success);
				pico_uk_ac_cam_cl_pico_interface_complete_complete_auth(object, invocation, username, password, success);
			}
			else {
				auththread_set_object(auththread, object);
				auththread_set_invocation(auththread, invocation);
			}
		}
	}
	else {
		LOG(LOG_ERR, "Returning on error with success %d\n", false);
		result = false;
		pico_uk_ac_cam_cl_pico_interface_complete_complete_auth(object, invocation, "", "", false);
	}

	return result;
}

/**
 * When the dbus calling process loses interest (e.g. the process is killed
 * unexpectedly) a "NameOwnerChanged" signal is received. We use this as a
 * trigger to stop the authentication started by the calling process.
 *
 * This is particularly important if the notimeout flag is set on the
 * authentication, since otherwise it's liable to run forever in the
 * background, triggering unnecessary authentications.
 *
 * @param processstoredata The object managing the thread bundle for the
 *        authentication.
 * @param old_owner The named owner that owned the thread before losing
 *        interest..
 */
void processstore_owner_lost(ProcessStore * processstoredata, char const * old_owner) {
	ProcessItem * item;
	ProcessItem * next;

	if (old_owner != NULL) {
		item = processstoredata->first;

		while (item != NULL) {
			next = item->next;

			if ((item->owner != NULL) && (strcmp(item->owner, old_owner) == 0)) {
				LOG(LOG_DEBUG, "Owner %s lost", old_owner);
				// Trigger the autnetication to stop
				auththread_ownerlost(item->auththread);
			}
			item = next;
		}
	}
}


/** @} addtogroup Service */

