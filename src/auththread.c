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
 * @brief Fuctionality for managing the authentication process
 * @section DESCRIPTION
 *
 * Each authentication is managed separately. This AuthThread structure
 * manages a single authentication, including the sending of beacons out to
 * potentially multiple nearby devices.
 *
 * Previously threads were used to support asynchronous operation, but this has
 * now been changed to an event-based process that utilises a GMainLoop.
 *
 * The authentication session is kicked off by calling auththread_start_auth().
 *
 * Each session is mortal, so will eventually complete of its own accord (either
 * as a result of an authentication attempt, a timeout, or the dbus owner
 * that kicked things off being lost). There is therefore usually no need to
 * stop a session forcefully.
 *
 * The lifetime of each AuthThread is managed by ProcessStore.
 *
 * Each AuthThread manages several other objects:
 *
 * 1. AuthConfig for handling the configuration of the authentication.
 * 2. BeaconThread for sending out beacons.
 * 3. Service for actually performing an authentication.
 *
 */

/** \addtogroup Service
 *  @{
 */

#include "config.h"

#include <stdio.h>
//#include <malloc.h>
#include <stdlib.h>
#include <syslog.h>
#include "pico/pico.h"
#include "pico/keyauth.h"
#include "processstore.h"
#include "pico/channel_bt.h"
#include "pico/sigmaverifier.h"
#include "pico/cryptosupport.h"

#include "log.h"
#include "service.h"
#include "servicebtc.h"
#include "servicervp.h"
#include "auththread.h"

// Defines

// Structure definitions

/**
 * @brief Opaque structure used for managing the authentication thread
 *
 * This opaque data structure contains the persistent data associated with each
 * session. The associated functions should be used to access and manipulate
 * the data.
 *
 * The lifecycle of this data is managed by ProcessStore.
 *
 */
struct _AuthThread {
	int handle;
	AuthConfig * authconfig;
	Buffer * username;
	Buffer * password;
	AUTHTHREADSTATE state;
	bool result;
	PicoUkAcCamClPicoInterface * object;
	GDBusMethodInvocation * invocation;

	// Private SharedState
	Shared * shared;
	Users * users;
	Users * filtered;

	Service * service;
	Buffer * extraData;
	GMainLoop * loop;
	guint timeoutid;
};

// Function prototypes

static bool auththread_setup(AuthThread * auththread);
static void authhtread_service_update(Service * service, int state, void * user_data);
static void auththread_service_stopped(Service * service, void * user_data);
static void auththread_complete_auth_reply(AuthThread * auththread, bool success);
static gboolean auththread_timeout(gpointer user_data);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
AuthThread * auththread_new() {
	AuthThread * auththread;

	auththread = CALLOC(sizeof(AuthThread), 1);

	auththread->handle = 0;
	auththread->authconfig = authconfig_new();
	auththread->state = AUTHTHREADSTATE_INVALID;
	auththread->result = false;
	auththread->username = buffer_new(0);
	auththread->password = buffer_new(0);

	buffer_clear(auththread->username);
	buffer_append_string(auththread->username, "Nobody");
	buffer_append(auththread->username, "\0", 1);

	auththread->object = NULL;

	auththread->shared = shared_new();
	auththread->users = users_new();
	auththread->filtered = users_new();

	// The service is now set up when auththread_start_auth() is called to allow the correct channeltype to be selected
	auththread->service = NULL;
	auththread->extraData = buffer_new(0);
	auththread->timeoutid = 0;

	return auththread;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param auththread The object to free.
 */
void auththread_delete(AuthThread * auththread) {
	if (auththread) {
		if (auththread->authconfig) {
			authconfig_delete(auththread->authconfig);
			auththread->authconfig = NULL;
		}

		if (auththread->username) {
			buffer_delete(auththread->username);
			auththread->username = NULL;
		}

		if (auththread->password) {
			buffer_delete(auththread->password);
			auththread->password = NULL;
		}

		if (auththread->shared) {
			shared_delete(auththread->shared);
			auththread->shared = NULL;
		}

		if (auththread->users) {
			users_delete(auththread->users);
			auththread->users = NULL;
		}

		if (auththread->filtered) {
			users_delete(auththread->filtered);
			auththread->filtered = NULL;
		}

		if (auththread->service) {
			service_delete(auththread->service);
			auththread->service = NULL;
		}

		if (auththread->extraData) {
			buffer_delete(auththread->extraData);
			auththread->extraData = NULL;
		}

		FREE(auththread);
	}
}

/**
 * Set the handle of this process. The handle is actually an index into the
 * array of ProcessItem structures stored by ProcessStore.
 *
 * @param auththread The object to access the data from.
 * @param The handle for the process.
 */
void auththread_set_handle(AuthThread * auththread, int handle) {
	auththread->handle = handle;
}

/**
 * Get the handle of this process. The handle is actually an index into the
 * array of ProcessItem structures stored by ProcessStore.
 *
 * @param auththread The object to access the data from.
 * @param The handle for the process.
 */
int auththread_get_handle(AuthThread * auththread) {
	return auththread->handle;
}

/**
 * Set the state for the auth session. See the AUTHTHREADSTATE enum in
 * auththread.h for details of the various states.
 *
 * @param auththread The object to access the data for.
 * @param state The state to set the thread to.
 */
void auththread_set_state(AuthThread * auththread, AUTHTHREADSTATE state) {
	auththread->state = state;
}

/**
 * Get the current state the session is in. See the AUTHTHREADSTATE enum in
 * auththread.h for details of the various states.
 *
 * @param auththread The object to access the data from.
 * @return The current state for the thread.
 */
AUTHTHREADSTATE auththread_get_state(AuthThread * auththread) {
	return auththread->state;
}

/**
 * Set the username for the session to authenticate to. The session can either
 * authenticate a specific user, or it can be configured to authenticate any
 * user. In the former case, if a user with different username tries to
 * authenticate, the authentication will be deemed to have failed. In the
 * latter case, the value of username is ignored and the authentication
 * process will return the name of the authenticated user.
 *
 * The string passed in will be copied, so it's safe to immediately free or
 * re-use the memory associated with the input parameter after this call.
 *
 * @param auththread The object to store the data in.
 * @param username The name of the user to authenticate, if the process is
 *        configured to only authenticate a specific user.
 */
void auththread_set_username(AuthThread * auththread, char const * username) {
	buffer_clear(auththread->username);
	buffer_append_string(auththread->username, username);
	buffer_append(auththread->username, "\0", 1);
}

/**
 * Get the username for the session to authenticate to. The session can either
 * authenticate a specific user, or it can be configured to authenticate any
 * user. In the former case, if a user with different username tries to
 * authenticate, the authentication will be deemed to have failed. In the
 * latter case, the value of username is ignored and the authentication
 * process will return the name of the authenticated user.
 *
 * The string returned is owned by AuthThread, so should not be freed or
 * altered by the caller.
 *
 * @param auththread The object to retrieve the data from.
 * @return The name of the user to authenticate, if the process is
 *         configured to only authenticate a specific user.
 */
char const * auththread_get_username(AuthThread const * auththread) {
	return buffer_get_buffer(auththread->username);
}

/**
 * Set the password to be stored with the session. This will have been
 * provided by the Pico app (in encrypted form) during the authentication
 * protocol. Sometimes this is needed by pico_pam to pass on to other PAMs.
 *
 * The string passed in will be copied, so it's safe to immediately free or
 * re-use the memory associated with the input parameter after this call.
 *
 * @param auththread The object to set the data for.
 * @param password The password to store.
 */
void auththread_set_password(AuthThread * auththread, char const * password) {
	buffer_clear(auththread->password);
	buffer_append_string(auththread->password, password);
	buffer_append(auththread->password, "\0", 1);
}

/**
 * Get the password provided by the Pico app. This password is stored by the
 * Pico app in encrypted form, but the service is able to decrypt it so that it
 * can be provided back to the PAM stack.
 *
 * The string returned is owned by AuthThread, so should not be freed or
 * altered by the caller.
 *
 * @param auththread The object to access the data from.
 * @return The password in plain text form.
 */
char const * auththread_get_password(AuthThread * auththread) {
	return buffer_get_buffer(auththread->password);
}

/**
 * Set the result of the authentication process. True if the authntication was
 * successful, false o/w.
 *
 * @param auththread The object to set the result for.
 * @param result The value to set. 
 */
void auththread_set_result(AuthThread * auththread, bool result) {
	auththread->result = result;
}

/**
 * Get the result of the authentication process. True if the authntication was
 * successful, false o/w.
 *
 * @param auththread The object to access the data from.
 * @return True if the authentication was successful, false o/w.
 */
bool auththread_get_result(AuthThread * auththread) {
	return auththread->result;
}

/**
 * Set the object for the call from pam_pico via dbus. This allows the service
 * to return a result for the same message at a later time.
 *
 * @param auththread The AuthThread object to set the data for.
 * @param object The object to set, as provided by GDbus.
 */
void auththread_set_object(AuthThread * auththread, PicoUkAcCamClPicoInterface * object) {
	auththread->object = object;
}

/**
 * Get the object for the call from pam_pico via dbus. This can be used to 
 * the result of the authentication back to pam_pico.
 *
 * If the result is NULL it means that pam_pico hasn't (yet) requested the
 * result, or that it's requsted it and it's been sent back already.
 *
 * @param auththread The AuthThread object to access the data from.
 * @return The object to use when replying to pam_pico, or NULL.
 */
PicoUkAcCamClPicoInterface * auththread_get_object(AuthThread * auththread) {
	return auththread->object;
}

/**
 * Set the invocation for the call from pam_pico via dbus. This allows the
 * service to return a result for the same message at a later time.
 *
 * @param auththread The AuthThread object to set the data for.
 * @param invocation The invocation to set, as provided by GDbus.
 */
void auththread_set_invocation(AuthThread * auththread, GDBusMethodInvocation * invocation) {
	auththread->invocation = invocation;
}

/**
 * Get the invocation for the call from pam_pico via dbus. This can be used to 
 * the result of the authentication back to pam_pico.
 *
 * If the result is NULL it means that pam_pico hasn't (yet) requested the
 * result, or that it's requsted it and it's been sent back already.
 *
 * @param auththread The AuthThread object to access the data from.
 * @return The invocation to use when replying to pam_pico, or NULL.
 */
GDBusMethodInvocation * auththread_get_invocation(AuthThread * auththread) {
	return auththread->invocation;
}

/**
 * Set the ownerlost status for the authentication. This is set to true when
 * the owner of the original dbus call that invoked the authentication drops
 * its request (for example, because the calling process has died).
 *
 * @param auththread The AuthThread object to set the data for.
 */
void auththread_ownerlost(AuthThread * auththread) {
	if (auththread->state < AUTHTHREADSTATE_COMPLETED) {
		if (auththread->service) {
			service_stop(auththread->service);
		}
	}
}

/**
 * Load the configuration from file, then overlay the configuration passed in
 * as a JSON string. The string is a configuration that's been passed in by
 * the dbus caller, and should override the configuration loaded from file.
 *
 * The exception to this is the anyuser value, which can be changed by the
 * dbus caller, but *cannot* be set in the configuration file (as this would
 * be right dangerous).
 *
 * @param auththread The AuthThread object to set the data for.
 */
bool auththread_config(AuthThread * auththread, char const * parameters) {
	bool anyuser_restore;
	bool result;
	Buffer * filename;
	Buffer const * configdir;

	configdir = authconfig_get_configdir(auththread->authconfig);
	filename = buffer_new(0);
	buffer_append_buffer(filename, configdir);
	buffer_append_string(filename, CONFIG_FILE);

	LOG(LOG_INFO, "Loading config from file: ");
	buffer_log(filename);

	// We dont want to read in the any_user value from file, so we need to  save and restore it
	anyuser_restore = authconfig_get_anyuser(auththread->authconfig);
	result = authconfig_load_json(auththread->authconfig, buffer_get_buffer(filename));
	// Restore the previous anyuser value
	authconfig_set_anyuser(auththread->authconfig, anyuser_restore);
	if (result == false) {
		LOG(LOG_ERR, "Config file failed to load or was badly formatted JSON\n");
	}

	// Overlay the config passed by dbus
	if (result) {
		LOG(LOG_INFO, "Config received from dbus and overlaid: ");
		result = authconfig_read_json(auththread->authconfig, parameters);
	}

	buffer_delete(filename);

	return result;
}

/**
 * Start the authentication process. This kicks off the events needed to
 * perform authentication, including sending out beacons and responding to
 * connections made by a potentially authenticating Pico.
 *
 * The call is asynchronous, and relies on a running GMainLoop in order to
 * supply events.
 *
 * This performs several tasks:
 *
 *  1. Sets up a channel in preparation for an authentication.
 *  2. Returns a code string to pam-pico for it to display as a QR code.
 *  3. Broadcasts the same code via Bluetooth as an invitation for Pico apps
 *     to authenticate.
 *  4. If a Pico app connects, performs authentication.
 *  5. Return the result of the authentication to pam_pico via dbus.
 *  6. Performs continuous authentication.
 *  7. If continuous authentication finishes, lock the user's screen.
 *
 * @param auththread The AuthThread object to use for the session.
 */
void auththread_start_auth(AuthThread * auththread) {
	PicoUkAcCamClPicoInterface * object;
	GDBusMethodInvocation * invocation;
	gboolean success;
	int handle;
	USERFILE usersresult;
	char const * beacon;
	bool beacons;
	bool continuous;
	float timeout;
	Buffer const * configdir;
	AUTHCHANNEL channeltype;
	Buffer const * url;
	char const * urlstring;
	ServiceRvp * servicervp;
#ifdef HAVE_LIBBLUETOOTH
	ServiceBtc * servicebtc;
#endif
	Buffer * pubfilename;
	Buffer * privfilename;
	Buffer * usersfilename;

	// Set up the configuration filenames
	configdir = authconfig_get_configdir(auththread->authconfig);
	pubfilename = buffer_new(0);
	privfilename = buffer_new(0);
	usersfilename = buffer_new(0);
	buffer_append_buffer(pubfilename, configdir);
	buffer_append_buffer(privfilename, configdir);
	buffer_append_buffer(usersfilename, configdir);
	buffer_append_string(pubfilename, PUB_FILE);
	buffer_append_string(privfilename, PRIV_FILE);
	buffer_append_string(usersfilename, USERS_FILE);

	// Set up the authentication thread

	// At this stage we're still potentially blocking the dbus caller (pam_pico),
	// so should set things up as quickly as possible

	auththread->state = AUTHTHREADSTATE_STARTED;
	handle = auththread->handle;
	object = auththread->object;
	invocation = auththread->invocation;

	beacons = authconfig_get_beacons(auththread->authconfig);
	continuous = authconfig_get_continuous(auththread->authconfig);
	timeout = authconfig_get_timeout(auththread->authconfig);
	channeltype = authconfig_get_channeltype(auththread->authconfig);

	switch (channeltype) {
	case AUTHCHANNEL_BTC:
#ifdef HAVE_LIBBLUETOOTH
		servicebtc = servicebtc_new();
		auththread->service = (Service *)servicebtc;

#else
		LOG(LOG_ERR, "Bluetooth Classic channel not supported");
		LOG(LOG_ERR, "To use it you must compile with the HAVE_LIBBLUETOOTH flag set");
		LOG(LOG_ERR, "Defaulting to RVP channel");
		// Default to RVP if no channel is selected
		auththread->service = (Service *)servicervp_new();

#endif
		break;
	case AUTHCHANNEL_RVP:
		servicervp = servicervp_new();
		auththread->service = (Service *)servicervp;
		url = authconfig_get_rvpurl(auththread->authconfig);
		urlstring = buffer_get_buffer(url);
		servicervp_set_urlprefix(servicervp, urlstring);
		break;
	default:
		LOG(LOG_ERR, "No channel type selected");
		// Default to RVP if no channel is selected
		auththread->service = (Service *)servicervp_new();
		break;
	}

	service_set_continuous(auththread->service, continuous);
	service_set_beacons(auththread->service, beacons);
	service_set_configdir(auththread->service, configdir);

	shared_load_or_generate_keys(auththread->shared, buffer_get_buffer(pubfilename), buffer_get_buffer(privfilename));

	// Load in the list of paired users from the confid directory
	usersresult = users_load(auththread->users, buffer_get_buffer(usersfilename));
	if (usersresult != USERFILE_SUCCESS) {
		LOG(LOG_ERR, "Failed to load user file, error: %d", usersresult);
	}

	buffer_delete(pubfilename);
	buffer_delete(privfilename);
	buffer_delete(usersfilename);

	service_set_loop(auththread->service, auththread->loop);
	service_set_update_callback(auththread->service, authhtread_service_update, auththread);
	service_set_stop_callback(auththread->service, auththread_service_stopped, auththread);

	success = auththread_setup(auththread);

	beacon = service_get_beacon(auththread->service);

	// Return the result to the dbus caller
	pico_uk_ac_cam_cl_pico_interface_complete_start_auth(object, invocation, handle, beacon, success);

	// The dbus caller is no longer being blocked, but is expected to call back
	// soon to get the authentication result

	// Set up a timer to stop the process after a period of time
	if (timeout > 0.0) {
		LOG(LOG_INFO, "Timeout set to %f seconds", timeout);
		auththread->timeoutid = g_timeout_add((guint)(timeout * 1000), auththread_timeout, auththread);
	}
}

/**
 * Fill out the supplied buffer with the commitment for the service assocaited
 * with this AuthThread. This will be the SH256 of the service identity public
 * key, so will be unique for each service.
 *
 * If the service hasn't yet started, the service key won't yet be loaded and
 * the function will return false (leaving the 'commitment' buffer unchanged).
 *
 * Similarly if there's some error in the generation of the commitment, the
 * function will return false.
 *
 * The `commitment` buffer belongs to the caller: it must be allocated before
 * calling this function and it's up to the caller to delete it afterwards.
 *
 * @param auththread The AuthThread to get the value for.
 * @param commitment A pre-allocated buffer to store the resuting commitment in.
 * @ereturn True if the commitment was stored correctly in the buffer, false if
 *          there was an error or the commitment couldn't be generated.
 */
bool auththread_get_commitment(AuthThread const * auththread, Buffer * commitment) {
	bool result;
	EC_KEY * serviceIdentityPublicKey;

	result = false;
	if ((commitment != NULL) && (auththread->state >= AUTHTHREADSTATE_STARTED)) {
		serviceIdentityPublicKey = shared_get_service_identity_public_key(auththread->shared);
		result = cryptosupport_generate_commitment(serviceIdentityPublicKey, commitment);
	}

	return result;
}

/**
 * Progress through authentication is handled using libpico's FsmService, but
 * at various stages AuthThread must perform its own actions. For example,
 * after authentication, but before the continuous process starts, the dbus
 * caller that requested the authentication must be told that a device
 * successfully authenticatd.
 *
 * This callback is therefore used to receive state updates from FsmService
 * (via Service, which acts as an intermediary) which allows it to perform
 * these additional tasks.
 *
 * @param service The Service object handling the state and FsmServie.
 * @param state The state that the FsmService just changed to.
 * @param user_data The user data provided when the callback was set up (in
 *        this case, the AuthThread data cast to void *).
 */
static void authhtread_service_update(Service * service, int state, void * user_data) {
	AuthThread * auththread = (AuthThread *)user_data;
	bool continuous;
	Buffer const * extraData;
	Buffer const * symmetricKey;
	bool result;
	char const * username;

	switch (state) {
		case FSMSERVICESTATE_START:
			// Cancel the timeout
			if (auththread->timeoutid) {
				g_source_remove(auththread->timeoutid);
				auththread->timeoutid = 0;
			}
			break;
		case FSMSERVICESTATE_AUTHENTICATED:
			auththread->result = TRUE;
			auththread->state = AUTHTHREADSTATE_COMPLETED;
			// The initial authentication is complete, so we need to get the result back
			// to pam_pico as quickly as possible

			// If pam_pico has already sent us a dbus message, we should reply to it
			// immediately; if not, we'll hold on to the result for a short while in case
			// it does
			extraData = service_get_received_extra_data(service);
			symmetricKey = service_get_symmetric_key(service);
			// Decrypt the returned data
			result = cryptosupport_decrypt_iv_base64(symmetricKey, extraData, auththread->password);
			if (!result) {
				LOG(LOG_ERR, "Failed to extract encrypted extra data sent by Pico");
			}

			auththread_complete_auth_reply(auththread, auththread->result);
			continuous = authconfig_get_continuous(auththread->authconfig);
			if (continuous) {
				LOG(LOG_INFO, "Moving to continuous auth");
				auththread->state = AUTHTHREADSTATE_CONTINUING;
			}
			else {
				LOG(LOG_INFO, "Requesting service stop");
				//service_stop(auththread->service);
			}
			break;
		case FSMSERVICESTATE_AUTHFAILED:
			auththread->result = FALSE;
			auththread->state = AUTHTHREADSTATE_COMPLETED;
			// The initial authentication is complete, so we need to get the result back
			// to pam_pico as quickly as possible

			// If pam_pico has already sent us a dbus message, we should reply to it
			// immediately; if not, we'll hold on to the result for a short while in case
			// it does
			auththread_complete_auth_reply(auththread, auththread->result);
			LOG(LOG_INFO, "Requesting service stop");
			//service_stop(auththread->service);
			break;
		case FSMSERVICESTATE_FIN:
		case FSMSERVICESTATE_ERROR:
			auththread_complete_auth_reply(auththread, FALSE);
			if (auththread->result == TRUE) {
				// The user successfully authenticated and something went wrong, so we should lock
				username = buffer_get_buffer(auththread->username);
				lock(username);
				LOG(LOG_INFO, "Locked");
			}
			break;
		default:
			// Do nothing
			break;
	}
}

/**
 * Stop the AuthThread authentication at the earliest opportunity.
 *
 * @param auththread The AuthThread to stop.
 */
void auththread_stop(AuthThread * auththread) {
	if (auththread->state < AUTHTHREADSTATE_HARVESTABLE) {
		if (auththread->service) {
			service_stop(auththread->service);
		}
	}
}

/**
 * This callback is called when authentication, or continuous authentication,
 * finishes (either successfully or unsuccessfully). The state is managed by
 * Service, which itself delegates to FsmService, but AuthThread here is tasked
 * with things like locking the user's machine, so we need to know when the
 * authentication finishes. Hence the need for this callback.
 *
 * @param service The Service object handling the state and FsmServie.
 * @param user_data The user data provided when the callback was set up (in
 *        this case, the AuthThread data cast to void *).
 */
static void auththread_service_stopped(Service * service, void * user_data) {
	AuthThread * auththread = (AuthThread *)user_data;
	char const * username;
	bool continuous;

	continuous = authconfig_get_continuous(auththread->authconfig);
	if (continuous) {
		username = buffer_get_buffer(auththread->username);
		lock(username);
		LOG(LOG_INFO, "Locked (stopped)");
	}
	if (auththread->timeoutid != 0) {
		g_source_remove(auththread->timeoutid);
		auththread->timeoutid = 0;
	}

	auththread_complete_auth_reply(auththread, FALSE);

	auththread->state = AUTHTHREADSTATE_HARVESTABLE;
}

/**
 * The dbus caller who initiated the authentication must make two calls
 * to the service; first to get the QR code, and second to get the
 * result of the authentication. The first call returns immediately, but
 * the second call may block for a while as the authentication proceeds.
 * Moreover, there's no guarantee that the caller will make the second
 * dbus call immediately; there may be a delay.
 *
 * There are various situations in which the caller should be replied to,
 * such as if the authentication succeeds, if it fails, or if an error
 * occurs. However, it's also important that only one reply is sent.
 *
 * This function will make the reply call if the caller is waiting
 * for it, and hasn't been replied to already. It sends back the
 * details of the authentication as they're known at this point in time.
 *
 * @param auththread The AuthThread object running the authentication.
 * @param success Value to return to the caller: TRUE if the authentication
 *        should be considered successful, FALSE o/w.
 */
static void auththread_complete_auth_reply(AuthThread * auththread, bool success) {
	PicoUkAcCamClPicoInterface * object;
	GDBusMethodInvocation * invocation;
	gchar const * username;
	gchar const * password;

	object = auththread->object;
	invocation = auththread->invocation;

	if ((object != NULL) && (invocation != NULL)) {
		auththread->object = NULL;
		auththread->invocation = NULL;
		username = buffer_get_buffer(auththread->username);
		password = buffer_get_buffer(auththread->password);
		LOG(LOG_INFO, "Returning on wait with success %d\n", success);
		pico_uk_ac_cam_cl_pico_interface_complete_complete_auth(object, invocation, username, password, success);
	}
}

/**
 * Set up the main Pico authentication proccess. It does this by setting
 * up a channel to listen on and then triggering the authentication
 * service to start.
 *
 * @param auththread The context object holding all details needed for the
 *        authentication, as well as space to update the result.
 * @return true of the set up completed successfully, false o/w.
 */
static bool auththread_setup(AuthThread * auththread) {
	int filteredNum;
	gchar const * username;
	bool result;
	bool anyuser;
	Users * filtered;

	result = true;
	username = auththread_get_username(auththread);
	anyuser = authconfig_get_anyuser(auththread->authconfig);

	filteredNum = 0;
	if (anyuser) {
		LOG(LOG_INFO, "Authenticating for any user");
		filtered = auththread->users;
	}
	else {
		LOG(LOG_INFO, "Authenticating for user %s", username);
		filtered = auththread->filtered;
		// Filter the list of users so we only have keys associated with this username
		filteredNum = users_filter_by_name(auththread->users, username, filtered);
		LOG(LOG_INFO, "Filtered to %d result(s) in users file", filteredNum);

		if (filteredNum == 0) {
			// A users input of NULL would allow anyone to log in
			// We don't want that, so ensure we bail in this case
			LOG(LOG_ERR, "Filtered list of users is NULL");
			result = false;
		}
	}

	if (result) {
		service_start(auththread->service, auththread->shared, filtered, auththread->extraData);
	}

	return result;
}

/**
 * AuthThread is now set to use a GMainLoop events rather than threading.
 * This function sets the GMainLoop to use for these events.
 *
 * @param auththread The context object holding all details needed for the
 *        authentication, as well as space to update the result.
 * @param loop The GMainLoop to use for event processing.
 */
void auththread_set_loop(AuthThread * auththread, GMainLoop * loop) {
	auththread->loop = loop;
}

/**
 * Internal callback triggered when a timeout occurs. This indicates that
 * the process should stop.
 *
 * @param user_data The user data, which in this case is the AuthThread structure
 *        cast to (void *).
 */
static gboolean auththread_timeout(gpointer user_data) {
	AuthThread * auththread = (AuthThread *)user_data;

	// This timeout fires only once
	auththread->timeoutid = 0;

	LOG(LOG_DEBUG, "Configured time limit reached");
	if (auththread->service) {
		service_stop(auththread->service);
	}

	return FALSE;
}

/** @} addtogroup Service */

