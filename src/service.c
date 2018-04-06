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
#include <glib.h>
#include <gio/gio.h>
#include <errno.h>
#include <unistd.h>
//#include <bluetooth/bluetooth.h>
//#include <bluetooth/hci.h>
//#include <bluetooth/hci_lib.h>
#include "pico/pico.h"
#include "pico/log.h"
#include "pico/keypair.h"
#include "pico/fsmservice.h"
#include "pico/keyauth.h"
#include "pico/messagestatus.h"

#include "beaconthread.h"
#include "service.h"
#include "service_private.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
Service * service_new() {
	Service * service;

	service = CALLOC(sizeof(Service), 1);

	service_init(service);

	return service;
}

/**
 * Initialise a new instance of the class. This call initialises the
 * member variables of the struct without allocating the memory for the
 * struct itself. This is useful when creating a subclass (since the
 * the memory doesn't need to be allocated twice, but the parent class still
 * needs to be initialised).
 *
 * @param service The Service object to initialise.
 */
void service_init(Service * service) {
	service->loop = NULL;
	service->fsmservice = fsmservice_new();
	service->beaconthread = beaconthread_new();
	service->stopping = FALSE;
	service->beacon = NULL;
	service->beacons = FALSE;
	service->timeoutid = 0;
	service->configdir = buffer_new(0);

	service->service_delete = NULL;
	service->service_start = NULL;
	service->service_stop = NULL;
}

/**
 * Deinitialise an instance of the class. This releases any resources
 * *except* the memory allocated to the structure itself. This is useful
 * when the stuct has been subclassed, since the child class will release
 * the structure that this forms part of,
 *
 * @param service The Service object to deinitialise.
 */
void service_deinit(Service * service) {
	BEACONTHREADSTATE state;

	if (service->stopping) {
		LOG(LOG_ERR, "Should not delete service while stopping");
	}
	if (service->fsmservice != NULL) {
		fsmservice_set_functions(service->fsmservice, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		fsmservice_set_userdata(service->fsmservice, NULL);
		fsmservice_delete(service->fsmservice);
		service->fsmservice = NULL;
	}

	if (service->beaconthread != NULL) {
		state = beaconthread_get_state(service->beaconthread);
		if ((state != BEACONTHREADSTATE_HARVESTABLE) && (state != BEACONTHREADSTATE_INVALID)) {
			LOG(LOG_ERR, "Should not delete service while still sending beacons");
		}

		beaconthread_delete(service->beaconthread);
		service->beaconthread = NULL;
	}

	if (service->configdir != NULL) {
		buffer_delete(service->configdir);
		service->configdir = NULL;
	}

	if (service->beacon != NULL) {
		FREE(service->beacon);
		service->beacon = NULL;
	}
}


/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param auththread The object to free.
 */
void service_delete(Service * service) {
	if (service != NULL) {
		service_deinit(service);

		if (service->service_delete != NULL) {
			// Inherited, so use the virtual delete
			service->service_delete(service);
		}
		else {
			// Otherwise we need to free the data ourselves	
			FREE(service);
		}
	}
}

/**
 * Set the GMainLoop in use by the application (there can be only one). This
 * value is needed handle events.
 *
 * @param service The object to set the value of.
 * @param loop The GMainLoop value to set.
 */
void service_set_loop(Service * service, GMainLoop * loop) {
	service->loop = loop;
}

/**
 * Get the beacon that this service is using to advertise to nearby Pico
 * devices on the Bluetooth channel.
 *
 * @param service The object to get the beacon for.
 * @return a NULL-terminated JSON-formatted beacon string.
 */
char const * service_get_beacon(Service const * service) {
	return service->beacon;
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
 * @param service The object to use.
 * @param shared A Shared object that contains the keys needed for
          authentication.
 * @param users The users that are allowed to authenticate, or NULL to
          allow any user to authenticate.
 * @param extraData A buffer containing any extra data to be sent to the
 *        Pico during the authentication process.
 */
void service_start(Service * service, Shared * shared, Users const * users, Buffer const * extraData) {
	service->service_start(service, shared, users, extraData);
}

/**
 * Set a callback that will be called when authenticationo completes (either
 * successfully or unsuccessfully). This can be used to notify a parent that
 * it's safe to clear up any resources associated with this Service.
 *
 * @param service The Service to set the callback for.
 * @param callback The callback to call once the Service has completed.
 * @param user_data The data to send with the callback.
 */
void service_set_stop_callback(Service * service, ServiceStopped callback, void * user_data) {
	service->stop_callback = callback;
	service->stop_user_data = user_data;
}

/**
 * Request that the service stops whatever it's doing and finish off. Having
 * called this, the callback set using service_set_stop_callback() will be
 * called -- potentially after a period of time -- to signify that the Service
 * has indeed completed everything, tidies up, and is ready to be deleted.
 *
 * This call is asynchronous, hence the need for the callback.
 *
 * @param service The Service to stop.
 */
void service_stop(Service * service) {
	service->service_stop(service);
}

/**
 * Set a callback that will be triggered every time the underlying FsmService
 * state machine updates its state.
 *
 * @param service The Service to set the callback for.
 * @param callback The callback to call whenever the underlying FSM state changes.
 * @param user_data The data to send with the callback.
 */
void service_set_update_callback(Service * service, ServiceUpdate callback, void * user_data) {
	service->update_callback = callback;
	service->update_user_data = user_data;
}

/**
 * Set whether the FSM should perform continuous authentication or not. If set
 * to true, once a Pico has authenticated the service will attempt to perform
 * continuous authentication over an indefinite period of time. If set to false,
 * the service will stop after the first full authentication and no longer try
 * to authenticate periodically after that.
 *
 * @param service The object to set the value for.
 * @param continuous True if the service should continuously authenticate the
 *        Pico, false o/w.
 */
void service_set_continuous(Service * service, bool continuous) {
	fsmservice_set_continuous(service->fsmservice, continuous);
}

/**
 * Set whether to advertise using Bluetooth beacons.
 *
 * @param service The object to set the value for.
 * @param beacons True if beacons should be sent, false o/w.
 */
void service_set_beacons(Service * service, bool beacons) {
	service->beacons = beacons;
}

/**
 * Get the latest piece of extra data sent by the Pico to the service. See
 * fsmservice_get_received_extra_data() for more details about when this
 * data is likely to be updated..
 *
 * The buffer is owned by FsmService, so should not be deleted by the
 * caller.
 *
 * @param service The object to get the value from.
 * @return A buffer containing the latest extra data. The buffer may be empty
 *         but will never be NULL.
 */
Buffer const * service_get_received_extra_data(Service * service) {
	return fsmservice_get_received_extra_data(service->fsmservice);
}

/**
 * Get the symmetric key stored for the authenticatd user. The value is
 * only valid after the state machine has reached the
 * FSMSERVICESTATE_STATUS state and the authentication succeeded.
 * Otherwise the buffer will be empty.
 *
 * The buffer is owned by FsmService, so should not be deleted by the
 * caller.
 *
 * @param service The object to get the data from.
 * @return A buffer containing the symmetric key stored for the user.
 */
Buffer const * service_get_symmetric_key(Service * service) {
	return fsmservice_get_symmetric_key(service->fsmservice);
}

/**
 * Set the directory to read configuration files from.
 *
 * @param service The object to set the value for.
 * @param configdir The folder to set the config directory to.
 */
void service_set_configdir(Service * service, Buffer const * configdir) {
	buffer_clear(service->configdir);
	buffer_append_buffer(service->configdir, configdir);
}

/** @} addtogroup Service */

