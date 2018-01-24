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

#ifndef __SERVICE_H
#define __SERVICE_H (1)

#include "pico/fsmservice.h"

// Defines

// Structure definitions

typedef struct _Service Service;

typedef void (*ServiceStopped)(Service * service, void * user_data);
typedef void (*ServiceUpdate)(Service * service, int state, void * user_data);

// Function prototypes

Service * service_new();
// service_delete() is virtual
void service_delete(Service * service);

void service_set_loop(Service * service, GMainLoop * loop);
char const * service_get_beacon(Service const * service);
void service_set_stop_callback(Service * service, ServiceStopped callback, void * user_data);
void service_set_continuous(Service * service, bool continuous);
void service_set_beacons(Service * service, bool beacons);
void service_set_update_callback(Service * service, ServiceUpdate callback, void * user_data);
Buffer const * service_get_received_extra_data(Service * service);
Buffer const * service_get_symmetric_key(Service * service);
void service_set_configdir(Service * service, Buffer const * configdir);

// Virtual functions
void service_start(Service * service, Shared * shared, Users const * users, Buffer const * extraData);
void service_stop(Service * service);


// Function definitions

#endif

