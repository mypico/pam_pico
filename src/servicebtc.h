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

#ifndef __SERVICEBTC_H
#define __SERVICEBTC_H (1)

#include "pico/fsmservice.h"

// Defines

// Structure definitions

typedef struct _ServiceBtc ServiceBtc;

// Function prototypes

ServiceBtc * servicebtc_new();
void servicebtc_delete(ServiceBtc * servicebtc);

void servicebtc_start(ServiceBtc * servicebtc, Shared * shared, Users const * users, Buffer const * extraData);
void servicebtc_stop(ServiceBtc * servicebtc);

// Function definitions

#endif

