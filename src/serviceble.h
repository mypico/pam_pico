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
 * @brief Provides Bluetooth Low Energy event support to tie to FsmService
 * @section DESCRIPTION
 *
 * FSMService provides only a framework of callbacks and events, but without
 * any way of communicating. The communication channel has to be tied to it
 * to make it work. This code provides the implementation of the callbacks to
 * allow the state machine to work with a Bluetooth Low Energy channel in order
 * to actually support authentication. A GATT service is used for this.
 *
 * On top of this, it also controls the sending of Bluetooth advertisements to
 * other devices to notify them that they can authenticate.
 *
 * The execution of this code is managed by AuthThread, while this code uses
 * FsmService from libpico to manage the authentication control flow.
 *
 */

#ifndef __SERVICEBLE_H
#define __SERVICEBLE_H (1)

#include "pico/fsmservice.h"

// Defines

// Structure definitions

typedef struct _ServiceBle ServiceBle;

// Function prototypes

ServiceBle * serviceble_new();
void serviceble_delete(ServiceBle * serviceble);

void serviceble_start(ServiceBle * serviceble, Shared * shared, Users const * users, Buffer const * extraData);
void serviceble_stop(ServiceBle * serviceble);

// Function definitions

#endif

