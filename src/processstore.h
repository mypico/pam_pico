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

#ifndef __PICO_CONTINUOUS_AUTH_H
#define __PICO_CONTINUOUS_AUTH_H (1)

#include <stdio.h>
#include <stdlib.h>
#include "gdbus-generated-cont.h"
#include "auththread.h"
#include "beaconthread.h"

// Defines


// Standard names to use for the configuration files
#define PUB_FILE "pico_pub_key.der"
#define PRIV_FILE "pico_priv_key.der"
#define USERS_FILE "users.txt"
#define BT_LIST_FILE "bluetooth.txt"
#define CONFIG_FILE "config.txt"

// Structure definitions

/**
 * The internal structure can be found in processstore.c
 */
typedef struct _ProcessStore ProcessStore;

// Function prototypes

ProcessStore * processstore_new();
void processstore_delete(ProcessStore * processstoredata);

int processstore_add(ProcessStore * processstoredata);
void processstore_remove(ProcessStore * processstoredata, int handle);
AuthThread * processstore_get_auththread(ProcessStore * processstoredata, int handle);
void processstore_harvest(ProcessStore * processstoredata);

void lock(char const * username);

bool start_auth(ProcessStore * processstoredata, PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, char const * username, char const * parameters);
bool complete_auth(ProcessStore * processstoredata, PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, int handle);
void processstore_set_loop(ProcessStore * processstoredata, GMainLoop * loop);
GMainLoop * processstore_get_loop(ProcessStore * processstoredata);
void processstore_owner_lost(ProcessStore * processstoredata, char const * old_owner);

// Function definitions

#endif

/** @} addtogroup Service */

