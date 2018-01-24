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

#ifndef __AUTHTHREAD_H
#define __AUTHTHREAD_H (1)

#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/continuous.h"
#include <picobt/devicelist.h>

#include "authconfig.h"
#include "gdbus-generated.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in auththread.c
 */
typedef struct _AuthThread AuthThread;

/**
 * @brief The states that each Auth Thread can take
 *
 * The states in this enum encapsulate the lifecycle of an AuthThread. On
 * creation the session starts with a state of AUTHTHREADSTATE_INVALID. Once
 * the session has been started it moves to the AUTHTHREADSTATE_STARTED state.
 * In this state it will wait for a Pico app to connect and attempt to perform
 * the authentication protocol, while potentially sending out beacons.
 *
 * The session remains in the AUTHTHREADSTATE_STARTED state until an
 * authentication completes (with either success or failure), a timeout
 * occurs (in which case the authentication is deemed to have failed), or the
 * dbus connection losses it owner (in which case the authentication result is
 * irrelevant, since we've got nowhere to send it back to). The session then
 * moves into the AUTHTHREADSTATE_COMPLETED state.
 *
 * Once in the AUTHTHREADSTATE_COMPLETED the result can be returned to pam_pico
 * for action.
 *
 * If pam_pico requested for continuous authentication at the outset, the
 * session will then move into the AUTHTHREADSTATE_CONTINUING state and
 * continuously authenticate to the Pico app until authentication fails, the
 * app disconnects, or the app stops authenticating. It may therefore remain in
 * this state for some time. Note that we don't care about losing the dbus
 * owner in this case, since it should already have lost interest (PAMs don't
 * handle continuous authentication).
 *
 * The last thing a session does before finishing is to move itself into the
 * AUTHTHREADSTATE_HARVESTABLE state. In this state, the data associated with
 * the session will be released for re-use the next time the
 * processstore_harvest() function is called (which, by default, occurs just
 * prior to any new processes being added).
 *
 */
typedef enum _AUTHTHREADSTATE {
	AUTHTHREADSTATE_INVALID,
	
	AUTHTHREADSTATE_STARTED,
	AUTHTHREADSTATE_COMPLETED,
	AUTHTHREADSTATE_CONTINUING,
	AUTHTHREADSTATE_HARVESTABLE,
	
	AUTHTHREADSTATE_NUM
} AUTHTHREADSTATE;

// Function prototypes

AuthThread * auththread_new();
void auththread_delete(AuthThread * auththread);

void auththread_set_handle(AuthThread * auththread, int handle);
int auththread_get_handle(AuthThread * auththread);
void auththread_set_state(AuthThread * auththread, AUTHTHREADSTATE state);
AUTHTHREADSTATE auththread_get_state(AuthThread * auththread);
void auththread_set_username(AuthThread * auththread, char const * username);
char const * auththread_get_username(AuthThread const * auththread);
void auththread_set_password(AuthThread * auththread, char const * password);
char const * auththread_get_password(AuthThread * auththread);
void auththread_set_result(AuthThread * auththread, bool result);
bool auththread_get_result(AuthThread * auththread);
void auththread_set_object(AuthThread * auththread, PicoUkAcCamClPicoInterface * object);
PicoUkAcCamClPicoInterface * auththread_get_object(AuthThread * auththread);
void auththread_set_invocation(AuthThread * auththread, GDBusMethodInvocation * invocation);
GDBusMethodInvocation * auththread_get_invocation(AuthThread * auththread);
void auththread_start_auth(AuthThread * auththread);
void auththread_ownerlost(AuthThread * auththread);
void auththread_set_loop(AuthThread * auththread, GMainLoop * loop);
bool auththread_config(AuthThread * auththread, char const * parameters);
bool auththread_get_commitment(AuthThread const * auththread, Buffer * commitment);
void auththread_stop(AuthThread * auththread);

// Function definitions

#endif

/** @} addtogroup Service */

