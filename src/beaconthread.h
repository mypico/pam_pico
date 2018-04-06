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

#ifndef __BEACONTHREAD_H
#define __BEACONTHREAD_H (1)

#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/continuous.h"
//#include <picobt/devicelist.h>

#include "authconfig.h"
#include "gdbus-generated.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in beaconthread.c
 */
typedef struct _BeaconThread BeaconThread;

/**
 * @brief The states that each Beacon Thread can take
 *
 * The states in this enum encapsulate the lifecycle of a beacon session. On
 * creation the session starts with a state of BEACONTHREADSTATE_INVALID. Once
 * the session has started it moves to the BEACONTHREADSTATE_STARTED state.
 * In this state it will periodically send out Bluetooth beacons inviting
 * nearby Pico apps to athenticate to it.
 *
 * This continues until AuthThread requests the session to stop by calling
 * beaconthread_stop(), usually meaning that a device has started the
 * authentication process, or authentication was cancelled by the calling
 * PAM. This will then  push the session into the BEACONTHREADSTATE_COMPLETED
 * state.
 *
 * The last thing this does before finishing is to move itself into the
 * BEACONTHREADSTATE_HARVESTABLE state. In this state, the data associated with
 * the session will be released for re-use the next time the
 * processstore_harvest() function is called (which, by default, occurs just
 * prior to any new processes being added.
 *
 */
typedef enum _BEACONTHREADSTATE {
	BEACONTHREADSTATE_INVALID = -1,
	
	BEACONTHREADSTATE_STARTED,
	BEACONTHREADSTATE_COMPLETED,
	BEACONTHREADSTATE_HARVESTABLE,
	
	BEACONTHREADSTATE_NUM
} BEACONTHREADSTATE;

typedef void (*BeaconThreadFinishCallback)(BeaconThread const * beaconthread, void * user_data);

// Function prototypes

BeaconThread * beaconthread_new();
void beaconthread_delete(BeaconThread * beaconthread);

void beaconthread_set_state(BeaconThread * beaconthread, BEACONTHREADSTATE state);
BEACONTHREADSTATE beaconthread_get_state(BeaconThread * beaconthread);
void beaconthread_set_code(BeaconThread * beaconthread, char const * code);
void beaconthread_set_finished_callback(BeaconThread * beaconthread, BeaconThreadFinishCallback callback, void * user_data);
void beaconthread_set_configdir(BeaconThread * beaconthread, Buffer const * configdir);

void beaconthread_start(BeaconThread * beaconthread, Users const * users);
void beaconthread_stop(BeaconThread * beaconthread);

// Function definitions

#endif

/** @} addtogroup Service */

