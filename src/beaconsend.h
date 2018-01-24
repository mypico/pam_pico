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
 * @brief Send Bluetooth beacons out to a specific device
 * @section DESCRIPTION
 *
 * In order for a nearby Pico to know that there's a machine to log in to
 * there are one of two approaches. The first is for the user to scan a
 * QR code on the device using their Pico. The second is for the Pico to receive
 * a beacon from the device over a Bluetooth channel. This works for Bluetooth
 * because it's 'proximity'-based. That is, the beacon will only be received
 * if the two devices are near one another.
 *
 * This file provides support for contacting a specific device (specified
 * using a Bluetooth MAC) and sending it a beacon, which is a JSON string
 * containing enough information for the Pico to get in contact with the
 * device prior to authentication.
 *
 * This code is used by the beaconthread.c code, which provides support for
 * calling the beaconsend code for multiple devices.
 *
 * The operation of beaconsend is asynchronous and uses a GMainLoop in order to
 * operate using events.
 *
 */

/** \addtogroup Service
 *  @{
 */

#ifndef __BEACONSEND_H
#define __BEACONSEND_H (1)

#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/continuous.h"
#include <picobt/devicelist.h>

//#include "gdbus-generated.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in beaconthread.c
 */
typedef struct _BeaconSend BeaconSend;

typedef void (*BeaconSendFinishCallback)(BeaconSend const * beaconsend, void * user_data);

// Function prototypes

BeaconSend * beaconsend_new();
void beaconsend_delete(BeaconSend * beaconsend);
void beaconsend_start(BeaconSend * beaconsend);
void beaconsend_stop(BeaconSend * beaconsend);
bool beaconsend_set_device(BeaconSend * beaconsend, char const * const device);
void beaconsend_set_code(BeaconSend * beaconsend, char const * code);
void beaconsend_set_finished_callback(BeaconSend * beaconsend, BeaconSendFinishCallback callback, void * user_data);

// Function definitions

#endif

/** @} addtogroup Service */

