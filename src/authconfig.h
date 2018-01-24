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
 * @brief Stores settings that define the behaviour of an authentication
 * @section DESCRIPTION
 *
 * There are a variety of configurations for how an authentication may take
 * place. For example, it may be performed via the Rendezvous Point, or over
 * Bluetooth. It may be an athentication for a specific user, or for an as-yet
 * unknown user, etc.
 *
 * The AuthConfig data structure stores all of the options needed to specify
 * an authentication process. The parameters are provided by the PAM in the
 * form of a JSON string. A function for parsing this JSON string and
 * populating the data structure is provided, along with getters and setters.
 *
 * The lifetime of each AuthConfig data item is managed by processstore.
 *
 */

/** \addtogroup Service
 *  @{
 */

#ifndef __SETTINGS_H
#define __SETTINGS_H (1)

#include "pico/debug.h"
#include "pico/pico.h"
#include "pico/json.h"

// Defines

// Structure definitions

/**
 * @brief The type of channel to use for authentication.
 *
 * The authentication protocol can be performed over several different channel
 * types. This enumerates the possible types.
 *
 *  - AUTHCHANNEL_RVP: Rendevzous Point channel (HTTP/HTTPS)
 *  - AUTHCHANNEL_BT: Bluetooth
 *
 */
typedef enum _AUTHCHANNEL {
	AUTHCHANNEL_INVALID = -1,
	
	AUTHCHANNEL_RVP,
	AUTHCHANNEL_BTC,
	
	AUTHCHANNEL_NUM
} AUTHCHANNEL;

/**
 * The internal structure can be found in authconfig.c
 */
typedef struct _AuthConfig AuthConfig;

// Function prototypes

AuthConfig * authconfig_new();
void authconfig_delete(AuthConfig * authconfig);
bool authconfig_read_json(AuthConfig * authconfig, char const * json);
bool authconfig_load_json(AuthConfig * authconfig, char const * filename);

void authconfig_set_continuous(AuthConfig * authconfig, bool continuous);
bool authconfig_get_continuous(AuthConfig const * authconfig);

void authconfig_set_channeltype(AuthConfig * authconfig, AUTHCHANNEL channeltype);
AUTHCHANNEL authconfig_get_channeltype(AuthConfig const * authconfig);

void authconfig_set_beacons(AuthConfig * authconfig, bool beacons);
bool authconfig_get_beacons(AuthConfig const * authconfig);

void authconfig_set_anyuser(AuthConfig * authconfig, bool anyuser);
bool authconfig_get_anyuser(AuthConfig const * authconfig);

void authconfig_set_timeout(AuthConfig * authconfig, float timeout);
float authconfig_get_timeout(AuthConfig const * authconfig);

void authconfig_set_rvpurl(AuthConfig * authconfig, char const * rvpurl);
Buffer const * authconfig_get_rvpurl(AuthConfig const * authconfig);

void authconfig_set_configdir(AuthConfig * authconfig, char const * configdir);
Buffer const * authconfig_get_configdir(AuthConfig const * authconfig);

// Function definitions

#endif

/** @} addtogroup Service */

