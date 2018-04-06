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
#include "authconfig.h"

// Defines

/**
 * @brief The default directory to load the configuration data from
 *
 * Different services should be set to use different configuration directories,
 * and if so, they will act independently. The configuration directory holds
 * various cnofiguration files:
 *
 * 1. Service identity public key file: "pico_pub_key.der"
 * 2. Service identity private key file: "pico_priv_key.der"
 * 3. Users file with details of all paired users of the service: "users.txt"
 * 4. List of Bluetooth MACs to send beacons to: "bluetooth.txt"
 * 5. File to read the default configuration from: "config.txt"
 *
 * These files should be considered secret, and permissions should be set
 * accordingly.
 *
 */
#define CONFIG_DIR "/etc/pam-pico/"
/**
 * @brief The default format to use for a Rendezvous Channel URI
 *
 * This is the format to use for a Rendezvous Point channel URI. A string of
 * this type is added to the QR code and/or beacon to allow other devices to
 * authenticate to the service. It's essentially the Rendezvous Point URL with
 * a random channel path added to the end.
 *
 */
#define URL_PREFIX "http://rendezvous.mypico.org/channel/"

// Structure definitions

/**
 * @brief Opaque structure used for storing an authentication config
 *
 * Each authentication may be set up with different characteristics, depending
 * on what the PAM wants. Usually these will be controlled by the command line
 * parameters sent to the PAM. This data structure is used to capture the
 * requested configuration, so that the authentication session can act
 * appropriately.
 *
 * The lifecycle of this data is managed by ProcessStore.
 *
 */
typedef struct _AuthConfig {
	bool continuous;
	AUTHCHANNEL channeltype;
	bool beacons;
	bool anyuser;
	float timeout;
	Buffer * rvpurl;
	Buffer * configdir;
} AuthConfig;

// Function prototypes

static void authconfig_postfix_char(Buffer * buffer, char character);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
AuthConfig * authconfig_new() {
	AuthConfig * authconfig;

	authconfig = CALLOC(sizeof(AuthConfig), 1);

	authconfig->continuous = false;
	authconfig->channeltype = AUTHCHANNEL_RVP;
	authconfig->beacons = false;
	authconfig->anyuser = false;
	authconfig->timeout = 0.0;
	authconfig->rvpurl = buffer_new(0);
	buffer_append_string(authconfig->rvpurl, URL_PREFIX);
	authconfig->configdir = buffer_new(0);
	buffer_append_string(authconfig->configdir, CONFIG_DIR);

	return authconfig;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param authconfig The object to free.
 */
void authconfig_delete(AuthConfig * authconfig) {
	if (authconfig) {
		if (authconfig->rvpurl != NULL) {
			buffer_delete(authconfig->rvpurl);
			authconfig->rvpurl = NULL;
		}

		FREE(authconfig);
	}
}

/**
 * Check whether a buffer ends with a particular character. If it doesn't,
 * then append the character; if it does, then do nothing.
 *
 * This is useful for terminating paths and URLS, for example adding a
 * forward slash to the end if there isn't one already.
 *
 * @param buffer The buffer to check and potentially append a character to.
 * @param character The character to check for and, if needed, append.
 */
static void authconfig_postfix_char(Buffer * buffer, char character) {
	bool postfix;
	int length;
	char finalcharacter;

	postfix = FALSE;
	if (buffer != NULL) {
		length = buffer_get_pos(buffer);
		if (length > 0) {
			finalcharacter = buffer_get_buffer(buffer)[length - 1];
			if (finalcharacter != character) {
				postfix = TRUE;
			}
		}
		else {
			postfix = TRUE;
		}
	}

	if (postfix == TRUE) {
		buffer_append(buffer, &character, 1);
	}
}

/**
 * Populate an AuthConfig data structure with values taken from the JSON string
 * provided. If no value is found in the JSON dictionary for a particular
 * parameter, then it is left at its default value.
 *
 * This function is used to configure an authentication process, taking the
 * parameters value provided from the StartAuth dbus message.
 *
 * @param authconfig The object to populate.
 * @param json The JSON formatted dictionary string to get the options from.
 */
bool authconfig_read_json(AuthConfig * authconfig, char const * json) {
	bool result;
	Json * config;
	char const * string;
	double decimal;
	long long int integer;
	JSONTYPE type;

	result = true;
	
	if (json && strlen(json) > 0) {
		config = json_new();
		result = json_deserialize_string(config, json, strlen(json));

		if (result) {
			type = json_get_type(config, "continuous");
			if (type == JSONTYPE_INTEGER) {
				integer = json_get_integer(config, "continuous");
				authconfig->continuous = (integer != 0);
			}

			type = json_get_type(config, "channeltype");
			if (type == JSONTYPE_STRING) {
				string = json_get_string(config, "channeltype");
				if (strcmp(string, "rvp") == 0) {
					authconfig->channeltype = AUTHCHANNEL_RVP;
				}
				if (strcmp(string, "btc") == 0) {
					authconfig->channeltype = AUTHCHANNEL_BTC;
				}
			}

			type = json_get_type(config, "beacons");
			if (type == JSONTYPE_INTEGER) {
				integer = json_get_integer(config, "beacons");
				authconfig->beacons = (integer != 0);
			}

			type = json_get_type(config, "anyuser");
			if (type == JSONTYPE_INTEGER) {
				integer = json_get_integer(config, "anyuser");
				authconfig->anyuser = (integer != 0);
			}

			type = json_get_type(config, "timeout");
			if (type == JSONTYPE_DECIMAL) {
				decimal = json_get_decimal(config, "timeout");
				authconfig->timeout = decimal;
			}

			type = json_get_type(config, "rvpurl");
			if (type == JSONTYPE_STRING) {
				string = json_get_string(config, "rvpurl");
				buffer_clear(authconfig->rvpurl);
				buffer_append_string(authconfig->rvpurl, string);
				authconfig_postfix_char(authconfig->rvpurl, '/');
			}

			type = json_get_type(config, "configdir");
			if (type == JSONTYPE_STRING) {
				string = json_get_string(config, "configdir");
				buffer_clear(authconfig->configdir);
				buffer_append_string(authconfig->configdir, string);
				authconfig_postfix_char(authconfig->configdir, '/');
			}
		}
		else {
			LOG(LOG_ERR, "JSON error: %s\n", json);
		}

		// Output config to log file
		json_log(config);

		json_delete(config);
	}
	
	return result;
}

/**
 * Load a JSON config string from file and overlay it on top of the config
 * structure. Only the keys contained in the data structure are changed.
 *
 * @param authconfig The config struture to update.
 * @param filename The file to load.
 * @return True if the file loaded okay or didn't exist; false if it contains
 *         a malformed JSON string.
 */
bool authconfig_load_json(AuthConfig * authconfig, char const * filename) {
	bool result;
	FILE * file;
	size_t size;
	Buffer * data;
	size_t read;
	size_t pos;
	char * streaminto;

	result = true;
	file = fopen(filename, "r");

	if (file != NULL) {
		// Establish size of file
		fseek(file, 0L, SEEK_END);
		size = ftell(file) + 1;
		fseek(file, 0L, SEEK_SET);
		data = buffer_new(size);

		pos = 0;
		while (feof(file) == 0) {
			buffer_set_min_size(data, pos + size);
			streaminto = buffer_get_buffer(data);
			read = fread(streaminto + pos, sizeof(char), size, file);
			pos += read;
			buffer_set_pos(data, pos);
		}

		fclose(file);

		streaminto = buffer_get_buffer(data);
		result = authconfig_read_json(authconfig, streaminto);
	}

	return result;
}

/**
 * Set the continuous authentication configuration option. This should be set
 * to true if continuous authentication will be perfromed, false o/w.
 *
 * The default value is false.
 *
 * @param authconfig The object to set the value for.
 * @param continouous The value to set.
 */
void authconfig_set_continuous(AuthConfig * authconfig, bool continuous) {
	authconfig->continuous = continuous;
}

/**
 * Get the continuous authentication configuration option. This will be set
 * to true if continuous authentication will be perfromed, false o/w.
 *
 * @param authconfig The object to get the value from.
 * @return The value.
 */
bool authconfig_get_continuous(AuthConfig const * authconfig) {
	return authconfig->continuous;
}

/**
 * Set the channel type configuration option. See the AUTHCHANNEL enum in
 * authconfig.h for possible values.
 *
 * The default is to use a Rendezvous Point channel (AUTHCHANNEL_RVP).
 *
 * @param authconfig The object to set the value for.
 * @param channeltype The value to set.
 */
void authconfig_set_channeltype(AuthConfig * authconfig, AUTHCHANNEL channeltype) {
	authconfig->channeltype = channeltype;
}

/**
 * Get the channel type configuration option. See the AUTHCHANNEL enum in
 * authconfig.h for possible values.
 *
 * The default is to use a Rendezvous Point channel (AUTHCHANNEL_RVP).
 *
 * @param authconfig The object to get the value from.
 * @return The value.
 */
AUTHCHANNEL authconfig_get_channeltype(AuthConfig const * authconfig) {
	return authconfig->channeltype;
}

/**
 * Set the beacons configuration option. This should be set to true if
 * Blutooth invitations should be broadcast, false o/w.
 *
 * The default value is false.
 *
 * @param authconfig The object to set the value for.
 * @param beacons The value to set.
 */
void authconfig_set_beacons(AuthConfig * authconfig, bool beacons) {
	authconfig->beacons = beacons;
}

/**
 * Get the beacons configuration option. This will be set to true if
 * Blutooth invitations should be broadcast, false o/w.
 *
 * The default value is false.
 *
 * @param authconfig The object to get the value from.
 * @return The value.
 */
bool authconfig_get_beacons(AuthConfig const * authconfig) {
	return authconfig->beacons;
}

/**
 * Set the anyuser configuration option. This should be set to true if
 * the process will allow any user to authenticate, false if only the user
 * specified (by username) can authenticate.
 *
 * The default value is false.
 *
 * @param authconfig The object to set the value for.
 * @param anyuser The value to set.
 *
 */
void authconfig_set_anyuser(AuthConfig * authconfig, bool anyuser) {
	authconfig->anyuser = anyuser;
}

/**
 * Get the anyuser configuration option. This will be set to true if
 * the process will allow any user to authenticate, false if only the user
 * specified (by username) can authenticate.
 *
 * The default value is false.
 *
 * @param authconfig The object to get the value from.
 * @return authconfig The value.
 */
bool authconfig_get_anyuser(AuthConfig const * authconfig) {
	return authconfig->anyuser;
}

/**
 * Set the timeout configuration option. This should be set to 0 if
 * the process will stay in the authenticating state (waiting for a connection)
 * indefinitely. If set to a positive value, the authentication will eventually
 * timeout and return false (authentication failure).
 *
 * The default value is 0.
 *
 * @param authconfig The object to set the value for.
 * @param timeout The timeout duration in milliseconds.
 *
 */
void authconfig_set_timeout(AuthConfig * authconfig, float timeout) {
	authconfig->timeout = timeout;
}

/**
 * Get the timeout configuration option. This will be set to 0 if
 * the process will stay in the authenticating state (waiting for a connection)
 * indefinitely. If set to a positive value, the authentication will eventually
 * timeout and return false (authentication failure).
 *
 * The default value is 0.
 *
 * @param authconfig The object to get the value from.
 * @return The value.
 */
float authconfig_get_timeout(AuthConfig const * authconfig) {
	return authconfig->timeout;
}

/**
 * Set the Rendezvous Point URL configuration option. This should be set to
 * the full URL, including path, to use for the Rendezvous Point. The
 * randomly generated channel name will be appended to the end of this.
 *
 * For example, the standard URL is https://rendezvous.mypico.org/channel/
 * (note the trailing forward slash), which will create a channel along the
 * following lines.
 *
 * https://rendezvous.mypico.org/channel/6f4a12cb5a6f3e8974efab5c20900535
 *
 * The default value is:
 *
 * http://rendezvous.mypico.org/channel/
 *
 * @param authconfig The object to set the value for.
 * @param rvpurl The URL to use for the Rendezvous Point.
 *
 */
void authconfig_set_rvpurl(AuthConfig * authconfig, char const * rvpurl) {
	buffer_clear(authconfig->rvpurl);
	buffer_append_string(authconfig->rvpurl, rvpurl);
}

/**
 * Get the Rendezvous Point URL configuration option. This will be set to
 * the full URL, including path, to use for the Rendezvous Point. The
 * randomly generated channel name should be appended to the end of this.
 *
 * For example, the standard URL is https://rendezvous.mypico.org/channel/
 * (note the trailing forward slash), which will create a channel along the
 * following lines.
 *
 * https://rendezvous.mypico.org/channel/6f4a12cb5a6f3e8974efab5c20900535
 *
 * The default value is:
 *
 * http://rendezvous.mypico.org/channel/
 *
 * The returned buffer belongs to the AuthConfig instance; it should not be
 * freed or directly changed, except using authconfig_set_rvpurl();
 *
 * @param authconfig The object to get the value from.
 * @return The URL to use for the Rendezvous Point.
 *
 */
Buffer const * authconfig_get_rvpurl(AuthConfig const * authconfig) {
	return authconfig->rvpurl;
}

/**
 * Set the configuration directory option. This should be set to
 * the full path of the directory where the configuration files for this
 * service are stored. It should include a trailinig forward slash.
 *
 * Different services should be set to use different configuration directories,
 * and if so, they will act independently. The configuration directory holds
 * various cnofiguration files:
 *
 * 1. Service identity public key file: "pico_pub_key.der"
 * 2. Service identity private key file: "pico_priv_key.der"
 * 3. Users file with details of all paired users of the service: "users.txt"
 * 4. List of Bluetooth MACs to send beacons to: "bluetooth.txt"
 * 5. File to read the default configuration from: "config.txt"
 *
 * These files should be considered secret, and permissions should be set
 * accordingly.
 *
 * The default value is:
 *
 * "/etc/pam-pico/"
 *
 * @param authconfig The object to set the value for.
 * @param configdir The URL to use for the Rendezvous Point.
 *
 */
void authconfig_set_configdir(AuthConfig * authconfig, char const * configdir) {
	buffer_clear(authconfig->configdir);
	buffer_append_string(authconfig->configdir, configdir);
}

/**
 * Get the configuration directory option. This will be set to
 * the full path of the directory where the configuration files for this
 * service are stored. It includes the trailinig forward slash.
 *
 * Different services should be set to use different configuration directories,
 * and if so, they will act independently. The configuration directory holds
 * various cnofiguration files:
 *
 * 1. Service identity public key file: "pico_pub_key.der"
 * 2. Service identity private key file: "pico_priv_key.der"
 * 3. Users file with details of all paired users of the service: "users.txt"
 * 4. List of Bluetooth MACs to send beacons to: "bluetooth.txt"
 * 5. File to read the default configuration from: "config.txt"
 *
 * These files should be considered secret, and permissions should be set
 * accordingly.
 *
 * The default value is:
 *
 * "/etc/pam-pico/"
 *
 * @param authconfig The object to get the value from.
 * @return The path to use to load the local configuration files from.
 *
 */
Buffer const * authconfig_get_configdir(AuthConfig const * authconfig) {
	return authconfig->configdir;
}

/** @} addtogroup Service */

