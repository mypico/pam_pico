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
 * @brief Test the pico-continuous service by calling its dbus functions
 * @section DESCRIPTION
 *
 * For testing the Pico service. This creates a small, simple application
 * that can be used to call the pico-continuous service. the calls are
 * performed using dbus, alowing te full authentication process to be
 * performed.
 *
 * Once buit, just type ./pico-test to run. To change the authentication
 * parameters, edit the CONFIG and USERNAME preprocessor macros. The former
 * must be valid JSON, and the latter a string.
 *
 * The pico-test app uses libdbus, which is rather low level, but has the
 * benefits of not needing threding to work (in contrast to GDBus) and not
 * having potential security issus (in contrast to dbus-glib). Both properties
 * are important for the PAM implementation.
 *
 */

/** \addtogroup Testing
 *  @{
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <termios.h>
#include <getopt.h>
#include <syslog.h>
#include "pico/pico.h"
#include "pico/users.h"
#include "pico/auth.h"
#include "pico/displayqr.h"
#include "pico/keypairing.h"
#include "pico/sigmaverifier.h"
#include "pico/cryptosupport.h"
//#include <picobt/bt.h>
//#include <picobt/devicelist.h>
//#include <security/pam_appl.h>
//#include <security/pam_misc.h>
#include <dbus/dbus.h>

#include "log.h"

// Defines

#define MESSAGE_PRESS_ENTER "\nPress ENTER then scan the Pico QR code to login\n"

#define USERNAME "anyone"
#define CONFIG "{\"continuous\":1, \"channeltype\":\"bluetooth\", \"beacons\":1, \"anyuser\":1}"

// Structure definitions

typedef enum _MODE {
    MODE_JSON,
    MODE_ANSI,
    MODE_COLOR_UTF8,
    MODE_COLORLESS_UTF8
} MODE;

// Function prototypes

int notify_service_start_auth();
void notify_service_complete_auth(int handle);
char * convert_text_to_qr_code(const char * qrtext, MODE mode, bool tttag, bool requireInput);

// Function definitions

/**
 * Application entry point.
 *
 * @param argc The number of arguments provided
 * @param argv An array of pointers to the argument strings
 * @return Always returns 0
 */
int main(int argc, char * argv[]) {
	int handle;

	LOG(LOG_INFO, "Start\n");
	handle = notify_service_start_auth();
	LOG(LOG_INFO, "Complete\n");
	notify_service_complete_auth(handle);

	return 0;
}

/**
 * Converts qrtext to the text that should be printed in the terminal
 *
 * @param qrtext Text to be converted
 * @param mode Terminal mode
 * @param tttag The output will be wrapped with <tt>
 * @param requireInput The "Press enter" message will be included in the end
 *
 * @return Newly allocated memory containing the text
 */
char * convert_text_to_qr_code(const char * qrtext, MODE mode, bool tttag, bool requireInput) {
	Buffer * qrbuffer;
	DisplayQR * displayqr;
	char * return_text;
	int length;
	int current;

	syslog(LOG_INFO, "Generating text qr code");
	if (mode == MODE_ANSI) {
		displayqr = displayqr_new_params(QRMODE_ANSI);
	} else if (mode == MODE_COLORLESS_UTF8) {
		displayqr = displayqr_new_params(QRMODE_COLORLESS_UTF8);
	} else {
		displayqr = displayqr_new_params(QRMODE_COLOR_UTF8);
	}
	displayqr_generate(displayqr, qrtext);

	qrbuffer = displayqr_get_output(displayqr);
	// Allocate enough memory to store the QR code ASCII
	length = buffer_get_pos(qrbuffer);
	if (tttag) {
		length += 11; //"<tt>\n</tt>\n"
	}
	if (requireInput) {
		length += strlen(MESSAGE_PRESS_ENTER);
	}
	return_text = malloc(length + 1);
	current = 0;
	if (tttag) {
		strcpy(return_text, "<tt>\n");
		current += 5;
	}
	memcpy(return_text + current, buffer_get_buffer(qrbuffer), buffer_get_pos(qrbuffer));
	return_text[current + buffer_get_pos(qrbuffer)] = '\0';
	current += buffer_get_pos(qrbuffer);
	if (tttag) {
		strncat(return_text, "</tt>\n", length - current);
		current += 6;
	}
	if (requireInput) {
		// If we're requesting user input, add a message so the user is aware
		strncat(return_text, MESSAGE_PRESS_ENTER, length - current);
		current += strlen(MESSAGE_PRESS_ENTER);
	}
	return_text[length] = '\0';
	syslog(LOG_INFO, "%d %d", current, length);
	displayqr_delete(displayqr);

	return return_text;
}

/**
 * Ask the service to start an authentication process. The service will return
 * the invitation to be displayed as a QR code and the service's handle for the
 * authentication process.
 *
 * @return The service's handle for the authentication process.
 */
int notify_service_start_auth() {
	DBusConnection * connection;
	DBusMessage * msg;
	DBusMessage * reply;
	DBusError error = DBUS_ERROR_INIT;
	DBusMessageIter msg_iter;
	bool result;
	// Sent values
	char const * username = USERNAME;
	char const * parameters = CONFIG;
	// Returned values
	int handle;
	char const * code;
	dbus_bool_t success;


	result = true;
	msg = NULL;
	reply = NULL;
	handle = 0;
	LOG(LOG_INFO, "Getting dbus proxy for continuous auth server\n");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		LOG(LOG_ERR, "Unable to connect to D-Bus: %s\n", error.message);
		result = false;
	}
	
	if (result) {
		msg = dbus_message_new_method_call("uk.ac.cam.cl.pico.service", "/PicoObject", "uk.ac.cam.cl.pico.interface", "StartAuth");
		if (msg == NULL) {
			LOG(LOG_ERR, "Could not allocate memory for message\n");
			result = false;
		}
	}

	if (result) {
		dbus_message_iter_init_append(msg, &msg_iter);
		
		result = dbus_message_iter_append_basic(&msg_iter, DBUS_TYPE_STRING, &username);
		if (!result) {
			LOG(LOG_ERR, "Not enough memory to add parameter to message\n");
		}
	}

	if (result) {
		result = dbus_message_iter_append_basic(&msg_iter, DBUS_TYPE_STRING, &parameters);
		if (!result) {
			LOG(LOG_ERR, "Not enough memory to add parameter to message\n");
		}
	}
	
	if (result) {
		reply = dbus_connection_send_with_reply_and_block(connection, msg, DBUS_TIMEOUT_INFINITE, &error);

		if (reply == NULL) {
			LOG(LOG_ERR, "Error sending D-Bus message: %s: %s\n", error.name, error.message);
			result = false;
		}
	}
	
	if (result) {
		result = !dbus_set_error_from_message(&error, reply);
		if (!result) {
			LOG(LOG_ERR, "Error from D-Bus message: %s: %s\n", error.name, error.message);
			result = false;
		}
	}
	
	if (result) {
		result = dbus_message_get_args(reply, &error, DBUS_TYPE_INT32, &handle, DBUS_TYPE_STRING, &code, DBUS_TYPE_BOOLEAN, &success, DBUS_TYPE_INVALID);
		if (!result) {
			LOG(LOG_ERR, "Returned argument types are incorrect: %s: %s\n", error.name, error.message);
			result = false;
		}	
	}

	if (result) {
		LOG(LOG_INFO, "Result: %d\n", result);
		LOG(LOG_INFO, "Handle: %d\n", handle);
		LOG(LOG_INFO, "Code: %s\n", code);
		LOG(LOG_INFO, "Success: %d\n", success);

		char * qrcode = convert_text_to_qr_code(code, MODE_COLOR_UTF8, false, false);
		printf("%s\n", qrcode);
	}

	if (reply) {
		dbus_message_unref(reply);
		reply = NULL;
	}

	if (msg) {
		dbus_message_unref(msg);
		msg = NULL;
	}
	
	if (connection) {
		dbus_connection_unref(connection);
		connection = NULL;
	}
	
	dbus_error_free(&error);

	LOG(LOG_INFO, "Done\n");
	
	return handle;
}

/**
 * Ask the service for the result of the authentication process. This call will
 * block until the result is available.
 *
 * The handle is returned by notify_service_start_auth().
 *
 * @param handle The service's handle for the authentication process.
 */
void notify_service_complete_auth(int handle) {
	DBusConnection * connection;
	DBusMessage * msg;
	DBusMessage * reply;
	DBusError error = DBUS_ERROR_INIT;
	DBusMessageIter msg_iter;
	bool result;
	// Sent values
	// Returned values
	char const * username = "";
	char const * password = "";
	dbus_bool_t success;

	success = false;
	result = true;
	msg = NULL;
	reply = NULL;
	LOG(LOG_INFO, "Getting dbus proxy for continuous auth server\n");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		LOG(LOG_ERR, "Unable to connect to D-Bus: %s\n", error.message);
		result = false;
	}
	
	if (result) {
		msg = dbus_message_new_method_call("uk.ac.cam.cl.pico.service", "/PicoObject", "uk.ac.cam.cl.pico.interface", "CompleteAuth");
		if (msg == NULL) {
			LOG(LOG_ERR, "Could not allocate memory for message\n");
			result = false;
		}
	}

	if (result) {
		dbus_message_iter_init_append(msg, &msg_iter);
		
		result = dbus_message_iter_append_basic(&msg_iter, DBUS_TYPE_INT32, &handle);
		if (!result) {
			LOG(LOG_ERR, "Not enough memory to add parameter to message\n");
		}
	}

	if (result) {
		reply = dbus_connection_send_with_reply_and_block(connection, msg, DBUS_TIMEOUT_INFINITE, &error);

		if (reply == NULL) {
			LOG(LOG_ERR, "Error sending D-Bus message: %s: %s\n", error.name, error.message);
			result = false;
		}
	}
	
	if (result) {
		result = !dbus_set_error_from_message(&error, reply);
		if (!result) {
			LOG(LOG_ERR, "Error from D-Bus message: %s: %s\n", error.name, error.message);
			result = false;
		}
	}
	
	if (result) {
		result = dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &username, DBUS_TYPE_STRING, &password, DBUS_TYPE_BOOLEAN, &success, DBUS_TYPE_INVALID);
		if (!result) {
			LOG(LOG_ERR, "Returned argument types are incorrect: %s: %s\n", error.name, error.message);
			result = false;
		}	
	}

	if (result) {
		LOG(LOG_INFO, "Result: %d\n", result);
		LOG(LOG_INFO, "username: %s\n", username);
		//LOG(LOG_INFO, "password: %s\n", password);
		LOG(LOG_INFO, "password length: %lu\n", strlen(password));
		LOG(LOG_INFO, "Success: %d\n", success);
	}

	if (reply) {
		dbus_message_unref(reply);
		reply = NULL;
	}

	if (msg) {
		dbus_message_unref(msg);
		msg = NULL;
	}
	
	if (connection) {
		dbus_connection_unref(connection);
		connection = NULL;
	}
	
	dbus_error_free(&error);

	LOG(LOG_INFO, "Done\n");
}

/** @} addtogroup Testing */

