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
 * Derived from code written by Markus Gutschke and released under the Apache 
 * License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * @brief PAM to allow users to log in to a device using the Pico app
 * @section DESCRIPTION
 *
 * This PAM comminucates with the pico-continuous service via DBus to trigger
 * an authentication invitation. A code is returned from the service which is
 * displayed by this PAM as a QR code, which can be scanned by the Pico app.
 * Scanning the code triggers the authentication process to take place between
 * the service and the Pico app. The result is returned to this PAM, allowing
 * it to decide whether or not the user is adequately authenticated.
 *
 * The process, from the PAM's point of view therefore requires two steps.
 * First contact the service to initiate the authentication; the service
 * returns a QR code at this stage, which is displayed. Second, contact the
 * service to collect the result. A handle is returned by the service at the
 * first stage, which must then be sent by the PAM at the second stage to allow
 * the two requests to be associated with one another.
 *

 * Useful reference material:
 *
 * 1. The Linux-PAM Module Writers' Guide:
 *    http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_MWG.html
 * 2. The Linux-PAM Application Developers' Guide
 *    http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_ADG.html
 *
 */

/** \addtogroup PAM
 *  @{
 */

#include "config.h"

#include <string.h>
#include <pthread.h>
#include <assert.h>
#include "pico/pico.h"
#include "pico/displayqr.h"
#include "pico/json.h"
#include "pico/debug.h"
#include <dbus/dbus.h>

#include "log.h"

#ifdef HAVE_SYS_FSUID_H
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

// Defines

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

/**
 * @brief The name to use for the PAM
 *
 * This is the name used to identify the Pluggable Authentication Module.
 *
 */
#define MODULE_NAME "pam_pico"

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

/**
 * @brief Message to display to the user
 *
 * Message to print to indicate the user must hit ENTER to log in
 * This is needed for SSH login, which won't allow messages to
 * be displayed to the user without expect some response back from them
 */
#define MESSAGE_PRESS_ENTER "\nPress ENTER then scan the Pico QR code to login\n"

/**
 * @brief Set the configuration variable as unset
 *
 * Register the variable as having not been written to.
 *
 * This is defined as a macro so that it can remain untyped. It can be used
 * with BoolConfig, FloatConfig, StringConfig and IntConfig.
 *
 * @param CONFIG The config variable to clear.
 */
#define config_clear(CONFIG) (CONFIG)->is_set = false

/**
 * @brief Set the value of the configuration variable
 *
 * Set the variable and register it as having been written to.
 *
 * This is defined as a macro so that it can remain untyped. It can be used
 * with BoolConfig, FloatConfig, StringConfig and IntConfig.
 *
 * @param CONFIG The value to set the variable to.
 * @param VALUE The value to set the variable to.
 */
#define config_set(CONFIG, VALUE) (CONFIG)->is_set = true; (CONFIG)->value = (VALUE)

/**
 * @brief Check whether the configuration variable is set or not
 *
 * Check whether or not a particular variable has been written to.
 *
 * This is defined as a macro so that it can remain untyped. It can be used
 * with BoolConfig, FloatConfig, StringConfig and IntConfig.
 *
 * @param CONFIG The variable to check.
 * @return True if the variable has been written to; false o/w.
 */
#define config_is_set(CONFIG) ((CONFIG)->is_set)

/**
 * @brief Get the value of the configuration variable if it's been set
 *
 * Return the variable value. If the variable hasn't been set, the default
 * value provided will be returned instea.
 *
 * This is defined as a macro so that it can remain untyped. It can be used
 * with BoolConfig, FloatConfig, StringConfig and IntConfig.
 *
 * @param CONFIG The variable to check.
 * @param DEFAULT The value to return if the variable hasn't yet been set,
 * @return The value of the variable, or the default value if it hasn't yet
 *         been set.
 */
#define config_get(CONFIG, DEFAULT) ((CONFIG)->is_set ? (CONFIG)->value : (DEFAULT))

// Structure definitions

/**
 * @brief An enum representating all command line arguments
 *
 * Strings are hard to deal with; when considering command line arguments it's
 * easier to use an enum. This enum lists every command line argument that can
 * be added to the PAM.
 *
 * The actual arguments come in as strings, but can be converted to members of
 * this enum using the convert_to_enum() function.
 *
 */
typedef enum _ARG {
	ARG_INVALID = -1,

	ARG_CHANNELTYPE,
	ARG_CONTINUOUS,
	ARG_BEACONS,
	ARG_ANYUSER,
	ARG_QRTYPE,
	ARG_INPUT,
	ARG_TIMEOUT,
	ARG_RVPURL,
	ARG_CONFIGDIR,

	ARG_NUM
} ARG;

/**
 * @brief List of possible command line arguments
 *
 * This array lists all of the command line arguments that can be accepted.
 * Each element in the array should tally with a member of the ARG enum, and
 * they *must* be listed in the same order.
 *
 * Items proceeded by an "=" symbol are expected to have an additional
 * parameter following them. Items that don't end with an "=" must match
 * exactly, without any further parameter.
 *
 * The convert_to_enum() function can be used to convert these strings into
 * their respective ARG enum values.
 *
 */
static char const * const argstring[ARG_NUM] = {
	"channeltype=",
	"continuous=",
	"beacons=",
	"anyuser=",
	"qrtype=",
	"input=",
	"timeout=",
	"rvpurl=",
	"configdir=",
};

/**
 * @brief An enum representating a Boolean parameter for a command line argument
 *
 * Strings are hard to deal with; when considering command line arguments it's
 * easier to use an enum. This enum can be used to manage Boolean parameters
 * following a command line argument.
 *
 * The actual parameter comes in as a string, but can be converted to a member
 * of this enum using the convert_to_enum() function.
 *
 */
typedef enum _BOOLEAN {
	BOOLEAN_INVALID = -1,

	BOOLEAN_FALSE,
	BOOLEAN_TRUE,

	BOOLEAN_NUM
} BOOLEAN;

/**
 * @brief List of possible strings to use for Boolean command line parameters
 *
 * This array lists all of the strings that can be accepted for a command line
 * argument that takes a Boolean as a parameter.
 *
 * Each element in the array should tally with a member of the BOOLEAN
 * enum, and they *must* be listed in the same order.
 *
 * The convert_to_enum() function can be used to convert these strings into
 * their respective BOOLEAN enum values.
 *
 */
static char const * const booleanstring[BOOLEAN_NUM] = {
	"0",
	"1",
};

/**
 * @brief An enum representating all parameters to the "channeltype" argument
 *
 * Strings are hard to deal with; when considering command line arguments it's
 * easier to use an enum. This enum lists every parameter that will be accepted
 * following a "channeltype=" command line argument.
 *
 * The actual parameter comes in as a string, but can be converted to a member
 * of this enum using the convert_to_enum() function.
 *
 */
typedef enum _CHANNELTYPE {
	CHANNELTYPE_INVALID = -1,

	CHANNELTYPE_RVP,
	CHANNELTYPE_BTC,
	CHANNELTYPE_BLE,

	CHANNELTYPE_NUM
} CHANNELTYPE;

/**
 * @brief List of possible parameters following a "channeltype" argument
 *
 * This array lists all of the parameters that can be accepted directly
 * following a "channeltype" command line argument.
 *
 * Each element in the array should tally with a member of the CHANNELTYPE
 * enum, and they *must* be listed in the same order.
 *
 * Items proceeded by an "=" symbol are expected to have an additional
 * parameter following them. Items that don't end with an "=" must match
 * exactly, without any further parameter.
 *
 * The convert_to_enum() function can be used to convert these strings into
 * their respective CHANNELTYPE enum values.
 *
 */
static char const * const channeltypestring[CHANNELTYPE_NUM] = {
	"rvp",
	"btc",
	"ble",
};

/**
 * @brief An enum representating all parameters to the "qrtype" argument
 *
 * Strings are hard to deal with; when considering command line arguments it's
 * easier to use an enum. This enum lists every parameter that will be accepted
 * following a "qrtype=" command line argument.
 *
 * The actual parameter comes in as a string, but can be converted to a member
 * of this enum using the convert_to_enum() function.
 *
 */
typedef enum _QRTYPE {
	QRTYPE_INVALID = -1,

	QRTYPE_JSON,
	QRTYPE_COLORUTF8,
	QRTYPE_COLORLESSUTF8,
	QRTYPE_ANSI,
	QRTYPE_TTTAG,
	QRTYPE_NONE,

	QRTYPE_NUM
} QRTYPE;

/**
 * @brief List of possible parameters following a "qrtype" argument
 *
 * This array lists all of the parameters that can be accepted directly
 * following a "qrtype" command line argument.
 *
 * Each element in the array should tally with a member of the QRTYPE
 * enum, and they *must* be listed in the same order.
 *
 * Items proceeded by an "=" symbol are expected to have an additional
 * parameter following them. Items that don't end with an "=" must match
 * exactly, without any further parameter.
 *
 * The convert_to_enum() function can be used to convert these strings into
 * their respective QRTYPE enum values.
 *
 */
static char const * const qrtypestring[QRTYPE_NUM] = {
	"json",
	"color_utf8",
	"colorless_utf8",
	"ansi",
	"tt_tag",
	"none"
};

/**
 * @brief Output from the authentication start function
 *
 * This is a convenience structure used to return the output from the
 * notify_service_start_auth() function. It's used as a vector to return
 * multiple values from a single function.
 *
 * The data encapsulates the result of a request to the pico-continous service
 * via dbus to start an authentication process.
 *
 */
typedef struct _StartAuthResult {
	int handle;
	char * code;
	bool success;
} StartAuthResult;

/**
 * @brief Output from the authentication complete function
 *
 * This is a convenience structure used to return the output from the
 * notify_service_complete_auth() function. It's used as a vector to return
 * multiple values from a single function.
 *
 * The data encapsulates the result of a request to the pico-continuous service
 * via dbus for the result of the authentication process.
 *
 */
typedef struct _CompleteAuthResult {
	char * username;
	char * password;
	bool success;
} CompleteAuthResult;

/**
 * @brief Structure to hold the data that must be passed to the input thread
 *
 * When requesting keyboard input from the user, it can be convenient to do so
 * from a separate thread, to avoid the user prompt blocking the PAM code
 * (which could cause it to miss the result of the authentication dbus request).
 *
 * This data structure captures the data to be passed to the thread for
 * handling user keyboard input.
 *
 */
typedef struct _PromptThreadData {
	char * qrtext;
	pam_handle_t * pamh;
} PromptThreadData;

/**
 * @brief Boolean configuration value that can also take the value 'unset'
 *
 * A single Boolean config value that also registers if the variable has been
 * writen to yet.
 *
 * The macros config_clear(), config_set(), config_is_set() and config_get()
 * should be used to manipulate the data structure.
 *
 */
typedef struct _BoolConfig {
	bool is_set;
	bool value;
} BoolConfig;

/**
 * @brief Float configuration value that can also take the value 'unset'
 *
 * A single float config value that also registers if the variable has been
 * writen to yet.
 *
 * The macros config_clear(), config_set(), config_is_set() and config_get()
 * should be used to manipulate the data structure.
 *
 */
typedef struct _FloatConfig {
	bool is_set;
	float value;
} FloatConfig;

/**
 * @brief String configuration value that can also take the value 'unset'
 *
 * A null-terminated char array config value that also registers if the
 * variable has been writen to yet.
 *
 * The macros config_clear(), config_set(), config_is_set() and config_get()
 * should be used to manipulate the data structure.
 *
 */
typedef struct _StringConfig {
	bool is_set;
	char const * value;
} StringConfig;

/**
 * @brief Integer configuration value that can also take the value 'unset'
 *
 * A single integer config value that also registers if the variable has been
 * writen to yet.
 *
 * The macros config_clear(), config_set(), config_is_set() and config_get()
 * should be used to manipulate the data structure.
 *
 */
typedef struct _IntConfig {
	bool is_set;
	int value;
} IntConfig;

/**
 * @brief Structure containing config values to be passed to the service via dbus
 *
 * When the PAM interacts with the pico-continuous service, it can pass in
 * configuration options, which override the values stored in the config.txt
 * file, which themselves override the default values.
 *
 * This data structure contains all of the variables that make up the
 * configuration options sent to the service for each authentication.
 *
 * The data is set from the command line parameters used when executing the
 * PAM (usually passed in through using one of the configuration files stored
 * in the /etc/pam.d directory). This data is then sent to the service via dbus
 * as a JSON string. The values are converted to this JSON string using the
 * externalconfig_generate_json() function.
 *
 * The data structure is intialised using externalconfig_new() and released
 * using externalconfig_delete().
 *
 */
typedef struct _ExternalConfig {
	IntConfig channeltype;
	BoolConfig continuous;
	BoolConfig beacons;
	BoolConfig anyuser;
	FloatConfig timeout;
	StringConfig rvpurl;
	StringConfig configdir;
} ExternalConfig;

// Function prototypes

static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message, struct pam_response **response);
void prompt(pam_handle_t *pamh, int style, PAM_CONST char *prompt);
void * thread_input(void * t);
char * convert_text_to_qr_code(const char * qrtext, QRTYPE mode, bool requireInput);
bool pam_auth(pam_handle_t *pamh, ExternalConfig * externalconfig, QRTYPE mode, bool requestInput);
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);
const char * get_user_name(pam_handle_t * pamh);
StartAuthResult * notify_service_start_auth(char const * username, char const * parameters);
CompleteAuthResult * notify_service_complete_auth(int handle);
ExternalConfig * externalconfig_new();
void externalconfig_delete(ExternalConfig * externalconfig);
void externalconfig_generate_json(ExternalConfig * externalconfig, Buffer * json);

// Function definitions

/**
 * Calls the PAM conversation function. This is the feedback callback provided 
 * by the client application for communicating with it.
 *
 * @param pamh The handle provided by PAM
 * @param nargs The number of messages to send (usually 1)
 * @param message The message to be displayed by the client
 * @param response Pointer to a struct pam_response array that the response(s) 
 *                 will be returned using
 * @return One of PAM_BUF_ERR (memory buffer error), PAM_CONV_ERR (conversation
 *         failure) or PAM_SUCCESS (success!)
 */
static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message, struct pam_response **response) {
	struct pam_conv *conv;
	int retval;

	// Retrieve the conversation callback
	retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	// Call the conversation callback and return the result
	return conv->conv(nargs, message, response, conv->appdata_ptr);
}

/**
 * Prompt the user via the client application, by invoking the client
 * applications conversation callback. Messages can either expect a
 * response from the user, or be entirely informational (no response 
 * expected).
 *
 * @param pamh The handle provided by PAM
 * @param style One of either PAM_PROMPT_ECHO_OFF or PAM_PROMPT_TEXT_INFO
 * @param prompt The message text to display to the user
 */
void prompt(pam_handle_t *pamh, int style, PAM_CONST char *prompt) {
	// Display QR code
	struct pam_message message;
	PAM_CONST struct pam_message *msgs = &message;
	struct pam_response *resp = NULL;
	int retval;

	// Set up the message structure
	message.msg_style = style;
	message.msg = prompt;

	// Call our wrapper to the conversation function
	retval = converse(pamh, 1, &msgs, &resp);
	if (retval != PAM_SUCCESS) {
	  LOG(LOG_WARNING, "Converse returned failure %d.", retval);
	}

	// Deallocate temporary storage
	if (resp) {
		if (resp->resp) {
			FREE(resp->resp);
		}
		FREE(resp);
	}
}

/**
 * Function for invoking a thread for receiving a user response.
 *
 * Some kind of bug (feature?) in SSH means that PAM modules can't offer
 * information to the user without the user being asked to type in a response.
 * Consequently, if we want the QR code to be displayed, we have to ask the
 * user to interact with the keyboard (hitting ENTER is the simplest we can
 * make it).
 * Since both the Pico protocol thread and the PAM user interaction thread are 
 * blocking while waiting for a response from the Pico or user, it's
 * convenient to run the two requests on separate threads, rather than run them 
 * in serial. We could run them in serial, but then the user would be required
 * to interact in a given order (scan then hit ENTER, or vice versa). If we run
 * them in parallel, the user can complete the tasks in either order. Sadly 
 * we can't go one further and not require the user to hit ENTER at all (see
 * the above reference to bugs).
 *
 * This is practical because neither thread needs to interact with one another,
 * since only the Pico protocol thread is actually important. We don't care
 * how the user response via the keyboard, we just need them to do it.
 *
 * We only need to do this for SSH, because it requires user input. Did I
 * mention bugs?
 *
 * @param t The data provided to the thread from its invoker
 * @return NULL
 */
void * thread_input(void * t) {
	PromptThreadData * promptthreaddata = (PromptThreadData *)t;

	prompt(promptthreaddata->pamh, PAM_PROMPT_ECHO_OFF, promptthreaddata->qrtext);
	pthread_exit(NULL);

	return NULL;
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
char * convert_text_to_qr_code(const char * qrtext, QRTYPE mode, bool requireInput) {
	Buffer * qrbuffer;
	DisplayQR * displayqr;
	char * return_text;
	int length;
	int current;

	LOG(LOG_INFO, "Generating text QR code");
	if (mode == QRTYPE_ANSI) {
		displayqr = displayqr_new_params(QRMODE_ANSI);
	}
	else if (mode == QRTYPE_COLORLESSUTF8) {
		displayqr = displayqr_new_params(QRMODE_COLORLESS_UTF8);
	}
	else {
		displayqr = displayqr_new_params(QRMODE_COLOR_UTF8);
	}
	displayqr_generate(displayqr, qrtext);
	
	// Allocate enough memory to store the QR code ASCII
	qrbuffer = displayqr_get_output(displayqr);
	length = buffer_get_pos(qrbuffer);
	if (mode == QRTYPE_TTTAG) {
		// Add length required to include "<tt>\n</tt>\n" (the actual strings are added later)
		length += 11;
	}
	if (requireInput == TRUE) {
		length += strlen(MESSAGE_PRESS_ENTER);
	}
	return_text = MALLOC(length + 1);
	current = 0;
	if (mode == QRTYPE_TTTAG) {
		strcpy(return_text, "<tt>\n");
		current += 5;
	}
	memcpy(return_text + current, buffer_get_buffer(qrbuffer), buffer_get_pos(qrbuffer));
	return_text[current + buffer_get_pos(qrbuffer)] = '\0';
	current += buffer_get_pos(qrbuffer);
	if (mode == QRTYPE_TTTAG) {
		strncat(return_text, "</tt>\n", length - current);
		current += 6;
	}
	if (requireInput == TRUE) {
		// If we're requesting user input, add a message so the user is aware
		strncat(return_text, MESSAGE_PRESS_ENTER, length - current);
		current += strlen(MESSAGE_PRESS_ENTER);
	}
	return_text[length] = '\0';
	displayqr_delete(displayqr);
	assert(length == current);

	return return_text;
}

/**
 * Convert a null-terminated string to an enum value. This function essentially
 * accepts a string and an array of strings, and returns the index of the string
 * into the array if it's there.
 *
 * The function is tailored for use with command line arguments. If an element
 * in the array is proceeded by an "=" character, then the check will match
 * the string up to and including the "=", returning the index as well as a
 * pointer to the string following the "=" character. This is useful for
 * command line arguments that take parameters of the form "arg=value".
 *
 * In the case where the element in the array is not proceeded by an "="
 * character, then the strings must match exactly.
 *
 * The array of strings to be searched through should be in the same order as
 * the enum values, to ensure the index returned relates correctly to the
 * enum.
 *
 * @param stringlist An array of strings to search for the argument within.
 * @param listlength The number of elements in the array.
 * @param start The start of the null-terminated string to search for.
 *        Typically this would be a command line argument argv[num].
 * @param remainder If this is non-NULL, this will be filled out with a
 *        pointer to the parameter following the argument. If the argument
 *        isn't in the array, this will be set to start.
 * @return The index of the string into the array (corresponding to the enum
 *         value), or -1 if the string could not be found.
 */
int convert_to_enum(char const * const * stringlist, int listlength, char const * start, char const ** remainder) {
	int count;
	char const * pos;
	int found;
	bool prefix;
	bool match;
	int length;
	char const * tail;

	found = -1;
	tail = start;
	for (count = 0; (count < listlength) && (found == -1); count++) {
		pos = stringlist[count];
		length = strlen(pos);
		prefix = ((length > 0) ? (pos[length - 1] == '=') : false);

		match = (prefix ? strncmp(pos, start, length) : strcmp(pos, start)) == 0;
		if (match) {
			found = count;
			tail = start + length;
		}
	}

	if (remainder != NULL) {
		*remainder = tail;
	}

	return found;
}

/**
 * Constructor for allocating and initialising an ExternalConfig data structure.
 *
 * @return The newly created ExternalConfig data structure.
 */
ExternalConfig * externalconfig_new() {
	ExternalConfig * externalconfig;

	externalconfig = CALLOC(sizeof(ExternalConfig), 1);

	config_clear(& externalconfig->channeltype);
	config_clear(& externalconfig->continuous);
	config_clear(& externalconfig->beacons);
	config_clear(& externalconfig->anyuser);
	config_clear(& externalconfig->timeout);
	config_clear(& externalconfig->rvpurl);
	config_clear(& externalconfig->configdir);

	return externalconfig;
}

/**
 * Destructor for deallocating an ExternalConfig data structure.
 *
 * @param externalconfig The data structure to destroy.
 */
void externalconfig_delete(ExternalConfig * externalconfig) {
	if (externalconfig) {
		FREE(externalconfig);
	}
}

/**
 * Convert an ExternalConfig data structure into a JSON string. An important
 * characteristic of the JSON is that it will only contain values that have
 * been explicitly set to true or false.
 *
 * @param externalconfig The config file to convert.
 * @param json A buffer to contain the output JSON string.
 */
void externalconfig_generate_json(ExternalConfig * externalconfig, Buffer * json) {
	Json * parameters;
	bool is_set;
	bool value;
	float decimal;
	int integer;
	char const * string;

	parameters = json_new();

	is_set = config_is_set(& externalconfig->continuous);
	if (is_set) {
		value = config_get(& externalconfig->continuous, false);
		json_add_integer(parameters, "continuous", (value ? 1 : 0));
	}

	is_set = config_is_set(& externalconfig->channeltype);
	if (is_set) {
		integer = config_get(& externalconfig->channeltype, CHANNELTYPE_RVP);
		switch (integer) {
		case CHANNELTYPE_RVP:
			json_add_string(parameters, "channeltype", "rvp");
			break;
		case CHANNELTYPE_BTC:
			json_add_string(parameters, "channeltype", "btc");
			break;
		case CHANNELTYPE_BLE:
			json_add_string(parameters, "channeltype", "ble");
			break;
		default:
			// Do nothing
			break;
		}
	}

	is_set = config_is_set(& externalconfig->beacons);
	if (is_set) {
		value = config_get(& externalconfig->beacons, false);
		json_add_integer(parameters, "beacons", (value ? 1 : 0));
	}

	is_set = config_is_set(& externalconfig->anyuser);
	if (is_set) {
		value = config_get(& externalconfig->anyuser, false);
		json_add_integer(parameters, "anyuser", (value ? 1 : 0));
	}

	is_set = config_is_set(& externalconfig->timeout);
	if (is_set) {
		decimal = config_get(& externalconfig->timeout, 40.0);
		json_add_decimal(parameters, "timeout", decimal);
	}
	is_set = config_is_set(& externalconfig->rvpurl);
	if (is_set) {
		string = config_get(& externalconfig->rvpurl, URL_PREFIX);
		json_add_string(parameters, "rvpurl", string);
	}

	is_set = config_is_set(& externalconfig->configdir);
	if (is_set) {
		string = config_get(& externalconfig->configdir, CONFIG_DIR);
		json_add_string(parameters, "configdir", string);
	}

	json_serialize_buffer(parameters, json);
	json_delete(parameters);
}

/**
 * Service function for user authentication.
 * This is the service module's implementation of the pam_authenticate(3)
 * interface.
 *
 * @param pamh The handle provided by PAM
 * @param flags Flags, potentially Or'd with PAM_SILENT.
 *              PAM_SILENT (do not emit any messages),
 *              PAM_DISALLOW_NULL_AUTHTOK (return PAM_AUTH_ERR if the database
 *              of authentication tokens has a NULL entry for this user
 * @param argc Number of PAM module arguments
 * @param argv Array of pointers to the arguments
 * @return PAM_AUTH_ERR (authentication failure),
 *         PAM_SUCCESS (athentication success)
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int rc;
	bool result;
	bool requestInput;
	ExternalConfig * externalconfig;
	ARG arg;
	int count;
	char const * remainder;
	CHANNELTYPE channeltype;
	BOOLEAN boolean;
	float decimal;
	QRTYPE mode;

	LOG(LOG_INFO, "Starting authentication");

	externalconfig = externalconfig_new();

	LOG(LOG_INFO, "%d arguments received.", argc);
	rc = PAM_AUTH_ERR;
	result = false;
	requestInput = false;
	mode = QRTYPE_COLORUTF8;

	for (count = 0; count < argc; count++) {
		arg = convert_to_enum(argstring, ARG_NUM, argv[count], & remainder);

		switch (arg) {
		case ARG_CHANNELTYPE:
			channeltype = convert_to_enum(channeltypestring, CHANNELTYPE_NUM, remainder, NULL);
			if (channeltype != CHANNELTYPE_INVALID) {
				LOG(LOG_INFO, "Setting channel type to %d", channeltype);
				config_set(& externalconfig->channeltype, channeltype);
			}
			break;
		case ARG_CONTINUOUS:
			boolean = convert_to_enum(booleanstring, BOOLEAN_NUM, remainder, NULL);
			if (boolean != BOOLEAN_INVALID) {
				LOG(LOG_INFO, "Setting continuous %s", (boolean == BOOLEAN_TRUE ? "on" : "off"));
				config_set(& externalconfig->continuous, boolean);
			}
			break;
		case ARG_BEACONS:
			boolean = convert_to_enum(booleanstring, BOOLEAN_NUM, remainder, NULL);
			if (boolean != BOOLEAN_INVALID) {
				LOG(LOG_INFO, "Setting beacons %s", (boolean == BOOLEAN_TRUE ? "on" : "off"));
				config_set(& externalconfig->beacons, boolean);
			}
			break;
		case ARG_ANYUSER:
			boolean = convert_to_enum(booleanstring, BOOLEAN_NUM, remainder, NULL);
			if (boolean != BOOLEAN_INVALID) {
				LOG(LOG_INFO, "Setting anyuser %s", (boolean == BOOLEAN_TRUE ? "on" : "off"));
				config_set(& externalconfig->anyuser, boolean);
			}
			break;
		case ARG_QRTYPE:
			mode = convert_to_enum(qrtypestring, QRTYPE_NUM, remainder, NULL);
			LOG(LOG_INFO, "Setting QR code type to %d", mode);
			break;
		case ARG_INPUT:
			boolean = convert_to_enum(booleanstring, BOOLEAN_NUM, remainder, NULL);
			if (boolean != BOOLEAN_INVALID) {
				LOG(LOG_INFO, "Setting input %s", (boolean == BOOLEAN_TRUE ? "on" : "off"));
				requestInput = boolean;
			}
			break;
		case ARG_TIMEOUT:
			sscanf(remainder, "%f", & decimal);
			LOG(LOG_INFO, "Setting timeout of %f seconds", decimal);
			config_set(& externalconfig->timeout, decimal);
			break;
		case ARG_RVPURL:
			LOG(LOG_INFO, "Setting rvp url to %s", remainder);
			config_set(& externalconfig->rvpurl, remainder);
			break;
		case ARG_CONFIGDIR:
			LOG(LOG_INFO, "Setting config dir to %s", remainder);
			config_set(& externalconfig->configdir, remainder);
			break;
		default:
			LOG(LOG_ERR, "Unknown argument \"%s\"", argv[count]);
			break;
		}
	}

	result = pam_auth(pamh, externalconfig, mode, requestInput);

	externalconfig_delete(externalconfig);

	rc = (result ? PAM_SUCCESS : PAM_AUTH_ERR);
	LOG(LOG_INFO, "Auth result %s\n", (result ? "PAM_SUCCESS" : "PAM_AUTH_ERR"));

	return rc;
}

/**
 * The main Pico authentication proccess. Requests the client application
 * to display a QR code, then performs the Pico protocol via a Rendezvous
 * Point channel with Pico.
 *
 * @param pamh The handle provided by PAM
 * @param An external config structure containing the values to sent to the
 *        pico-continuous servive.
 * @param mode Changes the way the qrcode is displayed to the user
 * @param requestInput True if input should be requested from user (which may
 *        be required by some faulty PAM client implementations).
 * @return true if authentication was successful, false o/w
 */
bool pam_auth(pam_handle_t * pamh, ExternalConfig * externalconfig, QRTYPE mode, bool requestInput) {
	bool result;
	char * qrtext;
	int threadResult;
	pthread_t threadInput;
	pthread_attr_t threadAttr;
	void * threadStatus;
	PromptThreadData promptthreaddata;
	char const * username;
	StartAuthResult * startauthresult;
	CompleteAuthResult * completeauthresult;
	Buffer * parameters;
	bool anyuser;
	int length;

	completeauthresult = NULL;
	anyuser = config_get(& externalconfig->anyuser, false);

	parameters = buffer_new(0);
	externalconfig_generate_json(externalconfig, parameters);

	username = get_user_name(pamh);
	LOG(LOG_INFO, "Authenticating for user %s", username);

	startauthresult = notify_service_start_auth(username, buffer_get_buffer(parameters));
	result = startauthresult->success;

	buffer_delete(parameters);
	qrtext = NULL;

	if (result) {
		// Prepare the QR code to be displayed to the user
		switch (mode) {
		case QRTYPE_NONE:
			qrtext = MALLOC(1);
			qrtext[0] = '\0';
			break;
		case QRTYPE_JSON:
			length = strlen(startauthresult->code);
			qrtext = MALLOC(length + 1);
			memcpy(qrtext, startauthresult->code, length + 1);
			break;
		default:
			qrtext = convert_text_to_qr_code(startauthresult->code, mode, requestInput);
			break;
		}

		LOG(LOG_ERR, "Pam Pico Pre Prompt");

		if (requestInput) {
			// Initialise thread to ensure we can force it to rejoin
			pthread_attr_init(& threadAttr);
			pthread_attr_setdetachstate(& threadAttr, PTHREAD_CREATE_JOINABLE);

			promptthreaddata.qrtext = qrtext;
			promptthreaddata.pamh = pamh;

			// Invoke the use input thread
			threadResult = pthread_create(& threadInput, & threadAttr, thread_input, (void *)&promptthreaddata);
			if (threadResult != 0) {
				LOG(LOG_ERR, "Error creating thread: %d\n", threadResult);
			}
			pthread_attr_destroy(& threadAttr);
		}
		else {
			// Display the QR code via the client's PAM conversation callback
			prompt(pamh, PAM_TEXT_INFO, qrtext);
		}

		LOG(LOG_ERR, "Pam Pico Post Prompt");

		// Perform the Pico authentication protocol
		completeauthresult = notify_service_complete_auth(startauthresult->handle);
		result = completeauthresult->success;

		LOG(LOG_INFO, "Pam Pico result %d", result);
	}

	if (result) {
		if (anyuser) {
			LOG(LOG_INFO, "Setting user %s", completeauthresult->username);
			pam_set_item(pamh, PAM_USER, completeauthresult->username);
		}

		pam_set_item(pamh, PAM_AUTHTOK, completeauthresult->password);

		if (requestInput) {
			// Wait for the user input thread to complete before proceeding
			threadResult = pthread_join(threadInput, & threadStatus);
			if (threadResult != 0) {
				LOG(LOG_ERR, "Error joining thread: %d\n", threadResult);
			}
		}

		if (qrtext) {
			FREE(qrtext);
		}
	}

	// Clean up
	if (startauthresult) {
		FREE(startauthresult->code);
		FREE(startauthresult);
	}
	if (completeauthresult) {
		FREE(completeauthresult->username);
		FREE(completeauthresult->password);
		FREE(completeauthresult);
	}

	// Return result: true if authentication was successful, false o/w
	return result;
}

/**
 * Service function to alter credentials.
 * This function performs the task of altering the credentials of the user
 * with respect to the corresponeding authorization scheme.
 *
 * @param pamh The handle provided by PAM
 * @param flags Flags, potentially OR'd with PAM_SILENT.
 *              PAM_SILENT (do not emit any messages),
 *              PAM_ESTABLISH_CRED (initialize the credentials for the user),
 *              PAM_DELETE_CRED (delete the credentials associated with the
 *              authentication service),
 *              PAM_REINITIALIZE_CRED (reinitialize the user credentials),
 *              PAM_REFRESH_CRED (extend the lifetime of the user credentials)
 * @param argc Number of PAM module arguments
 * @param argv Array of pointers to the arguments
 * @return PAM_CRED_UNAVAIL (this module cannot retrieve the user's
 *         credentials),
 *         PAM_CRED_EXPIRED (the user's credentials have expired),
 *         PAM_CRED_ERR (this module was unable to set the crednetials for the
 *         user),
 *         PAM_SUCCESS (the user credential was successfully set),
 *         PAM_USER_UNKNOWN (the user is not known to this authentication
 *         module)
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

/**
 * Obtain the username from the PAM module.
 * This code was adapted frrom Google Authenticator (Apache License, Version 
 * 2.0): https://github.com/google/google-authenticator
 *
 * @param pamh The handle provided by PAM
 * @return Buffer (that shouldn't be freed) containing the user's username
 */
const char * get_user_name(pam_handle_t * pamh) {
	const char * username;
	int result;

	// Obtain the user's name
	result = pam_get_user(pamh, & username, NULL);
	if ((result != PAM_SUCCESS) || (username == NULL)) {
		LOG(LOG_ERR, "pam_get_user() failed to get a user name");
		username = NULL;
	}

	return username;
}

/**
 * Ask the service to start an authentication process. The service will return
 * the invitation to be displayed as a QR code and the service's handle for the
 * authentication process.
 *
 * @return The service's handle for the authentication process.
 */
StartAuthResult * notify_service_start_auth(char const * username, char const * parameters) {
	DBusConnection * connection;
	DBusMessage * msg;
	DBusMessage * reply;
	DBusError error = DBUS_ERROR_INIT;
	DBusMessageIter msg_iter;
	bool result;
	// Sent values
	//char const * username = USERNAME;
	//char const * parameters = CONFIG;
	// Returned values
	int handle;
	char const * code;
	dbus_bool_t success;
	StartAuthResult * startauthresult;

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

	startauthresult = CALLOC(sizeof(StartAuthResult), 1);
	startauthresult->success = success;

	if (result) {
		startauthresult->code = CALLOC(sizeof(char), strlen(code) + 1);
		strcpy(startauthresult->code, code);

		startauthresult->handle = handle;

		//LOG(LOG_INFO, "Result: %d\n", result);
		//LOG(LOG_INFO, "Handle: %d\n", handle);
		//LOG(LOG_INFO, "Code: %s\n", code);
		LOG(LOG_INFO, "Authentication start result: %d\n", success);
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

	return startauthresult;
}

/**
 * Ask the service for the result of the authentication process. This call will
 * block until the result is available.
 *
 * The handle is returned by notify_service_start_auth().
 *
 * @param handle The service's handle for the authentication process.
 */
CompleteAuthResult * notify_service_complete_auth(int handle) {
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
	CompleteAuthResult * completeauthresult;

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

	completeauthresult = CALLOC(sizeof(CompleteAuthResult), 1);
	completeauthresult->success = success;

	if (result) {
		completeauthresult->username = CALLOC(sizeof(char), strlen(username) + 1);
		strcpy(completeauthresult->username, username);

		completeauthresult->password = CALLOC(sizeof(char), strlen(password) + 1);
		strcpy(completeauthresult->password, password);

		//LOG(LOG_INFO, "Result: %d\n", result);
		//LOG(LOG_INFO, "username: %s\n", username);
		//LOG(LOG_INFO, "password: %s\n", password);
		//LOG(LOG_INFO, "password length: %lu\n", strlen(password));
		LOG(LOG_INFO, "Authentication success: %d\n", success);
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

	return completeauthresult;
}

/**
 * @brief Provide details of the module and callbacks
 *
 * A standard data structure required by the PAM to provide details of the
 * module and the callbacks which the PAM authentication library should use
 * when interacting with this PAM.
 *
 */
#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif

/** @} addtogroup PAM */

