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
 * @brief Allow the Pico app to pair with a device
 * @section DESCRIPTION
 *
 * An application for pairing a Pico with a device, allowing the Pico to then
 * authenticate to the pam-pico module.
 *
 * The application requires a username to be provided (unless it's executed 
 * setuid, in which case the ruid will be used). Once the Pico has been paired,
 * the username will be stored in the pam-pico configuration file
 * /etc/pam-pico/users.txt alongside its public key to support future
 * authentication requires via the pam module.
 * 
 */

/** \addtogroup Pairing
 *  @{
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <termios.h>
#include <getopt.h>
#include <url-dispatcher.h>
#include "pico/debug.h"
#include "pico/pico.h"
#include "pico/users.h"
#include "pico/auth.h"
#include "pico/displayqr.h"
#include "pico/keypairing.h"
#include "pico/sigmaverifier.h"
#include "pico/cryptosupport.h"
#include "pico/feedback.h"
#include "pico/json.h"
#include <picobt/bt.h>
#include <picobt/devicelist.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <gtk/gtk.h>
#include <qrencode.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

// Defines

#define PUB_FILE "pico_pub_key.der"
#define PRIV_FILE "pico_priv_key.der"
#define USERS_FILE "users.txt"
#define BT_ADDRESS_FILE "bluetooth.txt"
#define LOCK_FILE ".lock"

// This should now be defined by the automake file
#ifndef PICOKEYDIR
#define PICOKEYDIR "/etc/pam-pico"
#endif

#define USERNAME_MAX (256)
#define PASSWORD_MAX USERNAME_MAX
#define PASSWD_BUF_SIZE 1024
#define MAX_BT_DEVICES (32)
#define PICO_SERVICE_UUID "ed995e5a-c7e7-4442-a6ee-7bb76df43b0d"

#define QR_SCALE (6)
#define QR_BORDER (4)

// Structure definitions

typedef struct _GuiData {
	bool scancomplete;
	GtkBuilder * xml;
	GString * username;
	GString * password;
	GString * hostname;
	Shared * shared;
	RVPChannel * channel;
	Buffer * extraDataBuffer;
	Buffer * password_ciphertext;
	int verbose;
	GString * code;
	Users * users;
	Buffer * symmetric_key;
	bt_device_list_t * device_list;
	GtkWidget * cancel;
	bool keypressed;
	GString * datadir;
	GString * keydir;
	bool result;
} GuiData;

// Function prototypes

void help();
bool create_config_dir(char const * keydir);
char * config_file_full_path(char const * root, char const * leaf);
bool check_user_password(char const * user, char const * pass);
void set_echo(bool enable);
bool show_qr_code(char * qrtext, void * localdata);
bool feedback_trigger(Feedback const * feedback, void * data);
bool command_line(char const * username, char const * hostname, int verbose, char const * keydir);
bool gui(char const * username, char const * hostname, int verbose, char const * keydir, char const * datadir, int argc, char * argv[]);
static gboolean key_press(GtkWidget * widget, gpointer data);
static gint next_page(gint current_page, gpointer data);
bool check_user(GuiData * gui_data);
GuiData * guidata_new();
void guidata_delete(GuiData * gui_data);
bool gui_pair_setup(GuiData * gui_data);
bool gui_pair_complete(GuiData * gui_data, Buffer * returned_stored_data);
void set_qr_code(GuiData * gui_data);
void * thread_start_pair(void * t);
void trigger_pair_thread(GuiData * gui_data);
static void prepare (GtkAssistant * assistant, GtkWidget * page, gpointer user_data);
char * set_string_if_null(char * string, char const * default_string);
gboolean pairing_complete (gpointer user_data);
static gboolean check_write_keydir(char const * keydir);
static gboolean open_settings(GtkWidget * widget, gpointer data);
static bool check_desktop_executable(char const * desktop, char const * executable);
static void execute_command (char const * cmd);
static gboolean set_permissions_keydir(char const * keydir);

// Function definitions

/**
 * Application entry point.
 *
 * This reads in the command line parameters, then executes either the command
 * line or GUI version depending on which was requested.
 *
 * @param argc The number of arguments provided
 * @param argv An array of pointers to the argument strings
 * @return Always returns 0
 */
int main(int argc, char * argv[]) {
	bool result;
	char * username;
	uid_t uid;
	struct passwd * pw_struct;
	char hostname[HOST_NAME_MAX + 1];
	int hostnameresult;
	int c;
	int verbose;
	int option_index;
	bool use_gui;
	char * datadir;
	char * keydir;

	// Parse arguments
	static struct option long_options[] = {
		{"user", required_argument, 0, 'u'},
		{"verbose", no_argument, 0, 'v'},
		{"gui", no_argument, 0, 'g'},
		{"datadir", required_argument, 0, 'd'},
		{"keydir", required_argument, 0, 'k'},
		{0, 0, 0, 0}
	};

	username = NULL;
	verbose = 1;
	use_gui = false;
	datadir = NULL;
	keydir = NULL;
	for (option_index = 0; c != -1;) {
		opterr = 0;
		c = getopt_long (argc, argv, "bu", long_options, &option_index);
		
		switch (c) {
			case 'u':
				username = strdup(optarg);
				break;
			case 'v':
				verbose = 2;
				break;
			case 'g':
				use_gui = true;
				break;
			case 'd':
				datadir = strdup(optarg);
				break;
			case 'k':
				keydir = strdup(optarg);
				break;
			case -1:
				// Do nothing
				break;
			default:
				help();
				exit(EXIT_FAILURE);
		};
	}

	datadir = set_string_if_null(datadir, PICOPAIRDIR);
	keydir = set_string_if_null(keydir, PICOKEYDIR);

	// If bluetooth, perform and send qrtext through bluetooth
	result = true;

	// The hostname is used as the name for pairing the Pico with
	hostnameresult = gethostname(hostname, HOST_NAME_MAX + 1);
	if (hostnameresult != 0) {
		result = false;
	}

	if (result == true) {
		// Establish the username, which will either be provided on the
		// command line, or available using getuid(), depending on whether
		// the application is being run with setuid or not.
		if (username == NULL) {
			uid = getuid();
			pw_struct = getpwuid(uid);
			if (pw_struct) {
				username = strdup(pw_struct->pw_name);
			}
			else {
				result = false;
			}
		}
	}
	username = set_string_if_null(username, "");

	if (result == true) {
		// Create the config file directory if it doesn't already exist
		// This is /etc/pam-pico by default.
		result = create_config_dir(keydir);
	}
	
	if (result == true) {
		if (use_gui) {
			result = gui(username, hostname, verbose, keydir, datadir, argc, argv);
		}
		else {
			result = command_line(username, hostname, verbose, keydir);
		}
	}

	free(username);
	free(datadir);
	free(keydir);

	return (result ? 0 : -1);
}

/**
 * If the string passed in is allocated (non-NULL), simply return the same
 * string; otherwise allocate a new string and copy the default_string into it.
 * In the latter case the resulting heap-allocated string is owned by the
 * caller, so should be free-d at some later stage.
 *
 * @param string The string to use if it exists.
 * @param string The value to copy if the string is not allocated.
 * @return Either the original string, or a newly allocated copy of the default
 *         string if the original string was NULL.
 */
char * set_string_if_null(char * string, char const * default_string) {
	char * result;

	if (string == NULL) {
		result = strdup(default_string);
	}
	else {
		result = string;
	}

	return result;
}

/**
 * Create the config file directory on disk if it doesn't already exist.
 *
 * @param keydir The directory to create.
 * @return true if the folder was created successfully or already existed,
 *         false o/w
 */
bool create_config_dir(char const * keydir) {
	int mkdirresult;

	// Attempt to create the directory
	mkdirresult = mkdir(keydir, 0755);
	if (mkdirresult != 0) {
		// Something probably went wrong, so print out an appropriate error message.
		switch (errno) {
			case EACCES:
				printf ("Permission denied when creating config directory %s. Do you have root access?.\n", keydir);
				break;
			case EEXIST:
				// Actually, nothing went wrong! It's just the directory already existed (which is fine).
				mkdirresult = 0;
				break;
			case ENOENT:
				printf ("Couldn't create config directory %s because the parent directories don't exist. Consider creating them manually.\n", keydir);
				break;
			case ENOSPC:
				printf ("Not enough space to create config directory %s.\n", keydir);
				break;
			case EROFS:
				printf ("Read only filesyste. Can't create config directory %s.\n", keydir);
				break;
			default:
				printf ("Error creating config directory %s.\n", keydir);
				break;
		}
	}

	// Return true if the directory now exists.
	return (mkdirresult == 0);
}

/**
 * Create a path from the standard config directory and a leaf filename.
 * Since memory is allocated by the function to store the returned result,
 * the calling code should free up this memory once it's done using it.
 *
 * @param root The stem of the path to use (i.e. the config directory), null
 *        terminated.
 * @param leaf The name of the file, null-terminated
 * @return The contatenation of the root and leaf to give a full pathname. The
 *         memory allocated to this should be freed once the calling
 *         application is done with it
 */
char * config_file_full_path(char const * root, char const * leaf) {
	int length;
	char * path;

	length = strlen(root) + strlen(leaf) + 1;
	path = malloc(length + 1);
	snprintf(path, length + 1, "%s/%s", root, leaf);
	path[length] = '\0';

	return path;
}


///////////////////////////////////////////////////////////////////////////
// Command line functions

/**
 * Perform command-line pairing. This will block until the task has completed.
 *
 * @param username The user to pair.
 * @param hostnae The name of the host to pair with.
 * @param verbose The level of verbosity to use.
 * @param keydir Te directory where user credentials are stored. The contents
 *        of this directory will be updated on successful pairing.
 * @return true if everything went as expected.
 */
bool command_line(char const * username, char const * hostname, int verbose, char const * keydir) {
	Shared * shared;
	bool result;
	char * pub;
	char * priv;
	char * users_file;
	char * bt_devices_file;
	Users * users;
	USERFILE load_result;
	char password[PASSWORD_MAX];
	char * read;
	Buffer * bt_addr_buffer;
	bt_device_list_t * device_list;
	bt_err_t bt_e;
	int count_pass_tries;
	Buffer * symmetric_key;
	Buffer * password_cleartext;
	Buffer * password_ciphertext;

	printf("Pico pairing user %s with host %s\n", username, hostname);

	result = check_write_keydir(keydir);

	if (result == false) {
		printf("\nYou do not have permissions to write to the key directory \"%s\".\nYou may need to run pico-pair as root.\n", keydir);
	}

	if (result == true) {
		result = set_permissions_keydir(keydir);
		if (result == false) {
			printf("\nCould not set permissions on the key directory \"%s\": %s\nYou may need to run pico-pair as root.\n", keydir, strerror(errno));
		}
	}

	if (result == true) {
		// Set up the paths to the public key, private key and user list files
		pub = config_file_full_path(keydir, PUB_FILE);
		priv = config_file_full_path(keydir, PRIV_FILE);
		users_file = config_file_full_path(keydir, USERS_FILE);
		bt_devices_file = config_file_full_path(keydir, BT_ADDRESS_FILE);
		bt_addr_buffer = buffer_new(0);

		shared = shared_new();

		shared_set_feedback_trigger(shared, feedback_trigger, &verbose);

		// Load in the service's identity keys if they exist, or generate new
		// ones otherwise
		shared_load_or_generate_keys(shared, pub, priv);

		users = users_new();

		device_list = bt_list_new();

		// Load in the user list files
		load_result = users_load(users, users_file);
		if ((load_result != USERFILE_SUCCESS) && (load_result != USERFILE_IOERROR)) {
			printf("Error reading users file: %d\n", load_result);
			result = false;
		}

		// Load the bluetooth address list
		if (result) {
			bt_e = bt_list_load(device_list, bt_devices_file);
			if ((bt_e != BT_SUCCESS) && (bt_e != BT_ERR_FILE_NOT_FOUND)) {
				printf("Error reading bluetooth address: %d\n", bt_e);
				result = false;
			}
		}

		if (result == true) {
			result = false;
			count_pass_tries = 0;
			do {
				printf("\nPlease type the password for user %s.\n", username);
				set_echo(false);
				read = fgets(password, PASSWORD_MAX, stdin);
				if (read != NULL) {
					// Remove newline ending
					if (strlen(password) > 0) {
						password[strlen(password) - 1] = '\0';
					}
				} else {
					printf("Error reading password.\n");
					result = false;
				}
				set_echo(true);

				if (check_user_password(username, password)) {
					result = true;
				} else {
					printf("\nPassword for user %s is not valid.\n", username);
				}
			} while (++count_pass_tries < 3 && !result);
		}

		symmetric_key = buffer_new(CRYPTOSUPPORT_AESKEY_SIZE);
		password_cleartext = buffer_new(0);
		password_ciphertext = buffer_new(0);

		// Generate a symmetric key for the user
		if (result == true) {
			result = cryptosupport_generate_symmetric_key(symmetric_key, CRYPTOSUPPORT_AESKEY_SIZE);
			if (result == false) {
				printf("Failed to generate local symmetric key.\n");
			}
		}

		if (result == true) {
			buffer_clear(password_cleartext);
			buffer_append_string(password_cleartext, password);
			result = cryptosupport_encrypt_iv_base64(symmetric_key, password_cleartext, password_ciphertext);
			if (result == false) {
				printf("Failed to encrypt password.\n");
			}
		}

		if (result == true) {
			buffer_append(password_ciphertext, "", 1);
			// Actually enact the Pico pairing protocol
			// Looping 45 times, this will keep the channel open for 30 minutes
			result = pair_send_username_loop(shared, hostname, buffer_get_buffer(password_ciphertext), username, bt_addr_buffer, show_qr_code, NULL, 45);
		}

		if (result == true) {
			// If everything went well, store the user in the list to allow authentication in future
			users_add_user(users, username, shared_get_pico_identity_public_key(shared), symmetric_key);

			// Export out the resulting user list file
			load_result = users_export(users, users_file);
			if (load_result != USERFILE_SUCCESS) {
				printf("Error saving users file: %d\n", load_result);
				result = false;
			}
		}
		else {
			printf("Pairing failed.\n");
		}

		buffer_delete(symmetric_key);
		buffer_delete(password_cleartext);
		buffer_delete(password_ciphertext);

		if (result && buffer_get_pos(bt_addr_buffer)) {
			bt_addr_t addr;
			bt_str_to_addr(buffer_get_buffer(bt_addr_buffer), &addr);
			// Save bluetooth address
			bt_list_add_device(device_list, &addr);
			bt_list_save(device_list, bt_devices_file);
		}

		if (result) {
			printf ("User %s successfully paired with %s\n", username, hostname);
		}

		// Tidy things up
		buffer_delete(bt_addr_buffer);
		bt_list_delete(device_list);
		shared_delete(shared);
		free(pub);
		free(priv);
		free(users_file);
		free(bt_devices_file);
	}

	return result;
}

/**
 * Display some helpful text to stdout.
 */
void help() {
	printf("Pico pairing tool, for pairng a Pico with a computer\n");
	printf("Syntax: pico-pair [--help] [--user <username>] [--verbose] [--gui] [--datadir <path>] [--keydir <path>]\n");
	printf("\n");
	printf("Parameters:\n");
	printf("\thelp - display this help text.\n");
	printf("\tuser <username> - the username to pair with.\n");
	printf("\tverbose - display greater detail about the pairing process.\n");

	printf("\tgui - run with a graphical user interface, rather than command line.\n");
	printf("\tkeydir <path> - directory to store the credentials in (default %s).\n", PICOKEYDIR);
	printf("\tdatadir <path> - directory to load assets from (default %s).\n", PICOPAIRDIR);

	printf("Example:\n");
	printf("\tpico-user --user $USER\n");
}

/**
 * Callback function to be called while command-line pairing to
 * display a QR code to the console.
 *
 * @param qrtext Text to generate the qr code from.
 * @param localdata unused
 */
bool show_qr_code(char * qrtext, void * localdata) {
	DisplayQR * displayqr;
	printf("\nPlease scan the barcode with your Pico app to pair.\n");
	// Display the QR code on the console
	displayqr = displayqr_new();
	displayqr_generate(displayqr, qrtext);

	printf("\n");
	displayqr_output(displayqr);
	displayqr_delete(displayqr);
	printf("\n");

	return true;
}

/**
 * Turn on or off screen echo. Typically you would turn echo off when the
 * user is requested to enter a password, to prevent shoulder-surfing.
 * For other (non-private) data-entry, it would be turned on.
 *
 * @param enable true to turn screen echo on, false to turn it off
 */
// See http://stackoverflow.com/questions/1413445/read-a-password-from-stdcin
void set_echo(bool enable) {
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);

	if (enable == false) {
		tty.c_lflag &= ~ECHO;
	}
	else {
		tty.c_lflag |= ECHO;
	}

	(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

/**
 * Check whether the password is correct for a given user.
 *
 * This function will return immediately if the password is correct. If it's
 * incorrect, it will block for a second or two. This is to rate-limit
 * password checking and mitigate brute-force cracking of a user's password.
 *
 * @param user The user whose password is to be checked.
 * @param pass The password to check.
 * @return true if the password is correct for the user, false o/w.
 */
bool check_user_password(char const * user, char const * pass) {
	pam_handle_t * pamh = NULL;
	int result;

	int conv_function(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
		if (num_msg != 1) {
			// odd
			return PAM_SUCCESS;
		}

		switch (msg[0]->msg_style) {
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			printf("%s\n", msg[0]->msg);
			break;
		case PAM_PROMPT_ECHO_ON:
		case PAM_PROMPT_ECHO_OFF:
			*resp = malloc(sizeof(struct pam_response));
			(*resp)->resp = strdup(pass);
			(*resp)->resp_retcode = 0;
			break;
		};

		return PAM_SUCCESS;
	}

	struct pam_conv conv = {
		conv_function,
		NULL
	};

	result = pam_start("pico-pair", user, &conv, &pamh);

	if (result == PAM_SUCCESS) {
		result = pam_authenticate(pamh, 0);
	}

	return result == PAM_SUCCESS;
}

/**
 * Print out progress on the pairing function (the sigma protocol) to the
 * console.
 *
 * Whether anything is actually printed will depend on the verbosity level.
 *
 * @param feedback The feedback structure used to request information about
 *        progress.
 * @param data User data provided when the callback was set up.
 * @return true to allow the process to continue, false to stop it.
 */
bool feedback_trigger(Feedback const * feedback, void * data) {
	int verbose = *((int *)data);
	double progress;
	char const * description;

	progress = feedback_get_progress(feedback);
	description = feedback_get_description(feedback);

	if (verbose > 1) {
		printf("%f%% : %s\n", progress, description);
	}

	return true;
}


///////////////////////////////////////////////////////////////////////////
// GUI functions


/**
 * Create a new GUI context data structure.
 *
 * @return The newly allocated and initialised data structure.
 */
GuiData * guidata_new() {
	GuiData * gui_data;

	gui_data = calloc(sizeof(GuiData), 1);

	gui_data->scancomplete = false;
	gui_data->username = g_string_new("");
	gui_data->password = g_string_new("");
	gui_data->hostname = g_string_new("");
	gui_data->code = g_string_new("");

	gui_data->shared = shared_new();
	gui_data->channel = NULL;
	gui_data->extraDataBuffer = buffer_new(0);
	gui_data->password_ciphertext = buffer_new(0);
	gui_data->verbose = 1;
	gui_data->users = users_new();
	gui_data->symmetric_key = buffer_new(CRYPTOSUPPORT_AESKEY_SIZE);
	gui_data->device_list = bt_list_new();
	gui_data->keypressed = false;
	gui_data->datadir = g_string_new(PICOPAIRDIR);
	gui_data->keydir = g_string_new("");

	return gui_data;
}

/**
 * Destroy a GUI context data structure and free up any resources it owns.
 *
 * @param gui_data The data structure to delete.
 */
void guidata_delete(GuiData * gui_data) {
	if (gui_data) {
		if (gui_data->username) {
			g_string_free(gui_data->username, TRUE);
		}
		if (gui_data->password) {
			g_string_free(gui_data->password, TRUE);
		}
		if (gui_data->hostname) {
			g_string_free(gui_data->hostname, TRUE);
		}
		if (gui_data->code) {
			g_string_free(gui_data->code, TRUE);
		}
		if (gui_data->shared) {
			shared_delete(gui_data->shared);
		}
		if (gui_data->channel) {
			channel_delete(gui_data->channel);
		}
		if (gui_data->extraDataBuffer) {
			buffer_delete(gui_data->extraDataBuffer);
		}
		if (gui_data->password_ciphertext) {
			buffer_delete(gui_data->password_ciphertext);
		}
		if (gui_data->users) {
			users_delete(gui_data->users);
		}
		if (gui_data->symmetric_key) {
			buffer_delete(gui_data->symmetric_key);
		}
		if (gui_data->device_list) {
			bt_list_delete(gui_data->device_list);
		}
		if (gui_data->datadir) {
			g_string_free(gui_data->datadir, TRUE);
		}
		if (gui_data->keydir) {
			g_string_free(gui_data->keydir, TRUE);
		}

		free(gui_data);
	}
}

/**
 * Perform GUI pairing (using GTK). This will execute a GTK main loop, which
 * will block until the task has completed.
 *
 * @param username A hint for the user to pair. This may be changed later by
 *        the user.
 * @param hostnae The name of the host to pair with.
 * @param verbose The level of verbosity to use. Currently has no effect for
 *        the GUI version (but does affect the command line version).
 * @param keydir Te directory where user credentials are stored. The contents
 *        of this directory will be updated on successful pairing.
 * @param datadir The directory to load resources from.
 * @param argc The number of arguments provided.
 * @param argv An array of pointers to the argument strings.
 * @return true if everything went as expected.
 */
bool gui(char const * username, char const * hostname, int verbose, char const * keydir, char const * datadir, int argc, char * argv[]) {
	bool result;
	GuiData * gui_data;
	GtkAssistant * window;
	GtkWidget * widget;
	GString * interface_file;
	GtkWidget * message;
	guint loadresult;
	GString * error;

	result = true;

	error = g_string_new("Unknown error");

	gui_data = guidata_new();
	gui_data->verbose = verbose;
	g_string_assign(gui_data->username, username);
	g_string_assign(gui_data->hostname, hostname);
	g_string_assign(gui_data->keydir, keydir);
	g_string_assign(gui_data->datadir, datadir);

	gtk_init(&argc, &argv);
	gui_data->xml = gtk_builder_new ();

	interface_file = g_string_new("");
	g_string_printf(interface_file, "%s/%s", datadir, "picopair.glade");
	loadresult = gtk_builder_add_from_file(gui_data->xml, interface_file->str, NULL);
	g_string_free(interface_file, TRUE);

	if (loadresult == 0) {
		g_string_printf(error, "Unable to load GUI resources from directory \"%s\".", datadir);
		result = false;
	}

	if (result == true) {
		window = GTK_ASSISTANT(gtk_builder_get_object(gui_data->xml, "picopair"));
		g_signal_connect(window, "prepare", G_CALLBACK(prepare), (gpointer)gui_data);
		gtk_builder_connect_signals (gui_data->xml, NULL);

		widget = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "username"));
		g_signal_connect(widget, "changed", G_CALLBACK (key_press), (gpointer)gui_data);

		gtk_entry_set_text(GTK_ENTRY(widget), gui_data->username->str);

		widget = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "password"));
		g_signal_connect(widget, "changed", G_CALLBACK (key_press), (gpointer)gui_data);

		widget = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "picopair"));
		gtk_assistant_set_forward_page_func(GTK_ASSISTANT(widget), next_page, gui_data, NULL);

		widget = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "btsettings"));
		g_signal_connect(widget, "clicked", G_CALLBACK (open_settings), (gpointer)gui_data);


		gui_data->cancel = gtk_button_new_with_label("Cancel");
		gtk_assistant_add_action_widget (window, gui_data->cancel);
		g_signal_connect(GTK_BUTTON(gui_data->cancel), "clicked", G_CALLBACK(gtk_main_quit), NULL);

		result = check_write_keydir(gui_data->keydir->str);

		if (result == false) {
			g_string_printf(error, "You do not have permissions to write to the key directory \"%s\".\n\nYou may need to run pico-pair as root.\n", keydir);
		}
	}

	if (result == true) {
		result = set_permissions_keydir(keydir);
		if (result == false) {
			g_string_printf(error, "\nCould not set permissions on the key directory \"%s\": %s\nYou may need to run pico-pair as root.\n", keydir, strerror(errno));
		}
	}

	if (result == true) {
		gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
		gtk_widget_show(GTK_WIDGET(window));
	}
	else {
		message = gtk_message_dialog_new (NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s", error->str);
		g_signal_connect(message, "response", G_CALLBACK (gtk_main_quit), NULL);
		gtk_widget_show(message);
	}

	gtk_main ();

	g_object_unref (G_OBJECT (gui_data->xml));

	guidata_delete(gui_data);
	g_string_free(error, TRUE);

	return result;
}

/**
 * Called when the next page of the assistant is requested (e.g. when the
 * user clicks on the Next button).
 *
 * @param current_page The current page visible to the user.
 * @param data Data structure containing the GUI context.
 * @return The page to move on to next (can be the same page for no change).
 */
static gint next_page(gint current_page, gpointer data) {
	GuiData * gui_data = (GuiData *)data;
	gint next;

	next = current_page;
	switch (current_page) {
	case 1:
		if (gui_data->keypressed && (check_user(gui_data))) {
			next++;
		}
		break;
	default:
		next++;
		break;
	}

	return next;
}

/**
 * Called just before a page is displayed, so that the page can be correctly
 * set up for use.
 *
 * @param assistant The assistant widget.
 * @param page The page to prepare.
 * @param user_data Data structure containing the GUI context.
 */
static void prepare (GtkAssistant * assistant, GtkWidget * page, gpointer user_data) {
	GuiData * gui_data = (GuiData *)user_data;
	gint current_page;
	GtkEntry * entry;

	current_page = gtk_assistant_get_current_page(GTK_ASSISTANT(assistant));
	gui_data->keypressed = false;

	switch (current_page) {
	case 1:
		entry = GTK_ENTRY(gtk_builder_get_object(gui_data->xml, "password"));
		gtk_entry_set_text(entry, "");
		break;
	case 2:
		if (gui_data->scancomplete == false) {
			gui_data->scancomplete = gui_pair_setup(gui_data);
			if (gui_data->scancomplete) {
				set_qr_code(gui_data);
				trigger_pair_thread(gui_data);
			}
		}
		gtk_widget_show(gui_data->cancel);
		break;
	default:
		gtk_widget_hide(gui_data->cancel);
		break;
	}
}

/**
 * Start the thread used to perform the pairing.
 *
 * @param gui_data Data structure containing the GUI context.
 */
void trigger_pair_thread(GuiData * gui_data) {
	pthread_t thread;
	pthread_attr_t thread_attr;
	int thread_result;

	pthread_attr_init(& thread_attr);
	pthread_attr_setdetachstate(& thread_attr, PTHREAD_CREATE_JOINABLE);

	thread_result = pthread_create(& thread, & thread_attr, thread_start_pair, (void *)gui_data);
	if (thread_result != 0) {
		printf("Error creating auth thread: %d\n", thread_result);
	}
	pthread_attr_destroy(&thread_attr);
}

/**
 * The thread function for pairing.
 *
 * @param t Data structure containing the GUI context.
 * @return Always returns NULL.
 */
void * thread_start_pair(void * t) {
	GuiData * gui_data = (GuiData *)t;
	Buffer * returned_stored_data;

	returned_stored_data = buffer_new(0);
	gui_data->result = gui_pair_complete(gui_data, returned_stored_data);
	buffer_delete(returned_stored_data);

	// Move to the next page, but make sure we call the function in the gtk UI thread
	g_idle_add (pairing_complete, (gpointer)gui_data);

	return NULL;
}

/**
 * Callback function triggered in the GUI thread once the pairing thread has
 * completed (either successfully or unsuccessfully).
 *
 * @param gui_data Data structure containing the GUI context.
 * @return Always returns false to remove the source.
 */
gboolean pairing_complete (gpointer user_data) {
	GuiData * gui_data = (GuiData *)user_data;
	GtkAssistant * assistant;

	assistant = GTK_ASSISTANT(gtk_builder_get_object(gui_data->xml, "picopair"));

	if (gui_data->result) {
		printf ("User %s successfully paired with %s\n", gui_data->username->str, gui_data->hostname->str);
		gtk_assistant_set_current_page(assistant, 4);
	}
	else {
		printf ("User %s pairing failed with %s\n", gui_data->username->str, gui_data->hostname->str);
		gtk_assistant_set_current_page(assistant, 3);
	}

	// Return false to remove the source
	// See: https://developer.gnome.org/glib/stable/glib-The-Main-Event-Loop.html#g-idle-add
	return false;
}

/**
 * Start the pairing process. This goes as far as needed in order to allow the
 * pairing QR code to be generated. The gui_pair_complete() function should
 * then be called to complete the process.
 *
 * @param gui_data Data structure containing the GUI context.
 * @return true if things went as expected, false if there was an error.
 */
bool gui_pair_setup(GuiData * gui_data) {
	bool result;
	char * pub;
	char * priv;
	char * bt_devices_file;
	char * users_file;
	USERFILE load_result;
	bt_err_t bt_e;
	Buffer * password_cleartext;
	Json * extra_data_json;
	Buffer * buffer;
	size_t size;
	char * qrtext;
	KeyPairing * key_pairing;
	KeyPair * service_identity_key;

	result = true;

	printf("Pico pairing user %s with host %s\n", gui_data->username->str, gui_data->hostname->str);

	// Set up the paths to the public key, private key and user list files
	pub = config_file_full_path(gui_data->keydir->str, PUB_FILE);
	priv = config_file_full_path(gui_data->keydir->str, PRIV_FILE);
	users_file = config_file_full_path(gui_data->keydir->str, USERS_FILE);
	bt_devices_file = config_file_full_path(gui_data->keydir->str, BT_ADDRESS_FILE);

	shared_set_feedback_trigger(gui_data->shared, feedback_trigger, &gui_data->verbose);
	
	// Load in the service's identity keys if they exist, or generate new
	// ones otherwise
	shared_load_or_generate_keys(gui_data->shared, pub, priv);

	free(pub);
	free(priv);

	// Load in the user list files
	load_result = users_load(gui_data->users, users_file);
	if ((load_result != USERFILE_SUCCESS) && (load_result != USERFILE_IOERROR)) {
		printf("Error reading users file: %d\n", load_result);
		result = false;
	}
	free(users_file);

	// Load the bluetooth address list
	if (result) {
		bt_e = bt_list_load(gui_data->device_list, bt_devices_file);
		if ((bt_e != BT_SUCCESS) && (bt_e != BT_ERR_FILE_NOT_FOUND)) {
			printf("Error reading bluetooth address: %d\n", bt_e);
			result = false;
		}
	}

	free(bt_devices_file);

	password_cleartext = buffer_new(0);
	
	// Generate a symmetric key for the user
	if (result == true) {
		buffer_clear(gui_data->symmetric_key);
		result = cryptosupport_generate_symmetric_key(gui_data->symmetric_key, CRYPTOSUPPORT_AESKEY_SIZE);
		if (result == false) {
			printf("Failed to generate local symmetric key.\n");
		}
	}

	if (result == true) {
		buffer_clear(password_cleartext);
		buffer_append_string(password_cleartext, gui_data->password->str);
		result = cryptosupport_encrypt_iv_base64(gui_data->symmetric_key, password_cleartext, gui_data->password_ciphertext);
		if (result == false) {
			printf("Failed to encrypt password.\n");
		}
	}

	buffer_delete(password_cleartext);
	buffer = buffer_new(0);

	if (result == true) {
		//buffer_clear(gui_data->password_ciphertext);
		buffer_append(gui_data->password_ciphertext, "", 1);
		// Actually enact the Pico pairing protocol
		// Looping 45 times, this will keep the channel open for 30 minutes

		extra_data_json = json_new();
		json_add_string(extra_data_json, "data", buffer_get_buffer(gui_data->password_ciphertext));
		json_add_string(extra_data_json, "name", gui_data->username->str);

		json_serialize_buffer(extra_data_json, gui_data->extraDataBuffer);
		buffer_append(gui_data->extraDataBuffer, "", 1);

		json_delete(extra_data_json);
		
		// Request a new rendezvous channel
		gui_data->channel = channel_new();

		channel_get_url(gui_data->channel, buffer);
		result = (buffer_get_pos(buffer) > 0);
	}
	

	if (result) {
		service_identity_key = shared_get_service_identity_key(gui_data->shared);

		// SEND
		// Generate a visual QR code for Key Pairing
		// {"sn":"NAME","spk":"PUB-KEY","sig":"B64-SIG","ed":"","sa":"URL","td":{},"t":"KP"}
		key_pairing = keypairing_new();
		keypairing_set(key_pairing, buffer, "", NULL, gui_data->hostname->str, service_identity_key);

		size = keypairing_serialize_size(key_pairing);
		qrtext = MALLOC(size + 1);
		keypairing_serialize(key_pairing, qrtext, size + 1);
		keypairing_delete(key_pairing);

		g_string_assign(gui_data->code, qrtext);
		
		FREE(qrtext);
	}

	buffer_delete(buffer);

	// The pairing step is now performed in gui_pair_complete(), so that it can
	// be spawned in a separate thread
	//result = pair_send_username_loop(gui_data->shared, gui_data->hostname->str, buffer_get_buffer(gui_data->password_ciphertext), gui_data->username->str, bt_addr_buffer, show_qr_code, NULL, 45);
	
	return result;
}

/**
 * Complete the pairing process, which should previously have been started by a
 * call to gui_pair_setup(). This function will block until the pairing is
 * complete, so should probably be run in its own thread.
 *
 * @param gui_data Data structure containing the GUI context.
 * @param returned_stored_data Any data that's sent by the Pico app during the
 *        pairing process (a pre-allocated buffer should be passed in, owned
 *        by the caller).
 * @return true if the pairing completed successfully, false o/w.
 */
bool gui_pair_complete(GuiData * gui_data, Buffer * returned_stored_data) {
	bool result;
	char * users_file;
	USERFILE export_result;
	char * bt_devices_file;
	int i;

	result = false;
	for (i = 0; i < 45 && !result; i++) {
		result = sigmaverifier(gui_data->shared, gui_data->channel, NULL, buffer_get_buffer(gui_data->extraDataBuffer), returned_stored_data, NULL);
	}

	if (result == true) {
		users_file = config_file_full_path(gui_data->keydir->str, USERS_FILE);
		// If everything went well, store the user in the list to allow authentication in future
		users_add_user(gui_data->users, gui_data->username->str, shared_get_pico_identity_public_key(gui_data->shared), gui_data->symmetric_key);

		// Export out the resulting user list file
		export_result = users_export(gui_data->users, users_file);
		if (export_result != USERFILE_SUCCESS) {
			printf("Error saving users file: %d\n", export_result);
			result = false;
		}
		free(users_file);
	}
	else {
		printf("Pairing failed.\n");
	}

	if (result && buffer_get_pos(returned_stored_data)) {
		bt_devices_file = config_file_full_path(gui_data->keydir->str, BT_ADDRESS_FILE);

		bt_addr_t addr;
		bt_str_to_addr(buffer_get_buffer(returned_stored_data), &addr);
		// Save bluetooth address
		bt_list_add_device(gui_data->device_list, &addr);
		bt_list_save(gui_data->device_list, bt_devices_file);

		free(bt_devices_file);
	}

	return result;
}

/**
 * Create a bitmap QR code and add it to the GUI.
 *
 * The data needed for the QR code is extracted from the GUI context.
 *
 * @param gui_data Data structure containing the GUI context.
 */
void set_qr_code(GuiData * gui_data) {
	GtkImage * image;
	QRcode * qrcode;
	GdkPixbuf * pixbuf;
	GdkPixbuf * scaled;
	int rowstride;
	int x;
	int y;
	int n_channels;
	guchar * pixels;
	guchar * p;
	unsigned char * col;

	image = GTK_IMAGE(gtk_builder_get_object(gui_data->xml, "code"));

	qrcode = QRcode_encodeString8bit(gui_data->code->str, 0, QR_ECLEVEL_M);

	pixbuf = gdk_pixbuf_new(GDK_COLORSPACE_RGB, false, 8, qrcode->width + (2 * QR_BORDER), qrcode->width + (2 * QR_BORDER));
	gdk_pixbuf_fill (pixbuf, 0xffffffff);

	rowstride = gdk_pixbuf_get_rowstride(pixbuf);
	pixels = gdk_pixbuf_get_pixels(pixbuf);
	n_channels = gdk_pixbuf_get_n_channels(pixbuf);

	for (y = 0; y < qrcode->width; y++) {
		for (x = 0; x < qrcode->width; x++) {
			p = pixels + (y + QR_BORDER) * rowstride + (x + QR_BORDER) * n_channels;
			col = qrcode->data + (y * qrcode->width) + x;
			if (*col & 1) {
				p[0] = 0;
				p[1] = 0;
				p[2] = 0;
			}
			else {
				p[0] = 255;
				p[1] = 255;
				p[2] = 255;
			}
		}
	}

	scaled = gdk_pixbuf_scale_simple(pixbuf, qrcode->width * QR_SCALE, qrcode->width * QR_SCALE, GDK_INTERP_NEAREST);
	gtk_image_set_from_pixbuf (image, scaled);
	g_object_unref(pixbuf);
	g_object_unref(scaled);
}

/**
 * Check whether the username/password combination entered by the user is
 * valid. If it's not, an error message will be displayed to the user.
 *
 * @param gui_data Data structure containing the GUI context.
 * @return true if the username and password are valid, false o/w.
 */
bool check_user(GuiData * gui_data) {
	bool result;
	GtkEntry * entry;
	gchar const * username;
	gchar const * password;
	GtkWidget * widget;
	bool showerror;

	entry = GTK_ENTRY(gtk_builder_get_object(gui_data->xml, "username"));
	username = gtk_entry_get_text(entry);

	entry = GTK_ENTRY(gtk_builder_get_object(gui_data->xml, "password"));
	password = gtk_entry_get_text(entry);

	if ((strlen(username) > 0) && (strlen(password) > 0)) {
		result = check_user_password(username, password);
	}
	else {
		result = false;
	}

	if ((strlen(username) > 0) || (strlen(password) > 0)) {
		showerror = true;
	}
	else {
		widget = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "incorrect"));
		gtk_widget_hide(widget);
		showerror = false;
	}

	if (result) {
		g_string_assign(gui_data->username, username);
		g_string_assign(gui_data->password, password);
	}

	gtk_entry_set_text(entry, "");

	if (showerror) {
		widget = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "incorrect"));
		gtk_widget_set_visible(widget, !result);
	}

	return result;
}

/**
 * Callback executed whenever the user presses a key inside the username or
 * password entry fields.
 *
 * This will remove any 'incorrect username/password' warning messages and
 * set the assistant action buttons appropriately (e.g. if either the
 * username or password fields are entry, the Next button should be
 * deactivated).
 *
 * @param widget The entry field the caret is in.
 * @param gui_data Data structure containing the GUI context.
 * @return Always returns true to ensure any later callbacks are also fired.
 */
static gboolean key_press(GtkWidget * widget, gpointer data) {
	GuiData * gui_data = (GuiData *)data;
	GtkWidget * message;
	GtkWidget * page;
	GtkEntry * entry;
	GtkAssistant * assistant;
	guint16 length;
	bool complete;
	bool was_complete;

	message = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "incorrect"));
	gtk_widget_hide(message);

	gui_data->keypressed = true;

	complete = true;
	entry = GTK_ENTRY(gtk_builder_get_object(gui_data->xml, "username"));
	length = gtk_entry_get_text_length(entry);
	complete = complete && (length > 0);
	entry = GTK_ENTRY(gtk_builder_get_object(gui_data->xml, "password"));
	length = gtk_entry_get_text_length(entry);
	complete = complete && (length > 0);

	assistant = GTK_ASSISTANT(gtk_builder_get_object(gui_data->xml, "picopair")); 
	page = GTK_WIDGET(gtk_builder_get_object(gui_data->xml, "userdetails"));

	was_complete = gtk_assistant_get_page_complete(assistant, page);

	if (complete != was_complete) {
		gui_data->keypressed = false;
		gtk_assistant_set_page_complete (assistant, page, complete);
	}

	return true;
}

/**
 * Check that the key directory can be written to and read from. This
 * function will attempt to create a temporary file inside the key directory.
 * If it fails it will return false, if it succeeds it will return true.
 * In either case the file is deleted before the function returns.
 *
 * @param keydir The full path of the directory to check.
 * @return true if the directory can be written to/read from, false o/w.
 */
static gboolean check_write_keydir(char const * keydir) {
	gboolean result;
	char * lockpath;
	FILE * lock;
	int delete_result;

	result = true;
	lockpath = config_file_full_path(keydir, LOCK_FILE);
	lock = fopen(lockpath, "w+");

	if (lock) {
		fclose(lock);
	} else{
		result = false;
	}

	if (result == true) {
		// Delete the file
		delete_result = unlink (lockpath);
		result = (delete_result == 0);
	}

	free(lockpath);

	return result;
}

static gboolean open_settings(GtkWidget * widget, gpointer data) {
	bool done;

	done = false;

	if (g_getenv ("MIR_SOCKET") != NULL) {
		url_dispatch_send("settings:///bluetooth", NULL, NULL);
		done = true;
	}

	if (done == false) {
		done = check_desktop_executable("Unity", "unity-control-center");
		if (done == true) {
			execute_command ("unity-control-center bluetooth");
		}
	}

	if (done == false) {
		done = check_desktop_executable("MATE", "blueman-manager");
		if (done == true) {
			execute_command ("blueman-manager");
		}
	}

	if (done == false) {
		execute_command ("gnome-control-center bluetooth");
		done = true;
	}

	return done;
}

static bool check_desktop_executable(char const * desktop, char const * executable) {
	bool result;
  gchar const * xdg_current_desktop;
  gchar * path;
  g_auto(GStrv) desktop_names;

	result = false;
	desktop_names = NULL;

	xdg_current_desktop = g_getenv("XDG_CURRENT_DESKTOP");
	if (xdg_current_desktop != NULL) {
		desktop_names = g_strsplit(xdg_current_desktop, ":", 0);
		if (g_strv_contains((gchar const * const *) desktop_names, desktop)) {
			path = g_find_program_in_path(executable);
			if (path != NULL) {
				g_free(path);
				result = true;
			}
		}
	}

	return result;
}

static void execute_command (char const * cmd) {
	GError * err = NULL;

	g_spawn_command_line_async (cmd, & err);
	if (err != NULL) {
		printf("Error opening settings: %s\n", err->message);
		g_clear_error (& err);
	}
}

/**
 * Set ownership of the key directory to root and permissions to user
 * read/write (i.e. removing read/write permissions from the group and other).
 *
 * Certain items (private and symmetric keys) require both confidentiality
 * and integrity, in order to maintain the integrity of the Pico
 * authentication. These permissions are used to ensure this remains the case.
 *
 * Users must be root to pair, and root can install arbitrary code into the
 * PAM configuration, so root has to be trusted anyway.
 *
 * The function attempts to set ownership first, since the user must have
 * higher privileges for this to succeed. Id it does, the function will attempt
 * to set the permissions on the directory.
 *
 * @param keydir The full path of the directory to change ownership and
 *        permissions of.
 * @return true if the ownership and permissions could be set, false o/w.
 */
static gboolean set_permissions_keydir(char const * keydir) {
	gboolean result;
	int set_result;

	// Set to be owned by root
	set_result = chown(keydir, 0, 0);
	result = (set_result == 0);

	// Set User permissions to RW
	// Set Group permissions to none
	// Set Other permissions to none
	if (result == true) {
		set_result = chmod(keydir, S_IRUSR | S_IWUSR);
		result = (set_result == 0);
	}

	return result;
}

/** @} addtogroup Pairing */

