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
 * @brief Pico authntication service; the main entry point
 * @section DESCRIPTION
 *
 * The continuous authentication service accepts messages over dbus from the
 * pam_pico module to perform the authentication while the user logs in.
 * 
 * The pam_pico PAM comminucates with this pico-continuous service via DBus to 
 * trigger an authentication invitation. The service returns a code which
 * pico_pam should display to the user as a QR code. This can be scanned by the
 * Pico app. Scanning the code triggers the Pico app to contact this service 
 * and attempt to perform an authentication. The result is returned to
 * pico_pam, allowing it to decide whether or not the user is adequately
 * authenticated.
 *
 * The process, from the service's point of view therefore requires three steps.
 * First it is contaced to initiate the authentication; the service returns its
 * code at this stage, which the PAM should display. The service then waits
 * for the Pico app to perform the complete authentication. Finally the
 * service will be contacted again by pico_pam to retrieve the result of the
 * authentication. The ordering of steps two and three may change, sine we
 * don't know whether the Pico app or pico_pam will contact the service first.
 * The service must be able to handle both cases.
 *
 * In addition to the above, the service may also send out its own invitations
 * via Blutooth, either instead of or as well as the QR code, but containing
 * the same information. The service also goes on to perform continuous
 * authentication of the Pico app. In the event that this continuous
 * authentication fails or is stopped, the service will lock the user's
 * screen.
 *
 * This code makes use of ProcessStore, AuthThread, BeaconThread, BeaconSend
 * Service and FsmService to manage the entire process. The hierarchy of
 * objects is as follows.
 *
 *       pico-continuous
 *             1
 *             |
 *             1
 *        ProdessStore
 *             1
 *             |
 *             *
 *         AuthThread
 *         1        1
 *        /          \
 *       1            1
 * BeaconThread    Service
 *       1            1
 *       |            |
 *       *            1
 *  BeaconSend    FsmService
 *
 * Where:
 * 1. pico-continuous: Single main entry point and GMainLoop of the service.
 * 2. ProcessStore: managed multiple authentication sessions.
 * 3. AuthThread: manages a single authentication.
 * 4. BeaconThread: sends beacons to multiple devices.
 * 5. BeaconSend: sends beacons to a single device.
 * 6. Service: manages the Bluetooth channel for authentication.
 * 7. FsmService: manages progress through the authentication process.
 *
 */

/** \addtogroup Service
 *  @{
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "pico/buffer.h"
#include "pico/shared.h"
#include "pico/auth.h"
#include "pico/users.h"
#include "pico/displayqr.h"
#include "pico/continuous.h"
#include "pico/messagepicoreauth.h"
#include "pico/messageservicereauth.h"
#include "pico/channel_bt.h"
#include "pico/debug.h"

#ifdef HAVE_LIBPICOBT
#include "picobt/btmain.h"
#endif // #ifdef HAVE_LIBPICOBT

#include "log.h"
#include "processstore.h"
#include "gdbus-generated.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

/**
 * Handle the continuous authentication message when it's received over dbus.
 *
 * @param object the dbus proxy object
 * @param invocation the dbus method invocation object
 * @param arg_username the authenticating user
 * @param arg_parameters json encoded paramter list
 * @param user_data the user data passed to the signal connect
 * @return TRUE if the function completed successfully
 */
static gboolean on_handle_start_auth(PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, const gchar * arg_username, const gchar * arg_parameters, gpointer user_data) {
	ProcessStore * processstoredata = (ProcessStore *)user_data;
	bool result;

	GDBusMessage * message;
	message = g_dbus_method_invocation_get_message(invocation);
	syslog(LOG_INFO, "Start auth\n");
	syslog(LOG_INFO, "Unique name: %s\n", g_dbus_message_get_sender(message));

	result = start_auth(processstoredata, object, invocation, arg_username, arg_parameters);

	return result;
}

/**
 * Handle the continuous authentication message when it's received over dbus.
 *
 * @param object the dbus proxy object
 * @param invocation the dbus method invocation object
 * @param arg_username the authenticating user
 * @param arg_parameters json encoded paramter list
 * @param user_data the user data passed to the signal connect
 * @return TRUE if the function completed successfully
 */
static gboolean on_handle_complete_auth(PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, gint handle, gpointer user_data) {
	ProcessStore * processstoredata = (ProcessStore *)user_data;
	bool result;

	GDBusMessage * message;
	message = g_dbus_method_invocation_get_message(invocation);
	syslog(LOG_INFO, "Complete auth\n");
	syslog(LOG_INFO, "Unique name: %s\n", g_dbus_message_get_sender(message));

	result = complete_auth(processstoredata, object, invocation, handle);

	return result;
}

/**
 * Handle the dbus exit signal.
 *
 * @param object the dbus proxy object
 * @param invocation the dbus method invocation object
 * @param user_data the user data passed to the signal connect
 * @return TRUE if the function completed successfully
 */
static gboolean on_handle_exit(PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, gpointer user_data) {
	ProcessStore * processstoredata = (ProcessStore *)user_data;
	GMainLoop * loop;

	loop = processstore_get_loop(processstoredata);

	syslog(LOG_INFO, "Exit\n");

	g_main_loop_quit(loop);
	
	pico_uk_ac_cam_cl_pico_interface_complete_exit(object, invocation);

	return TRUE;
}

/**
 * Callback function used in g_dbus_connection_signal_subscribe(), called
 * to receive dbus signals.
 *
 * @param connection A GDBusConnection.
 * @param sender_name The unique bus name of the sender of the signal.
 * @param object_path The object path that the signal was emitted on.
 * @param interface_name The name of the interface.
 * @param signal_name The name of the signal.
 * @param parameters A GVariant tuple with parameters for the signal.
 * @param user_data User data passed when subscribing to the signal.
 * @param connection the dbus connection object
 * @param name the name of the dbus message bus connection acquired
 * @param user_data the user data passed to the signal connect
 */
void signal_callback(GDBusConnection *connection, const gchar *sender_name, const gchar *object_path, const gchar *interface_name, const gchar *signal_name, GVariant *parameters, gpointer user_data) {
	ProcessStore * processstoredata = (ProcessStore *)user_data;

	gboolean result;
	gsize size;
	GVariant * child;
	const gchar * value;
	bool interesting;

	interesting = false;
	result = g_variant_is_of_type(parameters, G_VARIANT_TYPE_TUPLE);
	if (result) {
		size = g_variant_n_children (parameters);
		if (size == 3) {
			child = g_variant_get_child_value (parameters, 2);
			result = g_variant_is_of_type(child, G_VARIANT_TYPE_STRING);
			if (result) {
				value = g_variant_get_string (child, NULL);
				interesting = (strcmp(value, "") == 0);
			}

			if (interesting) {
				child = g_variant_get_child_value (parameters, 1);
				result = g_variant_is_of_type(child, G_VARIANT_TYPE_STRING);
				if (result) {
					value = g_variant_get_string (child, NULL);
					syslog(LOG_INFO, "Old owner: %s\n", value);
					processstore_owner_lost(processstoredata, value);
				}
			}
		}
	}
}

/**
 * Handle the dbus acquired signal.
 *
 * @param connection the dbus connection object
 * @param name the name of the dbus message bus connection acquired
 * @param user_data the user data passed to the signal connect
 */
static void on_bus_acquired(GDBusConnection * connection, const gchar * name, gpointer user_data) {
	GError *error;
	error = NULL;

	syslog(LOG_INFO, "Acquired message bus connection\n");

	PicoUkAcCamClPicoInterface * interface;

	interface = pico_uk_ac_cam_cl_pico_interface_skeleton_new();

	g_signal_connect(interface, "handle-start-auth", G_CALLBACK(on_handle_start_auth), user_data);

	g_signal_connect(interface, "handle-complete-auth", G_CALLBACK(on_handle_complete_auth), user_data);

	g_signal_connect(interface, "handle-exit", G_CALLBACK(on_handle_exit), user_data);

	g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(interface), connection, "/PicoObject", & error);

	guint sub_id;
	sub_id = g_dbus_connection_signal_subscribe(connection, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged", "/org/freedesktop/DBus", NULL, G_DBUS_SIGNAL_FLAGS_NONE, signal_callback, user_data, NULL);
	syslog(LOG_INFO, "Signal subscribed: %d\n", sub_id);
}

/**
 * Handle the dbus name acquired signal.
 *
 * @param connection the dbus connection object
 * @param name the name of the dbus message bus connection acquired
 * @param user_data the user data passed to the signal connect
 */
static void on_name_acquired(GDBusConnection * connection, const gchar * name, gpointer user_data) {
	syslog(LOG_INFO, "Acquired name: %s\n", name);
}

/**
 * Handle the dbus name acquired signal.
 *
 * @param connection the dbus connection object
 * @param name the name of the dbus message bus connection acquired
 * @param user_data the user data passed to the signal connect
 */
static void on_name_lost(GDBusConnection * connection, const gchar * name, gpointer user_data) {
	syslog(LOG_INFO, "Lost name: %s\n", name);
}

/**
 * Main; the entry point of the service.
 *
 * @param argc the number of arguments passed in
 * @param argv array of arguments passed in
 * @return value returned on service exit
 */
gint main(gint argc, gchar * argv[]) {
	GMainLoop * loop;
	guint id;
	ProcessStore * processstoredata;

	loop = g_main_loop_new(NULL, FALSE);

	processstoredata = processstore_new();
	processstore_set_loop(processstoredata, loop);

	// Initialise Bluetooth
	syslog(LOG_INFO, "Initialising Bluetooth\n");
#ifdef HAVE_LIBBLUETOOTH
	bt_init();
#endif

	syslog(LOG_INFO, "Requesting to own bus\n");
	id = g_bus_own_name(G_BUS_TYPE_SYSTEM, "uk.ac.cam.cl.pico.service", G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT | G_BUS_NAME_OWNER_FLAGS_REPLACE, on_bus_acquired, on_name_acquired, on_name_lost, (void *)processstoredata, NULL);
	
	// TODO: Check interaction with signals
	// See g_unix_signal_add()
	// https://developer.gnome.org/glib/stable/glib-UNIX-specific-utilities-and-integration.html
	// And example usage from gnome-keyring:
	// https://git.gnome.org//browse/gnome-keyring/tree/daemon/gkd-main.c#n1141
	// http://gtk.10911.n7.nabble.com/Unix-signals-in-GLib-td29344.html


	syslog(LOG_INFO, "Entering main loop\n");
	g_main_loop_run(loop);

	syslog(LOG_INFO, "Exited main loop\n");	
	g_bus_unown_name(id);
	g_main_loop_unref(loop);

	// Deinitialise Bluetooth
	syslog(LOG_INFO, "Deinit Bluetooth\n");
#ifdef HAVE_LIBBLUETOOTH
	bt_exit();
#endif

	syslog(LOG_INFO, "The End\n");

	processstore_delete(processstoredata);

	return 0;
}

/** @} addtogroup Service */

