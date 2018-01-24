#include <dbus/dbus.h>
#include <stdarg.h>

typedef struct {
	DBusConnection * (*dbus_bus_get)(DBusBusType type, DBusError * error);
	DBusMessage * (*dbus_message_new_method_call)(const char * bus_name, const char * path, const char * iface, const char * method);
	void (*dbus_message_iter_init_append)(DBusMessage * message, DBusMessageIter * iter);
	dbus_bool_t (*dbus_message_iter_append_basic)(DBusMessageIter * iter, int type, const void * value);
	DBusMessage * (*dbus_connection_send_with_reply_and_block)(DBusConnection * connection, DBusMessage * message, int timeout_milliseconds, DBusError * error);
	dbus_bool_t (*dbus_set_error_from_message)(DBusError * error, DBusMessage * message);
	dbus_bool_t (*dbus_message_get_args)(DBusMessage * message, DBusError * error, int first_arg_type, va_list args);
	void (*dbus_message_unref)(DBusMessage * message);
	void (*dbus_connection_unref)(DBusConnection * connection);
	void (*dbus_error_free)(DBusError * error);
} DBUSFunctions;

extern DBUSFunctions dbus_funcs;


/*
dbus_bus_get
dbus_message_new_method_call
dbus_message_iter_init_append
dbus_message_iter_append_basic
dbus_connection_send_with_reply_and_block
dbus_set_error_from_message
dbus_message_get_args
dbus_message_unref
dbus_connection_unref
dbus_error_free


DBusConnection * dbus_bus_get(DBusBusType type, DBusError * error);
DBusMessage * dbus_message_new_method_call(const char * bus_name, const char * path, const char * iface, const char * method);
void dbus_message_iter_init_append (DBusMessage * message, DBusMessageIter * iter);
dbus_bool_t dbus_message_iter_append_basic (DBusMessageIter * iter, int type, const void * value);
DBusMessage * dbus_connection_send_with_reply_and_block (DBusConnection * connection, DBusMessage * message, int timeout_milliseconds, DBusError * error);
dbus_bool_t  dbus_set_error_from_message (DBusError * error, DBusMessage * message);
dbus_bool_t dbus_message_get_args (DBusMessage * message, DBusError * error, int first_arg_type, ...);
void dbus_message_unref (DBusMessage * message);
void dbus_connection_unref (DBusConnection * connection);
void dbus_error_free (DBusError * error);
*/

