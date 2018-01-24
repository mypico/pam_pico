#include "mockdbus.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

DBusConnection * dbus_bus_get_default(DBusBusType type, DBusError * error) {
	return NULL;
}

DBusMessage * dbus_message_new_method_call_default(const char * bus_name, const char * path, const char * iface, const char * method) {
	return NULL;
}

void dbus_message_iter_init_append_default(DBusMessage * message, DBusMessageIter * iter) {
}

dbus_bool_t dbus_message_iter_append_basic_default(DBusMessageIter * iter, int type, const void * value) {
	return true;
}

DBusMessage * dbus_connection_send_with_reply_and_block_default(DBusConnection * connection, DBusMessage * message, int timeout_milliseconds, DBusError * error) {
	return NULL;
}

dbus_bool_t dbus_set_error_from_message_default(DBusError * error, DBusMessage * message) {
	return true;
}

dbus_bool_t dbus_message_get_args_default(DBusMessage * message, DBusError * error, int first_arg_type, va_list args) {
	return true;
}

void dbus_message_unref_default(DBusMessage * message) {
}

void dbus_connection_unref_default(DBusConnection * connection) {
}

void dbus_error_free_default(DBusError * error) {
}

DBUSFunctions dbus_funcs = {
	.dbus_bus_get = dbus_bus_get_default,
	.dbus_message_new_method_call = dbus_message_new_method_call_default,
	.dbus_message_iter_init_append = dbus_message_iter_init_append_default,
	.dbus_message_iter_append_basic = dbus_message_iter_append_basic_default,
	.dbus_connection_send_with_reply_and_block = dbus_connection_send_with_reply_and_block_default,
	.dbus_set_error_from_message = dbus_set_error_from_message_default,
	.dbus_message_get_args = dbus_message_get_args_default,
	.dbus_message_unref = dbus_message_unref_default,
	.dbus_connection_unref = dbus_connection_unref_default,
	.dbus_error_free = dbus_error_free_default,
};

DBusConnection * dbus_bus_get(DBusBusType type, DBusError * error) {
	return dbus_funcs.dbus_bus_get(type, error);
}

DBusMessage * dbus_message_new_method_call(const char * bus_name, const char * path, const char * iface, const char * method) {
	return dbus_funcs.dbus_message_new_method_call(bus_name, path, iface, method);
}

void dbus_message_iter_init_append(DBusMessage * message, DBusMessageIter * iter) {
	dbus_funcs.dbus_message_iter_init_append(message, iter);
}

dbus_bool_t dbus_message_iter_append_basic(DBusMessageIter * iter, int type, const void * value) {
	return dbus_funcs.dbus_message_iter_append_basic(iter, type, value);
}

DBusMessage * dbus_connection_send_with_reply_and_block(DBusConnection * connection, DBusMessage * message, int timeout_milliseconds, DBusError * error) {
	return dbus_funcs.dbus_connection_send_with_reply_and_block(connection, message, timeout_milliseconds, error);
}

dbus_bool_t  dbus_set_error_from_message(DBusError * error, DBusMessage * message) {
	return dbus_funcs.dbus_set_error_from_message(error, message);
}

dbus_bool_t dbus_message_get_args(DBusMessage * message, DBusError * error, int first_arg_type, ...) {
	va_list args;
	dbus_bool_t result;

	va_start(args, first_arg_type);
	result = dbus_funcs.dbus_message_get_args(message, error, first_arg_type, args);
	va_end(args);

	return result;
}

void dbus_message_unref(DBusMessage * message) {
	dbus_funcs.dbus_message_unref(message);
}

void dbus_connection_unref(DBusConnection * connection) {
	dbus_funcs.dbus_connection_unref(connection);
}

void dbus_error_free(DBusError * error) {
	dbus_funcs.dbus_error_free(error);
}



