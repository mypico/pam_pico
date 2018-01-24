/**
 * @file
 * @author cd611@cam.ac.uk
 * @version 1.0
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
 * @section DESCRIPTION
 *
 */

#include <check.h>
#include <stdbool.h>
#include <pico/shared.h>
#include "mockpam/mockpam.h"
#include "mockdbus/mockdbus.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

// pam_pico.c has no header file, so we proved the function signature here
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);

typedef enum _STAGE {
	STAGE_INVALID = -1,
	STAGE_START,
	STAGE_ITER_APPEND_FIRST,
	STAGE_ADDED_USERNAME,
	STAGE_ADDED_PARAMETERS,
	STAGE_REPLIED_TO_FIRST,
	STAGE_ITER_APPEND_SECOND,
	STAGE_ADDED_HANDLE,
	STAGE_REPLIED_TO_SECOND,
	STAGE_NUM
} STAGE;

// Values used to complete full successful execution

char * username = "MYUSER1";
char * password = "MyPassword1";
DBusConnection * connection_used = (DBusConnection *)0x9ec7a9d;
DBusMessage * message_first = (DBusMessage *)0x123456fa;
DBusMessage * message_second = (DBusMessage *)0x123457da;
DBusMessage * reply = (DBusMessage *)0x9e81a9d2;
pam_handle_t * pam_handle = (pam_handle_t*) 0x1234;
int handle_used = 3652;
int result;
STAGE stage;
bool error_freed;
DBusMessageIter * iter_used;
struct pam_conv conv;
int argc;
const char *argv[10];

// Override functions used to complete full successful execution

static int test_conv_func(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr) {
	ck_assert(appdata_ptr == (void*) 0xDEADBEEF);
	ck_assert_int_eq(num_msg, 1);
	ck_assert(msg != NULL);
	ck_assert(msg[0] != NULL);
	*resp = NULL;
	return PAM_SUCCESS;
}

static int test_get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
	ck_assert(pamh == pam_handle);
	ck_assert(prompt == NULL);
	*user = username;
	return PAM_SUCCESS;
}

static int test_set_item(pam_handle_t *pamh, int item_type, const void *item) {
	ck_assert(pamh == pam_handle);
	switch (item_type) {
	case PAM_USER:
		ck_assert_str_eq(item, username);
		break;
	case PAM_AUTHTOK:
		ck_assert_str_eq(item, password);
		break;
	default:
		ck_assert_msg(false, "Setting unexpected pam item");
		break;
	}
	return PAM_SUCCESS;
}

static int test_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
	ck_assert(pamh == pam_handle);
	ck_assert_int_eq(item_type, PAM_CONV);
	ck_assert(item != NULL);
	*item = &conv;
	return PAM_SUCCESS;
}

static DBusConnection * test_dbus_bus_get(DBusBusType type, DBusError * error) {
	ck_assert(error);

	return connection_used;
}

static void test_dbus_error_free(DBusError * error) {
	ck_assert(error);
	error_freed = true;
}

static DBusMessage * test_dbus_message_new_method_call(const char * bus_name, const char * path, const char * iface, const char * method) {
	DBusMessage * message;
	ck_assert(stage != STAGE_INVALID);
	ck_assert_str_eq(bus_name, "uk.ac.cam.cl.pico.service");
	ck_assert_str_eq(path, "/PicoObject");
	ck_assert_str_eq(iface, "uk.ac.cam.cl.pico.interface");
	if (stage < STAGE_REPLIED_TO_FIRST) {
		ck_assert_str_eq(method, "StartAuth");
		message = message_first;
	}
	else {
		ck_assert_str_eq(method, "CompleteAuth");
		message = message_second;
	}

	return message;
}

static void test_dbus_message_iter_init_append(DBusMessage * message, DBusMessageIter * iter) {
	ck_assert(stage != STAGE_INVALID);
	ck_assert(iter);
	iter_used = iter;
	if (stage < STAGE_REPLIED_TO_FIRST) {
		ck_assert(message == message_first);
		ck_assert(stage < STAGE_ITER_APPEND_FIRST);
		stage = STAGE_ITER_APPEND_FIRST;
	}
	else {
		ck_assert(message == message_second);
		ck_assert(stage < STAGE_ITER_APPEND_SECOND);
		stage = STAGE_ITER_APPEND_SECOND;
	}
}

static dbus_bool_t test_dbus_message_iter_append_basic(DBusMessageIter * iter, int type, const void * value) {
	ck_assert(stage != STAGE_INVALID);
	ck_assert(iter == iter_used);
	switch (stage) {
	case STAGE_ITER_APPEND_FIRST:
		ck_assert(stage < STAGE_REPLIED_TO_FIRST);
		ck_assert(type == DBUS_TYPE_STRING);
		ck_assert_str_eq(*(char **)value, username);
		stage = STAGE_ADDED_USERNAME;
		break;
	case STAGE_ADDED_USERNAME:
		ck_assert(stage >= STAGE_ITER_APPEND_FIRST);
		ck_assert(stage < STAGE_REPLIED_TO_FIRST);
		ck_assert(type == DBUS_TYPE_STRING);
		//ck_assert_str_eq(*(char **)value, "{\"anyuser\":1,\"beacons\":1,\"channeltype\":\"rvp\",\"continuous\":0}");
		stage = STAGE_ADDED_PARAMETERS;
		break;
	case STAGE_ITER_APPEND_SECOND:
		ck_assert(stage < STAGE_REPLIED_TO_SECOND);
		ck_assert(type == DBUS_TYPE_INT32);
		ck_assert_int_eq(*(int*)value, handle_used);
		stage = STAGE_ADDED_HANDLE;
		break;
	default:
		ck_assert_msg(false, "Incorrect parameters added to dbus message");
		break;
	}

	return true;
}

static DBusMessage * test_dbus_connection_send_with_reply_and_block(DBusConnection * connection, DBusMessage * message, int timeout_milliseconds, DBusError * error) {
	ck_assert(stage != STAGE_INVALID);
	ck_assert(connection_used == connection);
	ck_assert_int_gt(timeout_milliseconds, 0);
	ck_assert(error);

	ck_assert_msg(((message == message_first) || (message == message_second)), "Adding parameters to invalid message");

	if (message == message_first) {
		ck_assert(stage >= STAGE_ADDED_PARAMETERS);
		ck_assert(stage < STAGE_REPLIED_TO_FIRST);
		stage = STAGE_REPLIED_TO_FIRST;
	}

	if (message == message_second) {
		ck_assert(stage >= STAGE_ADDED_HANDLE);
		ck_assert(stage < STAGE_REPLIED_TO_SECOND);
		stage = STAGE_REPLIED_TO_SECOND;
	}

	return reply;
}

static dbus_bool_t test_dbus_set_error_from_message(DBusError * error, DBusMessage * message) {
	ck_assert(error);
	ck_assert(reply == message);
	ck_assert(stage != STAGE_INVALID);
	ck_assert(stage >= STAGE_REPLIED_TO_FIRST);

	return false;
}


static dbus_bool_t test_dbus_message_get_args(DBusMessage * message, DBusError * error, int first_arg_type, va_list args) {
	int arg_type = -1;
	int * handle_ptr = NULL;
	bool * success_ptr = NULL;
	char ** code_ptr = NULL;
	char ** username_ptr = NULL;
	char ** password_ptr = NULL;

	if (stage < STAGE_ITER_APPEND_SECOND) {
		ck_assert(first_arg_type == DBUS_TYPE_INT32);
		handle_ptr = va_arg(args, int*);
		ck_assert(handle_ptr);
		*handle_ptr = handle_used;

		arg_type = va_arg(args, int);
		ck_assert(arg_type == DBUS_TYPE_STRING);
		code_ptr = va_arg(args, char**);
		ck_assert(code_ptr);
		*code_ptr = "QR code";

		arg_type = va_arg(args, int);
		ck_assert(arg_type == DBUS_TYPE_BOOLEAN);
		success_ptr = va_arg(args, bool*);
		ck_assert(success_ptr);
		*success_ptr = true;
	}
	else {
		ck_assert(first_arg_type == DBUS_TYPE_STRING);
		username_ptr = va_arg(args, char**);
		ck_assert(username_ptr);
		*username_ptr = username;

		arg_type = va_arg(args, int);
		ck_assert(arg_type == DBUS_TYPE_STRING);
		password_ptr = va_arg(args, char**);
		ck_assert(password_ptr);
		*password_ptr = password;

		arg_type = va_arg(args, int);
		ck_assert(arg_type == DBUS_TYPE_BOOLEAN);
		success_ptr = va_arg(args, bool*);
		ck_assert(success_ptr);
		*success_ptr = true;
	}

	arg_type = va_arg(args, int);
	ck_assert(arg_type == DBUS_TYPE_INVALID);

	return true;
}

// Se defaults for complete full successful execution
static void set_default_auth_success() {
	iter_used = NULL;
	conv.appdata_ptr = (void*) 0xDEADBEEF;
	result = false;
	error_freed = false;
	argc = 7;
	argv[0] = "qrtype=json";
	argv[1] = "beacons=0";
	argv[2] = "anyuser=1";
	argv[3] = "input=0";
	argv[4] = "foo";
	argv[5] = "foo=bar";
	argv[6] = "channeltype=btc";
	stage = STAGE_START;

	conv.conv = test_conv_func;
	pam_funcs.pam_get_user = test_get_user;
	pam_funcs.pam_set_item = test_set_item;
	pam_funcs.pam_get_item = test_get_item;
	dbus_funcs.dbus_bus_get = test_dbus_bus_get;
	dbus_funcs.dbus_error_free = test_dbus_error_free;
	dbus_funcs.dbus_message_new_method_call = test_dbus_message_new_method_call;
	dbus_funcs.dbus_message_iter_init_append = test_dbus_message_iter_init_append;
	dbus_funcs.dbus_message_iter_append_basic = test_dbus_message_iter_append_basic;
	dbus_funcs.dbus_connection_send_with_reply_and_block = test_dbus_connection_send_with_reply_and_block;
	dbus_funcs.dbus_set_error_from_message = test_dbus_set_error_from_message;
	dbus_funcs.dbus_message_get_args = test_dbus_message_get_args;
}

//////////////////////////////////////
// Auth tests

START_TEST(test_dbus_call_order) {
	set_default_auth_success();

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_SUCCESS);
}
END_TEST

START_TEST(test_dbus_no_bus_first) {
	set_default_auth_success();

	DBusConnection * test_dbus_bus_get_fail(DBusBusType type, DBusError * error) {
		DBusConnection * connection = NULL;
		ck_assert(error);
		if (stage >= STAGE_REPLIED_TO_FIRST) {
			connection = connection_used;
		}
		return connection;
	}
	dbus_funcs.dbus_bus_get = test_dbus_bus_get_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage < STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_no_bus_second) {
	set_default_auth_success();

	DBusConnection * test_dbus_bus_get_fail(DBusBusType type, DBusError * error) {
		DBusConnection * connection = NULL;
		ck_assert(error);
		if (stage < STAGE_REPLIED_TO_FIRST) {
			connection = connection_used;
		}
		return connection;
	}
	dbus_funcs.dbus_bus_get = test_dbus_bus_get_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage >= STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_no_method_first) {
	set_default_auth_success();

	DBusMessage * test_dbus_message_new_method_call_fail(const char * bus_name, const char * path, const char * iface, const char * method) {
		DBusMessage * message;
		if (stage < STAGE_REPLIED_TO_FIRST) {
			message = NULL;
		}
		else {
			message = message_second;
		}

		return message;
	}

	dbus_funcs.dbus_message_new_method_call = test_dbus_message_new_method_call_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage < STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_no_method_second) {
	set_default_auth_success();

	DBusMessage * test_dbus_message_new_method_call_fail(const char * bus_name, const char * path, const char * iface, const char * method) {
		DBusMessage * message;
		if (stage < STAGE_REPLIED_TO_FIRST) {
			message = message_first;
		}
		else {
			message = NULL;
		}

		return message;
	}

	dbus_funcs.dbus_message_new_method_call = test_dbus_message_new_method_call_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage >= STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_send_fail_first) {
	set_default_auth_success();

	DBusMessage * test_dbus_connection_send_with_reply_and_block_fail(DBusConnection * connection, DBusMessage * message, int timeout_milliseconds, DBusError * error) {
		DBusMessage * reply_back;

		if (message == message_first) {
			stage = STAGE_REPLIED_TO_FIRST;
			reply_back = NULL;
		}

		if (message == message_second) {
			stage = STAGE_REPLIED_TO_SECOND;
			reply_back = reply;
		}

		return reply_back;
	}
	dbus_funcs.dbus_connection_send_with_reply_and_block = test_dbus_connection_send_with_reply_and_block_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage <= STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_send_fail_second) {
	set_default_auth_success();

	DBusMessage * test_dbus_connection_send_with_reply_and_block_fail(DBusConnection * connection, DBusMessage * message, int timeout_milliseconds, DBusError * error) {
		DBusMessage * reply_back = NULL;

		if (message == message_first) {
			stage = STAGE_REPLIED_TO_FIRST;
			reply_back = reply;
		}

		if (message == message_second) {
			stage = STAGE_REPLIED_TO_SECOND;
			reply_back = NULL;
		}

		return reply_back;
	}
	dbus_funcs.dbus_connection_send_with_reply_and_block = test_dbus_connection_send_with_reply_and_block_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage > STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_error_first) {
	set_default_auth_success();

	dbus_bool_t test_dbus_set_error_from_message_fail(DBusError * error, DBusMessage * message) {
		dbus_bool_t result = false;

		if (stage < STAGE_REPLIED_TO_SECOND) {
			result = true;
		}
		ck_assert(error);
		error->name = "error name";
		error->message = "error message";

		return result;
	}
	dbus_funcs.dbus_set_error_from_message = test_dbus_set_error_from_message_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage <= STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_error_second) {
	set_default_auth_success();

	dbus_bool_t test_dbus_set_error_from_message_fail(DBusError * error, DBusMessage * message) {
		dbus_bool_t result = false;

		if (stage >= STAGE_REPLIED_TO_SECOND) {
			result = true;
		}
		ck_assert(error);
		error->name = "error name";
		error->message = "error message";

		return result;
	}
	dbus_funcs.dbus_set_error_from_message = test_dbus_set_error_from_message_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage >= STAGE_REPLIED_TO_SECOND);
}
END_TEST

START_TEST(test_dbus_get_args_first) {
	set_default_auth_success();

	dbus_bool_t test_dbus_message_get_args_fail(DBusMessage * message, DBusError * error, int first_arg_type, va_list args) {
		int arg_type = -1;
		bool * success_ptr = NULL;
		char ** username_ptr = NULL;
		char ** password_ptr = NULL;
		dbus_bool_t result = false;

		if (stage < STAGE_ITER_APPEND_SECOND) {
			result = false;
		}
		else {
			ck_assert(first_arg_type == DBUS_TYPE_STRING);
			username_ptr = va_arg(args, char**);
			ck_assert(username_ptr);
			*username_ptr = username;

			arg_type = va_arg(args, int);
			ck_assert(arg_type == DBUS_TYPE_STRING);
			password_ptr = va_arg(args, char**);
			ck_assert(password_ptr);
			*password_ptr = password;

			arg_type = va_arg(args, int);
			ck_assert(arg_type == DBUS_TYPE_BOOLEAN);
			success_ptr = va_arg(args, bool*);
			ck_assert(success_ptr);
			*success_ptr = true;

			arg_type = va_arg(args, int);
			ck_assert(arg_type == DBUS_TYPE_INVALID);

			result = true;
		}

		return result;
	}
	dbus_funcs.dbus_message_get_args = test_dbus_message_get_args_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage <= STAGE_REPLIED_TO_FIRST);
}
END_TEST

START_TEST(test_dbus_get_args_second) {
	set_default_auth_success();

	dbus_bool_t test_dbus_message_get_args_fail(DBusMessage * message, DBusError * error, int first_arg_type, va_list args) {
		int arg_type = -1;
		int * handle_ptr = NULL;
		bool * success_ptr = NULL;
		char ** code_ptr = NULL;
		dbus_bool_t result = false;

		if (stage < STAGE_ITER_APPEND_SECOND) {
			ck_assert(first_arg_type == DBUS_TYPE_INT32);
			handle_ptr = va_arg(args, int*);
			ck_assert(handle_ptr);
			*handle_ptr = handle_used;

			arg_type = va_arg(args, int);
			ck_assert(arg_type == DBUS_TYPE_STRING);
			code_ptr = va_arg(args, char**);
			ck_assert(code_ptr);
			*code_ptr = "QR code";

			arg_type = va_arg(args, int);
			ck_assert(arg_type == DBUS_TYPE_BOOLEAN);
			success_ptr = va_arg(args, bool*);
			ck_assert(success_ptr);
			*success_ptr = true;

			arg_type = va_arg(args, int);
			ck_assert(arg_type == DBUS_TYPE_INVALID);

			result = true;
		}
		else {
			result = false;
		}

		return result;
	}
	dbus_funcs.dbus_message_get_args = test_dbus_message_get_args_fail;

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_AUTH_ERR);
	ck_assert(stage >= STAGE_REPLIED_TO_SECOND);
}
END_TEST

START_TEST(test_dbus_call_order_colorless_utf8) {
	argv[0] = "colorless_utf8";

	set_default_auth_success();

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_SUCCESS);
}
END_TEST

START_TEST(test_dbus_call_order_ansi) {
	argv[0] = "ansi";

	set_default_auth_success();

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_SUCCESS);
}
END_TEST

START_TEST(test_dbus_call_order_tt_tag) {
	argv[0] = "tt_tag";

	set_default_auth_success();

	result = pam_sm_authenticate(pam_handle, 0, argc, argv);
	ck_assert_msg(error_freed, "DBUS error structure not freed");
	ck_assert_int_eq(result, PAM_SUCCESS);
}
END_TEST


int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Pico PAM");

	// Base64 test case
	tc = tcase_create("Auth");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, test_dbus_call_order);
	tcase_add_test(tc, test_dbus_no_bus_first);
	tcase_add_test(tc, test_dbus_no_bus_second);
	tcase_add_test(tc, test_dbus_no_method_first);
	tcase_add_test(tc, test_dbus_no_method_second);
	tcase_add_test(tc, test_dbus_send_fail_first);
	tcase_add_test(tc, test_dbus_send_fail_second);
	tcase_add_test(tc, test_dbus_error_first);
	tcase_add_test(tc, test_dbus_error_second);
	tcase_add_test(tc, test_dbus_get_args_first);
	tcase_add_test(tc, test_dbus_get_args_second);
	tcase_add_test(tc, test_dbus_call_order_colorless_utf8);
	tcase_add_test(tc, test_dbus_call_order_ansi);
	tcase_add_test(tc, test_dbus_call_order_tt_tag);

	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

