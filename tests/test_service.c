/**
 * @file
 * @author  cd611@cam.ac.uk
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
#include <pthread.h>
#include <stdbool.h>
#include <pico/shared.h>
#include "mockbt/mockbt.h"
#include <pico/sigmaverifier.h>
#include <pico/sigmaprover.h>
#include <pico/keypairing.h>
#include <pico/json.h>
#include <pico/base64.h>
#include <pico/cryptosupport.h>
#include <pico/sigmakeyderiv.h>
#include <pico/keyagreement.h>
#include <pico/messagestatus.h>
#include <pico/auth.h>
#include <picobt/bt.h>
#include <picobt/devicelist.h>
#include "../src/processstore.h"

#define BT_UUID_FORMAT		"%02x%02x%02x%02x-%02x%02x-%02x%02x-" \
								"%02x%02x-%02x%02x%02x%02x%02x%02x"
#define PICO_SERVICE_UUID "ed995e5a-c7e7-4442-a6ee-7bb76df43b0d"
#define TEST_OBJECT ((PicoUkAcCamClPicoInterface * )(0x0964d3a))
#define TEST_INVOCATION (GDBusMethodInvocation * )(0x742a64)
#define TEST_MESSAGE (GDBusMessage *)(0xa5def4)

// Defines
typedef enum _MODE {
    MODE_JSON,
    MODE_ANSI,
    MODE_COLOR_UTF8,
    MODE_COLORLESS_UTF8
} MODE;


typedef struct {
	char channel_name[64];
	char stored_extra_data[64];
	KeyPair * picoIdentityKey;
	bool expect_success;
} ProverThreadData;

// Function prototypes
void authenticate(int expectedResult, char const * in_user, char const * expectedFinalUser, char const * stored_password, KeyPair * picoIdentityKey, Buffer * symmetric, char const * options, bool respond_via_bt);
void service_auth(gboolean expected_result, char const * in_user, char const * expected_final_user, char const * stored_password, KeyPair * picoIdentityKey, Buffer * symmetric, char const * parameters, bool respond_via_bt);

void* prover_main(void * thread_data);
void get_allocated_channel_name(char const * channel_url_const, char * out);
void start_prover_thread(pthread_t * ptd, const char* qrText, char * stored_password, KeyPair * picoIdentityKey, bool expect_success);
void setup();
void teardown();

// From pico-continuous.c (has no header file).
static gboolean on_handle_start_auth(PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, const gchar * arg_username, const gchar * arg_parameters, gpointer user_data);
static gboolean on_handle_complete_auth(PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, gint handle, gpointer user_data);

// Global Variables
KeyPair * picoIdentityKey[3];
char * usernames[3] = { "Alice", "Bob", "Charlie" };
char * passwords[3] = { "Passuser0", "Passuser1", "Passnonuser" };
Buffer * symmetric[3];
char const * symmetric_b64[3] = {
	"75CPiTMM83sGP0B6W3qmvA==",
	"+tuLmm0nYpgVjlrYihL6IA==",
	"3I9iMFD5CxzvjZskXIVmBg=="
};
char const * public_b64[3] = {
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiU0jMUMQC0dzAthaD7bP/lf2jPPVAtaU2nXIE6RbJnFZ5aS2qpf9eUXgOVDi5HXYBRYrfh/v/SJJchQra2/9bA==",
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzpNscJDHgvg+49E79yDor/BP/ZFIXgmS5n9CaRUDN37mBgxeZFLWT2Q5PiNvOYsDm6yvt0VNCOz2r2vjRi+4qQ==",
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESxX3XWHn7u/pOcLm9UWW4uu6i/IQ+qwCBu59+SG1LNHcHf3IyTtIlZ7cync1UZENH/1u4S0XSc2Fzkfr2avPiQ=="
};
char const * private_b64[3] = {
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLhZ/3Y790j50DeFLwgOnvS7No2XDuTQvvZLWTMBEUZahRANCAASJTSMxQxALR3MC2FoPts/+V/aM89UC1pTadcgTpFsmcVnlpLaql/15ReA5UOLkddgFFit+H+/9IklyFCtrb/1s",
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8c/POOuOEr4JCZ7hZZYlFHLKecNZAvZmHMLAsx6j0CChRANCAATOk2xwkMeC+D7j0Tv3IOiv8E/9kUheCZLmf0JpFQM3fuYGDF5kUtZPZDk+I285iwObrK+3RU0I7Pava+NGL7ip",
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZqaZMBOHFy6gjIo/VHRDivyo5tPCnGn9Hn3zRXG4IhehRANCAARLFfddYefu7+k5wub1RZbi67qL8hD6rAIG7n35IbUs0dwd/cjJO0iVntzKdzVRkQ0f/W7hLRdJzYXOR+vZq8+J"
};

static gint global_handle;
static bool global_start_returned;
static bool global_complete_returned;
static char const * global_expected_user;
static int global_expected_result;
static pthread_t ptd;
static KeyPair * global_picoIdentityKey;
static Buffer * global_symmetric;
static char const * global_stored_password;
static bool global_respond_via_bt;

// Function definitions

GDBusMessage * g_dbus_method_invocation_get_message(GDBusMethodInvocation * invocation) {
	ck_assert(TEST_INVOCATION == invocation);
	return TEST_MESSAGE;
}

char const * g_dbus_message_get_sender(GDBusMessage * message) {
	ck_assert(TEST_MESSAGE == message);
	return NULL;
}


// Test fixture
void setup() {
	int count;
	EC_KEY * eckey;
	EVP_PKEY * evpkey;

	for (count = 0; count < 3; count++) {
		picoIdentityKey[count] = keypair_new();
		eckey = cryptosupport_read_base64_string_public_key(public_b64[count]);
		keypair_setpublickey(picoIdentityKey[count], eckey);

		evpkey = cryptosupport_read_base64_string_private_key(private_b64[count]);
		keypair_setprivatekey(picoIdentityKey[count], evpkey);

		symmetric[count] = buffer_new(CRYPTOSUPPORT_AESKEY_SIZE);
		base64_decode_mem(symmetric_b64[count], strlen(symmetric_b64[count]), symmetric[count]);
	}
}

void teardown() {
	int count;

	for (count = 0; count < 3; count++) {
		keypair_delete(picoIdentityKey[count]);
		buffer_delete(symmetric[count]);
	}
}

void* prover_main(void * thread_data) {
	ProverThreadData * data = (ProverThreadData*) thread_data;
	EC_KEY * eckey;
	EVP_PKEY * evpkey;
	Buffer * key_copy;

	RVPChannel * channel = channel_connect(data->channel_name);
	key_copy = buffer_new(0);

	// The next sequence of calls are used to copy the key
	// OpenSSL almost certainly has a better way, but this was works
	// for the sake of the tests

	// Copy the public key
	keypair_getpublicder(data->picoIdentityKey, key_copy);
	eckey = cryptosupport_read_buffer_public_key(key_copy);

	// Copy the private key
	buffer_clear(key_copy);
	evpkey = keypair_getprivatekey(data->picoIdentityKey);
	cryptosupport_getprivateder(evpkey, key_copy);
	evpkey = cryptosupport_read_buffer_private_key(key_copy);

	Shared * shared = shared_new();
	//shared_load_or_generate_pico_keys(shared, "keydir/pico_pub_key.der", "keydir/pico_priv_key.der");

	shared_set_pico_identity_public_key(shared, eckey);
	shared_set_pico_identity_private_key(shared, evpkey);

	Buffer * extraData = buffer_new(0);
	Buffer * returnedExtraData = buffer_new(0);
	buffer_append_string(extraData, data->stored_extra_data);

	bool result = sigmaprover(shared, channel, extraData, returnedExtraData);

	ck_assert(result);

	buffer_delete(returnedExtraData);
	buffer_delete(extraData);
	shared_delete(shared);
	channel_delete(channel);
	buffer_delete(key_copy);
	free(data);

	return NULL;
}

void get_allocated_channel_name(char const * channel_url_const, char * out) {
	char * channel_url = malloc(strlen(channel_url_const) + 1);
	strcpy(channel_url, channel_url_const);
	char* channel_name = strtok(channel_url, "/");
	channel_name = strtok(NULL, "/");
	channel_name = strtok(NULL, "/");
	channel_name = strtok(NULL, "/");
	strcpy(out, channel_name);
	free(channel_url);
}

void start_prover_thread(pthread_t * ptd, const char* qrText, char * stored_password, KeyPair * picoIdentityKey, bool expect_success) {
	Json* json = json_new();
	bool result;
	result = json_deserialize_string(json, qrText, strlen(qrText));

	if (result) {
		ProverThreadData * thread_data = malloc(sizeof(ProverThreadData));

		get_allocated_channel_name(json_get_string(json, "sa"), thread_data->channel_name);
		ck_assert_int_eq(strlen(thread_data->channel_name), 32);

		strcpy(thread_data->stored_extra_data, stored_password);
		thread_data->picoIdentityKey = picoIdentityKey;
		thread_data->expect_success = expect_success;

		pthread_create(ptd, NULL, prover_main, thread_data);
	}
	else {
		printf("Invalid QR code (not a JSON string)\n");
	}

	json_delete(json);
}

static gboolean on_handle_start_auth(PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, const gchar * arg_username, const gchar * arg_parameters, gpointer user_data) {
	ProcessStore * processstoredata = (ProcessStore *)user_data;
	bool result;

	result = start_auth(processstoredata, object, invocation, arg_username, arg_parameters);

	return result;
}

static gboolean on_handle_complete_auth(PicoUkAcCamClPicoInterface * object, GDBusMethodInvocation * invocation, gint handle, gpointer user_data) {
	ProcessStore * processstoredata = (ProcessStore *)user_data;
	bool result;

	result = complete_auth(processstoredata, object, invocation, handle);

	return result;
}

void service_auth(gboolean expected_result, char const * in_user, char const * expected_final_user, char const * stored_password, KeyPair * picoIdentityKey, Buffer * symmetric, char const * parameters, bool respond_via_bt) {
	gboolean result;
	GMainLoop * loop;
	ProcessStore * processstoredata;

	loop = NULL;
	processstoredata = processstore_new();
	processstore_set_loop(processstoredata, loop);
	global_expected_user = expected_final_user;
	global_expected_result = expected_result;
	global_picoIdentityKey = picoIdentityKey;
	global_symmetric = symmetric;
	global_stored_password = stored_password;
	global_respond_via_bt = respond_via_bt;

	global_handle = 0;
	global_start_returned = false;
	result = on_handle_start_auth(TEST_OBJECT, TEST_INVOCATION, in_user, parameters, processstoredata);

	printf("Waiting...\n");
	while (!global_start_returned) {
		sleep(0.5);
	}
	printf("Start returned\n");

	global_complete_returned = false;
	result = on_handle_complete_auth(TEST_OBJECT, TEST_INVOCATION, global_handle, processstoredata);

	printf("Waiting...\n");
	while (!global_complete_returned) {
		sleep(0.5);
	}
	printf("Complete returned\n");

	printf("Result: %d\n", result);

	processstore_delete(processstoredata);
}

void pico_uk_ac_cam_cl_pico_interface_complete_start_auth (PicoUkAcCamClPicoInterface *object, GDBusMethodInvocation *invocation, gint handle, const gchar *code, gboolean success) {
	ck_assert(TEST_OBJECT == object);
	ck_assert(TEST_INVOCATION == invocation);

	global_handle = handle;

	printf("QRCode: %s\n", code);
	printf("Result: %d\n", success);

	Buffer * passcipher = buffer_new(0);
	Buffer * passclear = buffer_new(0);
	buffer_clear(passclear);
	buffer_append_string(passclear, global_stored_password);

	cryptosupport_encrypt_iv_base64(global_symmetric, passclear, passcipher);

	if (global_respond_via_bt == false) {
		start_prover_thread(&ptd, code, buffer_get_buffer(passcipher), global_picoIdentityKey, global_expected_result);
	}

	global_start_returned = true;
}

void pico_uk_ac_cam_cl_pico_interface_complete_complete_auth (PicoUkAcCamClPicoInterface *object, GDBusMethodInvocation *invocation, const gchar *username, const gchar *password, gboolean success) {
	ck_assert_int_eq(global_expected_result, success);
	if (success) {
		ck_assert_str_eq(username, global_expected_user);
		ck_assert_str_eq(password, global_stored_password);
	}

	global_complete_returned = true;
}

void authenticate(int expectedResult, char const * in_user, char const * expectedFinalUser, char const * stored_password, KeyPair * picoIdentityKey, Buffer * symmetric, char const * options, bool respond_via_bt) {
	char * options_copy = strdup(options);
	bool calledBt = false;
	Buffer * passclear;
	Buffer * passcipher;

	// Calculate the encrypted authtok
	passcipher = buffer_new(0);
	passclear = buffer_new(0);
	buffer_clear(passclear);
	buffer_append_string(passclear, stored_password);

	cryptosupport_encrypt_iv_base64(symmetric, passclear, passcipher);
	buffer_append(passcipher, "", 1);

/*
	void send_to_list(bt_device_list_t const * list, bt_uuid_t const * service, int cycles, int pool_size, void const * message, size_t length, BeaconPoolContinue send_continue, void * data) {
		char uuidstr[37];
		sprintf(uuidstr, BT_UUID_FORMAT,
			service->b[ 0], service->b[ 1], service->b[ 2], service->b[ 3],
			service->b[ 4], service->b[ 5], service->b[ 6], service->b[ 7],
			service->b[ 8], service->b[ 9], service->b[10], service->b[11],
			service->b[12], service->b[13], service->b[14], service->b[15]);
		ck_assert_str_eq(uuidstr, PICO_SERVICE_UUID);
		ck_assert(strlen(message) == length);
		ck_assert(send_continue);
		ck_assert_int_gt(pool_size, 0);

		if (respond_via_bt) {
			start_prover_thread(&ptd, message, buffer_get_buffer(passcipher), picoIdentityKey, expectedResult);
		}
		calledBt = true;
	}
	bt_funcs.send_to_list = send_to_list;
	*/


	sdp_session_t *sdp_connect(const bdaddr_t *src, const bdaddr_t *dst, uint32_t flags) {
		if (respond_via_bt) {
			start_prover_thread(&ptd, "", buffer_get_buffer(passcipher), picoIdentityKey, expectedResult);
		}
		calledBt = true;
		return NULL;
	}
	bt_funcs.sdp_connect = sdp_connect;



	calledBt = false;

	service_auth(expectedResult, in_user, expectedFinalUser, stored_password, picoIdentityKey, symmetric, options, respond_via_bt);

	pthread_join(ptd, NULL);
	if (respond_via_bt) {
		ck_assert(calledBt);
	}

	buffer_delete(passcipher);
	buffer_delete(passclear);
	free(options_copy);
}

START_TEST(test_authenticate_right_user) {
	authenticate(true, "", usernames[0], passwords[0], picoIdentityKey[0], symmetric[0], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":0}", false);
	authenticate(true, "", usernames[1], passwords[1], picoIdentityKey[1], symmetric[1], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":0}", false);
}
END_TEST

START_TEST(test_authenticate_unpaired_user) {
	authenticate(false, "", NULL, passwords[2], picoIdentityKey[2], symmetric[2], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":0}", false);
}
END_TEST

START_TEST(test_authenticate_specific_user) {
	authenticate(true, usernames[0], usernames[0], passwords[0], picoIdentityKey[0], symmetric[0], "{\"continuous\": 0,\"anyuser\":0,\"beacons\":0}", false);
	authenticate(false, usernames[0], NULL, passwords[0], picoIdentityKey[1], symmetric[1], "{\"continuous\": 0,\"anyuser\":0,\"beacons\":0}", false);

	authenticate(false, usernames[0], NULL, passwords[2], picoIdentityKey[2], symmetric[2], "{\"continuous\": 0,\"anyuser\":0,\"beacons\":0}", false);

	authenticate(true, usernames[1], usernames[1], passwords[1], picoIdentityKey[1], symmetric[1], "{\"continuous\": 0,\"anyuser\":0,\"beacons\":0}", false);
}
END_TEST

START_TEST(authenticate_non_existent_user_fails_directly) {
	authenticate(false, "Conan", usernames[0], passwords[0], picoIdentityKey[0], symmetric[0], "{\"continuous\": 0,\"anyuser\":0,\"beacons\":0}", false);
}
END_TEST

START_TEST(test_authenticate_bluetooth_right_user) {
	authenticate(true, "", usernames[0], passwords[0], picoIdentityKey[0], symmetric[0], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":1}", true);
	authenticate(true, "", usernames[1], passwords[1], picoIdentityKey[1], symmetric[1], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":1}", true);
}
END_TEST


START_TEST(test_authenticate_bluetooth_unpaired_user) {
	authenticate(false, "", NULL, passwords[2], picoIdentityKey[2], symmetric[2], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":1}", true);
}
END_TEST

START_TEST(test_bluetooth_but_scan_qr_code) {
	authenticate(true, "", usernames[0], passwords[0], picoIdentityKey[0], symmetric[0], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":1}", false);
	authenticate(true, "", usernames[1], passwords[1], picoIdentityKey[1], symmetric[1], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":1}", false);
	authenticate(false, "", NULL, passwords[2], picoIdentityKey[2], symmetric[2], "{\"continuous\": 0,\"anyuser\":1,\"beacons\":1}", false);
}
END_TEST


int main (void) {
 	int number_failed;
 	Suite * s;
 	SRunner *sr;
 	TCase * tc;
 	
 	s = suite_create("Pico PAM");
 	
 	tc = tcase_create("Service test");
 	tcase_set_timeout(tc, 20.0);
	tcase_add_unchecked_fixture(tc, setup, teardown);
	tcase_add_test(tc, test_authenticate_right_user);
	tcase_add_test(tc, test_authenticate_unpaired_user);
	tcase_add_test(tc, test_authenticate_specific_user);
	tcase_add_test(tc, authenticate_non_existent_user_fails_directly);
	//tcase_add_test(tc, test_authenticate_bluetooth_right_user);
	//tcase_add_test(tc, test_authenticate_bluetooth_unpaired_user);
	//tcase_add_test(tc, test_bluetooth_but_scan_qr_code);
 	suite_add_tcase(s, tc);
 	sr = srunner_create(s);
 	
 	srunner_run_all(sr, CK_NORMAL);
 	number_failed = srunner_ntests_failed(sr);
 	srunner_free(sr);
 	
 	return (number_failed == 0) ? 0 : -1;
}

