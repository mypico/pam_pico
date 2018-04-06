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

#include <security/pam_appl.h>

#include <check.h>
#include <stdbool.h>
#include <pico/shared.h>
#include "mockpam/mockpam.h"

// Defines
#define PAM_CONST const


// Function prototypes
void prompt(pam_handle_t *pamh, int style, PAM_CONST char *prompt);
const char * get_user_name(pam_handle_t * pamh);

int returnValue;
char * username;
pam_handle_t * pam_handle_username = (pam_handle_t*) 0x1234;

pam_handle_t * pam_handle_success = (pam_handle_t*) 0x1234;
bool called_success = false;
struct pam_conv conv;

pam_handle_t * pam_handle_failure = (pam_handle_t*) 0x1234;
bool called_failure = false;

// Function definitions

static int get_user(pam_handle_t *pamh, const char **user, const char *prompt) {
	ck_assert(pamh == pam_handle_username);
	ck_assert(prompt == NULL);
	*user = username;
	return returnValue;
}

START_TEST(test_get_user_name) {
	pam_funcs.pam_get_user = get_user;

	returnValue = PAM_SUCCESS;
	username = "MYUSER1";
	ck_assert_str_eq(get_user_name(pam_handle_username), "MYUSER1");	
	username = "MYUSER2";
	ck_assert_str_eq(get_user_name(pam_handle_username), "MYUSER2");	
   	
	returnValue = PAM_SYSTEM_ERR;
	ck_assert(get_user_name(pam_handle_username) == NULL);	
}
END_TEST

static int conv_func(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr) {
	ck_assert(appdata_ptr == (void*) 0xDEADBEEF);
	ck_assert_int_eq(num_msg, 1);
	ck_assert(msg != NULL);	
	ck_assert(msg[0] != NULL);	
	ck_assert_str_eq(msg[0]->msg, "The Message");	
	ck_assert_int_eq(msg[0]->msg_style, PAM_TEXT_INFO);	
	*resp = NULL;
	called_success = true;
	return PAM_SUCCESS;
}

static int get_item_success(const pam_handle_t *pamh, int item_type, const void **item) {
	ck_assert(pamh == pam_handle_success);
	ck_assert_int_eq(item_type, PAM_CONV);
	ck_assert(item != NULL);
	*item = &conv;
	return PAM_SUCCESS;
}

START_TEST(test_prompt) {
	conv.appdata_ptr = (void*) 0xDEADBEEF;

	conv.conv = conv_func;

	pam_funcs.pam_get_item = get_item_success;

	called_success = false;
	prompt(pam_handle_success, PAM_TEXT_INFO, "The Message");
	ck_assert(called_success == true);
}
END_TEST

static int get_item_failure(const pam_handle_t *pamh, int item_type, const void **item) {
	ck_assert(pamh == pam_handle_failure);
	called_failure = true;
	return PAM_SYSTEM_ERR;
}

START_TEST(prompt_does_not_call_conv_if_get_item_returns_error) {
	pam_funcs.pam_get_item = get_item_failure;

	called_failure = false;
	prompt(pam_handle_failure, PAM_TEXT_INFO, "The Message");
	ck_assert(called_failure == true);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Pico PAM");

	// Base64 test case
	tc = tcase_create("Pam");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, test_get_user_name);
	tcase_add_test(tc, test_prompt);
	tcase_add_test(tc, prompt_does_not_call_conv_if_get_item_returns_error);

	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

