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
 * @brief Bluetooth beacon tests
 * @section DESCRIPTION
 *
 * Performs unit test for the Bluetooth beacons.
 *
 */

#include <check.h>
#include <stdbool.h>
#include <unistd.h>
#include <pico/shared.h>
#include <pico/users.h>
#include <pico/beacons.h>

// Defines

// Structure definitions

// Function prototypes

// Function definitions

START_TEST(test_beacons) {
	// Currently no tests
	// Left for future use
}
END_TEST



int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Pico Bluetooth Beacon");

	// Base64 test case
	tc = tcase_create("Beacons");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, test_beacons);

	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}
