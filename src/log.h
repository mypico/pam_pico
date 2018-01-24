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
 * @brief Log data to syslog
 * @section DESCRIPTION
 *
 * The log interface provides various macros for logging, which simply
 * wrap the standard syslog calls.
 *
 * There is no source file associated with this header.
 *
 */

/** \addtogroup Service
 *  @{
 */

#ifndef __LOG_H
#define __LOG_H (1)

#include <syslog.h>

// Defines

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

//#define LOG(level_, ...) printf(__VA_ARGS__);
#define LOG(level_, ...) syslog((level_), __VA_ARGS__)

// Used to convert macro definitions into strings
// which can be useful for includingn them in logging strings
// See https://stackoverflow.com/a/2653351
#define PICOPAM_STR(a) PICOPAM_PREPROC(a)
#define PICOPAM_PREPROC(a) #a

// Structure definitions

// Function definitions

#endif

/** @} addtogroup Service */

