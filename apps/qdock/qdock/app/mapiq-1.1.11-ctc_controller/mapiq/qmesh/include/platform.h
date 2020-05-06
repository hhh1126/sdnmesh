/*
 *  Copyright (c) 2018-2019, Semiconductor Components Industries, LLC
 *  ("ON Semiconductor")   f/k/a Quantenna. All rights reserved.
 *  This software and/or documentation is licensed by ON Semiconductor under
 *  limited terms and conditions.  The terms and conditions pertaining to the
 *  software and/or documentation are available at
 *  http://www.onsemi.com/site/pdf/ONSEMI_T&C.pdf ("ON Semiconductor Standard
 *  Terms and Conditions of Sale, Section 8 Software").  Reproduction and
 *  redistribution in binary form, without modification, for use solely in
 *  conjunction with a Quantenna chipset, is permitted with an executed
 *  Quantenna Software Licensing Agreement and in compliance with the terms
 *  therein and all applicable laws. Do not use this software and/or
 *  documentation unless you have carefully read and you agree to the limited
 *  terms and conditions.  By using this software and/or documentation, you
 *  agree to the limited terms and conditions.
 *
 *  Portions of this software may include:
 *  Broadband Forum IEEE 1905.1/1a stack
 *  Copyright (c) 2017, Broadband Forum
 *  prplMesh Wi-Fi Multi-AP
 *  Copyright (c) 2018, prpl Foundation
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <stdarg.h>   // va_list
#include <stddef.h>
#include <stdint.h>

////////////////////////////////////////////////////////////////////////////////
// Hardware stuff
////////////////////////////////////////////////////////////////////////////////

// The following preprocessor macros must be defined to a platform-dependent
// value:
//
//   _HOST_IS_LITTLE_ENDIAN_        |--> Set one (and only one!) of these macros
//   _HOST_IS_BIG_ENDIAN_ENDIAN_    |    to "1" to indicate your CPU endianness
//
//
//   MAX_NETWORK_SEGMENT_SIZE  --------> This is the maximum packet size that
//                                       is allowed in your platform. It is
//                                       used to 'fragment' CMDUs.  Note that
//                                       even if your platform supports packets
//                                       bigger than 1500 bytes, this macro
//                                       must never be bigger than that.  This
//                                       macro is only present in this file for
//                                       those special cases where, for some
//                                       platform related reason, packets must
//                                       be smaller than 1500.
//
//
// In the next few lines we are just going to check that these are defined,
// nothing else.
// In order to actually define them use the "root" Makefile where these MACROS
// are sent to the compiler using the "-D flag" (open the "root" Makefile and
// search for "CCFLAGS" to understand how to do this)

#if !defined(_HOST_IS_LITTLE_ENDIAN_) && !defined(_HOST_IS_BIG_ENDIAN_ENDIAN_)
#  error  "You must define either '_HOST_IS_LITTLE_ENDIAN_' or '_HOST_IS_BIG_ENDIAN_'"
#elif defined(_HOST_IS_LITTLE_ENDIAN_) && defined(_HOST_IS_BIG_ENDIAN_ENDIAN_)
#  error  "You cannot define both '_HOST_IS_LITTLE_ENDIAN_' and '_HOST_IS_BIG_ENDIAN_' at the same time"
#endif

#ifndef  MAX_NETWORK_SEGMENT_SIZE
#  error  "You must define 'MAX_NETWORK_SEGMENT_SIZE' to some value (for example, '1500')"
#endif


////////////////////////////////////////////////////////////////////////////////
// Typical libc stuff
////////////////////////////////////////////////////////////////////////////////

// Output the provided format string (see 'man 3 printf' on any Linux box)
//
void PLATFORM_PRINTF(const char *format, ...) __attribute__((format (printf, 1, 2)));

void PLATFORM_PRINTF_RAW_ERROR(const char *format, ...);
void PLATFORM_PRINTF_RAW_WARNING(const char *format, ...);
void PLATFORM_PRINTF_RAW_INFO(const char *format, ...);
void PLATFORM_PRINTF_RAW_DETAIL(const char *format, ...);

// Same as 'PLATFORM_PRINTF', but the message will only be processed if the
// platform has the pertaining debug level enabled
//
void platform_printf_debug_error(const char *func, uint32_t line, const char *format, ...);
void platform_printf_debug_warning(const char *func, uint32_t line, const char *format, ...);
void platform_printf_debug_info(const char *func, uint32_t line, const char *format, ...);
void platform_printf_debug_detail(const char *func, uint32_t line, const char *format, ...);
void platform_printf_debug_verbose(const char *func, uint32_t line, const char *format, ...);
#define PLATFORM_PRINTF_DEBUG_ERROR(...) platform_printf_debug_error(__FUNCTION__, __LINE__, __VA_ARGS__)
#define PLATFORM_PRINTF_DEBUG_WARNING(...) platform_printf_debug_warning(__FUNCTION__, __LINE__, __VA_ARGS__)
#define PLATFORM_PRINTF_DEBUG_INFO(...) platform_printf_debug_info(__FUNCTION__, __LINE__, __VA_ARGS__)
#define PLATFORM_PRINTF_DEBUG_DETAIL(...) platform_printf_debug_detail(__FUNCTION__, __LINE__, __VA_ARGS__)
#define PLATFORM_PRINTF_DEBUG_VERBOSE(...) platform_printf_debug_verbose(__FUNCTION__, __LINE__, __VA_ARGS__)

// Used to set the verbosity of the previous functions:
//
//   0 => Only print ERROR messages
//   1 => Print ERROR and WARNING messages
//   2 => Print ERROR, WARNING and INFO messages
//   3 => Print ERROR, WARNING, INFO and DETAIL messages
//
void PLATFORM_PRINTF_DEBUG_SET_VERBOSITY_LEVEL(int level);

// Return the number of milliseconds ellapsed since the program started
//
uint32_t PLATFORM_GET_TIMESTAMP(void);


////////////////////////////////////////////////////////////////////////////////
// Misc stuff
////////////////////////////////////////////////////////////////////////////////

// [PLATFORM PORTING NOTE]
//   Depending on what other platform headers you have included up until this
//   point, 'NULL' might or might not be defined. If so, define it here
//
#ifndef NULL
#  define NULL (0x0)
#endif


////////////////////////////////////////////////////////////////////////////////
// Initialization functions
////////////////////////////////////////////////////////////////////////////////

// This function *must* be called before any other "PLATFORM_*()" API function
//
// Returns "0" if there was a problem. "1" otherwise.
//
// [PLATFORM PORTING NOTE]
//   Use this function to reserve memory, initialize semaphores, etc...
//
uint8_t PLATFORM_INIT(void);

#define DUMP_RX_PACKETS     (1 << 0)
#define DUMP_TX_PACKETS     (1 << 1)
void PLATFORM_SET_DUMP_PACKETS(uint8_t mask, uint32_t kbytes);
void PLATFORM_DUMP_PACKETS_INTO_FILE(uint32_t type, const char *ifname, uint8_t *packet, uint32_t len);

#include <libubox/uloop.h>
struct platform_timer
{
    struct uloop_timeout to;
    uint32_t ms;
    void *ctx;
    void *param;
    void (*cb)(void *ctx, void *param);
};

void *PLATFORM_SET_TIMEOUT(uint32_t ms,
    void (*cb)(void *, void *), void *ctx, void *param);
int PLATFORM_CANCEL_TIMEOUT(void *id);

#include <libubus.h>
struct ubus_context *platform_ubus;
uint16_t _check_register_message_type(uint16_t type);

#endif
