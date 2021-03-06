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

#ifndef _AL_H_
#define _AL_H_

#define AL_ERROR_OUT_OF_MEMORY      (1)
#define AL_ERROR_INVALID_ARGUMENTS  (2)
#define AL_ERROR_NO_INTERFACES      (3)
#define AL_ERROR_INTERFACE_ERROR    (4)
#define AL_ERROR_OS                 (5)
#define AL_ERROR_PROTOCOL_EXTENSION (6)

// This is the function that runs the 1905 Abstraction Layer (AL) state machine.
//
// In order to start the AL services this is what you have to do from your
// platform specific code:
//
//   1. Create a thread
//   2. Make that thread execute this function
//
// Before calling this function, the platform and al_datamodel must have been initialized.
//
// It returns when:
//
//   - Something went terribly wrong (maybe at initiallization time or maybe
//     later, while doing its bussiness). It that case it returns an error code
//     which is always bigger than '0':
//
//       AL_ERROR_OUT_OF_MEMORY:
//         A call to "memalloc()" failed, meaning there is no more memory
//         available in the system.
//
//       AL_ERROR_INVALID_ARGUMENTS:
//         The provided 'al_mac_address' is not valid.
//
//       AL_ERROR_NO_INTERFACES:
//         A call to "PLATFORM_GET_LIST_OF_1905_INTERFACES()" returned an empty
//         list, meaning there is nothing for the 1905 AL entity to do.
//
//       AL_ERROR_INTERFACE_ERROR:
//         A call to "PLATFORM_GET_LIST_OF_1905_INTERFACES() returned an error
//         or some other interface related problem.
//
//       AL_ERROR_OS:
//         One of the OS-related PLATFORM_* functions returned an error (these
//         are functions use to create queues, start timers, etc...)
//
//       AL_ERROR_PROTOCOL_EXTENSION;
//         Error registering, at least, one protocol extension.
//
//   - The HLE requested the AL service to stop. In this case it will return '0'
//
uint8_t start1905AL(void);

// This function for process all type AL Events.
// if you need deal with AL Event in main-thread,
// call it directly.
void process_ALEvent_by_MainThread(uint8_t *queue_message);

// This function sends an "AP-autoconfig WSC M1" message on all authenticated
// interfaces BUT ONLY if there is at least one unconfigured AP interface on
// this node.
uint8_t triggerDeviceAPAutoConfiguration(bool imm);

// This function sends an "AP-autoconfig Search" message on all authenticated interfaces
void triggerAPSearchProcess(void);

// This function sends an "AP-autoconfig Renew" message on all authenticated interfaces
void tiggerAPAutoconfigurationRenewProcess(void);

#endif

