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
 */

/** @file
 * @brief Driver interface for QSR1000/QSR10K
 *
 * This file provides driver functionality using QDOCK API
 *
 */

#ifndef _PLATFORM_INTERFACES_QSR1000_PRIV_H_
#define _PLATFORM_INTERFACES_QSR1000_PRIV_H_

int qsr1000_init_push_button(void);
void qsr1000_deinit_push_button(int sk);
int qsr1000_check_button_pressed(int sk);

#endif
