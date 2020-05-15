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

#ifndef __MAP_EXTCFG_QTN_H__
#define __MAP_EXTCFG_QTN_H__

#define EXTCFG_DEBUG(fmt, ...)	fprintf(stdout, fmt, ##__VA_ARGS__)
#define EXTCFG_ERROR(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)

#define SSID_MAXLEN	32
#define KEY_MAXLEN	64
#define IFNAME_MAXLEN 16
#define MAX_MBSS_NUM 8

#ifdef QTN_REMOTE_RPC_CALL
void qtn_rpc_disconnect(void);
#ifdef Q_OPENWRT
int qtn_rpc_connect(const char *p_host);
#else
int qtn_rpc_connect(void);
#endif
#endif

#endif
