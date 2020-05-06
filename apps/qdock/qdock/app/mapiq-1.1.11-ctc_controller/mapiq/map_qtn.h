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

#ifndef __MAP_QTN_H__
#define __MAP_QTN_H__

#include "map_common.h"
#include "mapiq_version.h"
#include "ieee80211_def.h"

typedef struct map_intf_cfg {
	char ssid[IEEE80211_SSID_MAXLEN + 1];
#define MAP_INTF_bBSS   (1 << 0)
#define MAP_INTF_fBSS   (1 << 1)
	uint8_t map_iftype;
	struct list_head lh;
} map_intf_cfg_t;

typedef struct map_cfg {
	pthread_mutex_t ifcfg_mutex;
	struct list_head ifcfg_head;
} map_cfg_t;

typedef struct map_ctx {
	void *ctx;

	struct ubus_context *ubus_ctx;

	uint8_t log_handle;

	uint8_t running;
	pthread_t thread;

	pthread_mutex_t evt_mutex;
	struct list_head evt_head;
	int evt_rxfd;
	int evt_txfd;

	uint32_t extcfg_objid;
} map_ctx_t;

typedef enum {
	MAP_BSS_INTF_STATE_UNKNOWN = 0,
	MAP_BSS_INTF_STATE_DOWN = 1,
	MAP_BSS_INTF_STATE_UP = 2,
	MAP_BSS_INTF_STATE_DELETED = 3,
} map_bss_intf_state;

extern map_ctx_t g_ctx;
extern map_cfg_t g_cfg;

#endif
