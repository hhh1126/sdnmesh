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

#ifndef __MAP_EXTCFG_H__
#define __MAP_EXTCFG_H__

#define MAP_EXTCFG_OBJ_NAME		"map.extcfg"

#define MAP_EXTCFG_METHOD_CFG_WIPHY	"cfg_wiphy"
#define MAP_EXTCFG_METHOD_ADD_WDEV	"add_wdev"
#define MAP_EXTCFG_METHOD_DEL_WDEV	"del_wdev"
#define MAP_EXTCFG_METHOD_CFG_WDEV	"cfg_wdev"
#define MAP_EXTCFG_METHOD_START_WPS	"start_wps"
#define MAP_EXTCFG_METHOD_GET_BSSCFG	"get_bsscfg"
#define MAP_EXTCFG_METHOD_GET_DEVDATA   "get_devdata"
#define MAP_EXTCFG_METHOD_START_MAP_AGENT	"start_map_agent"
#define MAP_EXTCFG_METHOD_START_MAP_CONTROLLER	"start_map_controller"

/* Attributes of device data parameters*/
#define MAP_EXTCFG_DEVDATA_ATTR_DEVICE_NAME_NAME       "device_name"
#define MAP_EXTCFG_DEVDATA_ATTR_MANUFACTURER_NAME_NAME "manufacturer_name"
#define MAP_EXTCFG_DEVDATA_ATTR_MODEL_NAME_NAME        "model_name"
#define MAP_EXTCFG_DEVDATA_ATTR_MODEL_NUMBER_NAME      "model_number"
#define MAP_EXTCFG_DEVDATA_ATTR_SERIAL_NUMBER_NAME     "serial_number"

/* Attributes of radio parameters*/
#define MAP_EXTCFG_WIPHY_ATTR_WIPHY_NAME	"wiphy"
#define MAP_EXTCFG_WIPHY_ATTR_TEARDOWN_NAME	"teardown"

/* Attributes of bss parameters*/
#define MAP_EXTCFG_ATTR_WDEV_NAME		"wdev"
#define MAP_EXTCFG_ATTR_WIPHY_NAME		"wiphy"
#define MAP_EXTCFG_ATTR_MODE_NAME		"mode"
#define MAP_EXTCFG_ATTR_SSID_NAME		"ssid"
#define MAP_EXTCFG_ATTR_AUTH_NAME		"auth"
#define MAP_EXTCFG_ATTR_ENCRYP_NAME		"encryp"
#define MAP_EXTCFG_ATTR_KEY_NAME		"key"
#define MAP_EXTCFG_ATTR_DISABLE_NAME		"disable"
#define MAP_EXTCFG_ATTR_WPS_NAME		"wps"
#define MAP_EXTCFG_ATTR_MAP_TYPES_NAME		"map_types"
#define MAP_EXTCFG_ATTR_BACKHAUL_NAME		"backhaul"
#define MAP_EXTCFG_ATTR_4ADDR_NAME		"4addr"
#define MAP_EXTCFG_ATTR_HIDE_SSID_NAME		"hide_ssid"


enum map_extcfg_devdata_attrs {
	MAP_EXTCFG_DEVDATA_ATTR_DEVICE_NAME,
	MAP_EXTCFG_DEVDATA_ATTR_MANUFACTURER_NAME,
	MAP_EXTCFG_DEVDATA_ATTR_MODEL_NAME,
	MAP_EXTCFG_DEVDATA_ATTR_MODEL_NUMBER,
	MAP_EXTCFG_DEVDATA_ATTR_SERIAL_NUMBER,

	/* keep last */
	NUM_MAP_EXTCFG_DEVDATA_ATTRS,
	MAX_MAP_EXTCFG_DEVDATA_ATTR = NUM_MAP_EXTCFG_DEVDATA_ATTRS - 1
};

enum map_extcfg_wiphy_attrs {
	MAP_EXTCFG_WIPHY_ATTR_WIPHY,
	MAP_EXTCFG_WIPHY_ATTR_TEARDOWN,

	/* keep last */
	NUM_MAP_EXTCFG_WIPHY_ATTRS,
	MAX_MAP_EXTCFG_WIPHY_ATTR = NUM_MAP_EXTCFG_WIPHY_ATTRS - 1
};

enum map_extcfg_wdev_attrs {
	MAP_EXTCFG_ATTR_WDEV = 0,
	MAP_EXTCFG_ATTR_WIPHY,
	MAP_EXTCFG_ATTR_MODE,
	MAP_EXTCFG_ATTR_SSID,
	MAP_EXTCFG_ATTR_AUTH,
	MAP_EXTCFG_ATTR_ENCRYP,
	MAP_EXTCFG_ATTR_KEY,
	MAP_EXTCFG_ATTR_DISABLE,
	MAP_EXTCFG_ATTR_WPS,
	MAP_EXTCFG_ATTR_MAP_TYPES,
	MAP_EXTCFG_ATTR_BACKHAUL,
	MAP_EXTCFG_ATTR_4ADDR,
	MAP_EXTCFG_ATTR_HIDE_SSID,

	/* keep last */
	NUM_MAP_EXTCFG_ATTRS,
	MAX_MAP_EXTCFG_ATTR = NUM_MAP_EXTCFG_ATTRS - 1
};

#define MAP_EXTCFG_BACKHAUL_ATTR_SSID_NAME			"ssid"
#define MAP_EXTCFG_BACKHAUL_ATTR_AUTH_NAME			"auth"
#define MAP_EXTCFG_BACKHAUL_ATTR_ENCRYP_NAME			"encryp"
#define MAP_EXTCFG_BACKHAUL_ATTR_KEY_NAME			"key"
enum map_extcfg_backhaul_attrs {
	MAP_EXTCFG_BACKHAUL_ATTR_SSID = 0,
	MAP_EXTCFG_BACKHAUL_ATTR_AUTH,
	MAP_EXTCFG_BACKHAUL_ATTR_ENCRYP,
	MAP_EXTCFG_BACKHAUL_ATTR_KEY,

	/* keep last */
	NUM_MAP_EXTCFG_BACKHAUL_ATTRS,
	MAX_MAP_EXTCFG_BACKHAUL_ATTR = NUM_MAP_EXTCFG_BACKHAUL_ATTRS - 1
};

// Note: map_auth_modes follows Table 32 – Authentication Types
// in <Wi-Fi Simple Configuration Technical Specification v2.0>
enum map_auth_modes {
	MAP_IEEE80211_AUTH_MODE_OPEN = 1 << 0,
	MAP_IEEE80211_AUTH_MODE_WPAPSK = 1 << 1,
	MAP_IEEE80211_AUTH_MODE_SHARED = 1 << 2,
	MAP_IEEE80211_AUTH_MODE_WPA = 1 << 3,
	MAP_IEEE80211_AUTH_MODE_WPA2 = 1 << 4,
	MAP_IEEE80211_AUTH_MODE_WPA2PSK = 1 << 5,
};

enum map_encryp_modes {
	MAP_IEEE80211_ENCRYP_MODE_NONE = 1 << 0,
	MAP_IEEE80211_ENCRYP_MODE_WEP = 1 << 1,
	MAP_IEEE80211_ENCRYP_MODE_TKIP = 1 << 2,
	MAP_IEEE80211_ENCRYP_MODE_AES = 1 << 3,
};

enum map_interface_types {
	MAP_INTERFACE_TYPE_UNSPECIFIED = 0,
	MAP_INTERFACE_TYPE_AP,                 /*!< access point */
	MAP_INTERFACE_TYPE_STATION,            /*!< managed BSS member */
	MAP_INTERFACE_TYPE_WDS,                /*!< wireless distribution interface */
	MAP_INTERFACE_TYPE_MONITOR,            /*!< monitor interface receiving all frames */
};

enum map_interface_mtypes {
	MAP_INTERFACE_MTYPE_BACKHAUL_STA	= 1 << 7,
	MAP_INTERFACE_MTYPE_BACKHAUL_BSS	= 1 << 6,
	MAP_INTERFACE_MTYPE_FRONTHAUL_BSS	= 1 << 5,
};

#endif
