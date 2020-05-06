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

#ifndef __MAP_SERVER_H__
#define __MAP_SERVER_H__

#ifdef MAPIQ_DEVID_STRING_FORMAT
#define MAP_DEVID_LEN	18		/* xx:xx:xx:xx:xx:xx */
#define MAP_BLOBMSG_TYPE_MAC	BLOBMSG_TYPE_STRING
#else
#define MAP_DEVID_LEN	ETH_ALEN
#define MAP_BLOBMSG_TYPE_MAC	BLOBMSG_TYPE_UNSPEC
#endif

#define MAP_DEVID_EQ(_a, _b)	MAP_MAC_EQ(_a, _b)

enum map_event_id {
	MAP_EVENT_WIPHY_UPDATED = 0,
	MAP_EVENT_WDEV_ADDED,
	MAP_EVENT_WDEV_UPDATED,
	MAP_EVENT_WDEV_DELETED,
	MAP_EVENT_WDEV_ASSOCIATED,
	MAP_EVENT_STA_CONNECTED,
	MAP_EVENT_STA_DISCONNECTED,
	MAP_EVENT_FRAME_RECEIVED,
	MAP_EVENT_WDEV_STATS_UPDATED,
	MAP_EVENT_STA_STATS_UPDATED,
	MAP_EVENT_MON_STATS_UPDATED,
	MAP_EVENT_WDEV_STATE_UPDATED,

	__MAP_EVENT_LAST
};

typedef struct map_event {
	int id;
	uint8_t dev_id[ETH_ALEN];
	union {
		uint8_t sta[ETH_ALEN];
		uint8_t radio[ETH_ALEN];
	} u;
	uint8_t *frame;
	uint16_t frame_len;
	uint8_t roam_result;
#define RSSI_ADV_LEN 4
	uint8_t rssi_adv[RSSI_ADV_LEN];
	uint8_t state;
	struct list_head lh;
} map_event_t;

typedef struct map_wdev_timeout_entry {
	struct list_head lh;
	uint8_t dev_id[ETH_ALEN];
	uint32_t fat_period;
	uint32_t sta_period;
	uint32_t mon_period;
	#define MAX_MAP_TIMER_NUM	3
	struct uloop_timeout *timeout[MAX_MAP_TIMER_NUM];
} map_wdev_timeout_entry_t;

enum map_sta_filter_timer_entry_search_type {
	MAP_STA_FILTER_TIMER_ENTRY_SEARCH_BY_TIMEOUT = 0,
	MAP_STA_FILTER_TIMER_ENTRY_SEARCH_BY_STA_MAC,
};

typedef struct map_sta_filter_timeout_entry {
	struct list_head lh;
	uint8_t dev_id[ETH_ALEN];
	uint8_t sta_id[ETH_ALEN];
	struct uloop_timeout *timeout;
} map_sta_filter_timeout_entry_t;

typedef struct map_bsscfg {
	uint32_t auth_mode;      /**< Authentication mode. */
	uint32_t encrypt;        /**< encrypt type. */
	uint8_t *ssid;           /**< SSID used on this BSS. */
	uint32_t ssid_len;       /**< Length of SSID. */
	uint8_t *key; 			 /**< Shared key. */
	uint32_t key_len;        /**< Length of key. */
#define MAP_BSSCFG_MTYPES_INVALID (0xffffffff)
	uint32_t mtypes;         /**< Multi-AP types */
} map_bsscfg_t;

typedef struct map_devdata {
	char *device_name      ; /**< Device Name (0..32 octets encoded in UTF-8). */
	char *manufacturer_name; /**< Manufacturer (0..64 octets encoded in UTF-8). */
	char *model_name       ; /**< Model Name (0..32 octets encoded in UTF-8). */
	char *model_number     ; /**< Model Number (0..32 octets encoded in UTF-8). */
	char *serial_number    ; /**< Serial Number (0..32 octets encoded in UTF-8). */
} map_devdata_t;


extern int map_service_init(void);
extern void map_service_deinit(void);
extern void map_notify_event(map_event_t *event);

extern void map_blobmsg_add_mac(const char *name, uint8_t *mac);
extern void map_blobmsg_get_mac(struct blob_attr *attr, uint8_t *mac);

extern int map_extcfg_init(void);
extern void map_extcfg_deinit(void);
extern int map_extcfg_cfg_wiphy(const char *wiphy_name, struct blob_attr **info);
extern int map_extcfg_add_wdev(const char *wiphy_name, struct blob_attr **info, char *ifname);
extern int map_extcfg_del_wdev(const char *wdev_name);
extern int map_extcfg_cfg_wdev(const char *wdev_name, struct blob_attr **info,
	int is_configured, struct blob_attr **backhaul_info);
extern int map_extcfg_start_wps(const char *wdev_name);
extern int map_extcfg_get_bsscfg(const char *wdev_name, map_bsscfg_t *bss_cfg);
extern int map_extcfg_get_devdata(map_devdata_t *dev_data);
extern void map_send_event(map_event_t *evt);
#endif
