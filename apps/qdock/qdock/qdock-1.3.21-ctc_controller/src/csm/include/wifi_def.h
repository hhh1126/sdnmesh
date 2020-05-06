/*SH0
 * *******************************************************************************
 * **                                                                           **
 * **         Copyright (c) 2018 Quantenna Communications, Inc.          **
 * **         All rights reserved.                                              **
 * **                                                                           **
 * *******************************************************************************
 * EH0*/

#ifndef __WIFI_DEF_H__
#define __WIFI_DEF_H__

#define WIFI_MBO_OCE_OUI		"\x50\x6f\x9a\x16"
#define WIFI_MBO_ANQP_OUI		"\x50\x6f\x9a\x12"
#define WIFI_MBO_NONPROF_CHAN_OUI	"\x50\x6f\x9a\x02"
#define WIFI_MAP_OUI			"\x50\x6f\x9a\x1b"

static inline int is_wifi_mbo_oce_ie(uint8_t *frm)
{
	return (frm && frm[1] >= 4
		&& (memcmp(frm + 2, WIFI_MBO_OCE_OUI, 4) == 0));
}

static inline int is_wifi_mbo_anqp_vendor_ie(uint8_t *frm)
{
	return (frm && frm[1] >= 4
		&& (memcmp(frm + 2, WIFI_MBO_ANQP_OUI, 4) == 0));
}

static inline int is_wifi_mbo_nonpref_chan_ie(uint8_t *frm)
{
	return (frm && frm[1] >= 4
		&& (memcmp(frm + 2, WIFI_MBO_NONPROF_CHAN_OUI, 4) == 0));
}

static inline uint32_t built_mbo_oce_ie(uint8_t *frm, uint8_t attr_len)
{
	*frm++ = 0xdd;
	*frm++ = 4 + attr_len;
	memcpy(frm, WIFI_MBO_OCE_OUI, 4);
	return attr_len + 4 + 2;
}

/* MBO attributes */
#define WIFI_MBO_ATTR_AP_CAP_IND		1
#define WIFI_MBO_ATTR_NONPREF_CHAN		2
#define WIFI_MBO_ATTR_CELL_CAP			3
#define WIFI_MBO_ATTR_ASSOC_DISALLOWED		4
#define WIFI_MBO_ATTR_CELL_PREF			5
#define WIFI_MBO_ATTR_TRANS_REASON		6
#define WIFI_MBO_ATTR_TRANS_REJECT_REASON	7
#define WIFI_MBO_ATTR_ASSOC_DELAY		8

/* Association Disallowed Reason Code field values */
enum {
	WIFI_MBO_DISALLOW_REASON_RESERVED = 0,
	WIFI_MBO_DISALLOW_REASON_UNSPECIFIED,
	WIFI_MBO_DISALLOW_REASON_MAX_REACHED,
	WIFI_MBO_DISALLOW_REASON_FAT_OVERLOADED,
	WIFI_MBO_DISALLOW_REASON_AUTH_OVERLOADED,
	WIFI_MBO_DISALLOW_REASON_INSUFF_RSSI,
};

/* Transition Reason Code field values */
enum {
	WIFI_MBO_TRANS_REASON_UNSPECIFIED = 0,
};

/* MAP attributes */
#define WIFI_MAP_ATTR_EXT			6

enum {
	WIFI_MAP_BACKHAUL_STA		= (1 << 7),
	WIFI_MAP_BACKHAUL_BSS		= (1 << 6),
	WIFI_MAP_FRONTHAUL_BSS		= (1 << 5),
};

#endif

