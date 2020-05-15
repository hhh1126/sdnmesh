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

#ifndef __MAP_API_H__
#define __MAP_API_H__

#define MAP_INTF_OBJ_NAME		"qdock.hal.intf"

#define MAP_METHOD_GET_WIPHYS_NAME	"get_wiphys"
#define MAP_METHOD_GET_WDEVS_NAME	"get_wdevs"

#define MAP_EVENT_WIPHY_UPDATED_NAME	"wiphy_updated"
#define MAP_EVENT_WDEV_ADDED_NAME	"wdev_added"
#define MAP_EVENT_WDEV_UPDATED_NAME	"wdev_updated"
#define MAP_EVENT_WDEV_DELETED_NAME	"wdev_deleted"

#define MAP_MLME_OBJ_NAME		"qdock.hal.mlme"

#define MAP_METHOD_CONFIG_WIPHY_NAME	"config_wiphy"
#define MAP_METHOD_CREATE_WDEV_NAME	"create_wdev"
#define MAP_METHOD_DELETE_WDEV_NAME	"delete_wdev"
#define MAP_METHOD_CONFIG_WDEV_NAME	"config_wdev"
#define MAP_METHOD_START_WPS_NAME	"start_wps"
#define MAP_METHOD_GET_BSSCFGS_NAME	"get_bsscfgs"
#define MAP_METHOD_GET_DEVDATA_NAME	"get_devdata"
#define MAP_METHOD_GET_STATIONS_NAME	"get_stations"
#define MAP_METHOD_DEL_STATION_NAME	"del_station"
#define MAP_METHOD_FILTER_STATION_NAME	"filter_station"
#define MAP_METHOD_REG_FRAME_NAME	"reg_frame"
#define MAP_METHOD_SEND_FRAME_NAME	"send_frame"
#define MAP_METHOD_MONITOR_CHAN_NAME	"monitor_channel"
#define MAP_METHOD_ROAM_WDEV_NAME	"roam_wdev"


#define MAP_EVENT_WDEV_ASSOCIATED_NAME	"wdev_associated"
#define MAP_EVENT_STA_CONNECTED_NAME	"sta_connected"
#define MAP_EVENT_STA_DISCONNECTED_NAME	"sta_disconnected"
#define MAP_EVENT_FRAME_RECEIVED_NAME	"frame_received"

#define MAP_STATISTICS_OBJ_NAME		"qdock.hal.statistics"

#define MAP_METHOD_SET_PERIODS_NAME		"set_periods"
#define MAP_METHOD_GET_MONITOR_STATS_NAME	"get_monitor_stats"

#define MAP_EVENT_WDEV_STATS_UPDATED_NAME	"wdev_stats_updated"
#define MAP_EVENT_STA_STATS_UPDATED_NAME	"sta_stats_updated"
#define MAP_EVENT_MONITOR_STATS_UPDATED_NAME	"monitor_stats_updated"

#define MAP_ATTR_RC_NAME		"rc"
#define MAP_ATTR_WIPHY_ID_NAME		"wiphy_id"
#define MAP_ATTR_WIPHYS_NAME		"wiphys"
#define MAP_ATTR_WDEV_ID_NAME		"wdev_id"
#define MAP_ATTR_WDEV_NAME		"wdev"
#define MAP_ATTR_WDEVS_NAME		"wdevs"
#define MAP_ATTR_STA_MAC_NAME		"sta_mac"
#define MAP_ATTR_STATION_NAME		"station"
#define MAP_ATTR_STATIONS_NAME		"stations"
#define MAP_ATTR_FILTER_NAME		"filter"
#define MAP_ATTR_MGMT_SUBTYPE_NAME	"subtype"
#define MAP_ATTR_REASON_NAME		"reason"
#define MAP_ATTR_FRAME_MATCH_NAME	"frame_match"
#define MAP_ATTR_FRAME_NAME		"frame"
#define MAP_ATTR_STATS_PERIODS_NAME	"stats_periods"
#define MAP_ATTR_STATS_FAT_NAME		"stats_fat"
#define MAP_ATTR_STATS_STATION_NAME	"stats_station"
#define MAP_ATTR_STATS_MONITOR_NAME	"stats_monitor"
#define MAP_ATTR_ROAM_TARGET_NAME	"target"
#define MAP_ATTR_FRAME_RX_NAME		"rx"
#define MAP_ATTR_WITHHOLD_NAME		"withhold"
#define MAP_ATTR_RSSI_NAME		"rssi"
#define MAP_ATTR_CHANNEL_NAME		"channel"
enum map_attrs {
	MAP_ATTR_RC = 0,
	MAP_ATTR_WIPHY_ID,
	MAP_ATTR_WIPHYS,
	MAP_ATTR_WDEV_ID,
	MAP_ATTR_WDEV,
	MAP_ATTR_WDEVS,
	MAP_ATTR_STA_MAC,
	MAP_ATTR_STATION,
	MAP_ATTR_STATIONS,
	MAP_ATTR_MGMT_SUBTYPE,
	MAP_ATTR_REASON,
	MAP_ATTR_FRAME_MATCH,
	MAP_ATTR_FRAME,
	MAP_ATTR_STATS_PERIODS,
	MAP_ATTR_STATS_FAT,
	MAP_ATTR_STATS_STATION,
	MAP_ATTR_STATS_MONITOR,
	MAP_ATTR_ROAM_TARGET,
	MAP_ATTR_FRAME_RX,
	MAP_ATTR_WITHHOLD,
	MAP_ATTR_RSSI,
	MAP_ATTR_CHANNEL,

	/* keep last */
	NUM_MAP_ATTRS,
	MAX_MAP_ATTR = NUM_MAP_ATTRS - 1
};


#define MAP_DEVDATA_ATTR_DEVICE_NAME_NAME       "device_name"
#define MAP_DEVDATA_ATTR_MANUFACTURER_NAME_NAME "manufacturer_name"
#define MAP_DEVDATA_ATTR_MODEL_NAME_NAME        "model_name"
#define MAP_DEVDATA_ATTR_MODEL_NUMBER_NAME      "model_number"
#define MAP_DEVDATA_ATTR_SERIAL_NUMBER_NAME     "serial_number"

enum map_devdata_attrs {
	MAP_DEVDATA_ATTR_DEVICE_NAME,
	MAP_DEVDATA_ATTR_MANUFACTURER_NAME,
	MAP_DEVDATA_ATTR_MODEL_NAME,
	MAP_DEVDATA_ATTR_MODEL_NUMBER,
	MAP_DEVDATA_ATTR_SERIAL_NUMBER,

	/* keep last */
	NUM_MAP_DEVDATA_ATTRS,
	MAX_MAP_DEVDATA_ATTR = NUM_MAP_DEVDATA_ATTRS - 1
};

#define MAP_WIPHY_ATTR_ID_NAME		"id"
#define MAP_WIPHY_ATTR_NAME_NAME	"name"
#define MAP_WIPHY_ATTR_PHYTYPE_NAME	"phytype"
#define MAP_WIPHY_ATTR_OPCLASS_NAME	"opclass"
#define MAP_WIPHY_ATTR_CHAN_NAME	"chan"
#define MAP_WIPHY_ATTR_FREQ_NAME	"freq"
#define MAP_WIPHY_ATTR_BW_NAME		"bw"
#define MAP_WIPHY_ATTR_PS_STATE_NAME	"ps"
#define MAP_WIPHY_ATTR_TXPOWER_NAME	"power"
#define MAP_WIPHY_ATTR_FEATURES_NAME	"features"
#define MAP_WIPHY_ATTR_LIMITS_NAME	"limits"
#define MAP_WIPHY_ATTR_OPCLASSES_NAME	"opclasses"
#define MAP_WIPHY_ATTR_TEAR_DOWN_NAME	"tear_down"
enum map_wiphy_attrs {
	MAP_WIPHY_ATTR_ID = 0,
	MAP_WIPHY_ATTR_NAME,
	MAP_WIPHY_ATTR_PHYTYPE,
	MAP_WIPHY_ATTR_OPCLASS,
	MAP_WIPHY_ATTR_CHANNEL,
	MAP_WIPHY_ATTR_FREQ,
	MAP_WIPHY_ATTR_BW,
	MAP_WIPHY_ATTR_PS_STATE,
	MAP_WIPHY_ATTR_TXPOWER,
	MAP_WIPHY_ATTR_FEATURES,
	MAP_WIPHY_ATTR_LIMITS,
	MAP_WIPHY_ATTR_OPCLASSES,
	MAP_WIPHY_ATTR_TEAR_DOWN,

	/* keep last */
	NUM_MAP_WIPHY_ATTRS,
	MAX_MAP_WIPHY_ATTR = NUM_MAP_WIPHY_ATTRS - 1
};

#define MAP_LIMIT_ATTR_TYPES_NAME	"types"
#define MAP_LIMIT_ATTR_MAX_NAME		"max"
enum map_limit_attr {
	MAP_LIMIT_ATTR_TYPES = 0,
	MAP_LIMIT_ATTR_MAX,

	/* keep last */
	NUM_MAP_LIMIT_ATTRS,
	MAX_MAP_LIMIT_ATTR = NUM_MAP_LIMIT_ATTRS - 1
};

#define MAP_OPCLASS_ATTR_ID_NAME	"id"
#define MAP_OPCLASS_ATTR_BW_NAME	"bw"
#define MAP_OPCLASS_ATTR_MAX_POWER_NAME	"max_power"
#define MAP_OPCLASS_ATTR_CHANS_NAME	"chans"
enum map_opclass_attr {
	MAP_OPCLASS_ATTR_ID = 0,
	MAP_OPCLASS_ATTR_BW,
	MAP_OPCLASS_ATTR_MAX_POWER,
	MAP_OPCLASS_ATTR_CHANS,

	/* keep last */
	NUM_MAP_OPCLASS_ATTRS,
	MAX_MAP_OPCLASS_ATTR = NUM_MAP_OPCLASS_ATTRS - 1
};

#define MAP_CHAN_ATTR_CHAN_NAME		"chan"
#define MAP_CHAN_ATTR_FREQ_NAME		"freq"
#define MAP_CHAN_ATTR_NONOPERABLE_NAME	"nonoperable"
#define MAP_CHAN_ATTR_REASON_NAME	"reason"
#define MAP_CHAN_ATTR_PREF_NAME		"preference"
#define MAP_CHAN_ATTR_FREQ_SEP_NAME	"fraq_sep"
enum map_chan_attr {
	MAP_CHAN_ATTR_CHAN = 0,
	MAP_CHAN_ATTR_FREQ,
	MAP_CHAN_ATTR_NONOPERABLE,
	MAP_CHAN_ATTR_REASON,
	MAP_CHAN_ATTR_PREF,
	MAP_CHAN_ATTR_FREQ_SEP,

	/* keep last */
	NUM_MAP_CHAN_ATTRS,
	MAX_MAP_CHAN_ATTR = NUM_MAP_CHAN_ATTRS - 1
};

#define MAP_WDEV_ATTR_ID_NAME		"id"
#define MAP_WDEV_ATTR_NAME_NAME		"name"
#define MAP_WDEV_ATTR_WIPHY_ID_NAME	"wiphy_id"
#define MAP_WDEV_ATTR_IFTYPE_NAME	"iftype"
#define MAP_WDEV_ATTR_IFTYPE_1905_NAME	"iftype_1905"
#define MAP_WDEV_ATTR_MODE_NAME		"mode"
#define MAP_WDEV_ATTR_BSSID_NAME	"bssid"
#define MAP_WDEV_ATTR_SSID_NAME		"ssid"
#define MAP_WDEV_ATTR_BINTVL_NAME	"bintval"
#define MAP_WDEV_ATTR_HT_CAPA_NAME	"htcapa"
#define MAP_WDEV_ATTR_HT_OP_NAME	"htop"
#define MAP_WDEV_ATTR_VHT_CAPA_NAME	"vhtcapa"
#define MAP_WDEV_ATTR_VHT_OP_NAME	"vhtop"
#define MAP_WDEV_ATTR_HE_CAPA_NAME	"hecapa"
#define MAP_WDEV_ATTR_HE_OP_NAME	"heop"
#define MAP_WDEV_ATTR_AUTH_NAME		"auth"
#define MAP_WDEV_ATTR_ENCRYP_NAME	"encryp"
#define MAP_WDEV_ATTR_KEY_NAME		"key"
#define MAP_WDEV_ATTR_OPCLASS_NAME	"opclass"
#define MAP_WDEV_ATTR_CHAN_NAME		"chan"
#define MAP_WDEV_ATTR_CHAN_FREQ_NAME	"chan_freq"
#define MAP_WDEV_ATTR_DISABLE_NAME	"disable"
#define MAP_WDEV_ATTR_WPS_NAME		"wps"
#define MAP_WDEV_ATTR_MAP_MTYPES_NAME	"map_mtypes"
#define MAP_WDEV_ATTR_STATUS_NAME	"status"
#define MAP_WDEV_ATTR_ESPI_NAME		"espi"
#define MAP_WDEV_ATTR_FAT_NAME		"fat"
#define MAP_WDEV_ATTR_BACKHAUL_NAME	"backhaul"
#define MAP_WDEV_ATTR_EXTCAP_NAME	"extcap"
#define MAP_WDEV_ATTR_IES_NAME		"ies"
#define MAP_WDEV_ATTR_4ADDR_NAME	"4addr"
#define MAP_WDEV_ATTR_HIDE_NAME		"hide"
#define MAP_WDEV_ATTR_RF_BANDS_NAME "rf_bands"
#define MAP_WDEV_ATTR_CAPINFO_NAME  "capinfo"

enum map_wdev_attrs {
	MAP_WDEV_ATTR_ID = 0,
	MAP_WDEV_ATTR_NAME,
	MAP_WDEV_ATTR_WIPHY_ID,
	MAP_WDEV_ATTR_IFTYPE,
	MAP_WDEV_ATTR_IFTYPE_1905,
	MAP_WDEV_ATTR_MODE,
	MAP_WDEV_ATTR_BSSID,
	MAP_WDEV_ATTR_SSID,
	MAP_WDEV_ATTR_BINTVL,
	MAP_WDEV_ATTR_HT_CAPA,
	MAP_WDEV_ATTR_HT_OP,
	MAP_WDEV_ATTR_VHT_CAPA,
	MAP_WDEV_ATTR_VHT_OP,
	MAP_WDEV_ATTR_HE_CAPA,
	MAP_WDEV_ATTR_HE_OP,
	MAP_WDEV_ATTR_AUTH,
	MAP_WDEV_ATTR_ENCRYP,
	MAP_WDEV_ATTR_KEY,
	MAP_WDEV_ATTR_OPCLASS,
	MAP_WDEV_ATTR_CHAN,
	MAP_WDEV_ATTR_CHAN_FREQ,
	MAP_WDEV_ATTR_DISABLE,
	MAP_WDEV_ATTR_WPS,
	MAP_WDEV_ATTR_MAP_MTYPES,
	MAP_WDEV_ATTR_STATUS,
	MAP_WDEV_ATTR_ESPI,
	MAP_WDEV_ATTR_FAT,
	MAP_WDEV_ATTR_BACKHAUL,
	MAP_WDEV_ATTR_EXTCAP,
	MAP_WDEV_ATTR_IES,
	MAP_WDEV_ATTR_4ADDR,
	MAP_WDEV_ATTR_HIDE,
	MAP_WDEV_ATTR_RF_BANDS,
	MAP_WDEV_ATTR_CAPINFO,
	MAP_WDEV_ATTR_MAP_EXTELEM,

	/* keep last */
	NUM_MAP_WDEV_ATTRS,
	MAX_MAP_WDEV_ATTR = NUM_MAP_WDEV_ATTRS - 1
};

#define MAP_IE_ATTR_FRAME_MASK_NAME		"mask"
#define MAP_IE_ATTR_VALUE_NAME			"value"
enum map_ie_attrs {
	MAP_IE_ATTR_FRAME_MASK = 0,
	MAP_IE_ATTR_VALUE,

	/* keep last */
	NUM_MAP_IE_ATTRS,
	MAX_MAP_IE_ATTR = NUM_MAP_IE_ATTRS - 1
};

#define MAP_ESPI_ATTR_AC_NAME		"ac"
#define MAP_ESPI_ATTR_FORMAT_NAME	"format"
#define MAP_ESPI_ATTR_BA_SIZE_NAME	"ba_size"
#define MAP_ESPI_ATTR_EST_AIRTIME_NAME	"eatf"
#define MAP_ESPI_ATTR_PPDU_DUR_NAME	"ppdu_dur"
enum map_espi_attrs {
	MAP_ESPI_ATTR_AC = 0,
	MAP_ESPI_ATTR_FORMAT,
	MAP_ESPI_ATTR_BA_SIZE,
	MAP_ESPI_ATTR_EST_AIRTIME,
	MAP_ESPI_ATTR_PPDU_DUR,

	/* keep last */
	NUM_MAP_ESPI_ATTRS,
	MAX_MAP_ESPI_ATTR = NUM_MAP_ESPI_ATTRS - 1
};

#define MAP_STATION_ATTR_MAC_NAME		"mac"
#define MAP_STATION_ATTR_CHANNEL_NAME		"channel"
#define MAP_STATION_ATTR_AGE_NAME		"age"
#define MAP_STATION_ATTR_ASSOC_REQ_NAME		"assoc"
#define MAP_STATION_ATTR_RSSI_NAME		"rssi"
#define MAP_STATION_ATTR_OPCLASS_NAME		"opclass"
#define MAP_STATION_ATTR_RATE_DOWNLINK_NAME	"rate_dl"
#define MAP_STATION_ATTR_AGE_DOWNLINK_NAME	"age_dl"
#define MAP_STATION_ATTR_RATE_UPLINK_NAME	"rate_ul"
#define MAP_STATION_ATTR_AGE_UPLINK_NAME	"age_ul"
#define MAP_STATION_ATTR_TX_BYTES_NAME		"tx_bytes"
#define MAP_STATION_ATTR_RX_BYTES_NAME		"rx_bytes"
#define MAP_STATION_ATTR_TX_PACKETS_NAME	"tx_packets"
#define MAP_STATION_ATTR_RX_PACKETS_NAME	"rx_packets"
#define MAP_STATION_ATTR_TX_ERRORS_NAME		"tx_errors"
#define MAP_STATION_ATTR_RX_ERRORS_NAME		"rx_errors"
#define MAP_STATION_ATTR_TX_RETRIES_NAME	"tx_retries"
enum map_station_attrs {
	MAP_STATION_ATTR_MAC = 0,
	MAP_STATION_ATTR_CHANNEL,
	MAP_STATION_ATTR_AGE,
	MAP_STATION_ATTR_ASSOC_REQ,
	MAP_STATION_ATTR_RSSI,
	MAP_STATION_ATTR_OPCLASS,
	MAP_STATION_ATTR_RATE_DOWNLINK,
	MAP_STATION_ATTR_AGE_DOWNLINK,
	MAP_STATION_ATTR_RATE_UPLINK,
	MAP_STATION_ATTR_AGE_UPLINK,
	MAP_STATION_ATTR_TX_BYTES,
	MAP_STATION_ATTR_RX_BYTES,
	MAP_STATION_ATTR_TX_PACKETS,
	MAP_STATION_ATTR_RX_PACKETS,
	MAP_STATION_ATTR_TX_ERRORS,
	MAP_STATION_ATTR_RX_ERRORS,
	MAP_STATION_ATTR_TX_RETRIES,

	/* keep last */
	NUM_MAP_STATION_ATTRS,
	MAX_MAP_STATION_ATTR = NUM_MAP_STATION_ATTRS - 1
};

#define MAP_STATS_ATTR_WDEV_NAME		"wdev"
#define MAP_STATS_ATTR_STA_NAME			"sta"
#define MAP_STATS_ATTR_MONITOR_NAME		"monitor"
enum map_stats_attrs {
	MAP_STATS_ATTR_WDEV = 0,
	MAP_STATS_ATTR_STA,
	MAP_STATS_ATTR_MONITOR,

	/* keep last */
	NUM_MAP_STATS_ATTRS,
	MAX_MAP_STATS_ATTR = NUM_MAP_STATS_ATTRS - 1
};

#define MAP_FILTER_ATTR_MODE_NAME			"mode"
#define MAP_FILTER_ATTR_RSSI_NAME			"rssi"
#define MAP_FILTER_ATTR_MASK_NAME			"mask"
#define MAP_FILTER_ATTR_DURATION_NAME			"duration"
#define MAP_FILTER_ATTR_REJECT_NAME			"reject"
#define MAP_FILTER_ATTR_IES_NAME			"ies"
enum map_filter_attrs {
	MAP_FILTER_ATTR_MODE = 0,
	MAP_FILTER_ATTR_RSSI,
	MAP_FILTER_ATTR_MASK,
	MAP_FILTER_ATTR_DURATION,
	MAP_FILTER_ATTR_REJECT,
	MAP_FILTER_ATTR_IES,

	/* keep last */
	NUM_MAP_FILTER_ATTRS,
	MAX_MAP_FILTER_ATTR = NUM_MAP_FILTER_ATTRS - 1
};

#define MAP_BACKHAUL_ATTR_SSID_NAME			"ssid"
#define MAP_BACKHAUL_ATTR_AUTH_NAME			"auth"
#define MAP_BACKHAUL_ATTR_ENCRYP_NAME			"encryp"
#define MAP_BACKHAUL_ATTR_KEY_NAME			"key"
enum map_backhaul_attrs {
	MAP_BACKHAUL_ATTR_SSID = 0,
	MAP_BACKHAUL_ATTR_AUTH,
	MAP_BACKHAUL_ATTR_ENCRYP,
	MAP_BACKHAUL_ATTR_KEY,

	/* keep last */
	NUM_MAP_BACKHAUL_ATTRS,
	MAX_MAP_BACKHAUL_ATTR = NUM_MAP_BACKHAUL_ATTRS - 1
};


#define MAP_ATTRS_POLICY_INIT(_attr, _type)	[_attr] = { .name = _attr##_NAME, .type = _type }

enum map_response_code {
	MAP_RC_OK,		/*!< command call success */
	MAP_RC_INVALID_VALUE,	/*!< command invalid value parameters */
	MAP_RC_MISS_ARGUMENT,	/*!< command miss parameters */
	MAP_RC_NO_RESPONSE,	/*!< driver do not response the command */
	MAP_RC_NOT_SUPPORTED,	/*!< radio entity sevice/driver do not support this command */
	MAP_RC_UNKNOWN_ERROR,	/*!< failed with unknown error */
	__MAP_RC_LAST
};

enum map_phytype {
	MAP_PHYTYPE_UNSPECIFIED = 0,
	MAP_PHYTYPE_FHSS,
	MAP_PHYTYPE_DSSS,
	MAP_PHYTYPE_IRBASEBAND,
	MAP_PHYTYPE_OFDM,
	MAP_PHYTYPE_HRDSSS,
	MAP_PHYTYPE_ERP,
	MAP_PHYTYPE_HT,
	MAP_PHYTYPE_DMG,
	MAP_PHYTYPE_VHT,

	__MAP_MAP_PHYTYPE_LAST
};

enum map_band_width {
	MAP_BAND_WIDTH_20,
	MAP_BAND_WIDTH_40,
	MAP_BAND_WIDTH_80,
	MAP_BAND_WIDTH_160,
	MAP_BAND_WIDTH_80P80,
	MAP_BAND_WIDTH_5,
	MAP_BAND_WIDTH_10,

	__MAP_BAND_WIDTH_LAST
};

enum map_features {
	MAP_FEATURE_REPORT_ONCHAN_UNASSOC	= 1 << 7,
	MAP_FEATURE_REPORT_OFFCHAN_UNASSOC	= 1 << 6,
	MAP_FEATURE_RSSI_BASED_STEERING		= 1 << 5,
};

enum map_iftype {
	MAP_IFTYPE_UNSPECIFIED = 0,	/*!< unspecified type */
	MAP_IFTYPE_AP,			/*!< access point */
	MAP_IFTYPE_STATION,		/*!< managed BSS member */
	MAP_IFTYPE_WDS,			/*!< wireless distribution interface */
	MAP_IFTYPE_MONITOR,		/*!< monitor interface receiving all frames */

	__MAP_MAP_IFTYPE_LAST
};

enum map_channel_status {
	MAP_CHAN_STATUS_NON_OPERABLE = 0,
	MAP_CHAN_STATUS_AVAILABLE,
	MAP_CHAN_STATUS_DFS_USABLE,
	MAP_CHAN_STATUS_DFS_UNAVAILABLE,
	MAP_CHAN_STATUS_DFS_AVAILABLE,

	__MAP_CHAN_STATUS_LAST
};

// Note: map_auth follows Table 32 – Authentication Types
// in <Wi-Fi Simple Configuration Technical Specification v2.0>
enum map_auth {
	MAP_AUTH_OPEN			= 1 << 0,
	MAP_AUTH_WPAPSK			= 1 << 1,
	MAP_AUTH_SHARED			= 1 << 2,
	MAP_AUTH_WPA			= 1 << 3,
	MAP_AUTH_WPA2			= 1 << 4,
	MAP_AUTH_WPA2PSK		= 1 << 5,
};

enum map_encryp {
	MAP_ENCRYP_NONE			= 1 << 0,
	MAP_ENCRYP_WEP			= 1 << 1,
	MAP_ENCRYP_TKIP			= 1 << 2,
	MAP_ENCRYP_CCMP			= 1 << 3,
};

enum map_mtype {
	MAP_MTYPE_BACKHAUL_STA		= 1 << 7,
	MAP_MTYPE_BACKHAUL_BSS		= 1 << 6,
	MAP_MTYPE_FRONTHAUL_BSS		= 1 << 5,
};

enum map_filter_mode {
	MAP_FILTER_MODE_NONE		= 0,	/*!< No other criteria for filter, except the station's mac address */
	MAP_FILTER_MODE_MINRSSI		= 1,	/*!< Filter the frames which rssi is below the specified value */
	MAP_FILTER_MODE_MAXRSSI		= 2,	/*!< Filter the frames which rssi is above the specified value */

	__MAP_FILTER_MODE_LAST
};

enum map_roam_status {
	MAP_ROAM_STATUS_SUCCESS		= 0,
	MAP_ROAM_STATUS_UNKNOWN_BSSID,
	MAP_ROAM_STATUS_UNAVAIL_CHAN,
	MAP_ROAM_STATUS_NOTRX_PROBE_RESP,
	MAP_ROAM_STATUS_NOTRX_ASSOC_RESP,
	MAP_ROAM_STATUS_UNSPECIFIED,
	MAP_ROAM_STATUS_WRONG_KEY,

	__MAP_ROAM_STATUS_LAST
};

enum map_frame_rx {
	MAP_FRAME_RX_COPY		= 0,
	MAP_FRAME_RX_BY_PASS,

	__MAP_FRAME_RX_LAST
};

#endif
