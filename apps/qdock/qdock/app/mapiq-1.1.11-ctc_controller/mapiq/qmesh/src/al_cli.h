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
 * @brief interface for CLI
 *
 * This file provides functionality for CLI
 */

#ifndef AL_CLI_H
#define AL_CLI_H

#define MAPCLI_OBJ_NAME        "map.cli"

#define MAPCLI_METHOD_SHOW_NAME         "show"
#define MAPCLI_METHOD_GET_CONF_NAME     "get_conf"
#define MAPCLI_METHOD_SET_CONF_NAME     "set_conf"
#define MAPCLI_METHOD_SYNC_BSSCFGS_NAME "sync_bsscfgs"
#define MAPCLI_METHOD_START_WPS_NAME    "start_wps"
#define MAPCLI_METHOD_SEND_1905_NAME    "send_1905"
#define MAPCLI_METHOD_TEST_NAME         "test"
#ifdef Q_STEERING_LOGIC
#define MAPCLI_METHOD_GET_QSTEERING_CONF_NAME     "get_qsteering_conf"
#define MAPCLI_METHOD_SET_QSTEERING_CONF_NAME     "set_qsteering_conf"
#endif

#define MAPCLI_ATTR_RC_NAME             "rc"
#define MAPCLI_ATTR_HELP_NAME           "help"
#define MAPCLI_ATTR_VERSION_NAME        "version"
#define MAPCLI_ATTR_VERBOSE_NAME        "verbose"
#define MAPCLI_ATTR_TABLE_NAME          "table"
#define MAPCLI_ATTR_WIPHYS_NAME         "wiphys"
#define MAPCLI_ATTR_WDEVS_NAME          "wdevs"
#define MAPCLI_ATTR_CLIENTS_NAME        "clients"
#define MAPCLI_ATTR_MONITORS_NAME       "monitors"
#define MAPCLI_ATTR_NETWORKS_NAME       "networks"
#define MAPCLI_ATTR_MAC_NAME            "mac"
#define MAPCLI_ATTR_CONFIGS_NAME        "configs"
#define MAPCLI_ATTR_SUBCMD_NAME         "subcmd"
#define MAPCLI_ATTR_PARAMS_NAME         "params"
#define MAPCLI_ATTR_NETWORKS_NAME       "networks"

#define MAPCLI_WIPHY_ATTR_ID_NAME               "uid"
#define MAPCLI_WIPHY_ATTR_IFNAME_NAME           "ifname"
#define MAPCLI_WIPHY_ATTR_MAXBSSES_NAME         "max_bsses"
#define MAPCLI_WIPHY_ATTR_MON_OFFCHAN_NAME      "monitor_offchan"
#define MAPCLI_WIPHY_ATTR_MON_ONCHAN_NAME       "monitor_onchan"
#define MAPCLI_WIPHY_ATTR_SELF_STEERING_NAME    "self_steering"
#define MAPCLI_WIPHY_ATTR_OPCLASS_NAME          "opclass"
#define MAPCLI_WIPHY_ATTR_CHANNEL_NAME          "channel"
#define MAPCLI_WIPHY_ATTR_POWERSAVED_NAME       "power_saved"
#define MAPCLI_WIPHY_ATTR_TXPOWER_NAME          "txpower"
#define MAPCLI_WIPHY_ATTR_PHYTYPE_NAME          "phytype"
#define MAPCLI_WIPHY_ATTR_HTCAPA_NAME           "htcapa"
#define MAPCLI_WIPHY_ATTR_VHTCAPA_NAME          "vhtcapa"
#define MAPCLI_WIPHY_ATTR_HECAPA_NAME           "hecapa"
#define MAPCLI_WIPHY_ATTR_WDEVS_NAME            "wdevs"
#define MAPCLI_WIPHY_ATTR_STEER_POLICY_NAME     "steer_policy"
#define MAPCLI_WIPHY_ATTR_METRIC_POLICY_NAME    "metric_policy"
#define MAPCLI_WIPHY_ATTR_OPCLASSES_NAME        "opclasses"

#define MAPCLI_POLICY_ATTR_STEER_NAME       "steer"
#define MAPCLI_POLICY_ATTR_CH_UTIL_NAME     "ch_util_threshold"
#define MAPCLI_POLICY_ATTR_RCPI_NAME        "rcpi_threshold"
#define MAPCLI_POLICY_ATTR_MARGIN_NAME      "rcpi_margin"
#define MAPCLI_POLICY_ATTR_INCLUSION_NAME   "inclusion"

#define MAPCLI_OPCLASS_ATTR_ID_NAME         "opclass"
#define MAPCLI_OPCLASS_ATTR_BW_NAME         "bw"
#define MAPCLI_OPCLASS_ATTR_MAXPOWER_NAME   "maxpower"
#define MAPCLI_OPCLASS_ATTR_CHANNELS_NAME   "channels"

#define MAPCLI_CHANNEL_ATTR_ID_NAME         "channel"
#define MAPCLI_CHANNEL_ATTR_DISABLE_NAME    "disable"
#define MAPCLI_CHANNEL_ATTR_PREF_NAME       "pref"
#define MAPCLI_CHANNEL_ATTR_REASON_NAME     "reason"
#define MAPCLI_CHANNEL_ATTR_MIN_SEP_NAME    "min_sep"

#define MAPCLI_WDEV_ATTR_IFNAME_NAME        "ifname"
#define MAPCLI_WDEV_ATTR_MAC_NAME           "mac"
#define MAPCLI_WDEV_ATTR_BSSID_NAME         "bssid"
#define MAPCLI_WDEV_ATTR_ROLE_NAME          "role"
#define MAPCLI_WDEV_ATTR_SSID_NAME          "ssid"
#define MAPCLI_WDEV_ATTR_KEY_NAME           "key"
#define MAPCLI_WDEV_ATTR_BINTVAL_NAME       "bintval"
#define MAPCLI_WDEV_ATTR_FRONTHAUL_NAME     "fronthaul"
#define MAPCLI_WDEV_ATTR_BACKHAUL_NAME      "backhaul"
#define MAPCLI_WDEV_ATTR_RADIO_NAME         "radio"
#define MAPCLI_WDEV_ATTR_CLIENT_NUM_NAME    "client_num"
#define MAPCLI_WDEV_ATTR_CLIENTS_NAME       "clients"
#define MAPCLI_WDEV_ATTR_METRIC_NAME        "metric"
#define MAPCLI_WDEV_ATTR_STATE_NAME         "state"

#define MAPCLI_WDEV_METRIC_ATTR_CHUTIL_NAME     "ch_util"
#define MAPCLI_WDEV_METRIC_ATTR_ESPIS_NAME      "espis"

#define MAPCLI_ESPI_ATTR_AC_NAME            "ac"
#define MAPCLI_ESPI_ATTR_FORMAT_NAME        "format"
#define MAPCLI_ESPI_ATTR_WINDOW_NAME        "ba_window"
#define MAPCLI_ESPI_ATTR_EST_AIRTIME_NAME   "est_airtime"
#define MAPCLI_ESPI_ATTR_DURATION_NAME      "duration"

#define MAPCLI_CLIENT_ATTR_MAC_NAME             "mac"
#define MAPCLI_CLIENT_ATTR_AGE_NAME             "age"
#define MAPCLI_CLIENT_ATTR_ASSOC_NAME           "assoc"
#define MAPCLI_CLIENT_ATTR_LINK_METRIC_NAME     "link_metric"
#define MAPCLI_CLIENT_ATTR_TRAFFIC_METRIC_NAME  "traffic_metric"
#define MAPCLI_CLIENT_ATTR_OPCLASS_NAME         "opclass"
#define MAPCLI_CLIENT_ATTR_CHANNEL_NAME         "channel"
#define MAPCLI_CLIENT_ATTR_SEEN_NAME            "seen_by"
#define MAPCLI_CLIENT_ATTR_BEACON_REPORT_NAME   "beacon_report"
#define MAPCLI_CLIENT_ATTR_BEACON_REPORT_IES_NAME   "beacon_report_ies"

#define MAPCLI_CLIENT_METRIC_ATTR_AGE_NAME      "age"
#define MAPCLI_CLIENT_METRIC_ATTR_DLRATE_NAME   "rate_dl"
#define MAPCLI_CLIENT_METRIC_ATTR_ULRATE_NAME   "rate_ul"
#define MAPCLI_CLIENT_METRIC_ATTR_RCPI_NAME     "rcpi"
#define MAPCLI_CLIENT_METRIC_ATTR_TXPKTS_NAME   "tx_pkts"
#define MAPCLI_CLIENT_METRIC_ATTR_TXBYTES_NAME  "tx_bytes"
#define MAPCLI_CLIENT_METRIC_ATTR_RXPKTS_NAME   "rx_pkts"
#define MAPCLI_CLIENT_METRIC_ATTR_RXBYTES_NAME  "rx_bytes"
#define MAPCLI_CLIENT_METRIC_ATTR_TXERRS_NAME   "tx_errors"
#define MAPCLI_CLIENT_METRIC_ATTR_RXERRS_NAME   "rx_errors"
#define MAPCLI_CLIENT_METRIC_ATTR_TXTRIES_NAME  "tx_tries"

#define MAPCLI_NETWORK_ATTR_CONTROLLER_NAME     "controller"
#define MAPCLI_NETWORK_ATTR_NEIGHBORS_NAME      "neighbors"
#define MAPCLI_NETWORK_ATTR_ALID_NAME           "alid"
#define MAPCLI_NETWORK_ATTR_RECV_ADDR_NAME      "recv_addr"

#define MAPCLI_WPS_ATTR_IFNAME_NAME             "ifname"

#define MAPCLI_1905_ATTR_IFNAME_NAME        "Ifname"
#define MAPCLI_1905_ATTR_DEST_ALID_NAME     "DestALid"
#define MAPCLI_1905_ATTR_TYPE_NAME          "MessageTypeValue"
#define MAPCLI_1905_ATTR_TLVS_NAME          "TLVs"
#define MAPCLI_1905_ATTR_MID_NAME           "mid"

#define MAPCLI_1905TLV_ATTR_TYPE_NAME       "tlv_type"
#define MAPCLI_1905TLV_ATTR_LEN_NAME        "tlv_length"
#define MAPCLI_1905TLV_ATTR_VALUE_NAME      "tlv_value"

#define MAPCLI_WSC_REGISTRAR_BSSINFO_NAME       "wsc_bssinfos"
#define MAPCLI_BSSINFO_ATTR_AL_MAC_NAME         "al_mac"
#define MAPCLI_BSSINFO_ATTR_OPCLASS_NAME        "opclass"
#define MAPCLI_BSSINFO_ATTR_SSID_NAME           "ssid"
#define MAPCLI_BSSINFO_ATTR_AUTH_MODE_NAME      "auth_mode"
#define MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE_NAME   "encr_mode"
#define MAPCLI_BSSINFO_ATTR_KEY_NAME            "key"
#define MAPCLI_BSSINFO_ATTR_BACKHAUL_NAME       "backhaul"
#define MAPCLI_BSSINFO_ATTR_FRONTHUAL_NAME      "fronthaul"

#define MAPCLI_PARAM_ATTR_WIPHY_NAME     "wiphy"
#define MAPCLI_PARAM_ATTR_WDEV_NAME      "wdev"
#define MAPCLI_PARAM_ATTR_OPCLASS_NAME   "opclass"
#define MAPCLI_PARAM_ATTR_CHANNEL_NAME   "channel"
#define MAPCLI_PARAM_ATTR_TXPOWER_NAME   "txpower"
#define MAPCLI_PARAM_ATTR_SSID_NAME      "ssid"
#define MAPCLI_PARAM_ATTR_AUTHMODE_NAME  "auth_mode"
#define MAPCLI_PARAM_ATTR_KEY_NAME       "key"
#define MAPCLI_PARAM_ATTR_BACKHUAL_NAME  "backhaul"
#define MAPCLI_PARAM_ATTR_FRONTHUAL_NAME "fronthaul"
#define MAPCLI_PARAM_ATTR_STATIONS_NAME  "stations"
#define MAPCLI_PARAM_ATTR_FRAME_NAME     "frame"
#define MAPCLI_PARAM_ATTR_MAC_NAME       "mac"
#define MAPCLI_PARAM_ATTR_BLOCK_NAME     "block"
#define MAPCLI_PARAM_ATTR_RENEW_NAME     "renew"
#define MAPCLI_PARAM_ATTR_DUMP_TYPE_NAME "type"
#define MAPCLI_PARAM_ATTR_DUMP_SIZE_NAME "size"
#define MAPCLI_PARAM_ATTR_DEAUTH_CODE_NAME "deauth_code"
#define MAPCLI_PARAM_ATTR_TARGET_BSSID_NAME   "target_bssid"
#define MAPCLI_PARAM_ATTR_TARGET_OPCLASS_NAME "target_opclass"
#define MAPCLI_PARAM_ATTR_TARGET_CHANNEL_NAME "target_channel"
#define MAPCLI_PARAM_ATTR_BTM_REQMODE_NAME    "btm_reqmode"

int mapcli_init(void);
void mapcli_deinit(void);

#endif
