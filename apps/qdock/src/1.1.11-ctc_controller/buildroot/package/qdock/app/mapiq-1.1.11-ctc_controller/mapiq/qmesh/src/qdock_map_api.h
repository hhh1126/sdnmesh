/*
 *  Copyright (c) 2019, Semiconductor Components Industries, LLC
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
 * @brief AL MAP ubus APIs defined for 3rd-party APPs
 *
 */

#ifndef QDOCK_MAP_API_H
#define QDOCK_MAP_API_H

#define MAPAPI_OBJ_NAME             "qdock.map"
#define MAPAPI_CONTROLLER_OBJ_NAME  "qdock.map.controller"
#define MAPAPI_LOCAL_OBJ_NAME       "qdock.map.localdevice"
#define MAPAPI_NETWORK_OBJ_NAME     "qdock.map.networkdevices"
#define MAPAPI_CONFIG_OBJ_NAME      "qdock.map.config"

#define MAPAPI_METHOD_SEARCH_CONTROLLER_NAME                "search_controller"
#define MAPAPI_METHOD_DO_TOPOLOGY_DISCOVERY_NAME            "do_topology_discovery"
#define MAPAPI_METHOD_START_AP_AUTOCONFIGURATION_NAME       "start_ap_autoconfiguration"
#define MAPAPI_METHOD_QUERY_TOPOLOGY_NAME                   "query_topology"
#define MAPAPI_METHOD_QUERY_AP_CAPA_NAME                    "query_ap_capa"
#define MAPAPI_METHOD_QUERY_STA_CAPA_NAME                   "query_sta_capa"
#define MAPAPI_METHOD_QUERY_BACKHAUL_LINK_METRICS_NAME      "query_backhaul_link_metrics"
#define MAPAPI_METHOD_QUERY_AP_METRICS_NAME                 "query_ap_metrics"
#define MAPAPI_METHOD_QUERY_ASSOC_STA_METRICS_NAME          "query_assoc_sta_metrics"
#define MAPAPI_METHOD_QUERY_UNASSOC_STA_METRICS_NAME        "query_unassoc_sta_metrics"
#define MAPAPI_METHOD_QUERY_BEACON_METRICS_NAME             "query_beacon_metrics"
#define MAPAPI_METHOD_SEND_STEERING_COMPLETED_NAME          "send_steering_completed"
#define MAPAPI_METHOD_DO_STEER_LOCAL_NAME                   "do_steer_local"
#define MAPAPI_METHOD_REQUEST_ASSOC_CONTROL_NAME            "request_assoc_control"
#define MAPAPI_METHOD_SEND_HLDATA_MESSAGE_NAME              "send_hldata_message"

#define MAPAPI_METHOD_QUERY_CHANNEL_PREFERENCE_NAME         "query_channel_preference"
#define MAPAPI_METHOD_REQUEST_CHANNEL_SELECTION_NAME        "request_channel_selection"
#define MAPAPI_METHOD_REQUEST_CLIENT_STEERING_NAME          "request_client_steering"
#define MAPAPI_METHOD_REQUEST_BACKHAUL_STEERING_NAME        "request_backhaul_steering"
#define MAPAPI_METHOD_REQUEST_POLICY_CONFIG_NAME            "request_policy_config"
#define MAPAPI_METHOD_SEND_COMBINED_METRICS_NAME            "send_combined_metrics"

#define MAPAPI_METHOD_GET_LOCAL_DEVICE_NAME                 "get_device"
#define MAPAPI_METHOD_GET_LOCAL_STATS_NAME                  "get_stats"
#define MAPAPI_METHOD_GET_LOCAL_RADIOS_NAME                 "get_radios"
#define MAPAPI_METHOD_GET_LOCAL_BSSES_NAME                  "get_bsses"
#define MAPAPI_METHOD_GET_LOCAL_LAST_ASSOC_FRAME_NAME       "get_last_assoc_frame"


#define MAPAPI_METHOD_GET_NETWORK_DEVICES_NAME              "get_devices"
#define MAPAPI_METHOD_GET_NETWORK_TOPOLOGY_NAME             "get_topology"
#define MAPAPI_METHOD_GET_NETWORK_WIFI_NAME                 "get_wifi"
#define MAPAPI_METHOD_GET_NETWORK_UNASSOC_STATIONS_NAME     "get_unassoc_stations"
#define MAPAPI_METHOD_GET_NETWORK_NEARBY_STATIONS_NAME      "get_nearby_stations"
#define MAPAPI_METHOD_GET_NETWORK_STATS_NAME                "get_stats"
#define MAPAPI_METHOD_GET_NETWORK_TOPOLOGY_MAP_NAME         "get_topology_map"
#define MAPAPI_METHOD_GET_CURRENT_MAP_ROLE                  "get_map_role"
#define MAPAPI_METHOD_GET_CONTROLLER_MAC                    "get_controller_mac"

#define MAPAPI_SET_ATTR_IFNAME_NAME                                  "ifname"
#define MAPAPI_SET_ATTR_DEST_ALID_NAME                               "dst_alid"
#define MAPAPI_SET_ATTR_BSSIDS_NAME                                  "bssids"
#define MAPAPI_SET_ATTR_NEIGHBOR_ALID_NAME                           "neighbor_alid"
#define MAPAPI_SET_ATTR_BSSIDS_NAME                                  "bssids"
#define MAPAPI_SET_ATTR_METRIC_TYPE_NAME                             "metric_type"
#define MAPAPI_SET_ATTR_CHANNELS_NAME                                "channels"
#define MAPAPI_SET_ATTR_BEACON_REQ_CHAN_NUMBER_NAME                  "chan_number"
#define MAPAPI_SET_ATTR_BEACON_REQ_CHAN_REPORTS_NAME                 "chan_reports"
#define MAPAPI_SET_ATTR_BEACON_REQ_REPORTING_DETAIL_NAME             "detail"
#define MAPAPI_SET_ATTR_BEACON_REQ_ELEMENT_IDS_NAME                  "element_ids"
#define MAPAPI_SET_ATTR_HLD_MESSAGE_PROTOCOL_NAME                    "protocol"
#define MAPAPI_SET_ATTR_HLD_MESSAGE_PAYLOAD_NAME                     "payload"
#define MAPAPI_SET_ATTR_ASSOC_CTRL_REQ_ASSOC_CONTROL_NAME            "assoc_control"
#define MAPAPI_SET_ATTR_ASSOC_CTRL_REQ_PERIOD_NAME                   "period"
#define MAPAPI_SET_ATTR_CHAN_SLEC_REQ_CHANNEL_SELECTION_NAME         "channel_selection"
#define MAPAPI_SET_ATTR_CHAN_SLEC_REQ_PREFERENCE_NAME                "preference"
#define MAPAPI_SET_ATTR_CHAN_SLEC_REQ_REASON_CODE_NAME               "reason_code"
#define MAPAPI_SET_ATTR_CHAN_SLEC_REQ_TXPOWER_LIMIT_NAME             "txpower_limit"
#define MAPAPI_SET_ATTR_POLICY_CONF_LOCAL_DISALLOWED_NAME            "local_disallowed"
#define MAPAPI_SET_ATTR_POLICY_CONF_BTM_DISALLOWED_NAME              "btm_disallowed"
#define MAPAPI_SET_ATTR_POLICY_CONF_RADIO_STEERING_POLICY_NAME       "radio_steering_policy"
#define MAPAPI_SET_ATTR_POLICY_CONF_STEERING_POLICY_NAME             "steering_policy"
#define MAPAPI_SET_ATTR_POLICY_CONF_CH_UTIL_THRESHOLD_NAME           "ch_util_threshold"
#define MAPAPI_SET_ATTR_POLICY_CONF_RCPI_THRESHOLD_NAME              "rcpi_threshold"
#define MAPAPI_SET_ATTR_POLICY_CONF_REPORTING_INTERVAL_NAME          "reporting_interval"
#define MAPAPI_SET_ATTR_POLICY_CONF_METRIC_REPORTING_POLICY_NAME     "metric_reporting_policy"
#define MAPAPI_SET_ATTR_POLICY_CONF_RCPI_MARGIN_NAME                 "rcpi_margin"
#define MAPAPI_SET_ATTR_POLICY_CONF_ASSOC_STA_TRAFFIC_INCLUDE_NAME   "assoc_sta_traffic_include"
#define MAPAPI_SET_ATTR_POLICY_CONF_ASSOC_STA_LINK_INCLUDE_NAME      "assoc_sta_link_include"
enum {
    MAPAPI_SET_ATTR_IFNAME = 0,
    MAPAPI_SET_ATTR_DEST_ALID,
    MAPAPI_SET_ATTR_NEIGHBOR_ALID,
    MAPAPI_SET_ATTR_BSSIDS,
    MAPAPI_SET_ATTR_METRIC_TYPE,
    MAPAPI_SET_ATTR_CHANNELS,
    MAPAPI_SET_ATTR_BEACON_REQ_CHAN_NUMBER,
    MAPAPI_SET_ATTR_BEACON_REQ_CHAN_REPORTS,
    MAPAPI_SET_ATTR_BEACON_REQ_REPORTING_DETAIL,
    MAPAPI_SET_ATTR_BEACON_REQ_ELEMENT_IDS,
    MAPAPI_SET_ATTR_HLD_MESSAGE_PROTOCOL,
    MAPAPI_SET_ATTR_HLD_MESSAGE_PAYLOAD,
    MAPAPI_SET_ATTR_ASSOC_CTRL_REQ_ASSOC_CONTROL,
    MAPAPI_SET_ATTR_ASSOC_CTRL_REQ_PERIOD,
    MAPAPI_SET_ATTR_CHAN_SLEC_REQ_CHANNEL_SELECTION,
    MAPAPI_SET_ATTR_CHAN_SLEC_REQ_PREFERENCE,
    MAPAPI_SET_ATTR_CHAN_SLEC_REQ_REASON_CODE,
    MAPAPI_SET_ATTR_CHAN_SLEC_REQ_TXPOWER_LIMIT,
    MAPAPI_SET_ATTR_POLICY_CONF_STEERING_LOCAL_DISALLOWED,
    MAPAPI_SET_ATTR_POLICY_CONF_STEERING_BTM_DISALLOWED,
    MAPAPI_SET_ATTR_POLICY_CONF_RADIO_STEERING_POLICY,
    MAPAPI_SET_ATTR_POLICY_CONF_STEERING_POLICY,
    MAPAPI_SET_ATTR_POLICY_CONF_CH_UTIL_THRESHOLD,
    MAPAPI_SET_ATTR_POLICY_CONF_RCPI_THRESHOLD,
    MAPAPI_SET_ATTR_POLICY_CONF_REPORTING_INTERVAL,
    MAPAPI_SET_ATTR_POLICY_CONF_METRIC_REPORTING_POLICY,
    MAPAPI_SET_ATTR_POLICY_CONF_RCPI_MARGIN,
    MAPAPI_SET_ATTR_POLICY_CONF_ASSOC_STA_TRAFFIC_INCLUDE,
    MAPAPI_SET_ATTR_POLICY_CONF_ASSOC_STA_LINK_INCLUDE,
    //TODO more

    NUM_MAPAPI_SET_ATTRS,
};

#define MAPAPI_ATTR_RC_NAME                                 "rc"

#define MAPAPI_NETWORK_ATTR_DEVICES_NAME                    "devices"

#define MAPAPI_DEVICE_ATTR_ALID_NAME                        "alid"
#define MAPAPI_DEVICE_ATTR_PROFILE_NAME                     "profile"
#define MAPAPI_DEVICE_ATTR_AGENT_ALID_NAME                  "agent_alid"
#define MAPAPI_DEVICE_ATTR_AGENT_PROFILE_NAME               "agent_profile"
#define MAPAPI_DEVICE_ATTR_CONTROLLER_ALID_NAME             "controller_alid"
#define MAPAPI_DEVICE_ATTR_CONTROLLER_PROFILE_NAME          "controller_profile"
#define MAPAPI_DEVICE_ATTR_DUPLICATED_CONTROLLERS_NAME      "duplicated_controllers"
#define MAPAPI_DEVICE_ATTR_LAST_SEEN_NAME                   "last_seen"
#define MAPAPI_DEVICE_ATTR_DUPLICATED_REGISTRARS_NAME       "duplicated_registrars"
#define MAPAPI_DEVICE_ATTR_SUPPORTED_SERVICES_NAME          "supported_services"
#define MAPAPI_DEVICE_ATTR_SUPPORTED_ROLE_NAME              "supported_role"
#define MAPAPI_DEVICE_ATTR_SERVICE_NAME                     "service"
#define MAPAPI_DEVICE_ATTR_ROLE_NAME                        "1905_role"
#define MAPAPI_DEVICE_ATTR_LAST_TOPOLOGY_RESPONSE_TS_NAME   "last_topoResponse"
#define MAPAPI_DEVICE_ATTR_CAPABILITIES_NAME                "capabilities"
#define MAPAPI_DEVICE_ATTR_INTERFACES_NAME                  "interfaces"
#define MAPAPI_DEVICE_ATTR_RADIOS_NAME                      "radios"
#define MAPAPI_DEVICE_ATTR_BSSES_NAME                       "bsses"
#define MAPAPI_DEVICE_ATTR_STATS_NAME                       "device_stats"

#define MAPAPI_DEVICE_STAT_ATTR_RECEIVED_CONFIGURATION_NAME "received_configuration"
#define MAPAPI_DEVICE_STAT_ATTR_AP_METRICS_INTERVAL_NAME    "ap_metrics_interval"

#define MAPAPI_INTERFACE_ATTR_MAC_ADDR_NAME                 "if_addr"
#define MAPAPI_INTERFACE_ATTR_MEDIA_TYPE_NAME               "media_type"
#define MAPAPI_INTERFACE_ATTR_MEDIA_INFO_NAME               "media_info"
#define MAPAPI_INTERFACE_ATTR_POWER_STATE_NAME              "power_state"
#define MAPAPI_INTERFACE_ATTR_IF_TYPE_NAME                  "local_if_type"
#define MAPAPI_INTERFACE_ATTR_NON_1905_NEIGHBORS_NAME       "non1905_neighs"
#define MAPAPI_INTERFACE_ATTR_1905_NEIGHBORS_NAME           "1905_neighs"
#define MAPAPI_INTERFACE_ATTR_PEER_IF_ADDRESS_NAME          "peer_if_address"
#define MAPAPI_INTERFACE_ATTR_NEIGHBORS_NAME                "neighs"
#define MAPAPI_INTERFACE_ATTR_NEIGHBOR_ADDR_NAME            "neigh_addr"
#define MAPAPI_INTERFACE_ATTR_IS_BRIDGE_NAME                "bridges"

#define MAPAPI_RADIO_ATTR_ID_NAME                           "radio_id"
#define MAPAPI_RADIO_ATTR_CAPABILITIES_NAME                 "capabilities"
#define MAPAPI_RADIO_ATTR_OPERATIONS_NAME                   "operations"
#define MAPAPI_RADIO_ATTR_CURRENTS_NAME                     "currents"
#define MAPAPI_RADIO_ATTR_MAXBSSES_NAME                     "max_bsses"
#define MAPAPI_RADIO_ATTR_MON_OFFCHAN_NAME                  "omonitor"
#define MAPAPI_RADIO_ATTR_MON_ONCHAN_NAME                   "monitor"
#define MAPAPI_RADIO_ATTR_SELF_STEERING_NAME                "agent_steer"
#define MAPAPI_RADIO_ATTR_OPCLASSES_NAME                    "opclasses"
#define MAPAPI_RADIO_ATTR_OPCLASSES_STATUS_NAME             "opclasses_status"
#define MAPAPI_RADIO_ATTR_OPCLASS_NAME                      "opclass"
#define MAPAPI_RADIO_ATTR_CHANNEL_NAME                      "channel"
#define MAPAPI_RADIO_ATTR_POWERSAVED_NAME                   "power_saved"
#define MAPAPI_RADIO_ATTR_TXPOWER_NAME                      "txpower"
#define MAPAPI_RADIO_ATTR_PHYTYPE_NAME                      "phytype"
#define MAPAPI_RADIO_ATTR_HTCAPA_NAME                       "htcapa"
#define MAPAPI_RADIO_ATTR_VHTCAPA_NAME                      "vhtcapa"
#define MAPAPI_RADIO_ATTR_HECAPA_NAME                       "hecapa"
#define MAPAPI_RADIO_ATTR_RECEIVED_CONFIG_NAME              "received_configuration"
#define MAPAPI_RADIO_ATTR_STEER_POLICY_NAME                 "steer_policy"
#define MAPAPI_RADIO_ATTR_METRIC_POLICY_NAME                "metric_policy"
#define MAPAPI_RADIO_ATTR_BSSES_NAME                        "bsses"
#define MAPAPI_RADIO_ATTR_FREQ_BAND_NAME                    "freq_band"
#define MAPAPI_RADIO_ATTR_STATS_NAME                        "radio_stats"

#define MAPAPI_RADIO_STAT_ATTR_UNASSOCIATED_STATIONS_NAME   "unassociated_stations"
#define MAPAPI_RADIO_STAT_ATTR_UTILIZATION_NAME             "utilization"

#define MAPAPI_UNASSOC_STATION_ATTR_MAC_NAME                "unassoc_sta_mac"
#define MAPAPI_UNASSOC_STATION_ATTR_LAST_UPDATED_NAME       "last_updated"
#define MAPAPI_UNASSOC_STATION_ATTR_OPCLASS_NAME            "opclass"
#define MAPAPI_UNASSOC_STATION_ATTR_CHANNEL_NAME            "channel"
#define MAPAPI_UNASSOC_STATION_ATTR_RCPI_NAME               "rssi"

#define MAPAPI_POLICY_ATTR_STEER_POLICY_NAME                "policy"
#define MAPAPI_POLICY_ATTR_BUSY_THRESHOLD_NAME              "busy_threshold"
#define MAPAPI_POLICY_ATTR_RCPI_THRESHOLD_NAME              "rcpi_threshold"
#define MAPAPI_POLICY_ATTR_STA_METRICS_RCPI_THRESHOLD_NAME  "sta_metrics_rcpi_thshold"
#define MAPAPI_POLICY_ATTR_STA_METRICS_RCPI_MARGIN_NAME     "sta_metrics_rcpi_margin"
#define MAPAPI_POLICY_ATTR_AP_METRICS_BUSY_THRESHOLD_NAME   "ap_metrics_rcpi_threshold"
#define MAPAPI_POLICY_ATTR_ASSOCED_STA_INCLUSION_NAME       "assoced_sta_inclusion"

#define MAPAPI_OPCLASS_ATTR_ID_NAME                         "opclass"
#define MAPAPI_OPCLASS_ATTR_BW_NAME                         "bw"
#define MAPAPI_OPCLASS_ATTR_MAXPOWER_NAME                   "maxpower"
#define MAPAPI_OPCLASS_ATTR_NON_OPERABLE_CHANNELS_NAME      "non_operable_channels"
#define MAPAPI_OPCLASS_ATTR_CHANNELS_NAME                   "channels"

#define MAPAPI_CHANNEL_ATTR_ID_NAME                         "channel"
#define MAPAPI_CHANNEL_ATTR_DISABLE_NAME                    "disable"
#define MAPAPI_CHANNEL_ATTR_PREF_NAME                       "preference"
#define MAPAPI_CHANNEL_ATTR_REASON_NAME                     "reason"
#define MAPAPI_CHANNEL_ATTR_MIN_SEP_NAME                    "min_freq_sep"

#define MAPAPI_BSS_ATTR_BSSID_NAME                          "bssid"
#define MAPAPI_BSS_ATTR_SSID_NAME                           "ssid"
#define MAPAPI_BSS_ATTR_IFNAME_NAME                         "ifname"
#define MAPAPI_BSS_ATTR_RADIO_NAME                          "radio"
#define MAPAPI_BSS_ATTR_ROLE_NAME                           "role"
#define MAPAPI_BSS_ATTR_RECEIVED_CONFIG_NAME                "recevied_config"
#define MAPAPI_BSS_ATTR_BINTVAL_NAME                        "bintval"
#define MAPAPI_BSS_ATTR_TEARDOWN_NAME                       "teardown"
#define MAPAPI_BSS_ATTR_FRONTHAUL_NAME                      "fronthaul"
#define MAPAPI_BSS_ATTR_BACKHAUL_NAME                       "backhaul"
#define MAPAPI_BSS_ATTR_AUTH_MODE_NAME                      "auth_mode"
#define MAPAPI_BSS_ATTR_ENCR_TYPE_NAME                      "encr_type"
#define MAPAPI_BSS_ATTR_KEY_NAME                            "key"
#define MAPAPI_BSS_ATTR_ASSOC_STATIONS_NAME                 "assoc_clients"
#define MAPAPI_BSS_ATTR_UNASSOC_STATIONS_NAME               "unassociated_stations"
#define MAPAPI_BSS_ATTR_STATIONS_NAME                       "stations"
#define MAPAPI_BSS_ATTR_CLIENT_ASSOC_CONTROL_NAME           "client_assoc_control"
#define MAPAPI_BSS_ATTR_STATUS_NAME                         "status"
#define MAPAPI_BSS_ATTR_STATS_NAME                          "bss_stats"
#define MAPAPI_BSS_STAT_ATTR_CHUTIL_NAME                    "utilization"
#define MAPAPI_BSS_STAT_ATTR_CLIENT_NUM_NAME                "n_assoc_clients"
#define MAPAPI_BSS_STAT_ATTR_ESPIS_NAME                     "espis"

#define MAPAPI_ESPI_ATTR_AC_NAME                            "ac"
#define MAPAPI_ESPI_ATTR_FORMAT_NAME                        "format"
#define MAPAPI_ESPI_ATTR_WINDOW_NAME                        "ba_size"
#define MAPAPI_ESPI_ATTR_EST_AIRTIME_NAME                   "estf"
#define MAPAPI_ESPI_ATTR_DURATION_NAME                      "ppdu_dur"

#define MAPAPI_ASSOC_CONTROL_ATTR_STA_MAC_NAME              "sta_mac"
#define MAPAPI_ASSOC_CONTROL_ATTR_AGE_NAME                  "expiration"

#define MAPAPI_STATION_ATTR_FMT_CTL                         "output"
#define MAPAPI_STATION_ATTR_MAC_NAME                        "sta_mac"
#define MAPAPI_STATION_ATTR_AGE_NAME                        "age"
#define MAPAPI_STATION_ATTR_ASSOC_NAME                      "assoc"
#define MAPAPI_STATION_ATTR_OPCLASS_NAME                    "opclass"
#define MAPAPI_STATION_ATTR_CHANNEL_NAME                    "channel"
#define MAPAPI_STATION_ATTR_SEEN_NAME                       "seen_by"
#define MAPAPI_STATION_ATTR_BACKHAUL_NAME                   "b_sta"
#define MAPAPI_STATION_ATTR_LAST_ASSOC_FRAME_NAME           "last_assoc_frame"
#define MAPAPI_STATION_ATTR_LAST_ASSOC_TS_NAME              "last_assoc"
#define MAPAPI_STATION_ATTR_CAPABILITIES_NAME               "capabilities"
#define MAPAPI_STATION_ATTR_RM_IE_NAME                      "rm"
#define MAPAPI_STATION_ATTR_EXT_CAPA_IE_NAME                "ext_capa"
#define MAPAPI_STATION_ATTR_BEACON_REPORT_NAME              "beacon_report"
#define MAPAPI_STATION_ATTR_BEACON_REPORT_IES_NAME          "beacon_report_ies"
#define MAPAPI_STATION_ATTR_CAPA_REPORT_RESULT_NAME         "result_code"
#define MAPAPI_STATION_ATTR_CAPA_REPORT_FRAME_NAME          "frame"
#define MAPAPI_STATION_ATTR_STATS_NAME                      "stats"
#define MAPAPI_STATION_ATTR_LINK_METRIC_NAME                "link"
#define MAPAPI_STATION_ATTR_TRAFFIC_METRIC_NAME             "traffic"
#define MAPAPI_STATION_ATTR_OPCLASSES_NAME                  "opclasses"
#define MAPAPI_STATION_ATTR_CHANNELS_NAME                   "channels"
#define MAPAPI_STATION_ATTR_STAS_NAME                       "stas"
#define MAPAPI_STATION_ATTR_SEEN_BY_DEVICES_NAME            "seen_by_devices"
#define MAPAPI_STATION_ATTR_SEEN_BY_BSSIDS_NAME             "seen_by_bssids"
#define MAPAPI_STATION_ATTR_ASSOC_WITH_NAME                 "assoc_with"

#define MAPAPI_STATION_METRIC_ATTR_AGE_NAME                 "last_updated"
#define MAPAPI_STATION_METRIC_ATTR_DLRATE_NAME              "rate_dl"
#define MAPAPI_STATION_METRIC_ATTR_ULRATE_NAME              "rate_ul"
#define MAPAPI_STATION_METRIC_ATTR_RCPI_NAME                "rcpi"
#define MAPAPI_STATION_METRIC_ATTR_TXPKTS_NAME              "packets_sent"
#define MAPAPI_STATION_METRIC_ATTR_TXBYTES_NAME             "bytes_sent"
#define MAPAPI_STATION_METRIC_ATTR_RXPKTS_NAME              "packets_received"
#define MAPAPI_STATION_METRIC_ATTR_RXBYTES_NAME             "bytes_received"
#define MAPAPI_STATION_METRIC_ATTR_TXERRS_NAME              "tx_packets_errors"
#define MAPAPI_STATION_METRIC_ATTR_RXERRS_NAME              "rx_packets_errors"
#define MAPAPI_STATION_METRIC_ATTR_TXTRIES_NAME             "retransmission_count"

#define MAPAPI_STEERING_ATTR_REQ_MODE_NAME                  "mode"
#define MAPAPI_STEERING_ATTR_CURRENT_BSSID_NAME             "current_bssid"
#define MAPAPI_STEERING_ATTR_BTM_DISASSOC_IMMINENT_NAME     "btm_disassoc_imminent"
#define MAPAPI_STEERING_ATTR_BTM_ABRIDGED_NAME              "btm_abridged"
#define MAPAPI_STEERING_ATTR_BTM_TIMER_NAME                 "btm_timer"
#define MAPAPI_STEERING_ATTR_STEERING_WINDOW_NAME           "steering_window"
#define MAPAPI_STEERING_ATTR_TARGET_BSSES_NAME              "target_bsses"
#define MAPAPI_STEERING_ATTR_TARGET_BSSID_NAME              "target_bssid"
#define MAPAPI_STEERING_ATTR_TARGET_OPCLASS_NAME            "target_opclass"
#define MAPAPI_STEERING_ATTR_TARGET_CHAN_NAME               "target_chan"

#define MAPAPI_CONFIG_METHOD_GET_DUMP_MESSAGES_NAME         "get_DumpMessages"
#define MAPAPI_SUSCRIBE_FRAME_RECEIVE_NAME                  "suscribe_receive_frame"
#define MAPAPI_CONFIG_ATTR_MESSAGEDUMP_NAME                 "MessageDump"
#define MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES_NAME           "suscribes"
#define MAPAPI_SUSCRIBE_FRAME_ATTR_ENABLE_NAME              "enable"

#define MAPAPI_SUSCRIBE_FRAME_ATTR_FRAME_TYPE_NAME          "frame_type"
#define MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBE_NAME            "suscribe"
#define MAPAPI_EVENT_DUPLICATED_CONTROLLER_DETECTED_NAME    "duplicated_controller_detected"
#define MAPAPI_EVENT_DUPLICATED_REGISTRAR_DETECTED_NAME     "duplicated_registrar_detected"
#define MAPAPI_EVENT_ROGUE_RENEW_DETECTED_NAME              "rogue_renew_detected"
#define MAPAPI_EVENT_AGENT_CONFIGURED_NAME                  "agent_configured"
#define MAPAPI_EVENT_STEERING_CANDIDATES_NEEDED_NAME        "steering_candidates_needed"
#define MAPAPI_EVENT_STEERING_OPPORTUNITY_NAME              "steering_opportunity"
#define MAPAPI_EVENT_RECEIVED_BTM_RESPONSE_NAME             "received_btm_response"
#define MAPAPI_EVENT_CLIENT_ASSOCIATED_NAME                 "client_associated"

#define MAPAPI_EVENT_ATTR_ALID_NAME                         "alid"
#define MAPAPI_1905_ATTR_MID_NAME                           "mid"
#define MAPAPI_EVENT_ATTR_SRC_ADDR                          "sa"
#define MAPAPI_EVENT_ATTR_DEST_ADDR                         "da"
#define MAPAPI_EVENT_ATTR_DATA                              "data"
#define MAPAPI_EVENT_ATTR_PROFILE_NAME                      "profile"
#define MAPAPI_EVENT_ATTR_SUPPORTED_ROLE_NAME               "supported_role"
#define MAPAPI_EVENT_ATTR_SUPPORTED_SERVICES_NAME           "supported_services"
#define MAPAPI_EVENT_ATTR_SERVICE_NAME                      "service"
#define MAPAPI_EVENT_ATTR_MSG_TYPE_NAME                     "msg_id"
#define MAPAPI_EVENT_ATTR_INTERFACES_NAME                   "interfaces"
#define MAPAPI_EVENT_ATTR_INTERFACE_MAC_ADDR_NAME           "mac_address"
#define MAPAPI_EVENT_ATTR_INTERFACE_MEDIA_TYPE_NAME         "media_type"
#define MAPAPI_EVENT_ATTR_INTERFACE_MEDIA_INFO_NAME         "media_info"
#define MAPAPI_EVENT_ATTR_BSSES_NAME                        "bsses"
#define MAPAPI_EVENT_ATTR_BSSID_NAME                        "bssid"
#define MAPAPI_EVENT_ATTR_SSID_NAME                         "ssid"
#define MAPAPI_EVENT_ATTR_RADIO_ID_NAME                     "radio_id"
#define MAPAPI_EVENT_ATTR_CURRENT_BSS_NAME                  "current_bss"
#define MAPAPI_EVENT_ATTR_STAS_TO_STEER_NAME                "stas_to_steer"
#define MAPAPI_EVENT_ATTR_STA_MAC_NAME                      "sta_mac"
#define MAPAPI_EVENT_ATTR_STEERING_WINDOW_NAME              "steering_window"
#define MAPAPI_EVENT_ATTR_TA_ADDRESS                        "ta_address"
#define MAPAPI_EVENT_ATTR_RA_ADDRESS                        "ra_address"
#define MAPAPI_EVENT_ATTR_FRAME                             "frame"
#define MAPAPI_EVENT_ATTR_LOCAL_NAME                        "local"
#define MAPAPI_EVENT_RECEIVED_HL_DATA_NAME                  "received_hldata"
#define MAPAPI_EVENT_RECEIVED_FRAME_NAME                    "received_frame"

#define MAPAPI_EVENT_ATTR_ALID_NAME                         "alid"
#define MAPAPI_1905_ATTR_MID_NAME                           "mid"
#define MAPAPI_EVENT_ATTR_SRC_ADDR_NAME                     "sa"
#define MAPAPI_EVENT_ATTR_DEST_ADDR_NAME                    "da"
#define MAPAPI_EVENT_ATTR_DATA_NAME                         "data"
#define MAPAPI_EVENT_ATTR_TLVS_NAME                         "tlvs"
#define MAPAPI_EVENT_ATTR_TLV_TYPE_NAME                     "tlv_type"
#define MAPAPI_EVENT_ATTR_TLV_NAME                          "tlv"

enum mapapi_1905_role {
    MAPAPI_1905_ROLE_REGISTRAR = 0,

    MAPAPI_1905_ROLE_RESERVED
};

enum mapapi_service_type {
    MAPAPI_SERVICE_CONTROLLER = 0,
    MAPAPI_SERVICE_AGENT = 1,

    MAPAPI_SERVICE_RESERVED
};

enum mapapi_interface_type {
    MAPAPI_INTERFACE_TYPE_ETH = 0,
    MAPAPI_INTERFACE_TYPE_BSS = 1,
    MAPAPI_INTERFACE_TYPE_STA = 2,

    MAPAPI_INTERFACE_TYPE_RESERVED,
};

#endif
