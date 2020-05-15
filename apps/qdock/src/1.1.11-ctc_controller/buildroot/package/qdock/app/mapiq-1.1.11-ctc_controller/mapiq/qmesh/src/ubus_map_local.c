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
 * @brief ubus map local object implementation
 *
 */

#include "qdock_map_api.h"
#include "al_ubus_server.h"

#include "platform.h"
#include "datamodel.h"
#include "al_utils.h"

static void fill_interface_media_infos(struct interface *intf)
{
    blobmsg_add_mac(&b, MAPAPI_INTERFACE_ATTR_MAC_ADDR_NAME, intf->addr);
    blobmsg_add_u32(&b, MAPAPI_INTERFACE_ATTR_MEDIA_TYPE_NAME, intf->media_type);
    blobmsg_add_binary(&b, MAPAPI_INTERFACE_ATTR_MEDIA_INFO_NAME, intf->media_specific_info, intf->media_specific_info_length);
}

static void fill_duplicated_infos(struct registrar *registrar)
{
    struct alDevice *dev;
    if (dlist_count(&registrar->duplicated_controller))
    {
        void *dup_ctrllers_list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_DUPLICATED_CONTROLLERS_NAME);
        dlist_for_each(dev, registrar->duplicated_controller, l)
        {
            void *dup_ctrller_table = blobmsg_open_table(&b, NULL);
            uint32_t intf_nr = dlist_count(&dev->interfaces);
            blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr);
            blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_PROFILE_NAME, dev->profile);
            if (intf_nr)
            {
                struct interface *intf;
                void *intfs_list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_INTERFACES_NAME);
                dlist_for_each(intf, dev->interfaces, l)
                {
                    void *intf_table = blobmsg_open_table(&b, NULL);
                    fill_interface_media_infos(intf);
                    blobmsg_close_table(&b, intf_table);
                }
                blobmsg_close_array(&b, intfs_list);
            }
            if (dev->is_map_agent || dev->is_map_controller)
            {
                void *services_list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_SUPPORTED_SERVICES_NAME);
                void *service_table;
                if (dev->is_map_controller)
                {
                    service_table = blobmsg_open_table(&b, NULL);
                    blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_SERVICE_NAME, 0);
                    blobmsg_close_table(&b, service_table);
                }
                if (dev->is_map_agent)
                {
                    service_table = blobmsg_open_table(&b, NULL);
                    blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_SERVICE_NAME, 1);
                    blobmsg_close_table(&b, service_table);
                }
                blobmsg_close_array(&b, services_list);
            }
            if (intf_nr)
            {
                struct interface *intf;
                bool have_bss = false;
                dlist_for_each(intf, dev->interfaces, l)
                {
                    struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
                    if (intf->type == interface_type_wifi
                            && ifw->role == interface_wifi_role_ap)
                    {
                        have_bss = true;
                        break;
                    }
                }
                if (have_bss)
                {
                    void *bsses_list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_BSSES_NAME);
                    dlist_for_each(intf, dev->interfaces, l)
                    {
                        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
                        if (intf->type == interface_type_wifi
                                && ifw->role == interface_wifi_role_ap)
                        {
                            void *bss_table = blobmsg_open_table(&b, NULL);
                            blobmsg_add_mac(&b, MAPAPI_BSS_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
                            blobmsg_add_binary(&b, MAPAPI_BSS_ATTR_SSID_NAME, ifw->bssInfo.ssid.ssid, ifw->bssInfo.ssid.length);
                            blobmsg_close_table(&b, bss_table);
                        }
                    }
                    blobmsg_close_array(&b, bsses_list);
                }
            }
            blobmsg_close_table(&b, dup_ctrller_table);
        }
        blobmsg_close_array(&b, dup_ctrllers_list);
    }

    if (dlist_count(&registrar->duplicated_registrar))
    {
        void *list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_DUPLICATED_REGISTRARS_NAME);
        dlist_for_each(dev, registrar->duplicated_registrar, l)
        {
            void *dup_reg_table = blobmsg_open_table(&b, NULL);
            blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_ALID_NAME, dev->al_mac_addr);
            // refer to IEEE 1905.1a Table 6-24—SupportedRole TLV
            // 0->controller is unique valid value
            blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_SUPPORTED_ROLE_NAME, 0);
            blobmsg_close_table(&b, dup_reg_table);
        }
        blobmsg_close_array(&b, list);
    }
}

static void fill_local_device()
{
    void *list;
    struct interface *intf;

    if (local_device->is_map_agent)
    {
        blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_AGENT_ALID_NAME, local_device->al_mac_addr);
        blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_AGENT_PROFILE_NAME, local_device->profile);
    }

    if (local_device->is_map_controller)
    {
        blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_CONTROLLER_ALID_NAME, local_device->al_mac_addr);
        blobmsg_add_u32(&b, MAPAPI_DEVICE_ATTR_CONTROLLER_PROFILE_NAME, local_device->profile);
    }

    if (dlist_count(&local_device->interfaces))
    {
        list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_INTERFACES_NAME);
        dlist_for_each(intf, local_device->interfaces, l)
        {
            void *intf_table = blobmsg_open_table(&b, NULL);
            fill_interface_media_infos(intf);
            blobmsg_add_u32(&b, MAPAPI_INTERFACE_ATTR_POWER_STATE_NAME, intf->power_state);
            blobmsg_close_table(&b, intf_table);
        }
        blobmsg_close_array(&b, list);
    }

    fill_duplicated_infos(&registrar);
    // TODO In fact, the last item of duplicated controllers list can be
    // regarded as the last seen one, so below information may redundant
    if (registrar.last_seen)
        blobmsg_add_mac(&b, MAPAPI_DEVICE_ATTR_LAST_SEEN_NAME, registrar.last_seen->al_mac_addr);

    // TODO onboarded_on: local station interface and remote bssid info, DataModel not support yet
    // TODO backhaul_local_interface: DataModel not support yet

}

static void fill_opclass_non_operable_channels(struct radioOpclass *opclass)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPAPI_OPCLASS_ATTR_NON_OPERABLE_CHANNELS_NAME);
    for (i = 0; i < opclass->channel_nums; i++)
    {
        if (opclass->channels[i].disabled)
            blobmsg_add_u32(&b, MAPAPI_CHANNEL_ATTR_ID_NAME, opclass->channels[i].id);
    }
    blobmsg_close_array(&b, list);
}

static void fill_radio_opclass(struct radioOpclass *opclass)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_ID_NAME, opclass->opclass);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_BW_NAME, opclass->bw);
    blobmsg_add_u32(&b, MAPAPI_OPCLASS_ATTR_MAXPOWER_NAME, opclass->max_txpower);
    fill_opclass_non_operable_channels(opclass);
    blobmsg_close_table(&b, table);
}

static void fill_radio_opclasses(struct radio *radio)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_OPCLASSES_NAME);

    for (i = 0; i < radio->opclass_nums; i++)
        fill_radio_opclass(&radio->opclasses[i]);

    blobmsg_close_array(&b, list);
}

static void fill_radio_operations(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_OPERATIONS_NAME);

    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_MAXBSSES_NAME, radio->maxBSS);
    fill_radio_opclasses(radio);
    // TODO supported: bitmask {HT, VHT, HE} Determined which objects below exists
    blobmsg_add_binary(&b, MAPAPI_RADIO_ATTR_HTCAPA_NAME, (uint8_t *)(&radio->ht_capa), sizeof(struct radioHtcap));
    blobmsg_add_binary(&b, MAPAPI_RADIO_ATTR_VHTCAPA_NAME, (uint8_t *)(&radio->vht_capa), sizeof(struct radioVhtcap));
    blobmsg_add_binary(&b, MAPAPI_RADIO_ATTR_HECAPA_NAME, (uint8_t *)(&radio->he_capa), sizeof(struct radioHecap));

    blobmsg_add_u8(&b, MAPAPI_RADIO_ATTR_MON_OFFCHAN_NAME, radio->monitor_offchan);
    blobmsg_add_u8(&b, MAPAPI_RADIO_ATTR_MON_ONCHAN_NAME, radio->monitor_onchan);
    blobmsg_add_u8(&b, MAPAPI_RADIO_ATTR_SELF_STEERING_NAME, radio->self_steering);
    blobmsg_close_table(&b, table);
}

static void fill_radio_capabilities(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_CAPABILITIES_NAME);
    fill_radio_operations(radio);
    // TODO bBSS: false, unless all of below are true
    // TODO bSTA : true if WDEV_SUPPORTS_MAP_bSTA

    blobmsg_close_table(&b, table);
}

static void fill_radio_currents(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_CURRENTS_NAME);
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_OPCLASS_NAME, radio->opclass);
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_CHANNEL_NAME, radio->chan);
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_TXPOWER_NAME, radio->txpower);
    blobmsg_add_u32(&b, MAPAPI_RADIO_ATTR_POWERSAVED_NAME, radio->powerSaved);

    // TODO primary_channel or second_channel?
    // TODO CCIF0 CCIF1?

    blobmsg_close_table(&b, table);
}

static void fill_radio_steer_policys(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_STEER_POLICY_NAME);
    blobmsg_add_u32(&b, MAPAPI_POLICY_ATTR_STEER_POLICY_NAME, radio->steering_policy.policy);
    blobmsg_add_u32(&b, MAPAPI_POLICY_ATTR_BUSY_THRESHOLD_NAME, radio->steering_policy.ch_util_threshold);
    blobmsg_add_u32(&b, MAPAPI_POLICY_ATTR_RCPI_THRESHOLD_NAME, radio->steering_policy.rcpi_threshold);
    blobmsg_close_table(&b, table);
}

static void fill_radio_metric_policys(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_METRIC_POLICY_NAME);
    blobmsg_add_u32(&b, MAPAPI_POLICY_ATTR_STA_METRICS_RCPI_THRESHOLD_NAME, radio->metric_policy.rcpi_threshold);
    blobmsg_add_u32(&b, MAPAPI_POLICY_ATTR_STA_METRICS_RCPI_MARGIN_NAME, radio->metric_policy.rcpi_margin);
    blobmsg_add_u32(&b, MAPAPI_POLICY_ATTR_AP_METRICS_BUSY_THRESHOLD_NAME, radio->metric_policy.rcpi_margin);
    blobmsg_add_u32(&b, MAPAPI_POLICY_ATTR_ASSOCED_STA_INCLUSION_NAME, radio->metric_policy.policy);
    blobmsg_close_table(&b, table);
}

static void fill_radio_received_policys(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPAPI_RADIO_ATTR_RECEIVED_CONFIG_NAME);
    fill_radio_steer_policys(radio);
    fill_radio_metric_policys(radio);
    blobmsg_close_table(&b, table);
}

static void fill_radio_bsses_bssid(struct radio *radio)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_BSSES_NAME);

    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        void *table = blobmsg_open_table(&b, NULL);
        blobmsg_add_mac(&b, MAPAPI_BSS_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
        blobmsg_close_table(&b, table);
    }
    blobmsg_close_array(&b, list);
}

static void fill_radio(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, NULL);

    blobmsg_add_mac(&b, MAPAPI_RADIO_ATTR_ID_NAME, radio->uid);
    fill_radio_capabilities(radio);
    fill_radio_currents(radio);
    fill_radio_received_policys(radio);
    // TODO bSTA backhaul station info

    fill_radio_bsses_bssid(radio);

    blobmsg_close_table(&b, table);
}

static void fill_radios(struct alDevice *dev)
{
    struct radio *radio;
    void *list = blobmsg_open_array(&b, MAPAPI_DEVICE_ATTR_RADIOS_NAME);

    dlist_for_each(radio, dev->radios, l)
        fill_radio(radio);

    blobmsg_close_array(&b, list);
}

static void fill_bss_received_configs(struct interfaceWifi *ifw)
{
    void *table = blobmsg_open_table(&b, MAPAPI_BSS_ATTR_RECEIVED_CONFIG_NAME);

    blobmsg_add_binary(&b, MAPAPI_BSS_ATTR_SSID_NAME, ifw->bssInfo.ssid.ssid, ifw->bssInfo.ssid.length);

    // TODO map ext byte

    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_TEARDOWN_NAME, ifw->bssInfo.teardown);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_FRONTHAUL_NAME, ifw->bssInfo.fronthaul);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_BACKHAUL_NAME, ifw->bssInfo.backhaul);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_AUTH_MODE_NAME, ifw->bssInfo.auth_mode);
    blobmsg_add_u32(&b, MAPAPI_BSS_ATTR_ENCR_TYPE_NAME, ifw->bssInfo.encryp);
    blobmsg_add_binary(&b, MAPAPI_BSS_ATTR_KEY_NAME, ifw->bssInfo.key.key, ifw->bssInfo.key.len);

    blobmsg_close_table(&b, table);
}

static void fill_bss_assoc_ctrl(struct interfaceWifi *ifw)
{
    struct blockedClient *client;
    uint32_t cur_ts = PLATFORM_GET_TIMESTAMP();

    void *list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_CLIENT_ASSOC_CONTROL_NAME);
    dlist_for_each(client, map_policy.blocked_clients, l)
    {
        if (!memcmp(client->bssid, ifw->bssInfo.bssid, sizeof(mac_address)))
        {
            void *table = blobmsg_open_table(&b, NULL);
            blobmsg_add_mac(&b, MAPAPI_ASSOC_CONTROL_ATTR_STA_MAC_NAME, client->mac);
            blobmsg_add_u32(&b, MAPAPI_ASSOC_CONTROL_ATTR_AGE_NAME, client->expiration - cur_ts);
            blobmsg_close_table(&b, table);
        }
    }
    blobmsg_close_array(&b, list);
}

static void fill_station_cabilities(struct staInfo *sta)
{
    void *table = blobmsg_open_table(&b, MAPAPI_STATION_ATTR_CAPABILITIES_NAME);

    if (sta->ies.rm_enabled)
        blobmsg_add_binary(&b, MAPAPI_STATION_ATTR_RM_IE_NAME, sta->ies.rm_enabled, sta->ies.rm_enabled[1]+2);
    if (sta->ies.extcap)
        blobmsg_add_binary(&b, MAPAPI_STATION_ATTR_EXT_CAPA_IE_NAME, sta->ies.extcap, sta->ies.extcap[1]+2);

    // TODO beacon report ies
    // TODO client_capa_report result_code and assoc frame body

    // TODO MBOs

    blobmsg_close_table(&b, table);
}

static void fill_assoced_station(struct staInfo *sta)
{
    void *table;

    if (!sta)
        return;

    table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_STATION_ATTR_MAC_NAME, sta->mac);
    blobmsg_add_u32(&b, MAPAPI_STATION_ATTR_BACKHAUL_NAME, sta->bSTA);
    // TODO if backhaul sta, record map_profile

    fill_station_cabilities(sta);

    // TODO station status

    // TODO station stats

    blobmsg_close_table(&b, table);
}

static void fill_bss_assoced_stations(struct interfaceWifi *ifw)
{
    struct staInfo *sta;
    void *list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_ASSOC_STATIONS_NAME);
    dlist_for_each(sta, ifw->clients, l)
    {
        fill_assoced_station(sta);
    }
    blobmsg_close_array(&b, list);
}

static void fill_bss(struct interfaceWifi *ifw)
{
    void *table;

    if (!ifw)
        return;

    table = blobmsg_open_table(&b, NULL);
    blobmsg_add_mac(&b, MAPAPI_BSS_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
    fill_bss_received_configs(ifw);

    // TODO local_configs
    fill_bss_assoc_ctrl(ifw);

    fill_bss_assoced_stations(ifw);
    blobmsg_close_table(&b, table);
}

static void fill_radio_bss_by_bssid(struct radio *radio, mac_address bssid)
{
    struct interfaceWifi *ifw = NULL;

    if (!radio)
        return;

    ifw = radioFindInterfaceWifi(radio, bssid);
    if (ifw)
        fill_bss(ifw);
}

static void fill_radio_bsses(struct radio *radio)
{
    uint32_t i;

    if (!radio)
        return;

    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        fill_bss(ifw);
    }
}

static void fill_bsses(struct alDevice *dev, struct radio *radio, dlist_head *bsses)
{
    struct macAddressItem *bss_item;
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_BSSES_NAME);

    if (dlist_count(bsses))
    {
        dlist_for_each(bss_item, *bsses, l)
        {
            if (radio)
            {
                fill_radio_bss_by_bssid(radio, bss_item->mac);
            }
            else
            {
                struct radio *cur_radio;
                dlist_for_each(cur_radio, dev->radios, l)
                {
                    fill_radio_bss_by_bssid(cur_radio, bss_item->mac);
                }
            }
        }
    }
    else
    {
        if (radio)
        {
            fill_radio_bsses(radio);
        }
        else
        {
            struct radio *cur_radio;
            dlist_for_each(cur_radio, dev->radios, l)
            {
                fill_radio_bsses(cur_radio);
            }
        }
    }

    blobmsg_close_array(&b, list);
}

static void fill_last_assoc_frame(mac_address sta_mac)
{
    struct staInfo *sta_info = findLocalWifiClient(sta_mac, NULL, NULL);

    if (!sta_info)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("the station" MACFMT " not assoc to local device\n", MACARG(sta_mac));
        fill_result(MAPAPI_RESULT_CONTEXT_NOT_FOUND);
        return;
    }

    if (sta_info->last_assoc && sta_info->last_assoc_len > 0)
        blobmsg_add_binary(&b, MAPAPI_STATION_ATTR_LAST_ASSOC_FRAME_NAME, sta_info->last_assoc, sta_info->last_assoc_len);
}

static void fill_local_device_stats()
{
    void *table;

    //TODO capabilities

    table = blobmsg_open_table(&b, MAPAPI_DEVICE_STAT_ATTR_RECEIVED_CONFIGURATION_NAME);

    blobmsg_add_u32(&b, MAPAPI_DEVICE_STAT_ATTR_AP_METRICS_INTERVAL_NAME, map_config.ap_metrics_intval);

    blobmsg_close_table(&b, table);

    //TODO links[]
    //TODO failed_assoc[]

}

static void fill_radio_unassoc_sta_infos(dlist_head *unassoc_head)
{
    struct radioUnassocSta *unassoc_sta = NULL;
    uint32_t cur_ts = PLATFORM_GET_TIMESTAMP();
    void *list = blobmsg_open_array(&b, MAPAPI_RADIO_STAT_ATTR_UNASSOCIATED_STATIONS_NAME);

    dlist_for_each(unassoc_sta, *unassoc_head, l)
    {
        void *table = blobmsg_open_table(&b, NULL);
        blobmsg_add_mac(&b, MAPAPI_UNASSOC_STATION_ATTR_MAC_NAME, unassoc_sta->mac);
        blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_LAST_UPDATED_NAME, cur_ts - unassoc_sta->last_ts);
        blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_CHANNEL_NAME, (uint32_t)unassoc_sta->channel);
        blobmsg_add_u32(&b, MAPAPI_UNASSOC_STATION_ATTR_RCPI_NAME, (uint32_t)unassoc_sta->rcpi);
        blobmsg_close_table(&b, table);
    }

    blobmsg_close_array(&b, list);
}

static void fill_radio_stats(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, NULL);
    // TODO last_updated
    // TODO busy (stored in units of 1000)
    // TODO noise (dBm)
    // TODO tx (stored in units of 1000)
    // TODO rx_own  (stored in units of 1000)
    // TODO rx_other  (stored in units of 1000)

    fill_radio_unassoc_sta_infos(&radio->unassocStaHead);
    blobmsg_close_table(&b, table);
}

static void fill_bss_espi(struct bssMetrics *metric)
{
    uint32_t i;

    for (i = 0; i < 4; i++)
    {
        if (metric->espis[i].valid)
        {
            void *table = blobmsg_open_table(&b, NULL);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_AC_NAME, i);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_FORMAT_NAME, metric->espis[i].format);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_WINDOW_NAME, metric->espis[i].window);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_EST_AIRTIME_NAME, metric->espis[i].est_airtime);
            blobmsg_add_u32(&b, MAPAPI_ESPI_ATTR_DURATION_NAME, metric->espis[i].duration);
            blobmsg_close_table(&b, table);
        }
    }
}

static void fill_bss_stats(struct bssInfo *bss_info)
{
    void *list;
    //TODO last_updated
    list = blobmsg_open_array(&b, MAPAPI_BSS_STAT_ATTR_ESPIS_NAME);
        fill_bss_espi(&bss_info->metrics);
    blobmsg_close_array(&b, list);
    //TODO traffic
}

static void fill_local_stats()
{
    void *table;
    void *list;
    struct radio *radio;

    table = blobmsg_open_table(&b, MAPAPI_DEVICE_ATTR_STATS_NAME);
    fill_local_device_stats();
    blobmsg_close_table(&b, table);
    list = blobmsg_open_array(&b, MAPAPI_RADIO_ATTR_STATS_NAME);
    dlist_for_each(radio, local_device->radios, l)
        fill_radio_stats(radio);
    blobmsg_close_array(&b, list);
    list = blobmsg_open_array(&b, MAPAPI_BSS_ATTR_STATS_NAME);
    dlist_for_each(radio, local_device->radios, l)
    {
        uint32_t i;
        for (i = 0; i < radio->configured_bsses.length; i++)
        {
            struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
            fill_bss_stats(&ifw->bssInfo);
        }
    }
    blobmsg_close_array(&b, list);
}

static int mapapi_get_local_device(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    fill_local_device();
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_local_radios(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    dlist_head radios;
    struct macAddressItem *rid;
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];
    blob_buf_init(&b, 0);
    dlist_head_init(&radios);
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (!tb[MAPAPI_GET_MAP_ATTR_RADIOS])
    {
        fill_radios(local_device);
    }
    else
    {
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_RADIOS], array_mac_to_dlist, &radios, MAPAPI_RADIO_ATTR_ID_NAME);
        dlist_for_each(rid, radios, l)
        {
            struct radio *radio = findDeviceRadio(local_device, rid->mac);
            if (radio)
                fill_radio(radio);
        }
        dlist_free_items(&radios, struct macAddressItem, l);
    }

    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_local_bsses(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    dlist_head bsses;
    mac_address radio_id;
    struct radio *radio = NULL;
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];

    blob_buf_init(&b, 0);
    dlist_head_init(&bsses);
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (tb[MAPAPI_GET_MAP_ATTR_RADIO_ID])
    {
        blobmsg_get_mac(tb[MAPAPI_GET_MAP_ATTR_RADIO_ID], radio_id);
        radio = findDeviceRadio(local_device, radio_id);
    }

    if (tb[MAPAPI_GET_MAP_ATTR_BSSES])
        visit_attrs(tb[MAPAPI_GET_MAP_ATTR_BSSES], array_mac_to_dlist, &bsses, MAPAPI_BSS_ATTR_BSSID_NAME);

    fill_bsses(local_device, radio, &bsses);

    dlist_free_items(&bsses, struct macAddressItem, l);

    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_local_last_assoc_frame(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    mac_address sta_mac;
    struct blob_attr *tb[NUM_MAPAPI_GET_MAP_ATTRS];

    blob_buf_init(&b, 0);
    blobmsg_parse(mapapi_get_map_policy, NUM_MAPAPI_GET_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (!tb[MAPAPI_GET_MAP_ATTR_STA_MAC])
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no sta mac found in attrs\n");
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_GET_MAP_ATTR_STA_MAC], sta_mac);
    fill_last_assoc_frame(sta_mac);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_get_local_stats(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    fill_local_stats();
    return ubus_send_reply(ctx, req, b.head);
}

static const struct ubus_method mapapi_local_methods[] = {
    UBUS_METHOD_NOARG(MAPAPI_METHOD_GET_LOCAL_DEVICE_NAME, mapapi_get_local_device),
    UBUS_METHOD(MAPAPI_METHOD_GET_LOCAL_RADIOS_NAME, mapapi_get_local_radios, mapapi_get_map_policy),
    UBUS_METHOD(MAPAPI_METHOD_GET_LOCAL_BSSES_NAME, mapapi_get_local_bsses, mapapi_get_map_policy),
    UBUS_METHOD(MAPAPI_METHOD_GET_LOCAL_LAST_ASSOC_FRAME_NAME, mapapi_get_local_last_assoc_frame, mapapi_get_map_policy),
    UBUS_METHOD_NOARG(MAPAPI_METHOD_GET_LOCAL_STATS_NAME, mapapi_get_local_stats),
    // TODO more
};

static struct ubus_object_type mapapi_local_obj_type =
UBUS_OBJECT_TYPE(MAPAPI_LOCAL_OBJ_NAME, mapapi_local_methods);

static struct ubus_object mapapi_local_obj = {
    .name = MAPAPI_LOCAL_OBJ_NAME,
    .type = &mapapi_local_obj_type,
    .methods = mapapi_local_methods,
    .n_methods = ARRAY_SIZE(mapapi_local_methods),
};

struct ubus_object *get_mapapi_local_obj(void)
{
    return &mapapi_local_obj;
}
