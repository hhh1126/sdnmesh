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
 * @brief ubus map object implementation
 *
 */
#include "qdock_map_api.h"
#include "al_ubus_server.h"
#include "ubus_map.h"

#include "platform.h"
#include "datamodel.h"
#include "al_send.h"
#include "al_utils.h"
#include "1905_tlvs.h"
#include "platform_interfaces.h"
#include "al.h"

enum {
    MAPAPI_SEARCH_CONTROLLER_ATTR_FREQ_BAND = 0,

    NUM_MAPAPI_SEARCH_CONTROLLER_ATTRS,
};

static const struct blobmsg_policy mapapi_search_controller_policy[] = {
    [MAPAPI_SEARCH_CONTROLLER_ATTR_FREQ_BAND] = { .name = MAPAPI_RADIO_ATTR_FREQ_BAND_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int mapapi_search_controller(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_SEARCH_CONTROLLER_ATTRS];
    uint16_t mid = getNextMid();
    int freq_band;

    blobmsg_parse(mapapi_search_controller_policy, NUM_MAPAPI_SEARCH_CONTROLLER_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (registrarIsLocal())
    {
        fill_result(MAPAPI_RESULT_INVALID_EXECUTION);
        return ubus_send_reply(ctx, req, b.head);
    }

    if (!tb[MAPAPI_SEARCH_CONTROLLER_ATTR_FREQ_BAND])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    freq_band = blobmsg_get_u32(tb[MAPAPI_SEARCH_CONTROLLER_ATTR_FREQ_BAND]);
    if (freq_band < IEEE80211_FREQUENCY_BAND_2_4_GHZ || freq_band > IEEE80211_FREQUENCY_BAND_60_GHZ)
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    registrar.d = NULL;

    PLATFORM_PRINTF_DEBUG_INFO("try to search neighboring controller for %s band\n",
        (freq_band == IEEE80211_FREQUENCY_BAND_2_4_GHZ) ? "2.4G" : ((freq_band == IEEE80211_FREQUENCY_BAND_5_GHZ) ? "5G" : "60G"));

    if (send1905APAutoconfigurationSearchPacket(mid, freq_band))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_DO_TOPOLOGY_DISCOVERY_ATTR_IFNAME = 0,

    NUM_MAPAPI_DO_TOPOLOGY_DISCOVERY_ATTRS,
};

static const struct blobmsg_policy mapapi_do_topology_discovery_policy[] = {
    [MAPAPI_DO_TOPOLOGY_DISCOVERY_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
};

static int mapapi_do_topology_discovery(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_DO_TOPOLOGY_DISCOVERY_ATTRS];
    uint16_t mid = getNextMid();
    char **ifs_names, *ifname;
    uint8_t  ifs_nr, i, ret = 0;

    blobmsg_parse(mapapi_do_topology_discovery_policy, NUM_MAPAPI_DO_TOPOLOGY_DISCOVERY_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (tb[MAPAPI_DO_TOPOLOGY_DISCOVERY_ATTR_IFNAME])
    {
        ifname = blobmsg_get_string(tb[MAPAPI_DO_TOPOLOGY_DISCOVERY_ATTR_IFNAME]);
        PLATFORM_PRINTF_DEBUG_INFO("try to do topology discovery [mid: 0x%04x] from interface %s\n",
	    mid, ifname);
        ret = send1905TopologyDiscoveryPacket(ifname, mid);
    }
    else
    {
        ifs_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifs_nr);
        for (i=0; i<ifs_nr; i++)
        {
	    PLATFORM_PRINTF_DEBUG_INFO("try to do topology discovery [mid: 0x%04x] from interface %s\n",
	        mid, ifs_names[i]);
	    ret |= send1905TopologyDiscoveryPacket(ifs_names[i], mid);
	}
    }

    if (ret)
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

static int mapapi_start_ap_autoconfiguration(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct radio *r;
    bool imm = local_device->configured ? true : false;

    blob_buf_init(&b, 0);

    local_device->configured = false;
    dlist_for_each(r, local_device->radios, l)
        r->configured = false;

    PLATFORM_PRINTF_DEBUG_INFO("try to start ap autoconfiguration with imm %d\n",imm);
    if (triggerDeviceAPAutoConfiguration(imm))
        fill_result(MAPAPI_RESULT_SUCCESS);
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_TOPOLOGY_ATTR_IFNAME = 0,
    MAPAPI_QUERY_TOPOLOGY_ATTR_DEST_ALID,

    NUM_MAPAPI_QUERY_TOPOLOGY_ATTRS,
};

static const struct blobmsg_policy mapapi_query_topology_policy[] = {
    [MAPAPI_QUERY_TOPOLOGY_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_TOPOLOGY_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
};

static int mapapi_query_topology(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_TOPOLOGY_ATTRS];
    const char *ifname;
    mac_address al_id;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_topology_policy, NUM_MAPAPI_QUERY_TOPOLOGY_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_TOPOLOGY_ATTR_DEST_ALID])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_TOPOLOGY_ATTR_DEST_ALID], al_id);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_TOPOLOGY_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send topology query [mid: 0x%04x] to "
        MACFMT " from interface %s\n", mid, MACARG(al_id), ifname);

    if (send1905TopologyQueryPacket(ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_AP_CAPA_ATTR_IFNAME = 0,
    MAPAPI_QUERY_AP_CAPA_ATTR_DEST_ALID,

    NUM_MAPAPI_QUERY_AP_CAPA_ATTRS,
};

static const struct blobmsg_policy mapapi_query_ap_capa_policy[] = {
    [MAPAPI_QUERY_AP_CAPA_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_AP_CAPA_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
};

static int mapapi_query_ap_capa(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_AP_CAPA_ATTRS];
    const char *ifname;
    mac_address al_id;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_ap_capa_policy, NUM_MAPAPI_QUERY_AP_CAPA_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_AP_CAPA_ATTR_DEST_ALID])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_AP_CAPA_ATTR_DEST_ALID], al_id);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_AP_CAPA_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send ap capa query [mid: 0x%04x] to "
        MACFMT " from interface %s\n", mid, MACARG(al_id), ifname);

    if (send1905ApCapabilityQuery(ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTR_IFNAME = 0,
    MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTR_DEST_ALID,

    NUM_MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTRS,
};

static const struct blobmsg_policy mapapi_query_channel_preference_policy[] = {
    [MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
};

static int mapapi_query_channel_preference(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTRS];
    const char *ifname;
    mac_address al_id;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_channel_preference_policy, NUM_MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTR_DEST_ALID])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTR_DEST_ALID], al_id);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_CHANNEL_PREFERENCE_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send channel preference query [mid: 0x%04x] to "
        MACFMT " from interface %s\n", mid, MACARG(al_id), ifname);

    if (send1905ChannelPreferenceQueryPacket(ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_STA_CAPA_ATTR_IFNAME = 0,
    MAPAPI_QUERY_STA_CAPA_ATTR_DEST_ALID,
    MAPAPI_QUERY_STA_CAPA_ATTR_BSSID,
    MAPAPI_QUERY_STA_CAPA_ATTR_STA_MAC,

    NUM_MAPAPI_QUERY_STA_CAPA_ATTRS,
};

static const struct blobmsg_policy mapapi_query_sta_capa_policy[] = {
    [MAPAPI_QUERY_STA_CAPA_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_STA_CAPA_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_STA_CAPA_ATTR_BSSID] = { .name = MAPAPI_BSS_ATTR_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_STA_CAPA_ATTR_STA_MAC] = { .name = MAPAPI_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_MAC },
};

static int mapapi_query_sta_capa(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_STA_CAPA_ATTRS];
    const char *ifname;
    mac_address al_id, bss_id, sta_mac;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_sta_capa_policy, NUM_MAPAPI_QUERY_STA_CAPA_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_STA_CAPA_ATTR_DEST_ALID] || !tb[MAPAPI_QUERY_STA_CAPA_ATTR_BSSID] ||
        !tb[MAPAPI_QUERY_STA_CAPA_ATTR_STA_MAC])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_STA_CAPA_ATTR_DEST_ALID], al_id);
    blobmsg_get_mac(tb[MAPAPI_QUERY_STA_CAPA_ATTR_BSSID], bss_id);
    blobmsg_get_mac(tb[MAPAPI_QUERY_STA_CAPA_ATTR_STA_MAC], sta_mac);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_STA_CAPA_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send STA capability query [mid: 0x%04x] to "
        MACFMT " from interface %s for sta ["MACFMT"] at bssid ["MACFMT"]\n", mid,
        MACARG(al_id), ifname, MACARG(sta_mac), MACARG(bss_id));

    if (send1905ClientCapabilityQuery(bss_id, sta_mac, ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_IFNAME = 0,
    MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_DEST_ALID,
    MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_NEIGHBOR_ALID,
    MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_METRIC_TYPE,

    NUM_MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTRS,
};

static const struct blobmsg_policy mapapi_query_backhaul_link_metrics_policy[] = {
    [MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_NEIGHBOR_ALID] = { .name = MAPAPI_SET_ATTR_NEIGHBOR_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_METRIC_TYPE] = { .name = MAPAPI_SET_ATTR_METRIC_TYPE_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int mapapi_query_backhaul_link_metrics(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTRS];
    const char *ifname;
    mac_address al_id, neighbor_al_id;
    int metric_type;
    uint16_t mid = getNextMid();
    uint8_t ret;

    blobmsg_parse(mapapi_query_backhaul_link_metrics_policy, NUM_MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_DEST_ALID] || !tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_METRIC_TYPE])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_DEST_ALID], al_id);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    metric_type = blobmsg_get_u32(tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_METRIC_TYPE]);
    if (metric_type > LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS)
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    if (tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_NEIGHBOR_ALID])
    {
        blobmsg_get_mac(tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_NEIGHBOR_ALID], neighbor_al_id);
	PLATFORM_PRINTF_DEBUG_INFO("try to send backhaul link metric query [mid: 0x%04x] to "
            MACFMT " of requesting neighbor " MACFMT " with metirc type 0x%02x from interface %s\n",
            mid, MACARG(al_id), MACARG(neighbor_al_id), metric_type,ifname);
	ret = send1905MetricsQueryPacket(ifname, mid, al_id, neighbor_al_id, metric_type);
    }
    else
    {
        PLATFORM_PRINTF_DEBUG_INFO("try to send backhaul link metric query [mid: 0x%04x] to "
            MACFMT " of all neighboring with metirc type 0x%02x from interface %s\n",
            mid, MACARG(al_id), metric_type,ifname);
        ret = send1905MetricsQueryPacket(ifname, mid, al_id, NULL, metric_type);
    }

    if (ret)
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_AP_METRICS_ATTR_IFNAME = 0,
    MAPAPI_QUERY_AP_METRICS_ATTR_DEST_ALID,
    MAPAPI_QUERY_AP_METRICS_ATTR_BSSIDS,

    NUM_MAPAPI_QUERY_AP_METRICS_ATTRS,
};

static const struct blobmsg_policy mapapi_query_ap_metrics_policy[] = {
    [MAPAPI_QUERY_AP_METRICS_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_AP_METRICS_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_AP_METRICS_ATTR_BSSIDS] = { .name = MAPAPI_SET_ATTR_BSSIDS_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static int mapapi_query_ap_metrics(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_AP_METRICS_ATTRS];
    const char *ifname;
    mac_address al_id;
    dlist_head bssids_head;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_ap_metrics_policy, NUM_MAPAPI_QUERY_AP_METRICS_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_AP_METRICS_ATTR_DEST_ALID] || !tb[MAPAPI_QUERY_AP_METRICS_ATTR_BSSIDS])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_AP_METRICS_ATTR_DEST_ALID], al_id);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_AP_METRICS_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    dlist_head_init(&bssids_head);
    visit_attrs(tb[MAPAPI_QUERY_AP_METRICS_ATTR_BSSIDS], array_mac_to_dlist, &bssids_head,
        MAPAPI_BSS_ATTR_BSSID_NAME);

    PLATFORM_PRINTF_DEBUG_INFO("try to send AP metric query [mid: 0x%04x] to "
        MACFMT " from interface %s\n", mid, MACARG(al_id), ifname);

    if (send1905ApMetricsQuery(&bssids_head, ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    dlist_free_items(&bssids_head, struct macAddressItem, l);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_IFNAME = 0,
    MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_DEST_ALID,
    MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_STA_MAC,

    NUM_MAPAPI_QUERY_ASSOC_STA_METRICS_ATTRS,
};

static const struct blobmsg_policy mapapi_query_assoc_sta_metrics_policy[] = {
    [MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_STA_MAC] = { .name = MAPAPI_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_MAC },
};

static int mapapi_query_assoc_sta_metrics(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_ASSOC_STA_METRICS_ATTRS];
    const char *ifname;
    mac_address al_id, sta_mac;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_assoc_sta_metrics_policy, NUM_MAPAPI_QUERY_ASSOC_STA_METRICS_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_DEST_ALID] || !tb[MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_STA_MAC])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_DEST_ALID], al_id);
    blobmsg_get_mac(tb[MAPAPI_QUERY_ASSOC_STA_METRICS_ATTR_STA_MAC], sta_mac);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send assoc sta metric query [mid: 0x%04x] to "
        MACFMT " for sta "MACFMT" from interface %s \n", mid,
        MACARG(al_id), MACARG(sta_mac), ifname);

    if (send1905AssociatedStaLinkMetricQuery(ifname, mid, al_id, sta_mac))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_CHANNELS_ATTR_CHANNEL = 0,
    MAPAPI_CHANNELS_ATTR_STATIONS,

    NUM_MAPAPI_CHANNELS_ATTRS,
};

static const struct blobmsg_policy mapapi_chans_policy[] = {
    [MAPAPI_CHANNELS_ATTR_CHANNEL] = { .name = MAPAPI_RADIO_ATTR_CHANNEL_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_CHANNELS_ATTR_STATIONS] = { .name = MAPAPI_BSS_ATTR_STATIONS_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static uint8_t mapapi_parse_chan_and_stas(dlist_head *head, struct blob_attr *attrs, struct chanUnassocSta *chan_item)
{
    struct blob_attr *tb[NUM_MAPAPI_CHANNELS_ATTRS];

    blobmsg_parse(mapapi_chans_policy, NUM_MAPAPI_CHANNELS_ATTRS,
        tb, blobmsg_data(attrs), blobmsg_len(attrs));

    if (!tb[MAPAPI_CHANNELS_ATTR_CHANNEL] || !tb[MAPAPI_CHANNELS_ATTR_STATIONS])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return 0;
    }

    dlist_head_init(&chan_item->unassocSTAs);
    chan_item->chan = blobmsg_get_u32(tb[MAPAPI_CHANNELS_ATTR_CHANNEL]);
    visit_attrs(tb[MAPAPI_CHANNELS_ATTR_STATIONS], array_mac_to_dlist, &chan_item->unassocSTAs,
        MAPAPI_STATION_ATTR_MAC_NAME);

    return 1;
}

static uint8_t mapapi_parse_chans(dlist_head *head, struct blob_attr *attrs)
{
    struct blob_attr *attr;
    int rem, ret = 0;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        struct chanUnassocSta *chan_item;
        chan_item = (struct chanUnassocSta *)malloc(sizeof(*chan_item));
        ret |= mapapi_parse_chan_and_stas(head, attr, chan_item);
        dlist_add_tail(head, &chan_item->l);
    }

    return ret;
}

void mapapi_free_dlist_chan_stas(dlist_head *head)
{
    struct chanUnassocSta *chan_item;

    dlist_for_each(chan_item, *head, l)
        dlist_free_items(&chan_item->unassocSTAs, struct macAddressItem, l);
}

enum {
    MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_IFNAME = 0,
    MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_DEST_ALID,
    MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_OPCLASS,
    MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_CHANNELS,

    NUM_MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTRS,
};

static const struct blobmsg_policy mapapi_query_unassoc_sta_metrics_policy[] = {
    [MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_OPCLASS] = { .name = MAPAPI_RADIO_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_CHANNELS] = { .name = MAPAPI_SET_ATTR_CHANNELS_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static int mapapi_query_unassoc_sta_metrics(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTRS];
    const char *ifname;
    mac_address al_id;
    int opclass;
    dlist_head chans_head;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_unassoc_sta_metrics_policy, NUM_MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_DEST_ALID] || !tb[MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_OPCLASS]
        || !tb[MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_CHANNELS])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_DEST_ALID], al_id);
    opclass = blobmsg_get_u32(tb[MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_OPCLASS]);

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_BACKHAUL_LINK_METRICS_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    dlist_head_init(&chans_head);

    if (!mapapi_parse_chans(&chans_head, tb[MAPAPI_QUERY_UNASSOC_STA_METRICS_ATTR_CHANNELS]))
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send unassoc sta metric query [mid: 0x%04x] to "
        MACFMT " with opclass %d from interface %s \n", mid, MACARG(al_id), opclass, ifname);

    if (send1905UnassociatedSTALinkMetricsQuery(ifname, mid, al_id, opclass, &chans_head))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    mapapi_free_dlist_chan_stas(&chans_head);
    dlist_free_items(&chans_head, struct chanUnassocSta, l);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_QUERY_BEACON_METRICS_ATTR_IFNAME = 0,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_DEST_ALID,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_STA_MAC,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_OPCLASS,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_NUMBER,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_BSSID,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_REPORTING_DETAIL,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_SSID,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS,
    MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS,

    NUM_MAPAPI_QUERY_BEACON_METRICS_ATTRS,
};

static const struct blobmsg_policy mapapi_query_beacon_metrics_policy[] = {
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_STA_MAC] = { .name = MAPAPI_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_OPCLASS] = { .name = MAPAPI_RADIO_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_NUMBER] = { .name = MAPAPI_SET_ATTR_BEACON_REQ_CHAN_NUMBER_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_BSSID] = { .name = MAPAPI_BSS_ATTR_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_REPORTING_DETAIL] = { .name = MAPAPI_SET_ATTR_BEACON_REQ_REPORTING_DETAIL_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_SSID] = { .name = MAPAPI_BSS_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_UNSPEC },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS] = { .name = MAPAPI_SET_ATTR_BEACON_REQ_CHAN_REPORTS_NAME, .type = BLOBMSG_TYPE_UNSPEC },
    [MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS] = { .name = MAPAPI_SET_ATTR_BEACON_REQ_ELEMENT_IDS_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

static int mapapi_query_beacon_metrics(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_QUERY_BEACON_METRICS_ATTRS];
    const char *ifname;
    int opclass, chan_number, reporting_detail, ssid_len;
    mac_address al_id, sta_mac, bssid;
    uint8_t *chan_reports = NULL, *element_ids = NULL, *tmp_data;
    uint8_t ssid[1 + TLV_FIELD_MAX_NUMBER] = { 0 };
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_query_beacon_metrics_policy, NUM_MAPAPI_QUERY_BEACON_METRICS_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_DEST_ALID] || !tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_STA_MAC]
        || !tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_OPCLASS] || !tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_NUMBER]
        || !tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_BSSID] || !tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_REPORTING_DETAIL]
        || !tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_SSID])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_DEST_ALID], al_id);
    blobmsg_get_mac(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_STA_MAC], sta_mac);
    blobmsg_get_mac(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_BSSID], bssid);
    opclass = blobmsg_get_u32(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_OPCLASS]);
    chan_number = blobmsg_get_u32(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_NUMBER]);
    reporting_detail = blobmsg_get_u32(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_REPORTING_DETAIL]);
    tmp_data = (uint8_t *)blobmsg_data(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_SSID]);
    ssid_len = blobmsg_data_len(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_SSID]);
    ssid[0] = ssid_len;
    memcpy(&ssid[1], tmp_data, ssid_len);
    ssid[1+ssid_len] = '\0';

    if ((tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS] && chan_number != 255)
        || (tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS] && !reporting_detail))
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    if ((!tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS] && chan_number == 255)
        || (!tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS] && reporting_detail == 1))
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    if (tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS])
    {
        tmp_data = (uint8_t *)blobmsg_data(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS]);
        chan_reports = zmemalloc(blobmsg_data_len(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS]));
        memcpy(chan_reports, tmp_data, blobmsg_data_len(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_CHAN_REPORTS]));
    }

    if (tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS])
    {
        tmp_data = (uint8_t *)blobmsg_data(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS]);
        element_ids = zmemalloc(blobmsg_data_len(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS]));
        memcpy(element_ids, tmp_data, blobmsg_data_len(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_ELEMENT_IDS]));
    }

    ifname = blobmsg_get_string(tb[MAPAPI_QUERY_BEACON_METRICS_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        goto __end;
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send beacon metric query [mid: 0x%04x] to "
        MACFMT " for sta " MACFMT " with bssid " MACFMT "from interface %s \n",
        mid, MACARG(al_id), MACARG(sta_mac), MACARG(bssid), ifname);

    if (send1905BeaconMetricsQuery(sta_mac, opclass, chan_number, bssid, reporting_detail, ssid,
        chan_reports, element_ids, ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

__end:
    if (chan_reports)
        free(chan_reports);

    if (element_ids)
        free(element_ids);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_SEND_STEERING_COMPLETED_ATTR_IFNAME = 0,
    MAPAPI_SEND_STEERING_COMPLETED_ATTR_DEST_ALID,

    NUM_MAPAPI_SEND_STEERING_COMPLETED_ATTRS,
};

static const struct blobmsg_policy mapapi_send_steering_completed_policy[] = {
    [MAPAPI_SEND_STEERING_COMPLETED_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_SEND_STEERING_COMPLETED_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
};

static int mapapi_send_steering_completed(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_SEND_STEERING_COMPLETED_ATTRS];
    const char *ifname;
    mac_address al_id;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_send_steering_completed_policy, NUM_MAPAPI_SEND_STEERING_COMPLETED_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_SEND_STEERING_COMPLETED_ATTR_DEST_ALID])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_SEND_STEERING_COMPLETED_ATTR_DEST_ALID], al_id);

    ifname = blobmsg_get_string(tb[MAPAPI_SEND_STEERING_COMPLETED_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send steering completed message [mid: 0x%04x] to "
        MACFMT " from interface %s\n", mid, MACARG(al_id), ifname);

    if (send190SteeringCompleted(ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_DO_STEER_LOCAL_ATTR_STA = 0,
    MAPAPI_DO_STEER_LOCAL_ATTR_CURRENT_BSSID,
    MAPAPI_DO_STEER_LOCAL_ATTR_BTM_DISASSOC_IMMINENT,
    MAPAPI_DO_STEER_LOCAL_ATTR_BTM_ABRIGED,
    MAPAPI_DO_STEER_LOCAL_ATTR_BTM_TIMER,
    MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSSID,
    MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_OPCLASS,
    MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_CHANNEL,

    NUM_MAPAPI_DO_STEER_LOCAL_ATTRS,
};

static const struct blobmsg_policy mapapi_do_steer_local_policy[] = {
    [MAPAPI_DO_STEER_LOCAL_ATTR_STA] = { .name = MAPAPI_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_DO_STEER_LOCAL_ATTR_CURRENT_BSSID] = { .name = MAPAPI_STEERING_ATTR_CURRENT_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_DO_STEER_LOCAL_ATTR_BTM_DISASSOC_IMMINENT] = { .name = MAPAPI_STEERING_ATTR_BTM_DISASSOC_IMMINENT_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_DO_STEER_LOCAL_ATTR_BTM_ABRIGED] = { .name = MAPAPI_STEERING_ATTR_BTM_ABRIDGED_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_DO_STEER_LOCAL_ATTR_BTM_TIMER] = { .name = MAPAPI_STEERING_ATTR_BTM_TIMER_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSSID] = { .name = MAPAPI_STEERING_ATTR_TARGET_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_OPCLASS] = { .name = MAPAPI_STEERING_ATTR_TARGET_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_CHANNEL] = { .name = MAPAPI_STEERING_ATTR_TARGET_CHAN_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static uint8_t mapapi_lookup_local_intf_and_assoced_sta(struct interfaceWifi *ifw,
    mac_address current_bss, mac_address sta)
{
    struct staInfo *client;

    if (ifw->role != interface_wifi_role_ap)
        return 0;

    if (current_bss && memcmp(ifw->bssInfo.bssid, current_bss, sizeof(mac_address)))
        return 0;

    dlist_for_each(client, ifw->clients, l)
    {
        if (sta && !memcmp(sta, client->mac, sizeof(mac_address)))
            return 1;
    }
    return 0;
}

static int mapapi_do_steer_local(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_DO_STEER_LOCAL_ATTRS];
    mac_address sta, current_bssid, target_bssid;
    uint8_t *frame = NULL, mode = 0, btm_disassoc_imminent = 0, btm_abridged = 0,
        target_opclass = 0, target_chan = 0, be_matched = 0;
    uint16_t btm_timmer = 0;
    uint32_t frame_len = IEEE80211_MAX_MGTFRAME_LEN;
    struct macAddressItem   *item;
    struct interface *intf;
    struct interfaceWifi *ifw;

    blobmsg_parse(mapapi_do_steer_local_policy, NUM_MAPAPI_DO_STEER_LOCAL_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_DO_STEER_LOCAL_ATTR_STA] || !tb[MAPAPI_DO_STEER_LOCAL_ATTR_CURRENT_BSSID]
        || !tb[MAPAPI_DO_STEER_LOCAL_ATTR_BTM_DISASSOC_IMMINENT] || !tb[MAPAPI_DO_STEER_LOCAL_ATTR_BTM_ABRIGED]
        || !tb[MAPAPI_DO_STEER_LOCAL_ATTR_BTM_TIMER] || !tb[MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSSID]
        || !tb[MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_OPCLASS] || !tb[MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_CHANNEL])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_DO_STEER_LOCAL_ATTR_STA], sta);
    dlist_for_each(item, map_policy.local_disallowed, l)
    {
        if (item && !memcmp(item->mac, sta, sizeof(mac_address)))
        {
            fill_result(MAPAPI_RESULT_INVALID_EXECUTION);
            return ubus_send_reply(ctx, req, b.head);
        }
    }

    /* FIXME : to check steering opportunity window when logic supported on agent's side*/

    blobmsg_get_mac(tb[MAPAPI_DO_STEER_LOCAL_ATTR_CURRENT_BSSID], current_bssid);
    dlist_for_each(intf, local_device->interfaces, l)
    {
        if (intf->type != interface_type_wifi)
            continue;

        if (mapapi_lookup_local_intf_and_assoced_sta((struct interfaceWifi *)intf, current_bssid, sta))
        {
            be_matched = 1;
	    ifw = (struct interfaceWifi *)intf;
            break;
        }
    }

    if (!be_matched)
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    btm_disassoc_imminent = blobmsg_get_u32(tb[MAPAPI_DO_STEER_LOCAL_ATTR_BTM_DISASSOC_IMMINENT]);
    btm_abridged = blobmsg_get_u32(tb[MAPAPI_DO_STEER_LOCAL_ATTR_BTM_ABRIGED]);
    btm_timmer = blobmsg_get_u32(tb[MAPAPI_DO_STEER_LOCAL_ATTR_BTM_TIMER]);
    target_opclass = blobmsg_get_u32(tb[MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_OPCLASS]);
    target_chan = blobmsg_get_u32(tb[MAPAPI_DO_STEER_LOCAL_ATTR_TARGET_BSS_CHANNEL]);

    if (btm_disassoc_imminent)
        mode |= (1 << IEEE80211_TRANSREQ_BSS_DISASSOC_SHIFT);

    if (btm_abridged)
        mode |= (1 << IEEE80211_TRANSREQ_ABRIDGED_SHIFT);

    if (!ifw->radio)
    {
        fill_result(MAPAPI_RESULT_NOT_SUPPORTED);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to steer local sta " MACFMT" from current bss"
        MACFMT " to target bss " MACFMT "\n", MACARG(sta), MACARG(current_bssid),
        MACARG(target_bssid));

    frame = malloc(IEEE80211_MAX_MGTFRAME_LEN);
    mapBuildBtmRequest(current_bssid, sta, 1, target_bssid,
        target_opclass, target_chan, mode, btm_timmer, frame, &frame_len);

    if (frame_len)
    {
        IFW_SEND_FRAME(ifw, frame, frame_len);
        fill_result(MAPAPI_RESULT_SUCCESS);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    free(frame);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_IFNAME = 0,
    MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_DEST_ALID,
    MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_BSSID,
    MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_ASSOC_CONTROL,
    MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_PERIOD,
    MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_STATIONS,

    NUM_MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTRS,
};

static const struct blobmsg_policy mapapi_request_association_control_policy[] = {
    [MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_BSSID] = { .name = MAPAPI_BSS_ATTR_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_ASSOC_CONTROL] = { .name = MAPAPI_SET_ATTR_ASSOC_CTRL_REQ_ASSOC_CONTROL_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_PERIOD] = { .name = MAPAPI_SET_ATTR_ASSOC_CTRL_REQ_PERIOD_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_STATIONS] = { .name = MAPAPI_BSS_ATTR_STATIONS_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static int mapapi_request_association_control(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTRS];
    const char *ifname;
    mac_address al_id, bssid;
    uint16_t mid = getNextMid();
    int assoc_control, period;
    dlist_head assoc_control_stas_head;

    blobmsg_parse(mapapi_request_association_control_policy, NUM_MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_DEST_ALID] || !tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_BSSID]
        || !tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_ASSOC_CONTROL] || !tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_PERIOD]
        || !tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_STATIONS])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_DEST_ALID], al_id);
    blobmsg_get_mac(tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_BSSID], bssid);
    assoc_control = blobmsg_get_u32(tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_ASSOC_CONTROL]);
    period = blobmsg_get_u32(tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_PERIOD]);
    dlist_head_init(&assoc_control_stas_head);
    visit_attrs(tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_STATIONS], array_mac_to_dlist, &assoc_control_stas_head,
        MAPAPI_STATION_ATTR_MAC_NAME);

    if (assoc_control > ASSOC_CTRL_UNBLOCK)
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    ifname = blobmsg_get_string(tb[MAPAPI_REQUEST_ASSOCIATION_CONTROL_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("try to send assoc control request message [mid: 0x%04x] to "
        MACFMT " for bss " MACFMT " with %sblock control from interface %s\n", mid, MACARG(al_id),
        MACARG(bssid), (assoc_control == ASSOC_CTRL_BLOCK) ? "" : "un", ifname);

    if (send1905ClientAssociationControlRequest(ifname, mid, al_id, bssid, assoc_control, period, &assoc_control_stas_head))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    dlist_free_items(&assoc_control_stas_head, struct macAddressItem, l);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_SEND_HLDATA_MESSAGE_ATTR_IFNAME = 0,
    MAPAPI_SEND_HLDATA_MESSAGE_ATTR_DEST_ALID,
    MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PROTOCOL,
    MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PAYLOAD,

    NUM_MAPAPI_SEND_HLDATA_MESSAGE_ATTRS,
};

static const struct blobmsg_policy mapapi_send_hldata_message_policy[] = {
    [MAPAPI_SEND_STEERING_COMPLETED_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_SEND_STEERING_COMPLETED_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PROTOCOL] = { .name = MAPAPI_SET_ATTR_HLD_MESSAGE_PROTOCOL_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PAYLOAD] = { .name = MAPAPI_SET_ATTR_HLD_MESSAGE_PAYLOAD_NAME, .type = BLOBMSG_TYPE_UNSPEC },
};

static int mapapi_send_hldata_message(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_SEND_HLDATA_MESSAGE_ATTRS];
    const char *ifname;
    mac_address al_id;
    uint16_t mid = getNextMid(), payload_len;
    uint8_t *payload, protocol;

    blobmsg_parse(mapapi_send_hldata_message_policy, NUM_MAPAPI_SEND_HLDATA_MESSAGE_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_SEND_STEERING_COMPLETED_ATTR_DEST_ALID] || !tb[MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PROTOCOL]
        || !tb[MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PAYLOAD])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    ifname = blobmsg_get_string(tb[MAPAPI_SEND_STEERING_COMPLETED_ATTR_IFNAME]);
    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(al_id);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_SEND_STEERING_COMPLETED_ATTR_DEST_ALID], al_id);
    protocol = blobmsg_get_u32(tb[MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PROTOCOL]);
    payload_len = blobmsg_data_len(tb[MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PAYLOAD]);
    payload = zmemalloc(payload_len);
    memcpy(payload, (uint8_t *)blobmsg_data(tb[MAPAPI_SEND_HLDATA_MESSAGE_ATTR_PAYLOAD]), payload_len);

    PLATFORM_PRINTF_DEBUG_INFO("try to send higher layer data message [mid: 0x%04x] to "
        MACFMT " with protocol [0x%02x] from interface %s\n", mid, MACARG(al_id), protocol, ifname);

    if (send1905HigherLayerData(protocol, payload, payload_len, ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    free(payload);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBE_FRAME_TYPE,
    MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES_SUSCRIBE,
    MAPAPI_SUSCRIBE_FRAME_SUSCRIBE_ATTRS
};

enum {
    MAPAPI_SUSCRIBE_FRAME_ATTR_ENABLE,
    MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES,
    MAPAPI_SUSCRIBE_FRAME_ATTRS
};

const struct blobmsg_policy mapapi_frame_receive_suscribe_policy[] =
{
    [MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBE_FRAME_TYPE] = { .name = MAPAPI_SUSCRIBE_FRAME_ATTR_FRAME_TYPE_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES_SUSCRIBE] = { .name = MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBE_NAME, .type = BLOBMSG_TYPE_INT32 },
};

const struct blobmsg_policy mapapi_frame_receive_suscribes_policy[] =
{
    [MAPAPI_SUSCRIBE_FRAME_ATTR_ENABLE] = { .name = MAPAPI_SUSCRIBE_FRAME_ATTR_ENABLE_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES] = { .name = MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES_NAME, .type = BLOBMSG_TYPE_ARRAY },
};


static void set_frame_receive_subscribe(uint16_t type, uint16_t flag)
{
    struct frame_suscribe_ctl_t *ctl;

    if (flag) {
        dlist_for_each(ctl, map_config.frame_suscribe.rx_1905_suscribe, l){
            if (ctl->type == type) {
                ctl->flag = flag;
                return;
            }
        }
        ctl=(struct frame_suscribe_ctl_t *)memalloc(sizeof(struct frame_suscribe_ctl_t));
        ctl->type = type;
        ctl->flag = flag;
        dlist_add_tail(&map_config.frame_suscribe.rx_1905_suscribe, &ctl->l);
    }
}

static void clear_frame_receive_subscribes()
{
    dlist_head *head = &map_config.frame_suscribe.rx_1905_suscribe;
    if (!dlist_empty(head))
        dlist_free_items(head, struct frame_suscribe_ctl_t, l);
}

static int set_frame_receive_subscribes(struct blob_attr *attrs)
{
    struct blob_attr *attr;
    int rem, ret = 0;
    uint16_t type, flag;
    struct blob_attr *tb[ARRAY_SIZE(mapapi_frame_receive_suscribe_policy)];

    blobmsg_for_each_attr(attr, attrs, rem)
	{
        blobmsg_parse(mapapi_frame_receive_suscribe_policy, ARRAY_SIZE(mapapi_frame_receive_suscribe_policy),
			tb, blobmsg_data(attr), blobmsg_len(attr));
	    if ((tb[MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBE_FRAME_TYPE]) && (tb[MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES_SUSCRIBE])) {
            type = blobmsg_get_u32(tb[MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBE_FRAME_TYPE]);
            flag = blobmsg_get_u32(tb[MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES_SUSCRIBE]);
            set_frame_receive_subscribe(type, flag);
            ret++;
        }
	}
    return ret;
}

static int mapapi_suscribe_frame_receive(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    int ret = 0, enable;
    struct blob_attr *tb[ARRAY_SIZE(mapapi_frame_receive_suscribes_policy)];

    blobmsg_parse(mapapi_frame_receive_suscribes_policy, ARRAY_SIZE(mapapi_frame_receive_suscribes_policy),
        tb, blobmsg_data(msg), blobmsg_len(msg));
    if (tb[MAPAPI_SUSCRIBE_FRAME_ATTR_ENABLE]) {
        enable = blobmsg_get_u32(tb[MAPAPI_SUSCRIBE_FRAME_ATTR_ENABLE]);

        if (enable) {
            if (tb[MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES])
		        ret = set_frame_receive_subscribes(tb[MAPAPI_SUSCRIBE_FRAME_ATTR_SUSCRIBES]);
        } else {
            clear_frame_receive_subscribes();
            ret = 1;
        }
    }

    blob_buf_init(&b, 0);
    if (ret)
        fill_result(MAPAPI_RESULT_SUCCESS);
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);
    return ubus_send_reply(ctx, req, b.head);
}

static const struct ubus_method mapapi_methods[] = {
    UBUS_METHOD(MAPAPI_METHOD_SEARCH_CONTROLLER_NAME, mapapi_search_controller, mapapi_search_controller_policy),
    UBUS_METHOD(MAPAPI_METHOD_DO_TOPOLOGY_DISCOVERY_NAME, mapapi_do_topology_discovery, mapapi_do_topology_discovery_policy),
    UBUS_METHOD_NOARG(MAPAPI_METHOD_START_AP_AUTOCONFIGURATION_NAME, mapapi_start_ap_autoconfiguration),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_TOPOLOGY_NAME, mapapi_query_topology, mapapi_query_topology_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_AP_CAPA_NAME, mapapi_query_ap_capa, mapapi_query_ap_capa_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_CHANNEL_PREFERENCE_NAME, mapapi_query_channel_preference, mapapi_query_channel_preference_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_STA_CAPA_NAME, mapapi_query_sta_capa, mapapi_query_sta_capa_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_BACKHAUL_LINK_METRICS_NAME, mapapi_query_backhaul_link_metrics, mapapi_query_backhaul_link_metrics_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_AP_METRICS_NAME, mapapi_query_ap_metrics, mapapi_query_ap_metrics_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_ASSOC_STA_METRICS_NAME, mapapi_query_assoc_sta_metrics, mapapi_query_assoc_sta_metrics_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_UNASSOC_STA_METRICS_NAME, mapapi_query_unassoc_sta_metrics, mapapi_query_unassoc_sta_metrics_policy),
    UBUS_METHOD(MAPAPI_METHOD_QUERY_BEACON_METRICS_NAME, mapapi_query_beacon_metrics, mapapi_query_beacon_metrics_policy),
    UBUS_METHOD(MAPAPI_METHOD_SEND_STEERING_COMPLETED_NAME, mapapi_send_steering_completed, mapapi_send_steering_completed_policy),
    UBUS_METHOD(MAPAPI_METHOD_DO_STEER_LOCAL_NAME, mapapi_do_steer_local, mapapi_do_steer_local_policy),
    UBUS_METHOD(MAPAPI_METHOD_REQUEST_ASSOC_CONTROL_NAME, mapapi_request_association_control, mapapi_request_association_control_policy),
    UBUS_METHOD(MAPAPI_METHOD_SEND_HLDATA_MESSAGE_NAME, mapapi_send_hldata_message, mapapi_send_hldata_message_policy),
	UBUS_METHOD(MAPAPI_SUSCRIBE_FRAME_RECEIVE_NAME, mapapi_suscribe_frame_receive, mapapi_frame_receive_suscribes_policy),
    //TODO more
};

static struct ubus_object_type mapapi_obj_type =
UBUS_OBJECT_TYPE(MAPAPI_OBJ_NAME, mapapi_methods);

static struct ubus_object mapapi_obj = {
    .name = MAPAPI_OBJ_NAME,
    .type = &mapapi_obj_type,
    .methods = mapapi_methods,
    .n_methods = ARRAY_SIZE(mapapi_methods),
};

struct ubus_object *get_mapapi_obj(void)
{
    return &mapapi_obj;
}

void mapapi_event_receive_hldata(uint8_t proto, uint8_t *src, uint8_t *dest, uint8_t *data, uint16_t data_len)
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_SRC_ADDR_NAME, src);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_DEST_ADDR_NAME, dest);
        blobmsg_add_binary( &b, MAPAPI_EVENT_ATTR_DATA_NAME, data, data_len);
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_RECEIVED_HL_DATA_NAME, b.head, -1);
    }
}

void mapapi_event_duplicated_controller_detected(struct alDevice *dev, uint16_t msg_type)
{
    if (platform_ubus) {
        uint32_t intf_nr = dlist_count(&dev->interfaces);
        blob_buf_init(&b, 0);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_ALID_NAME, dev->al_mac_addr);
        blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_PROFILE_NAME, dev->profile);
        blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_MSG_TYPE_NAME, msg_type);
        if (intf_nr)
        {
            struct interface *intf;
            void *intfs_list = blobmsg_open_array(&b, MAPAPI_EVENT_ATTR_INTERFACES_NAME);
            dlist_for_each(intf, dev->interfaces, l)
            {
                void *intf_table = blobmsg_open_table(&b, NULL);
                blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_INTERFACE_MAC_ADDR_NAME, intf->addr);
                blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_INTERFACE_MEDIA_TYPE_NAME, intf->media_type);
                blobmsg_add_binary(&b, MAPAPI_EVENT_ATTR_INTERFACE_MEDIA_INFO_NAME, intf->media_specific_info, intf->media_specific_info_length);
                blobmsg_close_table(&b, intf_table);
            }
            blobmsg_close_array(&b, intfs_list);
        }
        if (dev->is_map_agent || dev->is_map_controller)
        {
            void *services_list = blobmsg_open_array(&b, MAPAPI_EVENT_ATTR_SUPPORTED_SERVICES_NAME);
            void *service_table;
            if (dev->is_map_controller)
            {
                service_table = blobmsg_open_table(&b, NULL);
                blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_SERVICE_NAME, 0);
                blobmsg_close_table(&b, service_table);
            }
            if (dev->is_map_agent)
            {
                service_table = blobmsg_open_table(&b, NULL);
                blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_SERVICE_NAME, 1);
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
                void *bsses_list = blobmsg_open_array(&b, MAPAPI_EVENT_ATTR_BSSES_NAME);
                dlist_for_each(intf, dev->interfaces, l)
                {
                    struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
                    if (intf->type == interface_type_wifi
                            && ifw->role == interface_wifi_role_ap)
                    {
                        void *bss_table = blobmsg_open_table(&b, NULL);
                        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
                        blobmsg_add_binary(&b, MAPAPI_EVENT_ATTR_SSID_NAME, ifw->bssInfo.ssid.ssid, ifw->bssInfo.ssid.length);
                        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_RADIO_ID_NAME, ifw->radio->uid);
                        blobmsg_close_table(&b, bss_table);
                    }
                }
                blobmsg_close_array(&b, bsses_list);
            }
        }
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_DUPLICATED_CONTROLLER_DETECTED_NAME, b.head, -1);
    }
}

void mapapi_event_duplicated_registrar_detected(struct alDevice *dev)
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_ALID_NAME, dev->al_mac_addr);
        blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_PROFILE_NAME, dev->profile);
        // refer to IEEE 1905.1a Table 6-24—SupportedRole TLV
        // 0->controller is unique valid value
        blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_SUPPORTED_ROLE_NAME, 0);
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_DUPLICATED_REGISTRAR_DETECTED_NAME, b.head, -1);
    }
}

void mapapi_event_rogue_renew_detected(mac_address alid)
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_ALID_NAME, alid);
        // refer to IEEE 1905.1a Table 6-24—SupportedRole TLV
        // 0->controller is unique valid value
        blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_SUPPORTED_ROLE_NAME, 0);
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_ROGUE_RENEW_DETECTED_NAME, b.head, -1);
    }
}

void mapapi_event_agent_configured()
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_AGENT_CONFIGURED_NAME, b.head, -1);
    }
}

void mapapi_event_steering_candidates_needed(mac_address bssid, dlist_head *stations)
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_CURRENT_BSS_NAME, bssid);
        {
            void *stas_list = blobmsg_open_array(&b, MAPAPI_EVENT_ATTR_STAS_TO_STEER_NAME);
            struct macAddressItem *sta;
            dlist_for_each(sta, *stations, l)
            {
                void *sta_table = blobmsg_open_table(&b, NULL);
                blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_STA_MAC_NAME, sta->mac);
                blobmsg_close_table(&b, sta_table);
            }
            blobmsg_close_array(&b, stas_list);
        }
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_STEERING_CANDIDATES_NEEDED_NAME, b.head, -1);
    }
}


void mapapi_event_steering_opportunity(uint16_t steering_window, mac_address cur_bssid, dlist_head *stations)
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_STEERING_WINDOW_NAME, steering_window);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_CURRENT_BSS_NAME, cur_bssid);
        {
            void *stas_list = blobmsg_open_array(&b, MAPAPI_EVENT_ATTR_STAS_TO_STEER_NAME);
            struct macAddressItem *sta;
            dlist_for_each(sta, *stations, l)
            {
                void *sta_table = blobmsg_open_table(&b, NULL);
                blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_STA_MAC_NAME, sta->mac);
                blobmsg_close_table(&b, sta_table);
            }
            blobmsg_close_array(&b, stas_list);
        }
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_STEERING_OPPORTUNITY_NAME, b.head, -1);
    }
}

void mapapi_event_receive_btm_response(uint8_t *ta, uint8_t *ra, uint8_t *frame, uint32_t frame_len)
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_TA_ADDRESS, ta);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_RA_ADDRESS, ra);
        blobmsg_add_binary(&b, MAPAPI_EVENT_ATTR_FRAME, frame, frame_len);

        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_RECEIVED_BTM_RESPONSE_NAME, b.head, -1);
    }
}

void mapapi_event_client_associated(uint8_t *radio, uint8_t *bssid, uint8_t *ssid, uint8_t ssid_len,
    uint8_t *sta, uint8_t be_local)
{
    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_mac(&b, MAPAPI_BSS_ATTR_RADIO_NAME, radio);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_BSSID_NAME, bssid);
        blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, MAPAPI_EVENT_ATTR_SSID_NAME, ssid, ssid_len);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_STA_MAC_NAME, sta);
        blobmsg_add_u32(&b, MAPAPI_EVENT_ATTR_LOCAL_NAME, be_local);

        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_CLIENT_ASSOCIATED_NAME, b.head, -1);
    }
}

void mapapi_event_receive_frame(uint8_t *src, uint8_t *dest, uint16_t type, dlist_head *tlv_list)
{
    void *p, *p1;
    struct tlv_raw *tlv;

    if (platform_ubus) {
        blob_buf_init(&b, 0);
        blobmsg_add_u16(&b, MAPAPI_SUSCRIBE_FRAME_ATTR_FRAME_TYPE_NAME, type);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_SRC_ADDR_NAME, src);
        blobmsg_add_mac(&b, MAPAPI_EVENT_ATTR_DEST_ADDR_NAME, dest);
        if (tlv_list) {
            p = blobmsg_open_array(&b, MAPAPI_EVENT_ATTR_TLVS_NAME);
            dlist_for_each(tlv, *tlv_list, l){
                p1 = blobmsg_open_table(&b, NULL);
                blobmsg_add_u8(&b, MAPAPI_EVENT_ATTR_TLV_TYPE_NAME, tlv->tlv_type);
                blobmsg_add_binary(&b, MAPAPI_EVENT_ATTR_TLV_NAME, tlv->tlv, tlv->tlv_len);
                blobmsg_close_table(&b, p1);
            }
            blobmsg_close_table(&b, p);
        }
        ubus_notify(platform_ubus, get_mapapi_obj(), MAPAPI_EVENT_RECEIVED_FRAME_NAME, b.head, -1);
    }
}
