/*
 *  Copyright (c) 2018-2020, Semiconductor Components Industries, LLC
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
 * @brief Driver interface for QDOCK
 *
 * This file provides functionality using QDOCK API
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include <platform_linux.h>
#include <map_api.h>
#include "datamodel.h"
#include "platform.h"
#include "platform_interfaces_priv.h"
#include "../platform_os.h"
#include "../al_datamodel.h"
#include "../al_utils.h"
#include "../al.h"
#include "../al_send.h"
#include "../ubus_map.h"

#include "platform_qdock.h"

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define MAP_UBUS_TIMEOUT        (100000)
#define MAP_MAC_ADDR_LEN        (6)

static void qdock_notify_topology_changed(uint8_t *bssid, uint8_t *sta, int associated)
{
    if (!bssid || !sta)
        return;

    if (0 == send1905TopologyNotificationPacket(getNextMid(), bssid, sta, associated))
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology notification message\n");
}

static void qdock_notify_authenticated_link(uint8_t *id, uint8_t *bssid)
{
    uint8_t message[3+24];
    uint8_t *al_mac_address = DMalMacGet();
    uint16_t mid = getNextMid();
    uint32_t if_index = DMmacToInterfaceIndex(bssid);

    message[0]  = PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK;
    message[1]  = 0x00;
    message[2]  = 0x14;
    message[3]  = id[0];
    message[4]  = id[1];
    message[5]  = id[2];
    message[6]  = id[3];
    message[7]  = id[4];
    message[8]  = id[5];
    message[9]  = bssid[0];
    message[10] = bssid[1];
    message[11] = bssid[2];
    message[12] = bssid[3];
    message[13] = bssid[4];
    message[14] = bssid[5];
    message[15] = al_mac_address[0];
    message[16] = al_mac_address[1];
    message[17] = al_mac_address[2];
    message[18] = al_mac_address[3];
    message[19] = al_mac_address[4];
    message[20] = al_mac_address[5];

#if _HOST_IS_LITTLE_ENDIAN_ == 1
    message[21] = *(((uint8_t *)&mid)+1);
    message[22] = *(((uint8_t *)&mid)+0);
    message[23] = (if_index >> 24) & 0xff;
    message[24] = (if_index >> 16) & 0xff;
    message[25] = (if_index >> 8) & 0xff;
    message[26] = if_index  & 0xff;
#else
    message[21] = *(((uint8_t *)&mid)+0);
    message[22] = *(((uint8_t *)&mid)+1);
    message[23] = if_index  & 0xff;
    message[24] = (if_index >> 8) & 0xff;
    message[25] = (if_index >> 16) & 0xff;
    message[26] = (if_index >> 24) & 0xff;
#endif
    PLATFORM_PRINTF_DEBUG_DETAIL("process event PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK (0x%02x, 0x%02x, 0x%02x, ...)\n", message[0], message[1], message[2]);

    process_ALEvent_by_MainThread(message);
}

static struct _qdockData    qdockData;

static struct blob_buf b;
static int rc;

static const struct blobmsg_policy qdock_map_policy[NUM_MAP_ATTRS] = {
    [MAP_ATTR_RC] = {.name = MAP_ATTR_RC_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_ATTR_WIPHY_ID] = {.name = MAP_ATTR_WIPHY_ID_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_ATTR_WIPHYS] = {.name = MAP_ATTR_WIPHYS_NAME, .type = BLOBMSG_TYPE_ARRAY},
    [MAP_ATTR_WDEV_ID] = {.name = MAP_ATTR_WDEV_ID_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_ATTR_WDEV]  = {.name = MAP_ATTR_WDEV_NAME,  .type = BLOBMSG_TYPE_TABLE},
    [MAP_ATTR_WDEVS] = {.name = MAP_ATTR_WDEVS_NAME, .type = BLOBMSG_TYPE_ARRAY},
    [MAP_ATTR_STA_MAC] = {.name = MAP_ATTR_STA_MAC_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_ATTR_STATION] = {.name = MAP_ATTR_STATION_NAME, .type = BLOBMSG_TYPE_TABLE},
    [MAP_ATTR_STATIONS] = {.name = MAP_ATTR_STATIONS_NAME, .type = BLOBMSG_TYPE_ARRAY},
    [MAP_ATTR_MGMT_SUBTYPE]  = {.name = MAP_ATTR_MGMT_SUBTYPE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_ATTR_REASON]        = {.name = MAP_ATTR_REASON_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_ATTR_FRAME_MATCH]   = {.name = MAP_ATTR_FRAME_MATCH_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_ATTR_FRAME]         = {.name = MAP_ATTR_FRAME_NAME , .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_ATTR_STATS_PERIODS] = {.name = MAP_ATTR_STATS_PERIODS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_ATTR_STATS_FAT]     = {.name = MAP_ATTR_STATS_FAT_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_ATTR_STATS_STATION] = {.name = MAP_ATTR_STATS_STATION_NAME, .type = BLOBMSG_TYPE_ARRAY},
    [MAP_ATTR_STATS_MONITOR] = {.name = MAP_ATTR_STATS_MONITOR_NAME, .type = BLOBMSG_TYPE_ARRAY},
};

static const struct blobmsg_policy qdock_map_wiphy_policy[NUM_MAP_WIPHY_ATTRS] = {
    [MAP_WIPHY_ATTR_ID] = {.name = MAP_WIPHY_ATTR_ID_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WIPHY_ATTR_NAME] = {.name = MAP_WIPHY_ATTR_NAME_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAP_WIPHY_ATTR_PHYTYPE] = {.name = MAP_WIPHY_ATTR_PHYTYPE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_OPCLASS] = {.name = MAP_WIPHY_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_CHANNEL] = {.name = MAP_WIPHY_ATTR_CHAN_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_FREQ] = {.name = MAP_WIPHY_ATTR_FREQ_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_BW] = {.name = MAP_WIPHY_ATTR_BW_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_PS_STATE] = {.name = MAP_WIPHY_ATTR_PS_STATE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_TXPOWER] = {.name = MAP_WIPHY_ATTR_TXPOWER_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_FEATURES] = {.name = MAP_WIPHY_ATTR_FEATURES_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WIPHY_ATTR_LIMITS] = {.name = MAP_WIPHY_ATTR_LIMITS_NAME, .type = BLOBMSG_TYPE_ARRAY},
    [MAP_WIPHY_ATTR_OPCLASSES] = {.name = MAP_WIPHY_ATTR_OPCLASSES_NAME, .type = BLOBMSG_TYPE_ARRAY},
};

static const struct blobmsg_policy qdock_map_wiphy_limits_policy[NUM_MAP_LIMIT_ATTRS] = {
    [MAP_LIMIT_ATTR_TYPES] = {.name = MAP_LIMIT_ATTR_TYPES_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_LIMIT_ATTR_MAX] = {.name = MAP_LIMIT_ATTR_MAX_NAME, .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy qdock_map_wiphy_opclasses_policy[NUM_MAP_OPCLASS_ATTRS] = {
    [MAP_OPCLASS_ATTR_ID] = {.name = MAP_OPCLASS_ATTR_ID_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_OPCLASS_ATTR_BW] = {.name = MAP_OPCLASS_ATTR_BW_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_OPCLASS_ATTR_MAX_POWER] = {.name = MAP_OPCLASS_ATTR_MAX_POWER_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_OPCLASS_ATTR_CHANS] = {.name = MAP_OPCLASS_ATTR_CHANS_NAME, .type = BLOBMSG_TYPE_ARRAY},
};

static const struct blobmsg_policy qdock_map_wiphy_opclass_channels_policy[NUM_MAP_CHAN_ATTRS] = {
    [MAP_CHAN_ATTR_CHAN] = {.name = MAP_CHAN_ATTR_CHAN_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_CHAN_ATTR_FREQ] = {.name = MAP_CHAN_ATTR_FREQ_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_CHAN_ATTR_NONOPERABLE] = {.name = MAP_CHAN_ATTR_NONOPERABLE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_CHAN_ATTR_REASON] = {.name = MAP_CHAN_ATTR_REASON_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_CHAN_ATTR_PREF] = {.name = MAP_CHAN_ATTR_PREF_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_CHAN_ATTR_FREQ_SEP] = {.name = MAP_CHAN_ATTR_FREQ_SEP_NAME, .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy qdock_map_wdev_policy[NUM_MAP_WDEV_ATTRS] = {
    [MAP_WDEV_ATTR_ID] = {.name = MAP_WDEV_ATTR_ID_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_NAME] = {.name = MAP_WDEV_ATTR_NAME_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAP_WDEV_ATTR_WIPHY_ID] = {.name = MAP_WDEV_ATTR_WIPHY_ID_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_IFTYPE] = {.name = MAP_WDEV_ATTR_IFTYPE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_IFTYPE_1905] = {.name = MAP_WDEV_ATTR_IFTYPE_1905_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_MODE] = {.name = MAP_WDEV_ATTR_MODE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_BSSID] = {.name = MAP_WDEV_ATTR_BSSID_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_SSID] = {.name = MAP_WDEV_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_BINTVL] = {.name = MAP_WDEV_ATTR_BINTVL_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_HT_CAPA] = {.name = MAP_WDEV_ATTR_HT_CAPA_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_HT_OP] = {.name = MAP_WDEV_ATTR_HT_OP_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_VHT_CAPA] = {.name = MAP_WDEV_ATTR_VHT_CAPA_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_VHT_OP] = {.name = MAP_WDEV_ATTR_VHT_OP_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_HE_CAPA] = {.name = MAP_WDEV_ATTR_HE_CAPA_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_HE_OP] = {.name = MAP_WDEV_ATTR_HE_OP_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_AUTH] = {.name = MAP_WDEV_ATTR_AUTH_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_ENCRYP] = {.name = MAP_WDEV_ATTR_ENCRYP_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_KEY] = {.name = MAP_WDEV_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_WDEV_ATTR_OPCLASS] = {.name = MAP_WDEV_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_CHAN] = {.name = MAP_WDEV_ATTR_CHAN_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_DISABLE] = {.name = MAP_WDEV_ATTR_DISABLE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_WPS] = {.name = MAP_WDEV_ATTR_WPS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_MAP_MTYPES] = {.name = MAP_WDEV_ATTR_MAP_MTYPES_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_STATUS] = {.name = MAP_WDEV_ATTR_STATUS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_ESPI] = {.name = MAP_WDEV_ATTR_ESPI_NAME,     .type = BLOBMSG_TYPE_ARRAY},
    [MAP_WDEV_ATTR_FAT] = {.name = MAP_WDEV_ATTR_FAT_NAME,   .type = BLOBMSG_TYPE_INT32},
    [MAP_WDEV_ATTR_RF_BANDS] = {.name = MAP_WDEV_ATTR_RF_BANDS_NAME,   .type = BLOBMSG_TYPE_INT32},

};

static const struct blobmsg_policy qdock_map_wdev_stats_espi_policy[NUM_MAP_ESPI_ATTRS] = {
    [MAP_ESPI_ATTR_AC]          = {.name = MAP_ESPI_ATTR_AC_NAME,      .type = BLOBMSG_TYPE_INT32},
    [MAP_ESPI_ATTR_FORMAT]      = {.name = MAP_ESPI_ATTR_FORMAT_NAME,  .type = BLOBMSG_TYPE_INT32},
    [MAP_ESPI_ATTR_BA_SIZE]     = {.name = MAP_ESPI_ATTR_BA_SIZE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_ESPI_ATTR_EST_AIRTIME] = {.name = MAP_ESPI_ATTR_EST_AIRTIME_NAME,    .type = BLOBMSG_TYPE_INT32},
    [MAP_ESPI_ATTR_PPDU_DUR]    = {.name = MAP_ESPI_ATTR_PPDU_DUR_NAME, .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy qdock_map_station_policy[NUM_MAP_STATION_ATTRS] = {
    [MAP_STATION_ATTR_MAC] = {.name = MAP_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_STATION_ATTR_OPCLASS] = {.name = MAP_STATION_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_CHANNEL] = {.name = MAP_STATION_ATTR_CHANNEL_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_AGE] = {.name = MAP_STATION_ATTR_AGE_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_ASSOC_REQ] = {.name = MAP_STATION_ATTR_ASSOC_REQ_NAME, .type = BLOBMSG_TYPE_UNSPEC},
    [MAP_STATION_ATTR_RSSI] = {.name = MAP_STATION_ATTR_RSSI_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_RATE_DOWNLINK] = {.name = MAP_STATION_ATTR_RATE_DOWNLINK_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_AGE_DOWNLINK] = {.name = MAP_STATION_ATTR_AGE_DOWNLINK_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_RATE_UPLINK] = {.name = MAP_STATION_ATTR_RATE_UPLINK_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_AGE_UPLINK] = {.name = MAP_STATION_ATTR_AGE_UPLINK_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_TX_BYTES] = {.name = MAP_STATION_ATTR_TX_BYTES_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_RX_BYTES] = {.name = MAP_STATION_ATTR_RX_BYTES_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_TX_PACKETS] = {.name = MAP_STATION_ATTR_TX_PACKETS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_RX_PACKETS] = {.name = MAP_STATION_ATTR_RX_PACKETS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_TX_ERRORS] = {.name = MAP_STATION_ATTR_TX_ERRORS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_RX_ERRORS] = {.name = MAP_STATION_ATTR_RX_ERRORS_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAP_STATION_ATTR_TX_RETRIES] = {.name = MAP_STATION_ATTR_TX_RETRIES_NAME, .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy qdock_map_devdata_policy[NUM_MAP_DEVDATA_ATTRS] = {
    [MAP_DEVDATA_ATTR_DEVICE_NAME] = {.name = MAP_DEVDATA_ATTR_DEVICE_NAME_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAP_DEVDATA_ATTR_MANUFACTURER_NAME] = {.name = MAP_DEVDATA_ATTR_MANUFACTURER_NAME_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAP_DEVDATA_ATTR_MODEL_NAME] = {.name = MAP_DEVDATA_ATTR_MODEL_NAME_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAP_DEVDATA_ATTR_MODEL_NUMBER] = {.name = MAP_DEVDATA_ATTR_MODEL_NUMBER_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAP_DEVDATA_ATTR_SERIAL_NUMBER] = {.name = MAP_DEVDATA_ATTR_SERIAL_NUMBER_NAME, .type = BLOBMSG_TYPE_STRING},
};

static uint32_t qdock_ubus_get_objid(const char *command)
{
    if (!strcmp(command, MAP_METHOD_GET_WIPHYS_NAME))
        return qdockData.intf_objid;
    if (!strcmp(command, MAP_METHOD_GET_WDEVS_NAME))
        return qdockData.intf_objid;
    if (!strcmp(command, MAP_METHOD_SET_PERIODS_NAME))
        return qdockData.stas_objid;
    if (!strcmp(command, MAP_METHOD_GET_MONITOR_STATS_NAME))
        return qdockData.stas_objid;

    return qdockData.mlme_objid;
}

static int qdock_ubus_invoke(const char *command, ubus_data_handler_t cb, void *ctx)
{
    int ret = ubus_invoke(platform_ubus, qdock_ubus_get_objid(command), command,
            b.head, cb, ctx, MAP_UBUS_TIMEOUT);
    if (ret)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Failed to ubus_invoke for command %s: %s\n",
                command, ubus_strerror(ret));
        return ret;
    }

    /* return the response code */
    return rc;
}

#ifdef _ENABLE_BLOGMSG_DUMP_
#define DUMP_MAX_BINS   512
static char blogmsg_bins[DUMP_MAX_BINS * 3 + DUMP_MAX_BINS / 16 + 1];
static const char *qdock_dump_binary_blogmsg(void *priv, struct blob_attr *attr)
{
    uint8_t *data;
    char *pos = blogmsg_bins;
    int len, i;

    if (blob_id(attr) != BLOBMSG_TYPE_UNSPEC)
        return NULL;

    data = (uint8_t *)blobmsg_data(attr);
    len = blobmsg_data_len(attr);
    if (len > DUMP_MAX_BINS)
        len = DUMP_MAX_BINS;

    for (i = 0; i < len; i++)
    {
        if (i && (i & 0xf) == 0)
            pos += sprintf(pos, "\n");
        pos += sprintf(pos, "%02x ", data[i]);
    }

    return (const char *)blogmsg_bins;
}

static void qdock_dump_blogmsg(const char *name, struct blob_attr *msg, const char *caller)
{
    char *str = blobmsg_format_json_with_cb(msg, true, qdock_dump_binary_blogmsg, NULL, -1);

    PLATFORM_PRINTF_DEBUG_DETAIL("dump blogmsg in %s\n", caller);
    if (str)
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("%s\n", str);
        free(str);
    }
}
#define QDOCK_BLOGMSG_DUMP(_name, _msg) qdock_dump_blogmsg(_name, _msg, __func__)
#else
#define QDOCK_BLOGMSG_DUMP(_name, _msg)
#endif

static int qdock_check_response_code(struct blob_attr *rc_attr)
{
    if (!rc_attr)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("failed to receive response code\n");
        return rc;
    }

    rc = blobmsg_get_u32(rc_attr);

    return rc;
}

static inline void blobmsg_add_binary(struct blob_buf *buf, const char *name, const uint8_t *data, uint32_t len)
{
    if (data && len)
        blobmsg_add_field(buf, BLOBMSG_TYPE_UNSPEC, name, data, len);
}

static inline void blobmsg_add_macaddr(struct blob_buf *buf, const char *name, const uint8_t *addr)
{
    blobmsg_add_binary(buf, name, addr, MAP_MAC_ADDR_LEN);
}

static inline int blobmsg_get_binary(struct blob_attr *msg, uint8_t *binary, uint32_t min_len, uint32_t max_len)
{
    int len;
    uint8_t *data;

    if (!msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("msg null!\n");
        return -1;
    }

    data = blobmsg_data(msg);
    len = blobmsg_data_len(msg);

    if (len < min_len || len > max_len)
        return -1;

    memcpy(binary, data, len);
    return len;
}

static inline int blobmsg_get_macaddr(struct blob_attr *msg, mac_address macaddr)
{
    return blobmsg_get_binary(msg, macaddr, MAP_MAC_ADDR_LEN, MAP_MAC_ADDR_LEN);
}

static void qdock_visit_attrs(struct blob_attr *attrs, void (*cb)(void *, void *, int), void *ctx)
{
    struct blob_attr *attr;
    int rem;

    if (!attrs)
        return;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        if (cb)
            cb(ctx, blobmsg_data(attr), blobmsg_len(attr));
    }
}

static int qdock_config_wdev(uint8_t *wdev_id, struct intfwifiConfigInfo *cfg, uint32_t flags);
static void qdock_set_backhaul_info(struct interfaceWifi *ifw, struct ssid *ssid, struct key *key)
{
    struct intfwifiConfigInfo cfg;

    if (ssid->length == 0 || !ssid->ssid || key->len == 0 || !key->key)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("invalid backhual info ssid(%s) ssid_len(%d) key(%s) key_len(%d) for inf(%s)\n", ssid->ssid, ssid->length, key->key, key->len, ifw->i.name);
        return;
    }

    memcpy(&cfg.bh_ssid, ssid, sizeof(*ssid));
    copyKey(&cfg.bh_key, key);
    cfg.bh_auth = MAP_AUTH_WPA2PSK;
    cfg.bh_encryp = MAP_ENCRYP_CCMP;

    qdock_config_wdev(ifw->i.addr, &cfg, INTWIFI_CONFIG_FLAG_BH_CFG);
}

static void qdock_reset_backhaul_info(struct interfaceWifi *ifw)
{
    struct intfwifiConfigInfo cfg;

    qdock_config_wdev(ifw->i.addr, &cfg, INTWIFI_CONFIG_FLAG_BH_CLR);
}

static void qdock_conf_extcap(uint8_t *wdev_id, uint8_t *extcap, uint8_t *extcap_mask, uint32_t len)
{
    struct intfwifiConfigInfo cfg;

    cfg.extcap = extcap;
    cfg.extcap_mask = extcap_mask;
    cfg.extcap_len = len;

    qdock_config_wdev(wdev_id, &cfg, INTWIFI_CONFIG_FLAG_EXTCAP);
}

static void qdock_conf_appies(uint8_t *wdev_id, uint32_t mask, uint8_t *ies, uint32_t len)
{
    struct intfwifiConfigInfo cfg;

    cfg.ies_mask = mask;
    cfg.ies = ies;
    cfg.ies_len = len;

    qdock_config_wdev(wdev_id, &cfg, INTWIFI_CONFIG_FLAG_APPIES);
}

static void qdock_conf_4addr(uint8_t *wdev_id, bool enable)
{
    struct intfwifiConfigInfo cfg;

    cfg.enable_4addr = enable;

    qdock_config_wdev(wdev_id, &cfg, INTWIFI_CONFIG_FLAG_4ADDR);
}

static void qdock_conf_security(uint8_t *wdev_id, uint8_t auth, struct key *key)
{
    struct intfwifiConfigInfo cfg;

    cfg.auth = auth;
    if (auth != auth_mode_open)
        cfg.encryp = MAP_ENCRYP_CCMP;
    else
        cfg.encryp = MAP_ENCRYP_NONE;
    copyKey(&cfg.key, key);

    qdock_config_wdev(wdev_id, &cfg, INTWIFI_CONFIG_FLAG_AUTH | INTWIFI_CONFIG_FLAG_ENCRYP | INTWIFI_CONFIG_FLAG_KEY);
}

static void qdock_conf_wps(uint8_t *wdev_id, bool enable)
{
    struct intfwifiConfigInfo cfg;

    cfg.wps = enable;

    qdock_config_wdev(wdev_id, &cfg, INTWIFI_CONFIG_FLAG_WPS);
}

static void qdock_update_wifi_interface_info(struct interfaceWifi *ifw)
{
    struct _qdockBssInfo *info;

    /* find the other parameter which configured from controller(eg: bh/fh) */
    dlist_for_each(info, qdockData.creating_bsses, l)
    {
#ifdef _find_created_with_ssid_
        /* FIXME: find the creating context with ssid, role and radio id */
        if ((!ifw->radio || !memcmp(ifw->radio->uid, info->uid, sizeof(mac_address)))
                && ifw->role == info->role
                && !compareSSID(&ifw->bssInfo.ssid, &info->ssid))
#else
        if ((!ifw->radio || !memcmp(ifw->radio->uid, info->uid, sizeof(mac_address)))
                && ifw->i.name && !strcmp(ifw->i.name, info->ifname))
#endif
        {
            dlist_remove(&info->l);
            /* Note: clear teardown flag here to avoid mistaken deletion
             * of this interface when previous teardown cmd's teardowned
             * event arrive later than this created event */
            ifw->bssInfo.teardown = false;
            ifw->bssInfo.backhaul = info->backhaul;
            ifw->bssInfo.fronthaul = info->fronthaul;
            PLATFORM_PRINTF_DEBUG_INFO("set bBSS(%u)/fBSS(%u) for wdev(%s)\n",
                    info->backhaul, info->fronthaul, ifw->i.name);
            free(info);
            break;
        }
    }
}

static inline void qdock_handle_wifi_interface_status_changed(struct interfaceWifi *ifw, uint32_t status)
{
    /* register the PLATFORM_QUEUE_EVENT_NEW_1905_PACKET for this up state backhaul interface */
    if (ifw->bssInfo.backhaul && status == interface_power_state_on)
    {
        uint8_t queue_id = PLATFORM_FIND_QUEUE_ID_BY_NAME(AL_EVENTS_NAME);
        PLATFORM_REGISTER_QUEUE_EVENT_NEW_1905_PACKET(queue_id, &ifw->i);
    }

    /* wrokround for first wifi interface */
    if (status == interface_power_state_on)
    {
        qdock_update_wifi_interface_info(ifw);
        /* set backhaul configuation for fronthaul interface */
        if (ifw->bssInfo.fronthaul)
            qdock_set_backhaul_info(ifw, &ifw->radio->backhaul_ssid,
                    &ifw->radio->backhaul_key);

    }
    else if (status == interface_power_state_off)
    {
        /* reset backhaul configuation for fronthaul interface */
        if (ifw->bssInfo.fronthaul)
            qdock_reset_backhaul_info(ifw);
    }

    localInterfaceWifiStatusChanged(ifw, status);
}

static bool qdock_ops_tear_down_intf(struct interface *interface);
static void qdock_handle_wifi_interface_created(struct interfaceWifi *ifw)
{
    qdock_update_wifi_interface_info(ifw);

    /* FIXME: always set the STA interface to backhaul STA
     * Wifi backhaul: initial the device as repeater/sta mode
     * Ethernet backhaul: initial the device as ap mode */
    if (interface_wifi_role_sta == ifw->role)
    {
        qdock_conf_4addr(ifw->i.addr, true);
        ifw->bssInfo.backhaul = 1;
    }

    /* set backhaul configuation for fronthaul interface */
    if (ifw->bssInfo.fronthaul)
        qdock_set_backhaul_info(ifw, &ifw->radio->backhaul_ssid,
                &ifw->radio->backhaul_key);

    /* register the PLATFORM_QUEUE_EVENT_NEW_1905_PACKET for this new backhaul interface */
    if (ifw->bssInfo.backhaul)
    {
        uint8_t queue_id = PLATFORM_FIND_QUEUE_ID_BY_NAME(AL_EVENTS_NAME);
        PLATFORM_REGISTER_QUEUE_EVENT_NEW_1905_PACKET(queue_id, &ifw->i);
    }

    /* TODO: move to handles in radio? register the interface tear down */
    ifw->i.tearDown = qdock_ops_tear_down_intf;

    localInterfaceWifiCreated(ifw);

    // NOTE: when found a new interface update from qdock
    // It should be add this new interface's name to the
    // interfaces_list
    if (ifw->i.name)
    {
        if (!findInterface(ifw->i.name))
        {
            addInterface(ifw->i.name);
        }
        PLATFORM_PRINTF_DEBUG_INFO("wdev(%s) created\n", ifw->i.name);
    }
}

static void qdock_handle_wifi_interface_deleted(struct interfaceWifi *ifw)
{
    /* unregister the PLATFORM_QUEUE_EVENT_NEW_1905_PACKET for this deleted backhaul interface */
    if (ifw->bssInfo.backhaul)
    {
        uint8_t queue_id = PLATFORM_FIND_QUEUE_ID_BY_NAME(AL_EVENTS_NAME);
        PLATFORM_UNREGISTER_QUEUE_EVENT_NEW_1905_PACKET(queue_id, &ifw->i);
    }

    /* reset backhaul configuation for fronthaul interface */
    if (ifw->bssInfo.fronthaul)
        qdock_reset_backhaul_info(ifw);

    localInterfaceWifiDeleted(ifw);

    // NOTE: remove the interface name from the interfaces_list
    if (ifw->i.name)
    {
        PLATFORM_PRINTF_DEBUG_INFO("wdev(%s) deleted\n", ifw->i.name);
        removeInterface(ifw->i.name);
    }
}

static void qdock_update_wiphy_feature(struct radio *r, uint32_t feat)
{
    r->monitor_onchan = (feat & MAP_FEATURE_REPORT_ONCHAN_UNASSOC) ? true : false;
    r->monitor_offchan = (feat & MAP_FEATURE_REPORT_OFFCHAN_UNASSOC) ? true : false;
    r->self_steering = (feat & MAP_FEATURE_RSSI_BASED_STEERING) ? true : false;
}

static void qdock_update_wiphy_limit(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_LIMIT_ATTRS];
    uint32_t type;
    struct radio *r = (struct radio *)ctx;

    blobmsg_parse(qdock_map_wiphy_limits_policy,
            NUM_MAP_LIMIT_ATTRS, tb, data, len);

    if (!tb[MAP_LIMIT_ATTR_TYPES] || !tb[MAP_LIMIT_ATTR_MAX])
        return;

    type = blobmsg_get_u32(tb[MAP_LIMIT_ATTR_TYPES]);
#ifdef Q_OPENWRT
    PLATFORM_PRINTF_DEBUG_INFO("type = %d\n", type);
    PLATFORM_PRINTF_DEBUG_INFO("r->maxBSS = blobmsg_get_u32(tb[MAP_LIMIT_ATTR_MAX]) = %d\n", blobmsg_get_u32(tb[MAP_LIMIT_ATTR_MAX]));
#endif
    if (type & (1 << MAP_IFTYPE_AP))
        r->maxBSS = blobmsg_get_u32(tb[MAP_LIMIT_ATTR_MAX]);
}

static void qdock_update_wiphy_channel(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_CHAN_ATTRS];
    struct radioOpclass *opclass = (struct radioOpclass *)ctx;
    struct radioChannel *channel;

    blobmsg_parse(qdock_map_wiphy_opclass_channels_policy,
            NUM_MAP_CHAN_ATTRS, tb, data, len);

    if (!tb[MAP_CHAN_ATTR_CHAN])
        return;

    channel = opclassFindOrAddChannel(opclass, (uint8_t)blobmsg_get_u32(tb[MAP_CHAN_ATTR_CHAN]));
    if (!channel)
        return;

    if (tb[MAP_CHAN_ATTR_FREQ])
        channel->freq = blobmsg_get_u32(tb[MAP_CHAN_ATTR_FREQ]);

    if (tb[MAP_CHAN_ATTR_NONOPERABLE])
        channel->disabled = blobmsg_get_u32(tb[MAP_CHAN_ATTR_NONOPERABLE]) ? true : false;

    if (tb[MAP_CHAN_ATTR_REASON])
        channel->reason = (uint8_t)blobmsg_get_u32(tb[MAP_CHAN_ATTR_REASON]);

    if (tb[MAP_CHAN_ATTR_PREF])
        channel->pref = (uint8_t)blobmsg_get_u32(tb[MAP_CHAN_ATTR_PREF]);

    if (tb[MAP_CHAN_ATTR_FREQ_SEP])
        channel->min_sep = (uint8_t)blobmsg_get_u32(tb[MAP_CHAN_ATTR_FREQ_SEP]);
}

static void qdock_update_wiphy_opclass(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_OPCLASS_ATTRS];
    struct radio *r = (struct radio *)ctx;
    struct radioOpclass *opclass;

    blobmsg_parse(qdock_map_wiphy_opclasses_policy,
            NUM_MAP_OPCLASS_ATTRS, tb, data, len);

    if (!tb[MAP_OPCLASS_ATTR_ID])
        return;

    opclass = radioFindOrAddOpclass(r, (uint8_t)blobmsg_get_u32(tb[MAP_OPCLASS_ATTR_ID]));
    if (!opclass)
        return;

    if (tb[MAP_OPCLASS_ATTR_BW])
        opclass->bw = (uint8_t)blobmsg_get_u32(tb[MAP_OPCLASS_ATTR_BW]);

    if (tb[MAP_OPCLASS_ATTR_MAX_POWER])
        opclass->max_txpower = (uint8_t)blobmsg_get_u32(tb[MAP_OPCLASS_ATTR_MAX_POWER]);

    qdock_visit_attrs(tb[MAP_OPCLASS_ATTR_CHANS], qdock_update_wiphy_channel, opclass);
}

static void qdock_register_handlers(struct radio *radio);
static void qdock_update_wiphy(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_WIPHY_ATTRS];
    struct radio *radio;
    mac_address wiphy_id;

    blobmsg_parse(qdock_map_wiphy_policy, NUM_MAP_WIPHY_ATTRS, tb, data, len);

    if (blobmsg_get_macaddr(tb[MAP_WIPHY_ATTR_ID], wiphy_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wiphy id found in attrs\n");
        return;
    }

    radio = findDeviceRadio(local_device, wiphy_id);
    if (!radio)
    {
        radio = radioAlloc(local_device, wiphy_id);
        if (!radio)
            return;
        if (local_device->configured)
            local_device->configured = false;
        qdock_register_handlers(radio);

        PLATFORM_PRINTF_DEBUG_INFO("create new local radio " MACFMT "\n", MACARG(wiphy_id));
    }

    if (tb[MAP_WIPHY_ATTR_NAME])
        strncpy(radio->name, blobmsg_get_string(tb[MAP_WIPHY_ATTR_NAME]), T_RADIO_NAME_SZ - 1);

    if (tb[MAP_WIPHY_ATTR_PHYTYPE])
        radio->phytype = blobmsg_get_u32(tb[MAP_WIPHY_ATTR_PHYTYPE]);

    if (tb[MAP_WIPHY_ATTR_OPCLASS])
        radio->opclass = (uint8_t)blobmsg_get_u32(tb[MAP_WIPHY_ATTR_OPCLASS]);

    if (tb[MAP_WIPHY_ATTR_CHANNEL])
    {
        radio->chan = (uint8_t)blobmsg_get_u32(tb[MAP_WIPHY_ATTR_CHANNEL]);
        if (radio->chan <= 14)
            radio->band_supported = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
        else
            radio->band_supported = IEEE80211_FREQUENCY_BAND_5_GHZ;
        mapTryReportOperatingChannel(radio);
    }

    if (tb[MAP_WIPHY_ATTR_PS_STATE])
        radio->powerSaved = (uint8_t)blobmsg_get_u32(tb[MAP_WIPHY_ATTR_PS_STATE]);

    if (tb[MAP_WIPHY_ATTR_TXPOWER])
        radio->txpower = (uint8_t)blobmsg_get_u32(tb[MAP_WIPHY_ATTR_TXPOWER]);

    if (tb[MAP_WIPHY_ATTR_FEATURES])
        qdock_update_wiphy_feature(radio, blobmsg_get_u32(tb[MAP_WIPHY_ATTR_FEATURES]));

    qdock_visit_attrs(tb[MAP_WIPHY_ATTR_LIMITS], qdock_update_wiphy_limit, radio);
    qdock_visit_attrs(tb[MAP_WIPHY_ATTR_OPCLASSES], qdock_update_wiphy_opclass, radio);
    if (tb[MAP_WIPHY_ATTR_OPCLASSES])
        mapTryReportChannelPreference(radio);
}

static inline uint32_t qdock_iftype_to_role(uint32_t iftype)
{
    if (MAP_IFTYPE_AP == iftype)
        return interface_wifi_role_ap;
    if (MAP_IFTYPE_STATION == iftype)
        return interface_wifi_role_sta;
    return interface_wifi_role_other;
}

static void qdock_update_wdev(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_WDEV_ATTRS];
    bool wdev_created = false;
    const char *wdev_name = NULL;
    mac_address wdev_id;
    mac_address bssid;
    struct interfaceWifi *ifw;
    struct radio *r;
    int ssid_len;
    struct ieee80211_ie_htcap htcap_ie;
    struct ieee80211_ie_vhtcap vhtcap_ie;
    uint8_t hecap_ie[IEEE80211_HECAP_MAXLEN];

    blobmsg_parse(qdock_map_wdev_policy, NUM_MAP_WDEV_ATTRS, tb, data, len);

    if (blobmsg_get_macaddr(tb[MAP_WDEV_ATTR_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id found in wdev updated event attrs\n");
        return;
    }

    ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ifw)
    {
        mac_address wiphy_id;

        PLATFORM_PRINTF_DEBUG_DETAIL("try to add new wdev " MACFMT "\n", MACARG(wdev_id));

        if (blobmsg_get_macaddr(tb[MAP_WDEV_ATTR_WIPHY_ID], wiphy_id) < 0)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("try create wdev " MACFMT
                    ", but wiphy id not existed in attrs\n", MACARG(wdev_id));
            return;
        }

        r = findDeviceRadio(local_device, wiphy_id);
        if (!r)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("try create wdev " MACFMT
                    ", but wiphy " MACFMT " is created\n", MACARG(wdev_id), MACARG(wiphy_id));
            return;
        }

        ifw = radioAddLocalInterfaceWifi(r, wdev_id);
        if (!ifw)
            return;
        wdev_created = true;
    }

    r = ifw->radio;

    if (tb[MAP_WDEV_ATTR_NAME])
        wdev_name = blobmsg_get_string(tb[MAP_WDEV_ATTR_NAME]);
    if (wdev_name && (!ifw->i.name || strcmp(wdev_name, ifw->i.name)))
    {
        if (ifw->i.name)
            free((void *)ifw->i.name);
        ifw->i.name = strdup(wdev_name);
        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Recv thread* interface->interface.name = %s\n", wdev_name);
        if (isQtnWifiDevice(wdev_name))
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] *Recv thread* ni_interface_name = %s\n", ni_interface_name);
            ifw->i.interface_index = getIfIndex(ni_interface_name);
        }
        else
            ifw->i.interface_index = getIfIndex(wdev_name);
    }

    if (tb[MAP_WDEV_ATTR_IFTYPE_1905])
        ifw->i.media_type = blobmsg_get_u32(tb[MAP_WDEV_ATTR_IFTYPE_1905]);

    if (tb[MAP_WDEV_ATTR_IFTYPE])
        ifw->role = qdock_iftype_to_role(blobmsg_get_u32(tb[MAP_WDEV_ATTR_IFTYPE]));

    if (blobmsg_get_macaddr(tb[MAP_WDEV_ATTR_BSSID], bssid) >= 0
            && ifw->role == interface_wifi_role_ap)
        memcpy(ifw->bssInfo.bssid, bssid, MAP_MAC_ADDR_LEN);

    ssid_len = blobmsg_get_binary(tb[MAP_WDEV_ATTR_SSID], ifw->bssInfo.ssid.ssid, 0, SSID_MAX_LEN);
    if (ssid_len > 0)
        ifw->bssInfo.ssid.length = (uint8_t)ssid_len;

    blobmsg_get_binary(tb[MAP_WDEV_ATTR_HT_CAPA],
            (uint8_t *)(&htcap_ie), IEEE80211_HTCAP_LEN, IEEE80211_HTCAP_LEN);
    mapBuildAPHTCapabilitiesValue(&r->ht_capa, (uint8_t *)&htcap_ie);

    blobmsg_get_binary(tb[MAP_WDEV_ATTR_VHT_CAPA],
            (uint8_t *)(&vhtcap_ie), IEEE80211_VHTCAP_LEN, IEEE80211_VHTCAP_LEN);
    mapBuildAPVHTCapabilitiesValue(&r->vht_capa, (uint8_t *)&vhtcap_ie);

    blobmsg_get_binary(tb[MAP_WDEV_ATTR_HE_CAPA],
            hecap_ie, IEEE80211_HECAP_MINLEN, IEEE80211_HECAP_MAXLEN);
    mapBuildAPHECapabilitiesValue(&r->he_capa, hecap_ie);

    if (tb[MAP_WDEV_ATTR_BINTVL])
        ifw->bssInfo.bintval = (uint16_t)blobmsg_get_u32(tb[MAP_WDEV_ATTR_BINTVL]);

    if (tb[MAP_WDEV_ATTR_STATUS])
    {
        uint32_t status = blobmsg_get_u32(tb[MAP_WDEV_ATTR_STATUS]);
        if (status && (wdev_created || ifw->i.power_state == interface_power_state_off))
        {
            ifw->i.power_state = interface_power_state_on;
            qdock_handle_wifi_interface_status_changed(ifw, interface_power_state_on);
        }
        else if (!status && (wdev_created || ifw->i.power_state != interface_power_state_off))
        {
            ifw->i.power_state = interface_power_state_off;
            qdock_handle_wifi_interface_status_changed(ifw, interface_power_state_off);
        }
    }

    if (wdev_created) {
        qdock_handle_wifi_interface_created(ifw);
    }
}

struct station_update_context
{
    struct interfaceWifi *ifw;
    struct staInfo *client;
};

static void qdock_update_station(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_STATION_ATTRS];
    struct station_update_context *context = (struct station_update_context *)ctx;
    struct interfaceWifi *ifw = context->ifw;
    struct staInfo *sta;
    mac_address mac;
    uint8_t *frame;
    uint32_t frame_len = 0;

    blobmsg_parse(qdock_map_station_policy,
            NUM_MAP_STATION_ATTRS, tb, data, len);

    if (blobmsg_get_macaddr(tb[MAP_STATION_ATTR_MAC], mac) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no sta mac found in attrs\n");
        return;
    }

    sta = interfaceFindOrAddStation(ifw, mac);
    if (!sta)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("sta " MACFMT "can not added into datamodel\n", MACARG(mac));
        return;
    }

    context->client = sta;
    if (tb[MAP_STATION_ATTR_ASSOC_REQ])
    {
        frame = blobmsg_data(tb[MAP_STATION_ATTR_ASSOC_REQ]);
        frame_len = blobmsg_data_len(tb[MAP_STATION_ATTR_ASSOC_REQ]);
    }
    if (frame_len)
        updateAssocFrame(sta, frame, frame_len);

    if (tb[MAP_STATION_ATTR_AGE])
        sta->last_assoc_ts = PLATFORM_GET_TIMESTAMP() - blobmsg_get_u32(tb[MAP_STATION_ATTR_AGE]);
}

static void qdock_update_monitor_stats(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_STATION_ATTRS];
    struct radio *r = (struct radio *)ctx;
    mac_address mac;
    struct radioUnassocSta *sta;

    blobmsg_parse(qdock_map_station_policy,
            NUM_MAP_STATION_ATTRS, tb, data, len);

    if (blobmsg_get_macaddr(tb[MAP_STATION_ATTR_MAC], mac) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no sta mac found in attrs\n");
        return;
    }

    sta = radioFindOrAddUnassocSta(r, mac);
    if (!sta)
        return;

    if (tb[MAP_STATION_ATTR_OPCLASS])
        sta->opclass = (uint8_t)blobmsg_get_u32(tb[MAP_STATION_ATTR_OPCLASS]);

    if (tb[MAP_STATION_ATTR_CHANNEL])
        sta->channel = (uint8_t)blobmsg_get_u32(tb[MAP_STATION_ATTR_CHANNEL]);

    if (tb[MAP_STATION_ATTR_RSSI])
        sta->rcpi = mapPowerLevel2RCPI((int)blobmsg_get_u32(tb[MAP_STATION_ATTR_RSSI]));

    if (tb[MAP_STATION_ATTR_AGE])
        sta->last_ts = PLATFORM_GET_TIMESTAMP() - blobmsg_get_u32(tb[MAP_STATION_ATTR_AGE]);
}

static void qdock_register_map_bssconfig(struct _qdockBssCfg *cfg)
{
    struct wscRegistrarInfo *wsc_info;

    wsc_info = zmemalloc(sizeof(struct wscRegistrarInfo));

    memcpy(&wsc_info->bss_info.ssid, &cfg->ssid, sizeof(struct ssid));

    wsc_info->bss_info.auth_mode = cfg->auth_mode;
    copyKey(&wsc_info->bss_info.key, &cfg->key);
    wsc_info->bss_info.fronthaul = cfg->fronthaul;
    wsc_info->bss_info.backhaul = cfg->backhaul;
    wsc_info->rf_bands = cfg->rf_bands;

    PLATFORM_PRINTF_DEBUG_DETAIL("register wsc ssid(%s) auth(%d) key(%s) fbss(%d)/bbss(%d) band(0x%x)\n",
            wsc_info->bss_info.ssid.ssid, wsc_info->bss_info.auth_mode,
            wsc_info->bss_info.key.key, wsc_info->bss_info.fronthaul,
            wsc_info->bss_info.backhaul, wsc_info->rf_bands);

    strcpy(wsc_info->device_data.manufacturer_name, map_config.wsc_data.manufacturer_name);
    strcpy(wsc_info->device_data.device_name, map_config.wsc_data.device_name);
    strcpy(wsc_info->device_data.model_name, map_config.wsc_data.model_name);
    strcpy(wsc_info->device_data.model_number, map_config.wsc_data.model_number);
    strcpy(wsc_info->device_data.serial_number, map_config.wsc_data.serial_number);
    memcpy(wsc_info->device_data.uuid, map_config.wsc_data.uuid, 16);

    if (!WSCINFO_FLAG_IS_SET(registrarUpdateWsc(wsc_info), NEW_CREATED))
        free(wsc_info);
}

static void qdock_update_interface_wifi(struct _qdockBssCfg *cfg)
{
    struct radio *radio;
    dlist_for_each(radio, local_device->radios, l)
    {
        struct interfaceWifi *ifw = NULL;

        if (!(cfg->rf_bands & (1<<radio->band_supported)))
            continue;

        ifw = radioFindInterfaceWifiBySSID(radio, &cfg->ssid);
        if (ifw)
        {
            bool bh_only;
            bool mtype_changed = false;

            ifw->bssInfo.auth_mode = cfg->auth_mode;
            copyKey(&ifw->bssInfo.key, &cfg->key);
            if (ifw->bssInfo.fronthaul != cfg->fronthaul)
            {
                ifw->bssInfo.fronthaul = cfg->fronthaul;
                mtype_changed = true;
            }
            if (ifw->bssInfo.backhaul != cfg->backhaul)
            {
                ifw->bssInfo.backhaul = cfg->backhaul;
                mtype_changed = true;
            }

            if (registrarIsLocal() || mtype_changed)
            {
                bh_only = (ifw->bssInfo.backhaul && !ifw->bssInfo.fronthaul) ? 1 : 0;
                qdock_conf_wps(ifw->i.addr, bh_only ? 0 : 1);
            }
        }

        if (cfg->backhaul)
        {
            localRadioUpdateBackhaulSsid(radio, &cfg->ssid, &cfg->key, !cfg->fronthaul);
        }
    }
}

static void qdock_update_bsscfg(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_WDEV_ATTRS];
    rc = MAP_RC_OK;
    int ssid_len = 0;
    int key_len = 0;
    uint8_t map_auth_value = 0;
    uint8_t map_mtypes = 0;
    struct _qdockBssCfg bss_cfg;

    memset(&bss_cfg, 0 , sizeof(bss_cfg));

    blobmsg_parse(qdock_map_wdev_policy, NUM_MAP_WDEV_ATTRS, tb, data, len);

    if (!tb[MAP_WDEV_ATTR_NAME] ||
        !tb[MAP_WDEV_ATTR_BSSID] ||
        !tb[MAP_WDEV_ATTR_SSID] ||
        !tb[MAP_WDEV_ATTR_RF_BANDS] ||
        !tb[MAP_WDEV_ATTR_AUTH])
    {
        PLATFORM_PRINTF_DEBUG_ERROR("parse mandatory wdev attr failed, "
                "name(%p) bssid(%p) ssid(%p) rf_bands(%p) auth(%p)\n",
                tb[MAP_WDEV_ATTR_NAME], tb[MAP_WDEV_ATTR_BSSID], tb[MAP_WDEV_ATTR_SSID],
                tb[MAP_WDEV_ATTR_RF_BANDS], tb[MAP_WDEV_ATTR_AUTH]);
        goto parse_err;
    }

    if (blobmsg_get_macaddr(tb[MAP_WDEV_ATTR_BSSID], bss_cfg.bssid) < 0)
        goto parse_err;

    strncpy(bss_cfg.ifname, blobmsg_get_string(tb[MAP_WDEV_ATTR_NAME]), IFNAMSIZ - 1);

    bss_cfg.rf_bands = blobmsg_get_u32(tb[MAP_WDEV_ATTR_RF_BANDS]);

    ssid_len = blobmsg_get_binary(tb[MAP_WDEV_ATTR_SSID], bss_cfg.ssid.ssid, 0, SSID_MAX_LEN);
    if (ssid_len < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("parse wdev attr ssid len failed\n");
        goto parse_err;
    }
    bss_cfg.ssid.length = (uint8_t)ssid_len;

    if (tb[MAP_WDEV_ATTR_MAP_MTYPES])
    {
        map_mtypes = (uint8_t)blobmsg_get_u32(tb[MAP_WDEV_ATTR_MAP_MTYPES]);
        if (map_mtypes & MAP_MTYPE_BACKHAUL_BSS)
            bss_cfg.backhaul = true;
        if (map_mtypes & MAP_MTYPE_FRONTHAUL_BSS)
            bss_cfg.fronthaul = true;
    }
    // Work around for those radios/interfaces don't support MAP. (e.g. BBIC4 2.4G)
    else
    {
        struct interfaceWifi *ifw = findLocalWifiInterface(bss_cfg.bssid, interface_wifi_role_ap);
        if (ifw)
        {
            bss_cfg.backhaul = ifw->bssInfo.backhaul;
            bss_cfg.fronthaul = ifw->bssInfo.fronthaul;
        }
    }

    map_auth_value = blobmsg_get_u32(tb[MAP_WDEV_ATTR_AUTH]);
    // Check configuration's auth mode valid for controller
    if (registrarIsLocal())
    {
        if (!(map_auth_value & (MAP_AUTH_WPA2PSK | MAP_AUTH_OPEN)))
        {
            PLATFORM_PRINTF_DEBUG_WARNING("get a BSS configuration which auth mode(0x%x)"
                    " is not supported by MAP controller, ignore it!\n", map_auth_value);
            goto parse_err;
        }
    }
    // enum map_auth is the same define with enum auth_mode
    bss_cfg.auth_mode = map_auth_value;

    if (map_auth_value != MAP_AUTH_OPEN)
    {
        if (!tb[MAP_WDEV_ATTR_KEY])
        {
            PLATFORM_PRINTF_DEBUG_ERROR("parse wdev attr key failed\n");
            // Work around for those key_mgmt error or don't supported
            bss_cfg.auth_mode = MAP_AUTH_OPEN;
            goto do_reg_cfg;
        }
        key_len = blobmsg_get_binary(tb[MAP_WDEV_ATTR_KEY], bss_cfg.key.key, 8, 64);
        if (key_len < 0)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("parse wdev attr key len failed\n");
            // Work around for those key_mgmt error or don't supported
            bss_cfg.auth_mode = MAP_AUTH_OPEN;
            goto do_reg_cfg;
        }
        bss_cfg.key.len = (uint8_t)key_len;
    }

do_reg_cfg:

    qdock_register_map_bssconfig(&bss_cfg);
    qdock_update_interface_wifi(&bss_cfg);

    PLATFORM_PRINTF_DEBUG_INFO("driver bss cfgs updated\n");
    return;

parse_err:
    rc = MAP_RC_UNKNOWN_ERROR;
    PLATFORM_PRINTF_DEBUG_ERROR("drop unexpect bsscfg\n");
}

static void qdock_check_rc_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];

    rc = MAP_RC_UNKNOWN_ERROR;

    if (!msg) {
        PLATFORM_PRINTF_DEBUG_ERROR("attr is null\n");
        return;
    }

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));
    if (qdock_check_response_code(tb[MAP_ATTR_RC]))
    {
        char * method = req->priv;
        PLATFORM_PRINTF_DEBUG_ERROR("method [%s] failed, reason=%u\n",
                                (method ? method : ""), rc);
    }
}

static void qdock_get_wiphys_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    rc = MAP_RC_UNKNOWN_ERROR;

    QDOCK_BLOGMSG_DUMP("get_wiphys", msg);

    if (!msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("msg paramter is null\n");
        return;
    }

    /*
     *get all radios info here
    */
    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (MAP_RC_OK != qdock_check_response_code(tb[MAP_ATTR_RC]))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("get wiphys command return failed: %d\n", rc);
        return;
    }

    qdock_visit_attrs(tb[MAP_ATTR_WIPHYS], qdock_update_wiphy, NULL);
}

static void qdock_get_wdevs_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    rc = MAP_RC_UNKNOWN_ERROR;
    struct blob_attr *clone_msg;

    QDOCK_BLOGMSG_DUMP("get_wdevs", msg);

    if (!msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("msg paramter is null\n");
        return;
    }

    clone_msg = memalloc(blob_pad_len(msg));
    if (!clone_msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("out of memory\n");
        return;
    }
    memcpy(clone_msg, msg, blob_pad_len(msg));

    /*
     *get all interfaces info here
    */
    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(clone_msg), blob_len(clone_msg));

    if (MAP_RC_OK != qdock_check_response_code(tb[MAP_ATTR_RC]))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("get wdevs command return failed: %d\n", rc);
        goto rc_code_err;
    }

    qdock_visit_attrs(tb[MAP_ATTR_WDEVS], qdock_update_wdev, NULL);
rc_code_err:
    free(clone_msg);
}

static void qdock_get_stations_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    mac_address wdev_id;
    rc = MAP_RC_UNKNOWN_ERROR;
    struct station_update_context ctx;

    QDOCK_BLOGMSG_DUMP("get_stations", msg);

    if (!msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("msg paramter is null\n");
        return;
    }

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (MAP_RC_OK != qdock_check_response_code(tb[MAP_ATTR_RC]))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("get stations command return failed: %d\n", rc);
        return;
    }

    if (blobmsg_get_macaddr(tb[MAP_ATTR_WDEV_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("get stations command return failed: do not include the wdev id\n");
        return;
    }

    ctx.ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ctx.ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    qdock_visit_attrs(tb[MAP_ATTR_STATIONS], qdock_update_station, &ctx);
}

static void qdock_get_monitor_stats_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    mac_address wiphy_id;
    struct radio *r;
    rc = MAP_RC_UNKNOWN_ERROR;

    QDOCK_BLOGMSG_DUMP("get_monitor_stats", msg);

    if (!msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("msg paramter is null\n");
        return;
    }

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (MAP_RC_OK != qdock_check_response_code(tb[MAP_ATTR_RC]))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("get monitor stats command return failed: %d\n", rc);
        return;
    }

    if (blobmsg_get_macaddr(tb[MAP_ATTR_WIPHY_ID], wiphy_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("get monitor stats command return failed: do not include the wiphy id\n");
        return;
    }

    r = findDeviceRadio(local_device, wiphy_id);
    if (!r)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find radio for " MACFMT "\n", MACARG(wiphy_id));
        return;
    }

    qdock_visit_attrs(tb[MAP_ATTR_STATIONS], qdock_update_monitor_stats, r);
}

static void qdock_get_created_info_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	char *ifname = (char *)req->priv;
    struct blob_attr *tb[NUM_MAP_WDEV_ATTRS];
    rc = MAP_RC_OK;

    blobmsg_parse(qdock_map_wdev_policy, NUM_MAP_WDEV_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (!tb[MAP_WDEV_ATTR_NAME])
    {
        ifname[0] = '\0';
        rc = MAP_RC_UNKNOWN_ERROR;
    } else
    {
        strncpy(ifname, blobmsg_get_string(tb[MAP_WDEV_ATTR_NAME]), IFNAMSIZ - 1);
    }

    PLATFORM_PRINTF_DEBUG_INFO("interface %s created\n", ifname);
}

static void qdock_get_bsscfgs_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    rc = MAP_RC_UNKNOWN_ERROR;
    struct blob_attr *clone_msg;

    QDOCK_BLOGMSG_DUMP("get_bsscfgs", msg);

    PLATFORM_PRINTF_DEBUG_INFO("qdock_get_bsscfgs_cb\n");
    if (!msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("msg paramter is null\n");
        return;
    }

    clone_msg = memalloc(blob_pad_len(msg));
    if (!clone_msg)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("out of memory\n");
        return;
    }
    memcpy(clone_msg, msg, blob_pad_len(msg));

    /*
     *get all bsscfgs here
    */
    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(clone_msg), blob_len(clone_msg));

    if (MAP_RC_OK != qdock_check_response_code(tb[MAP_ATTR_RC]))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("get_bsscfgs command return failed: %d\n", rc);
        goto rc_code_err;
    }

    qdock_visit_attrs(tb[MAP_ATTR_WDEVS], qdock_update_bsscfg, NULL);
rc_code_err:
    free(clone_msg);
}

static void qdock_get_devdata_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_WDEV_ATTRS];
    rc = MAP_RC_OK;

    blobmsg_parse(qdock_map_devdata_policy, NUM_MAP_DEVDATA_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (tb[MAP_DEVDATA_ATTR_DEVICE_NAME])
        strncpy(map_config.wsc_data.device_name, blobmsg_get_string(tb[MAP_DEVDATA_ATTR_DEVICE_NAME]), 33-1);

    if (tb[MAP_DEVDATA_ATTR_MANUFACTURER_NAME])
        strncpy(map_config.wsc_data.manufacturer_name, blobmsg_get_string(tb[MAP_DEVDATA_ATTR_MANUFACTURER_NAME]), 65-1);

    if (tb[MAP_DEVDATA_ATTR_MODEL_NAME])
        strncpy(map_config.wsc_data.model_name, blobmsg_get_string(tb[MAP_DEVDATA_ATTR_MODEL_NAME]), 65-1);

    if (tb[MAP_DEVDATA_ATTR_MODEL_NUMBER])
        strncpy(map_config.wsc_data.model_number, blobmsg_get_string(tb[MAP_DEVDATA_ATTR_MODEL_NUMBER]), 65-1);

    if (tb[MAP_DEVDATA_ATTR_SERIAL_NUMBER])
        strncpy(map_config.wsc_data.serial_number, blobmsg_get_string(tb[MAP_DEVDATA_ATTR_SERIAL_NUMBER]), 65-1);

    PLATFORM_PRINTF_DEBUG_INFO("device data info updated\n");
}

static int qdock_get_wiphys(const uint8_t *wiphy_id)
{
    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WIPHY_ID_NAME, wiphy_id);

    return qdock_ubus_invoke(MAP_METHOD_GET_WIPHYS_NAME, qdock_get_wiphys_cb, NULL);
}

static int qdock_get_wdevs(const uint8_t *wiphy_id, const uint8_t *wdev_id)
{
    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WIPHY_ID_NAME, wiphy_id);
    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);

    return qdock_ubus_invoke(MAP_METHOD_GET_WDEVS_NAME, qdock_get_wdevs_cb, NULL);
}

static int qdock_config_wiphy(const uint8_t *wiphy_id, struct radioConfigInfo *cfg, uint32_t flags)
{
    if (!wiphy_id || !cfg || !flags)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_WIPHY_ATTR_ID_NAME, wiphy_id);

#define wiphy_blobmsg_check_and_add_u32(_attr, _val)    if (flags & RADIO_CONFIG_FLAG_##_attr)  \
        blobmsg_add_u32(&b, MAP_WIPHY_ATTR_##_attr##_NAME, _val)
    wiphy_blobmsg_check_and_add_u32(OPCLASS, cfg->opclass);
    wiphy_blobmsg_check_and_add_u32(CHAN, cfg->chan);
    wiphy_blobmsg_check_and_add_u32(TXPOWER, cfg->power);
    wiphy_blobmsg_check_and_add_u32(TEAR_DOWN, cfg->tear_down);
#undef wiphy_blobmsg_check_and_add_u32

    return qdock_ubus_invoke(MAP_METHOD_CONFIG_WIPHY_NAME, qdock_check_rc_cb, MAP_METHOD_CONFIG_WIPHY_NAME);
}

static int qdock_teardown_wiphy(const uint8_t *wiphy_id)
{
    struct radioConfigInfo cfg;

    cfg.tear_down = true;
    return qdock_config_wiphy(wiphy_id, &cfg, RADIO_CONFIG_FLAG_TEAR_DOWN);
}

static int qdock_create_wdev(const uint8_t *wiphy_id, struct bssInfo *bss_info, bool ap_mode, char *ifname)
{
    enum map_auth auth = MAP_AUTH_OPEN;
    enum map_encryp encrpy = MAP_ENCRYP_NONE;
    uint32_t mtype = 0, mode = MAP_IFTYPE_AP, enable_4addr = 0, hide_ssid = 0;

    if (!wiphy_id || !bss_info)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_WDEV_ATTR_WIPHY_ID_NAME, wiphy_id);

    blobmsg_add_binary(&b, MAP_WDEV_ATTR_SSID_NAME,
                    bss_info->ssid.ssid, bss_info->ssid.length);
    switch (bss_info->auth_mode) {
        case auth_mode_wpa2:
            PLATFORM_PRINTF_DEBUG_ERROR("Encryption type WPA2-Enterprise not supported\n");
            return -1;
        case auth_mode_wpa2psk:
            auth = MAP_AUTH_WPA2PSK;
            encrpy = MAP_ENCRYP_CCMP;
            break;
        default:
            PLATFORM_PRINTF_DEBUG_ERROR("Encryption type not supported\n");
            break;
    }
    blobmsg_add_u32(&b, MAP_WDEV_ATTR_AUTH_NAME, auth);
    blobmsg_add_u32(&b, MAP_WDEV_ATTR_ENCRYP_NAME, encrpy);

    if (encrpy != MAP_ENCRYP_NONE)
        blobmsg_add_binary(&b, MAP_WDEV_ATTR_KEY_NAME, bss_info->key.key, bss_info->key.len);

    if (!ap_mode)
    {
        mtype = MAP_MTYPE_BACKHAUL_STA;
        mode = MAP_IFTYPE_STATION;
        enable_4addr = 1;
    }
    else
    {
        bool bh_only = false;
        if (bss_info->backhaul)
        {
            mtype |= MAP_MTYPE_BACKHAUL_BSS;
            enable_4addr = 1;
            bh_only = true;
        }
        if (bss_info->fronthaul)
        {
            mtype |= MAP_MTYPE_FRONTHAUL_BSS;
            bh_only = false;
        }

        if (map_config.hide_backhaul_ssid && bh_only)
            hide_ssid = 1;

        blobmsg_add_u32(&b, MAP_WDEV_ATTR_HIDE_NAME, hide_ssid);
        blobmsg_add_u32(&b, MAP_WDEV_ATTR_WPS_NAME, bh_only ? 0 : 1);
    }
    blobmsg_add_u32(&b, MAP_WDEV_ATTR_MODE_NAME, mode);
    blobmsg_add_u32(&b, MAP_WDEV_ATTR_MAP_MTYPES_NAME, mtype);
    blobmsg_add_u32(&b, MAP_WDEV_ATTR_4ADDR_NAME, enable_4addr);

    return qdock_ubus_invoke(MAP_METHOD_CREATE_WDEV_NAME, qdock_get_created_info_cb, ifname);
}

static int qdock_delete_wdev(const uint8_t *wdev_id)
{
    if (!wdev_id)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_WDEV_ATTR_ID_NAME, wdev_id);

    return qdock_ubus_invoke(MAP_METHOD_DELETE_WDEV_NAME, qdock_check_rc_cb, MAP_METHOD_DELETE_WDEV_NAME);
}

static void qdock_append_backhaul_cfg(struct intfwifiConfigInfo *cfg)
{
    void *table = blobmsg_open_table(&b, MAP_WDEV_ATTR_BACKHAUL_NAME);

    blobmsg_add_binary(&b, MAP_WDEV_ATTR_SSID_NAME, cfg->bh_ssid.ssid, cfg->bh_ssid.length);
    blobmsg_add_u32(&b, MAP_WDEV_ATTR_AUTH_NAME, cfg->bh_auth);
    blobmsg_add_u32(&b, MAP_WDEV_ATTR_ENCRYP_NAME, cfg->bh_encryp);
    blobmsg_add_binary(&b, MAP_WDEV_ATTR_KEY_NAME, cfg->bh_key.key, cfg->bh_key.len);

    blobmsg_close_table(&b, table);
}

static void qdock_clear_backhaul_cfg(void)
{
    void *table = blobmsg_open_table(&b, MAP_WDEV_ATTR_BACKHAUL_NAME);
    blobmsg_close_table(&b, table);
}

static void qdock_append_extcap(struct intfwifiConfigInfo *cfg)
{
    uint8_t *extcap = (uint8_t *)malloc(cfg->extcap_len * 2);

    memcpy(extcap, cfg->extcap, cfg->extcap_len);
    memcpy(extcap + cfg->extcap_len, cfg->extcap_mask, cfg->extcap_len);

    blobmsg_add_binary(&b, MAP_WDEV_ATTR_EXTCAP_NAME, extcap, cfg->extcap_len * 2);

    free(extcap);
}

static void qdock_append_appies(struct intfwifiConfigInfo *cfg)
{
    void *list = blobmsg_open_array(&b, MAP_WDEV_ATTR_IES_NAME);
    void *table = blobmsg_open_table(&b, NULL);

    blobmsg_add_u32(&b, MAP_IE_ATTR_FRAME_MASK_NAME, cfg->ies_mask);
    blobmsg_add_binary(&b, MAP_IE_ATTR_VALUE_NAME, cfg->ies, cfg->ies_len);

    blobmsg_close_table(&b, table);
    blobmsg_close_array(&b, list);
}

static int qdock_config_wdev(uint8_t *wdev_id, struct intfwifiConfigInfo *cfg, uint32_t flags)
{
    if (!wdev_id || !cfg || !flags)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_WDEV_ATTR_ID_NAME, wdev_id);

    if (flags & INTWIFI_CONFIG_FLAG_SSID)
        blobmsg_add_binary(&b, MAP_WDEV_ATTR_SSID_NAME, cfg->ssid.ssid, cfg->ssid.length);
    if (flags & INTWIFI_CONFIG_FLAG_KEY)
        blobmsg_add_binary(&b, MAP_WDEV_ATTR_KEY_NAME, cfg->key.key, cfg->key.len);

#define wdev_blobmsg_check_and_add_u32(_attr, _val)    if (flags & INTWIFI_CONFIG_FLAG_##_attr)  \
        blobmsg_add_u32(&b, MAP_WDEV_ATTR_##_attr##_NAME, _val)
    wdev_blobmsg_check_and_add_u32(AUTH, cfg->auth);
    wdev_blobmsg_check_and_add_u32(ENCRYP, cfg->encryp);
    wdev_blobmsg_check_and_add_u32(OPCLASS, cfg->opclass);
    wdev_blobmsg_check_and_add_u32(CHAN, cfg->chan);
    wdev_blobmsg_check_and_add_u32(DISABLE, cfg->disable);
    wdev_blobmsg_check_and_add_u32(WPS, cfg->wps);
    wdev_blobmsg_check_and_add_u32(4ADDR, cfg->enable_4addr);
#undef wdev_blobmsg_check_and_add_u32

    if (flags & INTWIFI_CONFIG_FLAG_BH_CFG)
        qdock_append_backhaul_cfg(cfg);

    if (flags & INTWIFI_CONFIG_FLAG_EXTCAP)
        qdock_append_extcap(cfg);

    if (flags & INTWIFI_CONFIG_FLAG_APPIES)
        qdock_append_appies(cfg);

    if (flags & INTWIFI_CONFIG_FLAG_BH_CLR)
        qdock_clear_backhaul_cfg();

    return qdock_ubus_invoke(MAP_METHOD_CONFIG_WDEV_NAME, qdock_check_rc_cb, MAP_METHOD_CONFIG_WDEV_NAME);
}

static int qdock_start_wps(const uint8_t *wdev_id)
{
    if (!wdev_id)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);

    return qdock_ubus_invoke(MAP_METHOD_START_WPS_NAME, qdock_check_rc_cb, MAP_METHOD_START_WPS_NAME);
}

static int qdock_get_stations(const uint8_t *wdev_id, const uint8_t *sta_mac)
{
    if (!wdev_id)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);
    blobmsg_add_macaddr(&b, MAP_ATTR_STA_MAC_NAME, sta_mac);

    return qdock_ubus_invoke(MAP_METHOD_GET_STATIONS_NAME, qdock_get_stations_cb, NULL);
}

static int qdock_set_periods(const uint8_t *wdev_id, uint32_t wdev_period, uint32_t sta_period, uint32_t mon_period)
{
    void *table;

    if (!wdev_id)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);

    table = blobmsg_open_table(&b, MAP_ATTR_STATS_PERIODS_NAME);
    if (wdev_period != INVALID_REPORT_PERIOD)
        blobmsg_add_u32(&b, MAP_STATS_ATTR_WDEV_NAME, wdev_period);
    if (sta_period != INVALID_REPORT_PERIOD)
        blobmsg_add_u32(&b, MAP_STATS_ATTR_STA_NAME, sta_period);
    if (mon_period != INVALID_REPORT_PERIOD)
        blobmsg_add_u32(&b, MAP_STATS_ATTR_MONITOR_NAME, mon_period);
    blobmsg_close_table(&b, table);

    return qdock_ubus_invoke(MAP_METHOD_SET_PERIODS_NAME, qdock_check_rc_cb, MAP_METHOD_SET_PERIODS_NAME);
}

static int qdock_get_monitor_stats(const uint8_t *wiphy_id, uint8_t *stas, uint32_t nums)
{
    if (!wiphy_id)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WIPHY_ID_NAME, wiphy_id);
    if (stas && nums)
    {
        uint32_t i;
        void *list = blobmsg_open_array(&b, MAP_ATTR_STATIONS_NAME);

        for (i = 0; i < nums; i++)
            blobmsg_add_macaddr(&b, MAP_STATION_ATTR_MAC_NAME, stas + sizeof(mac_address) * i);

        blobmsg_close_array(&b, list);
    }

    return qdock_ubus_invoke(MAP_METHOD_GET_MONITOR_STATS_NAME, qdock_get_monitor_stats_cb, NULL);
}

static int qdock_reg_frame(const uint8_t *wdev_id,
        uint32_t subtype, const uint8_t *match,
        uint32_t match_len, bool rx, uint8_t rx_mode)
{
    if (!wdev_id)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);
    if (rx)
        blobmsg_add_u32(&b, MAP_ATTR_FRAME_RX_NAME, rx_mode);
    blobmsg_add_u32(&b, MAP_ATTR_MGMT_SUBTYPE_NAME, subtype);
    blobmsg_add_binary(&b, MAP_ATTR_FRAME_MATCH_NAME, match, match_len);

    return qdock_ubus_invoke(MAP_METHOD_REG_FRAME_NAME, qdock_check_rc_cb, MAP_METHOD_REG_FRAME_NAME);
}

static int qdock_send_frame(const uint8_t *wdev_id, uint8_t *frame, uint32_t frame_len)
{
    if (!wdev_id || !frame || !frame_len)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);
    blobmsg_add_binary(&b, MAP_ATTR_FRAME_NAME, frame, frame_len);

    return qdock_ubus_invoke(MAP_METHOD_SEND_FRAME_NAME, qdock_check_rc_cb, MAP_METHOD_SEND_FRAME_NAME);
}

static int qdock_filter_station(const uint8_t *wdev_id, const uint8_t *sta_mac, bool block)
{
    void *table;

    if (!wdev_id || !sta_mac)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);
    blobmsg_add_macaddr(&b, MAP_ATTR_STA_MAC_NAME, sta_mac);

    table = blobmsg_open_table(&b, MAP_ATTR_FILTER_NAME);
    if (block)
    {
        uint32_t mask = (uint32_t)-1;
        blobmsg_add_u32(&b, MAP_FILTER_ATTR_MODE_NAME, MAP_FILTER_MODE_NONE);
        blobmsg_add_u32(&b, MAP_FILTER_ATTR_MASK_NAME, mask);
        blobmsg_add_u32(&b, MAP_FILTER_ATTR_DURATION_NAME, 0xffffffff);
        blobmsg_add_u32(&b, MAP_FILTER_ATTR_REJECT_NAME, 33);
    }
    else
    {
        blobmsg_add_u32(&b, MAP_FILTER_ATTR_DURATION_NAME, 0);
    }

    blobmsg_close_table(&b, table);

    return qdock_ubus_invoke(MAP_METHOD_FILTER_STATION_NAME, qdock_check_rc_cb, MAP_METHOD_FILTER_STATION_NAME);
}

static int qdock_del_station(const uint8_t *wdev_id, const uint8_t *sta_mac, uint16_t sub_type, uint16_t reason_code)
{
    if (!wdev_id || !sta_mac)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);
    blobmsg_add_macaddr(&b, MAP_ATTR_STA_MAC_NAME, sta_mac);
    blobmsg_add_u32(&b, MAP_ATTR_MGMT_SUBTYPE_NAME, sub_type);
    blobmsg_add_u32(&b, MAP_ATTR_REASON_NAME, reason_code);

    return qdock_ubus_invoke(MAP_METHOD_DEL_STATION_NAME, qdock_check_rc_cb, MAP_METHOD_DEL_STATION_NAME);
}

static int qdock_monitor_channel(const uint8_t *wiphy_id, uint8_t opclass, uint8_t channel)
{
    if (!wiphy_id)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_WIPHY_ATTR_ID_NAME, wiphy_id);
    blobmsg_add_u32(&b, MAP_WIPHY_ATTR_OPCLASS_NAME, opclass);
    blobmsg_add_u32(&b, MAP_WIPHY_ATTR_CHAN_NAME, channel);

    return qdock_ubus_invoke(MAP_METHOD_MONITOR_CHAN_NAME, qdock_check_rc_cb, MAP_METHOD_MONITOR_CHAN_NAME);
}

static int qdock_roam_wdev(const uint8_t *wdev_id, const uint8_t *target, uint8_t opclass, uint8_t channel)
{
    if (!wdev_id || !target)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("input parameters is invalid\n");
        return -1;
    }

    blob_buf_init(&b, 0);

    blobmsg_add_macaddr(&b, MAP_ATTR_WDEV_ID_NAME, wdev_id);
    blobmsg_add_macaddr(&b, MAP_ATTR_ROAM_TARGET_NAME, target);
    blobmsg_add_u32(&b, MAP_WIPHY_ATTR_OPCLASS_NAME, opclass);
    blobmsg_add_u32(&b, MAP_WIPHY_ATTR_CHAN_NAME, channel);

    return qdock_ubus_invoke(MAP_METHOD_ROAM_WDEV_NAME, qdock_check_rc_cb, MAP_METHOD_ROAM_WDEV_NAME);
}

static int qdock_get_bsscfgs(void)
{
    blob_buf_init(&b, 0);

    return qdock_ubus_invoke(MAP_METHOD_GET_BSSCFGS_NAME, qdock_get_bsscfgs_cb, NULL);
}

static int qdock_get_devdata(void)
{
    blob_buf_init(&b, 0);

    return qdock_ubus_invoke(MAP_METHOD_GET_DEVDATA_NAME, qdock_get_devdata_cb, NULL);
}

static inline void qdock_ops_tear_down(uint8_t *uid, uint8_t *wdev)
{
    if (!uid && !wdev)
        return;

    if (wdev)
        qdock_delete_wdev(wdev);
    else
        qdock_teardown_wiphy(uid);
}

static inline void qdock_ops_set_operating_channel(uint8_t *wiphy_id, uint8_t opclass, uint8_t channel, uint8_t txpower)
{
    struct radioConfigInfo cfg;
    uint32_t flags;

    cfg.opclass = opclass;
    cfg.chan = channel;
    cfg.power = txpower;
    flags = RADIO_CONFIG_FLAG_OPCLASS | RADIO_CONFIG_FLAG_CHAN | RADIO_CONFIG_FLAG_TXPOWER;
    qdock_config_wiphy(wiphy_id, &cfg, flags);
}

static inline void qdock_ops_monitor_channel(uint8_t *wiphy_id, uint8_t opclass, uint8_t channel)
{
    qdock_monitor_channel(wiphy_id, opclass, channel);
}

static inline void qdock_ops_start_wps(uint8_t *wdev_id)
{
    qdock_start_wps(wdev_id);
}

static inline void qdock_ops_get_monitor_stats(uint8_t *wiphy_id,
        uint8_t *stas, uint32_t nums)
{
    qdock_get_monitor_stats(wiphy_id, stas, nums);
}

static inline void qdock_ops_send_frame(uint8_t *wdev_id, uint8_t *frame, uint32_t frame_len)
{
    qdock_send_frame(wdev_id, frame, frame_len);
}

static inline void qdock_ops_deauth_sta(uint8_t *bssid, uint8_t *sta, uint16_t code)
{
    qdock_del_station(bssid, sta, IEEE80211_FC0_SUBTYPE_DEAUTH, code);
}

static inline void qdock_ops_roam_sta(uint8_t *sta, uint8_t *bssid, uint8_t opclass, uint8_t channel)
{
    qdock_roam_wdev(sta, bssid, opclass, channel);
}

static inline void qdock_ops_filter_client(uint8_t *bssid, uint8_t *client, bool block)
{
    qdock_filter_station(bssid, client, block);
}

static inline void qdock_ops_set_report_period(uint8_t *bssid,
        uint32_t wdev_period, uint32_t sta_period, uint32_t mon_period)
{
    qdock_set_periods(bssid, wdev_period, sta_period, mon_period);
}

static inline void qdock_ops_register_mgmt_frame(uint8_t *bssid,
        struct frame_match *frame, bool rx)
{
    qdock_reg_frame(bssid, frame->subtype, frame->match, frame->match_len, rx, frame->rx_mode);
}

static inline void qdock_ops_conf_extcap(uint8_t *bssid, uint8_t *extcap, uint8_t *extcap_mask, uint32_t len)
{
    qdock_conf_extcap(bssid, extcap, extcap_mask, len);
}

static inline void qdock_ops_conf_appies(uint8_t *bssid, uint32_t mask, uint8_t *ies, uint32_t len)
{
    qdock_conf_appies(bssid, mask, ies, len);
}

static inline void qdock_ops_conf_4addr(uint8_t *bssid, bool enable)
{
    qdock_conf_4addr(bssid, enable);
}

static inline void qdock_ops_conf_security(uint8_t *bssid, uint8_t auth, struct key *key)
{
    qdock_conf_security(bssid, auth, key);
}

static inline void qdock_ops_reset_backhaul(struct interfaceWifi *ifw)
{
    qdock_reset_backhaul_info(ifw);
}

static inline void qdock_ops_set_backhaul(struct interfaceWifi *ifw)
{
    qdock_set_backhaul_info(ifw, &ifw->radio->backhaul_ssid,
            &ifw->radio->backhaul_key);
}

static struct radioHandles qdock_ops =
{
    .tearDown               = qdock_ops_tear_down,
    .setOperatingChannel    = qdock_ops_set_operating_channel,
    .monitorChannel         = qdock_ops_monitor_channel,
    .getMonitorStats        = qdock_ops_get_monitor_stats,
    .startWPS               = qdock_ops_start_wps,
    .sendFrame              = qdock_ops_send_frame,
    .deauthClient           = qdock_ops_deauth_sta,
    .roamSta                = qdock_ops_roam_sta,
    .filterClient           = qdock_ops_filter_client,
    .setReportPeriod        = qdock_ops_set_report_period,
    .registerMgmtFrame      = qdock_ops_register_mgmt_frame,
    .confExtcap             = qdock_ops_conf_extcap,
    .confAppIes             = qdock_ops_conf_appies,
    .conf4addr              = qdock_ops_conf_4addr,
    .confSecurity           = qdock_ops_conf_security,
    .resetBackhaul          = qdock_ops_reset_backhaul,
    .setBackhaul            = qdock_ops_set_backhaul,
};

static bool qdock_ops_tear_down_intf(struct interface *interface)
{
    if (0 != qdock_delete_wdev(interface->addr))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("qdock tear down interface failed!\n");
        return false;
    }
    return true;
}

static void qdock_store_bss_info(uint8_t *wiphy_id,
        struct bssInfo *bssInfo, bool is_ap, char *ifname)
{
    struct _qdockBssInfo *info;

    dlist_for_each(info, qdockData.creating_bsses, l)
    {
        if (!memcmp(wiphy_id, info->uid, sizeof(mac_address)) &&
                !strcmp(ifname, info->ifname))
            goto do_store;
    }

    if (!info)
    {
        info = (struct _qdockBssInfo *)malloc(sizeof(*info));
        if (!info)
            return;
        memcpy(info->uid, wiphy_id, sizeof(mac_address));
        strncpy(info->ifname, ifname, IFNAMSIZ - 1);
        dlist_add_tail(&qdockData.creating_bsses, &info->l);
    }

do_store:
    memcpy(&info->ssid, &bssInfo->ssid, sizeof(info->ssid));
    info->backhaul = bssInfo->backhaul;
    info->fronthaul = bssInfo->fronthaul;
    if (is_ap)
        info->role = interface_wifi_role_ap;
    else
        info->role = interface_wifi_role_sta;

    info->auth_mode = bssInfo->auth_mode;
    copyKey(&info->key, &bssInfo->key);
}

static bool qdock_ops_create_ap(struct radio *radio, struct bssInfo *bssInfo)
{
    char ifname[IFNAMSIZ] = { 0 };

    if (0 != qdock_create_wdev(radio->uid, bssInfo, true, ifname))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("qdock create ap failed!\n");
        return false;
    }

    /* remeber the context of creating wdev, will update some fields
     * in the interface context with this info */
    qdock_store_bss_info(radio->uid, bssInfo, true, ifname);

    return true;
}

static bool qdock_ops_create_sta(struct radio *radio, struct bssInfo *bssInfo)
{
    char ifname[IFNAMSIZ] = { 0 };

    if (0 != qdock_create_wdev(radio->uid, bssInfo, false, ifname))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("qdock create sta failed!\n");
        return false;
    }

    /* remeber the context of creating wdev, will update some fields
     * in the interface context with this info */
    qdock_store_bss_info(radio->uid, bssInfo, false, ifname);

    return true;
}

static bool qdock_ops_set_backhaul_info(struct radio *radio, struct ssid *ssid, struct key *key)
{
    int i;
    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        if (ifw->bssInfo.fronthaul)
            qdock_set_backhaul_info(ifw, ssid, key);
    }
    return true;
}

static void qdock_register_handlers(struct radio *radio)
{
    radio->addAP = qdock_ops_create_ap;
    radio->addSTA = qdock_ops_create_sta;
    radio->setBackhaulSsid = qdock_ops_set_backhaul_info;
    radio->configured = false;

    radioRegisterHandlers(radio, &qdock_ops);
}

void qdock_ops_sync_driver_bssconfigs(void)
{
    if (0 != qdock_get_bsscfgs())
    {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to get driver bssconfigs\n");
        return;
    }
    registrarDumpAllWsc("sync from driver");
    if (registrarCommitWsc())
    {
        localDeviceInterfaceWifiRegFramesAndConfigIEs();
        localDeviceInterfaceWifiBackhaulConfig();
        tiggerAPAutoconfigurationRenewProcess();
    }
}

static struct registrarHandles qdock_registrar_ops =
{
    .syncBssCfgs               = qdock_ops_sync_driver_bssconfigs,
};

static inline void qdock_collect_radios(void)
{
    // Collect the local radios into local_device.radios
    if (0 != qdock_get_wiphys(NULL))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to get local wiphys\n");
    }
}

static inline void qdock_collect_interfaces(void)
{
    if (0 != qdock_get_wdevs(NULL, NULL))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to get local wiphys\n");
    }
}

static void qdock_collect_clients(void)
{
    struct interface *intf;
    dlist_for_each(intf, local_device->interfaces, l)
    {
        if (intf->type != interface_type_wifi)
            continue;

        qdock_get_stations(intf->addr, NULL);
    }
}

void qdock_collect_local_registar(void)
{
    if (0 != qdock_get_devdata())
        PLATFORM_PRINTF_DEBUG_ERROR("fail to get driver devicedata\n");
    registrarRegisterHandlers(&qdock_registrar_ops);
}

void qdock_collect_local_infos(void)
{
    qdock_collect_radios();
    qdock_collect_interfaces();
    qdock_collect_clients();
}

static uint8_t qdock_wdev_associated_map_reason(uint32_t status)
{
    uint8_t reason = 0x06;
    switch (status)
    {
        case MAP_ROAM_STATUS_SUCCESS:
            reason = 0x00;
            break;
        case MAP_ROAM_STATUS_UNKNOWN_BSSID:
        case MAP_ROAM_STATUS_NOTRX_PROBE_RESP:
        case MAP_ROAM_STATUS_NOTRX_ASSOC_RESP:
            reason = 0x05;
            break;
        case MAP_ROAM_STATUS_UNAVAIL_CHAN:
            reason = 0x04;
            break;
        default:
            break;
    }
    return reason;
}

static void qdock_update_espi(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_ESPI_ATTRS];
    struct bssMetrics *metrics = (struct bssMetrics *)ctx;
    uint32_t ac;

    blobmsg_parse(qdock_map_wdev_stats_espi_policy,
            NUM_MAP_ESPI_ATTRS, tb, data, len);

    if (!tb[MAP_ESPI_ATTR_AC])
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no ac found in espi attrs\n");
        return;
    }

    ac = blobmsg_get_u32(tb[MAP_ESPI_ATTR_AC]);
    if (ac >= 4)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("wrong ac %u which should less than 4\n", ac);
        return;
    }

    metrics->espis[ac].valid = true;
    if (tb[MAP_ESPI_ATTR_FORMAT])
        metrics->espis[ac].format = (uint8_t)blobmsg_get_u32(tb[MAP_ESPI_ATTR_FORMAT]);

    if (tb[MAP_ESPI_ATTR_BA_SIZE])
        metrics->espis[ac].window = (uint8_t)blobmsg_get_u32(tb[MAP_ESPI_ATTR_BA_SIZE]);

    if (tb[MAP_ESPI_ATTR_EST_AIRTIME])
        metrics->espis[ac].est_airtime = (uint8_t)blobmsg_get_u32(tb[MAP_ESPI_ATTR_EST_AIRTIME]);

    if (tb[MAP_ESPI_ATTR_PPDU_DUR])
        metrics->espis[ac].est_airtime = (uint8_t)blobmsg_get_u32(tb[MAP_ESPI_ATTR_PPDU_DUR]);
}

static void qdock_update_sta_stats(void *ctx, void *data, int len)
{
    struct blob_attr *tb[NUM_MAP_STATION_ATTRS];
    struct interfaceWifi *ifw = (struct interfaceWifi *)(ctx);
    mac_address mac;
    struct staInfo *sta;
    uint32_t age = (uint32_t)-1;

    blobmsg_parse(qdock_map_station_policy,
            NUM_MAP_STATION_ATTRS, tb, data, len);

    if (blobmsg_get_macaddr(tb[MAP_STATION_ATTR_MAC], mac) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no sta mac found in attrs\n");
        return;
    }

    sta = interfaceFindStation(ifw, mac);
    if (!sta)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("sta " MACFMT "is not associated\n", MACARG(mac));
        return;
    }

    if (tb[MAP_STATION_ATTR_RSSI])
        sta->link_metrics.rcpi_ul = mapPowerLevel2RCPI((int)blobmsg_get_u32(tb[MAP_STATION_ATTR_RSSI]));

    if (tb[MAP_STATION_ATTR_RATE_DOWNLINK]
            && tb[MAP_STATION_ATTR_AGE_DOWNLINK])
    {
        sta->link_metrics.rate_dl = blobmsg_get_u32(tb[MAP_STATION_ATTR_RATE_DOWNLINK]);
        age = blobmsg_get_u32(tb[MAP_STATION_ATTR_AGE_DOWNLINK]);
    }

    if (tb[MAP_STATION_ATTR_RATE_UPLINK]
            && tb[MAP_STATION_ATTR_AGE_UPLINK])
    {
        uint32_t age_ul;
        sta->link_metrics.rate_ul = blobmsg_get_u32(tb[MAP_STATION_ATTR_RATE_UPLINK]);
        age_ul = blobmsg_get_u32(tb[MAP_STATION_ATTR_AGE_UPLINK]);
        if (age_ul < age)
            age = age_ul;
    }

    if (age != (uint32_t)-1 &&
            (tb[MAP_STATION_ATTR_RATE_DOWNLINK] || tb[MAP_STATION_ATTR_RATE_UPLINK]))
        sta->link_metrics.last_ts = PLATFORM_GET_TIMESTAMP() - age;

    if (tb[MAP_STATION_ATTR_TX_BYTES])
        sta->traffic_metrics.tx_bytes = blobmsg_get_u32(tb[MAP_STATION_ATTR_TX_BYTES]);

    if (tb[MAP_STATION_ATTR_RX_BYTES])
        sta->traffic_metrics.rx_bytes = blobmsg_get_u32(tb[MAP_STATION_ATTR_RX_BYTES]);

    if (tb[MAP_STATION_ATTR_TX_PACKETS])
        sta->traffic_metrics.tx_packets = blobmsg_get_u32(tb[MAP_STATION_ATTR_TX_PACKETS]);

    if (tb[MAP_STATION_ATTR_RX_PACKETS])
        sta->traffic_metrics.rx_packets = blobmsg_get_u32(tb[MAP_STATION_ATTR_RX_PACKETS]);

    if (tb[MAP_STATION_ATTR_TX_ERRORS])
        sta->traffic_metrics.tx_errors = blobmsg_get_u32(tb[MAP_STATION_ATTR_TX_ERRORS]);

    if (tb[MAP_STATION_ATTR_RX_ERRORS])
        sta->traffic_metrics.rx_errors = blobmsg_get_u32(tb[MAP_STATION_ATTR_RX_ERRORS]);

    if (tb[MAP_STATION_ATTR_TX_RETRIES])
        sta->traffic_metrics.tx_tries = blobmsg_get_u32(tb[MAP_STATION_ATTR_TX_RETRIES]);
}

static void qdock_update_sta_wdev_info(uint8_t *wdev_id, uint8_t *bssid, uint32_t status)
{
    struct interfaceWifi *ifw;

    ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_sta);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi sta interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    if (status)
    {
        memset(ifw->bssInfo.bssid, 0, sizeof(mac_address));
        interfaceRemoveStation(ifw, bssid);
    }
    else
    {
        memcpy(ifw->bssInfo.bssid, bssid, sizeof(mac_address));
        interfaceFindOrAddStation(ifw, bssid);
    }
}

static inline void qdock_process_wiphy_updated(struct blob_attr *msg)
{
    qdock_update_wiphy(NULL, blob_data(msg), blob_len(msg));
}

static inline void qdock_process_wdev_added(struct blob_attr *msg)
{
    qdock_update_wdev(NULL, blob_data(msg), blob_len(msg));
}

static inline void qdock_process_wdev_updated(struct blob_attr *msg)
{
    qdock_update_wdev(NULL, blob_data(msg), blob_len(msg));
}

static void qdock_process_wdev_deleted(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    struct interfaceWifi *ifw;
    mac_address wdev_id;

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (blobmsg_get_macaddr(tb[MAP_ATTR_WDEV_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id found in wdev delete event attrs\n");
        return;
    }

    ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    qdock_handle_wifi_interface_deleted(ifw);

    interfaceWifiRemove(ifw);
}

static void qdock_process_wdev_associated(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_WDEV_ATTRS];
    mac_address wdev_id;
    mac_address bssid;
    uint32_t status = 0x05;

    blobmsg_parse(qdock_map_wdev_policy, NUM_MAP_WDEV_ATTRS, tb, blob_data(msg), blob_len(msg));

    if ((blobmsg_get_macaddr(tb[MAP_WDEV_ATTR_ID], wdev_id) < 0)
        || (blobmsg_get_macaddr(tb[MAP_WDEV_ATTR_BSSID], bssid) < 0))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id and bssid found in attrs\n");
        return;
    }

    if (tb[MAP_WDEV_ATTR_STATUS])
        status = blobmsg_get_u32(tb[MAP_WDEV_ATTR_STATUS]);

    PLATFORM_PRINTF_DEBUG_INFO("wdev " MACFMT " with " MACFMT " associated status %u\n",
            MACARG(wdev_id), MACARG(bssid), status);

    qdock_update_sta_wdev_info(wdev_id, bssid, status);

    mapTryReportBackhualSteeringResponse(wdev_id, bssid, qdock_wdev_associated_map_reason(status));

    if (!status)
        qdock_notify_authenticated_link(wdev_id, bssid);
}

static void qdock_process_sta_connected(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    mac_address wdev_id;
    struct station_update_context ctx;

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (blobmsg_get_macaddr(tb[MAP_ATTR_WDEV_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id found in sta connect event attrs\n");
        return;
    }

    ctx.ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ctx.ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    ctx.client = NULL;
    qdock_update_station(&ctx, blobmsg_data(tb[MAP_ATTR_STATION]), blobmsg_len(tb[MAP_ATTR_STATION]));

    qdock_notify_topology_changed(wdev_id, ctx.client ? ctx.client->mac : NULL, 1);

    mapapi_event_client_associated(ctx.ifw->radio->uid, ctx.ifw->bssInfo.bssid, ctx.ifw->bssInfo.ssid.ssid, ctx.ifw->bssInfo.ssid.length, ctx.client->mac, 1);
}

static void qdock_process_sta_disconnected(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    mac_address wdev_id, sta_mac;
    struct interfaceWifi *ifw;

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if ((blobmsg_get_macaddr(tb[MAP_ATTR_WDEV_ID], wdev_id) < 0)
        || (blobmsg_get_macaddr(tb[MAP_ATTR_STA_MAC], sta_mac) < 0))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id/sta mac found in attrs\n");
        return;
    }

    ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    // Delete the client from interface.clients
    interfaceRemoveStation(ifw, sta_mac);

    qdock_notify_topology_changed(wdev_id, sta_mac, 0);
}

static void qdock_process_frame_received(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    mac_address wdev_id;
    uint8_t *frame;
    uint32_t frame_len = 0;

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (tb[MAP_ATTR_FRAME])
    {
        frame = blobmsg_data(tb[MAP_ATTR_FRAME]);
        frame_len = blobmsg_data_len(tb[MAP_ATTR_FRAME]);
    }
    if (!frame_len)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no payload in frame receive event attrs\n");
        return;
    }

    if (blobmsg_get_macaddr(tb[MAP_ATTR_WDEV_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id found in frame receive event attrs\n");
        return;
    }

    mapTryReport80211Frame(frame, frame_len);
}

static void qdock_process_wdev_stats_updated(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_WDEV_ATTRS];
    mac_address wdev_id;
    struct interfaceWifi *ifw;

    blobmsg_parse(qdock_map_wdev_policy, NUM_MAP_WDEV_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (blobmsg_get_macaddr(tb[MAP_WDEV_ATTR_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id found in attrs\n");
        return;
    }

    ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    if (tb[MAP_WDEV_ATTR_FAT])
        ifw->bssInfo.metrics.ch_util = mapFAT2ChannelUtil(blobmsg_get_u32(tb[MAP_WDEV_ATTR_FAT]));

    qdock_visit_attrs(tb[MAP_WDEV_ATTR_ESPI], qdock_update_espi, &ifw->bssInfo.metrics);

    /* Spec ask to send AP Metrics Response message containing one AP Metrics TLV for EACH of the BSSs on that radio.
     * and Channel Utilization is same for all BSSs on that radio
     * Report the AP Metrics when receiving the first BSS stats event */
    if (ifw->radio && (radioGetFirstAPInterface(ifw->radio) == ifw))
    {
        ifw->radio->ch_util = ifw->bssInfo.metrics.ch_util;
        mapTryReportAPMetrics(ifw->radio);
    }
}

static void qdock_process_sta_stats_updated(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    mac_address wdev_id;
    struct interfaceWifi *ifw;

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (blobmsg_get_macaddr(tb[MAP_ATTR_WDEV_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id found in attrs\n");
        return;
    }

    ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    qdock_visit_attrs(tb[MAP_ATTR_STATIONS], qdock_update_sta_stats, ifw);

    mapTryReportAssocStaMetrics(ifw);
}

#ifdef REPORT_MONITOR_STATS
static void qdock_process_monitor_stats_updated(struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAP_ATTRS];
    mac_address wdev_id;
    struct interfaceWifi *ifw;

    blobmsg_parse(qdock_map_policy, NUM_MAP_ATTRS, tb, blob_data(msg), blob_len(msg));

    if (blobmsg_get_macaddr(tb[MAP_ATTR_WDEV_ID], wdev_id) < 0)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("no wdev id found in attrs\n");
        return;
    }

    ifw = findLocalWifiInterface(wdev_id, interface_wifi_role_other);
    if (!ifw || !ifw->radio)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("can't find wifi interface for " MACFMT "\n", MACARG(wdev_id));
        return;
    }

    qdock_visit_attrs(tb[MAP_ATTR_STATIONS], qdock_update_monitor_stats, ifw->radio);
}
#endif

struct _driverEvent
{
    const char *name;
    void (*process_cb)(struct blob_attr *);
};

static const struct _driverEvent qdockEvents[] =
{
    { MAP_EVENT_WIPHY_UPDATED_NAME, qdock_process_wiphy_updated },
    { MAP_EVENT_WDEV_ADDED_NAME, qdock_process_wdev_added },
    { MAP_EVENT_WDEV_UPDATED_NAME, qdock_process_wdev_updated },
    { MAP_EVENT_WDEV_DELETED_NAME, qdock_process_wdev_deleted },
    { MAP_EVENT_WDEV_ASSOCIATED_NAME, qdock_process_wdev_associated },
    { MAP_EVENT_STA_CONNECTED_NAME, qdock_process_sta_connected },
    { MAP_EVENT_STA_DISCONNECTED_NAME, qdock_process_sta_disconnected },
    { MAP_EVENT_FRAME_RECEIVED_NAME, qdock_process_frame_received },
    { MAP_EVENT_WDEV_STATS_UPDATED_NAME, qdock_process_wdev_stats_updated },
    { MAP_EVENT_STA_STATS_UPDATED_NAME, qdock_process_sta_stats_updated },
#ifdef REPORT_MONITOR_STATS
    { MAP_EVENT_MONITOR_STATS_UPDATED_NAME, qdock_process_monitor_stats_updated },
#endif
};

static int qdock_driver_notify(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    int id;

    PLATFORM_PRINTF_DEBUG_INFO("[PLATFORM] QDOCK driver %s notified\n", method);
    QDOCK_BLOGMSG_DUMP(method, msg);

    if (!msg)
        return -1;

    for (id = 0; id < ARRAY_SIZE(qdockEvents); id++)
        if (0 == strcmp(qdockEvents[id].name, method))
            break;

    if (id >= ARRAY_SIZE(qdockEvents)
        || !qdockEvents[id].process_cb) {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] QDOCK do not find process for %s\n", method);
        return 0;
    }

    qdockEvents[id].process_cb(msg);

    return 0;
}

void qdock_platform_deinit(void)
{
    dlist_item *item;

    while (NULL != (item = dlist_get_first(&qdockData.creating_bsses)))
    {
        struct _qdockBssInfo *info = container_of(item, struct _qdockBssInfo, l);
        dlist_remove(item);

        free(info);
    }

    blob_buf_free(&b);
}

void qdock_platform_init(void)
{
    int ret;
    struct _qdockData *data = (struct _qdockData *)&qdockData;

    if (!platform_ubus)
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] platform ubus should be inited\n");
        return;
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] QDOCK data init started\n");
    memset(data, 0, sizeof(*data));

    dlist_head_init(&data->creating_bsses);

    if ((ret = ubus_lookup_id(platform_ubus, MAP_INTF_OBJ_NAME, &data->intf_objid))
        || (ret = ubus_lookup_id(platform_ubus, MAP_MLME_OBJ_NAME, &data->mlme_objid))
        || (ret = ubus_lookup_id(platform_ubus, MAP_STATISTICS_OBJ_NAME, &data->stas_objid)))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] QDOCK data init lookup id failed: %s\n",
            ubus_strerror(ret));
        return;
    }

    if ((ret = ubus_register_subscriber(platform_ubus, &data->notification)))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] QDOCK data init register subscriber failed: %s\n",
            ubus_strerror(ret));
        return;
    }

    data->notification.cb = qdock_driver_notify;
    if ((ret = ubus_subscribe(platform_ubus, &data->notification, data->intf_objid))
        || (ret = ubus_subscribe(platform_ubus, &data->notification, data->mlme_objid))
        || (ret = ubus_subscribe(platform_ubus, &data->notification, data->stas_objid)))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("[PLATFORM] QDOCK data init subscriber notification failed: %s\n",
            ubus_strerror(ret));
        return;
    }

    blob_buf_init(&b, 0);

    PLATFORM_PRINTF_DEBUG_DETAIL("[PLATFORM] QDOCK waiting notification\n");
}

bool isQtnWifiDevice(const char *if_name)
{
	if ((strstr(if_name, "wifi") || strstr(if_name, "wlan")) && strlen(ni_interface_name) > 0)
	    return true;

	return false;
}
