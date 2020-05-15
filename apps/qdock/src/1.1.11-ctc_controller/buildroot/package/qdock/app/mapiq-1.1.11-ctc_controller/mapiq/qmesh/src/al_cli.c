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
 * @brief CLI implementation
 *
 * This file provides functionality for CLI
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netinet/ether.h>

#include <libubox/uloop.h>
#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "platform.h"
#include "platform_interfaces.h"
#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "1905_l2.h"
#include "packet_tools.h"
#include "al.h"
#include "datamodel.h"
#include "utils.h"
#include "al_utils.h"
#include "al_datamodel.h"
#include "al_cli.h"
#include "al_send.h"
#include "linux/platform_qdock.h"
#ifdef Q_STEERING_LOGIC
#include "map_steering.h"
#endif

static struct blob_buf b;

enum
{
    MAPCLI_RESULT_SUCCESS = 0,
    MAPCLI_RESULT_INVALID_VALUE,
    MAPCLI_RESULT_INVALID_ARGUMENT,
    MAPCLI_RESULT_MISS_ARGUMENT,
    MAPCLI_RESULT_CONTEXT_NOT_FOUND,
    MAPCLI_RESULT_NOT_SUPPORTED,
    MAPCLI_RESULT_UNKNOWN_ERROR,
};

static const char *result_strings[] =
{
	[MAPCLI_RESULT_SUCCESS] = "Successed",
	[MAPCLI_RESULT_INVALID_VALUE] = "Failed: Invalid Value",
	[MAPCLI_RESULT_INVALID_ARGUMENT] = "Failed: Invalid Argument",
	[MAPCLI_RESULT_MISS_ARGUMENT] = "Failed: Miss Argument",
	[MAPCLI_RESULT_CONTEXT_NOT_FOUND] = "Failed: Context Not Found",
	[MAPCLI_RESULT_NOT_SUPPORTED] = "Failed: Not Supported",
	[MAPCLI_RESULT_UNKNOWN_ERROR] = "Failed: Unknown Error",
};

static void mapcli_fill_result(uint8_t rc, const char *help)
{
    if (rc >= MAPCLI_RESULT_UNKNOWN_ERROR)
        rc = MAPCLI_RESULT_UNKNOWN_ERROR;
    blobmsg_add_string(&b, MAPCLI_ATTR_RC_NAME, result_strings[rc]);
    if (help)
        blobmsg_add_string(&b, MAPCLI_ATTR_HELP_NAME, help);
}

static int mapcli_get_binary(const char *bin_str, uint8_t **bins, uint32_t *len)
{
    uint32_t val, buf_len, i = 0;
    const char *p = bin_str;
    char *endpr;
    uint8_t *buf;

    if (bins)
        *bins = NULL;
    if (len)
        *len = 0;

    buf_len = strlen(bin_str) / 3 + 1;
    buf = (uint8_t *)malloc(buf_len);
    while (p - bin_str < strlen(bin_str) && i < buf_len) {
        val = strtoul(p, &endpr, 16);
        if ((endpr - p) != 2 || val > 255) {
            free(buf);
            return -1;
        }
        buf[i++] = val;
        p = endpr + 1;
    }

    if (bins)
        *bins = buf;
    if (len)
        *len = i;
    return 0;
}

static void blobmsg_add_binary(struct blob_buf *buf, const char *name, uint8_t *data, uint32_t len)
{
    int i;
    char *pos, *string = malloc(len * 3 + 1);

    string[0] = '\0';
    pos = string;
    for (i = 0; i < len; i++)
        pos += sprintf(pos, "%02x ", data[i]);

    blobmsg_add_string(buf, name, string);
    free(string);
}

static void blobmsg_add_addr(struct blob_buf *buf, const char *name, uint8_t *addr)
{
    char uid_str[18];
    sprintf(uid_str, MACFMT, MACARG(addr));
    blobmsg_add_string(buf, name, uid_str);
}

static void mapcli_fill_basic_wdev(struct interfaceWifi *ifw)
{
    char ssid[SSID_MAX_LEN + 1];
    const char *name = "wdev";

    if (ifw->i.name)
        name = ifw->i.name;

    blobmsg_add_string(&b, MAPCLI_WDEV_ATTR_IFNAME_NAME, name);
    blobmsg_add_addr(&b, MAPCLI_WDEV_ATTR_MAC_NAME, ifw->i.addr);
    blobmsg_add_string(&b, MAPCLI_WDEV_ATTR_STATE_NAME,
            ifw->i.power_state == interface_power_state_on ? "on" : "off");
    memcpy(ssid, ifw->bssInfo.ssid.ssid, ifw->bssInfo.ssid.length);
    ssid[ifw->bssInfo.ssid.length] = '\0';
    blobmsg_add_string(&b, MAPCLI_WDEV_ATTR_SSID_NAME, ssid);
    blobmsg_add_string(&b, MAPCLI_WDEV_ATTR_ROLE_NAME,
            (ifw->role == interface_wifi_role_ap) ? "ap" : "sta");
    blobmsg_add_addr(&b, MAPCLI_WDEV_ATTR_BSSID_NAME, ifw->bssInfo.bssid);
}

static void mapcli_fill_wiphy_wdevs(struct radio *radio)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPCLI_WIPHY_ATTR_WDEVS_NAME);

    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        void *table = blobmsg_open_table(&b, NULL);
        mapcli_fill_basic_wdev(ifw);
        blobmsg_close_table(&b, table);
    }
    blobmsg_close_array(&b, list);
}

static void mapcli_fill_wiphy_policy(struct radio *radio)
{
    void *table = blobmsg_open_table(&b, MAPCLI_WIPHY_ATTR_STEER_POLICY_NAME);
    blobmsg_add_u32(&b, MAPCLI_POLICY_ATTR_STEER_NAME, radio->steering_policy.policy);
    blobmsg_add_u32(&b, MAPCLI_POLICY_ATTR_CH_UTIL_NAME, radio->steering_policy.ch_util_threshold);
    blobmsg_add_u32(&b, MAPCLI_POLICY_ATTR_RCPI_NAME, radio->steering_policy.rcpi_threshold);
    blobmsg_close_table(&b, table);

    table = blobmsg_open_table(&b, MAPCLI_WIPHY_ATTR_METRIC_POLICY_NAME);
    blobmsg_add_u32(&b, MAPCLI_POLICY_ATTR_RCPI_NAME, radio->metric_policy.rcpi_threshold);
    blobmsg_add_u32(&b, MAPCLI_POLICY_ATTR_MARGIN_NAME, radio->metric_policy.rcpi_margin);
    blobmsg_add_u32(&b, MAPCLI_POLICY_ATTR_CH_UTIL_NAME, radio->metric_policy.rcpi_margin);
    blobmsg_add_u32(&b, MAPCLI_POLICY_ATTR_INCLUSION_NAME, radio->metric_policy.policy);
    blobmsg_close_table(&b, table);
}

static void mapcli_fill_opclass_channel(struct radioChannel *channel)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_u32(&b, MAPCLI_CHANNEL_ATTR_ID_NAME, channel->id);
    blobmsg_add_u8(&b, MAPCLI_CHANNEL_ATTR_DISABLE_NAME, channel->disabled);
    blobmsg_add_u32(&b, MAPCLI_CHANNEL_ATTR_PREF_NAME, channel->pref);
    blobmsg_add_u32(&b, MAPCLI_CHANNEL_ATTR_REASON_NAME, channel->reason);
    blobmsg_add_u32(&b, MAPCLI_CHANNEL_ATTR_MIN_SEP_NAME, channel->min_sep);
    blobmsg_close_table(&b, table);
}

static void mapcli_fill_opclass_channels(struct radioOpclass *opclass)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPCLI_OPCLASS_ATTR_CHANNELS_NAME);

    for (i = 0; i < opclass->channel_nums; i++)
        mapcli_fill_opclass_channel(&opclass->channels[i]);

    blobmsg_close_array(&b, list);
}

static void mapcli_fill_wiphy_opclass(struct radioOpclass *opclass)
{
    void *table = blobmsg_open_table(&b, NULL);
    blobmsg_add_u32(&b, MAPCLI_OPCLASS_ATTR_ID_NAME, opclass->opclass);
    blobmsg_add_u32(&b, MAPCLI_OPCLASS_ATTR_BW_NAME, opclass->bw);
    blobmsg_add_u32(&b, MAPCLI_OPCLASS_ATTR_MAXPOWER_NAME, opclass->max_txpower);
    mapcli_fill_opclass_channels(opclass);
    blobmsg_close_table(&b, table);
}

static void mapcli_fill_wiphy_opclasses(struct radio *radio)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPCLI_WIPHY_ATTR_OPCLASSES_NAME);

    for (i = 0; i < radio->opclass_nums; i++)
        mapcli_fill_wiphy_opclass(&radio->opclasses[i]);

    blobmsg_close_array(&b, list);
}

const char *phytype_string[] = {
    "unknown", "fhss", "dsss", "irbaseband", "ofdm", "hrdss", "erp", "ht", "dmg", "vht"};

static void mapcli_fill_wiphy(struct radio *radio, int verbose, int isLocal)
{
    void *table = blobmsg_open_table(&b, NULL);

    if (isLocal)
        blobmsg_add_string(&b, MAPCLI_WIPHY_ATTR_IFNAME_NAME, radio->name);
    blobmsg_add_addr(&b, MAPCLI_WIPHY_ATTR_ID_NAME, radio->uid);
    blobmsg_add_u32(&b, MAPCLI_WIPHY_ATTR_MAXBSSES_NAME, radio->maxBSS);
    if (radio->opclass)
        blobmsg_add_u32(&b, MAPCLI_WIPHY_ATTR_OPCLASS_NAME, radio->opclass);
    if (radio->chan)
        blobmsg_add_u32(&b, MAPCLI_WIPHY_ATTR_CHANNEL_NAME, radio->chan);
    if (radio->txpower)
        blobmsg_add_u32(&b, MAPCLI_WIPHY_ATTR_TXPOWER_NAME, radio->txpower);
    mapcli_fill_wiphy_wdevs(radio);

    if (verbose)
    {
        uint32_t phytype = radio->phytype;
        blobmsg_add_u8(&b, MAPCLI_WIPHY_ATTR_MON_OFFCHAN_NAME, radio->monitor_offchan);
        blobmsg_add_u8(&b, MAPCLI_WIPHY_ATTR_MON_ONCHAN_NAME, radio->monitor_onchan);
        blobmsg_add_u8(&b, MAPCLI_WIPHY_ATTR_SELF_STEERING_NAME, radio->self_steering);
        blobmsg_add_u8(&b, MAPCLI_WIPHY_ATTR_POWERSAVED_NAME, radio->powerSaved);
        if (phytype >= ARRAY_SIZE(phytype_string))
            phytype = 0;
        blobmsg_add_string(&b, MAPCLI_WIPHY_ATTR_PHYTYPE_NAME, phytype_string[phytype]);
        blobmsg_add_binary(&b, MAPCLI_WIPHY_ATTR_HTCAPA_NAME, (uint8_t *)(&radio->ht_capa), sizeof(struct radioHtcap));
        blobmsg_add_binary(&b, MAPCLI_WIPHY_ATTR_VHTCAPA_NAME, (uint8_t *)(&radio->vht_capa), sizeof(struct radioVhtcap));
        blobmsg_add_binary(&b, MAPCLI_WIPHY_ATTR_HECAPA_NAME, (uint8_t *)(&radio->he_capa), sizeof(struct radioHecap));
        mapcli_fill_wiphy_policy(radio);
        mapcli_fill_wiphy_opclasses(radio);
    }

    blobmsg_close_table(&b, table);
}

static void mapcli_fill_wiphys(struct alDevice *alDev, int verbose, int isLocal)
{
    struct radio *radio;
    void *list = blobmsg_open_array(&b, MAPCLI_ATTR_WIPHYS_NAME);

    dlist_for_each(radio, alDev->radios, l)
        mapcli_fill_wiphy(radio, verbose, isLocal);

    blobmsg_close_array(&b, list);
}

static void mapcli_fill_basic_client(struct staInfo *client)
{
    blobmsg_add_addr(&b, MAPCLI_CLIENT_ATTR_MAC_NAME, client->mac);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_ATTR_AGE_NAME, (PLATFORM_GET_TIMESTAMP() - client->last_assoc_ts) / 1000);
}

static void mapcli_fill_wdev_clients(struct interfaceWifi *ifw)
{
    struct staInfo *client;
    void *list = blobmsg_open_array(&b, MAPCLI_WDEV_ATTR_CLIENTS_NAME);

    dlist_for_each(client, ifw->clients, l)
    {
        void *table = blobmsg_open_table(&b, NULL);
        mapcli_fill_basic_client(client);
        if (client->last_assoc && client->last_assoc_len)
            blobmsg_add_binary(&b, MAPCLI_CLIENT_ATTR_ASSOC_NAME,
                    client->last_assoc, client->last_assoc_len);
        blobmsg_close_table(&b, table);
    }

    blobmsg_close_array(&b, list);
}

static void mapcli_fill_wdev_metric_espis(struct bssMetrics *metric)
{
    int i;
    void *list = blobmsg_open_array(&b, MAPCLI_WDEV_METRIC_ATTR_ESPIS_NAME);

    for (i = 0; i < 4; i++)
    {
        if (metric->espis[i].valid)
        {
            void *table = blobmsg_open_table(&b, NULL);
            blobmsg_add_u32(&b, MAPCLI_ESPI_ATTR_AC_NAME, i);
            blobmsg_add_u32(&b, MAPCLI_ESPI_ATTR_FORMAT_NAME, metric->espis[i].format);
            blobmsg_add_u32(&b, MAPCLI_ESPI_ATTR_WINDOW_NAME, metric->espis[i].window);
            blobmsg_add_u32(&b, MAPCLI_ESPI_ATTR_EST_AIRTIME_NAME, metric->espis[i].est_airtime);
            blobmsg_add_u32(&b, MAPCLI_ESPI_ATTR_DURATION_NAME, metric->espis[i].duration);
            blobmsg_close_table(&b, table);
        }
    }
    blobmsg_close_array(&b, list);
}

static void mapcli_fill_wdev_metric(struct bssMetrics *metric)
{
    void *table = blobmsg_open_table(&b, MAPCLI_WDEV_ATTR_METRIC_NAME);
    blobmsg_add_u32(&b, MAPCLI_WDEV_METRIC_ATTR_CHUTIL_NAME, metric->ch_util);
    mapcli_fill_wdev_metric_espis(metric);
    blobmsg_close_table(&b, table);
}

static void mapcli_fill_wdev(struct interfaceWifi *ifw, int verbose, int isLocal)
{
    void *table = blobmsg_open_table(&b, NULL);
    mapcli_fill_basic_wdev(ifw);
    if (ifw->radio)
        blobmsg_add_addr(&b, MAPCLI_WDEV_ATTR_RADIO_NAME, ifw->radio->uid);
    blobmsg_add_binary(&b, MAPCLI_WDEV_ATTR_KEY_NAME, ifw->bssInfo.key.key, ifw->bssInfo.key.len);
    if (isLocal)
        blobmsg_add_u32(&b, MAPCLI_WDEV_ATTR_BINTVAL_NAME, ifw->bssInfo.bintval);
    blobmsg_add_u8(&b, MAPCLI_WDEV_ATTR_FRONTHAUL_NAME, ifw->bssInfo.fronthaul);
    blobmsg_add_u8(&b, MAPCLI_WDEV_ATTR_BACKHAUL_NAME, ifw->bssInfo.backhaul);
    blobmsg_add_u32(&b, MAPCLI_WDEV_ATTR_CLIENT_NUM_NAME, dlist_count(&ifw->clients));
    if (verbose)
    {
        mapcli_fill_wdev_metric(&ifw->bssInfo.metrics);
        mapcli_fill_wdev_clients(ifw);
    }
    blobmsg_close_table(&b, table);
}

static void mapcli_fill_wdevs(struct alDevice *alDev, int verbose, int isLocal)
{
    struct interface *intf;
    void *list = blobmsg_open_array(&b, MAPCLI_ATTR_WDEVS_NAME);

    dlist_for_each(intf, alDev->interfaces, l)
    {
        if (intf->type != interface_type_wifi)
            continue;

        mapcli_fill_wdev((struct interfaceWifi *)intf, verbose, isLocal);
    }

    blobmsg_close_array(&b, list);
}

static void mapcli_fill_client_link_metrics(struct staLinkMetrics *metric)
{
    void *table = blobmsg_open_table(&b, MAPCLI_CLIENT_ATTR_LINK_METRIC_NAME);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_AGE_NAME, PLATFORM_GET_TIMESTAMP() - metric->last_ts);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_DLRATE_NAME, metric->rate_dl);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_ULRATE_NAME, metric->rate_ul);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_RCPI_NAME, metric->rcpi_ul);
    blobmsg_close_table(&b, table);
}

static void mapcli_fill_client_traffic_metrics(struct staTrafficMetrics *metric)
{
    void *table = blobmsg_open_table(&b, MAPCLI_CLIENT_ATTR_TRAFFIC_METRIC_NAME);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_TXPKTS_NAME, metric->tx_packets);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_TXBYTES_NAME, metric->tx_bytes);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_RXPKTS_NAME, metric->rx_packets);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_RXBYTES_NAME, metric->rx_bytes);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_TXERRS_NAME, metric->tx_errors);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_RXERRS_NAME, metric->rx_errors);
    blobmsg_add_u32(&b, MAPCLI_CLIENT_METRIC_ATTR_TXTRIES_NAME, metric->tx_tries);
    blobmsg_close_table(&b, table);
}

static void mapcli_fill_clients(struct alDevice *alDev, uint8_t *mac, int verbose)
{
    struct interface *intf;
    void *list = blobmsg_open_array(&b, MAPCLI_ATTR_CLIENTS_NAME);

    dlist_for_each(intf, alDev->interfaces, l)
    {
        struct staInfo *client;
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi)
            continue;

        if (ifw->role == interface_wifi_role_sta)
            continue;

        dlist_for_each(client, ifw->clients, l)
        {
            void *table;

            if (mac && memcmp(mac, client->mac, sizeof(mac_address)))
                continue;

            table = blobmsg_open_table(&b, NULL);
            mapcli_fill_basic_client(client);
            if (verbose)
            {
                blobmsg_add_binary(&b, MAPCLI_CLIENT_ATTR_ASSOC_NAME,
                        client->last_assoc, client->last_assoc_len);
                mapcli_fill_client_link_metrics(&client->link_metrics);
                mapcli_fill_client_traffic_metrics(&client->traffic_metrics);
                if (client->beacon_report_ie_num > 0)
                {
                    void *list = blobmsg_open_array(&b, MAPCLI_CLIENT_ATTR_BEACON_REPORT_IES_NAME);
                    int i;
                    for (i = 0; i < client->beacon_report_ie_num; i++)
                    {
                        if (client->beacon_report_ie[i] && client->beacon_report_ie[i][1])
                        {
                            void *table = blobmsg_open_table(&b, NULL);
                            blobmsg_add_binary(&b, MAPCLI_CLIENT_ATTR_BEACON_REPORT_NAME,
                                    client->beacon_report_ie[i], client->beacon_report_ie[i][1]+2);
                            blobmsg_close_table(&b, table);
                        }
                    }
                    blobmsg_close_array(&b, list);
                }
            }
            blobmsg_close_table(&b, table);
        }
    }

    blobmsg_close_array(&b, list);
}

static void mapcli_fill_monitors(struct alDevice *alDev, uint8_t *mac, int verbose)
{
    struct radio *radio;
    void *list = blobmsg_open_array(&b, MAPCLI_ATTR_MONITORS_NAME);

    dlist_for_each(radio, alDev->radios, l)
    {
        struct radioUnassocSta *sta;
        dlist_for_each(sta, radio->unassocStaHead, l)
        {
            void *table;

            if (mac && memcmp(mac, sta->mac, sizeof(mac_address)))
                continue;

            table = blobmsg_open_table(&b, NULL);
            blobmsg_add_addr(&b, MAPCLI_CLIENT_ATTR_MAC_NAME, sta->mac);
            blobmsg_add_addr(&b, MAPCLI_CLIENT_ATTR_SEEN_NAME, radio->uid);
            blobmsg_add_u32(&b, MAPCLI_CLIENT_ATTR_AGE_NAME, PLATFORM_GET_TIMESTAMP() - sta->last_ts);
            blobmsg_add_u32(&b, MAPCLI_CLIENT_ATTR_OPCLASS_NAME, sta->opclass);
            blobmsg_add_u32(&b, MAPCLI_CLIENT_ATTR_CHANNEL_NAME, sta->channel);
            blobmsg_close_table(&b, table);
        }
    }
    blobmsg_close_array(&b, list);
}

static void mapcli_fill_controller(int verbose)
{
    void *table = blobmsg_open_table(&b, MAPCLI_NETWORK_ATTR_CONTROLLER_NAME);
    if (registrar.d)
        blobmsg_add_addr(&b, MAPCLI_NETWORK_ATTR_ALID_NAME, registrar.d->al_mac_addr);

    blobmsg_close_table(&b, table);
}

static void mapcli_fill_neighbor(struct alDevice *alDev, int verbose)
{
    void *table = blobmsg_open_table(&b, NULL);

    blobmsg_add_addr(&b, MAPCLI_NETWORK_ATTR_ALID_NAME, alDev->al_mac_addr);
    if(registrarIsLocal())
    {
        mapcli_fill_wiphys(alDev, verbose, 0);
        mapcli_fill_wdevs(alDev, verbose, 0);
        mapcli_fill_clients(alDev, NULL, verbose);
        mapcli_fill_monitors(alDev, NULL, verbose);
    }

    blobmsg_close_table(&b, table);
}

static void mapcli_fill_neighbors(int verbose)
{
    struct alDevice *alDev;
    void *list = blobmsg_open_array(&b, MAPCLI_NETWORK_ATTR_NEIGHBORS_NAME);

    dlist_for_each(alDev, network, l)
    {
        if (alDev == local_device)
            continue;
        mapcli_fill_neighbor(alDev, verbose);
    }

    blobmsg_close_array(&b, list);
}

static void mapcli_fill_networks(int verbose)
{
    void *table = blobmsg_open_table(&b, MAPCLI_ATTR_NETWORKS_NAME);

    mapcli_fill_controller(verbose);
    mapcli_fill_neighbors(verbose);

    blobmsg_close_table(&b, table);
}

enum {
    MAPCLI_SHOW_ATTR_TABLE = 0,
    MAPCLI_SHOW_ATTR_MAC,
    MAPCLI_SHOW_ATTR_VERBOSE,

    NUM_MAPCLI_SHOW_ATTRS,
};

static const struct blobmsg_policy mapcli_show_policy[] =
{
	[MAPCLI_SHOW_ATTR_TABLE] = { .name = MAPCLI_ATTR_TABLE_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_SHOW_ATTR_MAC] = { .name = MAPCLI_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_SHOW_ATTR_VERBOSE] = { .name = MAPCLI_ATTR_VERBOSE_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static const char *method_show_help_string =
    "ubus call " MAPCLI_OBJ_NAME " show {\""
        MAPCLI_ATTR_TABLE_NAME ":[NAME], "
        MAPCLI_ATTR_MAC_NAME ":[mac_string], "
        MAPCLI_ATTR_VERBOSE_NAME ":[0/1]\"}\n"
            "\tNAME: wiphy, wdev, client, monitor";
static int mapcli_show(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPCLI_SHOW_ATTRS];
    int verbose = 0;
    const char *table, *mac_str;
    struct ether_addr macaddr;

    blobmsg_parse(mapcli_show_policy, NUM_MAPCLI_SHOW_ATTRS,
        tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);

    if (tb[MAPCLI_SHOW_ATTR_VERBOSE])
        verbose = blobmsg_get_u32(tb[MAPCLI_SHOW_ATTR_VERBOSE]);

    table = blobmsg_get_string(tb[MAPCLI_SHOW_ATTR_TABLE]);
    mac_str = blobmsg_get_string(tb[MAPCLI_SHOW_ATTR_MAC]);

    if (mac_str && ether_aton_r(mac_str, &macaddr) == NULL)
        mapcli_fill_result(MAPCLI_RESULT_INVALID_VALUE, method_show_help_string);
    else if (!table)
    {
        mapcli_fill_networks(verbose);
        mapcli_fill_wiphys(local_device, verbose, 1);
        mapcli_fill_wdevs(local_device, verbose, 1);
        mapcli_fill_clients(local_device, NULL, verbose);
    }
    else if (!strcmp("wiphy", table))
        mapcli_fill_wiphys(local_device, verbose, 1);
    else if (!strcmp("wdev", table))
        mapcli_fill_wdevs(local_device, verbose, 1);
    else if (!strcmp("client", table))
        mapcli_fill_clients(local_device, mac_str ? macaddr.ether_addr_octet : NULL, verbose);
    else if (!strcmp("monitor", table))
        mapcli_fill_monitors(local_device, mac_str ? macaddr.ether_addr_octet : NULL, verbose);
    else if (!strcmp("network", table))
        mapcli_fill_networks(verbose);
    else
        mapcli_fill_result(MAPCLI_RESULT_INVALID_VALUE, method_show_help_string);

    return ubus_send_reply(ctx, req, b.head);
}

static const struct blobmsg_policy mapcli_wsc_conf_policy[] =
{
#define MAPCLI_CONF_POLICY(_t, _c) { .name = #_c, .type = BLOBMSG_TYPE_##_t }
    MAPCLI_CONF_POLICY(STRING, device_name),
    MAPCLI_CONF_POLICY(STRING, manufacturer_name),
    MAPCLI_CONF_POLICY(STRING, model_name),
    MAPCLI_CONF_POLICY(STRING, model_number),
    MAPCLI_CONF_POLICY(STRING, serial_number),
};

static void mapcli_set_wsc_config(struct blob_attr *attr)
{
    int i;
	struct blob_attr *tb[ARRAY_SIZE(mapcli_wsc_conf_policy)];

    blobmsg_parse(mapcli_wsc_conf_policy, ARRAY_SIZE(mapcli_wsc_conf_policy),
		tb, blobmsg_data(attr), blobmsg_len(attr));

    for (i = 0; i < ARRAY_SIZE(mapcli_wsc_conf_policy); i++)
    {
        if (!tb[i])
            continue;

#define MAPCLI_BLOBMSG_SET_STRING_CONF(_c, _s) \
        if (!strcmp(blobmsg_name(tb[i]), #_c))   strncpy(_s._c, blobmsg_get_string(tb[i]), sizeof(_s._c) - 1)

        MAPCLI_BLOBMSG_SET_STRING_CONF(device_name, map_config.wsc_data);
        MAPCLI_BLOBMSG_SET_STRING_CONF(manufacturer_name, map_config.wsc_data);
        MAPCLI_BLOBMSG_SET_STRING_CONF(model_name, map_config.wsc_data);
        MAPCLI_BLOBMSG_SET_STRING_CONF(model_number, map_config.wsc_data);
        MAPCLI_BLOBMSG_SET_STRING_CONF(serial_number, map_config.wsc_data);
    }
}

enum {
    MAPCLI_BSSINFO_ATTR_AL_MAC = 0,
    MAPCLI_BSSINFO_ATTR_OPCLASS,
    MAPCLI_BSSINFO_ATTR_SSID,
    MAPCLI_BSSINFO_ATTR_AUTH_MODE,
    MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE,
    MAPCLI_BSSINFO_ATTR_KEY,
    MAPCLI_BSSINFO_ATTR_BACKHAUL,
    MAPCLI_BSSINFO_ATTR_FRONTHAUL,

    NUM_MAPCLI_BSSINFO_ATTRS
};

static const struct blobmsg_policy mapcli_wsc_bssinfo_policy[] =
{
    [MAPCLI_BSSINFO_ATTR_AL_MAC] = { .name = MAPCLI_BSSINFO_ATTR_AL_MAC_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAPCLI_BSSINFO_ATTR_OPCLASS] = { .name = MAPCLI_BSSINFO_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAPCLI_BSSINFO_ATTR_SSID] = { .name = MAPCLI_BSSINFO_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAPCLI_BSSINFO_ATTR_AUTH_MODE] = { .name = MAPCLI_BSSINFO_ATTR_AUTH_MODE_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE] = { .name = MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAPCLI_BSSINFO_ATTR_KEY] = { .name = MAPCLI_BSSINFO_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_STRING},
    [MAPCLI_BSSINFO_ATTR_BACKHAUL] = { .name = MAPCLI_BSSINFO_ATTR_BACKHAUL_NAME, .type = BLOBMSG_TYPE_INT32},
    [MAPCLI_BSSINFO_ATTR_FRONTHAUL] = { .name = MAPCLI_BSSINFO_ATTR_FRONTHUAL_NAME, .type = BLOBMSG_TYPE_INT32},
};

static int mapcli_parse_wsc_bssinfo(struct blob_attr *attr, struct bssInfo *bss_info)
{
    struct blob_attr *tb[NUM_MAPCLI_BSSINFO_ATTRS];
    char *mac_str, *auth_mode, *encr_mode;
    struct ether_addr macaddr;

    blobmsg_parse(mapcli_wsc_bssinfo_policy, NUM_MAPCLI_BSSINFO_ATTRS,
            tb, blobmsg_data(attr), blobmsg_len(attr));

    if (tb[MAPCLI_BSSINFO_ATTR_AL_MAC])
    {
        mac_str = blobmsg_get_string(tb[MAPCLI_BSSINFO_ATTR_AL_MAC]);
        if (!mac_str || (ether_aton_r(mac_str, &macaddr) == NULL))
            return -1;
        memcpy(bss_info->bssid, macaddr.ether_addr_octet, sizeof(mac_address));
    }

    if (tb[MAPCLI_BSSINFO_ATTR_OPCLASS])
        memcpy(bss_info->opclass, blobmsg_get_string(tb[MAPCLI_BSSINFO_ATTR_OPCLASS]), 4);

    if (tb[MAPCLI_BSSINFO_ATTR_SSID])
    {
        strncpy((char *)bss_info->ssid.ssid, blobmsg_get_string(tb[MAPCLI_BSSINFO_ATTR_SSID]), SSID_MAX_LEN - 1);
        bss_info->ssid.length = strlen((char *)bss_info->ssid.ssid);
    }

    if (tb[MAPCLI_BSSINFO_ATTR_AUTH_MODE])
    {
        auth_mode = blobmsg_get_string(tb[MAPCLI_BSSINFO_ATTR_AUTH_MODE]);
        if (auth_mode)
        {
            if (!strcmp(auth_mode, "open"))
                bss_info->auth_mode = auth_mode_open;
            else if (!strcmp(auth_mode, "wpapsk"))
                bss_info->auth_mode = auth_mode_wpapsk;
            else if (!strcmp(auth_mode, "wpa2psk"))
                bss_info->auth_mode = auth_mode_wpa2psk;
        }
    }

    if (tb[MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE])
    {
        encr_mode = blobmsg_get_string(tb[MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE]);
        if (encr_mode)
        {
            if (!strcmp(encr_mode, "none"))
                bss_info->encryp = WPS_ENCR_NONE;
            else if (!strcmp(encr_mode, "aes"))
                bss_info->encryp = WPS_ENCR_AES;
            else if (!strcmp(encr_mode, "aes_tkip"))
                bss_info->encryp = WPS_ENCR_AES_TKIP;
        }
    }

    if (tb[MAPCLI_BSSINFO_ATTR_KEY])
    {
        strncpy((char *)bss_info->key.key, blobmsg_get_string(tb[MAPCLI_BSSINFO_ATTR_KEY]), 64);
        bss_info->key.len = strlen((char *)bss_info->key.key);
    }

    if (tb[MAPCLI_BSSINFO_ATTR_BACKHAUL] && blobmsg_get_u32(tb[MAPCLI_BSSINFO_ATTR_BACKHAUL]))
        bss_info->backhaul = true;

    if (tb[MAPCLI_BSSINFO_ATTR_FRONTHAUL] && blobmsg_get_u32(tb[MAPCLI_BSSINFO_ATTR_FRONTHAUL]))
        bss_info->fronthaul = true;

    return 0;
}

static int mapcli_parse_wsc_bssinfos(struct blob_attr *attrs,
        struct bssInfo **bss_infos, uint32_t *bss_nums)
{
    struct blob_attr *attr;
    uint32_t nums = 0, i = 0;
    int rem, retval = 0;
    struct bssInfo *ret;

    *bss_infos = NULL;
    *bss_nums = 0;

    if (attrs)
    {
        blobmsg_for_each_attr(attr, attrs, rem)
            nums++;
    }
    ret = (struct bssInfo *)malloc(sizeof(**bss_infos) * nums);
    memset(ret, 0, sizeof(*ret) * nums);

    if (attrs)
    {
        blobmsg_for_each_attr(attr, attrs, rem)
        {
            if (mapcli_parse_wsc_bssinfo(attr, &ret[i++]) < 0)
            {
                free(ret);
                retval = -1;
            }
        }
    }

    *bss_infos = ret;
    *bss_nums = nums;

    return retval;
}

static void mapcli_set_wsc_bssinfos(struct bssInfo *bss_infos, uint32_t bss_nums)
{
    int i;
    struct wscRegistrarInfo *wsc_info;
    struct bssInfo *bss_info;

    if (!bss_infos || !bss_nums)
        return;

    registrar.d = local_device;
    /* For now, it is always a MAP Controller. */
    registrar.is_map = true;

    /* Free previous wsc bss infos configuration */
    dlist_free_items(&registrar.wsc, struct wscRegistrarInfo, l);

    for (i = 0; i < bss_nums; i++) {
        bss_info = &bss_infos[i];

        wsc_info = zmemalloc(sizeof(struct wscRegistrarInfo));

        memcpy(wsc_info->bss_info.bssid, bss_info->bssid, sizeof(mac_address));
        copyLengthString(wsc_info->bss_info.ssid.ssid, &wsc_info->bss_info.ssid.length,
                (char *)bss_info->ssid.ssid, strlen((char *)bss_info->ssid.ssid));

        memcpy(wsc_info->bss_info.opclass, bss_info->opclass, 4);

        wsc_info->bss_info.auth_mode = bss_info->auth_mode;
        wsc_info->bss_info.encryp = bss_info->encryp;
        copyKey(&wsc_info->bss_info.key, &bss_info->key);
        wsc_info->bss_info.fronthaul = bss_info->fronthaul;
        wsc_info->bss_info.backhaul = bss_info->backhaul;

        if (!strcmp(bss_info->opclass, "8x"))
            wsc_info->rf_bands |= WPS_RF_24GHZ;
        else if (!strcmp(bss_info->opclass, "11x") || !strcmp(bss_info->opclass, "12x"))
            wsc_info->rf_bands |= WPS_RF_50GHZ;

        strncpy(wsc_info->device_data.manufacturer_name, map_config.wsc_data.manufacturer_name,
                strlen(map_config.wsc_data.manufacturer_name));
        strncpy(wsc_info->device_data.device_name, map_config.wsc_data.device_name,
                strlen(map_config.wsc_data.device_name));
        strncpy(wsc_info->device_data.model_name, map_config.wsc_data.model_name,
                strlen(map_config.wsc_data.model_name));
        strncpy(wsc_info->device_data.model_number, map_config.wsc_data.model_number,
                strlen(map_config.wsc_data.model_number));
        strncpy(wsc_info->device_data.serial_number, map_config.wsc_data.serial_number,
                strlen(map_config.wsc_data.serial_number));

        registrarAddWsc(wsc_info);
    }
}

static const struct blobmsg_policy mapcli_conf_policy[] =
{
    MAPCLI_CONF_POLICY(INT32, ap_metrics_intval),
    MAPCLI_CONF_POLICY(INT32, assoc_sta_intval),
    MAPCLI_CONF_POLICY(INT32, unassoc_sta_intval),
    MAPCLI_CONF_POLICY(INT32, support_agent_steering),
    MAPCLI_CONF_POLICY(INT32, monitor_dwell),
    MAPCLI_CONF_POLICY(INT32, rcpi_margin),
    MAPCLI_CONF_POLICY(INT32, wait_roaming),
    MAPCLI_CONF_POLICY(INT32, unassoc_sta_maxnums),
    MAPCLI_CONF_POLICY(INT32, retries),
    MAPCLI_CONF_POLICY(INT32, wait_ack),
    MAPCLI_CONF_POLICY(INT32, autoconf_wait),
    MAPCLI_CONF_POLICY(INT32, hide_backhaul_ssid),
    MAPCLI_CONF_POLICY(TABLE, wsc_data),
    MAPCLI_CONF_POLICY(INT32, dbg_level),
    MAPCLI_CONF_POLICY(INT32, ClientCapaQ_uponTopoR),
    MAPCLI_CONF_POLICY(INT32, APMetricsQ_uponTopoR),
    MAPCLI_CONF_POLICY(INT32, AssocedStaLinkQ_uponTopoR),
    MAPCLI_CONF_POLICY(INT32, filter_1905packet),

    MAPCLI_CONF_POLICY(ARRAY, wsc_bssinfos),
};

static const char *method_set_wsc_bssinfos_help_string =
    "ubus call " MAPCLI_OBJ_NAME " " MAPCLI_METHOD_SET_CONF_NAME " {"
        MAPCLI_WSC_REGISTRAR_BSSINFO_NAME ":[{"
        MAPCLI_BSSINFO_ATTR_AL_MAC_NAME ":\"AL_MAC\","
        MAPCLI_BSSINFO_ATTR_OPCLASS_NAME ":\"OPCLASS\","
        MAPCLI_BSSINFO_ATTR_SSID_NAME ":\"SSID\","
        MAPCLI_BSSINFO_ATTR_AUTH_MODE_NAME ":\"AUTH_MODE\","
        MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE_NAME ":\"ENCR_MODE\","
        MAPCLI_BSSINFO_ATTR_KEY_NAME ":\"KEY\","
        MAPCLI_BSSINFO_ATTR_BACKHAUL_NAME ":BACKHAUL,"
        MAPCLI_BSSINFO_ATTR_FRONTHUAL_NAME ":FRONTHAUL"
        "}]}";
static int mapcli_set_conf(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    int i;
    struct blob_attr *tb[ARRAY_SIZE(mapcli_conf_policy)];
    struct bssInfo *bss_infos = NULL;
    uint32_t bss_nums = 0;

    blobmsg_parse(mapcli_conf_policy, ARRAY_SIZE(mapcli_conf_policy),
		tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);

    for (i = 0; i < ARRAY_SIZE(mapcli_conf_policy) - 1; i++)
    {
        if (!tb[i])
            continue;

#define MAPCLI_BLOBMSG_SET_U32_CONF(_c, _s) \
        if (!strcmp(blobmsg_name(tb[i]), #_c))   _s._c = blobmsg_get_u32(tb[i])

        MAPCLI_BLOBMSG_SET_U32_CONF(ap_metrics_intval, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(assoc_sta_intval, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(unassoc_sta_intval, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(support_agent_steering, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(monitor_dwell, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(rcpi_margin, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(wait_roaming, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(unassoc_sta_maxnums, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(retries, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(wait_ack, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(search_period, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(autoconf_wait, map_config);
        MAPCLI_BLOBMSG_SET_U32_CONF(hide_backhaul_ssid, map_config);

        if (!strcmp(blobmsg_name(tb[i]), "wsc_data"))
            mapcli_set_wsc_config(tb[i]);

        if (!strcmp(blobmsg_name(tb[i]), "dbg_level"))
        {
            PLATFORM_PRINTF_DEBUG_SET_VERBOSITY_LEVEL(blobmsg_get_u32(tb[i]));
            map_config.dbg_level = blobmsg_get_u32(tb[i]);
        }

        MAPCLI_BLOBMSG_SET_U32_CONF(ClientCapaQ_uponTopoR, map_config.topology_policy);
        MAPCLI_BLOBMSG_SET_U32_CONF(APMetricsQ_uponTopoR, map_config.topology_policy);
        MAPCLI_BLOBMSG_SET_U32_CONF(AssocedStaLinkQ_uponTopoR, map_config.topology_policy);
        MAPCLI_BLOBMSG_SET_U32_CONF(filter_1905packet, map_config);
    }

    if (mapcli_parse_wsc_bssinfos(tb[i], &bss_infos, &bss_nums) < 0)
    {
        mapcli_fill_result(MAPCLI_RESULT_INVALID_VALUE,
                method_set_wsc_bssinfos_help_string);
        return ubus_send_reply(ctx, req, b.head);
    }
    mapcli_set_wsc_bssinfos(bss_infos, bss_nums);
    free(bss_infos);

    mapcli_fill_result(MAPCLI_RESULT_SUCCESS, NULL);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapcli_get_conf(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    void *table;
    void *list;
    char ssid[SSID_MAX_LEN + 1];
    const char *auth_mode = "", *encr_mode = "";
    struct wscRegistrarInfo *wsc_reginfo;
    blob_buf_init(&b, 0);

#define MAPCLI_BLOBMSG_ADD_CONF(_t, _c, _s) blobmsg_add_##_t(&b, #_c, _s._c)
    MAPCLI_BLOBMSG_ADD_CONF(u32, ap_metrics_intval, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, assoc_sta_intval, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, unassoc_sta_intval, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, support_agent_steering, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, monitor_dwell, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, rcpi_margin, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, wait_roaming, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, unassoc_sta_maxnums, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, retries, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, wait_ack, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, search_period, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, autoconf_wait, map_config);
    MAPCLI_BLOBMSG_ADD_CONF(u32, hide_backhaul_ssid, map_config);

    table = blobmsg_open_table(&b, "wsc_data");
    MAPCLI_BLOBMSG_ADD_CONF(string, device_name, map_config.wsc_data);
    MAPCLI_BLOBMSG_ADD_CONF(string, manufacturer_name, map_config.wsc_data);
    MAPCLI_BLOBMSG_ADD_CONF(string, model_name, map_config.wsc_data);
    MAPCLI_BLOBMSG_ADD_CONF(string, model_number, map_config.wsc_data);
    MAPCLI_BLOBMSG_ADD_CONF(string, serial_number, map_config.wsc_data);
    blobmsg_close_table(&b, table);

    MAPCLI_BLOBMSG_ADD_CONF(u32, dbg_level, map_config);

    MAPCLI_BLOBMSG_ADD_CONF(u32, ClientCapaQ_uponTopoR, map_config.topology_policy);
    MAPCLI_BLOBMSG_ADD_CONF(u32, APMetricsQ_uponTopoR, map_config.topology_policy);
    MAPCLI_BLOBMSG_ADD_CONF(u32, AssocedStaLinkQ_uponTopoR, map_config.topology_policy);
    MAPCLI_BLOBMSG_ADD_CONF(u32, filter_1905packet, map_config);

    list = blobmsg_open_array(&b, MAPCLI_WSC_REGISTRAR_BSSINFO_NAME);
    dlist_for_each(wsc_reginfo, registrar.wsc, l)
    {
        table = blobmsg_open_table(&b, NULL);
        blobmsg_add_addr(&b, MAPCLI_BSSINFO_ATTR_AL_MAC_NAME, wsc_reginfo->bss_info.bssid);
        blobmsg_add_string(&b, MAPCLI_BSSINFO_ATTR_OPCLASS_NAME, wsc_reginfo->bss_info.opclass);
        memcpy(ssid, wsc_reginfo->bss_info.ssid.ssid, wsc_reginfo->bss_info.ssid.length);
        ssid[wsc_reginfo->bss_info.ssid.length] = '\0';
        blobmsg_add_string(&b, MAPCLI_BSSINFO_ATTR_SSID_NAME, ssid);

        if (wsc_reginfo->bss_info.auth_mode == auth_mode_open)
            auth_mode = "open";
        else if (wsc_reginfo->bss_info.auth_mode == auth_mode_wpapsk)
            auth_mode = "wpapsk";
        else if (wsc_reginfo->bss_info.auth_mode == auth_mode_wpa2psk)
            auth_mode = "wpa2psk";
        blobmsg_add_string(&b, MAPCLI_BSSINFO_ATTR_AUTH_MODE_NAME, auth_mode);

        if (wsc_reginfo->bss_info.encryp == WPS_ENCR_NONE)
            encr_mode = "none";
        else if (wsc_reginfo->bss_info.encryp == WPS_ENCR_AES)
            encr_mode = "aes";
        else if (wsc_reginfo->bss_info.encryp == WPS_ENCR_AES_TKIP)
            encr_mode = "aes_tikp";
        blobmsg_add_string(&b, MAPCLI_BSSINFO_ATTR_ENCRYPT_MODE_NAME, encr_mode);

        blobmsg_add_string(&b, MAPCLI_BSSINFO_ATTR_KEY_NAME, (char *)wsc_reginfo->bss_info.key.key);
        blobmsg_add_u32(&b, MAPCLI_BSSINFO_ATTR_BACKHAUL_NAME, wsc_reginfo->bss_info.backhaul);
        blobmsg_add_u32(&b, MAPCLI_BSSINFO_ATTR_FRONTHUAL_NAME, wsc_reginfo->bss_info.fronthaul);
        blobmsg_close_table(&b, table);
    }
    blobmsg_close_array(&b, list);

    return ubus_send_reply(ctx, req, b.head);
}

static int mapcli_sync_bsscfgs(struct ubus_context *ctx,
        struct ubus_object *obj, struct ubus_request_data *req,
        const char *method, struct blob_attr *msg)
{
    blob_buf_init(&b, 0);

    REGISTRAR_SYNC_BSSCFGS();

    mapcli_fill_result(MAPCLI_RESULT_SUCCESS, NULL);
    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPCLI_WPS_ATTR_IFNAME = 0,

    NUM_MAPCLI_WPS_ATTRS,
};

static const struct blobmsg_policy mapcli_wps_policy[] =
{
	[MAPCLI_WPS_ATTR_IFNAME] = { .name = MAPCLI_WPS_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
};

static const char *method_wps_help_string =
    "ubus call " MAPCLI_OBJ_NAME " " MAPCLI_METHOD_START_WPS_NAME "{\""
        MAPCLI_WPS_ATTR_IFNAME_NAME ":\"IFNAME\"}";
static int mapcli_start_wps(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAPCLI_WPS_ATTRS];
    const char *ifname;
    struct interface *intf;
    struct interfaceWifi *ifw;

	blobmsg_parse(mapcli_wps_policy, NUM_MAPCLI_WPS_ATTRS,
		tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);

    ifname = blobmsg_get_string(tb[MAPCLI_WPS_ATTR_IFNAME]);
    if (!ifname)
    {
        mapcli_fill_result(MAPCLI_RESULT_MISS_ARGUMENT, method_wps_help_string);
        return ubus_send_reply(ctx, req, b.head);
    }

    intf = findLocalInterface(ifname);
    if (!intf || interface_type_wifi != intf->type)
    {
        mapcli_fill_result(MAPCLI_RESULT_CONTEXT_NOT_FOUND, NULL);
        return ubus_send_reply(ctx, req, b.head);
    }

    ifw = (struct interfaceWifi *)intf;
    if (!ifw->radio)
    {
        mapcli_fill_result(MAPCLI_RESULT_UNKNOWN_ERROR, NULL);
        return ubus_send_reply(ctx, req, b.head);
    }

    IFW_START_WPS(ifw);

    mapcli_fill_result(MAPCLI_RESULT_SUCCESS, NULL);
    return ubus_send_reply(ctx, req, b.head);
}

struct mapcli_1905tlv {
    uint8_t type;
    uint16_t len;
    uint8_t *val;
};

static uint8_t stream_1905[MAX_NETWORK_SEGMENT_SIZE];
static void mapcli_build_and_send_1905(const char *ifname, uint8_t *alid, uint16_t type,
        uint16_t mid, struct mapcli_1905tlv *tlvs, uint32_t tlv_num)
{
    const uint8_t version = CMDU_MESSAGE_VERSION_1905_1_2013;
    const uint8_t reserved = 0, indicator = 0;
    uint8_t frag = 0;
    uint32_t ind = 0;
    uint8_t *s = stream_1905;
    uint16_t tlv_len = 0;

    if (!tlvs)
        return;

    while (ind < tlv_num)
    {
        if (s == stream_1905)
        {
            _I1B(&version, &s);
            _I1B(&reserved, &s);
            _I2B(&type, &s);
            _I2B(&mid, &s);
            _I1B(&frag, &s);
            _I1B(&indicator, &s);
        }

        if (tlvs)
            tlv_len = tlvs[ind].len;
        if (s - stream_1905 + tlv_len + 1 + 2 > MAX_NETWORK_SEGMENT_SIZE)
        {
            PLATFORM_SEND_RAW_PACKET(ifname, alid, DMalMacGet(),
                  ETHERTYPE_1905, stream_1905, s - stream_1905);
            frag++;
            s = stream_1905;
            continue;
        }

        if (tlvs)
        {
            _I1B(&tlvs[ind].type, &s);
            _I2B(&tlvs[ind].len, &s);
            if (tlvs[ind].len && tlvs[ind].val)
                _InB(tlvs[ind].val, &s, tlvs[ind].len);
        }

        ind++;
    }

    if (s != stream_1905) {
        stream_1905[INDICATOR_OFFSET_IN_CMDU] |= 0x80;
        PLATFORM_SEND_RAW_PACKET(ifname, alid, DMalMacGet(),
              ETHERTYPE_1905, stream_1905, s - stream_1905);
    }
    return;
}

static int mapcli_parse_oct_string(uint8_t *octs, uint16_t len, char *str)
{
    uint32_t val;
    uint16_t i = 0;
    char *next;

    if (!octs)
        return 0;

    if (len && !str)
        return -1;

    while(i < len)
    {
        while (isspace(*str))
            ++str;
        if (*str == '\0')
            break;
        val = strtoul(str, &next, 16);
        if ((next - str) != 2 || val > 255)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("raw hex event parsed failed\n");
            return -1;
        }
        printf("[%u] = %02x\n", i, val);
		octs[i++] = (uint8_t)val;
		str = next;
    }

    if (i < len)
        return -1;
    return 0;
}

enum {
    MAPCLI_1905TLV_ATTR_TYPE = 0,
    MAPCLI_1905TLV_ATTR_LEN,
    MAPCLI_1905TLV_ATTR_VALUE,

    NUM_MAPCLI_1905TLV_ATTRS,
};

static const struct blobmsg_policy mapcli_1905tlv_policy[] =
{
	[MAPCLI_1905TLV_ATTR_TYPE] = { .name = MAPCLI_1905TLV_ATTR_TYPE_NAME, .type = BLOBMSG_TYPE_INT32},
	[MAPCLI_1905TLV_ATTR_LEN] = { .name = MAPCLI_1905TLV_ATTR_LEN_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_1905TLV_ATTR_VALUE] = { .name = MAPCLI_1905TLV_ATTR_VALUE_NAME, .type = BLOBMSG_TYPE_STRING },
};

static int mapcli_parse_1905_tlv(struct blob_attr *attr, struct mapcli_1905tlv *tlv)
{
	struct blob_attr *tb[NUM_MAPCLI_1905TLV_ATTRS];

	blobmsg_parse(mapcli_1905tlv_policy, NUM_MAPCLI_1905TLV_ATTRS,
		tb, blobmsg_data(attr), blobmsg_len(attr));

    if (!tb[MAPCLI_1905TLV_ATTR_TYPE]
            || !tb[MAPCLI_1905TLV_ATTR_LEN])
        return -1;

    tlv->type = (uint8_t)blobmsg_get_u32(tb[MAPCLI_1905TLV_ATTR_TYPE]);
    tlv->len = (uint16_t)blobmsg_get_u32(tb[MAPCLI_1905TLV_ATTR_LEN]);
    tlv->val = NULL;
    if (tlv->len)
        tlv->val = (uint8_t *)malloc(tlv->len);

    return mapcli_parse_oct_string(tlv->val, tlv->len,
            blobmsg_get_string(tb[MAPCLI_1905TLV_ATTR_VALUE]));
}

static void mapcli_free_1905_tlvs(struct mapcli_1905tlv *tlv, uint32_t tlv_num)
{
    uint32_t i;

    if (!tlv)
        return;

    for (i = 0; i < tlv_num; i++)
    {
        if (tlv[i].val)
            free(tlv[i].val);
    }
    free(tlv);
}

static int mapcli_parse_1905_tlvs(struct blob_attr *attrs,
    struct mapcli_1905tlv **tlvs, uint32_t *tlv_num)
{
    struct blob_attr *attr;
    uint32_t nums = 1, i = 0;
    int rem;
    struct mapcli_1905tlv *ret;

    *tlvs = NULL;
    *tlv_num = 0;

    if (attrs)
    {
        blobmsg_for_each_attr(attr, attrs, rem)
            nums++;
    }
    ret = (struct mapcli_1905tlv *)malloc(sizeof(**tlvs) * nums);
    memset(ret, 0, sizeof(*ret) * nums);

    if (attrs)
    {
        blobmsg_for_each_attr(attr, attrs, rem)
        {
            if (mapcli_parse_1905_tlv(attr, &ret[i++]) < 0)
            {
                mapcli_free_1905_tlvs(ret, nums);
                return -1;
            }
        }
    }

    ret[i].type = TLV_TYPE_END_OF_MESSAGE;
    ret[i].len = 0;
    ret[i].val = NULL;

    *tlvs = ret;
    *tlv_num = nums;

    return 0;
}

enum {
    MAPCLI_1905_ATTR_IFNAME = 0,
    MAPCLI_1905_ATTR_DEST_ALID,
    MAPCLI_1905_ATTR_TYPE,
    MAPCLI_1905_ATTR_MID,
    MAPCLI_1905_ATTR_TLVS,

    NUM_MAPCLI_1905_ATTRS,
};

static const struct blobmsg_policy mapcli_1905_policy[] =
{
	[MAPCLI_1905_ATTR_IFNAME] = { .name = MAPCLI_1905_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_1905_ATTR_DEST_ALID] = { .name = MAPCLI_1905_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_1905_ATTR_TYPE] = { .name = MAPCLI_1905_ATTR_TYPE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_1905_ATTR_MID] = { .name = MAPCLI_1905_ATTR_MID_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_1905_ATTR_TLVS] = { .name = MAPCLI_1905_ATTR_TLVS_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static const char *method_1905_help_string =
    "ubus call " MAPCLI_OBJ_NAME " " MAPCLI_METHOD_SEND_1905_NAME " {"
        MAPCLI_1905_ATTR_IFNAME_NAME ":\"IFNAME\","
        MAPCLI_1905_ATTR_DEST_ALID_NAME ":\"MAC_STRING\","
        MAPCLI_1905_ATTR_TYPE_NAME ":TYPE,"
        MAPCLI_1905_ATTR_MID_NAME ":MID,"
        MAPCLI_1905_ATTR_TLVS_NAME ":[{"
        MAPCLI_1905TLV_ATTR_TYPE_NAME ":TYPE,"
        MAPCLI_1905TLV_ATTR_LEN_NAME ":LEN,"
        MAPCLI_1905TLV_ATTR_VALUE_NAME ":\"OCT_STRING\""
        "}]}";
static int mapcli_send_1905(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAPCLI_1905_ATTRS];
    const char *ifname, *alid_str;
    uint32_t type;
	struct ether_addr macaddr;
    struct mapcli_1905tlv *tlvs = NULL;
    uint32_t tlv_num = 0;
    uint16_t mid = getNextMid();

	blobmsg_parse(mapcli_1905_policy, NUM_MAPCLI_1905_ATTRS,
		tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);

    ifname = blobmsg_get_string(tb[MAPCLI_1905_ATTR_IFNAME]);
    alid_str = blobmsg_get_string(tb[MAPCLI_1905_ATTR_DEST_ALID]);
    if (!alid_str || !tb[MAPCLI_1905_ATTR_TYPE])
    {
        mapcli_fill_result(MAPCLI_RESULT_MISS_ARGUMENT, method_1905_help_string);
        return ubus_send_reply(ctx, req, b.head);
    }

	if (ether_aton_r(alid_str, &macaddr) == NULL)
    {
        mapcli_fill_result(MAPCLI_RESULT_INVALID_VALUE, method_1905_help_string);
        return ubus_send_reply(ctx, req, b.head);
    }

    if (!ifname)
    {
        struct alDevice *alDev = alDeviceFind(macaddr.ether_addr_octet);
        if (alDev)
            ifname = alDev->receiving_interface_name;
    }

    if (!ifname)
    {
        mapcli_fill_result(MAPCLI_RESULT_MISS_ARGUMENT, method_1905_help_string);
        return ubus_send_reply(ctx, req, b.head);
    }

    type = blobmsg_get_u32(tb[MAPCLI_1905_ATTR_TYPE]);


    if (tb[MAPCLI_1905_ATTR_MID])
        mid = blobmsg_get_u32(tb[MAPCLI_1905_ATTR_MID]);
    else
        mid = getNextMid();

    PLATFORM_PRINTF_DEBUG_INFO("try to send 1905 frame[type: 0x%04x, mid: 0x%04x (decimal:%u)] to "
            MACFMT " from interface %s\n", type, mid, mid,
            MACARG(macaddr.ether_addr_octet), ifname);

    if (type == CMDU_TYPE_COMBINED_INFRASTRUCTURE_METRICS)
    {
        struct alDevice *neighbor = alDeviceFind(macaddr.ether_addr_octet);
        if (neighbor)
        {
            send1905CombinedInfrastructureMetrics(neighbor, ifname, mid);
            goto __end;
        }
    }

    if (mapcli_parse_1905_tlvs(tb[MAPCLI_1905_ATTR_TLVS], &tlvs, &tlv_num) < 0)
    {
        mapcli_fill_result(MAPCLI_RESULT_INVALID_VALUE, method_1905_help_string);
        return ubus_send_reply(ctx, req, b.head);
    }

    mapcli_build_and_send_1905(ifname, macaddr.ether_addr_octet, type, mid, tlvs, tlv_num);

    mapcli_free_1905_tlvs(tlvs, tlv_num);

__end:
    mapcli_fill_result(MAPCLI_RESULT_SUCCESS, NULL);
    blobmsg_add_u32(&b, MAPCLI_1905_ATTR_MID_NAME, mid);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPCLI_PARAM_ATTR_WIPHY = 0,
    MAPCLI_PARAM_ATTR_WDEV,
    MAPCLI_PARAM_ATTR_OPCLASS,
    MAPCLI_PARAM_ATTR_CHANNEL,
    MAPCLI_PARAM_ATTR_TXPOWER,
    MAPCLI_PARAM_ATTR_SSID,
    MAPCLI_PARAM_ATTR_AUTHMODE,
    MAPCLI_PARAM_ATTR_KEY,
    MAPCLI_PARAM_ATTR_BACKHUAL,
    MAPCLI_PARAM_ATTR_FRONTHUAL,
    MAPCLI_PARAM_ATTR_STATIONS,
    MAPCLI_PARAM_ATTR_FRAME,
    MAPCLI_PARAM_ATTR_MAC,
    MAPCLI_PARAM_ATTR_BLOCK,
    MAPCLI_PARAM_ATTR_RENEW,
    MAPCLI_PARAM_ATTR_DUMP_TYPE,
    MAPCLI_PARAM_ATTR_DUMP_SIZE,
    MAPCLI_PARAM_ATTR_DEAUTH_CODE,
    MAPCLI_PARAM_ATTR_TARGET_BSSID,
    MAPCLI_PARAM_ATTR_TARGET_OPCLASS,
    MAPCLI_PARAM_ATTR_TARGET_CHANNEL,
    MAPCLI_PARAM_ATTR_BTM_REQMODE,

    NUM_MAPCLI_PARAM_ATTRS
};

static const struct blobmsg_policy mapcli_param_policy[] = {
	[MAPCLI_PARAM_ATTR_WIPHY] = { .name = MAPCLI_PARAM_ATTR_WIPHY_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_WDEV] = { .name = MAPCLI_PARAM_ATTR_WDEV_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_OPCLASS] = { .name = MAPCLI_PARAM_ATTR_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_CHANNEL] = { .name = MAPCLI_PARAM_ATTR_CHANNEL_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_TXPOWER] = { .name = MAPCLI_PARAM_ATTR_TXPOWER_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_SSID] = { .name = MAPCLI_PARAM_ATTR_SSID_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_AUTHMODE] = { .name = MAPCLI_PARAM_ATTR_AUTHMODE_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_KEY] = { .name = MAPCLI_PARAM_ATTR_KEY_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_BACKHUAL] = { .name = MAPCLI_PARAM_ATTR_BACKHUAL_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_FRONTHUAL] = { .name = MAPCLI_PARAM_ATTR_FRONTHUAL_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_STATIONS] = { .name = MAPCLI_PARAM_ATTR_STATIONS_NAME, .type = BLOBMSG_TYPE_ARRAY },
	[MAPCLI_PARAM_ATTR_FRAME] = { .name = MAPCLI_PARAM_ATTR_FRAME_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_MAC] = { .name = MAPCLI_PARAM_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_BLOCK] = { .name = MAPCLI_PARAM_ATTR_BLOCK_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_RENEW] = { .name = MAPCLI_PARAM_ATTR_RENEW_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_DUMP_TYPE] = { .name = MAPCLI_PARAM_ATTR_DUMP_TYPE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_DUMP_SIZE] = { .name = MAPCLI_PARAM_ATTR_DUMP_SIZE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_DEAUTH_CODE] = { .name = MAPCLI_PARAM_ATTR_DEAUTH_CODE_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_TARGET_BSSID] = { .name = MAPCLI_PARAM_ATTR_TARGET_BSSID_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_PARAM_ATTR_TARGET_OPCLASS] = { .name = MAPCLI_PARAM_ATTR_TARGET_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_TARGET_CHANNEL] = { .name = MAPCLI_PARAM_ATTR_TARGET_CHANNEL_NAME, .type = BLOBMSG_TYPE_INT32 },
	[MAPCLI_PARAM_ATTR_BTM_REQMODE] = { .name = MAPCLI_PARAM_ATTR_BTM_REQMODE_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int mapcli_test_create_wdev(struct blob_attr *param_attr)
{
	struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    struct radio *r;
    struct bssInfo bss;
    const char *authmode;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WIPHY])
        return -1;

    r = findLocalRadio(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WIPHY]));
    if (!r)
        return -1;

    memset(&bss, 0, sizeof(bss));
    if (tb[MAPCLI_PARAM_ATTR_SSID])
    {
        strncpy((char *)bss.ssid.ssid, blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_SSID]), SSID_MAX_LEN -1);
        bss.ssid.length = strlen((char *)bss.ssid.ssid);
    }

    authmode = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_AUTHMODE]);
    if (authmode)
    {
        if (!strcmp(authmode, "open"))
            bss.auth_mode = auth_mode_open;
        else if (!strcmp(authmode, "shared"))
            bss.auth_mode = auth_mode_wpapsk;
        else if (!strcmp(authmode, "wpapsk"))
            bss.auth_mode = auth_mode_wpapsk;
        else if (!strcmp(authmode, "wpa2psk"))
            bss.auth_mode = auth_mode_wpa2psk;
    }

    if (tb[MAPCLI_PARAM_ATTR_KEY])
    {
        strncpy((char *)bss.key.key, blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_KEY]), 64);
        bss.key.len = strlen((char *)bss.key.key);
    }

    if (tb[MAPCLI_PARAM_ATTR_BACKHUAL]
            && blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_BACKHUAL]))
            bss.backhaul = true;

    if (tb[MAPCLI_PARAM_ATTR_FRONTHUAL]
            && blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_FRONTHUAL]))
            bss.fronthaul = true;

    radioAddAp(r, &bss);

    return 0;
}

static int mapcli_test_set_channel(struct blob_attr *param_attr)
{
	struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    struct radio *r;
    uint8_t opclass, channel, txpower = 0xff;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WIPHY]
            || !tb[MAPCLI_PARAM_ATTR_OPCLASS]
            || !tb[MAPCLI_PARAM_ATTR_CHANNEL])
        return -1;

    r = findLocalRadio(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WIPHY]));
    if (!r)
        return -1;
    opclass = (uint8_t)blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_OPCLASS]);
    channel = (uint8_t)blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_CHANNEL]);
    if (tb[MAPCLI_PARAM_ATTR_TXPOWER])
        txpower = (uint8_t)blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_TXPOWER]);

    RADIO_SET_OPERATING_CHANNEL(r, opclass, channel, txpower);

    return 0;
}

static int mapcli_test_send_frame(struct blob_attr *param_attr)
{
	struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    struct interface *intf;
    uint8_t *frame = NULL;
    uint32_t frame_len = 0;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WDEV]
            || !tb[MAPCLI_PARAM_ATTR_FRAME])
        return -1;

    intf = findLocalInterface(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WDEV]));
    if (!intf || intf->type != interface_type_wifi)
        return -1;

    if (mapcli_get_binary(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_FRAME]),
                &frame, &frame_len) < 0)
        return -1;

    IFW_SEND_FRAME((struct interfaceWifi *)intf, frame, frame_len);

    free(frame);

    return 0;
}

static int mapcli_test_conf_backhual(struct blob_attr *param_attr)
{
	struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    struct radio *r;
    struct ssid ssid;
    struct key key;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WIPHY]
            || !tb[MAPCLI_PARAM_ATTR_SSID]
            || !tb[MAPCLI_PARAM_ATTR_KEY])
        return -1;

    r = findLocalRadio(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WIPHY]));
    if (!r)
        return -1;

    strncpy((char *)ssid.ssid, blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_SSID]), SSID_MAX_LEN -1);
    ssid.length = strlen((char *)ssid.ssid);

    strncpy((char *)key.key, blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_KEY]), 64);
    key.len = strlen((char *)key.key);

    if (r->setBackhaulSsid != NULL)
        r->setBackhaulSsid(r, &ssid, &key);

    return 0;
}

static int mapcli_test_filter_client(struct blob_attr *param_attr)
{
	struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    uint32_t block = 1;
    struct interface *intf;
    struct interfaceWifi *ifw;
	struct ether_addr macaddr;
    const char *mac_str;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WDEV]
            || !tb[MAPCLI_PARAM_ATTR_MAC])
        return -1;

    intf = findLocalInterface(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WDEV]));
    if (!intf || interface_type_wifi != intf->type)
        return -1;

    ifw = (struct interfaceWifi *)intf;
    if (!ifw->radio)
        return -1;

    mac_str = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_MAC]);
	if (ether_aton_r(mac_str, &macaddr) == NULL)
        return -1;

    if (tb[MAPCLI_PARAM_ATTR_BLOCK])
        block = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_BLOCK]);

    if (block)
        IFW_BLOCK_CLIENT(ifw, macaddr.ether_addr_octet);
    else
        IFW_UNBLOCK_CLIENT(ifw, macaddr.ether_addr_octet);

    return 0;
}

static int mapcli_test_tear_down(struct blob_attr *param_attr)
{
	struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    const char *wiphy, *wdev;
    struct radio *r;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    wiphy = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WIPHY]);
    wdev = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WDEV]);

    dlist_for_each(r, local_device->radios, l)
    {
        int i;

        if (wiphy && strcmp(r->name, wiphy))
            continue;

        if (!wdev)
        {
            RADIO_TEARDOWN(r);
            PLATFORM_PRINTF_DEBUG_INFO("[CLI] tear down radio %s (" MACFMT ")\n",
                r->name ? r->name : "N/A", MACARG(r->uid));
            continue;
        }

        for (i = 0; i < r->configured_bsses.length; i++)
        {
            struct interfaceWifi *ifw = r->configured_bsses.data[i];

            if (ifw->role != interface_wifi_role_ap)
                continue;

            if (ifw->i.name && strcmp(ifw->i.name, wdev))
                continue;

            PLATFORM_PRINTF_DEBUG_INFO("[CLI] tear down interface %s (" MACFMT ")\n",
                ifw->i.name ? ifw->i.name : "N/A", MACARG(ifw->i.addr));
            interfaceTearDown(&ifw->i);
        }
    }

    return 0;
}

static int mapcli_test_trigger_reconfig(struct blob_attr *param_attr)
{
    struct radio *r;
    struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    uint32_t renew = 0;
    bool imm = local_device->configured ? true : false;

    if (param_attr)
    {
        blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
            tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

        if (tb[MAPCLI_PARAM_ATTR_RENEW])
            renew = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_RENEW]);
    }

    PLATFORM_PRINTF_DEBUG_INFO("[CLI] trigger auto reconfig, renew=:%u\n", renew);
    local_device->configured = false;
    dlist_for_each(r, local_device->radios, l)
    {
        r->backhaul_only_configured = false;
        r->configured = false;
    }
    /* send the AP Autoconfig Search, then send the AP Autoconfig WSC M1 */
    if (!renew)
    {
        registrar.d = NULL;
        /* reset the configure ts to send M1 right after receiving the Response */
        if (imm)
            local_device->configure_ts = PLATFORM_GET_TIMESTAMP()
                - map_config.autoconf_wait * 1000;

        triggerAPSearchProcess();
    }
    /* send the AP Autoconfig WSC M1 */
    else
    {
        triggerDeviceAPAutoConfiguration(imm);
    }

    return 0;
}

static int mapcli_test_get_monitor_stas(struct blob_attr *param_attr)
{
    struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    struct radio *r;
    struct blob_attr *attr;
    int rem;
    uint32_t nums = 0;
    uint8_t *stas = NULL;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WIPHY])
        return -1;

    r = findLocalRadio(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WIPHY]));
    if (!r)
        return -1;

    blobmsg_for_each_attr(attr, tb[MAPCLI_PARAM_ATTR_STATIONS], rem)
    {
        char *mac_str = blobmsg_get_string(attr);
        struct ether_addr macaddr;

        if (!mac_str || ether_aton_r(mac_str, &macaddr) == NULL)
            continue;

        if (0 == nums)
            stas = (uint8_t *)memalloc(sizeof(mac_address));
        else
            stas = (uint8_t *)memrealloc(stas, sizeof(mac_address) * (nums + 1));
        memcpy(stas + nums * sizeof(mac_address), macaddr.ether_addr_octet, sizeof(mac_address));
        nums++;
    }

    RADIO_GET_MONITOR_STATS(r, stas, nums);

    if (stas)
        free(stas);

    return 0;
}

static int mapcli_test_dump_packet(struct blob_attr *param_attr)
{
    struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    uint32_t kbytes = 0;
    uint8_t type = 0;

	blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
		tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (tb[MAPCLI_PARAM_ATTR_DUMP_TYPE])
        type = (uint8_t)blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_DUMP_TYPE]);
    if (tb[MAPCLI_PARAM_ATTR_DUMP_SIZE])
        kbytes = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_DUMP_SIZE]);

    PLATFORM_SET_DUMP_PACKETS(type, kbytes);
    return 0;
}

static int mapcli_test_deauth_client(struct blob_attr *param_attr)
{
    struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    uint32_t deauth_code = 33;
    struct interface *intf;
    struct interfaceWifi *ifw;
    struct ether_addr macaddr;
    const char *mac_str;

    blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
            tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WDEV]
            || !tb[MAPCLI_PARAM_ATTR_MAC])
        return -1;

    intf = findLocalInterface(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WDEV]));
    if (!intf || interface_type_wifi != intf->type)
        return -1;

    ifw = (struct interfaceWifi *)intf;
    if (!ifw->radio)
        return -1;

    mac_str = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_MAC]);
    if (ether_aton_r(mac_str, &macaddr) == NULL)
        return -1;

    if (tb[MAPCLI_PARAM_ATTR_DEAUTH_CODE])
        deauth_code = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_DEAUTH_CODE]);

    IFW_DEAUTH_CLIENT(ifw, macaddr.ether_addr_octet, deauth_code);
    return 0;
}

static int mapcli_test_send_btm(struct blob_attr *param_attr)
{
    struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    uint8_t     *frame = NULL;
    uint32_t    frame_len = IEEE80211_MAX_MGTFRAME_LEN;
    struct interface *intf;
    struct interfaceWifi *ifw;
    struct ether_addr macaddr;
    const char *mac_str;
    struct ether_addr target_bssid;
    const char *target_bssid_str;
    uint8_t     target_opclass = 128;
    uint8_t     target_channel = 36;
    uint8_t     mode = (1 << IEEE80211_TRANSREQ_CANDIDATE_INCLUDED_SHIFT)
                       |(1 << IEEE80211_TRANSREQ_BSS_DISASSOC_SHIFT)
                       |(1 << IEEE80211_TRANSREQ_ABRIDGED_SHIFT);
    uint8_t     token = 1;
    uint16_t    disassoc = 48;

    blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
            tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WDEV]
            || !tb[MAPCLI_PARAM_ATTR_MAC]
            || !tb[MAPCLI_PARAM_ATTR_TARGET_BSSID])
        return -1;

    intf = findLocalInterface(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WDEV]));
    if (!intf || interface_type_wifi != intf->type)
        return -1;

    ifw = (struct interfaceWifi *)intf;
    if (!ifw->radio)
        return -1;

    mac_str = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_MAC]);
    if (ether_aton_r(mac_str, &macaddr) == NULL)
        return -1;

    target_bssid_str = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_TARGET_BSSID]);
    if (ether_aton_r(target_bssid_str, &target_bssid) == NULL)
        return -1;

    if (tb[MAPCLI_PARAM_ATTR_TARGET_OPCLASS])
        target_opclass = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_TARGET_OPCLASS]);

    if (tb[MAPCLI_PARAM_ATTR_TARGET_CHANNEL])
        target_channel = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_TARGET_CHANNEL]);

    if (tb[MAPCLI_PARAM_ATTR_BTM_REQMODE])
        mode = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_BTM_REQMODE]);

    frame = malloc(IEEE80211_MAX_MGTFRAME_LEN);
    mapBuildBtmRequest(ifw->bssInfo.bssid, macaddr.ether_addr_octet, token,
            target_bssid.ether_addr_octet, target_opclass, target_channel,
            mode, disassoc, frame, &frame_len);
    if (frame_len)
        IFW_SEND_FRAME(ifw, frame, frame_len);
    free(frame);
    return 0;
}

static int mapcli_test_roam_backhaul_sta(struct blob_attr *param_attr)
{
    struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    struct interface *intf;
    struct interfaceWifi *ifw;
    struct ether_addr target_bssid;
    const char *target_bssid_str;
    uint8_t     target_opclass = 128;
    uint8_t     target_channel = 36;

    blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
            tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WDEV]
            || !tb[MAPCLI_PARAM_ATTR_TARGET_BSSID])
        return -1;

    intf = findLocalInterface(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WDEV]));
    if (!intf || interface_type_wifi != intf->type)
        return -1;

    ifw = (struct interfaceWifi *)intf;
    if (!ifw->radio)
        return -1;

    target_bssid_str = blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_TARGET_BSSID]);
    if (ether_aton_r(target_bssid_str, &target_bssid) == NULL)
        return -1;

    if (tb[MAPCLI_PARAM_ATTR_TARGET_OPCLASS])
        target_opclass = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_TARGET_OPCLASS]);

    if (tb[MAPCLI_PARAM_ATTR_TARGET_CHANNEL])
        target_channel = blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_TARGET_CHANNEL]);

    IFW_ROAM_STA(ifw, target_bssid.ether_addr_octet, target_opclass, target_channel);
    return 0;
}

static int mapcli_test_start_monitor(struct blob_attr *param_attr)
{
    struct blob_attr *tb[NUM_MAPCLI_PARAM_ATTRS];
    struct radio *r;
    uint8_t opclass, channel;

    blobmsg_parse(mapcli_param_policy, NUM_MAPCLI_PARAM_ATTRS,
            tb, blobmsg_data(param_attr), blobmsg_len(param_attr));

    if (!tb[MAPCLI_PARAM_ATTR_WIPHY] ||
        !tb[MAPCLI_PARAM_ATTR_OPCLASS] || !tb[MAPCLI_PARAM_ATTR_CHANNEL])
	return -1;

    r = findLocalRadio(blobmsg_get_string(tb[MAPCLI_PARAM_ATTR_WIPHY]));
    if (!r)
        return -1;

    opclass = (uint8_t)blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_OPCLASS]);
    channel = (uint8_t)blobmsg_get_u32(tb[MAPCLI_PARAM_ATTR_CHANNEL]);

    if (!findOpclassAndChannel(r, opclass, channel))
        return -1;

    if (r->monitor_offchan
        || (r->monitor_onchan && channel == r->chan))
    {
        RADIO_MONITOR_CHANNEL(r, opclass, channel);
        return 0;
    }
    else
        return -1;
}

struct mapcli_test_subcmd {
    const char *name;
    const char *help;
    int (*cmd)(struct blob_attr *);
};

static const struct mapcli_test_subcmd mapcli_tests[] =
{
    {"create_wdev", "{\"" MAPCLI_PARAM_ATTR_WIPHY_NAME "\":,\""
            MAPCLI_PARAM_ATTR_SSID_NAME "\":,\""
            MAPCLI_PARAM_ATTR_AUTHMODE_NAME "\":,"
            MAPCLI_PARAM_ATTR_KEY_NAME "\":,"
            MAPCLI_PARAM_ATTR_BACKHUAL_NAME "\":,"
            MAPCLI_PARAM_ATTR_FRONTHUAL_NAME "\":}",
        mapcli_test_create_wdev},
    {"set_channel", "{\"" MAPCLI_PARAM_ATTR_WIPHY_NAME "\":,\""
            MAPCLI_PARAM_ATTR_OPCLASS_NAME "\":,\""
            MAPCLI_PARAM_ATTR_CHANNEL_NAME "\":,"
            MAPCLI_PARAM_ATTR_TXPOWER_NAME "\":}",
        mapcli_test_set_channel},
    {"send_frame", "{\"" MAPCLI_PARAM_ATTR_WDEV_NAME "\":,\""
            MAPCLI_PARAM_ATTR_FRAME_NAME "\":}",
        mapcli_test_send_frame},
    {"conf_backhaul", "{\"" MAPCLI_PARAM_ATTR_WIPHY_NAME "\":,\""
            MAPCLI_PARAM_ATTR_SSID_NAME "\":,\""
            MAPCLI_PARAM_ATTR_KEY_NAME "\":}",
        mapcli_test_conf_backhual},
    {"filter_client", "{\"" MAPCLI_PARAM_ATTR_WDEV_NAME "\":,\""
            MAPCLI_PARAM_ATTR_MAC_NAME "\":,\""
            MAPCLI_PARAM_ATTR_BLOCK_NAME "\":}",
        mapcli_test_filter_client},
    {"tear_down", "{\"" MAPCLI_PARAM_ATTR_WIPHY_NAME "\":,\""
            MAPCLI_PARAM_ATTR_WDEV_NAME "\":}",
        mapcli_test_tear_down},
    {"reconfig", "{}",
        mapcli_test_trigger_reconfig},
    {"get_monitor_stats", "{\"" MAPCLI_PARAM_ATTR_WIPHY_NAME "\":,\""
            MAPCLI_PARAM_ATTR_STATIONS_NAME "\": []}",
        mapcli_test_get_monitor_stas},
    {"dump_packet", "{\"" MAPCLI_PARAM_ATTR_DUMP_TYPE_NAME "\":,\""
            MAPCLI_PARAM_ATTR_DUMP_SIZE_NAME "\":}",
        mapcli_test_dump_packet},
    {"deauth_client", "{\"" MAPCLI_PARAM_ATTR_WDEV_NAME "\":,\""
            MAPCLI_PARAM_ATTR_MAC_NAME "\":,\""
            MAPCLI_PARAM_ATTR_DEAUTH_CODE_NAME "\":}",
        mapcli_test_deauth_client},
    {"send_btm", "{\"" MAPCLI_PARAM_ATTR_WDEV_NAME "\":,\""
            MAPCLI_PARAM_ATTR_MAC_NAME "\":,\""
            MAPCLI_PARAM_ATTR_TARGET_BSSID_NAME "\":,\""
            MAPCLI_PARAM_ATTR_TARGET_OPCLASS_NAME "\":,\""
            MAPCLI_PARAM_ATTR_TARGET_CHANNEL_NAME "\":,\""
            MAPCLI_PARAM_ATTR_BTM_REQMODE_NAME "\":}",
        mapcli_test_send_btm},
    {"roam_backhaul_sta", "{\"" MAPCLI_PARAM_ATTR_WDEV_NAME "\":,\""
            MAPCLI_PARAM_ATTR_TARGET_BSSID_NAME "\":,\""
            MAPCLI_PARAM_ATTR_TARGET_OPCLASS_NAME "\":,\""
            MAPCLI_PARAM_ATTR_TARGET_CHANNEL_NAME "\":}",
        mapcli_test_roam_backhaul_sta},
    {"start_monitor", "{\"" MAPCLI_PARAM_ATTR_WIPHY_NAME "\":,\""
            MAPCLI_PARAM_ATTR_OPCLASS_NAME "\":,\""
            MAPCLI_PARAM_ATTR_CHANNEL_NAME "\":}",
        mapcli_test_start_monitor},
};

static const struct mapcli_test_subcmd *mapcli_test_get_subcmd(const char *name)
{
    int i;

    if (!name)
        return NULL;

    for (i = 0; i < ARRAY_SIZE(mapcli_tests); i++)
    {
        if (!strcmp(name, mapcli_tests[i].name))
            return &mapcli_tests[i];
    }
    return NULL;
}

enum {
    MAPCLI_TEST_ATTR_SUBCMD = 0,
    MAPCLI_TEST_ATTR_PARAMS,

    NUM_MAPCLI_TEST_ATTRS
};

static const struct blobmsg_policy mapcli_test_policy[] = {
	[MAPCLI_TEST_ATTR_SUBCMD] = { .name = MAPCLI_ATTR_SUBCMD_NAME, .type = BLOBMSG_TYPE_STRING },
	[MAPCLI_TEST_ATTR_PARAMS] = { .name = MAPCLI_ATTR_PARAMS_NAME, .type = BLOBMSG_TYPE_TABLE },
};

static const char *method_test_help_string =
    "ubus call " MAPCLI_OBJ_NAME " " MAPCLI_METHOD_TEST_NAME "{\""
        MAPCLI_ATTR_SUBCMD_NAME ":\"SUBTYPE\","
        MAPCLI_ATTR_PARAMS_NAME ":{PARAMS}";
static int mapcli_test(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[NUM_MAPCLI_TEST_ATTRS];
    const struct mapcli_test_subcmd *subcmd;
    int ret = -1;

	blobmsg_parse(mapcli_test_policy, NUM_MAPCLI_TEST_ATTRS,
		tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);

    subcmd = mapcli_test_get_subcmd(blobmsg_get_string(tb[MAPCLI_TEST_ATTR_SUBCMD]));
    if (!subcmd)
    {
        mapcli_fill_result(MAPCLI_RESULT_MISS_ARGUMENT, method_test_help_string);
        return ubus_send_reply(ctx, req, b.head);
    }

    if (subcmd->cmd)
        ret = subcmd->cmd(tb[MAPCLI_TEST_ATTR_PARAMS]);

    if (ret < 0)
        mapcli_fill_result(MAPCLI_RESULT_UNKNOWN_ERROR, subcmd->help);
    else
        mapcli_fill_result(MAPCLI_RESULT_SUCCESS, NULL);
    return ubus_send_reply(ctx, req, b.head);
}

#ifdef Q_STEERING_LOGIC
static const struct blobmsg_policy mapcli_qsteering_conf_policy[] =
{
    MAPCLI_CONF_POLICY(INT32, steering_enabled),
    MAPCLI_CONF_POLICY(INT32, rcpi_boundry_to_attemp_steering),
    MAPCLI_CONF_POLICY(INT32, better_rcpi_gain_in_target_bss),
    MAPCLI_CONF_POLICY(INT32, assoc_sta_rcpi_checking_period),
    MAPCLI_CONF_POLICY(INT32, waiting_for_neighboring_rcpi_collecting_done),
    MAPCLI_CONF_POLICY(INT32, waiting_for_steering_attemp_done),
    MAPCLI_CONF_POLICY(INT32, debugging_print_level),
};

static int mapcli_set_qsteering_conf(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    int i, resend_policy_config = 0;;
    struct blob_attr *tb[ARRAY_SIZE(mapcli_qsteering_conf_policy)];

    blobmsg_parse(mapcli_qsteering_conf_policy, ARRAY_SIZE(mapcli_qsteering_conf_policy),
            tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);

    if(!registrarIsLocal())
    {
        mapcli_fill_result(MAPCLI_RESULT_NOT_SUPPORTED, "Not allowed to config at agent's end!");
        return ubus_send_reply(ctx, req, b.head);
    }

    for (i = 0; i < ARRAY_SIZE(mapcli_qsteering_conf_policy); i++)
    {
        if (!tb[i])
            continue;

#define MAPCLI_BLOBMSG_SET_U32_QSTEERING_CONF(_c, _s) \
        if (!strcmp(blobmsg_name(tb[i]), #_c))   _s._c = blobmsg_get_u32(tb[i])

        if (!strcmp(blobmsg_name(tb[i]), "steering_enabled"))
        {
            if (map_steering_config.steering_enabled && !blobmsg_get_u32(tb[i]))
                stopQSteering();
            else if (!map_steering_config.steering_enabled && blobmsg_get_u32(tb[i]))
                startQSteering();
            map_steering_config.steering_enabled = blobmsg_get_u32(tb[i]);
        }

        if (!strcmp(blobmsg_name(tb[i]), "rcpi_boundry_to_attemp_steering"))
        {
            if (map_steering_config.rcpi_boundry_to_attemp_steering != blobmsg_get_u32(tb[i]))
                resend_policy_config = 1;
            map_steering_config.rcpi_boundry_to_attemp_steering = blobmsg_get_u32(tb[i]);
        }

        if (!strcmp(blobmsg_name(tb[i]), "assoc_sta_rcpi_checking_period"))
        {
            if (map_steering_config.assoc_sta_rcpi_checking_period != blobmsg_get_u32(tb[i]))
                resend_policy_config = 1;
            map_steering_config.assoc_sta_rcpi_checking_period = blobmsg_get_u32(tb[i]);
        }

        MAPCLI_BLOBMSG_SET_U32_QSTEERING_CONF(better_rcpi_gain_in_target_bss, map_steering_config);
        MAPCLI_BLOBMSG_SET_U32_QSTEERING_CONF(waiting_for_neighboring_rcpi_collecting_done, map_steering_config);
        MAPCLI_BLOBMSG_SET_U32_QSTEERING_CONF(waiting_for_steering_attemp_done, map_steering_config);
        MAPCLI_BLOBMSG_SET_U32_QSTEERING_CONF(debugging_print_level, map_steering_config);
    }

    if (resend_policy_config)
        qSteeringResendPolicyConfig();
    mapcli_fill_result(MAPCLI_RESULT_SUCCESS, NULL);
    return ubus_send_reply(ctx, req, b.head);
}

static int mapcli_get_qsteering_conf(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    blob_buf_init(&b, 0);

    if(!registrarIsLocal())
    {
        mapcli_fill_result(MAPCLI_RESULT_NOT_SUPPORTED, "Not allowed to view the config at agent's end!");
        return ubus_send_reply(ctx, req, b.head);
    }

#define MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(_t, _c, _s) blobmsg_add_##_t(&b, #_c, _s._c)
    MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(u32, steering_enabled, map_steering_config);
    MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(u32, rcpi_boundry_to_attemp_steering, map_steering_config);
    MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(u32, better_rcpi_gain_in_target_bss, map_steering_config);
    MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(u32, assoc_sta_rcpi_checking_period, map_steering_config);
    MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(u32, waiting_for_neighboring_rcpi_collecting_done, map_steering_config);
    MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(u32, waiting_for_steering_attemp_done, map_steering_config);
    MAPCLI_BLOBMSG_ADD_QSTEERING_CONF(u32, debugging_print_level, map_steering_config);

    return ubus_send_reply(ctx, req, b.head);
}
#endif

static const struct ubus_method mapcli_methods[] = {
    UBUS_METHOD(MAPCLI_METHOD_SHOW_NAME, mapcli_show, mapcli_show_policy),
    UBUS_METHOD_NOARG(MAPCLI_METHOD_GET_CONF_NAME, mapcli_get_conf),
    UBUS_METHOD(MAPCLI_METHOD_SET_CONF_NAME, mapcli_set_conf, mapcli_conf_policy),
    UBUS_METHOD_NOARG(MAPCLI_METHOD_SYNC_BSSCFGS_NAME, mapcli_sync_bsscfgs),
    UBUS_METHOD(MAPCLI_METHOD_START_WPS_NAME, mapcli_start_wps, mapcli_wps_policy),
    UBUS_METHOD(MAPCLI_METHOD_SEND_1905_NAME, mapcli_send_1905, mapcli_1905_policy),
    UBUS_METHOD(MAPCLI_METHOD_TEST_NAME, mapcli_test, mapcli_test_policy),
#ifdef Q_STEERING_LOGIC
    UBUS_METHOD_NOARG(MAPCLI_METHOD_GET_QSTEERING_CONF_NAME, mapcli_get_qsteering_conf),
    UBUS_METHOD(MAPCLI_METHOD_SET_QSTEERING_CONF_NAME, mapcli_set_qsteering_conf, mapcli_qsteering_conf_policy),
#endif
};

static struct ubus_object_type mapcli_obj_type =
    UBUS_OBJECT_TYPE(MAPCLI_OBJ_NAME, mapcli_methods);

static struct ubus_object mapcli_obj = {
    .name = MAPCLI_OBJ_NAME,
    .type = &mapcli_obj_type,
    .methods = mapcli_methods,
    .n_methods = ARRAY_SIZE(mapcli_methods),
};

int mapcli_init(void)
{
    int ret = ubus_add_object(platform_ubus, &mapcli_obj);
    if (ret) {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to add cli ubus %s object: %s\n",
            mapcli_obj.name, ubus_strerror(ret));
        return -1;
	}

    blob_buf_init(&b, 0);

    return 0;
}

void mapcli_deinit(void)
{
	blob_buf_free(&b);
}
