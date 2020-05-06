/*
 *  Copyright (c) 2019-2020, Semiconductor Components Industries, LLC
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
 * @brief ubus map server implementation
 *
 * This file provides ubus APIs functionality for other APPs
 *
 */

#include "qdock_map_api.h"
#include "al_ubus_server.h"
#include "platform.h"
#include "datamodel.h"

struct blob_buf b;

static const char *result_strings[] =
{
    [MAPAPI_RESULT_SUCCESS] = "Successed",
    [MAPAPI_RESULT_INVALID_VALUE] = "Failed: Invalid Value",
    [MAPAPI_RESULT_INVALID_ARGUMENT] = "Failed: Invalid Argument",
    [MAPAPI_RESULT_INVALID_EXECUTION] = "Failed: Invalid Execution",
    [MAPAPI_RESULT_MISS_ARGUMENT] = "Failed: Miss Argument",
    [MAPAPI_RESULT_CONTEXT_NOT_FOUND] = "Failed: Context Not Found",
    [MAPAPI_RESULT_NOT_SUPPORTED] = "Failed: Not Supported",
    [MAPAPI_RESULT_UNKNOWN_ERROR] = "Failed: Unknown Error",
};

const struct blobmsg_policy mapapi_set_policy[NUM_MAPAPI_SET_ATTRS] = {
    [MAPAPI_SET_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_SET_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_SET_ATTR_NEIGHBOR_ALID] = { .name = MAPAPI_SET_ATTR_NEIGHBOR_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_SET_ATTR_BSSIDS] = { .name = MAPAPI_SET_ATTR_BSSIDS_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

const struct blobmsg_policy mapapi_get_map_policy[NUM_MAPAPI_GET_MAP_ATTRS] = {
    [MAPAPI_GET_MAP_ATTR_DEVICES] = { .name = MAPAPI_NETWORK_ATTR_DEVICES_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_GET_MAP_ATTR_AL_ID] = { .name = MAPAPI_DEVICE_ATTR_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_GET_MAP_ATTR_RADIOS] = { .name = MAPAPI_DEVICE_ATTR_RADIOS_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_GET_MAP_ATTR_RADIO_ID] = { .name = MAPAPI_RADIO_ATTR_ID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_GET_MAP_ATTR_BSSES] = { .name = MAPAPI_DEVICE_ATTR_BSSES_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_GET_MAP_ATTR_BSS_ID] = { .name = MAPAPI_BSS_ATTR_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_GET_MAP_ATTR_STATIONS] = { .name = MAPAPI_BSS_ATTR_STATIONS_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_GET_MAP_ATTR_STA_MAC] = { .name = MAPAPI_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_GET_MAP_ATTR_FMT_CTL] = { .name = MAPAPI_STATION_ATTR_FMT_CTL, .type = BLOBMSG_TYPE_STRING },
};

struct blobmsg_policy mapapi_param_mac_policy[NUM_MAPAPI_PARAM_MAC_ATTRS] = {
    [MAPAPI_PARAM_ATTR_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_MAC },
};


int string_to_binary(const char *bin_str, uint8_t **bins, uint32_t *len)
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

void blobmsg_add_mac(struct blob_buf *buf, const char *name, uint8_t *mac)
{
#ifndef MAPIQ_DEVID_STRING_FORMAT
	blobmsg_add_field(buf, BLOBMSG_TYPE_UNSPEC, name, mac, ETH_ALEN);
#else
	char mac_string[18];
	sprintf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	blobmsg_add_string(buf, name, mac_string);
#endif
}

void blobmsg_get_mac(struct blob_attr *attr, uint8_t *mac)
{
#ifndef MAPIQ_DEVID_STRING_FORMAT
    memcpy(mac, blobmsg_data(attr), sizeof(mac_address));
#else
    ether_aton_r((char *)blobmsg_data(attr), (struct ether_addr *)mac);
#endif
}

void blobmsg_add_binary(struct blob_buf *buf, const char *name, uint8_t *data, uint32_t len)
{
#ifndef MAPIQ_DEVID_STRING_FORMAT
	blobmsg_add_field(buf, BLOBMSG_TYPE_UNSPEC, name, data, len);
#else
    int i;
    char *pos, *string = malloc(len * 3 + 1);

    string[0] = '\0';
    pos = string;
    for (i = 0; i < len; i++)
        pos += sprintf(pos, "%02x ", data[i]);

    blobmsg_add_string(buf, name, string);
    free(string);
#endif
}

void fill_result(uint8_t rc)
{
    if (rc >= MAPAPI_RESULT_UNKNOWN_ERROR)
        rc = MAPAPI_RESULT_UNKNOWN_ERROR;
    blobmsg_add_string(&b, MAPAPI_ATTR_RC_NAME, result_strings[rc]);
}

void array_mac_to_dlist(void *ctx, void *param, void *data, int len)
{
    dlist_head *head = (dlist_head *)ctx;
    struct macAddressItem *item;
    struct blob_attr *tb[NUM_MAPAPI_PARAM_MAC_ATTRS];

    mapapi_param_mac_policy[MAPAPI_PARAM_ATTR_MAC].name = (char *)param;

    blobmsg_parse(mapapi_param_mac_policy, NUM_MAPAPI_PARAM_MAC_ATTRS, tb, data, len);

    if (!tb[MAPAPI_PARAM_ATTR_MAC])
        return;

    item = zmemalloc(sizeof(struct macAddressItem));
    blobmsg_get_mac(tb[MAPAPI_PARAM_ATTR_MAC], item->mac);
    dlist_add_tail(head, &item->l);
}

void visit_attrs(struct blob_attr *attrs, void (*cb)(void *, void *, void *, int), void *ctx, void *param)
{
    struct blob_attr *attr;
    int rem;

    if (!attrs)
        return;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        if (cb)
            cb(ctx, param, blobmsg_data(attr), blobmsg_len(attr));
    }
}

int mapapi_server_init(void)
{
    int ret;
    struct ubus_object *obj;

    obj = get_mapapi_obj();
    ret = ubus_add_object(platform_ubus, obj);
    if (ret)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to add %s ubus object: %s\n",
                obj->name, ubus_strerror(ret));
        return -1;
    }

    obj = get_mapapi_local_obj();
    ret = ubus_add_object(platform_ubus, obj);
    if (ret)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to add %s ubus object: %s\n",
                obj->name, ubus_strerror(ret));
        return -1;
    }

    obj = get_mapapi_network_obj();
    ret = ubus_add_object(platform_ubus, obj);
    if (ret)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to add %s ubus object: %s\n",
                obj->name, ubus_strerror(ret));
        return -1;
    }

    if (map_config.role & MAP_ROLE_CONTROLLER)
    {
        obj = get_mapapi_controller_obj();
        ret = ubus_add_object(platform_ubus, obj);
        if (ret)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("fail to add %s ubus object: %s\n",
                    obj->name, ubus_strerror(ret));
            return -1;
        }
    }

    obj = get_mapapi_config_obj();
    ret = ubus_add_object(platform_ubus, obj);
    if (ret)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("fail to add %s ubus object: %s\n",
                obj->name, ubus_strerror(ret));
        return -1;
    }

    blob_buf_init(&b, 0);

    return 0;
}

void mapapi_server_deinit(void)
{
    ubus_remove_object(platform_ubus, get_mapapi_obj());

    ubus_remove_object(platform_ubus, get_mapapi_local_obj());

    ubus_remove_object(platform_ubus, get_mapapi_network_obj());

    if (map_config.role & MAP_ROLE_CONTROLLER)
        ubus_remove_object(platform_ubus, get_mapapi_controller_obj());

    free_list_mapapi_config_obj();
    ubus_remove_object(platform_ubus, get_mapapi_config_obj());

    blob_buf_free(&b);
}
