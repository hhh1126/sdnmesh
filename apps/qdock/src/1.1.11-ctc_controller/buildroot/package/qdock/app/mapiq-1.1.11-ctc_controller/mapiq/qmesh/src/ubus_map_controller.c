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
 * @brief ubus map controller object implementation
 *
 */

#include "qdock_map_api.h"
#include "al_ubus_server.h"

#include "platform.h"
#include "datamodel.h"
#include "al_send.h"
#include "al_utils.h"

enum {
    MAPAPI_CHANNELS_ATTR_CHANNEL = 0,

    NUM_MAPAPI_CHANNELS_ATTRS,
};

static const struct blobmsg_policy mapapi_channels_policy[] = {
    [MAPAPI_CHANNELS_ATTR_CHANNEL] = { .name = MAPAPI_RADIO_ATTR_CHANNEL_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static uint8_t mapapi_parse_channel(struct radioOpclass *opclass, struct blob_attr *attrs,
    int preference, int reason_code)
{
    struct blob_attr *attr, *tb[NUM_MAPAPI_CHANNELS_ATTRS];
    int rem, i = 0;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        blobmsg_parse(mapapi_channels_policy, NUM_MAPAPI_CHANNELS_ATTRS, tb,
            blobmsg_data(attr), blobmsg_len(attr));

        if (!tb[MAPAPI_CHANNELS_ATTR_CHANNEL])
            return 0;

        opclass->channel_nums++;
        struct radioChannel *ch = &opclass->channels[i];
        ch->id = blobmsg_get_u32(tb[MAPAPI_CHANNELS_ATTR_CHANNEL]);
        ch->pref = preference;
        ch->reason = reason_code;
        i++;
    }
    return 1;
}

enum {
    MAPAPI_OPCLASSES_ATTR_OPCLASS = 0,
    MAPAPI_OPCLASSES_ATTR_CHANNELS,
    MAPAPI_OPCLASSES_ATTR_PREFERENCE,
    MAPAPI_OPCLASSES_ATTR_REASON_CODE,

    NUM_MAPAPI_OPCLASSES_ATTRS,
};

static const struct blobmsg_policy mapapi_opclasses_policy[] = {
    [MAPAPI_OPCLASSES_ATTR_OPCLASS] = { .name = MAPAPI_OPCLASS_ATTR_ID_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_OPCLASSES_ATTR_CHANNELS] = { .name = MAPAPI_SET_ATTR_CHANNELS_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_OPCLASSES_ATTR_PREFERENCE] = { .name = MAPAPI_SET_ATTR_CHAN_SLEC_REQ_PREFERENCE_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_OPCLASSES_ATTR_REASON_CODE] = { .name = MAPAPI_SET_ATTR_CHAN_SLEC_REQ_REASON_CODE_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static uint8_t mapapi_parse_opclasses(struct radio *r, struct blob_attr *attrs)
{
    struct blob_attr *attr, *tb[NUM_MAPAPI_OPCLASSES_ATTRS];
    int rem, opclass_val, preference, reason_code;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        blobmsg_parse(mapapi_opclasses_policy, NUM_MAPAPI_OPCLASSES_ATTRS, tb,
	    blobmsg_data(attr), blobmsg_len(attr));
        if (!tb[MAPAPI_OPCLASSES_ATTR_OPCLASS] || !tb[MAPAPI_OPCLASSES_ATTR_CHANNELS]
	    || !tb[MAPAPI_OPCLASSES_ATTR_PREFERENCE] || !tb[MAPAPI_OPCLASSES_ATTR_REASON_CODE])
	    return 0;

        opclass_val = blobmsg_get_u32(tb[MAPAPI_OPCLASSES_ATTR_OPCLASS]);
        preference = blobmsg_get_u32(tb[MAPAPI_OPCLASSES_ATTR_PREFERENCE]);
        reason_code = blobmsg_get_u32(tb[MAPAPI_OPCLASSES_ATTR_REASON_CODE]);

        struct radioOpclass *opclass = &r->opclasses[r->opclass_nums++];
        opclass->opclass = opclass_val;
        if (!mapapi_parse_channel(opclass, tb[MAPAPI_OPCLASSES_ATTR_CHANNELS], preference, reason_code))
	    return 0;
    }
    return 1;
}

enum {
    MAPAPI_CHANNEL_SELECTION_ATTR_RADIO_ID = 0,
    MAPAPI_CHANNEL_SELECTION_ATTR_OPCLASSES,
    MAPAPI_CHANNEL_SELECTION_ATTR_TXPOWER_LIMIT,

    NUM_MAPAPI_CHANNEL_SELECTION_ATTRS,
};

static const struct blobmsg_policy mapapi_channel_selection_policy[] = {
    [MAPAPI_CHANNEL_SELECTION_ATTR_RADIO_ID] = { .name = MAPAPI_RADIO_ATTR_ID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_CHANNEL_SELECTION_ATTR_OPCLASSES] = { .name = MAPAPI_RADIO_ATTR_OPCLASSES_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_CHANNEL_SELECTION_ATTR_TXPOWER_LIMIT] = { .name = MAPAPI_SET_ATTR_CHAN_SLEC_REQ_TXPOWER_LIMIT_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static uint8_t mapapi_parse_chan_slec_radios(dlist_head *radios_head, struct blob_attr *attrs)
{
    struct blob_attr *attr, *tb[NUM_MAPAPI_CHANNEL_SELECTION_ATTRS];
    struct radio *item;
    mac_address radio_id;
    int rem;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        blobmsg_parse(mapapi_channel_selection_policy, NUM_MAPAPI_CHANNEL_SELECTION_ATTRS, tb,
            blobmsg_data(attr), blobmsg_len(attr));

        if (!tb[MAPAPI_CHANNEL_SELECTION_ATTR_RADIO_ID] || !tb[MAPAPI_CHANNEL_SELECTION_ATTR_OPCLASSES]
            || !tb[MAPAPI_CHANNEL_SELECTION_ATTR_TXPOWER_LIMIT])
	    return 0;

        item = (struct radio *)zmemalloc(sizeof(struct radio));

        blobmsg_get_mac(tb[MAPAPI_CHANNEL_SELECTION_ATTR_RADIO_ID], radio_id);
        memcpy(item->uid, radio_id, sizeof(mac_address));
        item->ctrler_maxpower = blobmsg_get_u32(tb[MAPAPI_CHANNEL_SELECTION_ATTR_TXPOWER_LIMIT]);

        if (!mapapi_parse_opclasses(item, tb[MAPAPI_CHANNEL_SELECTION_ATTR_OPCLASSES]))
	    return 0;

        dlist_add_tail(radios_head, &item->l);
    }
    return 1;
}

enum {
    MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_IFNAME = 0,
    MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_DEST_ALID,
    MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_CHANNEL_SELECTION,

    NUM_MAPAPI_REQUEST_CHANNEL_SELECTION_ATTRS,
};

static const struct blobmsg_policy mapapi_request_channel_selection_policy[] = {
    [MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_CHANNEL_SELECTION] = { .name = MAPAPI_SET_ATTR_CHAN_SLEC_REQ_CHANNEL_SELECTION_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static int mapapi_request_channel_selection(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_REQUEST_CHANNEL_SELECTION_ATTRS];
    struct alDevice *alDev;
    const char *ifname;
    mac_address al_id;
    uint16_t mid = getNextMid();
    dlist_head radio_chan_slec_head;

    blobmsg_parse(mapapi_request_channel_selection_policy, NUM_MAPAPI_REQUEST_CHANNEL_SELECTION_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_DEST_ALID] || !tb[MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_CHANNEL_SELECTION])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_DEST_ALID], al_id);
    alDev = alDeviceFind(al_id);

    if (!alDev)
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    ifname = blobmsg_get_string(tb[MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_IFNAME]);
    if (!ifname)
        ifname = alDev->receiving_interface_name;

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    dlist_head_init(&radio_chan_slec_head);
    if (!mapapi_parse_chan_slec_radios(&radio_chan_slec_head, tb[MAPAPI_REQUEST_CHANNEL_SELECTION_ATTR_CHANNEL_SELECTION]))
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        dlist_free_items(&radio_chan_slec_head, struct radio, l);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("Controller try to send channel selection request message [mid: 0x%04x] to "
        MACFMT " from interface %s\n", mid, MACARG(al_id), ifname);

    if (send1905ChannelSelectionRequst(&radio_chan_slec_head, al_id, ifname, mid))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    dlist_free_items(&radio_chan_slec_head, struct radio, l);
    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_STA_MAC = 0,
    MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_BSSID,
    MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_OPCLASS,
    MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_CHANNEL,

    NUM_MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTRS,
};

static const struct blobmsg_policy mapapi_client_steering_req_mandate_policy[] = {
    [MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_STA_MAC] = { .name = MAPAPI_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_BSSID] = { .name = MAPAPI_STEERING_ATTR_TARGET_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_OPCLASS] = { .name = MAPAPI_STEERING_ATTR_TARGET_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_CHANNEL] = { .name = MAPAPI_STEERING_ATTR_TARGET_CHAN_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static uint8_t mapapi_parse_steering_stas_and_target_bsses(dlist_head *head, struct blob_attr *attrs_stats,
    struct blob_attr *attrs_bsses)
{
    struct blob_attr *attr_sta, *atts_bss;
    struct blob_attr *tb[NUM_MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTRS];
    struct steeringStaItem *item, *tmp_item;
    int rem, overall_bss_attr_count = 0, attr_count = 0, dlist_count = 0;

    if (attrs_stats && attrs_bsses)
    {
        blobmsg_for_each_attr(attr_sta, attrs_stats, rem)
        {
            blobmsg_parse(mapapi_client_steering_req_mandate_policy, NUM_MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTRS, tb,
	        blobmsg_data(attr_sta), blobmsg_len(attr_sta));

	    if (tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_STA_MAC])
	    {
	        item = (struct steeringStaItem *)malloc(sizeof(*item));
		blobmsg_get_mac(tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_STA_MAC], item->mac);
	    }
	    else
                return 0;

            dlist_add_tail(head, &item->l);
        }

        blobmsg_for_each_attr(atts_bss, attrs_bsses, rem)
            overall_bss_attr_count++;

        blobmsg_for_each_attr(atts_bss, attrs_bsses, rem)
        {
            blobmsg_parse(mapapi_client_steering_req_mandate_policy, NUM_MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTRS, tb,
	        blobmsg_data(atts_bss), blobmsg_len(atts_bss));
	    attr_count++;

	    dlist_for_each_safe(item, tmp_item, *head, l)
	    {
	        dlist_count++;
	        if (attr_count == dlist_count || overall_bss_attr_count == 1)
	        {
		    if (!item || !tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_BSSID])
		        return 0;

                    blobmsg_get_mac(tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_BSSID], item->targetBssid);

                    if (tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_OPCLASS])
		        item->target_bss_opclass = blobmsg_get_u32(tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_OPCLASS]);

		    if (tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_CHANNEL])
		        item->target_bss_ch = blobmsg_get_u32(tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_CHANNEL]);
	        }
	    }
            dlist_count = 0;
        }
    }
    else if (attrs_bsses)
    {
        blobmsg_for_each_attr(atts_bss, attrs_bsses, rem)
        {
            blobmsg_parse(mapapi_client_steering_req_mandate_policy, NUM_MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTRS, tb,
	        blobmsg_data(atts_bss), blobmsg_len(atts_bss));

            if (!tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_BSSID])
	        return 0;

	    item = (struct steeringStaItem *)malloc(sizeof(*item));
            memset(item->mac, 0x0, sizeof(mac_address));
	    blobmsg_get_mac(tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_BSSID], item->targetBssid);

	    if (tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_OPCLASS])
	        item->target_bss_opclass = blobmsg_get_u32(tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_OPCLASS]);

	    if (tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_CHANNEL])
	        item->target_bss_ch = blobmsg_get_u32(tb[MAPAPI_CLIENT_STEERING_REQ_MANDATE_ATTR_TARGET_BSS_CHANNEL]);

	    dlist_add_tail(head, &item->l);
	}
    }
    else
        return 0;

    return 1;
}

enum {
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_IFNAME = 0,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_DEST_ALID,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BSSID,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_MODE,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_DISASSOC_IMMINENT,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_ABRIDGED,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_TIMER,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STEERING_WINDOW,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STATIONS,
    MAPAPI_REQUEST_CLIENT_STEERING_ATTR_TARGET_BSSES,

    NUM_MAPAPI_REQUEST_CLIENT_STEERING_ATTRS,
};

static const struct blobmsg_policy mapapi_request_client_steering_policy[] = {
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BSSID] = { .name = MAPAPI_BSS_ATTR_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_MODE] = { .name = MAPAPI_STEERING_ATTR_REQ_MODE_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_DISASSOC_IMMINENT] = { .name = MAPAPI_STEERING_ATTR_BTM_DISASSOC_IMMINENT_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_ABRIDGED] = { .name = MAPAPI_STEERING_ATTR_BTM_ABRIDGED_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_TIMER] = { .name = MAPAPI_STEERING_ATTR_BTM_TIMER_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STEERING_WINDOW] = { .name = MAPAPI_STEERING_ATTR_STEERING_WINDOW_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STATIONS] = { .name = MAPAPI_BSS_ATTR_STATIONS_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_REQUEST_CLIENT_STEERING_ATTR_TARGET_BSSES] = { .name = MAPAPI_STEERING_ATTR_TARGET_BSSES_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static int mapapi_request_client_steering(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_REQUEST_CLIENT_STEERING_ATTRS];
    struct alDevice *alDev;
    const char *ifname;
    mac_address al_id, src_bssid;
    uint8_t mode = 0, request_mode = 0, btm_disassoc_imminent = 0, btm_abridged = 0, sta_head_assigned = 0;
    uint16_t mid = getNextMid(), btm_timmer = 0, steering_window = 0;
    dlist_head steering_stas_head, *steering_stas = NULL;

    blobmsg_parse(mapapi_request_client_steering_policy, NUM_MAPAPI_REQUEST_CLIENT_STEERING_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_DEST_ALID] || !tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BSSID]
        || !tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_MODE] || !tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_DISASSOC_IMMINENT]
        || !tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_ABRIDGED] || !tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_TIMER])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_DEST_ALID], al_id);
    blobmsg_get_mac(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BSSID], src_bssid);
    request_mode = blobmsg_get_u32(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_MODE]);
    btm_disassoc_imminent = blobmsg_get_u32(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_DISASSOC_IMMINENT]);
    btm_abridged = blobmsg_get_u32(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_ABRIDGED]);
    btm_timmer = blobmsg_get_u32(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_BTM_TIMER]);
    alDev = alDeviceFind(al_id);

    if (!alDev || (mode | btm_disassoc_imminent | btm_abridged) > 1)
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    ifname = blobmsg_get_string(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_IFNAME]);
    if (!ifname)
        ifname = alDev->receiving_interface_name;

    if (!ifname || (!request_mode && !tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STEERING_WINDOW]))
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    if (tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STEERING_WINDOW])
        steering_window = blobmsg_get_u32(tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STEERING_WINDOW]);

    if (tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STATIONS] || tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_TARGET_BSSES])
    {
        sta_head_assigned = 1;
        dlist_head_init(&steering_stas_head);
        if (!mapapi_parse_steering_stas_and_target_bsses(&steering_stas_head, tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_STATIONS],
	    tb[MAPAPI_REQUEST_CLIENT_STEERING_ATTR_TARGET_BSSES]))
        {
            fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
            dlist_free_items(&steering_stas_head, struct steeringStaItem, l);
            return ubus_send_reply(ctx, req, b.head);
        }
    }

    if (request_mode)
        mode |= STEERING_REQ_MODE_MANDATE;

    if (btm_disassoc_imminent)
        mode |= STEERING_REQ_MODE_DISASSOC_IMM;

    if (btm_abridged)
        mode |= STEERING_REQ_MODE_ABRIDGED;

    if (sta_head_assigned)
        steering_stas = &steering_stas_head;

    PLATFORM_PRINTF_DEBUG_INFO("Controller try to send client steering request message [mid: 0x%04x] to "
        MACFMT " from interface %s with mode 0x%02x on BSS " MACFMT "\n", mid, MACARG(al_id), ifname, mode, MACARG(src_bssid));

    if (send1905ClientSteeringRequest(ifname, mid, al_id, src_bssid, mode, steering_window, btm_timmer, steering_stas))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    if (sta_head_assigned)
        dlist_free_items(&steering_stas_head, struct steeringStaItem, l);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_IFNAME = 0,
    MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_DEST_ALID,
    MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_STATION,
    MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_BSSID,
    MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_OPCLASS,
    MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_CHAN,

    NUM_MAPAPI_REQUEST_BACKHAUL_STEERING_ATTRS,
};

static const struct blobmsg_policy mapapi_request_backhaul_steering_policy[] = {
    [MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_STATION] = { .name = MAPAPI_STATION_ATTR_MAC_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_BSSID] = { .name = MAPAPI_STEERING_ATTR_TARGET_BSSID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_OPCLASS] = { .name = MAPAPI_STEERING_ATTR_TARGET_OPCLASS_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_CHAN] = { .name = MAPAPI_STEERING_ATTR_TARGET_CHAN_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static int mapapi_request_backhaul_steering(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_REQUEST_BACKHAUL_STEERING_ATTRS];
    const char *ifname;
    mac_address al_id, target_bssid, backhaul_sta;
    uint8_t target_opclass, target_chan;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_request_backhaul_steering_policy, NUM_MAPAPI_REQUEST_BACKHAUL_STEERING_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_DEST_ALID] || !tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_STATION]
        || !tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_BSSID] || !tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_OPCLASS]
        || !tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_CHAN])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_DEST_ALID], al_id);
    blobmsg_get_mac(tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_STATION], backhaul_sta);
    blobmsg_get_mac(tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_BSSID], target_bssid);
    target_opclass = blobmsg_get_u32(tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_OPCLASS]);
    target_chan = blobmsg_get_u32(tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_TARGET_CHAN]);
    ifname = blobmsg_get_string(tb[MAPAPI_REQUEST_BACKHAUL_STEERING_ATTR_IFNAME]);
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

    PLATFORM_PRINTF_DEBUG_INFO("Controller try to send backhaul steering request message [mid: 0x%04x] to "
        MACFMT " from interface %s for backhaul sta " MACFMT "\n", mid, MACARG(al_id), ifname, MACARG(backhaul_sta));

    if (send1905BackhaulSteeringRequest(ifname, mid, al_id, backhaul_sta, target_bssid, target_opclass, target_chan))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_RADIO_STEERING_POLICY_ATTR_RADIO_ID = 0,
    MAPAPI_RADIO_STEERING_POLICY_ATTR_STEERING_POLICY,
    MAPAPI_RADIO_STEERING_POLICY_ATTR_CH_UTIL_THRESHOLD,
    MAPAPI_RADIO_STEERING_POLICY_ATTR_RCPI_THRESHOLD,

    NUM_MAPAPI_RADIO_STEERING_POLICY_ATTRS,
};

static const struct blobmsg_policy mapapi_radio_steering_policy_policy[] = {
    [MAPAPI_RADIO_STEERING_POLICY_ATTR_RADIO_ID] = { .name = MAPAPI_RADIO_ATTR_ID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_RADIO_STEERING_POLICY_ATTR_STEERING_POLICY] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_STEERING_POLICY_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_RADIO_STEERING_POLICY_ATTR_CH_UTIL_THRESHOLD] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_CH_UTIL_THRESHOLD_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_RADIO_STEERING_POLICY_ATTR_RCPI_THRESHOLD] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_RCPI_THRESHOLD_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static uint8_t mapapi_parse_radio_steering_policy(dlist_head *head, struct blob_attr *attrs)
{
    struct blob_attr *attr, *tb[NUM_MAPAPI_RADIO_STEERING_POLICY_ATTRS];
    struct radioSteeringPolicyItem *item;
    int rem;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        blobmsg_parse(mapapi_radio_steering_policy_policy, NUM_MAPAPI_RADIO_STEERING_POLICY_ATTRS, tb,
            blobmsg_data(attr), blobmsg_len(attr));

        if (!tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_RADIO_ID] || !tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_STEERING_POLICY]
	    || !tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_CH_UTIL_THRESHOLD] || !tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_RCPI_THRESHOLD])
            return 0;

        item = (struct radioSteeringPolicyItem *)malloc(sizeof(*item));
        memset(item, 0x0, sizeof(*item));
        blobmsg_get_mac(tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_RADIO_ID], item->radio_id);
        item->steering_policy.policy = blobmsg_get_u32(tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_STEERING_POLICY]);
        item->steering_policy.ch_util_threshold = blobmsg_get_u32(tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_CH_UTIL_THRESHOLD]);
        item->steering_policy.rcpi_threshold = blobmsg_get_u32(tb[MAPAPI_RADIO_STEERING_POLICY_ATTR_RCPI_THRESHOLD]);

        dlist_add_tail(head, &item->l);
    }
    return 1;
}

enum {
    MAPAPI_METRIC_REPORTING_POLICY_ATTR_RADIO_ID = 0,
    MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_THRESHOLD,
    MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_MARGIN,
    MAPAPI_METRIC_REPORTING_POLICY_ATTR_CH_UTIL_THRESHOLD,
    MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_TRAFFIC_INCLUDE,
    MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_LINK_INCLUDE,

    NUM_MAPAPI_METRIC_REPORTING_POLICY_ATTRS,
};

static const struct blobmsg_policy mapapi_metric_reporting_policy_policy[] = {
    [MAPAPI_METRIC_REPORTING_POLICY_ATTR_RADIO_ID] = { .name = MAPAPI_RADIO_ATTR_ID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_THRESHOLD] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_RCPI_THRESHOLD_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_MARGIN] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_RCPI_MARGIN_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_METRIC_REPORTING_POLICY_ATTR_CH_UTIL_THRESHOLD] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_CH_UTIL_THRESHOLD_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_TRAFFIC_INCLUDE] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_ASSOC_STA_TRAFFIC_INCLUDE_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_LINK_INCLUDE] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_ASSOC_STA_LINK_INCLUDE_NAME, .type = BLOBMSG_TYPE_INT32 },
};

static uint8_t mapapi_parse_metric_reporting_policy(dlist_head *head, struct blob_attr *attrs)
{
    struct blob_attr *attr, *tb[NUM_MAPAPI_METRIC_REPORTING_POLICY_ATTRS];
    struct radioMetricPolicyItem *item;
    int rem;

    blobmsg_for_each_attr(attr, attrs, rem)
    {
        blobmsg_parse(mapapi_metric_reporting_policy_policy, NUM_MAPAPI_METRIC_REPORTING_POLICY_ATTRS, tb,
            blobmsg_data(attr), blobmsg_len(attr));

        if (!tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_RADIO_ID] || !tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_THRESHOLD]
            || !tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_MARGIN] || !tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_CH_UTIL_THRESHOLD]
            ||!tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_TRAFFIC_INCLUDE] || !tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_LINK_INCLUDE])
            return 0;

        item = (struct radioMetricPolicyItem *)malloc(sizeof(*item));
        memset(item, 0x0, sizeof(*item));
        blobmsg_get_mac(tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_RADIO_ID], item->radio_id);
        item->metric_policy.rcpi_threshold = blobmsg_get_u32(tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_THRESHOLD]);
        item->metric_policy.rcpi_margin = blobmsg_get_u32(tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_RCPI_MARGIN]);
        item->metric_policy.ch_util_threshold = blobmsg_get_u32(tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_CH_UTIL_THRESHOLD]);
        if (blobmsg_get_u32(tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_TRAFFIC_INCLUDE]))
            item->metric_policy.policy |= METRIC_REPORTING_POLICY_INCLUDE_ASSOCED_TRAFFIC_STATS;
        if (blobmsg_get_u32(tb[MAPAPI_METRIC_REPORTING_POLICY_ATTR_ASSOC_STA_LINK_INCLUDE]))
            item->metric_policy.policy |= METRIC_REPORTING_POLICY_INCLUDE_ASSOCED_LINK_METRICS;

        dlist_add_tail(head, &item->l);
    }
    return 1;
}

enum {
    MAPAPI_REQUEST_POLICY_CONFIG_ATTR_IFNAME = 0,
    MAPAPI_REQUEST_POLICY_CONFIG_ATTR_DEST_ALID,
    MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_LOCAL_DISALLOWED,
    MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_BTM_DISALLOWED,
    MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_RADIO_STEERING_POLICY,
    MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_REPORTING_INTERVAL,
    MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_METRIC_REPORTING_POLICY,

    NUM_MAPAPI_REQUEST_POLICY_CONFIG_ATTRS,
};

static const struct blobmsg_policy mapapi_request_policy_config_policy[] = {
    [MAPAPI_REQUEST_POLICY_CONFIG_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_REQUEST_POLICY_CONFIG_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
    [MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_LOCAL_DISALLOWED] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_LOCAL_DISALLOWED_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_BTM_DISALLOWED] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_BTM_DISALLOWED_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_RADIO_STEERING_POLICY] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_RADIO_STEERING_POLICY_NAME, .type = BLOBMSG_TYPE_ARRAY },
    [MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_REPORTING_INTERVAL] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_REPORTING_INTERVAL_NAME, .type = BLOBMSG_TYPE_INT32 },
    [MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_METRIC_REPORTING_POLICY] = { .name = MAPAPI_SET_ATTR_POLICY_CONF_METRIC_REPORTING_POLICY_NAME, .type = BLOBMSG_TYPE_ARRAY },
};

static int mapapi_request_policy_config(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_REQUEST_POLICY_CONFIG_ATTRS];
    const char *ifname;
    mac_address al_id;
    uint8_t interval;
    uint16_t mid = getNextMid();
    dlist_head local_disallowed_head, btm_disallowed_head, radio_steering_policy_head, metric_reporting_policy_head;

    blobmsg_parse(mapapi_request_policy_config_policy, NUM_MAPAPI_REQUEST_POLICY_CONFIG_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_DEST_ALID] || !tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_LOCAL_DISALLOWED]
        || !tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_BTM_DISALLOWED] || !tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_RADIO_STEERING_POLICY]
        || !tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_REPORTING_INTERVAL] || !tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_METRIC_REPORTING_POLICY])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_DEST_ALID], al_id);
    ifname = blobmsg_get_string(tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_IFNAME]);
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

    interval = blobmsg_get_u32(tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_REPORTING_INTERVAL]);

    dlist_head_init(&radio_steering_policy_head);
    if (!mapapi_parse_radio_steering_policy(&radio_steering_policy_head, tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_RADIO_STEERING_POLICY]))
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        dlist_free_items(&radio_steering_policy_head, struct radioSteeringPolicyItem, l);
        return ubus_send_reply(ctx, req, b.head);
    }

    dlist_head_init(&metric_reporting_policy_head);
    if (!mapapi_parse_metric_reporting_policy(&metric_reporting_policy_head, tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_METRICS_METRIC_REPORTING_POLICY]))
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        dlist_free_items(&radio_steering_policy_head, struct radioSteeringPolicyItem, l);
        dlist_free_items(&metric_reporting_policy_head, struct radioMetricPolicyItem, l);
        return ubus_send_reply(ctx, req, b.head);
    }

    dlist_head_init(&local_disallowed_head);
    visit_attrs(tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_LOCAL_DISALLOWED], array_mac_to_dlist, &local_disallowed_head,
        MAPAPI_STATION_ATTR_MAC_NAME);

    dlist_head_init(&btm_disallowed_head);
    visit_attrs(tb[MAPAPI_REQUEST_POLICY_CONFIG_ATTR_STEERING_BTM_DISALLOWED], array_mac_to_dlist, &btm_disallowed_head,
        MAPAPI_STATION_ATTR_MAC_NAME);

    PLATFORM_PRINTF_DEBUG_INFO("Controller try to send policy config request message [mid: 0x%04x] to "
        MACFMT " from interface %s \n", mid, MACARG(al_id), ifname);

    if (send1905MAPPolicyConfigRequest(&local_disallowed_head, &btm_disallowed_head, &radio_steering_policy_head,
        interval, &metric_reporting_policy_head, ifname, mid, al_id))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    dlist_free_items(&radio_steering_policy_head, struct radioSteeringPolicyItem, l);
    dlist_free_items(&metric_reporting_policy_head, struct radioMetricPolicyItem, l);
    dlist_free_items(&local_disallowed_head, struct macAddressItem, l);
    dlist_free_items(&btm_disallowed_head, struct macAddressItem, l);

    return ubus_send_reply(ctx, req, b.head);
}

enum {
    MAPAPI_SEND_COMBINED_METRICS_ATTR_IFNAME = 0,
    MAPAPI_SEND_COMBINED_METRICS_ATTR_DEST_ALID,

    NUM_MAPAPI_SEND_COMBINED_METRICS_ATTRS,
};

static const struct blobmsg_policy mapapi_send_combined_metrics_policy[] = {
    [MAPAPI_SEND_COMBINED_METRICS_ATTR_IFNAME] = { .name = MAPAPI_SET_ATTR_IFNAME_NAME, .type = BLOBMSG_TYPE_STRING },
    [MAPAPI_SEND_COMBINED_METRICS_ATTR_DEST_ALID] = { .name = MAPAPI_SET_ATTR_DEST_ALID_NAME, .type = BLOBMSG_TYPE_MAC },
};

static int mapapi_send_combined_metrics(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[NUM_MAPAPI_SEND_COMBINED_METRICS_ATTRS];
    struct alDevice *alDev;
    const char *ifname;
    mac_address al_id;
    uint16_t mid = getNextMid();

    blobmsg_parse(mapapi_send_combined_metrics_policy, NUM_MAPAPI_SEND_COMBINED_METRICS_ATTRS,
        tb, blob_data(msg), blob_len(msg));
    blob_buf_init(&b, 0);

    if (!tb[MAPAPI_SEND_COMBINED_METRICS_ATTR_DEST_ALID])
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    blobmsg_get_mac(tb[MAPAPI_SEND_COMBINED_METRICS_ATTR_DEST_ALID], al_id);
    alDev = alDeviceFind(al_id);
    if (!alDev)
    {
        fill_result(MAPAPI_RESULT_INVALID_VALUE);
        return ubus_send_reply(ctx, req, b.head);
    }

    ifname = blobmsg_get_string(tb[MAPAPI_SEND_COMBINED_METRICS_ATTR_IFNAME]);
    if (!ifname)
        ifname = alDev->receiving_interface_name;

    if (!ifname)
    {
        fill_result(MAPAPI_RESULT_MISS_ARGUMENT);
        return ubus_send_reply(ctx, req, b.head);
    }

    PLATFORM_PRINTF_DEBUG_INFO("Controller try to send combined metrics message [mid: 0x%04x] to "
        MACFMT " from interface %s\n", mid, MACARG(al_id), ifname);

    if (send1905CombinedInfrastructureMetrics(alDev, ifname, mid))
    {
        fill_result(MAPAPI_RESULT_SUCCESS);
        blobmsg_add_u32(&b, MAPAPI_1905_ATTR_MID_NAME, mid);
    }
    else
        fill_result(MAPAPI_RESULT_UNKNOWN_ERROR);

    return ubus_send_reply(ctx, req, b.head);
}
static const struct ubus_method mapapi_controller_methods[] = {
    UBUS_METHOD(MAPAPI_METHOD_REQUEST_CHANNEL_SELECTION_NAME, mapapi_request_channel_selection, mapapi_request_channel_selection_policy),
    UBUS_METHOD(MAPAPI_METHOD_REQUEST_CLIENT_STEERING_NAME, mapapi_request_client_steering, mapapi_request_client_steering_policy),
    UBUS_METHOD(MAPAPI_METHOD_REQUEST_BACKHAUL_STEERING_NAME, mapapi_request_backhaul_steering, mapapi_request_backhaul_steering_policy),
    UBUS_METHOD(MAPAPI_METHOD_REQUEST_POLICY_CONFIG_NAME, mapapi_request_policy_config, mapapi_request_policy_config_policy),
    UBUS_METHOD(MAPAPI_METHOD_SEND_COMBINED_METRICS_NAME, mapapi_send_combined_metrics, mapapi_send_combined_metrics_policy),
    //TODO more
};

static struct ubus_object_type mapapi_controller_obj_type =
UBUS_OBJECT_TYPE(MAPAPI_CONTROLLER_OBJ_NAME, mapapi_controller_methods);

static struct ubus_object mapapi_controller_obj = {
    .name = MAPAPI_CONTROLLER_OBJ_NAME,
    .type = &mapapi_controller_obj_type,
    .methods = mapapi_controller_methods,
    .n_methods = ARRAY_SIZE(mapapi_controller_methods),
};

struct ubus_object *get_mapapi_controller_obj(void)
{
    return &mapapi_controller_obj;
}
