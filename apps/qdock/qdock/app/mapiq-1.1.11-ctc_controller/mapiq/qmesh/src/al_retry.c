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

#include "platform.h"
#include "utils.h"

#include <stdarg.h>   // va_list
#include <stdio.h>    // vsnprintf

#include "al_send.h"
#include "datamodel.h"
#include "al_datamodel.h"
#include "al_utils.h"

#include "1905_tlvs.h"
#include "1905_cmdus.h"
#include "1905_alme.h"
#include "1905_l2.h"
#include "lldp_tlvs.h"
#include "lldp_payload.h"

#include "platform_os.h"
#include "platform_interfaces.h"
#include "platform_alme_server.h"
#ifdef QDOCK
#include "linux/platform_qdock.h"
#endif

#include "al_retry.h"

static dlist_head cmdu_retry_head;



void initCmduRetry(void)
{
    dlist_head_init(&cmdu_retry_head);
}

static void freeCmduRetryData(struct cmdu_retry *retry)
{
    if (retry->timer)
        PLATFORM_CANCEL_TIMEOUT(retry->timer);
    if (retry->ifname)
        free(retry->ifname);
    if (retry->cmdu)
        free_1905_CMDU_structure(retry->cmdu);
}

void deinitCmduRetry(void)
{
    dlist_item *item;

    while (NULL != (item = dlist_get_first(&cmdu_retry_head)))
    {
        struct cmdu_retry *retry = container_of(item, struct cmdu_retry, l);

        dlist_remove(item);

        freeCmduRetryData(retry);
        free(retry);
    }
}

static struct cmdu_retry *findCmduRetryByMtype(const uint8_t *dst_addr, uint16_t mtype)
{
    struct cmdu_retry *retry;
    dlist_for_each(retry, cmdu_retry_head, l)
    {
        if (!retry->cmdu)
            continue;
        if (mtype == retry->cmdu->message_type
                && 0 == memcmp(dst_addr, retry->dst_addr, sizeof(mac_address)))
            return retry;
    }
    return NULL;
}

/* internal use, not defined in spec */
#define CMDU_TYPE_INVALID           0xffff

struct cmdu_info
{
    uint16_t resp_type;
#define CMDU_INFO_FLAG_CHECK_REQUEST        (1 << 0)
#define CMDU_INFO_FLAG_RESP_DIFF_MID        (1 << 1)
    uint8_t flag;
};

static const struct cmdu_info _response_cmdu[] =
{
    /* CMDU_TYPE_TOPOLOGY_DISCOVERY */              { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_TOPOLOGY_NOTIFICATION */           { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_TOPOLOGY_QUERY */                  { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_TOPOLOGY_RESPONSE */               { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_VENDOR_SPECIFIC */                 { CMDU_TYPE_VENDOR_SPECIFIC, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_LINK_METRIC_QUERY */               { CMDU_TYPE_LINK_METRIC_RESPONSE, 0 },
    /* CMDU_TYPE_LINK_METRIC_RESPONSE */            { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH */     { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE */   { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_WSC */        { CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, CMDU_INFO_FLAG_CHECK_REQUEST | CMDU_INFO_FLAG_RESP_DIFF_MID },
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW */      { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION */  { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION */   { CMDU_TYPE_INVALID, 0 },
    /* CMDU_TYPE_HIGHER_LAYER_QUERY */              { CMDU_TYPE_HIGHER_LAYER_RESPONSE, 0 },
    /* CMDU_TYPE_HIGHER_LAYER_RESPONSE */           { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST */  { CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE, 0 },
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE */ { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_GENERIC_PHY_QUERY */               { CMDU_TYPE_GENERIC_PHY_RESPONSE, 0 },
    /* CMDU_TYPE_GENERIC_PHY_RESPONSE */            { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
};

static const struct cmdu_info _map_response_cmdu[] =
{
    /* CMDU_TYPE_ACK */                                     { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_AP_CAPABILITY_QUERY */                     { CMDU_TYPE_AP_CAPABILITY_REPORT, 0 },
    /* CMDU_TYPE_AP_CAPABILITY_REPORT */                    { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_MAP_POLICY_CONFIG_REQUEST */               { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CHANNEL_PREFERENCE_QUERY */                { CMDU_TYPE_CHANNEL_PREFERENCE_REPORT, 0 },
    /* CMDU_TYPE_CHANNEL_PREFERENCE_REPORT */               { CMDU_TYPE_ACK, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_CHANNEL_SELECTION_REQUEST */               { CMDU_TYPE_CHANNEL_SELECTION_RESPONSE, 0 },
    /* CMDU_TYPE_CHANNEL_SELECTION_RESPONSE */              { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_OPERATING_CHANNEL_REPORT */                { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CLIENT_CAPABILITY_QUERY */                 { CMDU_TYPE_CLIENT_CAPABILITY_REPORT, 0 },
    /* CMDU_TYPE_CLIENT_CAPABILITY_REPORT */                { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_AP_METRICS_QUERY */                        { CMDU_TYPE_AP_METRICS_RESPONSE, 0 },
    /* CMDU_TYPE_AP_METRICS_RESPONSE */                     { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_ASSOCIATED_STA_LINK_METRICS_QUERY */       { CMDU_TYPE_ASSOCIATED_STA_LINK_METRICS_RESPONSE, 0 },
    /* CMDU_TYPE_ASSOCIATED_STA_LINK_METRICS_RESPONSE */    { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* CMDU_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY */     { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE */  { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_BEACON_METRICS_QUERY */                    { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_BEACON_METRICS_RESPONSE */                 { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_COMBINED_INFRASTRUCTURE_METRICS */         { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CLIENT_STEERING_REQUEST */                 { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CLIENT_STEERING_BTM_REPORT */              { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CLIENT_ASSOCIATION_CONTROL */              { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_STEERING_COMPLETED */                      { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_HIGHER_LAYER_DATA */                       { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_BACKHAUL_STEERING_REQUEST */               { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_BACKHAUL_STEERING_RESPONSE */              { CMDU_TYPE_ACK, 0 },

    /* CMDU_TYPE_CHANNEL_SCAN_REQUEST */                    { CMDU_TYPE_CHANNEL_SCAN_REPORT, 0 },
    /* CMDU_TYPE_CHANNEL_SCAN_REPORT */                     { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CAC_REQUEST */                             { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CAC_TERMINATION */                         { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_CLIENT_DISASSOCIATION_STATS */             { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_ERROR_RESPONSE */                          { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_ASSOCIATION_STATUS_NOTIFICATION */         { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_TUNNELED */                                { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_BACKHAUL_STA_CAPABILITY_QUERY */           { CMDU_TYPE_BACKHAUL_STA_CAPABILITY_REPORT, 0 },
    /* CMDU_TYPE_BACKHAUL_STA_CAPABILITY_REPORT */          { CMDU_TYPE_INVALID, CMDU_INFO_FLAG_CHECK_REQUEST },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* NULL */                                              { CMDU_TYPE_ACK, 0 },
    /* CMDU_TYPE_FAILED_CONNECTION */                       { CMDU_TYPE_ACK, 0 },
};

static uint16_t getCmduInfoRespMtype(uint16_t mtype)
{
    if (mtype <= CMDU_TYPE_DEFINED_IN_1905_LAST)
        return _response_cmdu[mtype].resp_type;
    if (mtype >= CMDU_TYPE_DEFINED_IN_MAP_FIRST
        && mtype <= CMDU_TYPE_DEFINED_IN_MAP_LAST)
        return _map_response_cmdu[mtype - CMDU_TYPE_DEFINED_IN_MAP_FIRST].resp_type;
    return CMDU_TYPE_INVALID;
}

static uint8_t getCmduInfoFlag(uint16_t mtype)
{
    if (mtype <= CMDU_TYPE_DEFINED_IN_1905_LAST)
        return _response_cmdu[mtype].flag;
    if (mtype >= CMDU_TYPE_DEFINED_IN_MAP_FIRST
        && mtype <= CMDU_TYPE_DEFINED_IN_MAP_LAST)
        return _map_response_cmdu[mtype - CMDU_TYPE_DEFINED_IN_MAP_FIRST].flag;
    return 0;
}

static struct cmdu_retry *findCmduRetryByResp(const uint8_t *src_addr, uint16_t mtype, uint16_t mid, uint8_t diff_mid)
{
    struct cmdu_retry *retry;
    dlist_for_each(retry, cmdu_retry_head, l)
    {
        if (!retry->cmdu)
            continue;

        if (!diff_mid && mid != retry->cmdu->message_id)
            continue;

        if (mtype != getCmduInfoRespMtype(retry->cmdu->message_type))
            continue;

        if (memcmp(src_addr, retry->dst_addr, sizeof(mac_address)))
            continue;

        return retry;
    }
    return NULL;
}

static void processRetryTimer(void *ctx, void *p)
{
    struct cmdu_retry *retry = (struct cmdu_retry *)p;

    retry->timer = NULL;

    if (retry->retries++ < map_config.retries)
    {
        retry->timer = PLATFORM_SET_TIMEOUT(map_config.wait_ack,
                processRetryTimer, NULL, retry);
        PLATFORM_PRINTF_DEBUG_INFO("Retry(%uth) to send %s\n",
            retry->retries,
            retry->cmdu ? convert_1905_CMDU_type_to_string(retry->cmdu->message_type) : "NULL");
        if (retry->cmdu)
        {
            retry->cmdu->message_id = getNextMid();
            if (0 == send1905RawPacket(retry->ifname,
                    retry->cmdu->message_id, retry->dst_addr, retry->cmdu))
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send packet\n");
        }
    }

    if (!retry->timer)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Send %s excess the max tries %u\n",
                retry->cmdu ? convert_1905_CMDU_type_to_string(retry->cmdu->message_type) : "NULL",
                map_config.retries);
        dlist_remove(&retry->l);
        freeCmduRetryData(retry);
        free(retry);
    }
}

uint8_t checkAndFireRetryTimer(const char *ifname,
        const uint8_t *dst_addr, struct CMDU *cmdu)
{
    struct cmdu_retry *retry;

    if (!ifname || !dst_addr || !cmdu)
        return 0;

    if (CMDU_TYPE_INVALID == getCmduInfoRespMtype(cmdu->message_type))
        return 0;

    if (NULL != (retry = findCmduRetryByMtype(dst_addr, cmdu->message_type)))
    {
        PLATFORM_PRINTF_DEBUG_INFO("New %s sent before the last same message response received\n",
                convert_1905_CMDU_type_to_string(cmdu->message_type));

        freeCmduRetryData(retry);
    }
    else
    {
        retry = malloc(sizeof(*retry));
        dlist_add_tail(&cmdu_retry_head, &retry->l);
    }
    retry->cmdu = cmdu;
    retry->retries = 0;
    retry->ifname = strdup(ifname);
    memcpy(retry->dst_addr, dst_addr, sizeof(mac_address));

    retry->timer = PLATFORM_SET_TIMEOUT(map_config.wait_ack,
            processRetryTimer, NULL, retry);
    if (!retry->timer)
    {
        dlist_remove(&retry->l);
        free(retry);
        return 0;
    } else {
        return 1;
    }
}

void checkAndStopRetryTimer(const uint8_t *src_addr, uint16_t mtype, uint16_t mid)
{
    struct cmdu_retry *retry;
    uint8_t flag = getCmduInfoFlag(mtype);

    if (!(flag & CMDU_INFO_FLAG_CHECK_REQUEST))
        return;

    if (!src_addr)
        return;

    retry = findCmduRetryByResp(src_addr, mtype, mid, flag & CMDU_INFO_FLAG_RESP_DIFF_MID);
    if (retry)
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Response of %s received after %u retries\n",
            retry->cmdu ? convert_1905_CMDU_type_to_string(retry->cmdu->message_type) : "NULL",
            retry->retries);

        dlist_remove(&retry->l);
        freeCmduRetryData(retry);
        free(retry);
    }
}
