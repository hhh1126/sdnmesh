/*
 *  Copyright (c) 2020, Semiconductor Components Industries, LLC
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
 * @brief MAP roaming logic decision
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
#include "al_recv.h"
#include "linux/platform_qdock.h"
#include "ubus_map.h"
#include "map_steering.h"

struct mapSteeringConfig map_steering_config;
struct qSteeringPolicyConfig qsteering_policy_config;

dlist_head qsteering_sta_entry_head;

#define QSTEERING_PRINTF_FUNC_DEFINE(name, value) \
void qsteering_printf_debug_##name(const char *func, uint32_t line, const char *format, ...)\
{\
    va_list arglist;\
    if (map_steering_config.debugging_print_level < (value))\
        return; \
    printf("(%-20.20s:%04u)", func, line); \
    printf("%-6.6s: [Q_STEERING] ", ""#name""); \
    va_start( arglist, format ); \
    vprintf( format, arglist ); \
    va_end( arglist ); \
}

QSTEERING_PRINTF_FUNC_DEFINE(error, 0)
QSTEERING_PRINTF_FUNC_DEFINE(warning, 1)
QSTEERING_PRINTF_FUNC_DEFINE(info, 2)
QSTEERING_PRINTF_FUNC_DEFINE(detail, 3)


/** @brief  restore the steering configuration to default, and active it only at controller side */
void defaultQSteeringConfig(void)
{
    memset(&map_steering_config, 0, sizeof(map_steering_config));

    if (map_config.role == MAP_ROLE_CONTROLLER)
    {
        map_steering_config.steering_enabled = 1;
        map_steering_config.rcpi_boundry_to_attemp_steering = 80;
        map_steering_config.better_rcpi_gain_in_target_bss = 15;
        map_steering_config.assoc_sta_rcpi_checking_period = 2;
        map_steering_config.debugging_print_level = 1;
        map_steering_config.waiting_for_neighboring_rcpi_collecting_done = 2;
        map_steering_config.waiting_for_steering_attemp_done = 10;

        memset(&qsteering_policy_config, 0, sizeof(qsteering_policy_config));
        dlist_head_init(&qsteering_policy_config.policy_head);
    }
}

static void _qSteeringSTAEntryRemoveCandidatebyDevice(struct qSteeringSTAEntry *entry, struct alDevice *device)
{
    dlist_item *item;
    while (NULL != (item = dlist_get_first(&entry->candidates)))
    {
        struct qSteeringCandidateBSS *candidate = container_of(item, struct qSteeringCandidateBSS, l);
        if (!device || candidate->dev == device)
        {
            if (device)
                QSTEERING_PRINTF_DEBUG_DETAIL("Remove the bss candidate entry [" MACSTR "] of sta entry [" MACSTR "] away from head list"
                        " due to the associated device [" MACSTR "] is gone!\n", MAC2STR(candidate->bssid), MAC2STR(entry->sta_mac),
                        MAC2STR(candidate->dev->al_mac_addr));
            dlist_remove(item);
            free(candidate);
        }
    }
}

static struct qSteeringSTAEntry *_qSteeringSTAEntryAlloc(struct interfaceWifi *ifw, uint8_t *mac)
{
    struct qSteeringSTAEntry *entry = zmemalloc(sizeof(struct qSteeringSTAEntry));
    memcpy(entry->sta_mac, mac, sizeof(mac_address));
    entry->assoc_ifw = ifw;
    QSTEERING_PRINTF_DEBUG_DETAIL("allocate steering entry for sta" MACSTR " which is associating with " MACSTR "\n",
            MAC2STR(mac), MAC2STR(ifw->bssInfo.bssid));
    dlist_head_init(&entry->candidates);
    dlist_add_tail(&qsteering_sta_entry_head, &entry->l);
    return entry;
}

void _qSteeringSTAEntryDelete(struct qSteeringSTAEntry *entry)
{
    if (entry->collecting_sta_rcpi_timer)
    {
        QSTEERING_PRINTF_DEBUG_DETAIL("Cancel the sta entry [" MACSTR "] neighboring RCPI collecting timer!\n",
                MAC2STR(entry->sta_mac));
        PLATFORM_CANCEL_TIMEOUT(entry->collecting_sta_rcpi_timer);
    }

    QSTEERING_PRINTF_DEBUG_DETAIL("remove sta steering entry "MACSTR" away \n",MAC2STR(entry->sta_mac));
    dlist_remove(&entry->l);

    _qSteeringSTAEntryRemoveCandidatebyDevice(entry, NULL);

    free(entry);
}

static struct qSteeringPocicyItem *_qSteeringCheckPolicyConfigExist(const mac_address al_mac, const mac_address uid)
{
    struct qSteeringPocicyItem *policy_config;

    dlist_for_each(policy_config, qsteering_policy_config.policy_head, l)
    {
        if (!memcmp(al_mac, policy_config->device->al_mac_addr, sizeof(mac_address))
	    && !memcmp(uid, policy_config->radio_id, sizeof(mac_address)))
            return policy_config;
    }
    return NULL;
}

static struct qSteeringPocicyItem *_qSteeringAddNewPolicyConfigEntry(struct alDevice *device, const mac_address uid)
{
    struct qSteeringPocicyItem *policy_config = NULL;

    policy_config = (struct qSteeringPocicyItem *)malloc(sizeof(struct qSteeringPocicyItem));

    if (!policy_config)
        return NULL;
    policy_config->device = device;
    memcpy(policy_config->radio_id, uid, sizeof(mac_address));
    dlist_add_tail(&qsteering_policy_config.policy_head, &policy_config->l);
    QSTEERING_PRINTF_DEBUG_DETAIL("add new policy config entry for radio "MACSTR" in device "MACSTR"\n",MAC2STR(policy_config->radio_id),
        MAC2STR(policy_config->device->al_mac_addr));

    return policy_config;
}

static void _qSteeringRemovePolicyConfig(struct qSteeringPocicyItem *policy_config)
{
    QSTEERING_PRINTF_DEBUG_DETAIL("remove policy config entry of radio "MACSTR" from head\n",MAC2STR(policy_config->radio_id));
    dlist_remove(&policy_config->l);
    free(policy_config);
}

static struct qSteeringSTAEntry *findSteeringSTAEntry(uint8_t *mac)
{
    struct qSteeringSTAEntry *steering_sta_entry;
    dlist_for_each(steering_sta_entry, qsteering_sta_entry_head, l)
    {
        if (memcmp(steering_sta_entry->sta_mac, mac, 6) == 0)
            return steering_sta_entry;
    }
    return NULL;
}

static struct qSteeringSTAEntry *findOrAddSteeringSTAEntry(struct alDevice *device, struct interfaceWifi *ifw, uint8_t *mac,
        uint8_t rcpi, uint32_t last_ts, uint8_t *new_created)
{
    struct qSteeringSTAEntry *steering_sta_entry = findSteeringSTAEntry(mac);

    if (steering_sta_entry && steering_sta_entry->assoc_ifw != ifw)
    {
        QSTEERING_PRINTF_DEBUG_DETAIL("the sta entry " MACFMT " has reassociated with other new ifw " MACFMT ",destroy it then realloc\n",
                MAC2STR(steering_sta_entry->sta_mac), MAC2STR(ifw->bssInfo.bssid));
        _qSteeringSTAEntryDelete(steering_sta_entry);
        steering_sta_entry = NULL;
    }

    if (!steering_sta_entry)
    {
        steering_sta_entry = _qSteeringSTAEntryAlloc(ifw, mac);
        if (!steering_sta_entry)
        {
            QSTEERING_PRINTF_DEBUG_ERROR("Alloc qsteering entry for sta " MACFMT " failed\n",
                    MAC2STR(mac));
            return NULL;
        }
        steering_sta_entry->device = device;
        steering_sta_entry->rcpi = rcpi;
        steering_sta_entry->last_ts = last_ts;
        *new_created = 1;
    }

    return steering_sta_entry;
}

#if 0 /* implementation for sta beacon metric query is not required in the first phrase design*/
static uint8_t *qSteeringConstructAPChannelReport(uint8_t *tmp_buf, uint8_t bss_nums)
{
    uint8_t *reports = NULL, buff[512] = {0}; /* assume the maximum ap channel report per bss is 255 */
	int chan_reports_len = 0, chan_list_len = 1, report_num = 1, i, j, tmp_opclass, tmp_chan;

	for (i = 0; i < bss_nums; i++)
	{
	    for (j = 0; j < bss_nums; j++)
	    {
	        if (tmp_buf[2*j] > tmp_buf[2*i])
	        {
	            tmp_opclass = tmp_buf[2*i];
				tmp_chan = tmp_buf[2*i+1];
				tmp_buf[2*i] = tmp_buf[2*j];
				tmp_buf[2*i+1] = tmp_buf[2*j+1];
				tmp_buf[2*j] = tmp_opclass;
				tmp_buf[2*j+1] = tmp_chan;
	        }
	    }
	}

    buff[1] = tmp_opclass = tmp_buf[0];
	for (i = 0; i < bss_nums; i++)
	{
        if (tmp_buf[2*i] > tmp_opclass)
		{
		    tmp_opclass = tmp_buf[2*i];
			buff[chan_reports_len] = chan_list_len;
            chan_list_len ++;             /** @ add one byte len for the ap channel report len  */
			chan_reports_len += chan_list_len;
			buff[chan_reports_len + 1] = tmp_opclass;
			chan_list_len = 1;
			report_num++;

		}
		buff[chan_reports_len + chan_list_len + 1] = tmp_buf[2*i+1];
		chan_list_len++;
	}
	buff[chan_reports_len] = chan_list_len;
	chan_list_len ++;             /** @ add one byte len for the ap channel report len  */
	chan_reports_len += chan_list_len;
    reports = (uint8_t *)zmemalloc(chan_reports_len);
	if (reports)
	{
		*reports = report_num;
		memcpy((reports+1), buff, chan_reports_len);
	}

	return reports;
}
#endif

static int qSteeringConstructUnassocSTAMetricQuery(dlist_head *head, uint8_t chan, uint8_t *sta_mac)
{
    struct chanUnassocSta *chan_item;
    struct macAddressItem *mac_item;

    chan_item = (struct chanUnassocSta *)malloc(sizeof(*chan_item));

    if (!chan_item)
        return 0;

    dlist_add_tail(head, &chan_item->l);
    dlist_head_init(&chan_item->unassocSTAs);
    chan_item->chan = chan;

    mac_item = zmemalloc(sizeof(struct macAddressItem));
    if (!mac_item)
        return 0;

    memcpy(mac_item->mac, sta_mac, sizeof(mac_address));
    dlist_add_tail(&chan_item->unassocSTAs, &mac_item->l);

    return 1;
}

static int qSteeringSendPolicyConfig(struct alDevice *device, const mac_address uid, struct qSteeringPocicyItem *policy_config)
{
    uint8_t interval;
    dlist_head metric_reporting_policy_head;
    struct radioMetricPolicyItem *item;

    if (!device || !policy_config)
        return 0;

    interval = policy_config->repoting_interval;

    dlist_head_init(&metric_reporting_policy_head);
    item = (struct radioMetricPolicyItem *)malloc(sizeof(*item));
    memset(item, 0x0, sizeof(*item));
    memcpy(item->radio_id, uid, sizeof(mac_address));
    item->metric_policy.rcpi_threshold = policy_config->rcpi_threshold;
    item->metric_policy.policy |= METRIC_REPORTING_POLICY_INCLUDE_ASSOCED_LINK_METRICS;
    dlist_add_tail(&metric_reporting_policy_head, &item->l);
    QSTEERING_PRINTF_DEBUG_INFO(" send " MACSTR " policy config for radio " MACSTR " of sta rcpi metric reporting\n",
            MAC2STR(device->al_mac_addr), MAC2STR(uid));
    if (!send1905MAPPolicyConfigRequest(NULL, NULL, NULL, interval, &metric_reporting_policy_head, device->receiving_interface_name,
        getNextMid(), device->al_mac_addr))
    {
        QSTEERING_PRINTF_DEBUG_WARNING("Failed to send " MACSTR " policy config for radio " MACSTR " of sta rcpi metric reporting\n",
                MAC2STR(device->al_mac_addr), MAC2STR(uid));
        return 0;
    }

        return 1;
}

static void qSteeringInitAssocControlRequest(struct qSteeringSTAEntry *entry, struct qSteeringCandidateBSS *target)
{
    struct qSteeringCandidateBSS *candidate;
    dlist_head assoc_control_stas_head;
    struct macAddressItem *item;

    dlist_head_init(&assoc_control_stas_head);
    item = zmemalloc(sizeof(struct macAddressItem));
    memcpy(item->mac, entry->sta_mac, sizeof(mac_address));
    dlist_add_tail(&assoc_control_stas_head, &item->l);

    dlist_for_each(candidate, entry->candidates, l)
    {
        if (!candidate->dev)
            continue;

    	if (candidate == target || candidate->dev == entry->device)
            continue;

        QSTEERING_PRINTF_DEBUG_INFO("try to send client assoc control request to " MACSTR " for blocking sta "
                "" MACSTR " for %d sec long\n", MAC2STR(candidate->dev->al_mac_addr), MAC2STR(entry->sta_mac),
                map_steering_config.waiting_for_steering_attemp_done);
        if (!send1905ClientAssociationControlRequest(candidate->dev->receiving_interface_name, getNextMid(), candidate->dev->al_mac_addr,
            candidate->bssid, ASSOC_CTRL_BLOCK, map_steering_config.waiting_for_steering_attemp_done, &assoc_control_stas_head))
            QSTEERING_PRINTF_DEBUG_WARNING("send1905ClientAssociationControlRequest to " MACSTR " for blocking sta "
                    "" MACSTR " for %d sec long failed\n", MAC2STR(candidate->dev->al_mac_addr), MAC2STR(entry->sta_mac),
	            map_steering_config.waiting_for_steering_attemp_done);
    }
    dlist_free_items(&assoc_control_stas_head, struct macAddressItem, l);
}

static int qSteeringConstructStaHead(struct qSteeringSTAEntry *entry, struct qSteeringCandidateBSS *candidate, dlist_head *sta_head)
{
    struct steeringStaItem *item;

    if (!sta_head)
        return 0;

    item = zmemalloc(sizeof(struct steeringStaItem));
    if (!item)
        return 0;

    memcpy(item->mac, entry->sta_mac, sizeof(mac_address));
    memcpy(item->targetBssid, candidate->bssid, sizeof(mac_address));
    item->target_bss_opclass = candidate->opclass;
    item->target_bss_ch = candidate->chan;
    dlist_add_tail(sta_head, &item->l);

    return 1;
}

static int qSteeringInitClientSteeringMandate(struct qSteeringSTAEntry *entry, struct qSteeringCandidateBSS *candidate)
{
    uint16_t mid = getNextMid();
    uint8_t mode = STEERING_REQ_MODE_MANDATE | STEERING_REQ_MODE_DISASSOC_IMM;
    dlist_head steering_stas_head;

    if (!entry->device || !entry->assoc_ifw)
        return 0;

    dlist_head_init(&steering_stas_head);
    QSTEERING_PRINTF_DEBUG_DETAIL("try to construct steering sta head for " MACSTR " toward to target bss " MACSTR "\n",
            MAC2STR(entry->sta_mac), MAC2STR(candidate->bssid));
    if (!qSteeringConstructStaHead(entry, candidate, &steering_stas_head))
    {
        QSTEERING_PRINTF_DEBUG_WARNING("failed to construct steering sta head for " MACSTR " toward to target bss " MACSTR "\n",
                MAC2STR(entry->sta_mac), candidate->bssid);
        dlist_free_items(&steering_stas_head, struct steeringStaItem, l);
        return 0;
    }

    QSTEERING_PRINTF_DEBUG_INFO("try to send client steering request to " MACSTR " for sta "
            "" MACSTR " steering \n", MAC2STR(entry->device->al_mac_addr), MAC2STR(entry->sta_mac));
    if (!send1905ClientSteeringRequest(entry->device->receiving_interface_name, mid, entry->device->al_mac_addr,
        entry->assoc_ifw->bssInfo.bssid, mode, 0, 0, &steering_stas_head))
        QSTEERING_PRINTF_DEBUG_WARNING("send client steering request to " MACSTR " for sta "
                "" MACSTR " steering failed\n", MAC2STR(entry->device->al_mac_addr), MAC2STR(entry->sta_mac));

    entry->is_steering = 1;
    entry->steered_ts = PLATFORM_GET_TIMESTAMP();
    dlist_free_items(&steering_stas_head, struct steeringStaItem, l);

    return 1;
}

void qSteeringSendApCapabilityQuery(struct alDevice *device)
{
    QSTEERING_PRINTF_DEBUG_INFO("try to send AP capability query to " MACSTR "\n",
            MAC2STR(device->al_mac_addr));
    if (!send1905ApCapabilityQuery(device->receiving_interface_name, getNextMid(), device->al_mac_addr))
    {
        QSTEERING_PRINTF_DEBUG_WARNING("send AP capability query to " MACSTR " failed\n",
                MAC2STR(device->al_mac_addr));
    }
}

int qSteeringAddPolicyConfigReqForAssocedSTAMetric(struct alDevice *device, const mac_address uid)
{
    struct qSteeringPocicyItem *policy_config = _qSteeringCheckPolicyConfigExist(device->al_mac_addr, uid);

    if (!policy_config)
        policy_config = _qSteeringAddNewPolicyConfigEntry(device, uid);
    policy_config->repoting_interval = map_steering_config.assoc_sta_rcpi_checking_period;
    policy_config->rcpi_threshold = map_steering_config.rcpi_boundry_to_attemp_steering;

    qSteeringSendPolicyConfig(device, uid, policy_config);

    return 1;
}

void qSteeringDeleteRadioPolicyConfigEntryByDevice(struct alDevice *device)
{
    struct radio *radio;
    struct qSteeringPocicyItem *policy_config;

    dlist_for_each(radio, device->radios, l)
    {
        if (radio && (policy_config = _qSteeringCheckPolicyConfigExist(device->al_mac_addr, radio->uid)))
        {
            QSTEERING_PRINTF_DEBUG_DETAIL("The policy config entry of radio "MACSTR " is going to be removed!\n",
                    MAC2STR(radio->uid));
	    _qSteeringRemovePolicyConfig(policy_config);
        }
    }
}

void qSteeringDeleteSteeringSTAEntryAndCandidateBSSEntryByDevice(struct alDevice *device,
        dlist_head *sta_entry_head)
{
    while (!dlist_empty(sta_entry_head))
    {
        struct qSteeringSTAEntry *steering_sta_entry = container_of(dlist_get_first(sta_entry_head), struct qSteeringSTAEntry, l);
        if (steering_sta_entry)
        {
            if (steering_sta_entry->device == device)
            {
                QSTEERING_PRINTF_DEBUG_DETAIL("Remove the sta entry [" MACSTR "] away from head list"
                        " due to the associated device [" MACSTR "] is gone!\n", MAC2STR(steering_sta_entry->sta_mac));
                _qSteeringSTAEntryDelete(steering_sta_entry);
            }
            else
            {
                _qSteeringSTAEntryRemoveCandidatebyDevice(steering_sta_entry, device);
            }
        }
    }
}

void qSteeringDeleteAllEntries(struct alDevice *device)
{
    qSteeringDeleteRadioPolicyConfigEntryByDevice(device);
    qSteeringDeleteSteeringSTAEntryAndCandidateBSSEntryByDevice(device, &qsteering_sta_entry_head);
}

#if 0 /* implementation for sta beacon metric query is not required in the first phrase of design*/
int qSteeringSendBeaconMetricQueryForCandidateBSS(struct alDevice *device, struct interfaceWifi *assoced_ifw, struct staInfo *sta)
{
    uint8_t bss_nums = 0, chan_number = 0, opclass, reporting_detail = 0, ssid_len;
	struct alDevice *dev;
	struct interfaceWifi *ifw;
	mac_address bssid;
	uint8_t ssid[1 + TLV_FIELD_MAX_NUMBER] = { 0 }, tmp_buf[512] = {0}, *chan_reports = NULL;
	int ret = 0;

	if (!device || !assoced_ifw || !sta)
		return 0;

    dlist_for_each(dev, network, l)
    {
    	if (dev == device)
			continue;
        if ((ifw = findWifiInterfaceWithSSID(dev, &assoced_ifw->bssInfo.ssid, assoced_ifw->radio->band_supported)))
        {
        	opclass = ifw->radio->opclass;
			//memcpy(bssid, ifw->bssInfo.bssid, sizeof(mac_address));

			ssid_len = ifw->bssInfo.ssid.length;
			ssid[0] = ssid_len;
			memcpy(&ssid[1], ifw->bssInfo.ssid.ssid, ssid_len);
            ssid[1+ssid_len] = '\0';

            tmp_buf[2*bss_nums] = ifw->radio->opclass;
			tmp_buf[2*bss_nums+1] = ifw->radio->chan;
			bss_nums++;
        }
    }

    memcpy(bssid, TARGET_WILDCARD, sizeof(mac_address));

	if (tmp_buf[0] && tmp_buf[1])
	{
	    chan_reports = qSteeringConstructAPChannelReport(tmp_buf, bss_nums);
		chan_number = 255;
	}

	if (chan_reports)
	{
	    if (!send1905BeaconMetricsQuery(sta->mac, opclass, chan_number, bssid, reporting_detail, ssid,
			chan_reports, NULL, device->receiving_interface_name, getNextMid(), device->al_mac_addr))
		{
            PLATFORM_PRINTF_DEBUG_WARNING("[Q_STEERING] send1905BeaconMetricsQuery to " MACSTR " failed\n",
                                      MAC2STR(device->al_mac_addr));
            ret = 0;
        }
		ret = 1;
        free(chan_reports);
	}
	return ret;
}
#endif

void qSteeringSendClientCapabilityQueryForBTMCapability(struct alDevice *device, uint8_t *bssid, uint8_t *sta_mac)
{
    uint16_t mid = getNextMid();

    if (device && bssid && sta_mac)
    {
        QSTEERING_PRINTF_DEBUG_INFO("Try to send client capability query for sta "MACSTR " to learn itself btm capability\n",
                MAC2STR(sta_mac));
        send1905ClientCapabilityQuery(bssid, sta_mac, device->receiving_interface_name, mid, device->al_mac_addr);
    }
}

static void _processWaitingforCollectingTimer(void *ctx, void *p)
{
    struct qSteeringSTAEntry *steering_sta_entry = (struct qSteeringSTAEntry *)p;
    struct qSteeringCandidateBSS *candidate, *target_candidate = NULL;
    uint8_t max_rcpi_gain = 0, rcpi_gain, i = 1;
    uint32_t ts_gap;

    QSTEERING_PRINTF_DEBUG_INFO("The sta " MACFMT " neighboring RCPI collecting timer expired! btm_supported:%d rcpi:%d ts:%u\n",
            MACARG(steering_sta_entry->sta_mac), steering_sta_entry->btm_allowed, steering_sta_entry->rcpi, steering_sta_entry->last_ts);

    dlist_for_each(candidate, steering_sta_entry->candidates, l)
    {
        if (candidate->measured_timestamp > steering_sta_entry->last_ts)
            ts_gap = candidate->measured_timestamp - steering_sta_entry->last_ts;
        else
            ts_gap = steering_sta_entry->last_ts - candidate->measured_timestamp;
        QSTEERING_PRINTF_DEBUG_DETAIL("Candidate BSS (%d) " MACFMT " of rcpi:%d ts:%u ts_gap:%u\n", i++, MACARG(candidate->bssid),
                candidate->measured_rcpi, candidate->measured_timestamp, ts_gap);
        if (ts_gap < (map_steering_config.waiting_for_neighboring_rcpi_collecting_done * 1000))
        {
            if (candidate->measured_rcpi > steering_sta_entry->rcpi)
            {
                rcpi_gain = candidate->measured_rcpi - steering_sta_entry->rcpi;
                if ((rcpi_gain > map_steering_config.better_rcpi_gain_in_target_bss) && rcpi_gain > max_rcpi_gain)
                {
	             max_rcpi_gain = rcpi_gain;
	             target_candidate = candidate;
	        }
            }
        }
    }

    if (target_candidate)
    {
        QSTEERING_PRINTF_DEBUG_INFO("The target candidate of bss " MACSTR " is found with rcpi gain :%d \n", MAC2STR(target_candidate->bssid), rcpi_gain);
        memcpy(steering_sta_entry->target_bssid, target_candidate->bssid, sizeof(mac_address));
        qSteeringInitClientSteeringMandate(steering_sta_entry, target_candidate);
        if (!steering_sta_entry->btm_allowed)
            qSteeringInitAssocControlRequest(steering_sta_entry, target_candidate);
    }

    steering_sta_entry->collecting_sta_rcpi_timer = NULL;
}

static void qSteeringSendUnassocSTALinkMetricQueryForCandidateBSS(struct alDevice *device, struct interfaceWifi *assoced_ifw,
        struct staInfo *sta, uint8_t rcpi, uint32_t last_ts)
{
    uint8_t opclass, under_collecting = 0, new_created = 0;
    struct alDevice *dev;
    struct interfaceWifi *ifw;
    struct qSteeringSTAEntry *steering_sta_entry;
    dlist_head chans_head;

    if (!device || !assoced_ifw || !sta)
        return;

    steering_sta_entry = findOrAddSteeringSTAEntry(device, assoced_ifw, sta->mac, rcpi, last_ts, &new_created);

    if (!steering_sta_entry)
    {
        QSTEERING_PRINTF_DEBUG_WARNING("The steering sta entry of " MACSTR " is not found!\n", MAC2STR(sta->mac));
        return;
    }

    /* Ignoring the metric collection since the entry is under collecting */
    if (steering_sta_entry->collecting_sta_rcpi_timer)
        return;

    opclass = assoced_ifw->radio->opclass;
    dlist_for_each(dev, network, l)
    {
        if (dev == device || dev == local_device)
            continue;

        if ((ifw = findWifiInterfaceWithSSID(dev, &assoced_ifw->bssInfo.ssid, assoced_ifw->radio->band_supported)))
        {
            dlist_head_init(&chans_head);
            if (!qSteeringConstructUnassocSTAMetricQuery(&chans_head, assoced_ifw->radio->chan, sta->mac))
            {
                QSTEERING_PRINTF_DEBUG_WARNING("constructing unassoc sta metric query head for sta " MACSTR " on chan %d failed!\n", MAC2STR(sta->mac),
                        assoced_ifw->radio->chan);
                goto free_dlist;
            }

            if ((assoced_ifw->radio->chan != ifw->radio->chan && ifw->radio->monitor_offchan) || (assoced_ifw->radio->chan == ifw->radio->chan && ifw->radio->monitor_onchan))
            {
                QSTEERING_PRINTF_DEBUG_INFO("send unassoc STA metric query to " MACSTR " for sta " MACSTR "\n",MAC2STR(dev->al_mac_addr),MAC2STR(sta->mac));
	        if (!send1905UnassociatedSTALinkMetricsQuery(strlen(dev->receiving_interface_name) ? dev->receiving_interface_name :
                    device->receiving_interface_name, getNextMid(), dev->al_mac_addr, opclass, &chans_head))
	        {
                    QSTEERING_PRINTF_DEBUG_WARNING("send unassoc STA metric query to " MACSTR " for unassoc sta "
	                    "" MACSTR "failed\n", MAC2STR(dev->al_mac_addr), MAC2STR(sta->mac));
                }
                else
	            under_collecting = 1;
            }
            else
                QSTEERING_PRINTF_DEBUG_INFO(" send unassoc STA metric query to radio " MACSTR " on chan %d cause current chan %d and %s-chan monitoring is not supported\n",
                        MAC2STR(ifw->radio->uid), assoced_ifw->radio->chan, ifw->radio->chan, (assoced_ifw->radio->chan == ifw->radio->chan) ? "on" : "off");

free_dlist:
            mapapi_free_dlist_chan_stas(&chans_head);
            dlist_free_items(&chans_head, struct chanUnassocSta, l);
        }
    }

    if (under_collecting)
    {
        if (!sta->last_assoc_len)
            qSteeringSendClientCapabilityQueryForBTMCapability(device, assoced_ifw->bssInfo.bssid, sta->mac);
        else if (new_created)
            steering_sta_entry->btm_allowed = checkBtmSteeringForClient(sta);
        QSTEERING_PRINTF_DEBUG_INFO("Fire %d secs timer for collecting RCPI of neighboring BSSes\n",map_steering_config.waiting_for_neighboring_rcpi_collecting_done);
        steering_sta_entry->collecting_sta_rcpi_timer = PLATFORM_SET_TIMEOUT(map_steering_config.waiting_for_neighboring_rcpi_collecting_done * 1000,
                _processWaitingforCollectingTimer, NULL, steering_sta_entry);
    }
}

void qSteeringCheckAssocSTARCPI(struct alDevice *device, struct interfaceWifi *assoced_ifw,
        struct staInfo *sta, uint8_t rcpi, uint32_t last_ts)
{
    uint8_t go_steering;
    uint32_t cur_ts = PLATFORM_GET_TIMESTAMP();
    struct qSteeringSTAEntry *steering_sta_entry = findSteeringSTAEntry(sta->mac);

    if (steering_sta_entry && steering_sta_entry->is_steering)
    {
        if ((cur_ts - steering_sta_entry->steered_ts) > (map_steering_config.waiting_for_steering_attemp_done * 1000))
        {
            QSTEERING_PRINTF_DEBUG_DETAIL("reset sta entry "MACSTR" of is_steering flag to 0 after %d secs of steering period away\n",
                    MAC2STR(steering_sta_entry->sta_mac), map_steering_config.waiting_for_steering_attemp_done);
            steering_sta_entry->is_steering = 0;
            memset(steering_sta_entry->target_bssid, 0, sizeof(mac_address));
        }
        else
            return;
    }

    if (steering_sta_entry)
    {
        steering_sta_entry->rcpi = rcpi;
        steering_sta_entry->last_ts = last_ts;
    }

    go_steering = (rcpi < map_steering_config.rcpi_boundry_to_attemp_steering) ? 1 : 0;
    QSTEERING_PRINTF_DEBUG_INFO("" MACSTR " RCPI [%d] is %s than thresold [%d], %s need steering\n", MAC2STR(sta->mac), rcpi, go_steering ? "lower" : "higher",
            map_steering_config.rcpi_boundry_to_attemp_steering, go_steering ? "" : "don't");
    if(go_steering)
        qSteeringSendUnassocSTALinkMetricQueryForCandidateBSS(device, assoced_ifw, sta, rcpi, last_ts);
}

static struct qSteeringCandidateBSS *qSteeringFindCandidateBSS(struct qSteeringSTAEntry *entry, uint8_t *bssid)
{
    struct qSteeringCandidateBSS *candidate;

    dlist_for_each(candidate, entry->candidates, l)
    {
        if (!memcmp(candidate->bssid, bssid, sizeof(mac_address)))
            return candidate;
    }
    return NULL;
}

static void qSteeringUpdateCandidateBSS(struct alDevice *dev, struct interfaceWifi *ifw, struct qSteeringSTAEntry *entry, uint32_t ts, uint8_t rcpi)
{
    struct qSteeringCandidateBSS *candidate = qSteeringFindCandidateBSS(entry, ifw->bssInfo.bssid);

    if (!candidate)
    {
        candidate = zmemalloc(sizeof(struct qSteeringCandidateBSS));
        memcpy(candidate->bssid, ifw->bssInfo.bssid, sizeof(mac_address));
        dlist_add_tail(&entry->candidates, &candidate->l);
    }

    candidate->dev = dev;
    candidate->opclass = ifw->radio->opclass;
    candidate->chan = ifw->radio->chan;
    candidate->measured_timestamp = ts;
    candidate->measured_rcpi = rcpi;
    QSTEERING_PRINTF_DEBUG_DETAIL("Update the measurement of candidate BSS "MACSTR ", "
            "rcpi :%d timestamp :%u \n", MAC2STR(candidate->bssid), rcpi, ts);
}

int qSteeringUpdateUnassocSTARCPI(struct alDevice *device, uint8_t *sta_mac, uint8_t observed_rcpi, uint32_t ts, uint8_t band)
{
    struct interfaceWifi *ifw, *assoced_ifw = NULL;
    struct staInfo *sta;
    struct alDevice *dev = NULL;
    struct qSteeringSTAEntry *steering_sta_entry = findSteeringSTAEntry(sta_mac);

    if (!steering_sta_entry)
    {
        QSTEERING_PRINTF_DEBUG_WARNING("failed to loop up steering entry for " MACSTR " \n", MAC2STR(sta_mac));
        return 0;
    }

    sta = findWifiClient(sta_mac, &assoced_ifw, &dev);

    if (!sta || !assoced_ifw)
        return 0;

    if ((ifw = findWifiInterfaceWithSSID(device, &assoced_ifw->bssInfo.ssid, band)))
    {
        qSteeringUpdateCandidateBSS(device, ifw, steering_sta_entry, ts, observed_rcpi);
    }

    return 1;
}

void qSteeringUpdateBTMAllowed(uint8_t *sta_mac, bool btm_allowed)
{
    struct qSteeringSTAEntry *steering_sta_entry = findSteeringSTAEntry(sta_mac);

    if (steering_sta_entry)
    {
        QSTEERING_PRINTF_DEBUG_DETAIL("Update sta entry " MACSTR " BTM supported capability : %d\n", MAC2STR(steering_sta_entry->sta_mac), btm_allowed);
        steering_sta_entry->btm_allowed = btm_allowed;
    }
}

void qSteeringCheckSteeringSTAEntryForNewAssociation(uint8_t *bssid, uint8_t *sta_mac)
{
    struct qSteeringSTAEntry *steering_sta_entry = findSteeringSTAEntry(sta_mac);

    if (steering_sta_entry)
    {
        if (!memcmp(steering_sta_entry->assoc_ifw->bssInfo.bssid, bssid, sizeof(mac_address)))
        {
            QSTEERING_PRINTF_DEBUG_INFO("Reset is_steering flag of sta " MACSTR " to 0\n", MAC2STR(sta_mac));
            steering_sta_entry->is_steering = 0;
            memset(steering_sta_entry->target_bssid, 0, sizeof(mac_address));
	}
        else
        {
            if (steering_sta_entry->is_steering && !memcmp(steering_sta_entry->target_bssid, bssid, sizeof(mac_address)))
                QSTEERING_PRINTF_DEBUG_INFO("The sta entry " MACSTR " is steered to bss" MACSTR " as expected.\n",
	                MAC2STR(sta_mac), MAC2STR(bssid));
            else
                QSTEERING_PRINTF_DEBUG_INFO("The sta entry " MACSTR " is associating with other new bss" MACSTR ", removing the sta entry\n",
                        MAC2STR(sta_mac), MAC2STR(bssid));
	    _qSteeringSTAEntryDelete(steering_sta_entry);
        }
    }
}

static void qSteeringRemoveAllPolicyConfigReqForAssocedSTAMetric(dlist_head *policy_config_head)
{
    while (!dlist_empty(policy_config_head))
    {
        struct qSteeringPocicyItem *policy_config = container_of(dlist_get_first(policy_config_head), struct qSteeringPocicyItem, l);
        if (policy_config)
        {
            QSTEERING_PRINTF_DEBUG_DETAIL("Reset the reporting period of policy config entry radio "MACSTR " to 0 then remove it!\n",
                    MAC2STR(policy_config->radio_id));
	    policy_config->repoting_interval = 0;
	    policy_config->rcpi_threshold = 0;
	    qSteeringSendPolicyConfig(policy_config->device, policy_config->radio_id, policy_config);
            _qSteeringRemovePolicyConfig(policy_config);
        }
    }
}

static void qSteeringRemoveAllSteeringSTAEntries(dlist_head *sta_entry_head)
{
    while (!dlist_empty(sta_entry_head))
    {
        struct qSteeringSTAEntry *steering_sta_entry = container_of(dlist_get_first(sta_entry_head), struct qSteeringSTAEntry, l);
        if (steering_sta_entry)
	    _qSteeringSTAEntryDelete(steering_sta_entry);
    }
}

void qSteeringResendPolicyConfig(void)
{
    struct qSteeringPocicyItem *policy_config;

    dlist_for_each(policy_config, qsteering_policy_config.policy_head, l)
    {
        if (policy_config->repoting_interval != map_steering_config.assoc_sta_rcpi_checking_period
            || policy_config->rcpi_threshold != map_steering_config.rcpi_boundry_to_attemp_steering)
        {
            policy_config->repoting_interval = map_steering_config.assoc_sta_rcpi_checking_period;
            policy_config->rcpi_threshold = map_steering_config.rcpi_boundry_to_attemp_steering;
            qSteeringSendPolicyConfig(policy_config->device, policy_config->radio_id, policy_config);
        }
    }
}

/** @brief start qsteering logic in periodical */
void startQSteering()
{
    QSTEERING_PRINTF_DEBUG_INFO("Start QSteering functionality......\n");
    dlist_head_init(&qsteering_sta_entry_head);
    map_steering_config.steering_actived = 1;
}

/** @brief stop qsteering logic */
void stopQSteering()
{
    QSTEERING_PRINTF_DEBUG_INFO("Stop QSteering functionality......\n");
    qSteeringRemoveAllPolicyConfigReqForAssocedSTAMetric(&qsteering_policy_config.policy_head);
    qSteeringRemoveAllSteeringSTAEntries(&qsteering_sta_entry_head);
    map_steering_config.steering_actived = 0;
}

