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
 *
 *  Portions of this software may include:
 *  Broadband Forum IEEE 1905.1/1a stack
 *  Copyright (c) 2017, Broadband Forum
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

#include "platform.h"

#include "al.h"
#include "al_recv.h"
#include "al_retry.h"
#include "al_datamodel.h"
#include "al_utils.h"
#include "al_send.h"
#include "al_wsc.h"
#include "al_extension.h"

#include "1905_tlvs.h"
#include "1905_cmdus.h"
#include "1905_alme.h"
#include "1905_l2.h"
#include "lldp_tlvs.h"
#include "lldp_payload.h"

#include "platform_interfaces.h"
#include "platform_alme_server.h"
#ifdef QDOCK
#include "linux/platform_qdock.h"
#endif

#include <datamodel.h>
#ifdef QDOCK
#include "linux/platform_qdock.h"
#endif
#include "ubus_map.h"
#include <string.h> // memcmp(), memcpy(), ...
#ifdef Q_STEERING_LOGIC
#include "map_steering.h"
#endif

#ifdef SPARTAN_PLATFORM

#define PRGM_NAME                          "map"
#define CONTROLLER_FOUND_NAME              "event.map_controller_found"
#define DUPLICATE_CONTROLLER_FOUND_NAME    "event.map_duplicated_controller_found"
#define MAP_RELOAD_TO_AGENT                "map_reload_to_agent"
#define MAP_RELOAD_CONTROLLER              "map_reload_controller"

static void map_send_event(const char* type, const char *data)
{
    int len = 0;
    char cmd[256];

    len = snprintf(cmd,  sizeof(cmd),
        "ubus send \"system.event\" '{\"prgm\":\"%s\", \"type\":\"%s\", "
        "\"data\":\"%s\"}'", PRGM_NAME, type, data);
    if (len < 256)
        system(cmd);
}

static int map_compare_mac(const uint8_t* mac1, const uint8_t* mac2)
{
    uint8_t c1, c2;
    int i;
    for (i = 0; i < 6; i++) {
        c1 = mac1[i];
        c2 = mac2[i];
        if ((c1 >= 65) && (c1 <= 90))
            c1 += 32;
        if ((c2 >= 65) && (c2 <= 90))
            c2 += 32;
        if (c1 > c2)
            return 1;
        else if (c1 < c2)
            return -1;
   }
   return 0;
}

#endif

/** @brief Update the data model with the received supportedServiceTLV.
 *
 * @return true if the sender is a Multi-AP controller.
 *
 * @a sender_device may be NULL, in which case nothing is updated but the return value may still be used.
 * @a supportedService may be NULL, in which case nothing is updated and false is returned.
 */
static bool handleSupportedServiceTLV(struct alDevice *sender_device, struct tlv *supportedService, uint16_t msg_type)
{
    bool sender_is_map_agent = false;
    bool sender_is_map_controller = false;
    struct _supportedService* service;
#ifdef SPARTAN_PLATFORM
    char data[32] = {0};
    int ret = 0;
#endif

    if (supportedService == NULL || !sender_device) {
        return false;
    }

    dlist_for_each(service, supportedService->s.h.children[0], s.h.l)
    {
        switch (service->service)
        {
        case SERVICE_MULTI_AP_AGENT:
            sender_is_map_agent = true;
            break;
        case SERVICE_MULTI_AP_CONTROLLER:
            sender_is_map_controller = true;
            if (registrar.d)
            {
                if (registrar.d != sender_device &&
                        (CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE == msg_type ||
                         CMDU_TYPE_TOPOLOGY_RESPONSE ==  msg_type)
                   )
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Found duplicated controller " MACFMT "\n",
                            MACARG(sender_device->al_mac_addr));

                    registrarAddDuplicantedController(sender_device);
                    registrar.last_seen = sender_device;
                    mapapi_event_duplicated_controller_detected(sender_device, msg_type);
#ifdef SPARTAN_PLATFORM
                /* backoff mechenism when duplicated controller is found, keep the controller
                   which has minimum mac address and reload other controller to agent mode.
                   controller also need to be reloaded after duplicated controller detected,
                   otherwise the controller will not work normally. */
                ret = map_compare_mac(registrar.d->al_mac_addr, sender_device->al_mac_addr);
                if (ret > 0)
                    snprintf(data, sizeof(data), "%s", MAP_RELOAD_TO_AGENT);
                else
                    snprintf(data, sizeof(data), "%s", MAP_RELOAD_CONTROLLER);
                map_send_event(DUPLICATE_CONTROLLER_FOUND_NAME, data);
#endif
                }
            }
            else
            {
                PLATFORM_PRINTF_DEBUG_INFO("Controller is " MACFMT "\n", MACARG(sender_device->al_mac_addr));
                registrar.d = sender_device;
#ifdef SPARTAN_PLATFORM
                snprintf(data, sizeof(data), MACFMT, MACARG(sender_device->al_mac_addr));
                map_send_event(CONTROLLER_FOUND_NAME, data);
#endif
            }
            registrar.is_map = true;
            break;
        default:
            PLATFORM_PRINTF_DEBUG_WARNING(
                        "Received AP Autoconfiguration Search with unknown Supported Service %02x\n",
                        service->service);
            /* Ignore it, as required by the specification. */
            break;
        }
    }
    /* Even if we are not registrar/controller, save the supported services in the data model. */
    if (sender_is_map_agent || sender_is_map_controller)
    {
        sender_device->is_map_agent = sender_is_map_agent;
        sender_device->is_map_controller = sender_is_map_controller;
    }
    else if (CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE == msg_type)
    {
        /* Record as old 1905 registrar */
        registrarAddDuplicantedRegistrar(sender_device);
        mapapi_event_duplicated_registrar_detected(sender_device);
    }

    return sender_is_map_controller;
}

/** @brief Update the data model with the received ApOperationalBssTLV.
 *
 * @return true if the sender is a Multi-AP Agent.
 *
 * @a sender_device may be NULL, in which case nothing is updated but the return value may still be used.
 * @a apOperationalBss may be NULL, in which case nothing is updated and false is returned.
 */
static bool handleApOperationalBssTLV(const char *ifname, struct alDevice *sender_device, struct tlv *apOperationalBss)
{
    struct _apOperationalBssRadio *bssRadio;
    struct _apOperationalBssInfo *bssInfo;
    struct interfaceWifi *ifw;
    struct radio *radio;
    struct dlist_head bssids;

    if (!sender_device || !apOperationalBss) {
        return false;
    }

    dlist_head_init(&bssids);

    dlist_for_each(bssRadio, apOperationalBss->s.h.children[0], s.h.l)
    {
        struct macAddressItem *item = zmemalloc(sizeof(struct macAddressItem));

        if (item)
        {
            memcpy(item->mac, bssRadio->radio_uid, 6);
            dlist_add_tail(&bssids, &item->l);
        }

        radio = findOrAddDeviceRadio(sender_device, bssRadio->radio_uid);
        if (!radio)
            return false;

        dlist_for_each(bssInfo, bssRadio->s.h.children[0], s.h.l)
        {
            ifw = alDevicefindWifiInterface(sender_device, bssInfo->bssid);
            if (!ifw)
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("try to add new WifiInterface " MACFMT "\n", MACARG(bssInfo->bssid));
                ifw = interfaceWifiAlloc(bssInfo->bssid, sender_device);
                ifw->role = interface_wifi_role_ap;
                radioAddInterfaceWifi(radio, ifw);
            }
            memcpy(ifw->bssInfo.bssid, bssInfo->bssid, sizeof(mac_address));
            ifw->bssInfo.ssid.length = bssInfo->ssid.length;
            memset(&ifw->bssInfo.ssid.ssid, 0, sizeof(ifw->bssInfo.ssid.ssid));
            memcpy(ifw->bssInfo.ssid.ssid, bssInfo->ssid.ssid, bssInfo->ssid.length);

            if (registrarIsLocal())
                syncRemoteBssRole(&ifw->bssInfo, &ifw->bssInfo.ssid, radio->band_supported);
        }
    }

    if ((map_config.topology_policy.APMetricsQ_uponTopoR) &&
            ( 0 == send1905ApMetricsQuery(&bssids, ifname, getNextMid(), sender_device->al_mac_addr)))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'ap metrics query' message\n");
    }

    dlist_free_items(&bssids, struct macAddressItem, l);

    return true;
}

static bool handleAssociatedClientsTLV(const char *ifname, struct alDevice *sender_device, struct tlv *associated_clients)
{
    struct _associatedClientsBssInfo *bss_info;
    struct _associatedClientInfo *client_info;
    uint32_t cur_ts = PLATFORM_GET_TIMESTAMP();

    if (!sender_device || !associated_clients) {
        return false;
    }

    dlist_for_each(bss_info, associated_clients->s.h.children[0], s.h.l)
    {
        struct interfaceWifi *ifw;

        ifw = alDevicefindWifiInterface(sender_device, bss_info->bssid);
        if (!ifw)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("cannot find WifiInterface " MACFMT " belong to sender device\n", MACARG(bss_info->bssid));
            continue;
        }

        dlist_for_each(client_info, bss_info->s.h.children[0], s.h.l)
        {
            struct staInfo *sta_info = interfaceFindOrAddStation(ifw, client_info->addr);
            uint32_t age_ms = client_info->age *1000;

            if (!sta_info)
                continue;
            if (client_info->age == ASSOCIATED_CLIENT_MAX_AGE ||
                    age_ms >= cur_ts)
                sta_info->last_assoc_ts = 0;
            else
                sta_info->last_assoc_ts = cur_ts - age_ms;

            if ((map_config.topology_policy.ClientCapaQ_uponTopoR) &&
                    ( 0 == send1905ClientCapabilityQuery(bss_info->bssid, client_info->addr, ifname, getNextMid(), sender_device->al_mac_addr)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'client capability query' message\n");
            }
            if ((map_config.topology_policy.AssocedStaLinkQ_uponTopoR) &&
                    ( 0 == send1905AssociatedStaLinkMetricQuery(ifname, getNextMid(), sender_device->al_mac_addr, client_info->addr)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'associated sta link query' message\n");
            }
        }
    }

    return true;
}

static bool handleAssocEventTLV(struct alDevice *sender_device, struct clientAssocEventTLV *assoc_event)
{
    struct interfaceWifi *ifw;

    if (!sender_device || !assoc_event) {
        return false;
    }

    ifw = alDevicefindWifiInterface(sender_device, assoc_event->bssid);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("cannot find WifiInterface " MACFMT " belong to sender device\n", MACARG(assoc_event->bssid));
        return false;
    }

    if (assoc_event->event & CLIENT_ASSOC_EVENT_JOINED)
    {
        interfaceFindOrAddStation(ifw, assoc_event->client);
        mapapi_event_client_associated(ifw->radio->uid, ifw->bssInfo.bssid, ifw->bssInfo.ssid.ssid, ifw->bssInfo.ssid.length, assoc_event->client, 0);
        #ifdef Q_STEERING_LOGIC
        if(map_steering_config.steering_actived)
            qSteeringCheckSteeringSTAEntryForNewAssociation(assoc_event->bssid, assoc_event->client);
        #endif
    }
    else
        interfaceRemoveStation(ifw, assoc_event->client);

    return true;
}

static bool checkM1BandMatchWscBssInfo(struct wscRegistrarInfo *wsc_info, const mac_address mac, uint8_t rf_band)
{
    mac_address zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (!wsc_info || !mac)
        return false;

    PLATFORM_PRINTF_DEBUG_DETAIL("check registrar wsc bss info for al " MACFMT " rf_band(0x%0x)\n",
            MAC2STR(mac), rf_band);

    if ((wsc_info->rf_bands & rf_band) != 0
            && (wsc_info->bss_info.ssid.length != 0)
            && (!memcmp(wsc_info->bss_info.bssid, zero_mac, 6)
                || !memcmp(wsc_info->bss_info.bssid, mac, 6))
            )
        return true;

    return false;
}

void _handleRadioTransmitPowerLimitTLV(struct CMDU *c)
{
    struct tlv      *p;
    int             i = 0;
    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        struct transmitPowerLimitTLV *transmitPower;
        struct radio    *r;

        if (p->type != TLV_TYPE_TRANSMIT_POWER_LIMIT)
            continue;

        transmitPower = (struct transmitPowerLimitTLV *)p;

        r = findDeviceRadio(local_device, transmitPower->radio_uid);
        if (!r)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found\n", MACARG(transmitPower->radio_uid));
            continue;
        }
        r->ctrler_maxpower = transmitPower->tx_limit;
        PLATFORM_PRINTF_DEBUG_DETAIL("The nominal transmit power limit for this radio (" MACFMT ") is %u\n",
                MACARG(transmitPower->radio_uid), transmitPower->tx_limit);
    }
}

void _handleRadioOperatingChannelReportTLV(struct CMDU *c)
{
    struct tlv      *p;
    int             i = 0;
    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        struct operatingChannelReportTLV *t;
        struct radio    *r;

        if (p->type != TLV_TYPE_OPERATING_CHANNEL_REPORT)
            continue;

        t = (struct operatingChannelReportTLV *)p;

        r = findRadio(t->radio_uid);
        if (!r)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found\n", MACARG(t->radio_uid));
            continue;
        }
        /* Note that here get first element of array current operating opclass and channel as valid one to radio*/
        if (t->operChans[0] > 0)
        {
            r->opclass = t->operChans[1];
            r->chan = t->operChans[2];
            r->txpower = t->tx_power;
            PLATFORM_PRINTF_DEBUG_DETAIL("radio (" MACFMT ") update current opclass(%u) chan(%u) txpower(%u)\n",
                    MACARG(t->radio_uid), t->operChans[1], t->operChans[2], t->tx_power);
        }
    }
}

struct radio *_handleApRadioBasicCapabilitiesTLV(struct alDevice *device, struct tlv *t)
{
    struct radio *r;
    struct _apRadioBasicCapabilitiesClass *ap_radio_basic_capas_class;
    struct apRadioBasicCapabilitiesTLV *ap_basic_caps = (struct apRadioBasicCapabilitiesTLV *)t;

    r = findOrAddDeviceRadio(device, ap_basic_caps->radio_uid);
    if (!r)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found\n", MACARG(ap_basic_caps->radio_uid));
        return NULL;
    }
    r->maxBSS = ap_basic_caps->maxbss;
    dlist_for_each(ap_radio_basic_capas_class, t->s.h.children[0], s.h.l)
    {
        struct radioOpclass *opclass;
        struct _apRadioBasicCapabilitiesChannel *ap_radio_basic_capa_channel;

        opclass = radioFindOrAddOpclass(r, ap_radio_basic_capas_class->opclass);
        if (opclass)
        {
            opclass->max_txpower = ap_radio_basic_capas_class->txpower;
            opclassInitChannelList(opclass);
            // static non-operation channel set channel disabled true
            dlist_for_each(ap_radio_basic_capa_channel, ap_radio_basic_capas_class->s.h.children[0], s.h.l)
            {
                struct radioChannel *channel;
                channel = findOpclassAndChannel(r, opclass->opclass, ap_radio_basic_capa_channel->channel);
                if (channel)
                    channel->disabled = true;
            }
        }
    }
    return r;
}

static void _handleAssociatedSTALinkMetricsTLV(struct alDevice *sender_device, struct tlv *t)
{
    struct _assocedLinkMetrics *metrics = NULL;
    struct assocedStaLinkMetricsTLV *assoced_sta = NULL;
    uint32_t cur_ts = PLATFORM_GET_TIMESTAMP();

    assoced_sta = (struct assocedStaLinkMetricsTLV *)t;

    dlist_for_each(metrics, t->s.h.children[0], s.h.l)
    {
        struct interfaceWifi *ifw = NULL;
        struct staInfo *client = NULL;

        ifw = alDevicefindWifiInterface(sender_device, metrics->bssid);
        if (!ifw)
            continue;

        client = interfaceFindStation(ifw, assoced_sta->sta);
        if (!client)
            continue;

        PLATFORM_PRINTF_DEBUG_DETAIL("update client(" MACFMT ") link metrics: age(%d)"
                "rate_dl(%d) rate_ul(%d) rcpi_ul(%d) at ts(%d)\n", MACARG(assoced_sta->sta),
                metrics->age, metrics->rate_dl, metrics->rate_ul, metrics->rcpi_ul, cur_ts);
        client->link_metrics.last_ts = (cur_ts > metrics->age)?(cur_ts - metrics->age):0;
        client->link_metrics.rate_dl = metrics->rate_dl;
        client->link_metrics.rate_ul = metrics->rate_ul;
        client->link_metrics.rcpi_ul = metrics->rcpi_ul;
        #ifdef Q_STEERING_LOGIC
        if(map_steering_config.steering_actived && !client->bSTA)
            qSteeringCheckAssocSTARCPI(sender_device, ifw, client,
                client->link_metrics.rcpi_ul, client->link_metrics.last_ts);
        #endif
    }
}

static void _handleUnassociatedSTALinkMetricsTLV(struct alDevice *sender_device, struct tlv *t)
{
    struct _unassocedMetricResp *metrics = NULL;
    struct unassocedStaLinkMetricsRespTLV *unassoced_sta_tlv = (struct unassocedStaLinkMetricsRespTLV *)t;
    uint32_t cur_ts = PLATFORM_GET_TIMESTAMP();

    dlist_for_each(metrics, t->s.h.children[0], s.h.l)
    {
        struct radioUnassocSta *unassoc_client = alDeviceFindOrAddUnassocClient(sender_device,
                unassoced_sta_tlv->opclass, metrics->channel, metrics->sta);

        if (!unassoc_client)
            continue;

        PLATFORM_PRINTF_DEBUG_DETAIL("update unassoc client(" MACFMT ") infos: age(%d)"
                "rcpi_ul(%d) channel(%d) opclass(%d) at ts(%d)\n", MACARG(metrics->sta),
                metrics->age, metrics->rcpi_ul, metrics->channel, unassoced_sta_tlv->opclass, cur_ts);
        unassoc_client->last_ts = (cur_ts > metrics->age)?(cur_ts - metrics->age):0;
        unassoc_client->rcpi = metrics->rcpi_ul;
        unassoc_client->channel = metrics->channel;
        unassoc_client->opclass = unassoced_sta_tlv->opclass;
        #ifdef Q_STEERING_LOGIC
        qSteeringUpdateUnassocSTARCPI(sender_device, metrics->sta, unassoc_client->rcpi, unassoc_client->last_ts,
            (unassoc_client->channel > 14) ? IEEE80211_FREQUENCY_BAND_5_GHZ : IEEE80211_FREQUENCY_BAND_2_4_GHZ);
        #endif
    }
}

static void _handleBeaconMetricsResponseTLV(struct alDevice *sender_device, struct tlv *t)
{
    struct _elemIE *beacon_report_ie = NULL;
    struct beaconMetricRespTLV *beacon_resp_tlv = (struct beaconMetricRespTLV *)t;
    struct interface        *intf;
    int i = 0;

    dlist_for_each(intf, sender_device->interfaces, l)
    {
        struct staInfo *client = NULL;
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;

        if (intf->type != interface_type_wifi
                || ifw->role != interface_wifi_role_ap)
            continue;

        client = interfaceFindStation(ifw, beacon_resp_tlv->sta);
        if (!client)
            continue;

        // If no any beacon_report_ies, do nothing for this client next
        if (dlist_count(&t->s.h.children[0]) == 0)
            continue;

        // Free all older beacon_report_ies first
        for (i = 0; i < client->beacon_report_ie_num; i++)
        {
            if (client->beacon_report_ie[i])
            {
                free(client->beacon_report_ie[i]);
                client->beacon_report_ie[i] = NULL;
            }
        }

        // Store all newer beacon_report_ies to datamodel
        i = 0;
        dlist_for_each(beacon_report_ie, t->s.h.children[0], s.h.l)
        {
            uint32_t ie_len = beacon_report_ie->ie[1] + 2;

            client->beacon_report_ie[i] = (uint8_t *)malloc(ie_len);
            if (!client->beacon_report_ie[i])
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Out of memory\n");
                return;
            }
            memcpy(client->beacon_report_ie[i], beacon_report_ie->ie, ie_len);
            i++;
        }
        client->beacon_report_ie_num = i;
        return;
    }
}

static void _handleAssociatedSTATrafficStatsTLV(struct alDevice *sender_device, struct tlv *t)
{
    struct assocedTrafficStatsTLV *assoced_traffic = (struct assocedTrafficStatsTLV *)t;
    struct interface        *intf;

    dlist_for_each(intf, sender_device->interfaces, l)
    {
        struct staInfo *client = NULL;
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;

        if (intf->type != interface_type_wifi
                || ifw->role != interface_wifi_role_ap)
            continue;

        client = interfaceFindStation(ifw, assoced_traffic->sta);
        if (!client)
            continue;

        PLATFORM_PRINTF_DEBUG_DETAIL("update client(" MACFMT ") traffic stats:"
                "tx_pkts(%d) rx_pkts(%d) tx_bytes(%d) rx_bytes(%d) rx_bytes(%d) "
                "tx_errs(%d) rx_err(%d) tx_retries(%d)\n",
                MACARG(assoced_traffic->sta), assoced_traffic->tx_pkts, assoced_traffic->rx_pkts,
                assoced_traffic->tx_bytes, assoced_traffic->rx_bytes, assoced_traffic->tx_errs,
                assoced_traffic->rx_errs, assoced_traffic->tx_retries);

        client->traffic_metrics.tx_packets = assoced_traffic->tx_pkts;
        client->traffic_metrics.rx_packets = assoced_traffic->rx_pkts;
        client->traffic_metrics.tx_bytes = assoced_traffic->tx_bytes;
        client->traffic_metrics.rx_bytes = assoced_traffic->rx_bytes;
        client->traffic_metrics.tx_errors = assoced_traffic->tx_errs;
        client->traffic_metrics.rx_errors = assoced_traffic->rx_errs;
        client->traffic_metrics.tx_tries = assoced_traffic->tx_retries;
        return;
    }
}

struct _notifyTimerParam
{
    uint32_t rx_intf_index;
    mac_address from_addr;
};

static void _processNotifyOperatingChannelTimer(void *ctx, void *p)
{
    uint16_t mid = getNextMid();
    struct _notifyTimerParam *param = (struct _notifyTimerParam *)(p);
    if ( 0 == send1905OperatingChannelReport(DMinterfaceIndexToInterfaceName(param->rx_intf_index), mid, param->from_addr, NULL) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'operating channel report' message\n");
    }
    free(param);
}

static void _registerNotifyOperatingChannelTimer(uint32_t receiving_interface_index, uint8_t *src_addr)
{
    struct _notifyTimerParam *param = (struct _notifyTimerParam *)malloc(sizeof(*param));
    if (!param)
        return;

    param->rx_intf_index = receiving_interface_index;
    memcpy(param->from_addr, src_addr, sizeof(mac_address));
    if (!PLATFORM_SET_TIMEOUT(10 * 1000, _processNotifyOperatingChannelTimer, NULL, param))
        free(param);
}

struct _channelMonitorTimerParam
{
    struct CMDU *c;
    uint32_t index;
    uint32_t recv_index;
    struct unassocedStaLinkMetricsQueryTLV *metric_query;
    mac_address src_addr;
};

static void _freeMonitorChannelTimerParam(struct _channelMonitorTimerParam *param)
{
    free_1905_CMDU_structure(param->c);
    free(param);
}

static void _processReportMonitorResultTimer(void *ctx, void *p)
{
    struct _channelMonitorTimerParam *param = (struct _channelMonitorTimerParam *)(p);

    if ( 0 == send1905UnassociatedSTALinkMetricsResponse(param->c,
            DMinterfaceIndexToInterfaceName(param->recv_index), getNextMid(), param->src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'unassociated STA link metrics response' message\n");
    }

    _freeMonitorChannelTimerParam(param);
}

static void _registerReportMonitorResultTimer(struct _channelMonitorTimerParam *param)
{
    if (!PLATFORM_SET_TIMEOUT(map_config.unassoc_sta_intval * 1000, _processReportMonitorResultTimer, NULL, param))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Failed to fire monitor result report timer\n");
        _freeMonitorChannelTimerParam(param);
    }
}

static uint8_t _requestLocalRadiosToMonitorOnChannel(uint8_t opclass, uint8_t channel)
{
    uint8_t monitored = 0;
    struct radio        *r;
    dlist_for_each(r, local_device->radios, l)
    {
        if (!findOpclassAndChannel(r, opclass, channel))
            continue;

        if (r->monitor_offchan
            || (r->monitor_onchan && channel == r->chan))
        {
            RADIO_MONITOR_CHANNEL(r, opclass, channel);
            monitored++;
        }
        else
            PLATFORM_PRINTF_DEBUG_DETAIL("Do not support monitor on channel(%u: %u) for radio %s\n",
                    opclass, channel, r->name);
    }
    return monitored;
}

static void _processMonitorChannelTimer(void *ctx, void *p)
{
    uint32_t i = 0;
    struct _channelMonitorTimerParam *param = (struct _channelMonitorTimerParam *)(p);
    struct unassocedStaLinkMetricsQueryTLV  *metric_query = param->metric_query;
    struct _unassocedMetricQuery            *channelItem;

    dlist_for_each(channelItem, metric_query->tlv.s.h.children[0], s.h.l)
    {
        if (i++ < param->index)
            continue;
        param->index++;

        if (_requestLocalRadiosToMonitorOnChannel(metric_query->opclass, channelItem->channel))
        {
            if (!PLATFORM_SET_TIMEOUT(map_config.monitor_dwell, _processMonitorChannelTimer, NULL, param))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Failed to fire monitor channel timer(%u)\n", param->index);
                _freeMonitorChannelTimerParam(param);
            }
            return;
        }
    }

    /* All channels are applied, fire a timer to report the monitor result asked by controller */
    if (i <= param->index)
        _registerReportMonitorResultTimer(param);
}

static void _registerMonitorChannelTimer(struct CMDU *c,
        struct unassocedStaLinkMetricsQueryTLV *tlv, uint32_t recv_index, uint8_t *src_addr)
{
    struct _channelMonitorTimerParam *param = (struct _channelMonitorTimerParam *)malloc(sizeof(*param));
    if (!param)
            return;

    param->c = c;
    param->index = 0;
    param->metric_query = tlv;
    param->recv_index = recv_index;
    memcpy(&param->src_addr, src_addr, sizeof(mac_address));

    if (!PLATFORM_SET_TIMEOUT(50, _processMonitorChannelTimer, NULL, param))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Failed to fire monitor channel timer(%u)\n", param->index);
        _freeMonitorChannelTimerParam(param);
    }
}

static void _buildAndSendBeaconRequestFrame(struct staInfo *client,
        struct interfaceWifi *assoced, uint8_t feature, struct beaconMetricQueryTLV *beaconQuery)
{
    uint8_t     *frame = NULL;
    uint8_t     mode = mapGetBeaconMeasmode(feature);
    uint32_t    frame_len = IEEE80211_MAX_MGTFRAME_LEN;

    IEEE80211_UPDATE_TOKEN(client->token);
    client->beacon_req.token = client->token;
    frame = malloc(IEEE80211_MAX_MGTFRAME_LEN);
    mapBuildBeaconRequest(assoced->bssInfo.bssid, mode, client->beacon_req.token,
            beaconQuery, frame, &frame_len);
    if (frame_len)
        IFW_SEND_FRAME(assoced, frame, frame_len);
    free(frame);
}

bool checkBtmSteeringForClient(struct staInfo *client)
{
    struct macAddressItem *item;
    if (!mapCheckBtmSupported(client->ies.extcap))
        return 0;

    dlist_for_each(item, map_policy.btm_disallowed, l)
    {
        if (!memcmp(client->mac, item->mac, sizeof(mac_address)))
            return 0;
    }

    return 1;
}

static void _steerSpecifiedClientByBtm(struct staInfo *client, struct interfaceWifi *current,
        struct _targetBss *target, struct steeringReqTLV *steeringReq)
{
    uint8_t     *frame = NULL, mode = (1 << IEEE80211_TRANSREQ_CANDIDATE_INCLUDED_SHIFT);
    uint32_t    frame_len = IEEE80211_MAX_MGTFRAME_LEN;
    uint16_t    disassoc = 100;

    if (steeringReq->mode & STEERING_REQ_MODE_DISASSOC_IMM)
        mode |= (1 << IEEE80211_TRANSREQ_BSS_DISASSOC_SHIFT);
    if (steeringReq->mode & STEERING_REQ_MODE_ABRIDGED)
        mode |= (1 << IEEE80211_TRANSREQ_ABRIDGED_SHIFT);
    if (current->bssInfo.bintval)
        disassoc = steeringReq->disassoc / current->bssInfo.bintval;

    IEEE80211_UPDATE_TOKEN(client->token);
    client->btm_req.token = client->token;
    frame = malloc(IEEE80211_MAX_MGTFRAME_LEN);
    mapBuildBtmRequest(current->bssInfo.bssid, client->mac, client->btm_req.token,
            target->target, target->opclass, target->channel,
            mode, disassoc, frame, &frame_len);
    if (frame_len)
        IFW_SEND_FRAME(current, frame, frame_len);
    free(frame);
}

static void _steerSpecifiedClientByDeauth(struct staInfo *client, struct interfaceWifi *current)
{
    IFW_DEAUTH_CLIENT(current, client->mac, 33);
}

static void _steerSpecifiedClient(struct staInfo *client, struct interfaceWifi *current,
        struct _targetBss *target, struct steeringReqTLV *steeringReq)
{
    if (checkBtmSteeringForClient(client))
        _steerSpecifiedClientByBtm(client, current, target, steeringReq);
    else
        _steerSpecifiedClientByDeauth(client, current);
}

static struct _targetBss *_getTargetInSteeringRequestByIndex(struct steeringReqTLV *steeringReq, uint8_t clientInd)
{
    struct _targetBss       *targetItem, *firstItem = NULL;
    uint8_t                 targetInd = 0;
    dlist_for_each(targetItem, steeringReq->tlv.s.h.children[1], s.h.l)
    {
        if (targetInd == clientInd)
            return targetItem;
        if (!targetInd)
            firstItem = targetItem;
        targetInd++;
    }

    /* m = 1: The same target BSSID is indicated for all specified STAs */
    if (1 == targetInd)
        return firstItem;

    return NULL;
}

static void _sendSteeringCandidatesNeededEvent(struct steeringReqTLV *steeringReq)
{
    dlist_head              clients;
    struct _macAddress      *clientItem;
    uint8_t                 clientInd = 0;
    uint8_t                 targetCounts = dlist_count(&steeringReq->tlv.s.h.children[1]);

    if (!targetCounts)
        return;

    dlist_head_init(&clients);
    dlist_for_each(clientItem, steeringReq->tlv.s.h.children[0], s.h.l)
    {
        struct staInfo          *client;
        struct interfaceWifi    *assoced;

        clientInd++;

        if (NULL != (client = findLocalWifiClient(clientItem->mac, steeringReq->bssid, &assoced)))
        {
            struct _targetBss *target = _getTargetInSteeringRequestByIndex(steeringReq, clientInd);
            if (target && !memcmp(target->target, TARGET_WILDCARD, sizeof(mac_address)))
            {
                struct macAddressItem  *item = (struct macAddressItem *)malloc(sizeof(*item));
                memcpy(item->mac, clientItem->mac, sizeof(mac_address));
                dlist_add_tail(&clients, &item->l);
            }
        }
    }

    if (!clientInd)
    {
        struct _targetBss *target = _getTargetInSteeringRequestByIndex(steeringReq, 0);

        if (target && !memcmp(target->target, TARGET_WILDCARD, sizeof(mac_address)))
        {
            struct interfaceWifi *ifw = NULL;
            ifw = findLocalWifiInterface(steeringReq->bssid, interface_wifi_role_ap);
            if (ifw)
            {
                struct staInfo *client;
                dlist_for_each(client, ifw->clients, l)
                {
                    struct macAddressItem *item = (struct macAddressItem *)malloc(sizeof(*item));
                    memcpy(item->mac, client->mac, sizeof(mac_address));
                    dlist_add_tail(&clients, &item->l);
                }
            }
        }
    }

    mapapi_event_steering_candidates_needed(steeringReq->bssid, &clients);

    dlist_free_items(&clients, struct macAddressItem, l);
}

static void _sendSteeringOpportunityEvent(struct steeringReqTLV *steeringReq)
{
    dlist_head              clients;
    struct _macAddress      *clientItem;
    uint8_t                 clientInd = 0;


    dlist_head_init(&clients);
    dlist_for_each(clientItem, steeringReq->tlv.s.h.children[0], s.h.l)
    {
        struct staInfo          *client;
        struct interfaceWifi    *assoced;

        clientInd++;

        if (NULL != (client = findLocalWifiClient(clientItem->mac, steeringReq->bssid, &assoced)))
        {
            struct macAddressItem *item = (struct macAddressItem *)malloc(sizeof(*item));
            memcpy(item->mac, clientItem->mac, sizeof(mac_address));
            dlist_add_tail(&clients, &item->l);
        }
    }

    if (!clientInd)
    {
        struct interfaceWifi *ifw = NULL;
        ifw = findLocalWifiInterface(steeringReq->bssid, interface_wifi_role_ap);
        if (ifw)
        {
            struct staInfo *client;
            dlist_for_each(client, ifw->clients, l)
            {
                struct macAddressItem *item = (struct macAddressItem *)malloc(sizeof(*item));
                memcpy(item->mac, client->mac, sizeof(mac_address));
                dlist_add_tail(&clients, &item->l);
            }
        }
    }

    mapapi_event_steering_opportunity(steeringReq->window, steeringReq->bssid, &clients);

    dlist_free_items(&clients, struct macAddressItem, l);
}

static void _processSteeringAssociatedClients(struct steeringReqTLV *steeringReq,
        uint32_t receiving_interface_index, uint8_t *src_addr)
{
    struct interface  *intf;
    struct staInfo    *client;
    struct _targetBss *target = _getTargetInSteeringRequestByIndex(steeringReq, 0);

    if (!target || !memcmp(target->target, TARGET_WILDCARD, sizeof(mac_address)))
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Not find the specified target for all associated client\n");
        return;
    }

    dlist_for_each(intf, local_device->interfaces, l)
    {
        struct interfaceWifi *wifi_intf = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi)
            continue;

        if (!memcmp(steeringReq->bssid, wifi_intf->bssInfo.bssid, sizeof(mac_address)))
        {
            dlist_for_each(client, wifi_intf->clients, l)
            {
                client->btm_req.intf_index = receiving_interface_index;
                memcpy(client->btm_req.source, src_addr, sizeof(mac_address));
                _steerSpecifiedClient(client, wifi_intf, target, steeringReq);
            }
            return;
        }
    }
}

static uint8_t _processClientMandateSteeringRequest(struct steeringReqTLV *steeringReq, uint16_t mid,
        uint32_t receiving_interface_index, uint8_t *src_addr)
{
    dlist_head              error_clients;
    struct _macAddress      *clientItem;
    uint8_t                 clientInd = 0;
    uint8_t                 targetCounts = dlist_count(&steeringReq->tlv.s.h.children[1]);

    if (!targetCounts)
        return PROCESS_CMDU_KO;

    dlist_head_init(&error_clients);
    dlist_for_each(clientItem, steeringReq->tlv.s.h.children[0], s.h.l)
    {
        struct macAddressItem   *item;
        struct staInfo          *client;
        struct interfaceWifi    *assoced;

        clientInd++;

        if (NULL == (client = findLocalWifiClient(clientItem->mac, steeringReq->bssid, &assoced)))
        {
            item = (struct macAddressItem *)malloc(sizeof(*item));
            memcpy(item->mac, clientItem->mac, sizeof(mac_address));
            dlist_add_tail(&error_clients, &item->l);
        }
        else
        {
            struct _targetBss *target = _getTargetInSteeringRequestByIndex(steeringReq, clientInd);
            if (!target || !memcmp(target->target, TARGET_WILDCARD, sizeof(mac_address)))
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Not find the specified target for %u client\n", clientInd);
                break;
            }

            client->btm_req.intf_index = receiving_interface_index;
            memcpy(client->btm_req.source, src_addr, sizeof(mac_address));
            _steerSpecifiedClient(client, assoced, target, steeringReq);
        }
    }

    /* k = 0: Steering request applies to all associated STAs in the BSS per policy setting. */
    if (!clientInd)
        _processSteeringAssociatedClients(steeringReq, receiving_interface_index, src_addr);

    if ( 0 == send1905Ack(&error_clients, 0x02,
                DMinterfaceIndexToInterfaceName(receiving_interface_index), mid, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        dlist_free_items(&error_clients, struct macAddressItem, l);
        return PROCESS_CMDU_KO;
    }

    dlist_free_items(&error_clients, struct macAddressItem, l);

    return PROCESS_CMDU_OK;
}

static uint8_t _processClientOpportunitySteeringRequest(struct steeringReqTLV *steeringReq,
        uint16_t mid, uint32_t receiving_interface_index, uint8_t *src_addr)
{
	if ( 0 == send1905Ack(NULL, 0,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), mid, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
	}

    /* No any logic supported now for Agent to choose the Target BSS for Clients,
     * Just send the Steering Completed message */
	if ( 0 == send190SteeringCompleted(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'steering completed' message\n");
        return PROCESS_CMDU_KO;
	}

    return PROCESS_CMDU_OK;
}

static void _processBackhaulSteeringTimer(void *ctx, void *p)
{
    struct interfaceWifi    *ifw = (struct interfaceWifi *)p;

    PLATFORM_PRINTF_DEBUG_INFO("Fail to roaming backhaul to " MACFMT "\n", MACARG(ifw->last_steering_target));

    ifw->steering_timer = NULL;

    if (!registrar.d)
        return;

    send1905BackhaulSteeringResponse(ifw, 0x01, 0x05, DMinterfaceIndexToInterfaceName(registrar.d->receiving_interface_index), getNextMid(), registrar.d->al_mac_addr);
}

static void _roamBackhaulStaToTarget(struct interfaceWifi *ifw, uint8_t opclass, uint8_t channel)
{
    IFW_ROAM_STA(ifw, ifw->last_steering_target, opclass, channel);
    ifw->steering_timer = PLATFORM_SET_TIMEOUT(map_config.wait_roaming * 1000, _processBackhaulSteeringTimer, NULL, ifw);
}

static void _processUnblockClientTimer(void *ctx, void *p)
{
    struct blockedClient *blockedClient = (struct blockedClient *)(p);
    struct interfaceWifi *ifw = findLocalWifiInterface(blockedClient->bssid, interface_wifi_role_other);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_INFO("Fail find interface for " MACFMT "\n", MACARG(blockedClient->bssid));
        return;
    }

    dlist_remove(&blockedClient->l);
    IFW_UNBLOCK_CLIENT(ifw, blockedClient->mac);
    free(blockedClient);
}

static void _updateApMetricsUpdatePeriod(uint32_t period)
{
    struct interface        *intf;
    if (!period)
        period = map_config.ap_metrics_intval;

    dlist_for_each(intf, local_device->interfaces, l)
    {
        if (intf->type != interface_type_wifi)
            continue;

        IFW_SET_REPORT_PERIOD((struct interfaceWifi *)intf, period, INVALID_REPORT_PERIOD, INVALID_REPORT_PERIOD);
    }
}

static void _processClientAssocationControl(struct clientAssocCtrlReqTLV *req, mac_address mac)
{
    struct blockedClient *blockedClient = findLocalWifiBlockedClient(mac, req->bssid);
    struct interfaceWifi *ifw = findLocalWifiInterface(req->bssid, interface_wifi_role_other);
    uint32_t cur_ts = PLATFORM_GET_TIMESTAMP();
    uint32_t req_period_ms = req->period * 1000;

    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_INFO("Fail find interface for " MACFMT "\n", MACARG(req->bssid));
        return;
    }

    switch (req->ctrl)
    {
        case ASSOC_CTRL_BLOCK:
            if (blockedClient)
            {
                if (blockedClient->unblock_timer)
                    PLATFORM_CANCEL_TIMEOUT(blockedClient->unblock_timer);
            }
            else
            {
                blockedClient = malloc(sizeof(*blockedClient ));
                if (!blockedClient)
                    return;
                memcpy(blockedClient->bssid, req->bssid, sizeof(mac_address));
                memcpy(blockedClient->mac, mac, sizeof(mac_address));
                blockedClient->expiration = cur_ts + req_period_ms;
                dlist_add_tail(&map_policy.blocked_clients, &blockedClient->l);
            }
            blockedClient->unblock_timer = PLATFORM_SET_TIMEOUT(req_period_ms,
                    _processUnblockClientTimer, NULL, blockedClient);
            if (blockedClient->unblock_timer)
                IFW_BLOCK_CLIENT(ifw, mac);
            break;

        case ASSOC_CTRL_UNBLOCK:
            if (blockedClient)
            {
                if (blockedClient->unblock_timer)
                    PLATFORM_CANCEL_TIMEOUT(blockedClient->unblock_timer);
                dlist_remove(&blockedClient->l);
                free(blockedClient);
            }
            IFW_UNBLOCK_CLIENT(ifw, mac);
            break;

        default:
            PLATFORM_PRINTF_DEBUG_WARNING("Unknow control %u\n", req->ctrl);
            break;
    }
}

static void _resetMetricsReportDirection(struct radio *r)
{
    int i;

    r->dir = 0;
    for (i = 0; i < r->configured_bsses.length; i++)
    {
        struct staInfo  *client = NULL;
        struct interfaceWifi *ifw = (struct interfaceWifi *)r->configured_bsses.data[i];

        dlist_for_each(client, ifw->clients, l)
            client->dir = 0;
    }
}

// When a "ap capability query" is received we must obtain a series of
// information from the platform and then package and send it back
// in a "ap capability report" message.
static uint8_t processApCapabilityQuery(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    if ( 0 == send1905ApCapabilityReport(DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'ap capability report' message\n");
        return PROCESS_CMDU_KO;
    }
    return PROCESS_CMDU_OK;
}

// Note that no need to reply ACK when received "ap capability report"
static uint8_t processApCapabilityReport(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct alDevice *sender_device = alDeviceFindFromAnyAddress(src_addr);
    struct apCapabilityTLV *ap_cap;
    struct apHTCapabilitiesTLV *ap_ht_caps;
    struct apVHTCapabilitiesTLV *ap_vht_caps;
    struct apHECapabilitiesTLV *ap_he_caps;
    struct radio *r;
    struct tlv   *p;
    int i = 0;

    if (sender_device == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Received AP capability Report from undiscovered addr " MACSTR "\n",
            MAC2STR(src_addr));
        return PROCESS_CMDU_KO;
    }

    ap_cap = (struct apCapabilityTLV *)
            get_CMDU_tlv(c, TLV_TYPE_AP_CAPABILITY);

    if (!ap_cap)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop ap capa report: "
                "required at least one TLV ap_cap(%p)\n",
                ap_cap);
        return PROCESS_CMDU_KO;
    }

    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        switch (p->type)
        {
            case TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES:
            {
                r = _handleApRadioBasicCapabilitiesTLV(sender_device, p);
                if (!r)
                    continue;
                r->self_steering = !!(ap_cap->capa & AP_CAPABILITY_AGENT_RCPI_STEERING);
                r->monitor_onchan = !!(ap_cap->capa & AP_CAPABILITY_UNASSOCED_LINK_METRICS_ONCHAN);
                r->monitor_offchan = !!(ap_cap->capa & AP_CAPABILITY_UNASSOCED_LINK_METRICS_OFFCHAN);
                r->ht_capa.valid = false;
                r->vht_capa.valid = false;
                r->he_capa.valid = false;
                break;
            }
        }
    }

    i = 0;
    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        switch (p->type)
        {
            case TLV_TYPE_AP_HT_CAPABILITIES:
            {
                ap_ht_caps = (struct apHTCapabilitiesTLV *)p;
                r = findRadio(ap_ht_caps->radio_uid);
                if (!r)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found\n", MACARG(ap_ht_caps->radio_uid));
                    continue;
                }
                r->ht_capa.capabilities = ap_ht_caps->capabilities;
                r->ht_capa.valid = true;
                break;
            }
            case TLV_TYPE_AP_VHT_CAPABILITIES:
            {
                ap_vht_caps = (struct apVHTCapabilitiesTLV *)p;
                r = findRadio(ap_vht_caps->radio_uid);
                if (!r)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found\n", MACARG(ap_vht_caps->radio_uid));
                    continue;
                }
                r->vht_capa.tx_mcs = ap_vht_caps->tx_mcs;
                r->vht_capa.rx_mcs = ap_vht_caps->rx_mcs;
                r->vht_capa.capabilities1 = ap_vht_caps->capabilities1;
                r->vht_capa.capabilities2 = ap_vht_caps->capabilities2;
                r->vht_capa.valid = true;
                break;
            }
            case TLV_TYPE_AP_HE_CAPABILITIES:
            {
                ap_he_caps = (struct apHECapabilitiesTLV *)p;
                r = findRadio(ap_he_caps->radio_uid);
                if (!r)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found\n", MACARG(ap_he_caps->radio_uid));
                    continue;
                }
                memcpy(r->he_capa.mcs, ap_he_caps->mcs, 13);
                r->he_capa.capabilities1 = ap_he_caps->capabilities1;
                r->he_capa.capabilities2 = ap_he_caps->capabilities2;
                r->he_capa.valid = true;
                break;
            }
        }
    }

    return PROCESS_CMDU_OK;
}

// When a "Multi-AP policy config request" is received we must config
// and save a series of policy and then it shall respone a 1905 "ack" message.
static uint8_t processMapPolicyConfigRequest(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    uint8_t i = 0;
    struct  tlv *p;
    struct  radio *r;

    if (NULL == c->list_of_TLVs)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
        return PROCESS_CMDU_KO;
    }
    while (NULL != (p = c->list_of_TLVs[i]))
    {
        switch (p->type)
        {
            case TLV_TYPE_STEERING_POLICY:
            {
                struct _macAddress *localSteeringDisallowedSta;
                struct _macAddress *btmSteeringDisallowedSta;
                struct _steeringPolicy *steeringPolicy;
                struct macAddressItem *disallowedSta;

                // clear previous steering policy and BTM disallowed STA list
                dlist_free_items(&map_policy.local_disallowed, struct macAddressItem, l);
                dlist_free_items(&map_policy.btm_disallowed, struct macAddressItem, l);

                dlist_for_each(localSteeringDisallowedSta, p->s.h.children[0], s.h.l)
                {
                    disallowedSta = (struct macAddressItem *)malloc(sizeof(*disallowedSta));
                    if (disallowedSta)
                    {
                        memcpy(disallowedSta->mac, localSteeringDisallowedSta->mac, 6);
                        dlist_add_tail(&map_policy.local_disallowed, &disallowedSta->l);
                    }
                }
                dlist_for_each(btmSteeringDisallowedSta, p->s.h.children[1], s.h.l)
                {
                    disallowedSta = (struct macAddressItem *)malloc(sizeof(*disallowedSta));
                    if (disallowedSta)
                    {
                        memcpy(disallowedSta->mac, btmSteeringDisallowedSta->mac, 6);
                        dlist_add_tail(&map_policy.btm_disallowed, &disallowedSta->l);
                    }
                }
                dlist_for_each(steeringPolicy, p->s.h.children[2], s.h.l)
                {
                    r = findDeviceRadio(local_device, steeringPolicy->uid);
                    if (!r)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACSTR ") is not found\n", MAC2STR(steeringPolicy->uid));
                        continue;
                    }
                    r->steering_policy.policy = steeringPolicy->policy;
                    r->steering_policy.ch_util_threshold = steeringPolicy->ch_util;
                    r->steering_policy.rcpi_threshold = steeringPolicy->rcpi_threshold;
                }
                break;
            }
            case TLV_TYPE_METRIC_REPORTING_POLICY:
            {
                struct metricReportingPolicyTLV *metric_reporting_policy;
                struct _metricReportingPolicy *metricReportingPolicy;

                metric_reporting_policy = (struct metricReportingPolicyTLV *)p;
                map_policy.metric_intval = metric_reporting_policy->interval;
                _updateApMetricsUpdatePeriod(map_policy.metric_intval);
                dlist_for_each(metricReportingPolicy, p->s.h.children[0], s.h.l)
                {
                    r = findDeviceRadio(local_device, metricReportingPolicy->uid);
                    if (!r)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACSTR ") is not found\n", MAC2STR(metricReportingPolicy->uid));
                        continue;
                    }
                    r->metric_policy.configed = true;
                    r->metric_policy.rcpi_threshold = metricReportingPolicy->rcpi_threshold;
                    r->metric_policy.rcpi_margin = metricReportingPolicy->rcpi_margin;
                    r->metric_policy.ch_util_threshold = metricReportingPolicy->ch_util_threshold;
                    r->metric_policy.policy = metricReportingPolicy->policy &
                            (METRIC_REPORTING_POLICY_INCLUDE_ASSOCED_TRAFFIC_STATS|METRIC_REPORTING_POLICY_INCLUDE_ASSOCED_LINK_METRICS);

                    /* Make sure the first metrics will be reported when receiving the policy
                     * For the test case: 4.7.6 MAUT §10.2 Per-AP Metrics Response Controlled by AP Metrics Channel Utilization Reporting Threshold test */
                    _resetMetricsReportDirection(r);
                }
                break;
            }
            default:
            {
                break;
            }
        }
        i++;
    }
    if (0 == send1905Ack(NULL, 0, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
    }
    return PROCESS_CMDU_OK;
}

// When a "channel preference query" is received we must obtain a series of
// information from the platform and then package and send it back
// in a "channel preference report" message.
static uint8_t processChannelPreferenceQuery(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    if ( 0 == send1905ChannelPreferenceReport(NULL, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'ap channel preference' message\n");
        return PROCESS_CMDU_KO;
    }
    return PROCESS_CMDU_OK;
}

// When a "channel preference report" is received we shall delete all previously
// stored channel prefence information from the Multi-AP Agent pertaining to all radios
// of that Multi-AP Agent and replace it with the information contained within the
// Channel Preference Report message.
static uint8_t processChannelPreferenceReport(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    uint8_t i = 0;
    struct tlv  *p;
    struct alDevice *sender_device = alDeviceFindFromAnyAddress(src_addr);
    struct radio        *r;

    if (NULL == c->list_of_TLVs)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
        return PROCESS_CMDU_KO;
    }

    if (sender_device == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Received Channel Preference Report from undiscovered address " MACSTR "\n",
                MAC2STR(src_addr));
        return PROCESS_CMDU_KO;
    }

    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        switch (p->type)
        {
            case TLV_TYPE_CHANNEL_PREFERENCE:
            {
                struct channelPreferenceTLV *channelPref;
                struct _operatingClass *opclass;
                int malformed = 0;

                channelPref = (struct channelPreferenceTLV *)p;
                r = findDeviceRadio(sender_device, channelPref->radio_uid);
                if (!r)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found from Channel Perference TLV\n",
                            MACARG(channelPref->radio_uid));
                    continue;
                }

                dlist_for_each(opclass, p->s.h.children[0], s.h.l)
                {
                    struct radioOpclass *radioOpclass;
                    struct radioChannel *radioChannel;
                    uint8_t ch_num;

                    radioOpclass = radioFindOrAddOpclass(r, opclass->opclass);
                    if (!radioOpclass)
                        break;

                    for (ch_num = 0; ch_num < opclass->channels[0]; ch_num++)
                    {
                        radioChannel = opclassFindOrAddChannel(radioOpclass, opclass->channels[ch_num + 1]);
                        if (!radioChannel)
                            break;
                    }

                    malformed = updateChannelPreference(r, opclass->opclass, opclass->channels[0],
                            &opclass->channels[1], opclass->value);
                    if (malformed)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Channel Preference TLV  for %u is malformed\n", opclass->opclass);
                        break;
                    }
                }
                break;
            }
            case TLV_TYPE_RADIO_OPERATION_RESTRICTION:
            {
                struct radioOperRestrictionTLV *radioOperRest = NULL;
                struct _operRestOpclass *restOpclass;
                struct _operRestChan *restChan;
                int malformed = 0;

                radioOperRest = (struct radioOperRestrictionTLV *)p;
                r = findDeviceRadio(sender_device, radioOperRest->radio_uid);
                if (!r)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("The radio (" MACFMT ") is not found from radio operate restriction TLV\n",
                            MACARG(radioOperRest->radio_uid));
                    continue;
                }

                dlist_for_each(restOpclass, p->s.h.children[0], s.h.l)
                {
                    dlist_for_each(restChan, p->s.h.children[1], s.h.l)
                    {
                        malformed = updateRadioOperationRestriction(r, restOpclass->opclass,
                                restChan->channel, restChan->freq_sep);
                        if (malformed)
                        {
                            PLATFORM_PRINTF_DEBUG_WARNING("radio operation restriction TLV  for %u is malformed\n",
                                    restOpclass->opclass);
                            break;
                        }
                    }
                }
                break;
            }
            default:
            {
                    PLATFORM_PRINTF_DEBUG_WARNING("Channel perference report contains unexpected TLV type(%d)\n", p->type);
                    break;
            }
        }
    }

    if (0 == send1905Ack(NULL, 0, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
    }

    return PROCESS_CMDU_OK;
}

// When a "channel selection request" is received we will do things defined in 8.2 Channel Selection Request and Report
static uint8_t processChannelSelecetionRequest(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    _handleRadioTransmitPowerLimitTLV(c);

    if ( 0 == send1905ChannelSelectionResponse(c,
                DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'ap channel selection response' message\n");
        return PROCESS_CMDU_KO;
    }

    /* irrespective of whether any adjustments have been made, send an Operating Channel Report message
     * per section 17.1.13 containing information regarding the current operating parameters for each of the Multi-AP Agent's radios. */
    _registerNotifyOperatingChannelTimer(receiving_interface_index, src_addr);

    return PROCESS_CMDU_OK;
}

// When a "channel selection response" is received we must reply a Ack.
static uint8_t processChannelSelecetionResponse(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    if (0 == send1905Ack(NULL, 0,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
	}

    return PROCESS_CMDU_OK;
}

// When a "Operating Channel Report" is received we must reply a Ack.
static uint8_t processOperatingChannelReport(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    _handleRadioOperatingChannelReportTLV(c);

    if (0 == send1905Ack(NULL, 0,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
    }

    return PROCESS_CMDU_OK;
}

// When a "cleint capability query" is received we must obtain a series of
// information from the platform and then package and send it back
// in a "client capability report" message.
static uint8_t processClientCapabilityQuery(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    if ( 0 == send1905ClientCapabilityReport(c,
                DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'client capability report' message\n");
        return PROCESS_CMDU_KO;
    }
    return PROCESS_CMDU_OK;
}

// Note that no need to reply ACK when received "client capability report"
static uint8_t processClientCapabilityReport(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct clientInfoTLV * client_info;
    struct clientCapaReportTLV *client_capa_report;
    struct errorCodeTLV *error_code;
    struct staInfo *client;

    client_info = (struct clientInfoTLV *)
            get_CMDU_tlv(c, TLV_TYPE_CLIENT_INFO);

    client_capa_report = (struct clientCapaReportTLV *)
            get_CMDU_tlv(c, TLV_TYPE_CLIENT_CAPABILITY_REPORT);

    if (!client_info || !client_capa_report)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop client capa report: "
                "required TLV client_info(%p) and client_capa_report(%p)\n",
                client_info, client_capa_report);
        return PROCESS_CMDU_KO;
    }

    if (NULL == (client = findOrAddWifiClient(client_info->client, client_info->bssid, NULL)))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("The client (" MACFMT ") is not found\n", MACARG(client_info->client));
        return PROCESS_CMDU_KO;
    }

    client->last_result_code = client_capa_report->code;

    if (client_capa_report->code > CLIENT_CAPA_REPORT_CODE_SUCCESS)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Client capability report failed, get report code(%d)\n", client_capa_report->code);
        error_code = (struct errorCodeTLV *)get_CMDU_tlv(c, TLV_TYPE_ERROR_CODE);
        if (error_code)
            PLATFORM_PRINTF_DEBUG_WARNING("The error reason code is %d\n", error_code->code);
        return PROCESS_CMDU_OK;
    }

    if (client_capa_report->frame && client_capa_report->frame_len)
    {
        if (client->last_assoc)
            free(client->last_assoc);
        client->last_assoc = (uint8_t *)malloc(client_capa_report->frame_len);
        if (!client->last_assoc)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("Out of memory\n");
            return PROCESS_CMDU_KO;
        }
        memcpy(client->last_assoc, client_capa_report->frame, client_capa_report->frame_len);
        client->last_assoc_len = client_capa_report->frame_len;
        #ifdef Q_STEERING_LOGIC
        mapParseAssocFrame(client, client->last_assoc, client->last_assoc_len);
        qSteeringUpdateBTMAllowed(client->mac, checkBtmSteeringForClient(client));
        #endif
    }

    return PROCESS_CMDU_OK;
}

// When a "ap metrics query" is received we must obtain a series of
// information from the platform and then package and send it back
// in a "ap metrics response" message.
static uint8_t processApMetricsQuery(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct apMetricQueryTLV     *metricQuery = NULL;
    dlist_head                  bssids;
    struct _macAddress          *bssidItem;
    struct macAddressItem       *item;

    metricQuery = (struct apMetricQueryTLV *)
            get_CMDU_tlv(c, TLV_TYPE_AP_METRIC_QUERY);
    if (!metricQuery)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop ap metrics query: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

    dlist_head_init(&bssids);
    dlist_for_each(bssidItem, metricQuery->tlv.s.h.children[0], s.h.l)
    {
        item = (struct macAddressItem *)malloc(sizeof(*item));
        memcpy(item->mac, bssidItem->mac, sizeof(mac_address));
        dlist_add_tail(&bssids, &item->l);
    }

    if (0 == send1905ApMetricsResponse(&bssids, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'ap metrics response' message\n");
        dlist_free_items(&bssids, struct macAddressItem, l);
        return PROCESS_CMDU_KO;
    }

    dlist_free_items(&bssids, struct macAddressItem, l);
    return PROCESS_CMDU_OK;
}

// When a "ap metrics response" is received we must update a series of
// information for this device.
static uint8_t processApMetricsResponse(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    uint8_t i = 0;
    struct tlv  *p;
    struct alDevice *sender_device = alDeviceFindFromAnyAddress(src_addr);

    if (NULL == c->list_of_TLVs)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
        return PROCESS_CMDU_KO;
    }

    if (sender_device == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Received Ap metrics response from undiscovered address " MACSTR "\n",
                MAC2STR(src_addr));
        return PROCESS_CMDU_KO;
    }

    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        switch (p->type)
        {
            case TLV_TYPE_AP_METRICS:
            {
                struct interfaceWifi *ifw = NULL;
                struct apMetricsTLV *metric;

                metric = (struct apMetricsTLV *)p;
                ifw = alDevicefindWifiInterface(sender_device, metric->bssid);
                if (!ifw)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("cannot find ifw by bssid " MACFMT " from the sender device\n",
                            MAC2STR(metric->bssid));
                    break;
                }
                ifw->bssInfo.metrics.ch_util = metric->ch_util;

#define UPDATE_ESPI_FEILDES(espi, value) do {   \
        espi.valid = 1; \
        espi.format = (value[2] & ESPI_DATA_FORMAT_MASK) >> ESPI_DATA_FORMAT_SHIFT; \
        espi.window = (value[2] & ESPI_BA_WINDOW_MASK) >> ESPI_BA_WINDOW_SHIFT; \
        espi.est_airtime = value[1]; \
        espi.duration  = value[0]; \
    } while(0)
                if (metric->includes & ESPI_BE_INCLUDED)
                    UPDATE_ESPI_FEILDES(ifw->bssInfo.metrics.espis[0], metric->espi_be);
                if (metric->includes & ESPI_BK_INCLUDED)
                    UPDATE_ESPI_FEILDES(ifw->bssInfo.metrics.espis[1], metric->espi_bk);
                if (metric->includes & ESPI_VO_INCLUDED)
                    UPDATE_ESPI_FEILDES(ifw->bssInfo.metrics.espis[2], metric->espi_vo);
                if (metric->includes & ESPI_VI_INCLUDED)
                    UPDATE_ESPI_FEILDES(ifw->bssInfo.metrics.espis[3], metric->espi_vi);

                break;
            }
            case TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS:
            {
                _handleAssociatedSTATrafficStatsTLV(sender_device, p);
                break;
            }
            case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
            {
                _handleAssociatedSTALinkMetricsTLV(sender_device, p);
                break;
            }
            default:
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Ap metrics response contains unexpected TLV type(%d)\n", p->type);
                break;
            }
        }
    }

    return PROCESS_CMDU_OK;
}

// When a "associated STA link metrics query" is received we must obtain a series of
// information from the platform and then package and send it back
// in a "associated STA link metrics response" message.
static uint8_t processAssociatedStaLinkMetricQuery(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct staMacAddressTLV *staMac = NULL;

    staMac = (struct staMacAddressTLV *)get_CMDU_tlv(c, TLV_TYPE_STA_MAC_ADDRESS);
    if (!staMac)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop associated Sta link metric query: no client mac TLV included\n");
        return PROCESS_CMDU_KO;
    }

    if ( 0 == send1905AssociatedStaLinkMetricResponse(staMac->sta, NULL, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'associated STA link metrics response' message\n");
        return PROCESS_CMDU_KO;
    }
    return PROCESS_CMDU_OK;
}

static uint8_t processAssociatedStaLinkMetricResponse(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    uint8_t i = 0;
    struct tlv  *p;
    struct errorCodeTLV *error_code = NULL;
    struct alDevice *sender_device = alDeviceFindFromAnyAddress(src_addr);

    if (sender_device == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Received AssociatedStaLinkMetricResponse from undiscovered address("
                MACFMT ")\n", MACARG(src_addr));
        return PROCESS_CMDU_KO;
    }

    error_code = (struct errorCodeTLV *)get_CMDU_tlv(c, TLV_TYPE_ERROR_CODE);
    if (error_code)
    {
        PLATFORM_PRINTF_DEBUG_INFO("The error reason code of Received AssociatedStaLinkMetricResponse is %d\n", error_code->code);
        if (error_code->code == 2)
        {
            // error_code 2 means that specified STA is not associated with any BSSes of this agent
            // remove specified STA from datamodel
            //
            struct interface *intf;
            dlist_for_each(intf, sender_device->interfaces, l)
            {
                struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
                if (intf->type != interface_type_wifi ||
                        ifw->role != interface_wifi_role_ap)
                    continue;
                interfaceRemoveStation(ifw, error_code->sta);
            }
        }
        // when get errorCodeTLV, we don't believe the informations in assocedStaLinkMetricsTLV
        return PROCESS_CMDU_OK;
    }

    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        switch (p->type)
        {
            case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
            {
                _handleAssociatedSTALinkMetricsTLV(sender_device, p);
                break;
            }
        }
    }

    return PROCESS_CMDU_OK;
}

// When a "unassociated sta link metrics query" is received we must send back the "ack" message
// then obtain a series of information from the platform and then package and send it back
// in a "unassociated sta link metrics report" message.
static uint8_t processUnassociatedStaLinkMetricsQuery(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    dlist_head          error_clients;
    struct unassocedStaLinkMetricsQueryTLV  *metricQuery = NULL;
    struct _unassocedMetricQuery            *channelItem;

    metricQuery  = (struct unassocedStaLinkMetricsQueryTLV *)
            get_CMDU_tlv(c, TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY);
    if (!metricQuery )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop unassociated sta link metrics query: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

    dlist_head_init(&error_clients);

    dlist_for_each(channelItem, metricQuery->tlv.s.h.children[0], s.h.l)
    {
        struct _macAddress *staItem;
        dlist_for_each(staItem, channelItem->s.h.children[0], s.h.l)
        {
            struct macAddressItem *item;
            if (findLocalWifiClient(staItem->mac, NULL, NULL))
            {
                item = (struct macAddressItem *)malloc(sizeof(*item));
                memcpy(item->mac, staItem->mac, sizeof(mac_address));
                dlist_add_tail(&error_clients, &item->l);
            }
        }
    }

	if ( 0 == send1905Ack(&error_clients, 0x01,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
	   PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
       dlist_free_items(&error_clients, struct macAddressItem, l);
	   return PROCESS_CMDU_KO;
	}

    dlist_free_items(&error_clients, struct macAddressItem, l);

    _registerMonitorChannelTimer(c, metricQuery, receiving_interface_index, src_addr);

    /* CMDU will be freed in channel monitor timer process */
    return PROCESS_CMDU_OK | PROCESS_CMDU_CONSUMED;
}

static uint8_t processUnssociatedStaLinkMetricResponse(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct tlv  *p;
    struct alDevice *sender_device = alDeviceFindFromAnyAddress(src_addr);

    if (sender_device == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Received UnssociatedStaLinkMetricResponse from undiscovered address("
                 MACFMT ")\n", MACARG(src_addr));
        return PROCESS_CMDU_KO;
    }

    p = get_CMDU_tlv(c, TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE);
    if (!p)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop UnssociatedStaLinkMetricResponse: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

    _handleUnassociatedSTALinkMetricsTLV(sender_device, p);

    return PROCESS_CMDU_OK;
}

// When a "beacon metrics query" is received we must send back the "ack" message
// then wait the beacon response then package and send it back
// in a "beacon metrics response" message.
static uint8_t processBeaconMetricsQuery(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    dlist_head              error_clients;
    struct macAddressItem   item;
    struct staInfo          *client;
    struct interfaceWifi    *assoced_intf;
    struct beaconMetricQueryTLV *beaconQuery = NULL;
    uint8_t mode_supported;

    beaconQuery = (struct beaconMetricQueryTLV *)
            get_CMDU_tlv(c, TLV_TYPE_BEACON_METRICS_QUERY);
    if (!beaconQuery)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop beacon metrics query: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

    dlist_head_init(&error_clients);
    if (NULL == (client = findLocalWifiClient(beaconQuery->sta, NULL, &assoced_intf)))
    {
        memcpy(item.mac, beaconQuery->sta, sizeof(mac_address));
        dlist_add_tail(&error_clients, &item.l);
    }

	if ( 0 == send1905Ack(&error_clients, 0x02,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
	   PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
	   return PROCESS_CMDU_KO;
	}

    if (!client || !client->last_assoc
            || (0 == (mode_supported = mapCheckBeaconReportSupported(client->ies.rm_enabled))))
    {
	   PLATFORM_PRINTF_DEBUG_DETAIL("Client(" MACFMT ") do not support Beacon Report\n", MACARG(beaconQuery->sta));
	   return PROCESS_CMDU_OK;
    }

    client->beacon_req.intf_index = receiving_interface_index;
    memcpy(client->beacon_req.source, src_addr, sizeof(mac_address));

    _buildAndSendBeaconRequestFrame(client, assoced_intf, mode_supported, beaconQuery);

   return PROCESS_CMDU_OK;
}

static uint8_t processBeaconMetricsResponse(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct tlv  *p;
    struct alDevice *sender_device = alDeviceFindFromAnyAddress(src_addr);

    if (sender_device == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Received BeaconMetricsResponse from undiscovered address("
                 MACFMT ")\n", MACARG(src_addr));
        return PROCESS_CMDU_KO;
    }

    p = get_CMDU_tlv(c, TLV_TYPE_BEACON_METRICS_RESPONSE);
    if (!p)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop BeaconMetricsResponse: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

    _handleBeaconMetricsResponseTLV(sender_device, p);

    return PROCESS_CMDU_OK;
}

// When a "combined infrastructure metrics" is received we must send back the "ack" message.
static uint8_t processCombinedInfrastructureMetrics(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{

    if (0 == send1905Ack(NULL, 0, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
    }

    return PROCESS_CMDU_OK;
}

static uint8_t processClientSteeringRequest(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    uint8_t                 ret;
    struct steeringReqTLV   *steeringReq = NULL;

    steeringReq = (struct steeringReqTLV *)
            get_CMDU_tlv(c, TLV_TYPE_STEERING_REQUEST);
    if (!steeringReq)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop client steering reuqest: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

    if (steeringReq->mode & STEERING_REQ_MODE_MANDATE)
    {
        ret = _processClientMandateSteeringRequest(steeringReq, c->message_id, receiving_interface_index, src_addr);
        // when Controller sends a Steering Mandate with a wildcard Target BSS
        _sendSteeringCandidatesNeededEvent(steeringReq);
    }
    else
    {
        ret = _processClientOpportunitySteeringRequest(steeringReq, c->message_id, receiving_interface_index, src_addr);
        _sendSteeringOpportunityEvent(steeringReq);
    }

    return ret;
}

// fix me: to deal with steeringBtmReportTLV when steering logic in controller is ready
// When a "client steering BTM report" is received we must send back the "ack" message
static uint8_t processClientSteeringBTMReport(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    if (0 == send1905Ack(NULL, 0, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
    }

    return PROCESS_CMDU_OK;
}

// When a "steering completed" is received we must send back the "ack" message
static uint8_t processSteeringCompleted(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    if (0 == send1905Ack(NULL, 0, DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
    }

    return PROCESS_CMDU_OK;
}

// When a "backhaul steering request" is received we must send back the "ack" message
// then roam and wait the roam result and send back the "backhaul steering response" message.
static uint8_t processBackhaulSteeringRequest(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct interfaceWifi            *ifw = NULL;
    struct backhaulSteeringReqTLV   *steeringReq = NULL;

    steeringReq = (struct backhaulSteeringReqTLV *)
            get_CMDU_tlv(c, TLV_TYPE_BACKHAUL_STEERING_REQUEST);
    if (!steeringReq)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop backhaul steering reuqest: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

	if ( 0 == send1905Ack(NULL, 0,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
	}

    ifw = findLocalWifiInterface(steeringReq->sta, interface_wifi_role_sta);
    if (!ifw)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not find backhaul sta interface for " MACFMT "\n", MACARG(steeringReq->sta));
        return PROCESS_CMDU_KO;
    }

    if (ifw->steering_timer)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Last backhaul steering has not been finished yet\n");
        return PROCESS_CMDU_KO;
    }

    memcpy(&ifw->last_steering_target, steeringReq->target, sizeof(mac_address));

    if (ifw->radio)
    {
        struct radioChannel *channel =
            findOpclassAndChannel(ifw->radio, steeringReq->opclass, steeringReq->channel);
        if (!channel)
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("Channel (%u:%u) not supported for interface " MACFMT "\n",
                    steeringReq->opclass, steeringReq->channel, MACARG(steeringReq->sta));
            send1905BackhaulSteeringResponse(ifw, 0x01, 0x04, DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), src_addr);
            return PROCESS_CMDU_OK;
        }
        if (channel->disabled || !channel->pref)
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("Channel (%u:%u) not inavailable for interface " MACFMT ": disable %u; pref %u\n",
                    steeringReq->opclass, steeringReq->channel, MACARG(steeringReq->sta), channel->disabled, channel->pref);
            send1905BackhaulSteeringResponse(ifw, 0x01, 0x04, DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), src_addr);
            return PROCESS_CMDU_OK;
        }

        _roamBackhaulStaToTarget(ifw, steeringReq->opclass, steeringReq->channel);
    }

    return PROCESS_CMDU_OK;
}

// fix me: to deal with backhaulSteeringRespTLV when steering logic in controller is ready
// When a "backhaul steering response" is received we must send back the "ack" message
static uint8_t processBackhaulSteeringResponse(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    if (0 == send1905Ack(NULL, 0,
	DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        return PROCESS_CMDU_KO;
    }

    return PROCESS_CMDU_OK;
}

// When a "higher layer data" is received we must send back the "ack" message
static uint8_t processHigherLayerData(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t *dst_addr, uint8_t queue_id)
{
    struct higherLayerDataTLV       *higherData = NULL;
    uint8_t ret = PROCESS_CMDU_OK;

    higherData = (struct higherLayerDataTLV *)
            get_CMDU_tlv(c, TLV_TYPE_HIGHER_LAYER_DATA);
    if (!higherData)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Drop high layer data: no required TLV included\n");
        return PROCESS_CMDU_KO;
    }

    /* handle the higher layer data here */
    PLATFORM_PRINTF_DEBUG_DETAIL("Receive high layer data: protocol %u; data len %u\n",
            higherData->protocol, higherData->payload_len);

	if ( 0 == send1905Ack(NULL, 0,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        ret = PROCESS_CMDU_KO;
	}

    mapapi_event_receive_hldata(higherData->protocol, src_addr, dst_addr, higherData->payload, higherData->payload_len);

    return ret;
}

// When a "client association control request" is received we must send back the "ack" message
static uint8_t processClientAssociationControlRequest(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t queue_id)
{
    struct clientAssocCtrlReqTLV    *assocCtrl = NULL;
    struct tlv                      *p = NULL;
    dlist_head                      error_clients;
    struct macAddressItem           *item;
    int i = 0;

    dlist_head_init(&error_clients);

    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        struct _macAddress      *clientItem;
        if (p->type != TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST)
            continue;
        assocCtrl = (struct clientAssocCtrlReqTLV *)p;

        dlist_for_each(clientItem, assocCtrl->tlv.s.h.children[0], s.h.l)
        {
            /* If any of the STAs specified in the Client Association Control message
             * with Association Control field set to 0x00 (indicating Client Blocking)
             * is associated with the BSSID specified in the same message (an error scenario) */
            if (ASSOC_CTRL_BLOCK == assocCtrl->ctrl
                    && findLocalWifiClient(clientItem->mac, assocCtrl->bssid, NULL))
            {
                item = (struct macAddressItem *)malloc(sizeof(*item));
                memcpy(item->mac, clientItem->mac, sizeof(mac_address));
                dlist_add_tail(&error_clients, &item->l);
            }
            else
            {
                _processClientAssocationControl(assocCtrl, clientItem->mac);
            }
        }
    }

	if ( 0 == send1905Ack(&error_clients, 0x01,
            DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, src_addr) )
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not send '1905 ack' message\n");
        dlist_free_items(&error_clients, struct macAddressItem, l);
        return PROCESS_CMDU_KO;
	}

    dlist_free_items(&error_clients, struct macAddressItem, l);

    return PROCESS_CMDU_OK;
}

static uint8_t processMultiAPCmdu(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t *dst_addr, uint8_t queue_id)
{
    PLATFORM_PRINTF_DEBUG_INFO("<-- %s (%s)\n", convert_1905_CMDU_type_to_string(c->message_type),
        DMinterfaceIndexToInterfaceName(receiving_interface_index));
    switch (c->message_type)
    {
        case CMDU_TYPE_AP_CAPABILITY_QUERY:
            return processApCapabilityQuery(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_AP_CAPABILITY_REPORT:
            return processApCapabilityReport(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_MAP_POLICY_CONFIG_REQUEST:
            return processMapPolicyConfigRequest(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_CHANNEL_PREFERENCE_QUERY:
            return processChannelPreferenceQuery(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_CHANNEL_PREFERENCE_REPORT:
            return processChannelPreferenceReport(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_CHANNEL_SELECTION_REQUEST:
            return processChannelSelecetionRequest(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_CHANNEL_SELECTION_RESPONSE:
            return processChannelSelecetionResponse(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_OPERATING_CHANNEL_REPORT:
            return processOperatingChannelReport(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_CLIENT_CAPABILITY_QUERY:
            return processClientCapabilityQuery(c, receiving_interface_index, src_addr, queue_id);
	    break;

        case CMDU_TYPE_CLIENT_CAPABILITY_REPORT:
            return processClientCapabilityReport(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_AP_METRICS_QUERY:
            return processApMetricsQuery(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_AP_METRICS_RESPONSE:
            return processApMetricsResponse(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_ASSOCIATED_STA_LINK_METRICS_QUERY:
            return processAssociatedStaLinkMetricQuery(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_ASSOCIATED_STA_LINK_METRICS_RESPONSE:
            return processAssociatedStaLinkMetricResponse(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY:
            return processUnassociatedStaLinkMetricsQuery(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE:
            return processUnssociatedStaLinkMetricResponse(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_BEACON_METRICS_QUERY:
            return processBeaconMetricsQuery(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_BEACON_METRICS_RESPONSE:
            return processBeaconMetricsResponse(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_COMBINED_INFRASTRUCTURE_METRICS:
            return processCombinedInfrastructureMetrics(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_CLIENT_STEERING_REQUEST:
            return processClientSteeringRequest(c, receiving_interface_index, src_addr, queue_id);
            break;

	case CMDU_TYPE_CLIENT_STEERING_BTM_REPORT:
            return processClientSteeringBTMReport(c, receiving_interface_index, src_addr, queue_id);
            break;

	case CMDU_TYPE_STEERING_COMPLETED:
	    return processSteeringCompleted(c, receiving_interface_index, src_addr, queue_id);
	    break;

        case CMDU_TYPE_CLIENT_ASSOCIATION_CONTROL:
            return processClientAssociationControlRequest(c, receiving_interface_index, src_addr, queue_id);
            break;

	case CMDU_TYPE_BACKHAUL_STEERING_RESPONSE:
            return processBackhaulSteeringResponse(c, receiving_interface_index, src_addr, queue_id);
            break;

        case CMDU_TYPE_HIGHER_LAYER_DATA:
            return processHigherLayerData(c, receiving_interface_index, src_addr, dst_addr, queue_id);
            break;

        case CMDU_TYPE_BACKHAUL_STEERING_REQUEST:
            return processBackhaulSteeringRequest(c, receiving_interface_index, src_addr, queue_id);
            break;

        default:
            break;
    }
    return PROCESS_CMDU_OK;
}

////////////////////////////////////////////////////////////////////////////////
// Public functions (exported only to files in this same folder)
////////////////////////////////////////////////////////////////////////////////

uint8_t process1905Cmdu(struct CMDU *c, uint32_t receiving_interface_index, uint8_t *src_addr, uint8_t *dst_addr, uint8_t queue_id)
{
    if (NULL == c)
    {
        return PROCESS_CMDU_KO;
    }

    checkAndStopRetryTimer(src_addr, c->message_type, c->message_id);

    // Third party implementations maybe need to process some protocol
    // extensions
    //
    process1905CmduExtensions(c);

    switch (c->message_type)
    {
        case CMDU_TYPE_TOPOLOGY_DISCOVERY:
        {
            // When a "topology discovery" is received we must update our
            // internal database (that keeps track of which AL MACs and
            // interface MACs are seen on each interface) and send a "topology
            // query" message asking for more details.

            struct tlv *p;
            uint8_t  i;

            uint8_t  dummy_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            uint8_t  al_mac_address[6];
            uint8_t  mac_address[6];

            uint8_t  first_discovery;
            uint32_t ellapsed;

            memcpy(al_mac_address, dummy_mac_address, 6);
            memcpy(mac_address,    dummy_mac_address, 6);

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_TOPOLOGY_DISCOVERY (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            // We need to update the data model structure, which keeps track
            // of local interfaces, neighbors, and neighbors' interfaces, and
            // what type of discovery messages ("topology discovery" and/or
            // "bridge discovery") have been received on each link.

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // First, extract the AL MAC and MAC addresses of the interface
            // which transmitted this "topology discovery" message
            //
            i = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                    {
                        struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                        memcpy(al_mac_address, t->al_mac_address, 6);

                        break;
                    }
                    case TLV_TYPE_MAC_ADDRESS_TYPE:
                    {
                        struct macAddressTypeTLV *t = (struct macAddressTypeTLV *)p;

                        memcpy(mac_address, t->mac_address, 6);

                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            // Make sure that both the AL MAC and MAC addresses were contained
            // in the CMDU
            //
            if (0 == memcmp(al_mac_address, dummy_mac_address, 6) ||
                0 == memcmp(mac_address,    dummy_mac_address, 6))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            PLATFORM_PRINTF_DEBUG_DETAIL("AL MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n", al_mac_address[0], al_mac_address[1], al_mac_address[2], al_mac_address[3], al_mac_address[4], al_mac_address[5]);
            PLATFORM_PRINTF_DEBUG_DETAIL("MAC    address = %02x:%02x:%02x:%02x:%02x:%02x\n", mac_address[0],    mac_address[1],    mac_address[2],    mac_address[3],    mac_address[4],    mac_address[5]);

            // Next, update the data model
            //
            if (1 == (first_discovery = DMupdateDiscoveryTimeStamps(al_mac_address, mac_address, TIMESTAMP_TOPOLOGY_DISCOVERY, &ellapsed, receiving_interface_index)))
            {
#ifdef SPEED_UP_DISCOVERY
                // If the data model did not contain an entry for this neighbor,
                // "manually" (ie. "out of cycle") send a "Topology Discovery"
                // message on the receiving interface.
                // This will speed up the network discovery process, so that
                // the new node does not have to wait until our "60 seconds"
                // timer expires for him to "discover" us
                //
                PLATFORM_PRINTF_DEBUG_DETAIL("Is this a new node? Re-scheduling a Topology Discovery so that he 'discovers' us\n");

                if (0 == send1905TopologyDiscoveryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid()))
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology discovery message\n");
                }
#endif
            }

            // Finally, query the advertising neighbor for (much) more detailed
            // information (but only if we haven't recently queried it!)
            // This will make the other end send us a
            // CMDU_TYPE_TOPOLOGY_RESPONSE message, which we will later
            // process.
            //
            if (
                 0 == DMnetworkDeviceInfoNeedsUpdate(al_mac_address) ||  // Recently received a Topology Response or....
                 (2 == first_discovery && ellapsed < 5000)               // ...recently (<5 seconds) received a Topology Discovery

               )
            {
                // The first condition prevents us from re-asking (ie.
                // re-sending "Topology Queries") to one same node (we already
                // knew of) faster than once every minute.
                //
                // The second condition prevents us from flooding new nodes
                // (from which we haven't received a "Topology Response" yet)
                // with "Topology Queries" faster than once every 5 seconds)
                //
                break;
            }

            if ( 0 == send1905TopologyQueryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), al_mac_address))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'topology query' message\n");
            }

            break;
        }
        case CMDU_TYPE_TOPOLOGY_NOTIFICATION:
        {
            // When a "topology notification" is received we must send a new
            // "topology query" to the sender.
            // The "sender" AL MAC address is contained in the unique TLV
            // embedded in the just received "topology notification" CMDU.

            struct tlv *p;
            uint8_t  i;

            uint8_t dummy_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            uint8_t  al_mac_address[6];

            struct alDevice *sender_device = NULL;
            struct clientAssocEventTLV *client_assoc_event = NULL;


            memcpy(al_mac_address, dummy_mac_address, 6);

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_TOPOLOGY_NOTIFICATION (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // Extract the AL MAC addresses of the interface which transmitted
            // this "topology notification" message
            //
            i = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                    {
                        struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                        memcpy(al_mac_address, t->al_mac_address, 6);

                        break;
                    }
                    case TLV_TYPE_CLIENT_ASSOCIATION_EVENT:
                    {
                        client_assoc_event = (struct clientAssocEventTLV *)p;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            // Make sure that both the AL MAC and MAC addresses were contained
            // in the CMDU
            //
            if (0 == memcmp(al_mac_address, dummy_mac_address, 6))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            // Discard the relay Cmdu which derived from local device
            //
            if (!memcmp(al_mac_address, local_device->al_mac_addr, sizeof(mac_address)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Receive a topology notification derived from local device, Discard it\n");
                return PROCESS_CMDU_KO;
            }

            PLATFORM_PRINTF_DEBUG_DETAIL("AL MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n", al_mac_address[0], al_mac_address[1], al_mac_address[2], al_mac_address[3], al_mac_address[4], al_mac_address[5]);

#ifdef SPEED_UP_DISCOVERY
            // We will send a topology discovery back. Why is this useful?
            // Well... imagine a node that has just entered the secure network.
            // The first thing this node will do is sending a
            // "topology notification" which, when received by us, will trigger
            // a "topology query".
            // However, unless we send a "topology discovery" back, the new node
            // will not query us for a while (until we actually send our
            // periodic "topology discovery").
            //
             PLATFORM_PRINTF_DEBUG_DETAIL("Is this a new node? Re-scheduling a Topology Discovery so that he 'discovers' us\n");

             if (0 == send1905TopologyDiscoveryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid()))
             {
                 PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology discovery message\n");
             }
#endif
            // Finally, query the informing node.
            // Note that we don't have to check (as we did in the "topology
            // discovery" case) if we recently updated the data model or not.
            // This is because a "topology notification" *always* implies
            // network changes and thus the device must always be (re)-queried.
            //
            if ( 0 == send1905TopologyQueryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), al_mac_address))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'topology query' message\n");
            }

            sender_device = alDeviceFind(al_mac_address);
            if (sender_device && client_assoc_event)
                handleAssocEventTLV(sender_device, client_assoc_event);

            break;
        }
        case CMDU_TYPE_TOPOLOGY_QUERY:
        {
            // When a "topology query" is received we must obtain a series of
            // information from the platform and then package and send it back
            // in a "topology response" message.

            uint8_t *dst_mac;
            uint8_t *p;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_TOPOLOGY_QUERY (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            // We must send the response to the AL MAC of the node who sent the
            // query, however, this AL MAC is *not* contained in the query.
            // The only thing we can do at this point is try to search our AL
            // neighbors data base for a matching MAC.
            //
            p = DMmacToAlMac(src_addr);

            if (NULL == p)
            {
                // The standard says we should always send to the AL MAC
                // address, however, in these cases, instead of just dropping
                // the packet, sending the response to the 'src' address from
                // the TOPOLOGY QUERY seems the right thing to do.
                //
                dst_mac = src_addr;
                PLATFORM_PRINTF_DEBUG_WARNING("Unknown destination AL MAC. Using the 'src' MAC from the TOPOLOGY QUERY (%02x:%02x:%02x:%02x:%02x:%02x)\n", dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
            }
            else
            {
                dst_mac = p;
            }

            if ( 0 == send1905TopologyResponsePacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, dst_mac))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'topology query' message\n");
            }

            if (NULL != p)
            {
                free(p);
            }

            if (registrar.d && (registrar.d != local_device))
            {
                struct alDevice *controller_dev = registrar.d;
                if (!memcmp(controller_dev->al_mac_addr, src_addr, sizeof(mac_address)))
                    mapTryReportLocalRadiosOperatingChannel();
            }
            break;
        }
        case CMDU_TYPE_TOPOLOGY_RESPONSE:
        {
            // When a "topology response" is received we must update our
            // internal database (that keeps track of which 1905 devices are
            // present in the network)

            struct tlv *p;
            uint8_t  i;
            struct alDevice *sender_device;

            struct deviceInformationTypeTLV      *info = NULL;
            struct deviceBridgingCapabilityTLV  **x    = NULL;
            struct non1905NeighborDeviceListTLV **y    = NULL;
            struct neighborDeviceListTLV        **z    = NULL;
            struct powerOffInterfaceTLV         **q    = NULL;
            struct l2NeighborDeviceTLV          **r    = NULL;
            struct supportedServiceTLV           *s    = NULL;
            struct apOperationalBssTLV           *t    = NULL;
            struct associatedClientsTLV          *u    = NULL;

            uint8_t bridges_nr;
            uint8_t non1905_neighbors_nr;
            uint8_t x1905_neighbors_nr;
            uint8_t power_off_nr;
            uint8_t l2_neighbors_nr;

            uint8_t xi, yi, zi, qi, ri;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_TOPOLOGY_RESPONSE (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // First, extract the device info TLV and "count" how many bridging
            // capability TLVs, non-1905 neighbors TLVs and 1905 neighbors TLVs
            // there are
            //
            bridges_nr           = 0;
            non1905_neighbors_nr = 0;
            x1905_neighbors_nr   = 0;
            power_off_nr         = 0;
            l2_neighbors_nr      = 0;
            i                    = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_DEVICE_INFORMATION_TYPE:
                    {
                        info = (struct deviceInformationTypeTLV *)p;
                        break;
                    }
                    case TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES:
                    {
                        bridges_nr++;
                        break;
                    }
                    case TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST:
                    {
                        non1905_neighbors_nr++;
                        break;
                    }
                    case TLV_TYPE_NEIGHBOR_DEVICE_LIST:
                    {
                        x1905_neighbors_nr++;
                        break;
                    }
                    case TLV_TYPE_POWER_OFF_INTERFACE:
                    {
                        power_off_nr++;
                        break;
                    }
                    case TLV_TYPE_L2_NEIGHBOR_DEVICE:
                    {
                        l2_neighbors_nr++;
                        break;
                    }
                    case TLV_TYPE_SUPPORTED_SERVICE:
                    {
                        s = (struct supportedServiceTLV *)p;
                        break;
                    }
                    case TLV_TYPE_AP_OPERATIONAL_BSS:
                    {
                        // Note: This TLV are not use in MAP Agent
                        //
                        break;
                    }
                    case TLV_TYPE_ASSOCIATED_CLIENTS:
                    {
                        // Note: This TLV are not use in MAP Agent
                        //
                        break;
                    }
                    case TLV_TYPE_VENDOR_SPECIFIC:
                    {
                        // According to the standard, zero or more Vendor
                        // Specific TLVs may be present.
                        //
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            if (!info)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Drop Topology response message: miss the device information TLV\n");
                break;
            }

            // Next, now that we know how many TLVs of each type there are,
            // create an array of pointers big enough to contain them and fill
            // it.
            //
            if (bridges_nr > 0)
            {
                x = (struct deviceBridgingCapabilityTLV  **)memalloc(sizeof(struct deviceBridgingCapabilityTLV *)  * bridges_nr);
            }
            if (non1905_neighbors_nr > 0)
            {
                y = (struct non1905NeighborDeviceListTLV **)memalloc(sizeof(struct non1905NeighborDeviceListTLV *) * non1905_neighbors_nr);
            }
            if (x1905_neighbors_nr > 0)
            {
                z = (struct neighborDeviceListTLV        **)memalloc(sizeof(struct neighborDeviceListTLV        *) * x1905_neighbors_nr);
            }
            if (power_off_nr > 0)
            {
                q = (struct powerOffInterfaceTLV         **)memalloc(sizeof(struct powerOffInterfaceTLV         *) * power_off_nr);
            }
            if (l2_neighbors_nr > 0)
            {
                r = (struct l2NeighborDeviceTLV          **)memalloc(sizeof(struct l2NeighborDeviceTLV          *) * l2_neighbors_nr);
            }

            xi = 0;
            yi = 0;
            zi = 0;
            qi = 0;
            ri = 0;
            i  = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_DEVICE_INFORMATION_TYPE:
                    {
                        break;
                    }
                    case TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES:
                    {
                        /* coverity[var_deref_op] - No dereferencing null pointer "x"
                         * x has been alloced above if there is this tlv in the TLVs*/
                        x[xi++] = (struct deviceBridgingCapabilityTLV *)p;
                        break;
                    }
                    case TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST:
                    {
                        /* coverity[var_deref_op] - No dereferencing null pointer "y"
                         * y has been alloced above if there is this tlv in the TLVs*/
                        y[yi++] = (struct non1905NeighborDeviceListTLV *)p;
                        break;
                    }
                    case TLV_TYPE_NEIGHBOR_DEVICE_LIST:
                    {
                        /* coverity[var_deref_op] - No dereferencing null pointer "z"
                         * z has been alloced above if there is this tlv in the TLVs*/
                        z[zi++] = (struct neighborDeviceListTLV *)p;
                        break;
                    }
                    case TLV_TYPE_POWER_OFF_INTERFACE:
                    {
                        /* coverity[var_deref_op] - No dereferencing null pointer "q"
                         * q has been alloced above if there is this tlv in the TLVs*/
                        q[qi++] = (struct powerOffInterfaceTLV *)p;
                        break;
                    }
                    case TLV_TYPE_L2_NEIGHBOR_DEVICE:
                    {
                        /* coverity[var_deref_op] - No dereferencing null pointer "r"
                         * r has been alloced above if there is this tlv in the TLVs*/
                        r[ri++] = (struct l2NeighborDeviceTLV *)p;
                        break;
                    }
                    case TLV_TYPE_SUPPORTED_SERVICE:
                    {
                        break;
                    }
                    case TLV_TYPE_AP_OPERATIONAL_BSS:
                    {
                        t = (struct apOperationalBssTLV *)p;
                        break;
                    }
                    case TLV_TYPE_ASSOCIATED_CLIENTS:
                    {
                        u = (struct associatedClientsTLV *)p;
                        break;
                    }
                    default:
                    {
                        // We are not interested in other TLVs. Free them
                        //
                        free_1905_TLV_structure(p);
                        break;
                    }
                }
                i++;
            }

            // The CMDU structure is not needed anymore, but we cannot just let
            // the caller call "free_1905_CMDU_structure()", because it would
            // also free the TLVs references that we need (ie. those saved in
            // the "x", "y", "z", "q" and "r" pointer arrays).
            // The "fix" is easy: just set "c->list_of_TLVs" to NULL so that
            // when the caller calls "free_1905_CMDU_structure()", this function
            // ignores (ie. does not free) the "list_of_TLVs" list.
            //
            // This will work because and memory won't be lost because:
            //
            //   1. Those TLVs contained in "c->list_of_TLVs" that we are not
            //      keeping track off have already been freed (see the "default"
            //      case in the previous "switch" structure).
            //
            //   2. The rest of them will be freed when the data model entry
            //      is replaced/deleted.
            //
            //   3. Setting "C->list_of_TLVs" to NULL will cause
            //      "free_1905_CMDU_structure()" to ignore this list.
            //
            free(c->list_of_TLVs);
            c->list_of_TLVs = NULL;

            // If the device is not yet in our database, add it now.
            sender_device = alDeviceFind(info->al_mac_address);
            if (sender_device == NULL)
            {
                sender_device = alDeviceAlloc(info->al_mac_address);
            }
            alDeviceUpdateReceivingInterfaceIndex(sender_device, receiving_interface_index);
            alDeviceUpdateReceivingInterfaceName(sender_device, DMinterfaceIndexToInterfaceName(receiving_interface_index));
            alDeviceUpdateLastTopologyResponseTimestamp(sender_device, PLATFORM_GET_TIMESTAMP());

            handleSupportedServiceTLV(sender_device, (struct tlv *)s, c->message_type);
            handleApOperationalBssTLV(DMinterfaceIndexToInterfaceName(receiving_interface_index), sender_device, (struct tlv *)t);
            handleAssociatedClientsTLV(DMinterfaceIndexToInterfaceName(receiving_interface_index), sender_device, (struct tlv *)u);
            if (t)
                free_1905_TLV_structure((struct tlv *)t);
            if (u)
                free_1905_TLV_structure((struct tlv *)u);

            // Next, update the database. This will take care of duplicate
            // entries (and free TLVs if needed)
            //
            PLATFORM_PRINTF_DEBUG_DETAIL("Updating network devices database...\n");
            DMupdateNetworkDeviceInfo(info->al_mac_address,
                                      1, info,
                                      1, x, bridges_nr,
                                      1, y, non1905_neighbors_nr,
                                      1, z, x1905_neighbors_nr,
                                      1, q, power_off_nr,
                                      1, r, l2_neighbors_nr,
                                      1, s,
                                      0, NULL,
                                      0, NULL,
                                      0, NULL,
                                      0, NULL,
                                      0, NULL,
                                      0, NULL);

            // Show all network devices (ie. print them through the logging
            // system)
            //
            DMdumpNetworkDevices(PLATFORM_PRINTF_RAW_DETAIL);

            // And finally, send other queries to the device so that we can
            // keep updating the database once the responses are received
            //
            if ( 0 == send1905MetricsQueryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), info->al_mac_address,
                NULL, LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'metrics query' message\n");
            }
            if ( 0 == send1905HighLayerQueryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), info->al_mac_address))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'high layer query' message\n");
            }
            if ((map_config.topology_policy.APCapaQ_uponTopoR) &&
                ( 0 == send1905ApCapabilityQuery(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), info->al_mac_address)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'ap capability query' message\n");
            }
            for (i=0; i<info->local_interfaces_nr; i++)
            {
                if (MEDIA_TYPE_UNKNOWN == info->local_interfaces[i].media_type)
                {
                    // There is *at least* one generic inteface in the response,
                    // thus query for more information
                    //
                    if ( 0 == send1905GenericPhyQueryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), info->al_mac_address))
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'generic phy query' message\n");
                    }
                    break;
                }
            }

            // There is one extra thing that needs to be done: send topology
            // query to neighbor's neighbors.
            //
            // This is not strictly necessary for 1905 to work. In fact, as I
            // think the protocol was designed, every node should only be aware
            // of its *direct* neighbors; and it is the HLE responsability to
            // query each node and build the network topology map.
            //
            // However, the 1905 datamodel standard document, interestingly
            // (and, I think, erroneously) includes information from all the
            // nodes (even those that are not direct neighbors).
            //
            // Here we are going to retrieve that information but, because this
            // requires much more memory in the AL node, we will only do this
            // if the user actually expressed his desire to do so when starting
            // the AL entity.
            //
            if (1 == DMmapWholeNetworkGet())
            {
                // For each neighbor interface
                //
                for (i=0; i<zi; i++)
                {
                    uint8_t j;

                    // For each neighbor's neighbor on that interface
                    //
                    for (j=0; j<z[i]->neighbors_nr; j++)
                    {
                        uint8_t ii, jj;

                        // Discard the current node (obviously)
                        //
                        if (0 == memcmp(DMalMacGet(), z[i]->neighbors[j].mac_address, 6))
                        {
                            continue;
                        }

                        // Discard nodes I have just asked for
                        //
                        for (ii=0; ii<i; ii++)
                        {
                            for (jj=0; jj<z[ii]->neighbors_nr; jj++)
                            {
                                if (0 == memcmp(z[ii]->neighbors[jj].mac_address, z[i]->neighbors[j].mac_address, 6))
                                {
                                    continue;
                                }
                            }
                        }

                        // Discard neighbors whose information was updated
                        // recently (ie. no need to flood the network)
                        //
                        if (0 == DMnetworkDeviceInfoNeedsUpdate(z[i]->neighbors[j].mac_address))
                        {
                            continue;
                        }

                        if ( 0 == send1905TopologyQueryPacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(), z[i]->neighbors[j].mac_address))
                        {
                            PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'topology query' message\n");
                        }
                    }
                }
            }
            break;
        }
        case CMDU_TYPE_VENDOR_SPECIFIC:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_VENDOR_SPECIFIC (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            // TODO: Implement vendor specific hooks. Maybe, for now, we should
            // simply call a new "PLATFORM_VENDOR_SPECIFIC_CALLBACK()" function

            break;
        }
        case CMDU_TYPE_LINK_METRIC_QUERY:
        {
            struct tlv *p;
            uint8_t  i;

            uint8_t *dst_mac;
            uint8_t *al_mac;

            struct linkMetricQueryTLV *t;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_LINK_METRIC_QUERY (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // First, search for the "struct linkMetricQueryTLV"
            //
            i = 0;
            t = NULL;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_LINK_METRIC_QUERY:
                    {
                        t = (struct linkMetricQueryTLV *)p;
                        break;
                    }
                    case TLV_TYPE_VENDOR_SPECIFIC:
                    {
                        // According to the standard, zero or more Vendor
                        // Specific TLVs may be present.
                        //
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            if (NULL == t)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            if (LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS == t->destination)
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Destination = all neighbors\n");
            }
            else if (LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR == t->destination)
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Destination = specific neighbor (%02x:%02x:%02x:%02x:%02x:%02x)\n", t->specific_neighbor[0], t->specific_neighbor[1], t->specific_neighbor[2], t->specific_neighbor[3], t->specific_neighbor[4], t->specific_neighbor[5]);
            }
            else
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Unexpected 'destination' (%d)\n", t->destination);
                return PROCESS_CMDU_KO;
            }

            if (LINK_METRIC_QUERY_TLV_TX_LINK_METRICS_ONLY == t->link_metrics_type)
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Type        = Tx metrics only\n");
            }
            else if (LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY == t->link_metrics_type)
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Type        = Rx metrics only\n");
            }
            else if (LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS == t->link_metrics_type)
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Type        = Tx and Rx metrics\n");
            }
            else
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Unexpected 'type' (%d)\n", t->link_metrics_type);
                return PROCESS_CMDU_KO;
            }

            // And finally, send a "metrics response" to the requesting neighbor

            // We must send the response to the AL MAC of the node who sent the
            // query, however, this AL MAC is *not* contained in the query.
            // The only thing we can do at this point is try to search our AL
            // neighbors data base for a matching MAC.
            //
            al_mac = DMmacToAlMac(src_addr);

            if (NULL == al_mac)
            {
                // The standard says we should always send to the AL MAC
                // address, however, in these cases, instead of just dropping
                // the packet, sending the response to the 'src' address from
                // the METRICS QUERY seems the right thing to do.
                //
                dst_mac = src_addr;
                PLATFORM_PRINTF_DEBUG_WARNING("Unknown destination AL MAC. Using the 'src' MAC from the METRICS QUERY (%02x:%02x:%02x:%02x:%02x:%02x)\n", dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
            }
            else
            {
                dst_mac = al_mac;
            }

            if ( 0 == send1905MetricsResponsePacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, dst_mac, t->destination, t->specific_neighbor, t->link_metrics_type))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'metrics response' message\n");
            }

            if (NULL != al_mac)
            {
                free(al_mac);
            }

            break;
        }
        case CMDU_TYPE_LINK_METRIC_RESPONSE:
        {
            // When a "metrics response" is received we must update our
            // internal database (that keeps track of which 1905 devices are
            // present in the network)

            struct tlv *p;
            uint8_t  i;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_LINK_METRIC_RESPONSE (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // Call "DMupdateNetworkDeviceMetrics()" for each TLV
            //
            PLATFORM_PRINTF_DEBUG_DETAIL("Updating network devices database...\n");

            i = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_TRANSMITTER_LINK_METRIC:
                    case TLV_TYPE_RECEIVER_LINK_METRIC:
                    {
                        if (!DMupdateNetworkDeviceMetrics((uint8_t*)p))
                            free_1905_TLV_structure(p);
                        break;
                    }
                    default:
                    {
                        free_1905_TLV_structure(p);
                        break;
                    }
                }
                i++;
            }

            free(c->list_of_TLVs);
            c->list_of_TLVs = NULL;

            // Show all network devices (ie. print them through the logging
            // system)
            //
            DMdumpNetworkDevices(PLATFORM_PRINTF_RAW_DETAIL);

            break;
        }
        case CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH:
        {
            // When a "AP-autoconfig search" is received then, *only* if one
            // of our interfaces is the network AP registrar, an "AP-autoconfig
            // response" message must be sent.
            // Otherwise, the message is ignored.

            struct tlv *p;
            struct tlv *supportedService = NULL;
            uint8_t i;

            uint8_t dummy_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            uint8_t searched_role_is_present;
            uint8_t searched_role = IEEE80211_ROLE_AP;

            uint8_t freq_band_is_present;
            uint8_t freq_band = IEEE80211_FREQUENCY_BAND_2_4_GHZ;

            bool searched_service_controller = false;

            uint8_t  al_mac_address[6];
            struct alDevice *sender_device;

            searched_role_is_present = 0;
            freq_band_is_present     = 0;
            memcpy(al_mac_address, dummy_mac_address, 6);

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // First, parse the incomming packet to find out three things:
            // - The AL MAC of the node searching for AP-autoconfiguration
            //   parameters.
            // - The "searched role" contained in the "searched role TLV" (must
            //   be "REGISTRAR")
            // - The "freq band" contained in the "autoconfig freq band TLV"
            //   (must match the one of our local registrar interface)
            //
            i = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                    {
                        struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                        memcpy(al_mac_address, t->al_mac_address, 6);

                        break;
                    }
                    case TLV_TYPE_SEARCHED_ROLE:
                    {
                        struct searchedRoleTLV *t = (struct searchedRoleTLV *)p;

                        searched_role_is_present = 1;
                        searched_role            = t->role;

                        break;
                    }
                    case TLV_TYPE_AUTOCONFIG_FREQ_BAND:
                    {
                        struct autoconfigFreqBandTLV *t = (struct autoconfigFreqBandTLV *)p;

                        freq_band_is_present = 1;
                        freq_band            = t->freq_band;

                        break;
                    }
                    case TLV_TYPE_SUPPORTED_SERVICE:
                    {
                        /* Delay processing so we're sure we've seen the alMacAddressTypeTLV. */
                        supportedService = p;
                        break;
                    }
                    case TLV_TYPE_SEARCHED_SERVICE:
                    {
                        struct _supportedService* service;
                        dlist_for_each(service, p->s.h.children[0], s.h.l)
                        {
                            switch (service->service)
                            {
                            case SERVICE_MULTI_AP_CONTROLLER:
                                searched_service_controller = true;
                                break;
                            default:
                                PLATFORM_PRINTF_DEBUG_WARNING(
                                            "Received AP Autoconfiguration Search with unknown Searched Service %02x\n",
                                            service->service);
                                /* Ignore it, as required by the specification. */
                                break;
                            }
                        }
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            // Discard the relay Cmdu which derived from local device
            //
            if (!memcmp(al_mac_address, local_device->al_mac_addr, sizeof(mac_address)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Receive a AP-autoconfig search derived from local device\n");
                return PROCESS_CMDU_KO;
            }

            // Make sure that all needed parameters were present in the message
            //
            if (
                 0 == memcmp(al_mac_address, dummy_mac_address, 6) ||
                 0 == searched_role_is_present                              ||
                 0 == freq_band_is_present
               )
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            if (IEEE80211_ROLE_AP != searched_role)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Unexpected 'searched role'\n");
                return PROCESS_CMDU_KO;
            }

            /* If the device is not yet in our database, add it now. */
            sender_device = alDeviceFind(al_mac_address);
            if (sender_device == NULL)
            {
                sender_device = alDeviceAlloc(al_mac_address);
            }
            alDeviceUpdateReceivingInterfaceIndex(sender_device, receiving_interface_index);
            alDeviceUpdateReceivingInterfaceName(sender_device, DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (handleSupportedServiceTLV(sender_device, supportedService, c->message_type))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Multi-AP Controller shouldn't send AP Autoconfiguration Search\n");
                return PROCESS_CMDU_KO;
            }

            /* If we are the registrar, send the response. */
            if (registrarIsLocal())
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Local device is registrar, Sending response...\n");
                if (0 == send1905APAutoconfigurationResponsePacket(DMinterfaceIndexToInterfaceName(receiving_interface_index),
                            c->message_id, al_mac_address, freq_band, searched_service_controller))
                {
                        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'AP autoconfiguration response' message\n");
                }
            }
            else
            {
                PLATFORM_PRINTF_DEBUG_INFO("Local device is not registrar\n");
            }

            break;
        }
        case CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE:
        {
            // When a "AP-autoconfig response" is received then we have to
            // search for the first interface which is an unconfigured AP with
            // the same freq band as the one contained in the message and send
            // a AP-autoconfig WSC-M1

            struct tlv *p;
            struct tlv *supportedService = NULL;
            uint8_t i;
            struct alDevice *sender_device;
            bool imm = false;

            bool supported_role_is_present = false;
            uint8_t supported_role = IEEE80211_ROLE_AP;

            bool supported_freq_band_is_present = false;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // First, parse the incomming packet to find out two things:
            //   parameters.
            // - The "supported role" contained in the "supported role TLV"
            //   (must be "REGISTRAR")
            // - The "supported freq band" contained in the "supported freq
            // band TLV" (must match the one of our local unconfigured
            // interface)
            //
            i = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_SUPPORTED_ROLE:
                    {
                        struct supportedRoleTLV *t = (struct supportedRoleTLV *)p;

                        supported_role_is_present = true;
                        supported_role            = t->role;

                        break;
                    }
                    case TLV_TYPE_SUPPORTED_FREQ_BAND:
                    {
                        supported_freq_band_is_present = true;

                        break;
                    }
                    case TLV_TYPE_SUPPORTED_SERVICE:
                    {
                        /* Delay processing so we're sure we've seen the alMacAddressTypeTLV. */
                        supportedService = p;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            // Make sure that all needed parameters were present in the message
            //
            if (
                 !supported_role_is_present      ||
                 !supported_freq_band_is_present
               )
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            if (IEEE80211_ROLE_AP != supported_role)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Unexpected 'searched role'\n");
                return PROCESS_CMDU_KO;
            }

            /* FIXME: There is no al_mac_address, try to use the src_addr to create the alDevice. */
            sender_device = alDeviceFind(src_addr);
            if (sender_device == NULL)
            {
                sender_device = alDeviceAlloc(src_addr);
            }
            alDeviceUpdateReceivingInterfaceIndex(sender_device, receiving_interface_index);
            alDeviceUpdateReceivingInterfaceName(sender_device, DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (!handleSupportedServiceTLV(sender_device, supportedService, c->message_type))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Multi-AP Agent shouldn't send AP Autoconfiguration Response\n");
                return PROCESS_CMDU_KO;
            }

            if (local_device->configured)
                imm = true;
            if (registrar.d)
                triggerDeviceAPAutoConfiguration(imm);

            break;
        }
        case CMDU_TYPE_AP_AUTOCONFIGURATION_WSC:
        {
            struct tlv *p;
            uint8_t i;
            bool free_wcs = true;

            /* Collected list of WSCs. Note that these will point into the TLV structures, so don't use wscM2Free()! */
            wscM2List wsc_list = {0, NULL};
            uint8_t wsc_type = WSC_TYPE_UNKNOWN;

            struct apRadioBasicCapabilitiesTLV *ap_radio_basic_capabilities = NULL;
            struct apRadioIdentifierTLV *ap_radio_identifier = NULL;
            uint8_t remote_peer_maxbss = 255;


            // When a "AP-autoconfig WSC" is received we first have to find out
            // if the contained message is M1 or M2.
            // If it is M1, send an M2 response.
            // If it is M2, apply the received configuration.

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_AP_AUTOCONFIGURATION_WSC (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            i = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_WSC:
                    {
                        struct wscTLV *t = (struct wscTLV *)p;
                        struct wscM2Buf m;
                        uint8_t new_wsc_type;

                        if (wsc_type == WSC_TYPE_M1)
                        {
                            PLATFORM_PRINTF_DEBUG_WARNING("Only a single M2 TLV is allowed.\n");
                            return PROCESS_CMDU_KO;
                        }
                        m.m2 = t->wsc_frame;
                        m.m2_size = t->wsc_frame_size;
                        new_wsc_type = wscGetType(m.m2, m.m2_size);
                        if (new_wsc_type == WSC_TYPE_M1 && wsc_type == WSC_TYPE_M2)
                        {
                            PLATFORM_PRINTF_DEBUG_WARNING("Only M2 TLVs are allowed in M2 CMDU.\n");
                            return PROCESS_CMDU_KO;
                        }
                        PTRARRAY_ADD(wsc_list, m);
                        wsc_type = new_wsc_type;
                        break;
                    }
                    case TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES:
                        ap_radio_basic_capabilities = container_of(p, struct apRadioBasicCapabilitiesTLV, tlv);
                        break;
                    case TLV_TYPE_AP_RADIO_IDENTIFIER:
                        ap_radio_identifier = container_of(p, struct apRadioIdentifierTLV, tlv);
                        break;

                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            // Make sure there was a WSC TLV in the message
            //
            if (wsc_list.length == 0)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("At least one WSC TLV expected inside WSC CMDU\n");
                return PROCESS_CMDU_KO;
            }

            if (WSC_TYPE_M2 == wsc_type)
            {
                struct radio *radio = NULL;

                if (ap_radio_identifier != NULL)
                {
                    radio = findDeviceRadio(local_device, ap_radio_identifier->radio_uid);
                    if (radio == NULL)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Received AP radio identifier for unknown radio " MACSTR "\n",
                                                      MAC2STR(ap_radio_identifier->radio_uid));
                        return PROCESS_CMDU_KO;
                    }
                    if (radio->wsc_info == NULL)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Received WSC M2 for radio " MACSTR " which didn't send M1\n",
                                                      MAC2STR(ap_radio_identifier->radio_uid));
                        return PROCESS_CMDU_KO;
                    }
                }
                else
                {
                    /* For non-multi-AP, we don't have a radio identifier. Just take the last radio for which we sent an M1.
                     * @todo There must be a better way to do this. */
                    dlist_for_each(radio, local_device->radios, l)
                    {
                        if (radio->wsc_info)
                        {
                            break;
                        }
                    }
                    if (radio == NULL)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Received M2 but no corresponding M1 found.\n");
                        return PROCESS_CMDU_KO;
                    }
                }

                // Sync configuration with driver
                //
                REGISTRAR_SYNC_BSSCFGS();

                // Process it and apply the configuration to the corresponding
                // interface.
                //
                for (i = 0; i < wsc_list.length; i++)
                {
                    if (!wscProcessM2(radio, wsc_list.data[i].m2, wsc_list.data[i].m2_size))
                       free_wcs = false;
                }

                if (free_wcs)
                {
                    wscApplyM2(radio);
                    wscInfoFree(radio);
                }
                PTRARRAY_CLEAR(wsc_list);

                // One more thing: This node *might* have other unconfigured AP
                // interfaces (in addition to the one we have just configured),
                // thus, re-trigger the AP discovery process, just in case.
                // Note that this function will do nothing if there are no
                // unconfigured AP interfaces remaining.
                radio->configured = true;
                return PROCESS_CMDU_OK_TRIGGER_AP_SEARCH;
            }
            else if (WSC_TYPE_M1 == wsc_type)
            {
                // We hadn't previously sent an M1 (ie. we are the registrar),
                // thus the contents of the just received message must be M1.
                //
                // Process it and send an M2 response.
                //
                wscM2List m2_list = {0, NULL};
                struct wscM1Info m1_info;

                bool send_radio_identifier = ap_radio_basic_capabilities != NULL;

                struct alDevice *sender_device = alDeviceFindFromAnyAddress(src_addr);

                struct wscRegistrarInfo *wsc_info = NULL;

                /* wsc_list will have length 1, checked above (implicitly) */
                if (!wscParseM1(wsc_list.data[0].m2, wsc_list.data[0].m2_size, &m1_info))
                {
                    // wscParseM1 already printed an error message.
                    break;
                }

                if (sender_device == NULL)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Received WSC M1 from undiscovered address " MACSTR "\n",
                                                  MAC2STR(src_addr));
                    // There should have been a discovery before, so ignore this one.
                    break;
                }

                if (send_radio_identifier)
                {
                    /* Update data model with radio capabilities */
                    struct radio *radio = _handleApRadioBasicCapabilitiesTLV(sender_device, &ap_radio_basic_capabilities->tlv);
                    if (!radio)
                        break;

                    if (m1_info.rf_bands & WPS_RF_24GHZ)
                        radio->band_supported = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
                    else if (m1_info.rf_bands & WPS_RF_50GHZ)
                        radio->band_supported = IEEE80211_FREQUENCY_BAND_5_GHZ;
                    else if (m1_info.rf_bands & WPS_RF_60GHZ)
                        radio->band_supported = IEEE80211_FREQUENCY_BAND_60_GHZ;

                    remote_peer_maxbss = radio->maxBSS;
                }

                dlist_for_each(wsc_info, registrar.wsc, l)
                {
                    if (checkM1BandMatchWscBssInfo(wsc_info, sender_device->al_mac_addr, m1_info.rf_bands))
                    {
                        struct wscM2Buf new_m2;
                        wscBuildM2(&m1_info, wsc_info, &new_m2);
                        PTRARRAY_ADD(m2_list, new_m2);
                        if (m2_list.length >= remote_peer_maxbss)
                        {
                            PLATFORM_PRINTF_DEBUG_INFO("wsc m2 num is limited by remote peer's maxbss num(%u)\n", remote_peer_maxbss);
                            break;
                        }
                    }
                }

                PLATFORM_PRINTF_DEBUG_DETAIL("m2_list.length = %d\n", m2_list.length);
                /* there is no wsc_info match with m1's rf_bands, teardown this rf band. */
                if (m2_list.length == 0)
                {
                    struct wscM2Buf new_m2;

                    wsc_info = zmemalloc(sizeof(struct wscRegistrarInfo));
                    wsc_info->rf_bands = m1_info.rf_bands;
                    wsc_info->bss_info.teardown = true;

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

                    wscBuildM2(&m1_info, wsc_info, &new_m2);
                    PTRARRAY_ADD(m2_list, new_m2);
                    free(wsc_info);
                }

                if ( 0 == send1905APAutoconfigurationWSCM2Packet(DMinterfaceIndexToInterfaceName(receiving_interface_index), getNextMid(),
                                                                 sender_device->al_mac_addr, m2_list,
                                                                 send_radio_identifier ? ap_radio_basic_capabilities->radio_uid : NULL,
                                                                 send_radio_identifier))
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'AP autoconfiguration WSC-M2' message\n");
                }
                wscFreeM2List(m2_list);
            }
            else
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Unknown type of WSC message!\n");
            }

            break;
        }
        case CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW:
        {
            struct radio *radio;
            bool imm = local_device->configured ? true : false;
            struct alMacAddressTypeTLV *t;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            // First, parse the incomming packet here we only care the AL MAC
            //
            t = (struct alMacAddressTypeTLV *)get_CMDU_tlv(c, TLV_TYPE_AL_MAC_ADDRESS_TYPE);

            if (!t)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Receive a AP-autoconfig Renew have no required AL_MAC_ADDRESS_TLV, Discard it\n");
                return PROCESS_CMDU_KO;
            }

            // Discard the relay Cmdu which derived from local device
            //
            if (!memcmp(t->al_mac_address, local_device->al_mac_addr, sizeof(mac_address)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Receive a AP-autoconfig Renew derived from local device, Discard it\n");
                return PROCESS_CMDU_KO;
            }

            if (!registrar.d)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Receive a AP-autoconfig Renew but no controller found yet, Discard it\n");
                return PROCESS_CMDU_KO;
            }

            if (memcmp(registrar.d->al_mac_addr, t->al_mac_address, sizeof(mac_address)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Receive a AP-autoconfig Renew which al_mac "
                        MACFMT " is not match recorded controller's al_mac " MACFMT ", Discard it\n",
                        MACARG(t->al_mac_address), MACARG(registrar.d->al_mac_addr));
                mapapi_event_rogue_renew_detected(t->al_mac_address);
                return PROCESS_CMDU_KO;
            }

            /* reset the configured, to trigger get the new configurations for all readios */
            local_device->configured = false;
            dlist_for_each(radio, local_device->radios, l)
            {
                radio->backhaul_only_configured = false;
                radio->configured = false;
            }

            triggerDeviceAPAutoConfiguration(imm);
            break;
        }
        case CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION:
        {
            // According to "Section 9.2.2.2", when a "push button event
            // notification" is received we have to:
            //
            //   1. Transition *all* interfaces to POWER_STATE_PWR_ON
            //
            //   2. Start the "push button" configuration process in all those
            //     interfaces that:
            //       2.1 Are not 802.11
            //       2.2 Are 802.11 APs, configured as "registrars", but only if
            //           the received message did not contain 802.11 media type
            //           information.

            struct tlv *p;
            uint8_t i;

            uint8_t dummy_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            char **ifs_names;
            uint8_t  ifs_nr;

            uint8_t wifi_data_is_present;

            uint8_t  al_mac_address[6];

            wifi_data_is_present = 0;
            memcpy(al_mac_address, dummy_mac_address, 6);

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // First, parse the incomming packet to find out if the 'push
            // button' event TLV contains 802.11 data.
            //
            i = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                    {
                        struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                        memcpy(al_mac_address, t->al_mac_address, 6);

                        break;
                    }
                    case TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION:
                    {
                        uint8_t j;
                        struct pushButtonEventNotificationTLV *t = (struct pushButtonEventNotificationTLV *)p;


                        for (j=0; j<t->media_types_nr; j++)
                        {
                            if (INTERFACE_TYPE_IS_IEEE_802_11(t->media_types[j].media_type) &&
                                    (t->media_types[j].media_type != INTERFACE_TYPE_IEEE_802_11AX))
                            {
                                wifi_data_is_present = 1;
                                break;
                            }
                        }

                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            if (0 == memcmp(al_mac_address, dummy_mac_address, 6))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            // Discard the relay Cmdu which derived from local device
            //
            if (!memcmp(al_mac_address, local_device->al_mac_addr, sizeof(mac_address)))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Receive a push button derived from local device, Discard it\n");
                return PROCESS_CMDU_KO;
            }

            // Next, switch on all interfaces
            //
            ifs_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifs_nr);

            PLATFORM_PRINTF_DEBUG_DETAIL("Transitioning all local interfaces to POWER_ON\n");

#ifndef DO_NOT_ACCEPT_UNAUTHENTICATED_COMMANDS
            for (i=0; i<ifs_nr; i++)
            {
                PLATFORM_SET_INTERFACE_POWER_MODE(ifs_names[i], INTERFACE_POWER_STATE_ON);
            }
#endif
            // Finally, for those non wifi interfaces (or a wifi interface whose
            // MAC address matches the network registrar MAC address), start
            // the "push button" configuration process.
            // @todo this is different from Multi-AP PBC.
            //
            PLATFORM_PRINTF_DEBUG_DETAIL("Starting 'push button' configuration process on all compatible interfaces\n");
            for (i=0; i<ifs_nr; i++)
            {
                struct interfaceInfo *x;

                x = PLATFORM_GET_1905_INTERFACE_INFO(ifs_names[i]);
                if (NULL == x)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not retrieve info of interface %s\n", ifs_names[i]);
                    continue;
                }

                if (2 == x->push_button_on_going)
                {
                    PLATFORM_PRINTF_DEBUG_INFO("%s is not compatible. Skipping...\n",ifs_names[i]);

                    free_1905_INTERFACE_INFO(x);
                    continue;
                }

                if (INTERFACE_TYPE_IS_IEEE_802_11(x->interface_type))
                {
                     if (
                          IEEE80211_ROLE_AP != x->interface_type_data.ieee80211.role ||
                          !registrarIsLocal()
                         )
                     {
                         PLATFORM_PRINTF_DEBUG_INFO("This wifi interface %s is already configured. Skipping...\n",ifs_names[i]);

                         free_1905_INTERFACE_INFO(x);
                         continue;
                     }
                     else if (0 == wifi_data_is_present)
                     {
                         PLATFORM_PRINTF_DEBUG_INFO("This wifi interface is the registrar, but the 'push button event notification' message did not contain wifi data. Skipping...\n");

                         free_1905_INTERFACE_INFO(x);
                         continue;
                     }
                }

                free_1905_INTERFACE_INFO(x);

                PLATFORM_PRINTF_DEBUG_INFO("Starting push button configuration process on interface %s\n", ifs_names[i]);
            #ifdef QDOCK
                if (0 == PLATFORM_START_PUSH_BUTTON_CONFIGURATION(ifs_names[i]))
            #else
                if (0 == PLATFORM_START_PUSH_BUTTON_CONFIGURATION(ifs_names[i], queue_id, al_mac_address, c->message_id))
            #endif
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not start 'push button' configuration process on interface %s\n",ifs_names[i]);
                }
            }

            free_LIST_OF_1905_INTERFACES(ifs_names, ifs_nr);

            break;
        }
        case CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));
            // TODO: Somehow "signal" upper layers (?)

            break;
        }
        case CMDU_TYPE_GENERIC_PHY_QUERY:
        {
            // When a "generic phy query" is received we must reply with the
            // list of local "generic" interfaces inside a "generic phy
            // response" CMDU.
            // Not that even if we don't have any "generic" interface (ie. its
            // 'media type' is "MEDIA_TYPE_UNKNOWN") the response will be sent
            // (containing a TLV that says there are "zero" generic interfaces)

            uint8_t *dst_mac;
            uint8_t *p;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_GENERIC_PHY_QUERY (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            // We must send the response to the AL MAC of the node who sent the
            // query, however, this AL MAC is *not* contained in the query.
            // The only thing we can do at this point is try to search our AL
            // neighbors data base for a matching MAC.
            //
            p = DMmacToAlMac(src_addr);

            if (NULL == p)
            {
                // The standard says we should always send to the AL MAC
                // address, however, in these cases, instead of just dropping
                // the packet, sending the response to the 'src' address from
                // the TOPOLOGY QUERY seems the right thing to do.
                //
                dst_mac = src_addr;
                PLATFORM_PRINTF_DEBUG_WARNING("Unknown destination AL MAC. Using the 'src' MAC from the GENERIC PHY QUERY (%02x:%02x:%02x:%02x:%02x:%02x)\n", dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
            }
            else
            {
                dst_mac = p;
            }

            if ( 0 == send1905GenericPhyResponsePacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, dst_mac))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'topology query' message\n");
            }

            if (NULL != p)
            {
                free(p);
            }

            break;
        }
        case CMDU_TYPE_GENERIC_PHY_RESPONSE:
        {
            // When a "generic phy response" is received we must update our
            // internal database (that keeps track of which 1905 devices are
            // present in the network)

            struct genericPhyDeviceInformationTypeTLV *t;

            struct tlv *p;
            uint8_t  i;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_GENERIC_PHY_RESPONSE (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // Call "DMupdateGenericPhyInfo()" for the "generic phy
            // device information type TLV"  contained in this CMDU.
            //
            i = 0;
            t = NULL;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION:
                    {
                        t = (struct genericPhyDeviceInformationTypeTLV *)p;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            if (NULL == t)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            PLATFORM_PRINTF_DEBUG_DETAIL("Updating network devices database...\n");
            DMupdateNetworkDeviceInfo(t->al_mac_address,
                                      0, NULL,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL,
                                      1, t,
                                      0, NULL,
                                      0, NULL,
                                      0, NULL,
                                      0, NULL,
                                      0, NULL);

            // Show all network devices (ie. print them through the logging
            // system)
            //
            DMdumpNetworkDevices(PLATFORM_PRINTF_RAW_DETAIL);

            break;
        }
        case CMDU_TYPE_HIGHER_LAYER_QUERY:
        {
            // When a "high layer query" is received we must reply with the
            // list of items inside a "high layer response" CMDU.

            uint8_t *dst_mac;
            uint8_t *al_mac;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_HIGHER_LAYER_QUERY (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            // We must send the response to the AL MAC of the node who sent the
            // query, however, this AL MAC is *not* contained in the query.
            // The only thing we can do at this point is try to search our AL
            // neighbors data base for a matching MAC.
            //
            al_mac = DMmacToAlMac(src_addr);

            if (NULL == al_mac)
            {
                // The standard says we should always send to the AL MAC
                // address, however, in these cases, instead of just dropping
                // the packet, sending the response to the 'src' address from
                // the TOPOLOGY QUERY seems the right thing to do.
                //
                dst_mac = src_addr;
                PLATFORM_PRINTF_DEBUG_WARNING("Unknown destination AL MAC. Using the 'src' MAC from the HIGH LAYER QUERY (%02x:%02x:%02x:%02x:%02x:%02x)\n", dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
            }
            else
            {
                dst_mac = al_mac;
            }

            if ( 0 == send1905HighLayerResponsePacket(DMinterfaceIndexToInterfaceName(receiving_interface_index), c->message_id, dst_mac))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'high layer response' message\n");
            }

            if (NULL != al_mac)
            {
                free(al_mac);
            }

            break;
        }
        case CMDU_TYPE_HIGHER_LAYER_RESPONSE:
        {
            // When a "high layer response" is received we must update our
            // internal database (that keeps track of which 1905 devices are
            // present in the network)

            struct x1905ProfileVersionTLV      *profile         = NULL;
            struct deviceIdentificationTypeTLV *identification  = NULL;
            struct controlUrlTypeTLV           *control_url     = NULL;
            struct ipv4TypeTLV                 *ipv4            = NULL;
            struct ipv6TypeTLV                 *ipv6            = NULL;

            uint8_t  al_mac_address[6];
            uint8_t  al_mac_address_is_present;

            struct tlv *p;
            uint8_t  i;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_HIGHER_LAYER_RESPONSE (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // Call "DMupdateGenericPhyInfo()" with each of the TLVs contained
            // in this CMDU
            //
            i                         = 0;
            al_mac_address_is_present = 0;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                    {
                        struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                        memcpy(al_mac_address, t->al_mac_address, 6);

                        al_mac_address_is_present = 1;

                        free_1905_TLV_structure(p);
                        break;
                    }
                    case TLV_TYPE_1905_PROFILE_VERSION:
                    {
                        profile = (struct x1905ProfileVersionTLV *)p;
                        break;
                    }
                    case TLV_TYPE_DEVICE_IDENTIFICATION:
                    {
                        identification = (struct deviceIdentificationTypeTLV *)p;
                        break;
                    }
                    case TLV_TYPE_CONTROL_URL:
                    {
                        control_url = (struct controlUrlTypeTLV *)p;
                        break;
                    }
                    case TLV_TYPE_IPV4:
                    {
                        ipv4 = (struct ipv4TypeTLV *)p;
                        break;
                    }
                    case TLV_TYPE_IPV6:
                    {
                        ipv6 = (struct ipv6TypeTLV *)p;
                        break;
                    }
                    default:
                    {
                        free_1905_TLV_structure(p);
                        break;
                    }
                }
                i++;
            }

            if (0 == al_mac_address_is_present)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            // Next, update the database. This will take care of duplicate
            // entries (and free the TLV if needed)
            //
            PLATFORM_PRINTF_DEBUG_DETAIL("Updating network devices database...\n");
            DMupdateNetworkDeviceInfo(al_mac_address,
                                      0, NULL,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL, 0,
                                      0, NULL,
                                      0, NULL,
                                      1, profile,
                                      1, identification,
                                      1, control_url,
                                      1, ipv4,
                                      1, ipv6);

            // References to the TLVs cannot be freed by the caller (see the
            // comment in "case CMDU_TYPE_TOPOLOGY_RESPONSE:" to understand the
            // following two lines).
            //
            free(c->list_of_TLVs);
            c->list_of_TLVs = NULL;

            // Show all network devices (ie. print them through the logging
            // system)
            //
            DMdumpNetworkDevices(PLATFORM_PRINTF_RAW_DETAIL);

            break;
        }
        case CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST:
        {
            // When an "interface power change" request is received we need to
            // set the local interfaces to the requested power modes and reply
            // back with the result of these operations

            struct interfacePowerChangeInformationTLV *t;

            struct tlv *p;
            uint8_t  i;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // Search for the "interface power change information type" TLV
            //
            i = 0;
            t = NULL;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION:
                    {
                        t = (struct interfacePowerChangeInformationTLV *)p;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            if (NULL == t)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            for (i=0; i<t->power_change_interfaces_nr; i++)
            {
                uint8_t r;
                uint8_t results;

#ifndef DO_NOT_ACCEPT_UNAUTHENTICATED_COMMANDS
                r = PLATFORM_SET_INTERFACE_POWER_MODE(DMmacToInterfaceName(t->power_change_interfaces[i].interface_address), t->power_change_interfaces[i].requested_power_state);
#else
                r = INTERFACE_POWER_RESULT_KO;
#endif

                switch (r)
                {
                    case INTERFACE_POWER_RESULT_EXPECTED:
                    {
                        results = POWER_STATE_RESULT_COMPLETED;
                        break;
                    }
                    case INTERFACE_POWER_RESULT_NO_CHANGE:
                    {
                        results = POWER_STATE_RESULT_NO_CHANGE;
                        break;
                    }
                    case INTERFACE_POWER_RESULT_ALTERNATIVE:
                    {
                        results = POWER_STATE_RESULT_ALTERNATIVE_CHANGE;
                        break;
                    }
                    case INTERFACE_POWER_RESULT_KO:
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("  Could not set power mode on interface %s\n",DMmacToInterfaceName(t->power_change_interfaces[i].interface_address));
                        results = POWER_STATE_RESULT_NO_CHANGE;
                        break;
                    }
                    default:
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("  Unknown power mode return value: %d\n",r);
                        results = POWER_STATE_RESULT_NO_CHANGE;
                        break;
                    }
                }

                PLATFORM_PRINTF_DEBUG_DETAIL("  Setting interface #%d %s (%02x:%02x:%02x:%02x:%02x:%02x) to %s --> %s\n", i,
                                             DMmacToInterfaceName(t->power_change_interfaces[i].interface_address),
                                             t->power_change_interfaces[i].interface_address[0], t->power_change_interfaces[i].interface_address[1], t->power_change_interfaces[i].interface_address[2], t->power_change_interfaces[i].interface_address[3], t->power_change_interfaces[i].interface_address[4], t->power_change_interfaces[i].interface_address[5],
                                             t->power_change_interfaces[i].requested_power_state == POWER_STATE_REQUEST_OFF  ? "POWER OFF"  :
                                             t->power_change_interfaces[i].requested_power_state == POWER_STATE_REQUEST_ON   ? "POWER ON"   :
                                             t->power_change_interfaces[i].requested_power_state == POWER_STATE_REQUEST_SAVE ? "POWER SAVE" :
                                             "Unknown",
                                             results == POWER_STATE_RESULT_COMPLETED ? "Completed" :
                                             results == POWER_STATE_RESULT_NO_CHANGE ? "No change" :
                                             results == POWER_STATE_RESULT_ALTERNATIVE_CHANGE ? "Alternative change" :
                                             "Unknown"
                                             );
            }

            break;
        }
        case CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE:
        {
            // When an "interface power change" response is received we don't
            // need to do anything special. Simply log the event.

            struct interfacePowerChangeStatusTLV *t;

            struct tlv *p;
            uint8_t  i;

            PLATFORM_PRINTF_DEBUG_INFO("<-- CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

            if (NULL == c->list_of_TLVs)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
                break;
            }

            // Search for the "interface power change status" TLV
            //
            i = 0;
            t = NULL;
            while (NULL != (p = c->list_of_TLVs[i]))
            {
                switch (p->type)
                {
                    case TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS:
                    {
                        t = (struct interfacePowerChangeStatusTLV *)p;
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                i++;
            }

            if (NULL == t)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this CMDU\n");
                return PROCESS_CMDU_KO;
            }

            for (i=0; i<t->power_change_interfaces_nr; i++)
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("  Interface #%d %s (%02x:%02x:%02x:%02x:%02x:%02x) --> %s\n", i,
                                             DMmacToInterfaceName(t->power_change_interfaces[i].interface_address),
                                             t->power_change_interfaces[i].interface_address[0], t->power_change_interfaces[i].interface_address[1], t->power_change_interfaces[i].interface_address[2], t->power_change_interfaces[i].interface_address[3], t->power_change_interfaces[i].interface_address[4], t->power_change_interfaces[i].interface_address[5],
                                             t->power_change_interfaces[i].result == POWER_STATE_RESULT_COMPLETED ? "Completed" :
                                             t->power_change_interfaces[i].result == POWER_STATE_RESULT_NO_CHANGE ? "No change" :
                                             t->power_change_interfaces[i].result == POWER_STATE_RESULT_ALTERNATIVE_CHANGE ? "Alternative change" :
                                             "Unknown");
            }

            break;
        }

        default:
        {
            return processMultiAPCmdu(c, receiving_interface_index, src_addr, dst_addr, queue_id);
            break;
        }
    }

    return PROCESS_CMDU_OK;
}

uint8_t processLlpdPayload(struct PAYLOAD *payload, uint32_t receiving_interface_index)
{
    struct tlv *p;
    uint8_t  i;

    uint8_t dummy_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t  al_mac_address[6];
    uint8_t  mac_address[6];

    memcpy(al_mac_address, dummy_mac_address, 6);
    memcpy(mac_address,    dummy_mac_address, 6);

    if (NULL == payload)
    {
        return 0;
    }

    PLATFORM_PRINTF_DEBUG_INFO("<-- LLDP BRIDGE DISCOVERY (%s)\n", DMinterfaceIndexToInterfaceName(receiving_interface_index));

    // We need to update the data model structure, which keeps track
    // of local interfaces, neighbors, and neighbors' interfaces, and
    // what type of discovery messages ("topology discovery" and/or
    // "bridge discovery") have been received on each link.

    // First, extract the AL MAC and MAC addresses of the interface
    // which transmitted this bridge discovery message
    //
    i = 0;
    while (NULL != (p = payload->list_of_TLVs[i]))
    {
        switch (p->type)
        {
            case TLV_TYPE_CHASSIS_ID:
            {
                struct chassisIdTLV *t = (struct chassisIdTLV *)p;

                if (CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS == t->chassis_id_subtype)
                {
                    memcpy(al_mac_address, t->chassis_id, 6);
                }

                break;
            }
            case TLV_TYPE_MAC_ADDRESS_TYPE:
            {
                struct portIdTLV *t = (struct portIdTLV *)p;

                if (PORT_ID_TLV_SUBTYPE_MAC_ADDRESS == t->port_id_subtype)
                {
                    memcpy(mac_address, t->port_id, 6);
                }

                break;
            }
            case TLV_TYPE_TIME_TO_LIVE:
            {
                break;
            }
            default:
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("Ignoring TLV type %d\n", p->type);
                break;
            }
        }
        i++;
    }

    // Make sure that both the AL MAC and MAC addresses were contained
    // in the CMDU
    //
    if (0 == memcmp(al_mac_address, dummy_mac_address, 6) ||
        0 == memcmp(mac_address,    dummy_mac_address, 6))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("More TLVs were expected inside this LLDP message\n");
        return 0;
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("AL MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n", al_mac_address[0], al_mac_address[1], al_mac_address[2], al_mac_address[3], al_mac_address[4], al_mac_address[5]);
    PLATFORM_PRINTF_DEBUG_DETAIL("MAC    address = %02x:%02x:%02x:%02x:%02x:%02x\n", mac_address[0],    mac_address[1],    mac_address[2],    mac_address[3],    mac_address[4],    mac_address[5]);

    // Finally, update the data model
    //
    if (0 == DMupdateDiscoveryTimeStamps(al_mac_address, mac_address, TIMESTAMP_BRIDGE_DISCOVERY, NULL, receiving_interface_index))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Problems updating data model with topology response TLVs\n");
        return 0;
    }

    return 1;
}

uint8_t process1905Alme(uint8_t *alme_tlv, uint8_t alme_client_id)
{
    if (NULL == alme_tlv)
    {
        return 0;
    }

    // The first byte of the 'alme_tlv' structure always contains its type
    //
    switch (*alme_tlv)
    {
        case ALME_TYPE_GET_INTF_LIST_REQUEST:
        {
            // Obtain the list of local interfaces, retrieve detailed info for
            // each of them, build a response, and send it back.
            //
            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_GET_INTF_LIST_REQUEST\n");

            send1905InterfaceListResponseALME(alme_client_id);

            break;
        }
        case ALME_TYPE_SET_INTF_PWR_STATE_REQUEST:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_SET_INTF_PWR_STATE_REQUEST\n");
            break;
        }
        case ALME_TYPE_GET_INTF_PWR_STATE_REQUEST:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_GET_INTF_PWR_STATE_REQUEST\n");
            break;
        }
        case ALME_TYPE_SET_FWD_RULE_REQUEST:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_SET_FWD_RULE_REQUEST\n");
            break;
        }
        case ALME_TYPE_GET_FWD_RULES_REQUEST:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_GET_FWD_RULES_REQUEST\n");
            break;
        }
        case ALME_TYPE_MODIFY_FWD_RULE_REQUEST:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_MODIFY_FWD_RULE_REQUEST\n");
            break;
        }
        case ALME_TYPE_REMOVE_FWD_RULE_REQUEST:
        {
            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_MODIFY_FWD_RULE_CONFIRM\n");
            break;
        }
        case ALME_TYPE_GET_METRIC_REQUEST:
        {
            // Obtain the requested metrics, build a response, and send it back.
            //
            struct getMetricRequestALME *p;

            uint8_t dummy_mac_address[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_GET_METRIC_REQUEST\n");

            p = (struct getMetricRequestALME *)alme_tlv;

            if (0 == memcmp(p->interface_address, dummy_mac_address, 6))
            {
                // Request metrics against all neighbors
                //
                send1905MetricsResponseALME(alme_client_id, NULL);
            }
            else
            {
                // Request metrics against one specific neighbor
                //
                send1905MetricsResponseALME(alme_client_id, p->interface_address);
            }

            break;
        }
        case ALME_TYPE_CUSTOM_COMMAND_REQUEST:
        {
            struct customCommandRequestALME *p;

            PLATFORM_PRINTF_DEBUG_INFO("<-- ALME_TYPE_CUSTOM_COMMAND_REQUEST\n");

            p = (struct customCommandRequestALME *)alme_tlv;

            send1905CustomCommandResponseALME(alme_client_id, p->command);

            break;
        }
        case ALME_TYPE_GET_INTF_LIST_RESPONSE:
        case ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM:
        case ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE:
        case ALME_TYPE_SET_FWD_RULE_CONFIRM:
        case ALME_TYPE_GET_FWD_RULES_RESPONSE:
        case ALME_TYPE_MODIFY_FWD_RULE_CONFIRM:
        case ALME_TYPE_REMOVE_FWD_RULE_CONFIRM:
        case ALME_TYPE_GET_METRIC_RESPONSE:
        case ALME_TYPE_CUSTOM_COMMAND_RESPONSE:
        {
            // These messages should never be receiving by an AL entity. It is
            // the AL entity the one who generates them and then sends them to
            // the HLE.
            //
            PLATFORM_PRINTF_DEBUG_WARNING("ALME RESPONSE/CONFIRM message received (type = %d). Ignoring...\n", *alme_tlv);
            break;
        }

        default:
        {
            PLATFORM_PRINTF_DEBUG_WARNING("Unknown ALME message received (type = %d). Ignoring...\n", *alme_tlv);
            break;
        }
    }

    return 1;
}

