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
 *  prplMesh Wi-Fi Multi-AP
 *  Copyright (c) 2018, prpl Foundation
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

#include <datamodel.h>
#include <platform.h>
#ifdef QDOCK
#include <map_api.h>
#include "linux/platform_qdock.h"
#include "./platform_os.h"
#endif
#include "tlv.h"
#include "1905_tlvs.h"

#include <assert.h>
#include <string.h> // memcpy
#ifdef Q_STEERING_LOGIC
#include "map_steering.h"
#endif

#define EMPTY_MAC_ADDRESS {0, 0, 0, 0, 0, 0}

struct alDevice *local_device = NULL;

struct mapPolicy map_policy;

struct registrar registrar = {
    .d = NULL,
    .is_map = false,
    .wsc = {&registrar.wsc, &registrar.wsc},
    .duplicated_controller = {&registrar.duplicated_controller, &registrar.duplicated_controller},
    .last_seen = NULL,
    .duplicated_registrar = {&registrar.duplicated_registrar, &registrar.duplicated_registrar},
    .ops = {NULL}
};

DEFINE_DLIST_HEAD(network);

/* global operating class table for channel set conversion */
static const struct opclassChanTable gb_opclass_chan[] = {
	{81, {1,2,3,4,5,6,7,8,9,10,11,12,13,0}},
	{82, {14,0}},
	{83, {1,2,3,4,5,6,7,8,9,0}},
	{84, {5,6,7,8,9,10,11,12,13,0}},
	{94, {133,137,0}},
	{95, {132,134,136,138,0}},
	{96, {131,132,133,134,135,136,137,138,0}},
	{101, {21,25,0}},
	{102, {11,13,15,17,19,0}},
	{103, {1,2,3,4,5,6,7,8,9,10,0}},
	{104, {184,192,0}},
	{105, {188,196,0}},
	{106, {191,195,0}},
	{107, {189,191,193,195,197,0}},
	{108, {188,189,190,191,192,193,194,195,196,197,0}},
	{109, {184,188,192,196,0}},
	{110, {183,184,185,186,187,188,189,0}},
	{111, {182,183,184,185,186,187,188,189,0}},
	{112, {8,12,16,0}},
	{113, {7,8,9,10,11,0}},
	{114, {6,7,8,9,10,11,0}},
	{115, {36,40,44,48,0}},
	{116, {36,44,0}},
	{117, {40,48,0}},
	{118, {52,56,60,64,0}},
	{119, {52,60,0}},
	{120, {56,64,0}},
	{121, {100,104,108,112,116,120,124,128,132,136,140,144,0}},
	{122, {100,108,116,124,132,140,0}},
	{123, {104,112,120,128,136,144,0}},
	{124, {149,153,157,161,0}},
	{125, {149,153,157,161,165,169,0}},
	{126, {149,157,0}},
	{127, {153,161,0}},
	{128, {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,0}},
	{129, {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,0}},
	{130, {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,0}},
	{180, {1,2,3,4,5,6,0}},
};

void datamodelInit(void)
{
    map_policy.metric_intval = 0;
    memset(&map_policy, 0, sizeof(struct mapPolicy));
    dlist_head_init(&map_policy.local_disallowed);
    dlist_head_init(&map_policy.btm_disallowed);
    dlist_head_init(&map_policy.blocked_clients);
}

/* 'alDevice' related functions
 */
static void localDeviceResetAllRadioInformedChan(void)
{
    struct radio *radio;
    dlist_for_each(radio, local_device->radios, l)
    {
        radio->informed_chan = 0;
    }
}

struct alDevice *alDeviceAlloc(const mac_address al_mac_addr)
{
    struct alDevice *ret = zmemalloc(sizeof(struct alDevice));
    PLATFORM_PRINTF_DEBUG_INFO("add device " MACSTR " network database\n", MAC2STR(al_mac_addr));
    dlist_add_tail(&network, &ret->l);
    memcpy(ret->al_mac_addr, al_mac_addr, sizeof(mac_address));
    dlist_head_init(&ret->interfaces);
    dlist_head_init(&ret->radios);
    ret->is_map_agent = false;
    ret->is_map_controller = false;
    return ret;
}

void alDeviceDelete(struct alDevice *alDevice)
{
    if (!alDevice)
        return;

    if (alDevice == registrar.d)
    {
        registrar.d = NULL;
        registrar.is_map = false;
        localDeviceResetAllRadioInformedChan();
        PLATFORM_PRINTF_DEBUG_INFO("Controller " MACSTR " is removed\n", MAC2STR(alDevice->al_mac_addr));
    }

    #ifdef Q_STEERING_LOGIC
    if (map_steering_config.steering_actived)
        qSteeringDeleteAllEntries(alDevice);
    #endif
    while (!dlist_empty(&alDevice->radios)) {
        struct radio *radio = container_of(dlist_get_first(&alDevice->radios), struct radio, l);
        radioDelete(radio);
    }
    // Note: here only delete those interface not belong to any radios.
    while (!dlist_empty(&alDevice->interfaces)) {
        struct interface *interface = container_of(dlist_get_first(&alDevice->interfaces), struct interface, l);
        interfaceDelete(interface);
    }
    dlist_remove(&alDevice->l);
    free(alDevice);
}

/* 'radio' related functions
 */
struct radio*   radioAlloc(struct alDevice *dev, const mac_address mac)
{
    struct radio *r = zmemalloc(sizeof(struct radio));
    memcpy(r->uid, mac, sizeof(mac_address));
    PLATFORM_PRINTF_DEBUG_DETAIL("radio " MACSTR " is add to dev(" MACSTR ")->radios list\n",
            MAC2STR(mac), MAC2STR(dev->al_mac_addr));
    r->index = -1;
    dlist_head_init(&r->unassocStaHead);
    dlist_add_tail(&dev->radios, &r->l);
    return r;
}

struct radio*   radioAllocLocal(const mac_address mac, const char *name, int index)
{
    struct radio *r = radioAlloc(local_device, mac);
    if (name)
        strncpy(r->name, name, T_RADIO_NAME_SZ - 1);
    r->index = index;
    r->configured = local_device->configured;
    return r;
}

void    radioDelete(struct radio *radio)
{
    unsigned i;
    dlist_remove(&radio->l);
    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        /* The interfaceWifi is deleted automatically when we delete the interface itself. */
        interfaceDelete(&radio->configured_bsses.data[i]->i);
    }

    radioRemoveAllUnassocSta(radio);

    PTRARRAY_CLEAR(radio->configured_bsses);
    free(radio);
}

struct interfaceWifi *radioGetFirstAPInterface(struct radio *radio)
{
    unsigned i;

    if (!radio)
        return NULL;

    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        if (interface_wifi_role_ap == ifw->role)
            return ifw;
    }

    return NULL;
}

struct radio *findRadio(const mac_address uid)
{
    struct radio *radio;
    struct alDevice *dev;
    dlist_for_each(dev, network, l)
    {
        dlist_for_each(radio, dev->radios, l)
        {
            if (memcmp(radio->uid, uid, 6) == 0)
            {
                return radio;
            }
        }
    }
    return NULL;
}

struct radio *findDeviceRadio(const struct alDevice *device, const mac_address uid)
{
    struct radio *radio;
    dlist_for_each(radio, device->radios, l)
    {
        if (memcmp(radio->uid, uid, 6) == 0)
        {
            return radio;
        }
    }
    return NULL;
}

struct radio *findOrAddDeviceRadio(struct alDevice *device, const mac_address uid)
{
    struct radio *radio;
    #ifdef Q_STEERING_LOGIC
    uint8_t new_alloced = 0;
    #endif
    radio = findDeviceRadio(device, uid);
    if (!radio)
    {
        radio = radioAlloc(device, uid);
        if (!radio)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("Alloc radio failed for alDevice " MACFMT "\n",
                    MACARG(device->al_mac_addr));
            return NULL;
        }
        #ifdef Q_STEERING_LOGIC
        new_alloced = 1;
        #endif
    }
    #ifdef Q_STEERING_LOGIC
    if (map_steering_config.steering_actived && new_alloced)
    {
        qSteeringSendApCapabilityQuery(device);
        qSteeringAddPolicyConfigReqForAssocedSTAMetric(device, uid);
    }
    #endif
    return radio;
}

struct radio *findLocalRadio(const char *name)
{
    struct radio *radio;
    dlist_for_each(radio, local_device->radios, l)
    {
        if (strncmp(radio->name, name, sizeof(radio->name)) == 0)
        {
            return radio;
        }
    }
    return NULL;
}

int radioAddInterfaceWifi(struct radio *radio, struct interfaceWifi *ifw)
{
    PTRARRAY_ADD(radio->configured_bsses, ifw);
    ifw->radio = radio;
    return 0;
}

struct interfaceWifi *radioAddLocalInterfaceWifi(struct radio *radio, mac_address uid)
{
    struct interfaceWifi *ifw = interfaceWifiAlloc(uid, local_device);
    radioAddInterfaceWifi(radio, ifw);

    return ifw;
}

struct interfaceWifi *radioFindInterfaceWifi(struct radio *radio, mac_address bssid)
{
    uint32_t i;

    if (!radio)
        return NULL;

    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        if (!memcmp(ifw->bssInfo.bssid, bssid, sizeof(mac_address)))
            return ifw;
    }

    return NULL;
}

struct interfaceWifi *radioFindInterfaceWifiBySSID(struct radio *radio, struct ssid *ssid)
{
    uint32_t i;

    if (!radio)
        return NULL;

    for (i = 0; i < radio->configured_bsses.length; i++)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
        if (!compareSSID(&ifw->bssInfo.ssid, ssid))
            return ifw;
    }

    return NULL;
}

struct radioUnassocSta *radioFindOrAddUnassocSta(struct radio *radio, const mac_address sta_mac)
{
    struct radioUnassocSta *sta;
    uint32_t counts = 0;
    struct radioUnassocSta *oldest = NULL;

    dlist_for_each(sta, radio->unassocStaHead, l)
    {
        if (!memcmp(sta->mac, sta_mac, sizeof(mac_address)))
            return sta;
        counts++;
        if (!oldest || oldest->last_ts > sta->last_ts)
            oldest = sta;
    }

    if (counts >= map_config.unassoc_sta_maxnums && oldest)
    {
        dlist_remove(&oldest->l);
        free(oldest);
    }

    sta = zmemalloc(sizeof(*sta));
    memcpy(sta->mac, sta_mac, sizeof(mac_address));
    dlist_add_tail(&radio->unassocStaHead, &sta->l);

    return sta;
}

void radioRemoveAllUnassocSta(struct radio *radio)
{
    dlist_item *item;
    while (NULL != (item = dlist_get_first(&radio->unassocStaHead)))
    {
        struct radioUnassocSta *sta = container_of(item, struct radioUnassocSta, l);
        dlist_remove(item);

        free(sta);
    }
}

void radioAddAp(struct radio *radio, struct bssInfo *bss_info)
{
    if (radio->addAP == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("No addAP callback for radio " MACSTR " to be configured with ssid %.*s\n",
                                      MAC2STR(radio->uid), bss_info->ssid.length, bss_info->ssid.ssid);
        return;
    }
    radio->addAP(radio, bss_info);
}

void radioAddSta(struct radio *radio, struct bssInfo *bss_info)
{
    if (radio->addSTA == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("No addSTA callback for radio " MACSTR " to be configured with ssid %.*s\n",
                                      MAC2STR(radio->uid), bss_info->ssid.length, bss_info->ssid.ssid);
        return;
    }
    radio->addSTA(radio, bss_info);
}

void radioRegisterHandlers(struct radio *radio, struct radioHandles *ops)
{
    if (!radio || !ops)
        return;
    memcpy(&radio->ops, ops, sizeof(*ops));
}

void interfaceTearDown(struct interface *iface)
{
    if (iface->tearDown == NULL)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("No tearDown callback for interface %s\n", iface->name);
        /* Here teaDown is NULL means that this iface is not for multi-AP,
         * Maybe it's a local configuared interface, so nothing to do*/

        return;
    }
    iface->tearDown(iface);
}


/* 'interface' related functions
 */
static struct interface * interfaceInit(struct interface *i, const mac_address addr, struct alDevice *owner)
{
    i->type = interface_type_unknown;
    memcpy(i->addr, addr, 6);
    if (owner != NULL) {
        alDeviceAddInterface(owner, i);
    }
    return i;
}

struct interface *interfaceAlloc(const mac_address addr, struct alDevice *owner)
{
    return interfaceInit(zmemalloc(sizeof(struct interface)), addr, owner);
}

void interfaceDelete(struct interface *interface)
{
    unsigned i;
    for (i = 0; i < interface->neighbors.length; i++)
    {
        interfaceRemoveNeighbor(interface, interface->neighbors.data[i]);
    }
    /* Even if the interface doesn't have an owner, removing it from the empty list doesn't hurt. */
    dlist_remove(&interface->l);

    if (interface->name)
        free((void *)interface->name);
    free(interface);
}

void interfaceAddNeighbor(struct interface *interface, struct interface *neighbor)
{
    PTRARRAY_ADD(interface->neighbors, neighbor);
    PTRARRAY_ADD(neighbor->neighbors, interface);
}

void interfaceRemoveNeighbor(struct interface *interface, struct interface *neighbor)
{
    PTRARRAY_REMOVE_ELEMENT(interface->neighbors, neighbor);
    PTRARRAY_REMOVE_ELEMENT(neighbor->neighbors, interface);
    if (neighbor->owner == NULL && neighbor->neighbors.length == 0)
    {
        /* No more references to the neighbor interface. */
        free(neighbor);
    }
}

/* 'interfaceWifi' related functions
 */
struct interfaceWifi *interfaceWifiAlloc(const mac_address addr, struct alDevice *owner)
{
    struct interfaceWifi *ifw = zmemalloc(sizeof(*ifw));
    dlist_head_init(&ifw->clients);
    interfaceInit(&ifw->i, addr, owner);
    ifw->i.type = interface_type_wifi;

    return ifw;
}

void    interfaceWifiRemove(struct interfaceWifi *ifw)
{
    dlist_item *item;
    PTRARRAY_REMOVE_ELEMENT(ifw->radio->configured_bsses, ifw);
    while (NULL != (item = dlist_get_first(&ifw->clients)))
    {
        struct staInfo *sta = container_of(item, struct staInfo, l);
        dlist_remove(item);

        free(sta);
    }

    if (ifw->steering_timer)
        PLATFORM_CANCEL_TIMEOUT(ifw->steering_timer);
    /* Clients don't need to be deleted; they are also in the interface neighbour list, so they will be deleted or unlinked
     * together with the interface. */
    interfaceDelete(&ifw->i); /* This also frees interfaceWifi itself. */
}

struct staInfo *interfaceFindStation(struct interfaceWifi *ifw, const mac_address sta_mac)
{
    struct staInfo *sta;
    dlist_for_each(sta, ifw->clients, l)
    {
        if (!memcmp(sta->mac, sta_mac, sizeof(mac_address)))
            return sta;
    }

    return NULL;
}

struct staInfo *interfaceFindOrAddStation(struct interfaceWifi *ifw, const mac_address sta_mac)
{
    struct staInfo *sta = interfaceFindStation(ifw, sta_mac);

    if (!sta)
    {
        sta = zmemalloc(sizeof(*sta));
        memcpy(sta->mac, sta_mac, sizeof(mac_address));
        dlist_add_tail(&ifw->clients, &sta->l);
    }

    return sta;
}

void interfaceRemoveStation(struct interfaceWifi *ifw, const mac_address sta_mac)
{
    struct staInfo *sta;
    dlist_for_each(sta, ifw->clients, l)
    {
        if (!memcmp(sta->mac, sta_mac, sizeof(mac_address)))
        {
            if (sta->last_assoc)
            {
                free(sta->last_assoc);
            }
            dlist_remove(&sta->l);
            free(sta);
            break;
        }
    }
}

/* 'alDevice' related functions
 */
void alDeviceAddInterface(struct alDevice *device, struct interface *interface)
{
    assert(interface->owner == NULL);
    dlist_add_tail(&device->interfaces, &interface->l);
    interface->owner = device;
}

struct alDevice *alDeviceFind(const mac_address al_mac_addr)
{
    struct alDevice *ret;
    dlist_for_each(ret, network, l)
    {
        if (memcmp(ret->al_mac_addr, al_mac_addr, 6) == 0)
            return ret;
    }
    return NULL;
}

struct alDevice *alDeviceFindFromAnyAddress(const mac_address sender_addr)
{
    struct alDevice *sender_device = alDeviceFind(sender_addr);
    if (sender_device == NULL)
    {
        struct interface *sender_interface = findDeviceInterface(sender_addr);
        if (sender_interface != NULL)
        {
            sender_device = sender_interface->owner;
        }
    }
    return sender_device;
}

struct interface *alDeviceFindInterface(const struct alDevice *device, const mac_address addr)
{
    struct interface *ret;
    dlist_for_each(ret, device->interfaces, l)
    {
        if (memcmp(ret->addr, addr, 6) == 0)
        {
            return ret;
        }
    }
    return NULL;
}

struct interface *alDeviceFindInterfaceFromInterfaceIndex(const struct alDevice *device, int index)
{
    struct interface *ret;
    dlist_for_each(ret, device->interfaces, l)
    {
        if (ret->interface_index == index)
        {
            return ret;
        }
    }
    return NULL;
}

struct interfaceWifi *alDevicefindWifiInterface(struct alDevice *device, const mac_address addr)
{
    struct interface *intf;
    dlist_for_each(intf, device->interfaces, l)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;

        if (intf->type != interface_type_wifi)
            continue;

        if (0 == memcmp(intf->addr, addr, sizeof(mac_address)))
            return ifw;
    }

    return NULL;
}

struct radioUnassocSta *alDeviceFindOrAddUnassocClient(struct alDevice *device, uint8_t opc, uint8_t ch, const mac_address mac)
{
    struct radio *r;

    dlist_for_each(r, device->radios, l)
    {
        struct radioChannel *chan = NULL;

        chan = findOpclassAndChannel(r, opc, ch);
        if (!chan)
            continue;

        if (chan->disabled)
            continue;

        return radioFindOrAddUnassocSta(r, mac);
    }

    return NULL;
}

static bool localRadioBackhaulSsidChanged(struct radio *radio, struct ssid *ssid, struct key *key)
{
    if (ssid->length != radio->backhaul_ssid.length) {
        return true;
    }
    if (memcmp(ssid->ssid, radio->backhaul_ssid.ssid, ssid->length) != 0) {
        return true;
    }
    if (key->len != radio->backhaul_key.len) {
        return true;
    }
    if (memcmp(key->key, radio->backhaul_key.key, key->len) != 0) {
        return true;
    }
    return false;
}

void localRadioUpdateBackhaulSsid(struct radio *radio, struct ssid *ssid, struct key *key, uint8_t backhaul_only)
{
    // Note: work around for prior backhaul_only bss than mixedhaul bss
    // Once get a backhaul_only bss configured and complete datamodel update,
    // we do not update backhaul info from new mixedhaul bss any more.
    if (!radio->backhaul_only_configured ||
            (radio->backhaul_only_configured && backhaul_only))
    {
        if (localRadioBackhaulSsidChanged(radio, ssid, key))
        {
            if (radio->setBackhaulSsid != NULL)
                radio->setBackhaulSsid(radio, ssid, key);

            memcpy(&radio->backhaul_ssid, ssid, sizeof(*ssid));
            copyKey(&radio->backhaul_key, key);
        }
        if (!radio->backhaul_only_configured)
            radio->backhaul_only_configured = backhaul_only;
    }
}

static void interfaceWifiSetReportPeriod(struct interfaceWifi *ifw)
{
    uint32_t period = map_policy.metric_intval;

    if (!period)
        period = map_config.ap_metrics_intval;

#ifdef REPORT_MONITOR_STATS
    IFW_SET_REPORT_PERIOD(ifw, period, map_config.assoc_sta_intval, map_config.unassoc_sta_intval);
#else
    IFW_SET_REPORT_PERIOD(ifw, period, map_config.assoc_sta_intval, INVALID_REPORT_PERIOD);
#endif
}

static void interfaceWifiResetReportPeriod(struct interfaceWifi *ifw)
{
    IFW_SET_REPORT_PERIOD(ifw, 0, 0, 0);
}

void localInterfaceWifiCreated(struct interfaceWifi *ifw)
{
    interfaceWifiSetReportPeriod(ifw);
}

void localInterfaceWifiDeleted(struct interfaceWifi *ifw)
{
    interfaceWifiResetReportPeriod(ifw);
}

static struct frame_match map_required_rxframes[] =
{
    {"BSS Transition Management Response", IEEE80211_FC0_SUBTYPE_ACTION, MAP_FRAME_RX_BY_PASS, 2, (uint8_t *)"\x0a\x08"},
    {"Radio Measurement Report", IEEE80211_FC0_SUBTYPE_ACTION, MAP_FRAME_RX_BY_PASS, 2, (uint8_t *)"\x05\x01"},
    {"Association Request", IEEE80211_FC0_SUBTYPE_ASSOC_REQ, MAP_FRAME_RX_COPY, 0, NULL},
};

static struct frame_match map_required_txframes[] =
{
    {"BSS Transition Management Request", IEEE80211_FC0_SUBTYPE_ACTION, 0, 2, (uint8_t *)"\x0a\x07"},
    {"Radio Measurement Request", IEEE80211_FC0_SUBTYPE_ACTION, 0, 2, (uint8_t *)"\x05\x00"},
};

/* Enable the BSS Transition */
static uint8_t map_required_extcap[] =       { 0x00, 0x00, 0x08 };
static uint8_t map_required_extcap_mask[] =  { 0x00, 0x00, 0x08 };
static uint8_t map_required_appies[] =
{
    /* RM Enabled Capabilities element */
	IEEE80211_ELEMID_RM_ENABLED, 5, IEEE80211_RM_NEIGH_REPORT_CAP, 0x00, 0x00, 0x00, 0x00
};
static uint8_t map_ext_ie[] = { IEEE80211_ELEMID_VENDOR, 0x07, 0x50, 0x6f, 0x9a, 0x1b, 0x06, 0x01, 0x00 };

static void interfaceWifiRegFramesAndConfigIEs(struct interfaceWifi *ifw)
{
    int i;
    uint32_t mask;
    uint8_t appie[128], val = 0;

    for (i = 0; i < ARRAY_SIZE(map_required_rxframes); i++)
        IFW_REG_MGMT_FRAME(ifw, map_required_rxframes + i, 1);
    for (i = 0; i < ARRAY_SIZE(map_required_txframes); i++)
        IFW_REG_MGMT_FRAME(ifw, map_required_txframes + i, 0);

    IFW_CONF_EXTCAP(ifw, map_required_extcap,
            map_required_extcap_mask, ARRAY_SIZE(map_required_extcap));

    mask = (1 << (IEEE80211_FC0_SUBTYPE_BEACON >> 4));
    mask |= (1 << (IEEE80211_FC0_SUBTYPE_PROBE_RESP >> 4));
    IFW_CONF_IES(ifw, mask, map_required_appies, ARRAY_SIZE(map_required_appies));

    if (ifw->bssInfo.backhaul)
        val |= WIFI_MAP_BACKHAUL_BSS;
    if (ifw->bssInfo.fronthaul)
        val |= WIFI_MAP_FRONTHAUL_BSS;
    map_ext_ie[8] = val;
    memcpy(appie, map_required_appies, ARRAY_SIZE(map_required_appies));
    memcpy(appie + ARRAY_SIZE(map_required_appies), map_ext_ie, ARRAY_SIZE(map_ext_ie));
    mask = (1 << (IEEE80211_FC0_SUBTYPE_ASSOC_RESP >> 4));
    IFW_CONF_IES(ifw, mask, appie, ARRAY_SIZE(map_required_appies) + ARRAY_SIZE(map_ext_ie));
    PLATFORM_PRINTF_DEBUG_DETAIL("interface(%s) config IEs bBSS(%u)/fBSS(%u) done\n",
            ifw->i.name, ifw->bssInfo.backhaul, ifw->bssInfo.fronthaul);
}

void localInterfaceWifiStatusChanged(struct interfaceWifi *ifw, uint32_t status)
{
    if (status == interface_power_state_on
            && ifw->role == interface_wifi_role_ap)
    {
        interfaceWifiRegFramesAndConfigIEs(ifw);
        interfaceWifiSetReportPeriod(ifw);
    }
    else if (status == interface_power_state_off
            && ifw->role == interface_wifi_role_ap)
    {
        interfaceWifiResetReportPeriod(ifw);
    }
}

void localDeviceInterfaceWifiRegFramesAndConfigIEs(void)
{
    struct interface *intf;
    dlist_for_each(intf, local_device->interfaces, l)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi ||
                intf->power_state != interface_power_state_on ||
                ifw->role != interface_wifi_role_ap)
            continue;

        interfaceWifiRegFramesAndConfigIEs(ifw);
    }
}

void localDeviceInterfaceWifiBackhaulConfig(void)
{
    struct interface *intf;
    dlist_for_each(intf, local_device->interfaces, l)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi ||
                intf->power_state != interface_power_state_on ||
                ifw->role != interface_wifi_role_ap)
            continue;

        if (ifw->bssInfo.backhaul)
        {
            uint8_t queue_id = PLATFORM_FIND_QUEUE_ID_BY_NAME(AL_EVENTS_NAME);
            PLATFORM_REGISTER_QUEUE_EVENT_NEW_1905_PACKET(queue_id, &ifw->i);
            IFW_CONF_4ADDR(ifw, true);
        }
    }
}

struct interface *findDeviceInterface(const mac_address addr)
{
    struct alDevice *alDevice;
    struct interface *ret = NULL;

    dlist_for_each(alDevice, network, l)
    {
        ret = alDeviceFindInterface(alDevice, addr);
        if (ret != NULL)
        {
            return ret;
        }
    }
    return NULL;
}

struct interface *findLocalInterface(const char *name)
{
    struct interface *ret;
    if (local_device == NULL)
    {
        return NULL;
    }
    dlist_for_each(ret, local_device->interfaces, l)
    {
        if (ret->name && strcmp(ret->name, name) == 0)
        {
            return ret;
        }
    }
    return NULL;
}

struct interfaceWifi *findLocalWifiInterface(const mac_address addr, enum interfaceWifiRole role)
{
    struct interface        *intf;

    dlist_for_each(intf, local_device->interfaces, l)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi
                || (role != interface_wifi_role_other && ifw->role != role))
            continue;

        if (0 == memcmp(intf->addr, addr, sizeof(mac_address)))
            return ifw;
    }

    return NULL;
}

struct interfaceWifi *findWifiInterfaceWithSSID(struct alDevice *al_dev, struct ssid *ssid, uint8_t band)
{
    struct interface        *intf;

    dlist_for_each(intf, al_dev->interfaces, l)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi || ifw->role != interface_wifi_role_ap
                || ifw->radio->band_supported != band)
            continue;

        if (!compareSSID(&ifw->bssInfo.ssid, ssid))
            return ifw;
    }

    return NULL;
}

struct staInfo *findWifiClient(const mac_address addr,
        struct interfaceWifi **assoc_intf, struct alDevice **assoc_dev)
{
    struct alDevice         *dev;
    dlist_for_each(dev, network, l)
    {
        struct radio *radio;
        dlist_for_each(radio, dev->radios, l)
        {
            uint32_t i;
            for (i = 0; i < radio->configured_bsses.length; i++)
            {
                struct staInfo *sta = NULL;
                struct interfaceWifi *ifw = (struct interfaceWifi *)radio->configured_bsses.data[i];
                sta = interfaceFindStation(ifw, addr);
                if (sta)
                {
                    if (assoc_intf)
                        *assoc_intf = ifw;
                    if (assoc_dev)
                        *assoc_dev = dev;
                    return sta;
                }
            }
        }
    }
    return NULL;
}

struct staInfo *findOrAddWifiClient(const mac_address addr,
        const mac_address bssid, struct interfaceWifi **assoc_intf)
{
    struct interfaceWifi    *ifw = NULL;
    struct alDevice         *dev;

    dlist_for_each(dev, network, l)
    {
        ifw = alDevicefindWifiInterface(dev, bssid);
        if (ifw)
            break;
    }

    if (!ifw)
        return NULL;

    if (assoc_intf)
        *assoc_intf = ifw;

    return interfaceFindOrAddStation(ifw, addr);
}

struct staInfo *findLocalWifiClient(const mac_address addr,
        const uint8_t *bssid, struct interfaceWifi **assoc_intf)
{
    struct staInfo          *client;
    struct interface        *intf;

    dlist_for_each(intf, local_device->interfaces, l)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi
                || ifw->role != interface_wifi_role_ap)
            continue;

        if (bssid && memcmp(ifw->bssInfo.bssid, bssid, sizeof(mac_address)))
            continue;

        dlist_for_each(client, ifw->clients, l)
        {
            if (0 == memcmp(client->mac, addr, sizeof(mac_address)))
            {
                if (assoc_intf)
                    *assoc_intf = ifw;
                return client;
            }
        }
    }

    return NULL;
}

struct radioOpclass *radioFindOrAddOpclass(struct radio *radio, uint8_t opc)
{
    int i;
    struct radioOpclass *opclass;
    for (i = 0; i < radio->opclass_nums && i < OPCLASS_MAXNUM; i++)
    {
        opclass = &radio->opclasses[i];
        if (opclass->opclass == opc)
            return opclass;
    }

    if (radio->opclass_nums >= OPCLASS_MAXNUM)
        return NULL;
    opclass = &radio->opclasses[radio->opclass_nums++];
    memset(opclass, 0, sizeof(*opclass));
    opclass->opclass = opc;

    return opclass;
}

struct radioChannel *opclassFindOrAddChannel(struct radioOpclass *opclass, uint8_t ch)
{
    int i;
    struct radioChannel *chan;
    for (i = 0; i < opclass->channel_nums && i < CHAN_MAXNUM_PER_OPCLASS; i++)
    {
        chan = &opclass->channels[i];
        if (chan->id == ch)
            return chan;
    }

    if (opclass->channel_nums >= CHAN_MAXNUM_PER_OPCLASS)
        return NULL;
    chan = &opclass->channels[opclass->channel_nums++];
    memset(chan, 0, sizeof(*chan));
    chan->id = ch;

    return chan;
}

void opclassInitChannelList(struct radioOpclass *opclass)
{
    int i;
    int array_idx = -1;

    for (i = 0; i < ARRAY_SIZE(gb_opclass_chan); i++)
    {
        if (gb_opclass_chan[i].opclass == opclass->opclass)
        {
            array_idx = i;
            break;
        }
    }

    if (array_idx < 0)
        return;

    for (i = 0; i < CHAN_MAXNUM_PER_OPCLASS && gb_opclass_chan[array_idx].chan_set[i]; i++)
    {
        opclassFindOrAddChannel(opclass, gb_opclass_chan[array_idx].chan_set[i]);
    }
}

struct radioOpclass *findOpclass(struct radio *radio, uint8_t opc)
{
    int i;
    for (i = 0; i < radio->opclass_nums && i < OPCLASS_MAXNUM; i++)
    {
        struct radioOpclass *opclass = &radio->opclasses[i];
        if (opclass->opclass == opc)
            return opclass;
    }
    return NULL;
}

struct radioChannel *findOpclassAndChannel(struct radio *radio, uint8_t opc, uint8_t ch)
{
    struct radioOpclass *opclass = findOpclass(radio, opc);
    if (opclass)
    {
        int i;
        for (i = 0; i < opclass->channel_nums && i < CHAN_MAXNUM_PER_OPCLASS; i++)
        {
            struct radioChannel *chan = &opclass->channels[i];
            if (!chan->disabled && ch == chan->id)
                return chan;
        }
    }
    return NULL;
}

struct radioUnassocSta *findLocalUnassocClientOnChannel(uint8_t *mac, uint8_t ch)
{
    struct radio        *r;

    dlist_for_each(r, local_device->radios, l)
    {
        struct radioUnassocSta *unassocSta;
        dlist_for_each(unassocSta, r->unassocStaHead, l)
        {
            if (unassocSta->channel == ch && !memcmp(unassocSta->mac, mac, sizeof(mac_address)))
                return unassocSta;
        }
    }
    return NULL;
}

struct radioUnassocSta *findUnassocClientByDevice(mac_address mac, struct alDevice *dev)
{
    struct radio *r;

    dlist_for_each(r, dev->radios, l)
    {
        struct radioUnassocSta *unassocSta;
        dlist_for_each(unassocSta, r->unassocStaHead, l)
        {
            if (!memcmp(unassocSta->mac, mac, sizeof(mac_address)))
                return unassocSta;
        }
    }
    return NULL;
}

void registrarAddWsc(struct wscRegistrarInfo *wsc)
{
    dlist_add_head(&registrar.wsc, &wsc->l);
}

struct wscRegistrarInfo *registrarUpdateWsc(struct wscRegistrarInfo *wsc)
{
    struct wscRegistrarInfo *cur_wsc;

    dlist_for_each(cur_wsc, registrar.wsc, l)
    {
        if ((wsc->rf_bands & cur_wsc->rf_bands) &&
                (!compareSSID(&wsc->bss_info.ssid, &cur_wsc->bss_info.ssid)))
        {
            if (cur_wsc->bss_info.auth_mode != wsc->bss_info.auth_mode)
            {
                cur_wsc->bss_info.auth_mode = wsc->bss_info.auth_mode;
                WSCINFO_FLAG_SET(cur_wsc, SECURITY_CHANGED);
                WSCINFO_FLAG_SET(cur_wsc, HAVE_CHANGED);
            }
            if (cur_wsc->bss_info.key.len != wsc->bss_info.key.len ||
                    (memcmp(cur_wsc->bss_info.key.key, wsc->bss_info.key.key, wsc->bss_info.key.len)))
            {
                copyKey(&cur_wsc->bss_info.key, &wsc->bss_info.key);
                WSCINFO_FLAG_SET(cur_wsc, SECURITY_CHANGED);
                WSCINFO_FLAG_SET(cur_wsc, HAVE_CHANGED);
            }
            if (cur_wsc->bss_info.fronthaul != wsc->bss_info.fronthaul)
            {
                cur_wsc->bss_info.fronthaul = wsc->bss_info.fronthaul;
                WSCINFO_FLAG_SET(cur_wsc, MTYPE_CHANGED);
                WSCINFO_FLAG_SET(cur_wsc, HAVE_CHANGED);
            }
            if (cur_wsc->bss_info.backhaul != wsc->bss_info.backhaul)
            {
                cur_wsc->bss_info.backhaul = wsc->bss_info.backhaul;
                WSCINFO_FLAG_SET(cur_wsc, MTYPE_CHANGED);
                WSCINFO_FLAG_SET(cur_wsc, HAVE_CHANGED);
            }
            WSCINFO_FLAG_SET(cur_wsc, HAVE_UPDATED);
            return cur_wsc;
        }
    }

    dlist_add_tail(&registrar.wsc, &wsc->l);
    WSCINFO_FLAG_SET(wsc, NEW_CREATED);
    WSCINFO_FLAG_SET(wsc, HAVE_UPDATED);
    return wsc;
}

bool registrarCommitWsc(void)
{
    struct wscRegistrarInfo *cur_wsc;
    struct wscRegistrarInfo *tmp_wsc;
    bool have_changed = false;

    dlist_for_each_safe(cur_wsc, tmp_wsc, registrar.wsc, l)
    {
        /* remove the wsc_info without HAVE_UPDATED flag and set have_changed*/
        if(!WSCINFO_FLAG_IS_SET(cur_wsc, HAVE_UPDATED))
        {
            dlist_remove(&cur_wsc->l);
            free(cur_wsc);
            have_changed = true;
            continue;
        }
        /* check the wsc_info with HAVE_CHANGED/NEW_CREATED flag and set have_changed*/
        if (WSCINFO_FLAG_IS_SET(cur_wsc, HAVE_CHANGED) ||
                WSCINFO_FLAG_IS_SET(cur_wsc, NEW_CREATED))
        {
            have_changed = true;
        }
        WSCINFO_FLAG_CLR_ALL(cur_wsc);
    }
    return have_changed;
}

void registrarDumpAllWsc(char *prefix)
{
    struct wscRegistrarInfo *wsc_info;

    PLATFORM_PRINTF_DEBUG_INFO("%s Dump all Wsc BSS configs\n", prefix);
    PLATFORM_PRINTF_DEBUG_INFO("bssid/ssid/auth/key/rf_modes/fBSS/bBSS/flags\n");

    dlist_for_each(wsc_info, registrar.wsc, l)
    {
        struct bssInfo *cfg = &wsc_info->bss_info;
        PLATFORM_PRINTF_DEBUG_INFO("" MACFMT ", %s, %u, %s, %u, %u, %u, 0x%x\n",
                MACARG(cfg->bssid), cfg->ssid.ssid, cfg->auth_mode,
                cfg->key.key, wsc_info->rf_bands, cfg->fronthaul, cfg->backhaul, wsc_info->flags);
    }
}

void registrarRegisterHandlers(struct registrarHandles *ops)
{
    if (!ops)
        return;
    memcpy(&registrar.ops, ops, sizeof(*ops));
}

void registrarAddDuplicantedController(struct alDevice *dev)
{
    dlist_add_tail(&registrar.duplicated_controller, &dev->l);
}

void registrarAddDuplicantedRegistrar(struct alDevice *dev)
{
    dlist_add_tail(&registrar.duplicated_registrar, &dev->l);
}

void resetCtrlerChannelPreference(struct radio *r)
{
    int i, j, ind = (r->ctrler_pref_ind + 1) & 0x01;
    for (i = 0; i < r->opclass_nums && i < OPCLASS_MAXNUM; i++)
    {
        struct radioOpclass *opclass = &r->opclasses[i];
        for (j = 0; j < opclass->channel_nums && j < CHAN_MAXNUM_PER_OPCLASS; j++)
        {
            struct radioChannel *ch = &opclass->channels[j];
            ch->ctrler_pref[ind] = 15;
            ch->ctrler_reason[ind] = 0;
        }
    }
}

int updateCtrlerChannelPreference(struct radio *r, uint8_t opc,
        uint8_t ch_num, uint8_t *chans, uint8_t value)
{
    int i, j, k, ind = (r->ctrler_pref_ind + 1) & 0x01;
    for (i = 0; i < r->opclass_nums && i < OPCLASS_MAXNUM; i++)
    {
        struct radioOpclass *opclass = &r->opclasses[i];
        if (opclass->opclass != opc)
            continue;

        /* An empty Channel List field (k=0) indicates that the indicated
         * Preference applies to all channels in the Operating Class. */
        if (!ch_num)
        {
            for (j = 0; j < opclass->channel_nums && j < CHAN_MAXNUM_PER_OPCLASS; j++)
            {
                struct radioChannel *ch = &opclass->channels[j];
                ch->ctrler_pref[ind] = (value >> CHAN_PREF_PREFERENCE_SHIFT) & CHAN_PREF_PREFERENCE_MASK;
                ch->ctrler_reason[ind] = (value >> CHAN_PREF_REASON_SHIFT) & CHAN_PREF_REASON_MASK;
            }
            return 0;
        }

        for (k = 0; k < ch_num; k++)
        {
            for (j = 0; j < opclass->channel_nums && j < CHAN_MAXNUM_PER_OPCLASS; j++)
            {
                struct radioChannel *ch = &opclass->channels[j];
                if (ch->id == chans[k]) {
                    ch->ctrler_pref[ind] = (value >> CHAN_PREF_PREFERENCE_SHIFT) & CHAN_PREF_PREFERENCE_MASK;
                    ch->ctrler_reason[ind] = (value >> CHAN_PREF_REASON_SHIFT) & CHAN_PREF_REASON_MASK;
                    break;
                }
            }

            /* channel is not belong to the opclass */
            if (j >= opclass->channel_nums || j >= CHAN_MAXNUM_PER_OPCLASS)
                return 1;
        }
    }
    return 0;
}

int updateChannelPreference(struct radio *r, uint8_t opc,
	uint8_t ch_num, uint8_t *chans, uint8_t value)
{
     int i, j, k;
     for (i = 0; i < r->opclass_nums && i < OPCLASS_MAXNUM; i++)
     {
         struct radioOpclass *opclass = &r->opclasses[i];
         if (opclass->opclass != opc)
             continue;
         for (k = 0; k < ch_num; k++)
         {
            for (j = 0; j < opclass->channel_nums && j < CHAN_MAXNUM_PER_OPCLASS; j++)
            {
                struct radioChannel *ch = &opclass->channels[j];
                if (ch->id == chans[k]) {
                    ch->pref = (value >> CHAN_PREF_PREFERENCE_SHIFT) & CHAN_PREF_PREFERENCE_MASK;
                    ch->reason = (value >> CHAN_PREF_REASON_SHIFT) & CHAN_PREF_REASON_MASK;
                }
            }
            /* channel is not belong to the opclass */
            if (j >= opclass->channel_nums || j >= CHAN_MAXNUM_PER_OPCLASS)
                return 1;
         }
     }
     return 0;
}

int updateRadioOperationRestriction(struct radio *r, uint8_t opc,
       uint8_t channel, uint8_t min_sep)
{
    int i, j;
    for (i = 0; i < r->opclass_nums && i < OPCLASS_MAXNUM; i++)
    {
        struct radioOpclass *opclass = &r->opclasses[i];
        if (opclass->opclass != opc)
            continue;

        for (j = 0; j < opclass->channel_nums && j < CHAN_MAXNUM_PER_OPCLASS; j++)
        {
            struct radioChannel *ch = &opclass->channels[j];
            if (ch->id == channel) {
                ch->disabled = 1;
                ch->min_sep = min_sep;
            }
            /* channel is not belong to the opclass */
            if (j >= opclass->channel_nums || j >= CHAN_MAXNUM_PER_OPCLASS)
                return 1;
        }
    }
    return 0;
}

static int compareBandwidth(uint8_t bw1, uint8_t bw2)
{
    uint8_t bw_value[] = {20, 40, 80, 160, 160, 5, 10};
    if (bw1 >= ARRAY_SIZE(bw_value) || bw2 >= ARRAY_SIZE(bw_value))
        return 0;
    return (bw_value[bw1] - bw_value[bw2]);
}

int checkCurrentAndGetPerfChannel(struct radio *r, int ind, struct radioOpclass **opc, struct radioChannel **chan)
{
    int i, j;
    uint8_t max_pref = 0, pref;
    struct radioOpclass *max_pref_opc = NULL;
    struct radioChannel *max_pref_ch = NULL;

    if (opc) *opc = NULL;
    if (chan) *chan = NULL;
    ind &= 0x01;

    PLATFORM_PRINTF_DEBUG_INFO("Try to find the preferable channel for "
            MACFMT "\n", MACARG(r->uid));
    for (i = 0; i < r->opclass_nums && i < OPCLASS_MAXNUM; i++)
    {
        struct radioOpclass *opclass = &r->opclasses[i];
        for (j = 0; j < opclass->channel_nums && j < CHAN_MAXNUM_PER_OPCLASS; j++)
        {
            struct radioChannel *ch = &opclass->channels[j];

            if (ch->disabled)
                continue;

            pref = ch->pref;
            if (pref > ch->ctrler_pref[ind])
                pref = ch->ctrler_pref[ind];

            /* store the better preference opclass/channel */
            if (!max_pref_ch || pref > max_pref)
            {
                max_pref = pref;
                max_pref_ch = ch;
                max_pref_opc = opclass;
            }
            /* store the channel same as current and larger bandwidth when have same preference */
            else if (pref == max_pref)
            {
                if (max_pref_ch->id != r->chan)
                {
                    if (ch->id == r->chan
                            || compareBandwidth(opclass->bw, max_pref_opc->bw) > 0)
                    {
                        max_pref_ch = ch;
                        max_pref_opc = opclass;
                    }
                }
                else if (ch->id == r->chan && compareBandwidth(opclass->bw, max_pref_opc->bw) > 0)
                {
                    max_pref_ch = ch;
                    max_pref_opc = opclass;
                }
            }
        }
    }

    /* not find the most preference channel */
    if (!max_pref || !max_pref_ch)
        return 0;

    if (opc) *opc = max_pref_opc;
    if (chan) *chan = max_pref_ch;

    if (max_pref_opc->opclass != r->opclass
            || max_pref_ch->id != r->chan)
        return 0;

    return 1;
}

struct blockedClient *findLocalWifiBlockedClient(const mac_address mac, const mac_address bssid)
{
    struct blockedClient    *client;

    dlist_for_each(client, map_policy.blocked_clients, l)
    {
        if (!memcmp(client->bssid, bssid, sizeof(mac_address))
                && !memcmp(client->mac, mac, sizeof(mac_address)))
            return client;
    }

    return NULL;
}

int compareSSID(struct ssid *ssid1, struct ssid *ssid2)
{
    if (!ssid1 || !ssid2)
        return -1;

    if (ssid1->length != ssid2->length)
        return -1;

    if (ssid1->length == 0)
        return 0;

    if (!memcmp(ssid1->ssid, ssid2->ssid, ssid1->length))
        return 0;
    return -1;
}

void copyKey(struct key *dst_key, struct key *src_key)
{
    if (src_key->len > KEY_MAX_LEN)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("The key passphrase/PSK length %d > limited 64!\n", (int)src_key->len);
        src_key->len = KEY_MAX_LEN;
    }
    memset(dst_key->key, 0, KEY_MAX_LEN);
    memcpy(dst_key->key, src_key->key, src_key->len);
    dst_key->len = src_key->len;
}

uint16_t _check_register_message_type(uint16_t type)
{
    struct frame_suscribe_ctl_t *ctl, *p;

    dlist_for_each_safe(ctl, p, map_config.frame_suscribe.rx_1905_suscribe, l){
        if (ctl->type==type)
          return ctl->flag;
    }
    return 0;
}

void syncRemoteBssRole(struct bssInfo *bssInfo, struct ssid *ssid, uint8_t radio_band)
{
    struct interfaceWifi *ifw = findWifiInterfaceWithSSID(local_device, ssid, radio_band);

    if (ifw)
    {
        bssInfo->fronthaul = ifw->bssInfo.fronthaul;
        bssInfo->backhaul= ifw->bssInfo.backhaul;
        copyKey(&bssInfo->key, &ifw->bssInfo.key);
    }
}

