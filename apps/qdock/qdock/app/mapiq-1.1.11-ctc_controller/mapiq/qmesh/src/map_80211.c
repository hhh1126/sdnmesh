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

#include "al_datamodel.h"
#include "datamodel.h"
#include "al_send.h"
#include "1905_tlvs.h"
#include "al_utils.h"
#include "map_80211.h"
#include "ubus_map.h"

void mapBuildAPHTCapabilitiesValue(void *v, uint8_t *ie)
{
    struct radioHtcap *map_htcapa = (struct radioHtcap *)v;
    struct ieee80211_ie_htcap *htcap = (struct ieee80211_ie_htcap *)ie;
    uint8_t txss, rxss = 4, capa = 0;

    if (!map_htcapa || !ie || !mapCheckHTCapabilitiesIE(ie))
        return;

    while (rxss > 1
            && 0 == IEEE80211_HTCAP_MCS_VALUE(htcap, rxss - 1))
        rxss--;
    rxss-- ;

    if (IEEE80211_HTCAP_MCS_TXRX_NOT_EQUAL(htcap)
            && IEEE80211_HTCAP_MCS_TX_DEFINED(htcap))
        txss = IEEE80211_HTCAP_MCS_STREAMS(htcap);
    else
        txss = rxss;

    capa |= txss << HT_CAPABILITIES_TXSS_SHIFT;
    capa |= rxss << HT_CAPABILITIES_RXSS_SHIFT;
    if (htcap->cap[0] & IEEE80211_HTCAP_C_SHORTGI20)
        capa |= HT_CAPABILITIES_SGI_20M;
    if (htcap->cap[0] & IEEE80211_HTCAP_C_SHORTGI40)
        capa |= HT_CAPABILITIES_SGI_40M;
    if (htcap->cap[0] & IEEE80211_HTCAP_C_CHWIDTH40)
        capa |= HT_CAPABILITIES_BW_40M;

    map_htcapa->capabilities = capa;
    map_htcapa->valid = true;
}

static uint8_t _getNssCodeFromMCS(uint16_t mcs)
{
	uint8_t nss = 8;
	while ((nss > 1) && ((mcs & IEEE80211_VHT_MCSMAP_MASK)
			== IEEE80211_VHT_MCSMAP_MASK)) {
		nss--;
		mcs <<= 2;
	}
    nss--;
    return nss;
}

void mapBuildAPVHTCapabilitiesValue(void *v, uint8_t *ie)
{
    struct radioVhtcap *map_vhtcapa = (struct radioVhtcap *)v;
    struct ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)ie;
    uint8_t txss, rxss, capa1 = 0, capa2 = 0, bw, ext_bw;

	if (!map_vhtcapa || !ie || !mapCheckVHTCapabilitiesIE(ie))
		return;

    map_vhtcapa->tx_mcs = IEEE80211_VHTCAP_GET_TX_MCS_NSS(vhtcap);
    map_vhtcapa->rx_mcs = IEEE80211_VHTCAP_GET_RX_MCS_NSS(vhtcap);

    txss = _getNssCodeFromMCS(map_vhtcapa->tx_mcs);
    rxss = _getNssCodeFromMCS(map_vhtcapa->rx_mcs);
    capa1 |= txss << VHT_CAPABILITIES_TXSS_SHIFT;
    capa1 |= rxss << VHT_CAPABILITIES_RXSS_SHIFT;
    if (IEEE80211_VHTCAP_GET_SGI_80MHZ(vhtcap))
        capa1 |= VHT_CAPABILITIES_SGI_80M;
    if (IEEE80211_VHTCAP_GET_SGI_160MHZ(vhtcap))
        capa1 |= VHT_CAPABILITIES_SGI_160M;

    bw = IEEE80211_VHTCAP_GET_CHANWIDTH(vhtcap);
    ext_bw = IEEE80211_VHTCAP_GET_EXTENDED_NSS_BW_SUPPORT(vhtcap);
    if (0 == ext_bw && 0x02 == bw)
        capa2 |= VHT_CAPABILITIES_BW_8080M;
    if (0 == ext_bw && bw > 0x00 && bw <= 0x02)
        capa2 |= VHT_CAPABILITIES_BW_160M;
    if (IEEE80211_VHTCAP_GET_SU_BEAM_FORMER(vhtcap))
        capa2 |= VHT_CAPABILITIES_SU_BF;
    if (IEEE80211_VHTCAP_GET_MU_BEAM_FORMER(vhtcap))
        capa2 |= VHT_CAPABILITIES_MU_BF;

    map_vhtcapa->capabilities1 = capa1;
    map_vhtcapa->capabilities2 = capa2;
    map_vhtcapa->valid = true;
}

void mapBuildAPHECapabilitiesValue(void *v, uint8_t *ie)
{
    struct radioHecap *map_hecapa = (struct radioHecap *)v;
    struct ieee80211_ie_hecap *hecap = (struct ieee80211_ie_hecap *)ie;
    uint8_t mcs_ext_len = 0, txss, rxss, capa1 = 0, capa2 = 0;
    uint8_t *ext_mcs = ie + sizeof(*hecap);

	if (!map_hecapa || !ie || !mapCheckHECapabilitiesIE(ie))
		return;

    if (IEEE80211_HECAP_GET_160M_SUPPORTED(hecap)) {
        capa1 |= HE_CAPABILITIES_BW_160M;
        mcs_ext_len += 4;
    }
    if (IEEE80211_HECAP_GET_8080M_SUPPORTED(hecap)) {
        capa1 |= HE_CAPABILITIES_BW_8080M;
        mcs_ext_len += 4;
    }

    if (hecap->len < IEEE80211_HECAP_MINLEN + mcs_ext_len - 2)
        return;

    map_hecapa->mcs[0] = mcs_ext_len  + 4;
    memcpy(map_hecapa->mcs + 1, hecap->mcs_map_le80, 4);
    memcpy(map_hecapa->mcs + 1 + 4, ext_mcs, mcs_ext_len);

    txss = _getNssCodeFromMCS((uint16_t)(IEEE80211_HECAP_GET_TX_MCS_NSS_80M(hecap)));
    rxss = _getNssCodeFromMCS((uint16_t)(IEEE80211_HECAP_GET_RX_MCS_NSS_80M(hecap)));
    capa1 |= txss << HE_CAPABILITIES_TXSS_SHIFT;
    capa1 |= rxss << HE_CAPABILITIES_RXSS_SHIFT;

    if (IEEE80211_HECAP_GET_SU_BEAM_FORMER(hecap))
        capa2 |= HE_CAPABILITIES_SU_BF;
    if (IEEE80211_HECAP_GET_MU_BEAM_FORMER(hecap))
        capa2 |= HE_CAPABILITIES_MU_BF;
    /* FIXME: correct? */
    if (IEEE80211_HECAP_GET_FULL_BW_UL_MUMIMO(hecap))
        capa2 |= HE_CAPABILITIES_UL_MUMIMO;
    if (IEEE80211_HECAP_GET_PART_BW_UL_MUMIMO(hecap))
        capa2 |= HE_CAPABILITIES_UL_MUMIMO_OFMDA;
    if (IEEE80211_HECAP_GET_PART_BW_DL_MUMIMO(hecap))
        capa2 |= HE_CAPABILITIES_DL_MUMIMO_OFMDA;
    capa2 |= HE_CAPABILITIES_UL_OFMDA;
    capa2 |= HE_CAPABILITIES_DL_OFMDA;

    map_hecapa->capabilities1 = capa1;
    map_hecapa->capabilities2 = capa2;
    map_hecapa->valid = true;
}

static void mapSetup80211Head(struct ieee80211_frame *wh,
	uint8_t type, uint8_t subtype, uint8_t *bssid,
	uint8_t *da, uint8_t *sa)
{
	wh->fc[0] = IEEE80211_FC0_VERSION_0 | type | subtype;
	wh->fc[1] = IEEE80211_FC1_DIR_NODS;
	memcpy(wh->addr1, da, IEEE80211_ADDR_LEN);
	memcpy(wh->addr2, sa, IEEE80211_ADDR_LEN);
	memcpy(wh->addr3, bssid, IEEE80211_ADDR_LEN);
	wh->dur[0] = 0;
	wh->dur[1] = 0;
}

static void mapSetup80211Action(struct ieee80211_action *act,
	uint8_t category, uint8_t action)
{
	act->category = category;
	act->action = action;
}

uint8_t mapGetBeaconMeasmode(uint8_t feature)
{
    if (feature & IEEE80211_RM_BEACON_ACTIVE_REPORT_CAP)
        return IEEE80211_BEACONREQ_MEASMODE_ACTIVE;
    if (feature & IEEE80211_RM_BEACON_PASSIVE_REPORT_CAP)
        return IEEE80211_BEACONREQ_MEASMODE_PASSIVE;
    if (feature & IEEE80211_RM_BEACON_TABLE_REPORT_CAP)
        return IEEE80211_BEACONREQ_MEASMODE_TABLE;
    return IEEE80211_BEACONREQ_MEASMODE_TABLE;
}

void mapBuildBeaconRequest(uint8_t *bssid, uint8_t mode, uint8_t token,
        void *param, uint8_t *frame, uint32_t *frame_len)
{
	struct beaconMetricQueryTLV *beaconQuery = (struct beaconMetricQueryTLV *)param;
	struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
	struct ieee80211_action_radio_measure_request *meas_req =
		(struct ieee80211_action_radio_measure_request *)(wh + 1);
	struct ieee80211_ie_measure_comm *meas_comm =
		(struct ieee80211_ie_measure_comm *)meas_req->am_data;
	struct ieee80211_ie_measreq_beacon *beacon_req =
		(struct ieee80211_ie_measreq_beacon *)meas_comm->data;
    uint32_t min_required = sizeof(*wh) + sizeof(*meas_req)
            + sizeof(*meas_comm) + sizeof(*beacon_req) + 3;
    uint8_t *pos, *efrm;

    if (!bssid || !beaconQuery || !frame
            || !frame_len || *frame_len < min_required)
        return;

    efrm = frame + *frame_len;

    mapSetup80211Head(wh, IEEE80211_FC0_TYPE_MGT,
		IEEE80211_FC0_SUBTYPE_ACTION, bssid, beaconQuery->sta, bssid);
	mapSetup80211Action(&meas_req->header, IEEE80211_ACTION_CAT_RM,
		IEEE80211_RM_RADIO_MEAS_REQ);

    meas_req->am_token = token;
	meas_req->am_rep_num = host_to_le16(0);

	meas_comm->id = IEEE80211_ELEMID_MEASREQ;
	meas_comm->token = token;
	meas_comm->mode = 0;
	meas_comm->type = IEEE80211_RM_MEASTYPE_BEACON;

	beacon_req->operating_class = beaconQuery->opclass;
	beacon_req->channel_num = beaconQuery->channel;
	beacon_req->random_interval_tu = host_to_le16(0);
	beacon_req->duration_tu = host_to_le16(10);

	beacon_req->measure_mode = mode;
	memcpy(beacon_req->bssid, beaconQuery->bssid, IEEE80211_ADDR_LEN);

	pos = beacon_req->data;
	/* Reporting Detail subelement */
	*pos++ = IEEE80211_BEACONREQ_SUBELEMID_DETAIL;
	*pos++ = 1;
	*pos++ = beaconQuery->detail;

    /* SSID subelement */
    if (beaconQuery->ssid[0])
    {
        if (efrm - pos < beaconQuery->ssid[0] + 2)
            goto _fail;
        *pos++ = IEEE80211_BEACONREQ_SUBELEMID_SSID;
        memcpy(pos, &beaconQuery->ssid[0], beaconQuery->ssid[0] + 1);
        pos += beaconQuery->ssid[0] + 1;
    }

    if (beaconQuery->channel == 255)
    {
        struct _channelReport *reportItem;
        dlist_for_each(reportItem, beaconQuery->tlv.s.h.children[0], s.h.l)
        {
            if (efrm - pos < reportItem->ch_report[0] + 2)
                goto _fail;
            /* AP Channel Report subelement */
            *pos++ = IEEE80211_BEACONREQ_SUBELEMID_CHAN_REPORT;
            memcpy(pos, &reportItem->ch_report[0], reportItem->ch_report[0] + 1);
            pos += reportItem->ch_report[0] + 1;
        }
    }

    if (beaconQuery->detail)
    {
        struct _elemIE *ieItem;
        dlist_for_each(ieItem, beaconQuery->tlv.s.h.children[1], s.h.l)
        {
            if (efrm - pos < ieItem->ie[1] + 2)
                goto _fail;
            /* Request subelement */
            memcpy(pos, &ieItem->ie[0], ieItem->ie[1] + 2);
            pos += ieItem->ie[1] + 2;
        }
    }

	meas_comm->len = pos - meas_req->am_data - 2;

    *frame_len = pos - frame;
    return;

_fail:
    *frame_len = 0;
}

bool mapParseMeasReport(uint8_t *frame, uint32_t frame_len,
        void (*report_ie_cb)(void *, uint8_t *), void *ctx)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
    struct ieee80211_action_radio_measure_report *report =
		(struct ieee80211_action_radio_measure_report *)(wh + 1);
    uint32_t min_required = sizeof(*wh) + sizeof(*report);
	uint8_t *frm, *efrm = frame + frame_len;

	if (!frame || !frame_len || !report_ie_cb || frame_len < min_required)
		return 0;

	frm = report->am_data;
	while (frm + 2 <= efrm)
    {
		if (frm + 2 + frm[1] > efrm)
			return 0;

		report_ie_cb(ctx, frm);

		frm += (2 + frm[1]);
	}

	if (frm != efrm)
        return 0;
    return 1;
}

void mapBuildBtmRequest(uint8_t *bssid, uint8_t *sta, uint8_t token,
        uint8_t *target, uint8_t opclass, uint8_t channel,
        uint8_t mode, uint16_t disassoc, uint8_t *frame, uint32_t *frame_len)
{
    struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
    struct ieee80211_action_btm_req *btm_req = (struct ieee80211_action_btm_req *)(wh + 1);
    struct ieee80211_ie_neighbor_report *neigh_report =
        (struct ieee80211_ie_neighbor_report *)btm_req->info;
    uint32_t min_required = sizeof(*wh) + sizeof(*btm_req) + sizeof(*neigh_report) + 3;
    uint8_t *pos;
    struct staInfo *client;

    if (!bssid || !sta || !target || !frame
        || !frame_len || *frame_len < min_required)
        return;

    client = findLocalWifiClient(sta, bssid, NULL);
    if (!client)
        return;

    mapSetup80211Head(wh, IEEE80211_FC0_TYPE_MGT,
        IEEE80211_FC0_SUBTYPE_ACTION, bssid, sta, bssid);
    mapSetup80211Action(&btm_req->header, IEEE80211_ACTION_CAT_WNM,
        IEEE80211_WNM_BSS_TRANS_MGMT_REQ);

    btm_req->dialog_token = token;
    btm_req->request_mode = mode;
    btm_req->disassoc_timer = host_to_le16(disassoc);
    btm_req->validity_interval = 0xff;

    neigh_report->id = IEEE80211_ELEMID_NEIGH_REPORT;
    neigh_report->len = sizeof(*neigh_report) + 3 - 2;
    memcpy(neigh_report->bssid, target, IEEE80211_ADDR_LEN);
    /* FIXME: how to build the bssid information? */
    neigh_report->bssid_info = host_to_le32(0xffffffff);
    neigh_report->operating_class = opclass;
    neigh_report->channel = channel;
    /* FIXME: how to build the phy type? */
    neigh_report->phy_type = 9;

    pos = neigh_report->data;
    /* add bss transition candidate preference */
    *pos++ = IEEE80211_SUBELEMID_CANDIDATE_PREFER;
    *pos++ = 1;
    *pos++ = 255;

    *frame_len = pos - frame;
}

bool mapParseBtmResponse(uint8_t *frame, uint32_t frame_len,
        uint8_t *status, uint8_t **target)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
    struct ieee80211_action_btm_rsp *rsp =
        (struct ieee80211_action_btm_rsp *)(wh + 1);
    uint32_t min_required = sizeof(*wh) + sizeof(*rsp);

	if (!frame || !frame_len || frame_len < min_required)
		return 0;

    if (status)
        *status = rsp->status_code;
    if (target)
    {
        *target = NULL;
        if (frame_len >= min_required + IEEE80211_ADDR_LEN)
            *target = rsp->data;
    }

    return 1;
}

static void mapTryReport80211RadioMeasReportFrame(uint8_t *frame, uint32_t frame_len)
{
    struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
    struct ieee80211_action_radio_measure_report *act = (struct ieee80211_action_radio_measure_report *)(wh + 1);
    struct staInfo *client;

    if (frame_len < sizeof(*wh) + sizeof(*act))
        return;

    client = findLocalWifiClient(wh->addr2, wh->addr1, NULL);
    if (!client)
        return;

    if (client->beacon_req.token != act->am_token)
        return;

    send1905BeaconMetricsResponse(frame, frame_len,
        DMinterfaceIndexToInterfaceName(client->beacon_req.intf_index),
        getNextMid(), client->beacon_req.source);
}

static void mapTryReport80211BTMResponseFrame(uint8_t *frame, uint32_t frame_len)
{
    struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
    struct ieee80211_action_btm_rsp *act = (struct ieee80211_action_btm_rsp *)(wh + 1);
    struct staInfo *client;

    if (frame_len < sizeof(*wh) + sizeof(*act))
        return;

    client = findLocalWifiClient(wh->addr2, wh->addr1, NULL);
    if (!client)
        return;

    if (client->btm_req.token != act->dialog_token)
        return;

    send1905ClientSteeringBTMReport(frame, frame_len,
        DMinterfaceIndexToInterfaceName(client->btm_req.intf_index),
        getNextMid(), client->btm_req.source);

    mapapi_event_receive_btm_response(wh->addr2, wh->addr1, frame, frame_len);
}

static void mapTryReport80211ActionFrame(uint8_t *frame, uint32_t frame_len)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
    struct ieee80211_action *act = (struct ieee80211_action *)(wh + 1);

    if (frame_len < sizeof(*wh) + sizeof(*act))
        return;

    switch (act->category)
    {
        case IEEE80211_ACTION_CAT_RM:
        {
            switch (act->action)
            {
                case IEEE80211_RM_RADIO_MEAS_REPORT:
                    mapTryReport80211RadioMeasReportFrame(frame, frame_len);
                    break;

                default:
                    break;
            }
            break;
        }

        case IEEE80211_ACTION_CAT_WNM:
        {
            switch (act->action)
            {
                case IEEE80211_WNM_BSS_TRANS_MGMT_RESP:
                    mapTryReport80211BTMResponseFrame(frame, frame_len);
                    break;

                default:
                    break;
            }
            break;
        }

        default:
            break;
    }
}

void mapTryReport80211Frame(uint8_t *frame, uint32_t frame_len)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;

    if (!frame || frame_len < sizeof(*wh))
        return;

    if (IEEE80211_FC0_TYPE_MGT != (wh->fc[0] & IEEE80211_FC0_TYPE_MASK))
        return;

    switch (wh->fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_ACTION:
            mapTryReport80211ActionFrame(frame, frame_len);
            break;

        default:
            break;
    }
}

static uint8_t map_ext_ie[] = { IEEE80211_ELEMID_VENDOR, 0x07, 0x50, 0x6f, 0x9a, 0x1b, 0x06, 0x01, 0x00 };

void mapParseAssocFrame(struct staInfo *client, uint8_t *frame, uint32_t frame_len)
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)frame;
    uint8_t *frm = (uint8_t *)(wh + 1), *efrm = frame + frame_len;
    struct staIEs *ies = &client->ies;
    uint8_t *rm_enabled = NULL;
    uint8_t *extcap = NULL;

    memset(ies, 0, sizeof(*ies));

    if (!frame || frame_len < sizeof(*wh))
        return;

    if (IEEE80211_FC0_TYPE_MGT != (wh->fc[0] & IEEE80211_FC0_TYPE_MASK))
        return;

    if (IEEE80211_FC0_SUBTYPE_ASSOC_REQ != (wh->fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
        && IEEE80211_FC0_SUBTYPE_REASSOC_REQ != (wh->fc[0] & IEEE80211_FC0_SUBTYPE_MASK))
        return;

    frm += (2 + 2);
    if (IEEE80211_FC0_SUBTYPE_REASSOC_REQ == (wh->fc[0] & IEEE80211_FC0_SUBTYPE_MASK))
        frm += 6;

    while (frm + 2 <= efrm)
    {
        switch (frm[0])
        {
            case IEEE80211_ELEMID_RM_ENABLED:
                rm_enabled = frm;
                break;
            case IEEE80211_ELEMID_EXTCAP:
                extcap = frm;
                break;
            case IEEE80211_ELEMID_VENDOR:
                if (!memcmp(frm, map_ext_ie, 8))
                    client->bSTA = !!(frm[8] & WIFI_MAP_BACKHAUL_STA);
                break;
        }
        frm += frm[1] + 2;
    }
    if (frm != efrm)
        return;

    ies->rm_enabled = rm_enabled;
    ies->extcap = extcap;
}

void updateAssocFrame(struct staInfo *client, uint8_t *frame, uint32_t frame_len)
{
    if (!client)
        return;

    if (client->last_assoc)
        free(client->last_assoc);

    client->last_assoc = NULL;
    client->last_assoc_len = 0;
    if (frame && frame_len)
    {
        client->last_assoc = (uint8_t *)malloc(frame_len);
        memcpy(client->last_assoc, frame, frame_len);
        client->last_assoc_len = frame_len;
    }

    mapParseAssocFrame(client, client->last_assoc, client->last_assoc_len);
}
