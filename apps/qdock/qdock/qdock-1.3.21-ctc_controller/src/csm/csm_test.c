/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2016 -2018 Quantenna Communications, Inc.          **
**         All rights reserved.                                              **
**                                                                           **
*******************************************************************************
EH0*/
#include "csm.h"

static inline uint16_t csm_mbo_reg_frm_len(uint16_t len)
{
	uint16_t payload_len = 0;

	/* reg frm tlv first 3Bytes */
	payload_len = CSM_IE_LEN(len + 1 + 1 + 1);

	return (sizeof(tlv_t) + payload_len);
}

static inline csmmsg_t *csm_mbo_reg_frm_alloc(uint8_t *bssid, uint32_t len)
{
	return csm_new_msg(CMD_REGISTER_FRAME, CSM_RPE_VER(6), CSM_CODING_TLV,
			bssid, sizeof(csmmsgh_t) + len);
}

static uint32_t csm_mbo_reg_frame_build_tlv(void *ctx, uint8_t *bss_mac,
	uint8_t *frm, uint32_t space, uint8_t txrx, uint8_t subtype,
	uint8_t drv_process, uint8_t match_len, uint8_t *match)
{
	tlv_t *tlv = (tlv_t *)frm;
	uint16_t len = match_len + 1 + 1 + 1; /* reg frm tlv first 3Bytes */

	if (!match && match_len)
		match_len = 0;
	if (space < sizeof(*tlv) + CSM_IE_LEN(len)) {
		CSM_WARNING(" no space to add frame");
		return 0;
	}

	tlv->value[0] = subtype;
	tlv->value[1] = drv_process;
	tlv->value[2] = match_len;
	if (match_len)
		memcpy(tlv->value + 3, match, match_len);

	if (txrx == 1)
		tlv->type = host_to_le16(TLVTYPE_FRAME_TX_SEL);
	else
		tlv->type = host_to_le16(TLVTYPE_FRAME_RX_SEL);

	tlv->len = host_to_le16(len);

	return CSM_IE_LEN(len) + sizeof(*tlv);
}

int csm_mbo_reg_frm_cmd(void *ctx, uint8_t *bss_mac, uint8_t txrx, uint8_t subtype,
	uint8_t drv_process, uint8_t match_len, uint8_t *match)
{
	csmmsg_t *msg;
	csmmsgh_t *h;
	uint8_t *pos;
	uint16_t msg_len;

	if (!ctx || !bss_mac)
		return -1;
	if (!match && match_len)
		match_len = 0;

	msg_len = csm_mbo_reg_frm_len(match_len);
	msg = csm_mbo_reg_frm_alloc(bss_mac, msg_len);
	if (msg) {
		h = (csmmsgh_t *) csm_get_msg_body(msg);
		pos = h->payload;
		pos += csm_mbo_reg_frame_build_tlv(ctx, bss_mac,
			pos, CSM_RPE_MAX_LEN - (pos - (uint8_t *)msg),
			txrx, subtype, drv_process, match_len, match);

		csm_push_cmd(ctx, msg);
	}

	return 0;
}

static inline uint16_t csm_mbo_send_frm_len(uint16_t frm_len)
{
	uint16_t tlv_len, payload_len = 0;

	tlv_len = sizeof(tlv_t) + csm_tlv_vlen(TLVTYPE_CHANNEL_BAND);
	payload_len = sizeof(tlv_t) +  CSM_IE_LEN(frm_len);

	return tlv_len + payload_len;
}

static inline csmmsg_t *csm_mbo_send_frm_alloc(uint8_t *bssid, uint16_t len)
{
	return csm_new_msg(CMD_FRAME, CSM_RPE_VER(6), CSM_CODING_TLV,
			bssid, sizeof(csmmsgh_t) + len);
}

static uint32_t csm_mbo_send_frm_build_tlv(void *ctx, uint8_t *bssid, uint8_t *start,
	uint8_t channel, uint16_t frm_len, uint8_t *frm)
{
	uint8_t *pos = start;
	uint8_t tmp[4];

	if (!frm && frm_len)
		frm_len = 0;

	memset(tmp, 0, 4);
	tmp[0] = channel;
	pos += csm_encap_tlv(pos, TLVTYPE_CHANNEL_BAND, tmp, 4);
	if (frm_len)
		pos += csm_encap_tlv(pos, TLVTYPE_FRAME, frm, frm_len);

	return (pos - start);
}

int csm_mbo_send_frame_cmd(void *ctx, uint8_t *bssid, uint8_t channel,
	uint16_t frm_len, uint8_t *frm)
{
	csmmsg_t *msg;
	csmmsgh_t *h;
	uint8_t *pos;
	uint16_t msg_len;

	if (!ctx || !bssid)
		return -1;

	msg_len = csm_mbo_send_frm_len(frm_len);
	msg = csm_mbo_send_frm_alloc(bssid, msg_len);
	if (msg) {
		h = (csmmsgh_t *) csm_get_msg_body(msg);
		pos = h->payload;
		pos += csm_mbo_send_frm_build_tlv(ctx, bssid,
			pos, channel, frm_len, frm);

		csm_push_cmd(ctx, msg);
	}
	return 0;
}
