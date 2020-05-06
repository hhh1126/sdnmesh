/*SH0
 * *******************************************************************************
 * **                                                                           **
 * **         Copyright (c) 2018 Quantenna Communications, Inc.                  **
 * **         All rights reserved.                                              **
 * **                                                                           **
 * *******************************************************************************
 * EH0*/

#ifndef __IEEE80211_DEF_H__
#define __IEEE80211_DEF_H__

#define	IEEE80211_FC0_VERSION_0			0x00

#define	IEEE80211_FC0_TYPE_MASK			0x0c
#define	IEEE80211_FC0_TYPE_MGT			0x00
#define	IEEE80211_FC0_TYPE_CTL			0x04
#define	IEEE80211_FC0_TYPE_DATA			0x08

#define	IEEE80211_FC0_SUBTYPE_MASK		0xf0
#define	IEEE80211_FC0_SUBTYPE_ASSOC_REQ		0x00
#define	IEEE80211_FC0_SUBTYPE_ASSOC_RESP	0x10
#define	IEEE80211_FC0_SUBTYPE_REASSOC_REQ	0x20
#define	IEEE80211_FC0_SUBTYPE_REASSOC_RESP	0x30
#define	IEEE80211_FC0_SUBTYPE_PROBE_REQ		0x40
#define	IEEE80211_FC0_SUBTYPE_PROBE_RESP	0x50
#define	IEEE80211_FC0_SUBTYPE_BEACON		0x80
#define	IEEE80211_FC0_SUBTYPE_DISASSOC		0xa0
#define	IEEE80211_FC0_SUBTYPE_AUTH		0xb0
#define	IEEE80211_FC0_SUBTYPE_DEAUTH		0xc0
#define IEEE80211_FC0_SUBTYPE_ACTION		0xd0

#define	IEEE80211_FC1_DIR_MASK			0x03
#define	IEEE80211_FC1_DIR_NODS			0x00	/* STA->STA */
#define	IEEE80211_FC1_DIR_TODS			0x01	/* STA->AP  */
#define	IEEE80211_FC1_DIR_FROMDS		0x02	/* AP ->STA */
#define	IEEE80211_FC1_DIR_DSTODS		0x03	/* AP ->AP  */

/* categories */
#define IEEE80211_ACTION_CAT_SPEC_MGMT		0	/* Spectrum MGMT */
#define IEEE80211_ACTION_CAT_QOS		1	/* qos */
#define IEEE80211_ACTION_CAT_DLS		2	/* dls */
#define IEEE80211_ACTION_CAT_BA			3	/* block ack */
#define IEEE80211_ACTION_CAT_PUBLIC		4	/* Public */
#define IEEE80211_ACTION_CAT_RM			5	/* Radio measurement */
#define IEEE80211_ACTION_CAT_FBSS		6	/* Fast BSS */
#define IEEE80211_ACTION_CAT_HT			7	/* HT */
#define IEEE80211_ACTION_CAT_SA_QUERY		8	/* SA Query */
#define IEEE80211_ACTION_CAT_PROT_DUAL_PA	9	/* Protected Dual of Public Action */
#define IEEE80211_ACTION_CAT_WNM		10	/* WNM */
#define IEEE80211_ACTION_CAT_UNPROT_WNM		11	/* Unprotected WNM */
#define IEEE80211_ACTION_CAT_TDLS		12	/* TDLS */
#define IEEE80211_ACTION_CAT_MESH		13	/* Mesh */
#define IEEE80211_ACTION_CAT_MULTIHOP		14	/* Multihop */
#define IEEE80211_ACTION_CAT_SELF_PROT		15	/* self protected */

#define IEEE80211_ACTION_CAT_VHT		21	/* VHT */
#define IEEE80211_ACTION_CAT_VEND_PROT	126	/* Protected Vendor specific Action frame */
#define IEEE80211_ACTION_CAT_VENDOR		0x7F	/* Vendor specific Action frame */

/*
* Management information element payloads.
*/
enum {
	IEEE80211_ELEMID_SSID			= 0,
	IEEE80211_ELEMID_MEASREQ		= 38,
	IEEE80211_ELEMID_SUPPCHAN		= 36,
	IEEE80211_ELEMID_HTCAP			= 45,
	IEEE80211_ELEMID_NEIGH_REPORT		= 52,
	IEEE80211_ELEMID_REG_CLASSES		= 59,
	IEEE80211_ELEMID_HTINFO			= 61,
	IEEE80211_ELEMID_RM_ENABLED		= 70,
	IEEE80211_ELEMID_INTERWORKING		= 107,
	IEEE80211_ELEMID_ADVERTISEMENT		= 108,
	IEEE80211_ELEMID_EXTCAP			= 127,
	IEEE80211_ELEMID_VHTCAP			= 191,
	IEEE80211_ELEMID_VHTOP			= 192,
	IEEE80211_ELEMID_VENDOR			= 221,  /* vendor private */
	IEEE80211_ELEMID_EXT			= 255,  /* Elements using the Element ID Extension field */
};

/*
* Element ID Extension
*/
enum {
	IEEE80211_ELEMID_EXT_HECAP		= 35,
	IEEE80211_ELEMID_EXT_HEOP		= 36,
};

/* IEEE 802.11v - WNM Action field values */
#define IEEE80211_WNM_EVENT_REQ				0
#define	IEEE80211_WNM_EVENT_REPORT			1
#define	IEEE80211_WNM_DIAGNOSTIC_REQ			2
#define	IEEE80211_WNM_DIAGNOSTIC_REPORT			3
#define	IEEE80211_WNM_LOCATION_CFG_REQ			4
#define	IEEE80211_WNM_LOCATION_CFG_RESP			5
#define	IEEE80211_WNM_BSS_TRANS_MGMT_QUERY		6
#define	IEEE80211_WNM_BSS_TRANS_MGMT_REQ		7
#define	IEEE80211_WNM_BSS_TRANS_MGMT_RESP		8
#define	IEEE80211_WNM_FMS_REQ				9
#define	IEEE80211_WNM_FMS_RESP				10
#define	IEEE80211_WNM_COLLOCATED_INTERFERENCE_REQ	11
#define	IEEE80211_WNM_COLLOCATED_INTERFERENCE_REPORT	12
#define	IEEE80211_WNM_TFS_REQ				13
#define	IEEE80211_WNM_TFS_RESP				14
#define	IEEE80211_WNM_TFS_NOTIFY			15
#define	IEEE80211_WNM_SLEEP_MODE_REQ			16
#define	IEEE80211_WNM_SLEEP_MODE_RESP			17
#define	IEEE80211_WNM_TIM_BROADCAST_REQ			18
#define	IEEE80211_WNM_TIM_BROADCAST_RESP		19
#define	IEEE80211_WNM_QOS_TRAFFIC_CAPAB_UPDATE		20
#define	IEEE80211_WNM_CHANNEL_USAGE_REQ			21
#define	IEEE80211_WNM_CHANNEL_USAGE_RESP		22
#define	IEEE80211_WNM_DMS_REQ				23
#define	IEEE80211_WNM_DMS_RESP				24
#define	IEEE80211_WNM_TIMING_MEASUREMENT_REQ		25
#define	IEEE80211_WNM_NOTIFICATION_REQ			26
#define	IEE8E0211_WNM_NOTIFICATION_RESP			27

#define IEEE80211_SSID_MAXLEN		32

#define IEEE80211_WNM_NOTIFY_ACK	0

#define IEEE80211_RM_ENABLED_LEN	7

#define IEEE80211_DELIMITER_130		130
#define IEEE80211_DELIMITER_0		0

/* RM measurement capabiltiy bits */
/* byte 0 */
#define IEEE80211_RM_LINK_REPORT_CAP		0x01
#define IEEE80211_RM_NEIGH_REPORT_CAP		0x02
#define IEEE80211_RM_BEACON_PASSIVE_REPORT_CAP	0x10
#define IEEE80211_RM_BEACON_ACTIVE_REPORT_CAP	0x20
#define IEEE80211_RM_BEACON_TABLE_REPORT_CAP	0x40

/* PUBIC Action field values */
#define IEEE80211_PUBLIC_GAS_INITIAL_REQ		10
#define IEEE80211_PUBLIC_GAS_INITIAL_RESP		11

/* RM Action field values */
#define IEEE80211_RM_RADIO_MEAS_REQ			0
#define IEEE80211_RM_RADIO_MEAS_REPORT			1
#define IEEE80211_RM_LINK_MEAS_REQ			2
#define IEEE80211_RM_LINK_MEAS_REPORT			3
#define IEEE80211_RM_NEIGH_REPORT_REQ			4
#define IEEE80211_RM_NEIGH_REPORT_RESP			5

/* Radio Measurement */
#define IEEE80211_RM_MEASTYPE_CH_LOAD	0x03    /* Channel Load Request */
#define IEEE80211_RM_MEASTYPE_NOISE	0x04    /* Noise histogram Request */
#define IEEE80211_RM_MEASTYPE_BEACON	0x05    /* Beacon Request */
#define IEEE80211_RM_MEASTYPE_FRAME	0x06    /* Frame Request */
#define IEEE80211_RM_MEASTYPE_STA	0x07    /* STA statistics Request */
#define IEEE80211_RM_MEASTYPE_LCI	0x08    /* LCI Request */
#define IEEE80211_RM_MEASTYPE_CATEGORY	0x09    /* Transmit stream/Category Request */
#define IEEE80211_RM_MEASTYPE_MUL_DIAG	0x0A    /* Multicast diagnostics request */
#define IEEE80211_RM_MEASTYPE_LOC_CIVIC	0x0B    /* Location Civic request */
#define IEEE80211_RM_MEASTYPE_LOC_ID	0x0C    /* Location Identifier request */
#define IEEE80211_RM_MEASTYPE_QTN_CCA	0xFE    /* QTN CCA extension */
#define IEEE80211_RM_MEASTYPE_PAUSE	0xFF    /* Measurement Pause Request */

/* Measurement Report Mode */
#define IEEE80211_RM_MEASMODE_LATE	(1 << 0)
#define IEEE80211_RM_MEASMODE_INCAPABLE	(1 << 1)
#define IEEE80211_RM_MEASMODE_REFUSED	(1 << 2)


/* Access network type */
#define IEEE80211_ACCESS_TYPE_PRIVATE_NONAUTH	0
#define IEEE80211_ACCESS_TYPE_PRIVATE		1
#define IEEE80211_ACCESS_TYPE_PUBLIC_CHARGEABLE	2
#define IEEE80211_ACCESS_TYPE_PUBLIC_FREE	3
#define IEEE80211_ACCESS_TYPE_PEASONAL		4
#define IEEE80211_ACCESS_TYPE_EMERGENCY		5
#define IEEE80211_ACCESS_TYPE_TEST		14
#define IEEE80211_ACCESS_TYPE_WILDCARD		15

#define IEEE80211_ADVERTISEMENT_PROTOCOL_ANQP		0
#define IEEE80211_STATUS_ADVERTISEMENT_PROTOCOL_NOTSUPPORTED	59
#define IEEE80211_STATUS_SUCCESS				0
#define IEEE80211_ANQP_INFO_ID_QUERY_LIST			256
#define IEEE80211_ANQP_INFO_ID_CAPABILITY_LIST			257
#define IEEE80211_ANQP_INFO_ID_NEIGHBOR_REPORT			272

/* Extended Capabilities bits */
#define IEEE80211_EXTCAP_BIT_BSS_TRANSITION	19
#define IEEE80211_EXTCAP_BIT_INTERWORKING	31
#define IEEE80211_EXTCAP_BIT_WNM_NOTIFICATION	46
#define IEEE80211_EXTCAP_BIT_LAST		46

static inline int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

static inline int ieee80211_get_freq_from_chan(uint8_t chan)
{
	if (chan == 14)
		return 2484;
	else if (chan < 14)
		return 2407 + chan * 5;
	else if (chan >= 182 && chan <= 196)
		return 4000 + chan * 5;
	else
		return 5000 + chan * 5;
}

#define	IEEE80211_ADDR_LEN	6		/* size of 802.11 address */
/*
 * generic definitions for IEEE 802.11 frames
 */
struct ieee80211_frame {
	uint8_t fc[2];
	uint8_t dur[2];
	uint8_t addr1[IEEE80211_ADDR_LEN];
	uint8_t addr2[IEEE80211_ADDR_LEN];
	uint8_t addr3[IEEE80211_ADDR_LEN];
	uint8_t seq[2];
	/* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
	/* see below */
} __attribute__ ((packed));

#define IEEE80211_FRAME_TYPE(_f)	((_f)->fc[0] & IEEE80211_FC0_TYPE_MASK)
#define IEEE80211_FRAME_SUBTYPE(_f)	((_f)->fc[0] & IEEE80211_FC0_SUBTYPE_MASK)

struct ieee80211_action {
	uint8_t	category;
	uint8_t	action;
} __attribute__ ((packed));

struct ieee80211_action_btm_req {
	struct ieee80211_action header;
	uint8_t		dialog_token;
	uint8_t		request_mode;
	uint16_t	disassoc_timer;
	uint8_t		validity_interval;
	uint8_t		info[0];
	/* Optional BSS termination duration */
	/* Optional session information URL */
	/* Optional BSS Transition Candidate list (neighbor report) */
} __attribute__ ((packed));

struct ieee80211_action_btm_rsp {
	struct ieee80211_action	header;
	uint8_t	dialog_token;
	uint8_t status_code;
	uint8_t bss_term_delay;
	uint8_t data[0];
	/* Optional Target BSSID */
	/* Optional BSS Transition Candidate list (neighbor report) */
} __attribute__ ((packed));

#define IEEE80211_EXTCAP_BTM		0x08
struct ieee80211_extcap_param {
	uint8_t param_id;
	uint8_t param_len;
	uint8_t ext_cap[8];
} __attribute__ ((packed));
#define IEEE80211_EXTCAP_LEN		(sizeof(struct ieee80211_extcap_param))

/*
* 802.11n HT Capability IE
*/
struct ieee80211_ie_htcap {
	uint8_t id;                  /* element ID */
	uint8_t len;                 /* length in bytes */
	uint8_t cap[2];              /* HT capabilities */
	uint8_t ampdu;               /* A-MPDU parameters */
#define IEEE80211_HTCAP_MCS_LEN		16
	uint8_t mcsset[IEEE80211_HTCAP_MCS_LEN];          /* supported MCS set */
	uint8_t extcap[2];           /* extended HT capabilities */
	uint8_t txbf[4];             /* txbf capabilities */
	uint8_t antenna;             /* antenna capabilities */
} __attribute__ ((packed));
#define IEEE80211_HTCAP_LEN		(sizeof(struct ieee80211_ie_htcap))

#define	IEEE80211_HTCAP_C_CHWIDTH40		0x0002
#define IEEE80211_HTCAP_C_SHORTGI20		0x0020
#define IEEE80211_HTCAP_C_SHORTGI40		0x0040

/* MCS Tx MCS Set Defined, B0 in set 12 */
#define IEEE80211_HTCAP_MCS_TX_DEFINED(htcap) \
	(((htcap)->mcsset[12] & 0x1))
/* MCS Tx Rx MCS Set Not Equal, B1 in set 12 */
#define IEEE80211_HTCAP_MCS_TXRX_NOT_EQUAL(htcap) \
	(((htcap)->mcsset[12] & 0x2) >> 1)
/* MCS maximum spatial streams, B2-B3 in set 12 */
#define IEEE80211_HTCAP_MCS_STREAMS(htcap) \
	(((htcap)->mcsset[12] & 0xC) >> 2)
/* MCS set value (all bits) */
#define IEEE80211_HTCAP_MCS_VALUE(htcap, _set) \
	((htcap)->mcsset[_set])


enum {
	IEEE80211_HT_MCSSET_20_40_NSS1,		/* CBW = 20/40 MHz, Nss = 1, Nes = 1, EQM/ No EQM */
	IEEE80211_HT_MCSSET_20_40_NSS2,		/* CBW = 20/40 MHz, Nss = 2, Nes = 1, EQM */
	IEEE80211_HT_MCSSET_20_40_NSS3,		/* CBW = 20/40 MHz, Nss = 3, Nes = 1, EQM */
	IEEE80211_HT_MCSSET_20_40_NSS4,		/* CBW = 20/40 MHz, Nss = 4, Nes = 1, EQM */
	IEEE80211_HT_MCSSET_20_40_UEQM1,	/* MCS 32 and UEQM MCSs 33 - 39 */
	IEEE80211_HT_MCSSET_20_40_UEQM2,	/* UEQM MCSs 40 - 47 */
	IEEE80211_HT_MCSSET_20_40_UEQM3,	/* UEQM MCSs 48 - 55 */
	IEEE80211_HT_MCSSET_20_40_UEQM4,	/* UEQM MCSs 56 - 63 */
	IEEE80211_HT_MCSSET_20_40_UEQM5,	/* UEQM MCSs 64 - 71 */
	IEEE80211_HT_MCSSET_20_40_UEQM6,	/* UEQM MCSs 72 - 76 plus 3 reserved bits */
};

/*
* 802.11n HT Information IE
*/
struct ieee80211_ie_htinfo {
	uint8_t	id;			/* element ID */
	uint8_t	len;			/* length in bytes */
	uint8_t	ctrlchannel;		/* control channel */
	uint8_t	bytes[5];		/* ht ie 5 bytes */
	uint8_t	basicmcsset[IEEE80211_HTCAP_MCS_LEN];	/* basic MCS set */
} __attribute__ ((packed));
#define IEEE80211_HTINFO_LEN		(sizeof(struct ieee80211_ie_htinfo))

#define	IEEE80211_HTINFO_CHOFF_SCN			0
#define	IEEE80211_HTINFO_CHOFF_SCA			1
#define	IEEE80211_HTINFO_CHOFF_SCB			3

#define IEEE80211_HTINFO_B1_SEC_CHAN_OFFSET		0x03
#define IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40		0x04
#define IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40_SHIFT	2

/* B0-B1, byte 1 */
#define IEEE80211_HTINFO_EXT_CHOFFSET(htie) \
	(((htie)->bytes[0] & 0x3))

/*
* 802.11ac VHT Capabilities element
*/
struct ieee80211_ie_vhtcap {
	uint8_t id;			/* element ID */
	uint8_t len;			/* length in bytes */
	uint8_t cap[4];			/* VHT capabilities info */
#define IEEE80211_VHTCAP_MCS_LEN	8
	uint8_t mcs_nss_set[IEEE80211_VHTCAP_MCS_LEN];	/* supported MSC and NSS set */
} __attribute__ ((packed));
#define IEEE80211_VHTCAP_LEN		(sizeof(struct ieee80211_ie_vhtcap))

#define IEEE80211_VHTCAP_C_CHWIDTH			0x0C
#define IEEE80211_VHTCAP_C_MU_BEAM_FORMER_CAP		0x08
#define IEEE80211_VHTCAP_C_MU_BEAM_FORMEE_CAP		0x10
#define IEEE80211_VHTCAP_C_MU_BEAM_CAP			0x18
#define IEEE80211_VHTCAP_C_MU_BEAM_CAP_SHIFT		3

/* B2-3 Supported channel width */
#define IEEE80211_VHTCAP_GET_CHANWIDTH(vhtcap) \
	(((vhtcap)->cap[0] & 0x0C) >> 2)

/* B5 Short GI for 80MHz support */
#define IEEE80211_VHTCAP_GET_SGI_80MHZ(vhtcap) \
	(((vhtcap)->cap[0] & 0x20) >> 5)

/* B6 Short GI for 160MHz support */
#define IEEE80211_VHTCAP_GET_SGI_160MHZ(vhtcap) \
	(((vhtcap)->cap[0] & 0x40) >> 6)

/* B0-B15 RX VHT-MCS MAP for Spatial streams 1-8 */
#define IEEE80211_VHTCAP_GET_RX_MCS_NSS(vhtcap) \
	(((vhtcap)->mcs_nss_set[1] << 8) | \
		((vhtcap)->mcs_nss_set[0]))

/* B32-B47 TX VHT-MCS MAP for Spatial streams 1-8 */
#define IEEE80211_VHTCAP_GET_TX_MCS_NSS(vhtcap) \
	(((vhtcap)->mcs_nss_set[5] << 8) | \
		((vhtcap)->mcs_nss_set[4]))

#define IEEE80211_VHT_MCSMAP_MASK	0xC000

/*
* 802.11ac VHT Operation element
*/
struct ieee80211_ie_vhtop {
	uint8_t id;		/* element ID */
	uint8_t len;		/* length in bytes */
	uint8_t info[3];	/* VHT Operation info */
	uint8_t bvhtmcs[2];	/* basic VHT MSC and NSS set */
} __attribute__ ((packed));
#define IEEE80211_VHTOP_LEN		(sizeof(struct ieee80211_ie_vhtop))

/* VHT Operation Information subfields */
enum ieee80211_vhtop_chanwidth {
	IEEE80211_VHTOP_CHAN_WIDTH_20_40MHZ,
	IEEE80211_VHTOP_CHAN_WIDTH_80MHZ,
	IEEE80211_VHTOP_CHAN_WIDTH_160MHZ,
	IEEE80211_VHTOP_CHAN_WIDTH_80PLUS80MHZ,
};

/* Channel Center Frequency Segment 0 */
#define IEEE80211_VHTOP_GET_CENTERFREQ0(vhtop) \
	(vhtop)->info[1]

/* Channel Center Frequency Segment 1 */
#define IEEE80211_VHTOP_GET_CENTERFREQ1(vhtop) \
	(vhtop)->info[2]

/*
* 802.11ax HE Capabilities element
*/
struct ieee80211_ie_hecap {
	uint8_t id;			/* Element ID */
	uint8_t len;			/* Length in bytes */
	uint8_t id_ext;			/* Element ID extension */
	uint8_t mac_cap[6];		/* HE MAC capabilities info */
	uint8_t phy_cap[11];		/* HE PHY capabilities info */
	uint8_t mcs_map_le80[4];	/* TX RX HE-MCS Map <=80MHz */
//      uint8_t mcs_map_160[4];		/* TX RX HE-MCS Map 160MHz(optional) */
//      uint8_t mcs_map_80p80[4];	/* TX RX HE-MCS Map 80+80MHz(optional) */
//      uint8_t ppe_thres[0];		/* PPE Thresholds(optional)(variable) */
} __packed;
#define IEEE80211_HECAP_MINLEN		(sizeof(struct ieee80211_ie_hecap))
#define IEEE80211_HECAP_MAXLEN		(sizeof(struct ieee80211_ie_hecap) + 4 + 4 + (7 + 4 * 6 * 8 + 7) / 8)

/*
* 802.11ax HE Operation Element
*/
struct ieee80211_ie_heop {
	uint8_t id;			/* Element ID */
	uint8_t len;			/* length in bytes */
	uint8_t id_ext;			/* Element ID Extension */
	uint8_t params[3];		/* HE Operation Parameters */
	uint8_t bsscolor_info[1];	/* BSS Color Information */
	uint8_t basic_mcs_nss[2];	/* Basic HE MCS and NSS Set */
//	uint8_t vhtop_info[3];		/* VHT Operation Information(optional) */
//	uint8_t heop_maxbssid[1];	/* Max Co-Located BSSID Indicator(optional) */
} __attribute__ ((packed));
#define IEEE80211_HEOP_MINLEN		(sizeof(struct ieee80211_ie_heop))
#define IEEE80211_HEOP_MAXLEN		(sizeof(struct ieee80211_ie_heop) + 3 + 1)

#define FIRST_OPERATING_2G_CHAN		1
#define LAST_OPERATING_2G_CHAN		14
#define FIRST_OPERATING_4G_CHAN		183
#define LAST_OPERATING_4G_CHAN		196
#define FIRST_OPERATING_5G_CHAN		36
#define LAST_OPERATING_5G_CHAN		169

#define START_FREQ_2GBAND	2407
#define START_FREQ_4GBAND	4000
#define START_FREQ_5GBAND	5000
#define CHAN_SPACE		5

/* Request mode in Trans Req */
#define IEEE80211_TRANSREQ_CANDIDATE_INCLUDED_SHIFT	(0)
#define IEEE80211_TRANSREQ_ABRIDGED_SHIFT		(1)
#define IEEE80211_TRANSREQ_BSS_DISASSOC_SHIFT		(2)
#define IEEE80211_TRANSREQ_BSS_TERM_SHIFT		(3)
#define IEEE80211_TRANSREQ_ESS_DISASSOC_SHIFT		(4)

/* BSSID Information field */
#define IEEE80211_BSSIDINFO_REACHABILITY_SHIFT	(0)
#define IEEE80211_BSSIDINFO_SECURITY_SHIFT	(2)
#define IEEE80211_BSSIDINFO_KEY_SCOPE_SHIFT	(3)
#define IEEE80211_BSSIDINFO_SPECTRUM_SHIFT	(4)
#define IEEE80211_BSSIDINFO_QOS_SHIFT		(5)
#define IEEE80211_BSSIDINFO_APSD_SHIFT		(6)
#define IEEE80211_BSSIDINFO_RADIO_MEAS_SHIFT	(7)
#define IEEE80211_BSSIDINFO_DELAYED_BA_SHIFT	(8)
#define IEEE80211_BSSIDINFO_IMM_BA_SHIFT	(9)
#define IEEE80211_BSSIDINFO_MOBILITY_SHIFT	(10)
#define IEEE80211_BSSIDINFO_HT_SHIFT		(11)
#define IEEE80211_BSSIDINFO_VHT_SHIFT		(12)

static inline int check_vht_operation_ie(uint8_t *ie)
{
	if(ie[0] == IEEE80211_ELEMID_VHTOP
		&& ie[1] == IEEE80211_VHTOP_LEN - 2) {
		return 1;
	}
	return 0;
}

static inline int check_ht_operation_ie(uint8_t *ie)
{
	if(ie[0] == IEEE80211_ELEMID_HTINFO
		&& ie[1] == IEEE80211_HTINFO_LEN - 2) {
		return 1;
	}
	return 0;
}

static inline int check_he_operation_ie(uint8_t *ie)
{
	if(ie[0] == IEEE80211_ELEMID_EXT
		&& ie[1] >= IEEE80211_HEOP_MINLEN - 2
		&& ie[1] <= IEEE80211_HEOP_MAXLEN - 2
		&& ie[2] == IEEE80211_ELEMID_EXT_HEOP)
		return 1;
	return 0;
}

static inline int check_vht_capabilities_ie(uint8_t *ie)
{
	if(ie[0] == IEEE80211_ELEMID_VHTCAP
		&& ie[1] == IEEE80211_VHTCAP_LEN - 2) {
		return 1;
	}
	return 0;
}

static inline int check_ht_capabilities_ie(uint8_t *ie)
{
	if(ie[0] == IEEE80211_ELEMID_HTCAP
		&& ie[1] == IEEE80211_HTCAP_LEN - 2) {
		return 1;
	}
	return 0;
}

static inline int check_he_capabilities_ie(uint8_t *ie)
{
	if(ie[0] == IEEE80211_ELEMID_EXT
		&& ie[1] >= IEEE80211_HECAP_MINLEN - 2
		&& ie[1] <= IEEE80211_HECAP_MAXLEN - 2
		&& ie[2] == IEEE80211_ELEMID_EXT_HECAP)
		return 1;
	return 0;
}

static inline uint8_t get_bss_txss_from_vht_capabilities(uint8_t *ie)
{
	struct ieee80211_ie_vhtcap *vhtcap
		= (struct ieee80211_ie_vhtcap *)ie;
	uint16_t mcsmap;
	uint8_t nss = 8;

	if (!ie || !check_vht_capabilities_ie(ie))
		return 0;

	mcsmap = (uint16_t)IEEE80211_VHTCAP_GET_TX_MCS_NSS(vhtcap);

	while ((nss > 1) && ((mcsmap & IEEE80211_VHT_MCSMAP_MASK)
			== IEEE80211_VHT_MCSMAP_MASK)) {
		nss--;
		mcsmap <<= 2;
	};
	return nss;
}

static inline uint8_t get_bss_txss_from_ht_capabilities(uint8_t *ie)
{
	struct ieee80211_ie_htcap *htcap
		= (struct ieee80211_ie_htcap *)ie;
	uint8_t nss = 4;

	if (!ie || !check_ht_capabilities_ie(ie))
		return 0;

	if (IEEE80211_HTCAP_MCS_TXRX_NOT_EQUAL(htcap)
		&& IEEE80211_HTCAP_MCS_TX_DEFINED(htcap)) {
		nss = IEEE80211_HTCAP_MCS_STREAMS(htcap) + 1;
	} else {
		while (nss > 1
			&& 0 == IEEE80211_HTCAP_MCS_VALUE(htcap, nss - 1)) {
			nss--;
		}
	}

	return nss;
}

/* RM - radio measurement request */
struct ieee80211_action_radio_measure_request {
	struct ieee80211_action	header;
	uint8_t am_token;
	uint16_t am_rep_num;
	uint8_t am_data[0];
} __attribute__ ((packed));

/* RM - radio measurement report */
struct ieee80211_action_radio_measure_report {
	struct ieee80211_action header;
	uint8_t am_token;
	uint8_t am_data[0];
} __attribute__ ((packed));

struct ieee80211_ie_measure_comm {
	uint8_t id;             /* IEEE80211_ELEMID_MEASREQ = 38 */
	uint8_t len;		/* 14 for known types */
	uint8_t token;		/* Non-zero number for diff. measurement reqs. */
	uint8_t mode;		/* bits: 1 enable, 2 req, 3 report, 0,4-7 reserved */
	uint8_t type;		/* basic = 0, cca = 1, rpi histogram = 2 */
	uint8_t data[0];	/* variable format according to meas_type */
} __attribute__ ((packed));

/* Measurement Mode definitions for Beacon request */
#define IEEE80211_BEACONREQ_MEASMODE_PASSIVE		0
#define IEEE80211_BEACONREQ_MEASMODE_ACTIVE		1
#define IEEE80211_BEACONREQ_MEASMODE_TABLE		2
struct ieee80211_ie_measreq_beacon {
	uint8_t operating_class;
	uint8_t channel_num;
	uint16_t random_interval_tu;
	uint16_t duration_tu;
	uint8_t measure_mode;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint8_t data[0];
} __attribute__ ((packed));

/* Optional subelement IDs for Beacon request */
#define IEEE80211_BEACONREQ_SUBELEMID_SSID		0
#define IEEE80211_BEACONREQ_SUBELEMID_DETAIL		2
#define IEEE80211_BEACONREQ_SUBELEMID_REQUEST		10
#define IEEE80211_BEACONREQ_SUBELEMID_CHAN_REPORT	51
#define IEEE80211_BEACONREQ_SUBELEMID_LAST_BEACON_REPORT_IND	164

/* Reporting Detail values */
#define IEEE80211_REPORTING_DETAIL_LEVEL0	0

struct ieee80211_ie_measrep_beacon {
	uint8_t operating_class;
	uint8_t channel_num;
	uint8_t start_time[8];
	uint16_t duration_tu;
	uint8_t reported_frame_info;
	uint8_t rcpi;
	uint8_t rsni;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint8_t antenna_id;
	uint8_t parent_tsf[4];
	uint8_t data[0];
} __attribute__ ((packed));

struct ieee80211_ie_neighbor_report {
	uint8_t id;
	uint8_t len;
	uint8_t bssid[IEEE80211_ADDR_LEN];
	uint32_t bssid_info;
	uint8_t operating_class;
	uint8_t channel;
	uint8_t phy_type;
	uint8_t data[0];
} __attribute__ ((packed));

struct ieee80211_action_btm_query {
	struct ieee80211_action header;
	uint8_t dialog_token;
	uint8_t reason;
	uint8_t data[0]; /* optional prefered BSS candidate list */
} __attribute__ ((packed));

struct ieee80211_action_notify_req {
	struct ieee80211_action header;
	uint8_t dialog_token;
	uint8_t type;
	uint8_t data[0];
} __attribute__ ((packed));

struct ieee80211_action_notify_rsp {
	struct ieee80211_action header;
	uint8_t dialog_token;
	uint8_t status;
} __attribute__ ((packed));

struct ieee80211_action_rm_neighbor_report_request {
	struct ieee80211_action header;
	uint8_t token;
	uint8_t data[0];
} __attribute__ ((packed));

struct ieee80211_action_rm_neighbor_report_response {
	struct ieee80211_action header;
	uint8_t token;
	uint8_t data[0];
} __attribute__ ((packed));

static inline int ieee80211_mcs2rate(int mcs, int mode, int sgi, int vht)
{
#define N(a)    (sizeof(a[0]) / sizeof(a[0][0][0]))
	uint32_t rates[2][2][77] = {{{

			/* LGI & 20 MHz */
			/* MCS0-MC31 (4 streams) are supported */
			13, 26, 39, 52, 78, 104, 117, 130,
			26, 52, 78, 104, 156, 208, 234, 260,
			39, 78, 117, 156, 234, 312, 351, 390,
			52, 104, 156, 208, 312, 416, 468, 520,

			12, 78, 104, 130, 117, 156, 195, 104, /* UEQM */
			130, 130, 156, 182, 182, 208, 156, 195,
			195, 234, 273, 273, 312, 130, 156, 182,
			156, 182, 208, 234, 208, 234, 260, 260,
			286, 195, 234, 273, 234, 273, 312, 351,
			312, 351, 390, 390, 429},
		{

			/* LGI & 40 MHz */
			/* MCS0-MCS31 (4 streams) are supported */
			27, 54, 81, 108, 162, 216, 243, 270,
			54, 108, 162, 216, 324, 432, 486, 540,
			81, 162, 243, 324, 486, 648, 729, 810,
			108, 216, 324, 432, 648, 864, 972, 1080,

			12, 162, 216, 270, 243, 324, 405, 216, /* UEQM */
			270, 270, 324, 378, 378, 432, 324, 405,
			405, 486, 567, 567, 648, 270, 324, 378,
			324, 378, 432, 486, 432, 486, 540, 540,
			594, 405, 486, 567, 486, 567, 648, 729,
			648, 729, 810, 810, 891}},
		{{

			/* SGI & 20 MHz */
			/* MCS0-MC31 (4 streams) are supported */
			14, 28, 42, 56, 86, 114, 130, 144,
			28, 56, 86, 114, 172, 230, 260, 288,
			42, 86, 130, 172, 260, 346, 390, 432,
			56, 114, 172, 230, 346, 462, 520, 576,

			12, 86, 114, 144, 130, 172, 216, 86,	/* UEQM */
			114, 114, 172, 202, 202, 230, 172, 216,
			216, 260, 302, 302, 346, 144, 172, 202,
			172, 202, 230, 260, 230, 260, 288, 288,
			316, 216, 260, 302, 260, 302, 346, 390,
			346, 390, 432, 432, 476},
		{

			/* SGI * 40 MHz */
			/* MCS0-MC31 (4 streams) are supported */
			30, 60, 90, 120, 180, 240, 270, 300,
			60, 120, 180, 240, 360, 480, 540, 600,
			90, 180, 270, 360, 540, 720, 810, 900,
			120, 240, 360, 480, 720, 960, 1080,1200,

			12, 180, 240, 300, 270, 360, 450, 240, /* UEQM */
			300, 300, 360, 420, 420, 480, 360, 450,
			450, 540, 630, 630, 720, 300, 360, 420,
			360, 420, 480, 540, 480, 540, 600, 600,
			660, 450, 540, 630, 540, 630, 720, 810,
			720, 810, 900, 900, 990}}
		};

	uint32_t vht_rates[2][4][10] = {
		{{
			/* LGI & 80 MHz */
			/* MCS0-MC9 */
			59, 117, 176, 234, 351, 468, 527, 585, 702, 780
		},
		{
			/* LGI & 160/80+80 MHz */
			/* MCS0-MC9 */
			117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560
		},
		{
			/* LGI & 20 MHz */
			/* MCS0-MC9 */
			13, 26, 39, 52, 78, 104, 117, 130, 156, 173
		},
		{
			/* LGI & 40 MHz */
			/* MCS0-MC9 */
			27, 54, 81, 108, 162, 216, 243, 270, 324, 360
		}},
		{{
			/* SGI & 80 MHz */
			/* MCS0-MC9 */
			65, 130, 195, 260, 390, 520, 585, 650, 780, 867
		},
		{
			/* SGI & 160 MHz */
			/* MCS0-MC9 */
			130, 260, 390, 520, 780, 1040, 1170, 1300, 1560, 1733
		},
		{
			/* SGI & 20 MHz */
			/* MCS0-MC9 */
			14, 29, 43, 58, 87, 116, 130, 144, 173, 192
		},
		{
			/* SGI & 40 MHz */
			/* MCS0-MC9 */
			30, 60, 90, 120, 180, 240, 270, 300, 360, 400
		}}};
	if (vht) {
		if(mcs >= 10)
			return -1;

		return (vht_rates[sgi][mode][mcs]);
	} else {
		if(mcs >= N(rates))
			return -1;

		return (rates[sgi][mode][mcs]);
	}

#undef N
}

#define IEEE80211_GET_UINT16(_frm)	((_frm)[0] | ((_frm)[1] << 8))
#define IEEE80211_SET_UINT16(_frm, _val)	do { (_frm)[0] = (_val) & 0xff;	\
							(_frm)[1] = ((_val) >> 8) & 0xff; } while (0)
#define IEEE80211_SET_UINT32(_frm, _val)	do { (_frm)[0] = (_val) & 0xff;	\
							(_frm)[1] = ((_val) >> 8) & 0xff;	\
							(_frm)[2] = ((_val) >> 16) & 0xff;	\
							(_frm)[3] = ((_val) >> 24) & 0xff; } while (0)

#define IEEE80211_SSID_MAXLEN	32

#define IEEE80211_MS_TO_TU(x)           (((x) * 1000) / 1024)

#endif
