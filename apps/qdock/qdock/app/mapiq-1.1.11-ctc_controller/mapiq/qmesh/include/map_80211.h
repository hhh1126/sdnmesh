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

#ifndef __MAP_80211_H__
#define __MAP_80211_H__

#define IEEE80211_FC0_VERSION_0         0x00

#define IEEE80211_FC0_TYPE_MASK         0x0c
#define IEEE80211_FC0_TYPE_MGT          0x00
#define IEEE80211_FC0_TYPE_CTL          0x04
#define IEEE80211_FC0_TYPE_DATA         0x08

#define IEEE80211_FC0_SUBTYPE_MASK          0xf0
#define IEEE80211_FC0_SUBTYPE_ASSOC_REQ     0x00
#define IEEE80211_FC0_SUBTYPE_ASSOC_RESP    0x10
#define IEEE80211_FC0_SUBTYPE_REASSOC_REQ   0x20
#define IEEE80211_FC0_SUBTYPE_REASSOC_RESP  0x30
#define IEEE80211_FC0_SUBTYPE_PROBE_REQ     0x40
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP    0x50
#define IEEE80211_FC0_SUBTYPE_BEACON        0x80
#define IEEE80211_FC0_SUBTYPE_DISASSOC      0xa0
#define IEEE80211_FC0_SUBTYPE_AUTH          0xb0
#define IEEE80211_FC0_SUBTYPE_DEAUTH        0xc0
#define IEEE80211_FC0_SUBTYPE_ACTION        0xd0

#define IEEE80211_FC1_DIR_MASK              0x03
#define IEEE80211_FC1_DIR_NODS              0x00	/* STA->STA */
#define IEEE80211_FC1_DIR_TODS              0x01	/* STA->AP  */
#define IEEE80211_FC1_DIR_FROMDS            0x02	/* AP ->STA */
#define IEEE80211_FC1_DIR_DSTODS            0x03	/* AP ->AP  */

/* categories */
#define IEEE80211_ACTION_CAT_RM			5	/* Radio measurement */
#define IEEE80211_ACTION_CAT_WNM        10  /* WNM */

/* RM Action field values */
#define IEEE80211_RM_RADIO_MEAS_REQ			0
#define IEEE80211_RM_RADIO_MEAS_REPORT		1

/* IEEE 802.11v - WNM Action field values */
#define	IEEE80211_WNM_BSS_TRANS_MGMT_QUERY  6
#define	IEEE80211_WNM_BSS_TRANS_MGMT_REQ    7
#define	IEEE80211_WNM_BSS_TRANS_MGMT_RESP   8

/*
* Management information element payloads.
*/
enum {
	IEEE80211_ELEMID_MEASREQ		= 38,
	IEEE80211_ELEMID_HTCAP			= 45,
	IEEE80211_ELEMID_NEIGH_REPORT   = 52,
	IEEE80211_ELEMID_RM_ENABLED		= 70,
	IEEE80211_ELEMID_EXTCAP			= 127,
	IEEE80211_ELEMID_VHTCAP			= 191,
    IEEE80211_ELEMID_VENDOR         = 221,  /* vendor private */
	IEEE80211_ELEMID_EXT			= 255,  /* Elements using the Element ID Extension field */
};

/*
* Element ID Extension
*/
enum {
	IEEE80211_ELEMID_EXT_HECAP		= 35,
};

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

/* Request mode in Trans Req */
#define IEEE80211_TRANSREQ_CANDIDATE_INCLUDED_SHIFT (0)
#define IEEE80211_TRANSREQ_ABRIDGED_SHIFT           (1)
#define IEEE80211_TRANSREQ_BSS_DISASSOC_SHIFT       (2)
#define IEEE80211_TRANSREQ_BSS_TERM_SHIFT           (3)
#define IEEE80211_TRANSREQ_ESS_DISASSOC_SHIFT       (4)

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

/* Radio Measurement */
#define IEEE80211_RM_MEASTYPE_BEACON	0x05    /* Beacon Request */

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

#define	IEEE80211_HTCAP_C_CHWIDTH40		0x02
#define IEEE80211_HTCAP_C_SHORTGI20		0x20
#define IEEE80211_HTCAP_C_SHORTGI40		0x40

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

/* B2-3 Supported channel width */
#define IEEE80211_VHTCAP_GET_CHANWIDTH(vhtcap) \
	(((vhtcap)->cap[0] & 0x0C) >> 2)

/* B5 Short GI for 80MHz support */
#define IEEE80211_VHTCAP_GET_SGI_80MHZ(vhtcap) \
	(((vhtcap)->cap[0] & 0x20) >> 5)

/* B6 Short GI for 160MHz support */
#define IEEE80211_VHTCAP_GET_SGI_160MHZ(vhtcap) \
	(((vhtcap)->cap[0] & 0x40) >> 6)

/* B11 SU Beamformer Capable */
#define IEEE80211_VHTCAP_GET_SU_BEAM_FORMER(vhtcap) \
	(((vhtcap)->cap[1] & 0x08) >> 4)

/* B19 MU Beamformer Capable */
#define IEEE80211_VHTCAP_GET_MU_BEAM_FORMER(vhtcap) \
	(((vhtcap)->cap[2] & 0x08) >> 4)

/* B30-B31 Extended NSS BW Support */
#define IEEE80211_VHTCAP_GET_EXTENDED_NSS_BW_SUPPORT(vhtcap)    \
	(((vhtcap)->cap[3] & 0xc0) >> 6)

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

/* B2-B7 Channel Width Set */
#define IEEE80211_HECAP_GET_160M_SUPPORTED(hecap) \
	((((hecap)->phy_cap[0]) >> 1) & 0x04)
#define IEEE80211_HECAP_GET_8080M_SUPPORTED(hecap) \
	((((hecap)->phy_cap[0]) >> 1) & 0x08)

#define IEEE80211_HECAP_GET_RX_MCS_NSS_80M(hecap) \
	(((hecap)->mcs_map_le80[1] << 8) | \
		((hecap)->mcs_map_le80[0]))

#define IEEE80211_HECAP_GET_TX_MCS_NSS_80M(hecap) \
	(((hecap)->mcs_map_le80[3] << 8) | \
		((hecap)->mcs_map_le80[2]))

/* B26 OFDMA RA Support */
#define IEEE80211_HECAP_GET_OFDMA_RA_SUPPORT(hecap) \
	(((hecap)->mac_cap[3] & 0x04) >> 2)

/* B31 SU Beamformer Capable */
#define IEEE80211_HECAP_GET_SU_BEAM_FORMER(hecap) \
	(((hecap)->phy_cap[4] & 0x80) >> 7)

/* B33 MU Beamformer Capable */
#define IEEE80211_HECAP_GET_MU_BEAM_FORMER(hecap) \
	(((hecap)->phy_cap[5] & 0x02) >> 1)

/* B22 Full Bandwidth UL MU-MIMO */
#define IEEE80211_HECAP_GET_FULL_BW_UL_MUMIMO(hecap) \
	(((hecap)->phy_cap[2] & 0x40) >> 6)
/* B23 Partial Bandwidth UL MU-MIMO */
#define IEEE80211_HECAP_GET_PART_BW_UL_MUMIMO(hecap) \
	(((hecap)->phy_cap[2] & 0x80) >> 7)
/* B54 Partial Bandwidth DL MU-MIMO */
#define IEEE80211_HECAP_GET_PART_BW_DL_MUMIMO(hecap) \
	(((hecap)->phy_cap[6] & 0x40) >> 6)

static inline int mapCheckHTCapabilitiesIE(uint8_t *ie)
{
    if(ie[0] == IEEE80211_ELEMID_HTCAP
            && ie[1] == IEEE80211_HTCAP_LEN - 2) {
        return 1;
    }
    return 0;
}

static inline int mapCheckVHTCapabilitiesIE(uint8_t *ie)
{
    if(ie[0] == IEEE80211_ELEMID_VHTCAP
            && ie[1] == IEEE80211_VHTCAP_LEN - 2) {
        return 1;
    }
    return 0;
}

static inline int mapCheckHECapabilitiesIE(uint8_t *ie)
{
    if(ie[0] == IEEE80211_ELEMID_EXT
            && ie[1] >= IEEE80211_HECAP_MINLEN - 2
            && ie[1] <= IEEE80211_HECAP_MAXLEN - 2
            && ie[2] == IEEE80211_ELEMID_EXT_HECAP)
        return 1;
    return 0;
}

/* RM measurement capabiltiy bits */
/* byte 0 */
#define IEEE80211_RM_LINK_REPORT_CAP            0x01
#define IEEE80211_RM_NEIGH_REPORT_CAP           0x02
#define IEEE80211_RM_BEACON_PASSIVE_REPORT_CAP  0x10
#define IEEE80211_RM_BEACON_ACTIVE_REPORT_CAP   0x20
#define IEEE80211_RM_BEACON_TABLE_REPORT_CAP    0x40
#define IEEE80211_RM_BEACON_REPORT_CAP    (IEEE80211_RM_BEACON_PASSIVE_REPORT_CAP   \
            | IEEE80211_RM_BEACON_ACTIVE_REPORT_CAP | IEEE80211_RM_BEACON_TABLE_REPORT_CAP)
/* RRM - radio resource measurement enabled capabilities element */
struct ieee80211_ie_rrm {
    uint8_t id;
    uint8_t len;
    uint8_t cap[5];
} __attribute__ ((packed));

static inline int mapCheckBeaconReportSupported(uint8_t *ie)
{
	if (!ie || ie[0] != IEEE80211_ELEMID_RM_ENABLED || ie[1] < 1)
        return 0;
    return (ie[2] & IEEE80211_RM_BEACON_REPORT_CAP);
}

#define IEEE80211_EXTCAP_BTM_BIT    19
struct ieee80211_ie_extcap {
    uint8_t id;
    uint8_t len;
    uint8_t ext_cap[8];
} __attribute__ ((packed));

static inline int mapCheckBtmSupported(uint8_t *ie)
{
    struct ieee80211_ie_extcap *extcap = (struct ieee80211_ie_extcap *)ie;
	if (!ie || extcap->id != IEEE80211_ELEMID_EXTCAP || extcap->len < IEEE80211_EXTCAP_BTM_BIT / 8 + 1)
        return 0;
    return (extcap->ext_cap[IEEE80211_EXTCAP_BTM_BIT / 8] & (1 << (IEEE80211_EXTCAP_BTM_BIT % 8)));
}

#define IEEE80211_SUBELEMID_CANDIDATE_PREFER    (3)
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

/* token is nonzero number per the Spec */
#define IEEE80211_UPDATE_TOKEN(_token)  do {    \
    (_token)++;   if (!(_token))    (_token)++; } while (0)

static inline uint8_t mapPowerLevel2RCPI(int power)
{
    if (power <= -110)
        return 0;
    if (power >= 0)
        return 220;
    return (uint8_t)((110 + power) << 1);
}

static inline int mapRCPI2PowerLevel(uint8_t rcpi)
{
    if (rcpi >= 220)
        return 0;
    return ((rcpi >> 1) - 110);
}

static inline uint8_t mapFAT2ChannelUtil(uint32_t fat)
{
    if (fat >= 1000)
        return 255;

    return (((1000 - fat) * 261) >> 10);
}

void mapBuildAPHTCapabilitiesValue(void *v, uint8_t *ie);
void mapBuildAPVHTCapabilitiesValue(void *v, uint8_t *ie);
void mapBuildAPHECapabilitiesValue(void *v, uint8_t *ie);
uint8_t mapGetBeaconMeasmode(uint8_t feature);
void mapBuildBeaconRequest(uint8_t *bssid, uint8_t mode, uint8_t token,
        void *param, uint8_t *frame, uint32_t *frame_len);
bool mapParseMeasReport(uint8_t *frame, uint32_t frame_len,
        void (*report_ie_cb)(void *, uint8_t *), void *ctx);
void mapBuildBtmRequest(uint8_t *bssid, uint8_t *sta, uint8_t token,
        uint8_t *target, uint8_t opclass, uint8_t channel,
        uint8_t mode, uint16_t disassoc, uint8_t *frame, uint32_t *frame_len);
bool mapParseBtmResponse(uint8_t *frame, uint32_t frame_len,
        uint8_t *status, uint8_t **target);

void mapTryReport80211Frame(uint8_t *frame, uint32_t frame_len);

#define IEEE80211_MAX_MGTFRAME_LEN     4096

/* MAP attributes */
#define WIFI_MAP_ATTR_EXT       6
enum {
    WIFI_MAP_BACKHAUL_STA       = (1 << 7),
    WIFI_MAP_BACKHAUL_BSS       = (1 << 6),
    WIFI_MAP_FRONTHAUL_BSS      = (1 << 5),
};

#if _HOST_IS_LITTLE_ENDIAN_ == 1
#define le_to_host16(n) ((n))
#define host_to_le16(n) ((n))
#define be_to_host16(n) bswap_16((n))
#define host_to_be16(n) (bswap_16((n)))
#define le_to_host32(n) ((n))
#define host_to_le32(n) ((n))
#define be_to_host32(n) bswap_32((n))
#define host_to_be32(n) (bswap_32((n)))
#define le_to_host64(n) ((n))
#define host_to_le64(n) ((n))
#define be_to_host64(n) bswap_64((n))
#define host_to_be64(n) (bswap_64((n)))
#elif _HOST_IS_BIG_ENDIAN_ == 1
#define le_to_host16(n) bswap_16(n)
#define host_to_le16(n) bswap_16(n)
#define be_to_host16(n) (n)
#define host_to_be16(n) (n)
#define le_to_host32(n) bswap_32(n)
#define host_to_le32(n) bswap_32(n)
#define be_to_host32(n) (n)
#define host_to_be32(n) (n)
#define le_to_host64(n) bswap_64(n)
#define host_to_le64(n) bswap_64(n)
#define be_to_host64(n) (n)
#define host_to_be64(n) (n)
#else
#error Could not determine CPU byte order
#endif

#endif
