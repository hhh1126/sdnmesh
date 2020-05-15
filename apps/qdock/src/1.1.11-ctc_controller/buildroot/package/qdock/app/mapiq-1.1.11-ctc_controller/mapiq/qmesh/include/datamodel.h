/*
 *  Copyright (c) 2018-2020, Semiconductor Components Industries, LLC
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

#ifndef DATAMODEL_H
#define DATAMODEL_H

#include "tlv.h" // ssid
#include "map_80211.h"
#include "ptrarray.h"

#include <stdbool.h> // bool
#include <stddef.h>  // size_t
#include <net/if.h>

/** @file
 *
 * Multi-AP/1905.1a Data Model.
 *
 * This file defines the structures that comprise the data model used for Multi-AP / IEEE 1905.1a, and the functions
 * to manipulate it.
 */

/** @brief Authentication modes.
 *
 * These are only used in WPS exchanges, so values are taken from there.
 *
 * We don't support deprecated shared and WPA modes, so also their constants are not defined.
 * Note: auth_mode follows Table 32 – Authentication Types in <Wi-Fi Simple Configuration Technical Specification v2.0>
 */
enum auth_mode {
    auth_mode_open    = 0x0001, /**< Open mode, no authentication. */
    auth_mode_wpapsk  = 0x0002, /**< WPA-Personal-mode deprecated */
    auth_mode_shared  = 0x0004, /**< Shared-mode deprecated */
    auth_mode_wpa     = 0x0008, /**< WPA-mode deprecated */
    auth_mode_wpa2    = 0x0010, /**< WPA2-Enterprise. */
    auth_mode_wpa2psk = 0x0020, /**< WPA2-Personal. */
};

struct key {
    #define KEY_MAX_LEN 64 /**< @brief maximum length of key. */
    uint8_t  len;          /**< byte length of key. */
    uint8_t  key[KEY_MAX_LEN]; /**< key content. */
};

struct staLinkMetrics {
    uint32_t last_ts;       /**< Last updated timestamp */
    uint32_t rate_dl;       /**< Estimated MAC Data Rate in downlink (in Mb/s). */
    uint32_t rate_ul;       /**< Estimated MAC Data Rate in uplink (in Mb/s). */
    uint8_t rcpi_ul;        /**< Uplink RCPI for STA. */
};

struct staTrafficMetrics {
    uint32_t tx_packets;    /**< Raw counter of the number of bytes sent to the associated STA */
    uint32_t tx_bytes;      /**< Raw counter of number of bytes received from the associated STA */
    uint32_t rx_packets;    /**< Raw counter of the number of packets successfully sent to the associated STA. */
    uint32_t rx_bytes;      /**< Raw counter of the number of packets received from the associated STA */
    uint32_t tx_errors;     /**< Raw counter of the number of packets received from the associated STA during the measurement window */
    uint32_t rx_errors;     /**< Raw counter of the number of packets which were received in error from the associated STA */
    uint32_t tx_tries;      /**< Raw counter of the number of packets sent with the retry flag set to the associated STA */
};

struct staIEs {
    uint8_t *rm_enabled;
    uint8_t *extcap;
};

struct staActionContext {
    uint8_t     token;      /**< last sent Action frame token */
    uint32_t	intf_index;  /**< the request is from which interface index */
    mac_address source;     /**< the request is from which source */
};

/** @brief Definition of a STA. */
struct staInfo {
    dlist_item  l;                  /**< Membership of the wifiInterface::clients */
    mac_address mac;                /**< MAC address of the STA. */
    bool        bSTA;               /**< Is this backhaul STA. */

    struct staLinkMetrics       link_metrics;       /**< Client Link metrics */
    struct staTrafficMetrics    traffic_metrics;    /**< Client Traffic metrics */
    int8_t                      dir;                /** Internal used for recording the dirction of crossing the threshold */
    uint32_t    last_assoc_ts;      /**< Last associated timestamps */
    uint32_t    last_assoc_len;     /**< The length of the most recently received (Re)Association Request frame from this client */
    uint8_t     *last_assoc;        /**< The most recently received (Re)Association Request frame from this client */
    uint8_t     last_result_code;   /**< The most recently result code for the client capability report message */
    struct staIEs ies;              /**< The parsed IEs from the lasted assoc */
    uint8_t     token;              /**< Frame's token */
    struct staActionContext beacon_req; /**< Beacon Request context */
    struct staActionContext btm_req;    /**< Beacon Request context */
    uint8_t     *beacon_report_ie[255];
    uint32_t    beacon_report_ie_num;
};

struct bssEspi {
    uint8_t valid;          /**< Valid */
    uint8_t format;         /**< Data Format (see Table 9-261 of Ref. IEEE802.11-2016) */
    uint8_t window;         /**< BA Window Size (see Table 9-262 of Ref. IEEE802.11-2016) */
    uint8_t est_airtime;    /**< Estimated Air Time Fraction (see  §9.4.2.174 of Ref. IEEE802.11-2016) */
    uint8_t duration;       /**< Data PPDU Duration target (see  §9.4.2.174 of Ref. IEEE802.11-2016) */
};

struct bssMetrics {
    uint8_t         ch_util;        /**< Channel Utilization as measured by the radio operating the BSS */
    struct bssEspi  espis[4];       /**< Estimated Service Parameters Information field */
};

/** @brief Definition of a BSS. */
struct bssInfo {
    mac_address bssid;          /**< BSSID (MAC address) of the BSS configured by this WSC exchange. */
    struct ssid ssid;           /**< SSID used on this BSS. */
    char    opclass[4];         /**< Operating class string pattern, 8x, 11x, 12x */
    uint16_t bintval;           /**< Beacon Interval */
    enum auth_mode auth_mode;   /**< Authentication mode. Encryption is implied (none for open, CCMP for WPA2). */
    uint8_t encryp;             /**< Encryption mode. */
    struct key key;             /**< Key used on this BSS, valid only for WPA2*/
    bool teardown;				/**< Is this BSS tear down */
    bool backhaul;              /**< Is backhaul AP */
    bool fronthaul;             /**< Is fronthaul AP */
    bool backhaul_sta;          /**< Is backhaul STA */
    struct bssMetrics metrics;  /**< AP metrics */
};

#define INTWIFI_CONFIG_FLAG_SSID     (1<<0)
#define INTWIFI_CONFIG_FLAG_AUTH     (1<<1)
#define INTWIFI_CONFIG_FLAG_ENCRYP   (1<<2)
#define INTWIFI_CONFIG_FLAG_KEY      (1<<3)
#define INTWIFI_CONFIG_FLAG_OPCLASS  (1<<4)
#define INTWIFI_CONFIG_FLAG_CHAN     (1<<5)
#define INTWIFI_CONFIG_FLAG_DISABLE  (1<<6)
#define INTWIFI_CONFIG_FLAG_WPS      (1<<7)
#define INTWIFI_CONFIG_FLAG_BH_CFG   (1<<8)
#define INTWIFI_CONFIG_FLAG_EXTCAP   (1<<9)
#define INTWIFI_CONFIG_FLAG_APPIES   (1<<10)
#define INTWIFI_CONFIG_FLAG_4ADDR    (1<<11)
#define INTWIFI_CONFIG_FLAG_BH_CLR   (1<<12)

/** @brief interface wifi config info. */
struct intfwifiConfigInfo {
    struct ssid ssid;           /**< SSID used on this BSS. */
    uint8_t auth;               /**< Authentication mode. */
    uint8_t encryp;             /**< Encryption mode. */
    struct key key;             /**< Key used on this BSS, valid only for WPA2 */
    uint8_t     opclass;        /**< Operating class work on*/
    uint8_t     chan;           /**< Operating channel work on*/
    bool        disable;        /**< Whether disable this interface wifi, 0 for enable, 1 for disable. */
    bool        wps;            /**< wps enable, 0 for disable, 1 for enable. */
    bool        enable_4addr;   /**< 4 addr mode enable, 0 for disable, 1 for enable. */

    struct ssid bh_ssid;
    uint8_t bh_auth;            /**< Authentication mode. */
    uint8_t bh_encryp;          /**< Encryption mode. */
    struct key  bh_key;         /**< key used for backhaul BSS*/

    uint32_t extcap_len;
    uint8_t *extcap;
    uint8_t *extcap_mask;

    uint32_t ies_mask;
    uint32_t ies_len;
    uint8_t *ies;
};

/** @brief WSC device information. */
struct wscDeviceData {
    char device_name      [33]; /**< Device Name (0..32 octets encoded in UTF-8). */
    char manufacturer_name[65]; /**< Manufacturer (0..64 octets encoded in UTF-8). */
    char model_name       [65]; /**< Model Name (0..32 octets encoded in UTF-8). */
    char model_number     [65]; /**< Model Number (0..32 octets encoded in UTF-8). */
    char serial_number    [65]; /**< Serial Number (0..32 octets encoded in UTF-8). */
    /* @todo device type is missing */
    uint8_t uuid          [16]; /**< UUID (16 octets). */
};

enum interfaceType {
    interface_type_unknown = -1, /**< Interface was created without further information. */
    interface_type_ethernet = 0, /**< Wired ethernet interface. */
    interface_type_wifi = 1,     /**< 802.11 wireless interface. */
    interface_type_other = 255,  /**< Other interfaces types, not supported by this data model. */
};

enum interfacePowerState {
    interface_power_state_on = 0,
    interface_power_state_save = 1,
    interface_power_state_off = 2,
};

/** @brief Definition of an interface
 *
 * The interface stores some information, but mostly the information is retrieved through callback functions.
 *
 * An interface may be created either because it belongs to an alDevice, or because it is a neighbor of an interface
 * that belongs to an alDevice.
 *
 * When an interface is added as the neighbor of another interface, the inverse relationship is added as well.
 *
 * When an interface is removed as the neighbor of another interface, and the interface does not belong to an alDevice,
 * it is destroyed.
 */
struct interface
{
    dlist_item l; /**< @brief Membership of the owner's alDevice::interfaces */

    /** @brief Interface name, e.g. eth0.
     *
     * Only set for local interfaces. Other device interface has this as NULL.
     */
    const char  *name;

/** @brief Interface index. */
    int interface_index;

    /** @brief Interface address. */
    mac_address addr;

    /** @brief Interface type. This indicates the subclass of the interface struct. */
    enum interfaceType type;

    /** @brief If the interface belongs to a 1905.1/EasyMesh device, this points to the owning device. */
    struct alDevice *owner;

    /** @brief IEEE 1905.1a Media Type, as per "IEEE Std 1905.1-2013, Table 6-12". */
    uint16_t media_type;

    /** @brief IEEE 1905.1a Media-specific Information, as per "IEEE Std 1905.1-2013, Table 6-12 and 6-13". */
    uint8_t media_specific_info[16];
    uint8_t media_specific_info_length; /**< @brief Valid length of @a media_specific_info. */

    enum interfacePowerState power_state;

    /** @brief Info to control discovery messages sent to this interface.
     *
     * These are only valid for interfaces that are direct neighbors of the local device.
     *
     * @todo these don't belong here, because a single neighbor interface may be linked with multiple local interfaces.
     *
     * @{
     */
    uint32_t              last_topology_discovery_ts;
    uint32_t              last_bridge_discovery_ts;
    /** @} */

    /** @brief Some interfaces may have additional information that can be used in some 1905.1a messages.
     *
     * @todo actually use these instead of going through interfaceData.
     */
    struct wscDeviceData *device_data;

    /** @brief Some additional information for receive 1905 packages. */
    struct linux_interface_info *interface_info;

    /** @brief Neighbour interfaces. */
    PTRARRAY(struct interface *) neighbors;

    /** @brief Operations on the interface.
     *
     * Implementing these as function pointers allows each interface to have a different driver.
     *
     * Note that the handlers should in general not update the data model. Instead, the data model should be updated by driver
     * events that detect a change in the data model.
     * @{
     */

    /** @brief Handler to bring this interface down. */
    bool (*tearDown)(struct interface *interface);

    /** @} */
};

enum interfaceWifiRole {
    interface_wifi_role_ap = 0, /**< AP role */
    interface_wifi_role_sta = 0x4, /**< STA role */
    interface_wifi_role_p2p_cli = 0x8, /**< P2P CLI role */
    interface_wifi_role_p2p_go = 0x9, /**< P2P GO role */
    interface_wifi_role_ad_pcp = 0xa, /**< AD PCP role */
    interface_wifi_role_other = 0xf, /**< Other role, not supported by this data model */
};

/** @brief Wi-Fi interface.
 *
 * Subclass of ::interface for IEEE 802.11 BSSIDs.
 *
 * Wi-Fi interfaces are navigable both through the ::radio and through the ::alDevice structures. The ::alDevice
 * structure is the ::hlist_item parent.
 */
struct interfaceWifi {
    struct interface i;

    enum interfaceWifiRole role;

    /** @brief BSS info for this Wifi interface.
     *
     * Valid for AP and STA interfaces.
     */
    struct bssInfo bssInfo;

    /** @brief Radio on which this interface is active. Must not be NULL. */
    struct radio *radio;

    /** @brief Channel in use
     *
     *  This have to be a valid channel who refers to channel::id
     */
    struct radioChannel *channel;

    /** @brief Clients connected to this BSS.
     *
     * Only valid if this is an AP.
     */
    dlist_head clients;

    /** @brief Internal used for STA mode wifi interface, time wait for the roaming result. */
    void *steering_timer;

    /** @brief Internal used for STA mode wifi interface to record the last steering target from controller. */
    mac_address last_steering_target;
};

struct radioHtcap {
    bool valid;
    uint8_t capabilities;        /**< @brief HT Capabilities. */
};

struct radioVhtcap {
    bool valid;
    uint16_t tx_mcs;             /**< @brief Supported VHT Tx MCS. */
    uint16_t rx_mcs;             /**< @brief Supported VHT Rx MCS. */
    uint8_t capabilities1;       /**< @brief VHT Capabilities. */
    uint8_t capabilities2;       /**< @brief VHT Capabilities. */
};

struct radioHecap {
    bool valid;
    /* mcs's max length ref to Multi-AP Specification Version 1.0
    Table 15. AP HE Capabilities TLV format */
    uint8_t mcs[1+12];           /**< @brief Supported HE MCS.*/
    uint8_t capabilities1;       /**< @brief HE Capabilities. */
    uint8_t capabilities2;       /**< @brief HE Capabilities. */
};

/** @brief Wi-Fi radio supported channels.
 */
struct radioChannel {
    uint8_t     id;         /**< Channel id (0..255) */
    uint32_t    freq;       /**< Frequency */
    bool        disabled;   /**< Is this channel disabled(static non-operable) ? */
    uint8_t     pref;       /**< The preference value of the channel */
    uint8_t     reason;     /**< The reason of the preference */
    uint8_t     min_sep;    /**< Minimum frequency separation (in multiples of 10 MHz) that this radio would require when operating on this channel */

    uint8_t     ctrler_pref[2];     /**< Preference from controller */
    uint8_t     ctrler_reason[2];   /**< Reason of preference from controller */
};

#define T_RADIO_NAME_SZ     IFNAMSIZ
#define T_RADIO_RX           0
#define T_RADIO_TX           1

/** @brief Wi-Fi Operation Class supported.
 *
 */
struct radioOpclass {
    uint8_t                 opclass;        /**< Operating class id */
    enum {
        BAND_WIDTH_20 = 0,
        BAND_WIDTH_40,
        BAND_WIDTH_80,
        BAND_WIDTH_160,
        BAND_WIDTH_80P80,
        BAND_WIDTH_5,
        BAND_WIDTH_10 }     bw;             /**< bandwidth */
    uint8_t                 max_txpower;    /**< max txpower supported for operating class */

    uint8_t                 channel_nums;   /**< channel numbers */
#define CHAN_MAXNUM_PER_OPCLASS     32
    struct radioChannel channels[CHAN_MAXNUM_PER_OPCLASS];         /**< List of channels allocated for this opclass */
};

struct opclassChanTable {
	uint8_t opclass;
	uint8_t chan_set[CHAN_MAXNUM_PER_OPCLASS];
};

/** @brief Radio Steering Policies.
 *
 */
struct radioSteeringPolicy {
    uint8_t policy;             /**< @brief Steering Policy. */
    uint8_t ch_util_threshold;  /**< @brief Channel Utilization Threshold. */
    uint8_t rcpi_threshold;     /**< @brief RCPI Steering Threshold. */
};

/** @brief radio steering policy item for dlist
*
*/
struct radioSteeringPolicyItem {
    dlist_item l;
    mac_address radio_id;                        /**< @brief the mac of radio */
    struct radioSteeringPolicy steering_policy;  /**< Radio Steering Policy */
};

/** @brief Radio Metric Policies.
 *
 */
struct radioMetricPolicy {
    bool    configed;           /**< @brief The paramters below is configured from Metric Reporting Policy TLV */
    uint8_t rcpi_threshold;     /**< @brief STA Metrics Reporting RCPI Threshold */
    uint8_t rcpi_margin;        /**< @brief STA Metrics Reporting RCPI Hysteresis Margin Override */
    uint8_t ch_util_threshold;  /**< @brief AP Metrics Channel Utilization Reporting Threshold */
    uint8_t policy;             /**< @brief Associated STA Inclusion Policy */
};

/** @brief radio metric policy item for dlist
*
*/
struct radioMetricPolicyItem {
    dlist_item l;
    mac_address radio_id;			/**< @brief the mac of radio */
    struct radioMetricPolicy metric_policy;	/**< Radio Metric Policy */
};

/** @brief Radio Unassociated STA.
 *
 */
struct radioUnassocSta {
    dlist_item  l;              /**< Membership of ::radio */
    mac_address mac;            /**< Unassociated STA Mac address */
    uint32_t last_ts;           /**< Last updated timestamps */
    uint8_t opclass;            /**< Monitored on which opclass */
    uint8_t channel;            /**< Monitored on which channel */
    uint8_t rcpi;               /**< Monitored uplink rcpi */
};

/** @brief Channel Unassociated STA
*
*/
struct chanUnassocSta {
    dlist_item l;           /**< Membership of ::chan */
    uint8_t chan;           /**< unassoc sta look up for the given chan */
    dlist_head unassocSTAs; /**< brief List of unassociated STAs */
};

#define RADIO_CONFIG_FLAG_OPCLASS      (1<<0)
#define RADIO_CONFIG_FLAG_CHAN         (1<<1)
#define RADIO_CONFIG_FLAG_TXPOWER      (1<<2)
#define RADIO_CONFIG_FLAG_TEAR_DOWN    (1<<3)

/** @brief Radio Configure Info.
 *
 */
struct radioConfigInfo
{
    uint8_t     opclass;        /**< Operating class work on */
    uint8_t     chan;           /**< Operating channel work on */
    uint8_t     power;          /**< Radio power allowed */
    bool        tear_down;      /**< Tear down all the wdevs created on this wiphy */
};

/** @brief registered tx/rx frame.
 *
 */
struct frame_match
{
    const char *name;
    uint8_t subtype;
    uint8_t rx_mode;
    uint8_t match_len;
    const uint8_t *match;
};

/** @brief Radio Handlers.
 *
 */
struct radioHandles
{
    /** @brief Handler to tear down specified the AP mode wdevs on the wiphy, bssid is null stands for all.
     */
    void (*tearDown)(uint8_t *uid, uint8_t *wdev);

    /** @brief Handler to set the operating channel with transimit power.
     */
    void (*setOperatingChannel)(uint8_t *uid, uint8_t opclass, uint8_t chan, uint8_t txpower);

    /** @brief Handler to monitor the specified channel.
     */
    void (*monitorChannel)(uint8_t *uid, uint8_t opclass, uint8_t chan);

    /** @brief Handler to get monitor stats for specified STAs.
     */
    void (*getMonitorStats)(uint8_t *wiphy_id, uint8_t *stas, uint32_t nums);

    /** @brief Handler to start WPS on which interface.
     */
    void (*startWPS)(uint8_t *mac);

    /** @brief Handler to send frame.
     */
    void (*sendFrame)(uint8_t *bssid, uint8_t *frame, uint32_t frame_len);

    /** @brief Handler to deauth client.
     */
    void (*deauthClient)(uint8_t *bssid, uint8_t *sta, uint16_t reason);

    /** @brief Handler to roam sta.
     */
    void (*roamSta)(uint8_t *bssid, uint8_t *target, uint8_t opclass, uint8_t chan);

    /** @brief Handler to filter client.
     */
    void (*filterClient)(uint8_t *bssid, uint8_t *sta, bool block);

#define INVALID_REPORT_PERIOD     (0xffffffff)
    /** @brief Handler to set report period.
     */
    void (*setReportPeriod)(uint8_t *bssid, uint32_t ifw_period, uint32_t sta_period, uint32_t mon_period);

    /** @brief Handler to register rx/tx frame.
     */
    void (*registerMgmtFrame)(uint8_t *bssid, struct frame_match *frame, bool rx);

    /** @brief Handler config extcap bits.
     */
    void (*confExtcap)(uint8_t *bssid, uint8_t *extcap, uint8_t *extcap_mask, uint32_t len);

    /** @brief Handler config appie for mamagement frames.
     */
    void (*confAppIes)(uint8_t *bssid, uint32_t mask, uint8_t *ies, uint32_t len);

    /** @brief Handler config 4addr enable.
     */
    void (*conf4addr)(uint8_t *bssid, bool enable);

    /** @brief Handler config security.
     */
    void (*confSecurity)(uint8_t *bssid, uint8_t auth, struct key *key);

    /** @brief Handler reset backhaul info for interface wifi.
     */
    void (*resetBackhaul)(struct interfaceWifi *ifw);

    /** @brief Handler set backhaul info for interface wifi.
     */
    void (*setBackhaul)(struct interfaceWifi *ifw);

};

/** @brief Wi-Fi radio.
 *
 * A device may have several radios, and each radio may have several configured interfaces. Each interface is a STA or
 * AP and can join exactly one BSSID.
 */
struct radio {
    dlist_item  l;                      /**< Membership of ::alDevice */

    mac_address uid;                    /**< Radio Unique Identifier for this radio. */
    char        name[T_RADIO_NAME_SZ];  /**< Radio's name (eg phy0) */
    uint32_t    index;                  /**< Radio's index (PHY) */
    uint8_t     confAnts[2];            /**< Configured antennas rx/tx */
    uint32_t    maxApStations;          /**< How many associated stations are supported in AP mode */
    uint32_t    maxBSS;                 /**< Maximum number of BSSes */
    bool        monitor_onchan;         /**< Is on channel monitor mode supported on this radio ? */
    bool        monitor_offchan;        /**< Is off channel monitor mode supported on this radio ? */
    bool        self_steering;          /**< Is Agent-initiated RCPI-based Steering supported ? */
    uint32_t    phytype;
    uint8_t     opclass;                /**< Current operating class */
    uint8_t     chan;                   /**< Current operating channel */
    uint8_t     informed_chan;          /**< Operating channel has been informed to registrar */
    bool        powerSaved;             /**< Is radio is in power save mode? */
    uint8_t     band_supported;         /**< Band ID, see IEEE80211_FREQUENCY_BAND_ */
    uint8_t     txpower;                /**< Tx power */
    uint8_t     ch_util;                /**< Channel Utilization as measured by the radio */
    int8_t      dir;                    /** @brief Internal used for recording the dirction of crossing the threshold */
    struct radioHtcap  ht_capa;         /**< HT capability */
    struct radioVhtcap vht_capa;        /**< VHT capability */
    struct radioHecap  he_capa;         /**< HE capability */

    struct radioSteeringPolicy  steering_policy;    /**< Radio Steering Policy */
    struct radioMetricPolicy    metric_policy;      /**< Radio Metric Report Policy */

#define OPCLASS_MAXNUM      32
    uint8_t opclass_nums;   /**< opclass numbers */
    /** @brief List of operating classes and their attributes/channels */
    struct radioOpclass opclasses[OPCLASS_MAXNUM];

    /** @brief max Tx power is requested from controller */
    uint8_t     ctrler_maxpower;
    /** @brief The index of the valid Channel Preference from controller */
    uint8_t     ctrler_pref_ind;
    uint8_t     channel_selected;
    uint8_t     opclass_selected;

    /** @brief List of unassociated STAs */
    dlist_head  unassocStaHead;

    /** @brief List of BSSes configured for this radio.
     *
     * Their interfaceWifi::radio pointer points to this object.
     */
    PTRARRAY(struct interfaceWifi *) configured_bsses;

    /** @brief Information used during WSC.
     *
     * During WSC exchange, the enrollee has to keep some information that will be used when it receives the M2.
     * So this is only valid for the local device, if it is an agent.
     *
     * The structure is dynamically allocated when the M1 message is constructed. It can be deleted after M2 has been received.
     */
    struct {
        uint8_t   m1[1000]; /**< Buffer for constructing the M1 message. */
        uint16_t  m1_len;   /**< Used length of @a m1. */
        uint8_t  *nonce;    /**< Pointer into @a m1 to location of the nonce. Length is 16 bytes. */
        uint8_t  *mac;      /**< Pointer into @a m1 to location of the MAC address. */
        uint8_t  *priv_key; /**< Private key, allocated separately. */
        uint16_t  priv_key_len;  /**< Length of @a priv_key. */
    } *wsc_info;

    struct ssid backhaul_ssid; /**< @brief If len != 0, the single backhaul SSID for this radio. */
    // uint8_t     backhaul_key[64]; /**< @brief If backhaul_ssid is set, its WPA2 key. */
    // uint8_t     backhaul_key_length; /**< @brief Length of backhaul_key. */
    struct key  backhaul_key;  /**< @brief If backhaul_ssid is set, its WPA2 key. */
    uint8_t     backhaul_only_configured; /**< @brief if backhaul_only_configured set, means already have backhaul_only bss info configured. */

    /** @brief Keep track if radio has been configured already. Only relevant for local device. */
    bool configured;

    /** @brief Pointer to driver private data.
     */
    void *priv;

    /** @brief Operations on the radio.
     *
     * Implementing these as function pointers allows each radio to have a different driver.
     *
     * Note that the handlers should in general not update the data model. Instead, the data model should be updated by driver
     * events that detect a change in the data model.
     * @{
     */

    /** @brief Handler to add an access point interface on this radio.
     *
     * @param radio The radio on which the AP is to be added.
     * @param bss_info The AP's BSS info.
     */
    bool (*addAP)(struct radio *radio, struct bssInfo *bss_info);

    /** @brief Handler to add an station interface on this radio.
     *
     * @param radio The radio on which the STA is to be added.
     * @param bss_info The STA's BSS info.
     */
    bool (*addSTA)(struct radio *radio, struct bssInfo *bss_info);

    /** @brief Handler to set the backhaul SSID.
     *
     * This function is called for each radio when the (global) backhaul SSID is updated.
     */
    bool (*setBackhaulSsid)(struct radio *radio, struct ssid *ssid, struct key *key);

    /** @brief Handlers of this radio.
     */
    struct radioHandles ops;
    /** @} */
};

/** @brief 1905.1 device.
 *
 * Representation of a 1905.1 device in the network, discovered through topology discovery.
 */
struct alDevice {
    dlist_item l; /**< @brief Membership of ::network */

    mac_address al_mac_addr;    /**< @brief 1905.1 AL MAC address for this device. */
    uint32_t    profile;        /**< @brief 1905.1 profile type,  0x0:PROFILE_1905_1, 0x1:PROFILE_1905_1A. */
    dlist_head interfaces;      /**< @brief The interfaces belonging to this device. */
#define MAX_RADIOS_PER_AGENT    4
    dlist_head radios;          /**< @brief The radios belonging to this device. */

    /**< @brief The map services supported by this device.
     * is_map_agent | is_map_controller |      services     |
     *    true      |      false        |   map_agent       |
     *    false     |      true         |   map_controller  |
     *    true      |      true         |   dual_services   |
     *    false     |      false        |   legacy registar |
     **/
    bool is_map_agent; /**< @brief true if this device is a Multi-AP Agent. */
    bool is_map_controller; /**< @brief true if this device is a Multi-AP Controller. */

    bool configured; /**< @brief true if device has been configured, false if AP-Autoconfig needs to be done. */
    uint32_t configure_ts; /**< @brief latest configure start timestamp */
    mac_address receiving_addr; /**< @brief Reachable from local interface */
    uint32_t receiving_interface_index;	/**< @brief Receiving interface index */
    char receiving_interface_name[33]; /**< @brief Receiving interface name */
    uint32_t last_topo_resp_ts;  /**< @brief Last received topology response timestamp */
};

/** @brief mac address item for dlist, eg: can be used to store the Steering Disallowed STA
 *
 */
struct macAddressItem {
    dlist_item l;
    mac_address mac;
};

/** @brief blocked client context
 *
 */
struct blockedClient {
    dlist_item l;
    mac_address mac;
    mac_address bssid;
    void *unblock_timer;
    uint32_t expiration;
};

#define MAP_ROLE_AGENT (0x1)
#define MAP_ROLE_CONTROLLER (0x2)

struct type_message_register {
    dlist_item l;
    uint16_t message_type;
    uint16_t flag;
};

struct frame_suscribe_t {
    dlist_head rx_1905_suscribe;
};

struct mapBasicTopologyPolicy {
    bool APCapaQ_uponTopoR;
    bool ClientCapaQ_uponTopoR;
    bool APMetricsQ_uponTopoR;
    bool AssocedStaLinkQ_uponTopoR;
};

/** @brief Configuration
 *
 */
struct mapConfig {
    uint8_t role;
    uint8_t ap_metrics_intval;          /**<@brief AP Metrics Reporting Interval in seconds */
    uint8_t assoc_sta_intval;           /**<@brief Associated STA Metrics Reporting Interval in seconds */
    uint8_t unassoc_sta_intval;         /**<@brief Unassociated STA Metrics Reporting Interval in seconds */
    uint8_t support_agent_steering;     /**<@brief Support the Agent-initiated RCPI-based Steering? */
    uint32_t monitor_dwell;             /**<@brief The timer of the dwell on monitored channel in milliseconds */
    uint8_t rcpi_margin;                /**<@brief RCPI hysteresis margin */
    uint8_t wait_roaming;               /**<@brief Wait the backhaul STA roaming result in seconds */
    uint32_t unassoc_sta_maxnums;       /**<@brief Unassociate Sta max numbers */
    uint8_t retries;                    /**<@brief Retry numbers to send unresponsed CMDU */
    uint32_t wait_ack;                  /**<@brief Wait the response of CMDU in milliseconds */
    uint32_t search_period;             /**<@brief Send the autoconfiguration search period in seconds */
    uint32_t autoconf_wait;             /**<@brief Wait the autoconfiguration for all radios in seconds */
    uint32_t hide_backhaul_ssid;        /**<@brief Hide backhaul ssid if needed */

    /** @brief Device identification, used in WSC exchanges.
     */
    struct wscDeviceData wsc_data;
    uint32_t dbg_level;
    uint8_t profile;

    struct frame_suscribe_t frame_suscribe;
    char *ini2;
    char *ini5;

    struct mapBasicTopologyPolicy topology_policy;
    bool filter_1905packet;
};

extern struct mapConfig map_config;

/** @brief Configuration for qdock.map.config
 *
 */
struct ControllerConf {
    bool Enable;
    bool DisableUponWiFiOnboarding;
};

struct AuthType {
    bool OpenAuth;
    bool wpa2;
    bool wpa3;
};

struct MemMgnt {
    bool MAPTopologyAssocReq_En;
    bool NeighBSSStale;
    bool PurgeSTAStatsOlderThan;
};

struct BeaconReq {
    bool Repetitions;
    bool RandomizationInt;
    bool Mode;
    uint32_t Duration;
};

struct BTMReqSteering {
    bool PreferredCandidateIncluded;
    uint32_t Validity;
    uint32_t MBORetryDelay;
};

struct DeauthSteering {
    bool useDisassoc;
    uint32_t useReason;
};

struct PassiveSteering {
    uint32_t rejectWithCode;
};

struct AgentConf {
    uint32_t BSSdenyAssocToNonMAP;
    uint32_t ScanTimeout;
    struct AuthType auth_types;
    struct MemMgnt mgnt;
    struct BeaconReq bcn_req;
    struct BTMReqSteering btm_req;
    struct DeauthSteering deauth_steer;
    struct PassiveSteering passive_steer;
};

struct topo_discovery {
    uint32_t TopoQ_minInterval;
    uint32_t TopoQ_uponM1_delay;
    bool TopoQ_uponM1;
    bool TopoQ_uponSearch;
    bool TopoQ_uponTopoD;
    bool TopoQ_uponTopoQ;
    bool APCapaQ_uponTopoR;
    bool STACapaQ_uponTopoR;
    bool STACapaQ_uponTopoN;
    bool APMetricsQ_uponTopoR;
};

struct frame_suscribe_ctl_t {
    dlist_item l;
    uint16_t type;
    uint16_t flag;
};

enum profileId {
    PROFILE_ID_1 = 1,
    PROFILE_ID_2 = 2,
};

struct mapapiConfig {
    enum profileId Profile;
    struct ControllerConf controller;
    struct AgentConf agent;
    struct topo_discovery discovery;
};

extern struct mapapiConfig mapapi_config;

/** @brief Global Policies.
 *
 */
struct mapPolicy {
    dlist_head local_disallowed; /**<@brief STA MAC addresses for which local steering is disallowed */
    dlist_head btm_disallowed;   /**<@brief STA MAC addresses for which BTM steering is disallowed */
    uint8_t metric_intval;       /**<@brief AP Metrics Reporting Interval in seconds */

    dlist_head blocked_clients; /**<@brief Clients for which local interface should be blocked, see struct blockedClient */
};

extern struct mapPolicy map_policy;

/** @brief steering sta item for dlist
*
*/
struct steeringStaItem {
    dlist_item l;
    mac_address mac;			/**< @brief the mac of steering sta */
    mac_address targetBssid;	/**< @brief the bssid of target bss */
    uint8_t target_bss_opclass; /**< @brief the opclass of target bss */
    uint8_t target_bss_ch;		/**< @brief the ch of target bss */
};

/** @brief The local AL device.
 *
 * This must be non-NULL for the AL functionality to work, but it may be NULL when the datamodel is used by an
 * external entity (e.g. a separate HLE).
 */
extern struct alDevice *local_device;

/** @brief WPS constants used in the wscDeviceData fields.
 *
 * These correspond to the definitions in WSC.
 * @{
 */
#define WPS_ENCR_NONE       (0x0001)
#define WPS_ENCR_WEP        (0x0002) /* deprecated */
#define WPS_ENCR_TKIP       (0x0004)
#define WPS_ENCR_AES        (0x0008)
#define WPS_ENCR_AES_TKIP   (0x000c) /* mixed mode */

#define WPS_RF_24GHZ           (0x01)
#define WPS_RF_50GHZ           (0x02)
#define WPS_RF_60GHZ           (0x04)

/** @} */

/** @brief Device data received from registrar/controller through WSC.
 *
 * If local_device is the registrar/controller, this is the device data that is sent out through WSC.
 *
 * Note that the WSC data can only be mapped to a specific radio through the RF band. Note that WSC allows to apply the
 * same data to multiple bands simultaneously, but 1905.1/Multi-AP does not; still, the WSC frame may specify multiple
 * bands.
 *
 * Only PSK authentication is supported, not entreprise, so we can use a fixed-length key.
 */
struct wscRegistrarInfo {
    dlist_item l;
    struct bssInfo bss_info;
    struct wscDeviceData device_data;
    uint8_t rf_bands;           /**< Bitmask of WPS_RF_24GHZ, WPS_RF_50GHZ, WPS_RF_60GHZ. */
#define WSCINFO_FLAG_HAVE_UPDATED_SHIFT (0)
#define WSCINFO_FLAG_HAVE_CHANGED_SHIFT (1)
#define WSCINFO_FLAG_NEW_CREATED_SHIFT  (2)
#define WSCINFO_FLAG_SECURITY_CHANGED_SHIFT (3)
#define WSCINFO_FLAG_MTYPE_CHANGED_SHIFT    (4)
#define WSCINFO_FLAG_IS_SET(_info, _name)  BIT_IS_SET((_info)->flags, (WSCINFO_FLAG_##_name##_SHIFT))
#define WSCINFO_FLAG_SET(_info, _name)     SET_BIT((_info)->flags, (WSCINFO_FLAG_##_name##_SHIFT))
#define WSCINFO_FLAG_CLR(_info, _name)     CLR_BIT((_info)->flags, (WSCINFO_FLAG_##_name##_SHIFT))
#define WSCINFO_FLAG_CLR_ALL(_info)        (_info->flags = 0)
    uint8_t flags;              /**< Flags used for Registrar wsc update function */
    uint8_t key[8];
};

/** @brief registrar Handlers.
 *
 */
struct registrarHandles
{
    /** @brief Handler trigger to sync bsscfgs from driver.
     */
    void (*syncBssCfgs)(void);
};

/** @brief The discovered/configured Multi-AP controller or 1905.1 AP-Autoconfiguration Registrar.
 *
 * This points to the alDevice that was discovered to offer the Controller service. It may be the local_device, if it
 * was configured to take the controller role.
 *
 * There can be only one controller OR registrar in the network, so this is a singleton.
 *
 * The local device is the registrar/controller if registrar.d == local_device and local_device is not NULL.
 */
extern struct registrar {
    /**< If non-NULL, a controller was configured/discovered. And
     * if found duplicated controllers, this point remain the first seen one. */
    struct alDevice *d;
    bool is_map; /**< If true, it is a Multi-AP Controller. If it is false, it is only a 1905.1 Registrar. */

    /** @brief List of configured wscDeviceInfo objects. */
    dlist_head wsc;

    /** @brief List of alDevices found as duplicated controller. */
    dlist_head duplicated_controller;
    /** if found duplicated controllers, this point record the last seen one. */
    struct alDevice *last_seen;

    /** @brief List of alDevices found as duplicated registrar. */
    dlist_head duplicated_registrar;

    /** @brief function Handles for this registrar*/
    struct registrarHandles ops;
} registrar;

/** @brief Add a WSC definition to the registrar.
 *
 * Ownership transfers to the registrar object so the @a wsc must be dynamically allocated and must not be freed.
 */
void registrarAddWsc(struct wscRegistrarInfo *wsc);

/** @brief Update a wsc info to the dlist of wsc in registrar.
 * @return the point of wsc_info which could indicate whether need free wsc or not,
 *  if NEW_CREATED flag is set, mean add a new wsc to registrar, wsc don't be free,
 *  otherwise it should be free.
 **/
struct wscRegistrarInfo *registrarUpdateWsc(struct wscRegistrarInfo *wsc);

/** @brief Commit new updates base on flags in wscinfo for regitrar
 * @return true mean have new updated and need to send renew, otherwise
 *  return false mean no change happen, do not need to send renew.
 **/
bool registrarCommitWsc(void);

/** @brief Dump all WSC definitions in registrar. */
void registrarDumpAllWsc(char *prefix);

/** @brief Register the handlers of the registrar. */
void registrarRegisterHandlers(struct registrarHandles *ops);

/** @brief Add a found controller to the dlist of duplicated_controller in registrar. */
void registrarAddDuplicantedController(struct alDevice *dev);

/** @brief Add a found registrar to the dlist of duplicated_registrar in registrar. */
void registrarAddDuplicantedRegistrar(struct alDevice *dev);

/** @brief The network, i.e. a list of all discovered devices.
 *
 * Every discovered alDevice is added to this list. local_device (if it exists) is part of the list.
 */
extern dlist_head network;


/** @brief Initialize the data model. Must be called before anything else. */
void datamodelInit(void);

/** @brief Add a @a neighbor as a neighbor of @a interface. */
void interfaceAddNeighbor(struct interface *interface, struct interface *neighbor);

/** @brief Remove a @a neighbor as a neighbor of @a interface.
 *
 * @a neighbor may be free'd by this function. If the @a neighbor is not owned by an alDevice, and the neighbor has no
 * other neighbors, it is deleted.
 */
void interfaceRemoveNeighbor(struct interface *interface, struct interface *neighbor);

/** @brief Allocate a new @a alDevice. */
struct alDevice *alDeviceAlloc(const mac_address al_mac_addr);

/** @brief Delete a device and all its interfaces/radios.
  */
void alDeviceDelete(struct alDevice *alDevice);

/** @brief  Allocate a new ::radio on the specified @a device
 *  @param  device  Device which owns this radio
 *  @param  mac     Unique identifier (mac address)
 */
struct radio *  radioAlloc(struct alDevice *device, const mac_address mac);

/** @brief  Allocate a new local ::radio and add it to the global ::local_device list
 *  @param  mac     Unique identifier (mac address)
 *  @param  name    Local system name
 *  @param  index   Local system index
 */
struct radio *  radioAllocLocal(const mac_address mac, const char *name, int index);

/** @brief  Delete a ::radio and all its interfaces. */
void radioDelete(struct radio *radio);

/** @brief  Find the first wifi interface in ::radio. */
struct interfaceWifi *radioGetFirstAPInterface(struct radio *radio);

/** @brief Find the radio with a given radio-uid in all devices of network list. */
struct radio *findRadio(const mac_address uid);

/** @brief Find the radio with a given radio-uid belonging to the given device. */
struct radio *findDeviceRadio(const struct alDevice *device, const mac_address uid);

/** @brief Find the radio with the given name in the local device. */
struct radio *findLocalRadio(const char *name);

/** @brief Find the radio or create a radio belongs the given device. */
struct radio *findOrAddDeviceRadio(struct alDevice *device, const mac_address uid);

/** @brief  Add an interface to ::radio
 *  @return 0:success, <0:error
 */
int radioAddInterfaceWifi(struct radio *radio, struct interfaceWifi *iface);

/** @brief Find a interfaceWifi belong to the given radio by bssid. */
struct interfaceWifi *radioFindInterfaceWifi(struct radio *radio, mac_address bssid);

/** @brief Find a interfaceWifi belong to the given radio by ssid. */
struct interfaceWifi *radioFindInterfaceWifiBySSID(struct radio *radio, struct ssid *ssid);

/** @brief Add a new unassoc station to the radio. */
struct radioUnassocSta *radioAddUnassocSta(struct radio *radio, const mac_address sta_mac);

/** @brief Remove an oldest unassoc station from the radio. */
void radioRemoveOldestUnassocSta(struct radio *radio);

/** @brief Configure an AP on the radio. */
void radioAddAp(struct radio *radio, struct bssInfo *bss_info);

/** @brief Configure a STA on the radio. */
void radioAddSta(struct radio *radio, struct bssInfo *bss_info);

/** @brief Register the handlers of the radio. */
void radioRegisterHandlers(struct radio *radio, struct radioHandles *ops);

/** @brief Deconfigure an interface.
 *
 * After tear-down completes, the interface will have been deleted.
 */
void interfaceTearDown(struct interface *iface);

/** @brief Allocate a new interface, with optional owning device.
 *
 * If the owner is NULL, the interface must be added as a neighbor of another interface, to make sure it is still
 * referenced.
 */
struct interface *interfaceAlloc(const mac_address addr, struct alDevice *owner);

/** @brief Delete an interface and all its neighbors. */
void interfaceDelete(struct interface *interface);

/** @brief Allocate a new interface wifi (BSS) */
struct interfaceWifi *interfaceWifiAlloc(const mac_address addr, struct alDevice *owner);

/** @brief Remove a BSS from a radio and delete it. */
void interfaceWifiRemove(struct interfaceWifi *interfaceWifi);

/** @brief Add a new station to the interface wifi. */
struct staInfo *interfaceAddStation(struct interfaceWifi *ifw, const mac_address sta_mac);

/** @brief Remove a station from the interface wifi. */
void interfaceRemoveStation(struct interfaceWifi *ifw, const mac_address sta_mac);

/** @brief Associate an interface with an alDevice.
 *
 * The interface must not be associated with another device already.
 */
void alDeviceAddInterface(struct alDevice *device, struct interface *interface);

/** @brief Find an alDevice based on its AL-MAC address. */
struct alDevice *alDeviceFind(const mac_address al_mac_addr);

/** @brief Find an alDevice based on an address which may be its AL-MAC address or the sending interface address. */
struct alDevice *alDeviceFindFromAnyAddress(const mac_address sender_addr);

/** @brief Find the interface belonging to a specific device. */
struct interface *alDeviceFindInterface(const struct alDevice *device, const mac_address addr);

/** @brief Find the interface belonging to a specific device from ifindex. */
struct interface *alDeviceFindInterfaceFromInterfaceIndex(const struct alDevice *device, int index);

/** @brief Find the wifi interface belonging to with a specific device from interface mac */
struct interfaceWifi *alDevicefindWifiInterface(struct alDevice *device, const mac_address addr);

/** @brief Find or Add UnassocSta belonging to a specific device's radio by opclass, channel and mac address info. */
struct radioUnassocSta *alDeviceFindOrAddUnassocClient(struct alDevice *device, uint8_t opc, uint8_t ch, const mac_address mac);

/** @brief Update the backhaul SSID on this device.
 *
 * If the given ssid/key is different from the already configured one, this will call updateBackhaulSsid on all radios.
 */
void localRadioUpdateBackhaulSsid(struct radio *radio, struct ssid *ssid, struct key *key, uint8_t backhaul_only);

/** @brief Find the interface belonging to any device.
 *
 * Only interfaces that are owned by a 1905 device are taken into account, not non-1905 neighbors.
 */
struct interface *findDeviceInterface(const mac_address addr);

/** @brief Find the local interface with a specific interface name. */
struct interface *findLocalInterface(const char *name);

/** @brief Find the local wifi interface with a specific interface mac and role */
struct interfaceWifi *findLocalWifiInterface(const mac_address addr, enum interfaceWifiRole role);

/** @brief Reset the Channel Preference from controller */
void resetCtrlerChannelPreference(struct radio *r);

/** @brief Update the Channel Preference from controller */
int updateCtrlerChannelPreference(struct radio *r, uint8_t opclass,
        uint8_t ch_num, uint8_t *chans, uint8_t value);

/** @brief Update the Channel Preference from agent */
int updateChannelPreference(struct radio *r, uint8_t opclass,
        uint8_t ch_num, uint8_t *chans, uint8_t value);

/** @brief Update Radio Operation Restriction from agent */
int updateRadioOperationRestriction(struct radio *r, uint8_t opclass, uint8_t channel, uint8_t min_sep);

/** @brief Check current channel is one of the most prefered channel, or find one */
int checkCurrentAndGetPerfChannel(struct radio *r, int ind, struct radioOpclass **opc, struct radioChannel **ch);

/** @brief Find the wifi interface by the given ssid and fequency band */
struct interfaceWifi *findWifiInterfaceWithSSID(struct alDevice *al_dev, struct ssid *ssid, uint8_t band);

/** @brief Find a client by mac addr belongs to this network. */
struct staInfo *findWifiClient(const mac_address addr, struct interfaceWifi **assoc_intf, struct alDevice **assoc_dev);

/** @brief Find or add a client by mac addr and bssid belongs to this network. */
struct staInfo *findOrAddWifiClient(const mac_address addr, const mac_address bssid, struct interfaceWifi **assoc_intf);

/** @brief Find the client associated with local interface by client's mac address. */
struct staInfo *findLocalWifiClient(const mac_address addr, const uint8_t *bssid, struct interfaceWifi **assoc_intf);

/** @brief Find the radio opcalss context. */
struct radioOpclass *findOpclass(struct radio *radio, uint8_t opc);

/** @brief Find the radio channel context. */
struct radioChannel *findOpclassAndChannel(struct radio *radio, uint8_t opc, uint8_t ch);

/** @brief Find the unassoc client infomation. */
struct radioUnassocSta *findLocalUnassocClientOnChannel(uint8_t *mac, uint8_t ch);

/** @brief Find the unassoc client by mac address belongs to this device. */
struct radioUnassocSta *findUnassocClientByDevice(mac_address mac, struct alDevice *dev);

/** @brief Find the blocked client context. */
struct blockedClient *findLocalWifiBlockedClient(const mac_address mac, const mac_address bssid);

/** @brief Find or Add the opclass into radio. */
struct radioOpclass *radioFindOrAddOpclass(struct radio *radio, uint8_t opc);

/** @brief Create interface belongs to local radio. */
struct interfaceWifi *radioAddLocalInterfaceWifi(struct radio *radio, mac_address uid);

/** @brief Find or Add the channel into opclass. */
struct radioChannel *opclassFindOrAddChannel(struct radioOpclass *opclass, uint8_t ch);

/** @brief Initial the channel list into opclass. */
void opclassInitChannelList(struct radioOpclass *opclass);

/** @brief Find or Add the unassociated Sta. */
struct radioUnassocSta *radioFindOrAddUnassocSta(struct radio *radio, const mac_address sta_mac);

/** @brief Remove all the unassociated Sta. */
void radioRemoveAllUnassocSta(struct radio *radio);

/** @brief Find associated Station on interface */
struct staInfo *interfaceFindStation(struct interfaceWifi *ifw, const mac_address sta_mac);
/** @brief Find associated Station on interface and create new one if not found */
struct staInfo *interfaceFindOrAddStation(struct interfaceWifi *ifw, const mac_address sta_mac);

/** @brief wifi interface created callback */
void localInterfaceWifiCreated(struct interfaceWifi *ifw);

/** @brief wifi interface deleted callback */
void localInterfaceWifiDeleted(struct interfaceWifi *ifw);

/** @brief wifi interface status changed callback */
void localInterfaceWifiStatusChanged(struct interfaceWifi *ifw, uint32_t status);

/** @brief local device's wifi interfaces Register Mgmt frames and config APPIEs/EXTIEs */
void localDeviceInterfaceWifiRegFramesAndConfigIEs(void);

/** @brief local device's wifi backhaul interface config 4addr and register receive 1905 packet event*/
void localDeviceInterfaceWifiBackhaulConfig(void);

/** @brief compare the SSID */
int compareSSID(struct ssid *ssid1, struct ssid *ssid2);

/** @brief copy key*/
void copyKey(struct key *dst_key, struct key *src_key);

/** @brief Update the (re)associate frame. */
void updateAssocFrame(struct staInfo *client, uint8_t *frame, uint32_t frame_len);

void mapParseAssocFrame(struct staInfo *client, uint8_t *frame, uint32_t frame_len);

uint16_t _check_register_message_type(uint16_t type);

/** @brief sync the remote bss role according controller itself ssid*/
void syncRemoteBssRole(struct bssInfo *bssInfo, struct ssid *ssid, uint8_t radio_brand);

/** @brief true if the local device is a registrar/controller, false if not.
 *
 * If there is no local device, it is always false (even a MultiAP Controller without Agent must have an AL MAC
 * address, so it must have a local device).
 */
static inline bool registrarIsLocal(void)
{
    return local_device != NULL && local_device == registrar.d;
}

static inline uint32_t getLocalRadioNumbers(void)
{
    return dlist_count(&local_device->radios);
}

static inline void alDeviceUpdateReceivingInterface(struct alDevice *device, uint8_t *receiving_addr)
{
    memcpy(device->receiving_addr, receiving_addr, sizeof(mac_address));
}

static inline void alDeviceUpdateReceivingInterfaceIndex(struct alDevice *device, uint32_t receiving_index)
{
    device->receiving_interface_index = receiving_index;
}

static inline void alDeviceUpdateReceivingInterfaceName(struct alDevice *device, const char *receiving_if_name)
{
    strncpy(device->receiving_interface_name, receiving_if_name, sizeof(device->receiving_interface_name) - 1);
}

static inline void alDeviceUpdateLastTopologyResponseTimestamp(struct alDevice *device, uint32_t timestamp)
{
    device->last_topo_resp_ts = timestamp;
}

#define RADIO_TEARDOWN(_r)         do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("tear down all wdevs on " MACFMT "\n", MACARG((_r)->uid));   \
        if ((_r)->ops.tearDown)    \
            (_r)->ops.tearDown((_r)->uid, NULL);   \
    } while(0)
#define RADIO_SET_OPERATING_CHANNEL(_r, _opc, _ch, _txpower)         do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("set operating channel(%u: %u) with txpower %u for " MACFMT "\n",  \
                _opc, _ch, _txpower, MACARG((_r)->uid));   \
        if ((_r)->ops.setOperatingChannel)    \
            (_r)->ops.setOperatingChannel((_r)->uid, _opc, _ch, _txpower);   \
    } while(0)
#define RADIO_MONITOR_CHANNEL(_r, _opc, _ch)               do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("monitor channel(%u: %u) on " MACFMT "\n",  \
                _opc, _ch, MACARG((_r)->uid));   \
        if ((_r)->ops.monitorChannel)    \
            (_r)->ops.monitorChannel((_r)->uid, _opc, _ch);   \
    } while(0)
#define RADIO_GET_MONITOR_STATS(_r, _stas, _nums)               do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("get monitor %u stats on " MACFMT "\n",  \
                _nums, MACARG((_r)->uid));   \
        if ((_r)->ops.getMonitorStats)    \
            (_r)->ops.getMonitorStats((_r)->uid, _stas, _nums);   \
    } while(0)
#define IFW_START_WPS(_ifw)                                do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("start wps on " MACFMT "\n",  \
                MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.startWPS)    \
            (_ifw)->radio->ops.startWPS((_ifw)->i.addr);   \
    } while(0)
#define IFW_SEND_FRAME(_ifw, _frm, _frm_len)               do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("send frame(len %u) on " MACFMT "\n",  \
                _frm_len, MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.sendFrame)    \
            (_ifw)->radio->ops.sendFrame((_ifw)->i.addr, _frm, _frm_len);   \
    } while(0)
#define IFW_DEAUTH_CLIENT(_ifw, _sta, _code)                do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("deauth sta " MACFMT " with code %u on " MACFMT "\n",  \
                MACARG(_sta), _code, MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.deauthClient)    \
            (_ifw)->radio->ops.deauthClient((_ifw)->i.addr, _sta, _code);   \
    } while(0)
#define IFW_ROAM_STA(_ifw, _target, _opc, _ch)              do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("roam sta interface " MACFMT " to target " \
                MACFMT " on channel(%u: %u)\n", MACARG((_ifw)->i.addr), MACARG(_target), _opc, _ch);   \
        if ((_ifw)->radio && (_ifw)->radio->ops.roamSta)    \
            (_ifw)->radio->ops.roamSta((_ifw)->i.addr, _target, _opc, _ch);   \
    } while(0)
#define IFW_BLOCK_CLIENT(_ifw, _sta)                     do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("block sta " MACFMT " on " MACFMT "\n",  \
                MACARG(_sta), MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.filterClient)    \
            (_ifw)->radio->ops.filterClient((_ifw)->i.addr, _sta, true);   \
    } while(0)
#define IFW_UNBLOCK_CLIENT(_ifw, _sta)                     do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("unblock sta " MACFMT " on " MACFMT "\n",  \
                MACARG(_sta), MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.filterClient)    \
            (_ifw)->radio->ops.filterClient((_ifw)->i.addr, _sta, false);   \
    } while(0)
#define IFW_SET_REPORT_PERIOD(_ifw, _fat, _sta, _mon)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("set period(%d, %d, %d) for stats on " MACFMT "\n",  \
                (int)(_fat), (int)(_sta), (int)(_mon), MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.setReportPeriod)    \
            (_ifw)->radio->ops.setReportPeriod((_ifw)->i.addr, _fat, _sta, _mon);   \
    } while(0)
#define IFW_REG_MGMT_FRAME(_ifw, _frame, _rx)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("register %s %s on " MACFMT "\n",  \
                (_frame)->name, (_rx) ? "rx" : "tx", MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.registerMgmtFrame)    \
            (_ifw)->radio->ops.registerMgmtFrame((_ifw)->i.addr, _frame, _rx);   \
    } while(0)
#define IFW_CONF_EXTCAP(_ifw, _extcap, _extcap_mask, _len)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("config extcap on " MACFMT "\n",  \
                MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.confExtcap)    \
            (_ifw)->radio->ops.confExtcap((_ifw)->i.addr, _extcap, _extcap_mask, _len);   \
    } while(0)
#define IFW_CONF_IES(_ifw, _mask, _ies, _len)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("config app ies on " MACFMT "\n",  \
                MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.confAppIes)    \
            (_ifw)->radio->ops.confAppIes((_ifw)->i.addr, _mask, _ies, _len);   \
    } while(0)
#define IFW_CONF_4ADDR(_ifw, _enb)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("config 4addr on " MACFMT "\n",  \
                MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.conf4addr)    \
            (_ifw)->radio->ops.conf4addr((_ifw)->i.addr, _enb);   \
    } while(0)
#define IFW_CONF_SECURITY(_ifw, _auth, _key)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("config security on " MACFMT "\n",  \
                MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.confSecurity)    \
            (_ifw)->radio->ops.confSecurity((_ifw)->i.addr, _auth, _key);   \
    } while(0)
#define IFW_RESET_BACKHAUL(_ifw)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("reset backhaul on " MACFMT "\n",  \
                MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.resetBackhaul)    \
            (_ifw)->radio->ops.resetBackhaul(_ifw);   \
    } while(0)
#define IFW_SET_BACKHAUL(_ifw)    do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("set backhaul on " MACFMT "\n",  \
                MACARG((_ifw)->i.addr));   \
        if ((_ifw)->radio && (_ifw)->radio->ops.setBackhaul)    \
            (_ifw)->radio->ops.setBackhaul(_ifw);   \
    } while(0)

#define REGISTRAR_SYNC_BSSCFGS() do {    \
        PLATFORM_PRINTF_DEBUG_DETAIL("trigger registrar sync bsscfgs\n");   \
        if (registrar.ops.syncBssCfgs)    \
            registrar.ops.syncBssCfgs();   \
    } while(0)

#endif // DATAMODEL_H
