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
 */

/** @file
 * @brief interface for QDOCK
 *
 * This file provides functionality using QDOCK.
 */

#ifndef PLATFORM_QDOCK_H
#define PLATFORM_QDOCK_H

void qdock_platform_init(void);
void qdock_platform_deinit(void);
void qdock_collect_local_infos(void);
void qdock_collect_local_registar(void);
void qdock_get_driver_devicedata(void);
void qdock_get_driver_bssconfigs(void);
bool isQtnWifiDevice(const char *if_name);

struct _qdockBssInfo
{
    dlist_item l;

    mac_address uid;                /**< Creating on which radio. */
    struct ssid ssid;               /**< SSID used on this BSS. */
    char ifname[IFNAMSIZ];          /**< Interface name */
    bool backhaul;                  /**< Is backhaul AP/STA */
    bool fronthaul;                 /**< Is fronthaul AP */
    enum auth_mode auth_mode;       /**< Authentication mode. Encryption is implied (none for open, CCMP for WPA2). */
    struct key key;                 /**< Shared key. Only valid for @a auth_mode_wpa2psk. */

    enum interfaceWifiRole role;    /**< AP or STA */
};

struct _qdockBssCfg
{
    char ifname[IFNAMSIZ];      /**< Interface name */
    mac_address bssid;          /**< BSSID (MAC address) of the BSS configured by this WSC exchange. */
    struct ssid ssid;           /**< SSID used on this BSS. */
    enum auth_mode auth_mode;   /**< Authentication mode. Encryption is implied (none for open, CCMP for WPA2). */
    struct key key;             /**< Shared key. Only valid for @a auth_mode_wpa2psk. */
    bool backhaul;              /**< Is backhaul AP */
    bool fronthaul;             /**< Is fronthaul AP */
    uint8_t rf_bands;           /**< Bitmask of WPS_RF_24GHZ, WPS_RF_50GHZ, WPS_RF_60GHZ. */
};

struct _qdockData
{
    struct ubus_subscriber notification;
    uint32_t intf_objid;
    uint32_t mlme_objid;
    uint32_t stas_objid;

    dlist_head creating_bsses;
};

#endif // PLATFORM_QDOCK_H
