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
 * @brief Driver interface for local ini file
 *
 * This file provides functionality
 *
 */

#include "../ini.h"
#include "datamodel.h"
#include "../al.h"

#define CTC_SSID_KEY "ssid"
#define CTC_AUTH_KEY "auth"
#define CTC_ENCRYPT_KEY "encrypt"
#define CTC_BACKHAUL_KEY "backhaul"
#define CTC_FRONTHAUL_KEY "fronthaul"
#define CTC_KEY_KEY "pwd"
#define CTC_SSID_DASH "_"

struct local_radio_config {
    dlist_head head;
    uint8_t rf_bands;
    char last_fail_key[8];
};

static int parse_key_value(struct wscRegistrarInfo *wsc, char *key, char *value)
{
    int ret = 0;
    if (!strcmp(key, CTC_SSID_KEY)) {
        memcpy(wsc->bss_info.ssid.ssid, value, strlen(value));
        wsc->bss_info.ssid.length = strlen(value);
    } else if (!strcmp(key, CTC_AUTH_KEY)) {
        if (!strcmp(value, "WPA/WPA2-PSK") || !strcmp(value, "WPA2-PSK")) {
            wsc->bss_info.auth_mode = auth_mode_wpa2psk;
        }
    } else if (!strcmp(key, CTC_ENCRYPT_KEY)) {
        if (!strcmp(value, "WEP"))
            ret = -1;
    } else if (!strcmp(key, CTC_BACKHAUL_KEY)) {
        if (!strcmp(value, "1"))
            wsc->bss_info.backhaul = 1;
    } else if (!strcmp(key, CTC_FRONTHAUL_KEY)) {
        if (!strcmp(value, "1"))
            wsc->bss_info.fronthaul = 1;
    } else if (!strcmp(key, CTC_KEY_KEY)) {
        wsc->bss_info.key.len = strlen(value);
        memcpy(wsc->bss_info.key.key, value, wsc->bss_info.key.len);
    }
    return ret;
}

static void set_default_wsc(struct wscRegistrarInfo *wsc)
{
    wsc->bss_info.auth_mode = auth_mode_open;
}

static int parse_config_ini(void *p, const char *section, const char *name, const char *value)
{
    struct local_radio_config *c = (struct local_radio_config *)p;
    dlist_head *head = &c->head;
    if ((name) && (value)) {
        char *key;
        struct wscRegistrarInfo *cur_wsc = NULL;
        if (!dlist_empty(head))
            cur_wsc = container_of(dlist_get_last(head), struct wscRegistrarInfo, l);
        if (memcmp(name, CTC_SSID_KEY, strlen(CTC_SSID_KEY))==0){
            if ((key = strstr(name, CTC_SSID_DASH))) {
                *key = '\0';
                key++;
            } else key = CTC_SSID_KEY;
            if (strlen(name)!=strlen(CTC_SSID_KEY)) //vap configuration
            {
                if (!(strcmp(name, c->last_fail_key)))
                    return 0;
                if ((!cur_wsc) || strcmp((const char *)cur_wsc->key, name)) {//new wsc
                    cur_wsc = zmemalloc(sizeof(struct wscRegistrarInfo));
                    memset(c->last_fail_key, 0, 8);
                    set_default_wsc(cur_wsc);
                    strcpy((char *)cur_wsc->key, (const char *)name);
                    cur_wsc->rf_bands  = c->rf_bands;
                    dlist_add_tail(head, &cur_wsc->l);
                }
                if (parse_key_value(cur_wsc, key, (char *)value)) {
                    strcpy(c->last_fail_key, name);
                    dlist_remove(&cur_wsc->l);
                    free(cur_wsc);
                }
            }
        }
    }
    return 0;
}

static void local_registrar_sync_bssconfigs(void)
{
    struct wscRegistrarInfo *wsc, *p;
    struct local_radio_config local_cfgs;

    dlist_head_init(&local_cfgs.head);
    if (map_config.ini5) {
        memset(local_cfgs.last_fail_key, 0, 8);
        local_cfgs.rf_bands = WPS_RF_50GHZ;
        ini_parse(map_config.ini5, parse_config_ini, &local_cfgs);
    }
    if (map_config.ini2) {
        memset(local_cfgs.last_fail_key, 0, 8);
        local_cfgs.rf_bands = WPS_RF_24GHZ;
        ini_parse(map_config.ini2, parse_config_ini, &local_cfgs);
    }
    dlist_for_each_safe(wsc, p, local_cfgs.head, l){
        dlist_remove(&wsc->l);
        if (!WSCINFO_FLAG_IS_SET(registrarUpdateWsc(wsc), NEW_CREATED))
            free(wsc);
    }
    if (registrarCommitWsc())
    {
        tiggerAPAutoconfigurationRenewProcess();
    }
}

static struct registrarHandles local_registrar_ops =
{
    .syncBssCfgs               = local_registrar_sync_bssconfigs,
};

void local_collect_local_registrar()
{
    registrarRegisterHandlers(&local_registrar_ops);
}

