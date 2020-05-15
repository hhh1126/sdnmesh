/*
 *  Copyright (c) 2019, Semiconductor Components Industries, LLC
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
 * @brief AL MAP ubus functions define
 *
 */

#ifndef UBUS_MAP_H
#define UBUS_MAP_H

#include <datamodel.h>

void mapapi_free_dlist_chan_stas(dlist_head *head);
void mapapi_event_receive_hldata(uint8_t proto, uint8_t *src, uint8_t *dest, uint8_t *data, uint16_t data_len);
void mapapi_event_duplicated_controller_detected(struct alDevice *dev, uint16_t msg_type);
void mapapi_event_duplicated_registrar_detected(struct alDevice *dev);
void mapapi_event_rogue_renew_detected(mac_address alid);
void mapapi_event_agent_configured(void);
void mapapi_event_steering_candidates_needed(mac_address bssid, dlist_head *stations);
void mapapi_event_steering_opportunity(uint16_t steering_window, mac_address cur_bssid, dlist_head *stations);
void mapapi_event_receive_btm_response(uint8_t *ta, uint8_t *ra, uint8_t *frame, uint32_t frame_len);
void mapapi_event_client_associated(uint8_t *radio, uint8_t *bssid, uint8_t *ssid, uint8_t ssid_len,
    uint8_t *sta, uint8_t be_local);
void mapapi_event_receive_frame(uint8_t *src, uint8_t *dest, uint16_t type, dlist_head *tlv_list);
#endif
