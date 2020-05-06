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

#ifndef _AL_RETRY_H_
#define _AL_RETRY_H_

struct cmdu_retry
{
    dlist_item l;           /**< @brief Membership of the retry list head */
    void *timer;            /**< @brief Retry timer context */
    uint8_t retries;        /**< @brief Retry numbers */
    struct CMDU *cmdu;      /**< @brief CMDU needed to be retried */
    char *ifname;           /**< @brief CMDU sent from */
    mac_address dst_addr;   /**< @brief CMDU sent to */
};

// This function inits the cmdu retry module
//
void initCmduRetry(void);

// This function de-inits the cmdu retry module
//
void deinitCmduRetry(void);

// This function check and fire the retry timer for cmdu
// Called when the CMDU needed to wait response/ack
//
uint8_t checkAndFireRetryTimer(const char *ifname, const uint8_t *dst_addr, struct CMDU *cmdu);

// This function check and remove the cmdu for retry
// Called when receiving the response/ack
//
void checkAndStopRetryTimer(const uint8_t *src_addr, uint16_t mtype, uint16_t mid);

#endif
