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
 * @brief header file for MAP roaming logic
 *
 */

#ifndef MAP_STEERING_H
#define MAP_STEERING_H


struct qSteeringPocicyItem {
    dlist_item l;
    struct alDevice *device;
    mac_address radio_id;
    uint8_t repoting_interval;
    uint8_t rcpi_threshold;
};

struct qSteeringCandidateBSS {
    dlist_item  l;
    mac_address bssid;
    struct alDevice *dev;
    uint8_t opclass;
    uint8_t chan;
    uint8_t measured_rcpi;
    uint32_t measured_timestamp;
};

struct qSteeringSTAEntry {
    dlist_item  l;
    bool is_steering;
    bool btm_allowed;
    mac_address sta_mac;
    mac_address target_bssid;
    uint8_t rcpi;
    uint32_t last_ts;
    uint32_t steered_ts;
    struct alDevice *device;
    struct interfaceWifi *assoc_ifw;
    struct dlist_head candidates;
    void *collecting_sta_rcpi_timer;
};

/** @brief map steering config
*
*/
struct mapSteeringConfig {
    uint8_t steering_enabled;
    uint8_t steering_actived;
    uint8_t rcpi_boundry_to_attemp_steering;
    uint8_t better_rcpi_gain_in_target_bss;
    uint8_t assoc_sta_rcpi_checking_period;
    int     waiting_for_neighboring_rcpi_collecting_done;
    int     waiting_for_steering_attemp_done;
    int     debugging_print_level;
};

extern struct mapSteeringConfig map_steering_config;

struct qSteeringPolicyConfig {
    dlist_head policy_head;
};

extern struct qSteeringPolicyConfig qsteering_policy_config;

void qsteering_printf_debug_error(const char *func, uint32_t line, const char *format, ...);
void qsteering_printf_debug_warning(const char *func, uint32_t line, const char *format, ...);
void qsteering_printf_debug_info(const char *func, uint32_t line, const char *format, ...);
void qsteering_printf_debug_detail(const char *func, uint32_t line, const char *format, ...);

#define QSTEERING_PRINTF_DEBUG_ERROR(...) qsteering_printf_debug_error(__FUNCTION__, __LINE__, __VA_ARGS__)
#define QSTEERING_PRINTF_DEBUG_WARNING(...) qsteering_printf_debug_warning(__FUNCTION__, __LINE__, __VA_ARGS__)
#define QSTEERING_PRINTF_DEBUG_INFO(...) qsteering_printf_debug_info(__FUNCTION__, __LINE__, __VA_ARGS__)
#define QSTEERING_PRINTF_DEBUG_DETAIL(...) qsteering_printf_debug_detail(__FUNCTION__, __LINE__, __VA_ARGS__)

/** @brief  restore the steering configuration to default, and active it only at controller side*/
void defaultQSteeringConfig(void);

void qSteeringSendApCapabilityQuery(struct alDevice *device);

int qSteeringAddPolicyConfigReqForAssocedSTAMetric(struct alDevice *device, const mac_address uid);

void qSteeringDeleteAllEntries(struct alDevice *device);

#if 0 /* implementation for sta beacon metric query is not required in the first phrase design*/
int qSteeringSendBeaconMetricQueryForCandidateBSS(struct alDevice *device, struct interfaceWifi *assoced_ifw, struct staInfo *sta);
#endif

void qSteeringCheckAssocSTARCPI(struct alDevice *device, struct interfaceWifi *assoced_ifw,
	struct staInfo *sta, uint8_t rcpi, uint32_t last_ts);

int qSteeringUpdateUnassocSTARCPI(struct alDevice *device, uint8_t *sta_mac, uint8_t observed_rcpi, uint32_t ts, uint8_t band);

void qSteeringUpdateBTMAllowed(uint8_t *sta_mac, bool btm_allowed);

void qSteeringCheckSteeringSTAEntryForNewAssociation(uint8_t *bssid, uint8_t *sta_mac);

void qSteeringResendPolicyConfig(void);

/** @brief start qsteering logic in periodical */
void startQSteering();

/** @brief stop qsteering logic */
void stopQSteering();

#endif
