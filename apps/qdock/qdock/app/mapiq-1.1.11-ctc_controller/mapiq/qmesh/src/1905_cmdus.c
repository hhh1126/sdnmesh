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
 *
 *  Portions of this software may include:
 *  Broadband Forum IEEE 1905.1/1a stack
 *  Copyright (c) 2017, Broadband Forum
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

#include "platform.h"
#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "1905_l2.h"
#include "packet_tools.h"
#include "tlv.h"

/** @brief Specification of the constraint of how many times a something may occur. */
enum count_required {
    count_required_zero = 0,      /**< @brief TLV is not allowed in this CMDU. */
    count_required_zero_or_one,   /**< @brief TLV is optional in this CMDU. */
    count_required_zero_or_more,  /**< @brief TLV is optional and may occur several times in this CMDU. */
    count_required_one,           /**< @brief TLV is required in this CMDU. */
    count_required_one_or_more,   /**< @brief TLV is required and may occur several times in this CMDU. */
    /** @brief Sentinel value marking the end of an array of cmdu_tlv_count_required.
     *
     * This takes the value 0, so that automatic 0 initialisation fills in the sentinel.
     *
     * It can also be the same value as count_required_zero because the latter doesn't occur in a
     * cmdu_tlv_count_required list: TLVs that are required not to be present are simply not mentioned in the list.
     */
    count_required_sentinel = 0,
};

/** @brief Specification of the constraint of how many times a specific TLV type may occur in a CMDU. */
struct cmdu_tlv_count_required {
    uint8_t type;               /**< TLV type to which this constraint applies. */
    enum count_required count;  /**< The constraint for this TLV type. count_required_zero is not used. */
};

/** @brief Static information about CMDUs. */
struct cmdu_info {
    /** @brief List of constraints of how many times each TLV type may occur in a CMDU.
     *
     * TLV types that are not allowed do not appear in the list.
     *
     * The list is an array where the last entry has cmdu_tlv_count_required::count_required == count_required_sentinel.
     */
    const struct cmdu_tlv_count_required *tlv_count_required;
};

/** @brief Definition of the static information of each CMDU type.
 *
 * This array is indexed by CMDU type.
 */
static const struct cmdu_info cmdu_info[] =
{
    [CMDU_TYPE_TOPOLOGY_DISCOVERY] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_AL_MAC_ADDRESS_TYPE, count_required_one},
            {TLV_TYPE_MAC_ADDRESS_TYPE, count_required_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_TOPOLOGY_NOTIFICATION] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_AL_MAC_ADDRESS_TYPE, count_required_one},
            {TLV_TYPE_CLIENT_ASSOCIATION_EVENT, count_required_zero_or_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_TOPOLOGY_RESPONSE] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            /* "IEEE Std 1905.1-2013, Section 6.3.3" */
            {TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES, count_required_zero_or_more},
            {TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST, count_required_zero_or_more},
            {TLV_TYPE_NEIGHBOR_DEVICE_LIST, count_required_zero_or_more},
            {TLV_TYPE_POWER_OFF_INTERFACE, count_required_zero_or_more},
            {TLV_TYPE_L2_NEIGHBOR_DEVICE, count_required_zero_or_more},
            {TLV_TYPE_DEVICE_INFORMATION_TYPE, count_required_one},
            /* "Multi-AP Specification Version 1.0, Section 17.1.4" */
            /* Multi-AP 1.0 is inconsistent: Section 6.2 says this is required, Section 17.1.4 says it's optional.
             * Since we also need to support non-Multi-AP devices, it is optional. */
            {TLV_TYPE_SUPPORTED_SERVICE, count_required_zero_or_one},
            /* Multi-AP requires exactly 1. However a non-Multi-AP device will not send it, so accept 0 as well. */
            {TLV_TYPE_AP_OPERATIONAL_BSS, count_required_zero_or_one},
            {TLV_TYPE_ASSOCIATED_CLIENTS, count_required_zero_or_one},
            {0, count_required_sentinel},
        },
    },
    /* CMDU_TYPE_VENDOR_SPECIFIC is a special case since any TLV is allowed. */
    [CMDU_TYPE_LINK_METRIC_QUERY] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_LINK_METRIC_QUERY, count_required_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_LINK_METRIC_RESPONSE] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_TRANSMITTER_LINK_METRIC, count_required_zero_or_more},
            {TLV_TYPE_RECEIVER_LINK_METRIC, count_required_zero_or_more},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_AL_MAC_ADDRESS_TYPE, count_required_one},
            {TLV_TYPE_SEARCHED_ROLE, count_required_one},
            {TLV_TYPE_AUTOCONFIG_FREQ_BAND, count_required_one},
            {TLV_TYPE_SUPPORTED_SERVICE, count_required_zero_or_one},
            {TLV_TYPE_SEARCHED_SERVICE, count_required_zero_or_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_SUPPORTED_ROLE, count_required_one},
            {TLV_TYPE_SUPPORTED_FREQ_BAND, count_required_one},
            {TLV_TYPE_SUPPORTED_SERVICE, count_required_zero_or_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_AP_AUTOCONFIGURATION_WSC] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_WSC, count_required_one_or_more}, // More is only possible if sender is Multi-AP Controller
            {TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES, count_required_zero_or_one}, // One iff sender is Multi-AP Agent
            {TLV_TYPE_AP_RADIO_IDENTIFIER, count_required_zero_or_one}, // One iff sender is Multi-AP Controller
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_AL_MAC_ADDRESS_TYPE, count_required_one},
            {TLV_TYPE_SUPPORTED_ROLE, count_required_one},
            {TLV_TYPE_SUPPORTED_FREQ_BAND, count_required_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION, count_required_zero_or_one},
            {TLV_TYPE_AL_MAC_ADDRESS_TYPE, count_required_one},
            {TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION, count_required_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_AL_MAC_ADDRESS_TYPE, count_required_one},
            {TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION, count_required_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_HIGHER_LAYER_RESPONSE] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_CONTROL_URL, count_required_zero_or_one},
            {TLV_TYPE_IPV4, count_required_zero_or_one},
            {TLV_TYPE_IPV6, count_required_zero_or_one},
            {TLV_TYPE_AL_MAC_ADDRESS_TYPE, count_required_one},
            {TLV_TYPE_1905_PROFILE_VERSION, count_required_one},
            {TLV_TYPE_DEVICE_IDENTIFICATION, count_required_one},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION, count_required_one_or_more},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS, count_required_one_or_more},
            {0, count_required_sentinel},
        },
    },
    [CMDU_TYPE_GENERIC_PHY_RESPONSE] = {
        .tlv_count_required = (const struct cmdu_tlv_count_required[]){
            {TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION, count_required_one},
            {0, count_required_sentinel},
        },
    },
};

#define MAP_CMDU_INFO_BEGIN(_a)     \
        [CMDU_TYPE_##_a - CMDU_TYPE_DEFINED_IN_MAP_FIRST] = {      \
            .tlv_count_required = (const struct cmdu_tlv_count_required[]){
#define MAP_CMDU_INFO_TLV(_a, _b)       {TLV_TYPE_##_a, count_required_##_b}
#define MAP_CMDU_INFO_END()             {0, count_required_sentinel},},}
/** @brief Definition of the static information of each CMDU type defined in Multi-AP Technical Specification .
 *
 * This array is indexed by CMDU type - CMDU_TYPE_DEFINED_IN_MAP_FIRST.
 */
static const struct cmdu_info map_cmdu_info[] =
{
    MAP_CMDU_INFO_BEGIN(ACK)
        MAP_CMDU_INFO_TLV(ERROR_CODE, zero_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(AP_CAPABILITY_QUERY)
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(AP_CAPABILITY_REPORT)
        MAP_CMDU_INFO_TLV(AP_CAPABILITY, one),
        MAP_CMDU_INFO_TLV(AP_RADIO_BASIC_CAPABILITIES, one_or_more),
        MAP_CMDU_INFO_TLV(AP_HT_CAPABILITIES, zero_or_more),
        MAP_CMDU_INFO_TLV(AP_VHT_CAPABILITIES, zero_or_more),
        MAP_CMDU_INFO_TLV(AP_HE_CAPABILITIES, zero_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(MAP_POLICY_CONFIG_REQUEST)
        MAP_CMDU_INFO_TLV(STEERING_POLICY, zero_or_one),
        MAP_CMDU_INFO_TLV(METRIC_REPORTING_POLICY, zero_or_one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CHANNEL_PREFERENCE_QUERY)
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CHANNEL_PREFERENCE_REPORT)
        MAP_CMDU_INFO_TLV(CHANNEL_PREFERENCE, zero_or_more),
        MAP_CMDU_INFO_TLV(RADIO_OPERATION_RESTRICTION, zero_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CHANNEL_SELECTION_REQUEST)
        MAP_CMDU_INFO_TLV(CHANNEL_PREFERENCE, zero_or_more),
        MAP_CMDU_INFO_TLV(TRANSMIT_POWER_LIMIT, zero_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CHANNEL_SELECTION_RESPONSE)
        MAP_CMDU_INFO_TLV(CHANNEL_SELECTION_RESPONSE, one_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(OPERATING_CHANNEL_REPORT)
        MAP_CMDU_INFO_TLV(OPERATING_CHANNEL_REPORT, one_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CLIENT_CAPABILITY_QUERY)
        MAP_CMDU_INFO_TLV(CLIENT_INFO, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CLIENT_CAPABILITY_REPORT)
        MAP_CMDU_INFO_TLV(CLIENT_INFO, one),
        MAP_CMDU_INFO_TLV(CLIENT_CAPABILITY_REPORT, one),
        MAP_CMDU_INFO_TLV(ERROR_CODE, zero_or_one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(AP_METRICS_QUERY)
        MAP_CMDU_INFO_TLV(AP_METRIC_QUERY, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(AP_METRICS_RESPONSE)
        MAP_CMDU_INFO_TLV(AP_METRICS, one_or_more),
        MAP_CMDU_INFO_TLV(ASSOCIATED_STA_TRAFFIC_STATS, zero_or_more),
        MAP_CMDU_INFO_TLV(ASSOCIATED_STA_LINK_METRICS, zero_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(ASSOCIATED_STA_LINK_METRICS_QUERY)
        MAP_CMDU_INFO_TLV(STA_MAC_ADDRESS, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(ASSOCIATED_STA_LINK_METRICS_RESPONSE)
        MAP_CMDU_INFO_TLV(ASSOCIATED_STA_LINK_METRICS, one_or_more),
        MAP_CMDU_INFO_TLV(ERROR_CODE, zero_or_one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(UNASSOCIATED_STA_LINK_METRICS_QUERY)
        MAP_CMDU_INFO_TLV(UNASSOCIATED_STA_LINK_METRICS_QUERY, one_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(UNASSOCIATED_STA_LINK_METRICS_RESPONSE)
        MAP_CMDU_INFO_TLV(UNASSOCIATED_STA_LINK_METRICS_RESPONSE, one),
        MAP_CMDU_INFO_TLV(ERROR_CODE, zero_or_one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(BEACON_METRICS_QUERY)
        MAP_CMDU_INFO_TLV(BEACON_METRICS_QUERY, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(BEACON_METRICS_RESPONSE)
        MAP_CMDU_INFO_TLV(BEACON_METRICS_RESPONSE, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(COMBINED_INFRASTRUCTURE_METRICS)
        MAP_CMDU_INFO_TLV(AP_METRICS, one_or_more),
        MAP_CMDU_INFO_TLV(TRANSMITTER_LINK_METRIC, zero_or_more),
        MAP_CMDU_INFO_TLV(RECEIVER_LINK_METRIC, zero_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CLIENT_STEERING_REQUEST)
        MAP_CMDU_INFO_TLV(STEERING_REQUEST, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CLIENT_STEERING_BTM_REPORT)
        MAP_CMDU_INFO_TLV(STEERING_BTM_REPORT, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CLIENT_ASSOCIATION_CONTROL)
        MAP_CMDU_INFO_TLV(CLIENT_ASSOCIATION_CONTROL_REQUEST, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(STEERING_COMPLETED)
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(HIGHER_LAYER_DATA)
        MAP_CMDU_INFO_TLV(HIGHER_LAYER_DATA, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(BACKHAUL_STEERING_REQUEST)
        MAP_CMDU_INFO_TLV(BACKHAUL_STEERING_REQUEST, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(BACKHAUL_STEERING_RESPONSE)
        MAP_CMDU_INFO_TLV(BACKHAUL_STEERING_RESPONSE, one),
        MAP_CMDU_INFO_TLV(ERROR_CODE, zero_or_one),
    MAP_CMDU_INFO_END(),

    /* profile 2 */
    MAP_CMDU_INFO_BEGIN(CHANNEL_SCAN_REQUEST)
        MAP_CMDU_INFO_TLV(CHANNEL_SCAN_REQUEST, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CHANNEL_SCAN_REPORT)
        MAP_CMDU_INFO_TLV(TIMESTAMP, one),
        MAP_CMDU_INFO_TLV(CHANNEL_SCAN_RESULT, one_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CAC_REQUEST)
        MAP_CMDU_INFO_TLV(CAC_REQUEST, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CAC_TERMINATION)
        MAP_CMDU_INFO_TLV(CAC_TERMINATION, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(CLIENT_DISASSOCIATION_STATS)
        MAP_CMDU_INFO_TLV(STA_MAC_ADDRESS, one),
        MAP_CMDU_INFO_TLV(REASON_CODE, one),
        MAP_CMDU_INFO_TLV(ASSOCIATED_STA_TRAFFIC_STATS, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(ERROR_RESPONSE)
        MAP_CMDU_INFO_TLV(PROFILE2_ERROR_CODE, one_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(ASSOCIATION_STATUS_NOTIFICATION)
        MAP_CMDU_INFO_TLV(ASSOCIATION_STATUS_NOTIFICATION, one),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(TUNNELED)
        MAP_CMDU_INFO_TLV(SOURCE_INFO, one),
        MAP_CMDU_INFO_TLV(TUNNELED_MESSAGE_TYPE, one),
        MAP_CMDU_INFO_TLV(TUNNELED, one_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(BACKHAUL_STA_CAPABILITY_QUERY)
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(BACKHAUL_STA_CAPABILITY_REPORT)
        MAP_CMDU_INFO_TLV(BACKHAUL_STA_RADIO_CAPABILITIES, zero_or_more),
    MAP_CMDU_INFO_END(),

    MAP_CMDU_INFO_BEGIN(FAILED_CONNECTION)
        MAP_CMDU_INFO_TLV(STA_MAC_ADDRESS, one),
        MAP_CMDU_INFO_TLV(STATUS_CODE, one),
        MAP_CMDU_INFO_TLV(REASON_CODE, zero_or_one),
    MAP_CMDU_INFO_END(),
};

static inline const struct cmdu_tlv_count_required *_get_CMDU_tlv_required_counts(uint16_t message_type)
{
    if (message_type <= CMDU_TYPE_DEFINED_IN_1905_LAST)
        return cmdu_info[message_type].tlv_count_required;
    if (message_type >= CMDU_TYPE_DEFINED_IN_MAP_FIRST
        && message_type <= CMDU_TYPE_DEFINED_IN_MAP_LAST)
        return map_cmdu_info[message_type - CMDU_TYPE_DEFINED_IN_MAP_FIRST].tlv_count_required;
    return NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Auxiliary, static tables
////////////////////////////////////////////////////////////////////////////////

// The following table tells us the value of the 'relay_indicator' flag for
// each type of CMDU message.
//
// The values were obtained from "IEEE Std 1905.1-2013, Table 6-4"
//
// Note that '0xff' is a special value that means: "this CMDU message type can
// have the flag set to either '0' or '1' and its actual value for this
// particular message must be specified in some other way"
//
static uint8_t _relayed_CMDU[] = \
{
    /* CMDU_TYPE_TOPOLOGY_DISCOVERY             */  0,
    /* CMDU_TYPE_TOPOLOGY_NOTIFICATION          */  1,
    /* CMDU_TYPE_TOPOLOGY_QUERY                 */  0,
    /* CMDU_TYPE_TOPOLOGY_QUERY                 */  0,
    /* CMDU_TYPE_VENDOR_SPECIFIC                */  0xff,
    /* CMDU_TYPE_LINK_METRIC_QUERY              */  0,
    /* CMDU_TYPE_LINK_METRIC_RESPONSE           */  0,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH    */  1,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE  */  0,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_WSC       */  0,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW     */  1,
    /* CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION */  1,
    /* CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION  */  1,
    /* CMDU_TYPE_HIGHER_LAYER_QUERY             */  0,
    /* CMDU_TYPE_HIGHER_LAYER_RESPONSE          */  0,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST */  0,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE*/  0,
    /* CMDU_TYPE_GENERIC_PHY_QUERY              */  0,
    /* CMDU_TYPE_GENERIC_PHY_RESPONSE           */  0,
};

static inline uint8_t _get_CMDU_relay_indicator(uint16_t message_type)
{
    if (message_type <= CMDU_TYPE_DEFINED_IN_1905_LAST)
        return _relayed_CMDU[message_type];

    // realy indicator for CMDU message defined in "Multi-AP Technical Specification, Table 5"
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Auxiliary static functions
////////////////////////////////////////////////////////////////////////////////

// Each CMDU must follow some rules regarding which TLVs they can contain
// depending on their type.
//
// This is extracted from "IEEE Std 1905.1-2013, Section 6.2":
//
//   1. When generating a CMDU:
//      a) It shall include all of the TLVs that are listed for the message
//      b) It shall not include any other TLV that is not listed for the message
//      c) It may additionally include zero or more vendor specific TLVs
//
//   2. When receiving a CMDU:
//      a) It may process or ignore any vendor specific TLVs
//      b) It shall ignore all TLVs that are not specified for the message
//      c) It shall ignore the entire message if the message does not include
//         all of the TLVs that are listed for this message
//
// This function receives a pointer to a CMDU structure, 'p' and a 'rules_type'
// value:
//
//   * If 'rules_type' == CHECK_CMDU_TX_RULES, the function will check the
//     structure against the "generating a CMDU" rules (ie. rules 1.a, 1.b and
//     1.c).
//     If any of them is broken this function returns "0" (and 'p' is *not*
//     freed, as this is the caller's responsability)
//
//   * If 'rules_type' == CHECK_CMDU_RX_RULES, the function will check the
//     structure against the "receiving a CMDU" rules (ie. rules 2.a, 2.b and
//     2.c)
//     Regarding rule 2.a, we have chosen to preserve vendor specific TLVs in
//     the structure.
//     Rule 2.b is special in that non-vendor specific TLVs that are not
//     specified for the message type are removed (ie. the 'p' structure is
//     modified!)
//     Rule 2.c is special in that if it is broken, 'p' is freed
//
//  Note a small asymmetry: with 'rules_type' == CHECK_CMDU_TX_RULES,
//  unexpected options cause the function to fail while with 'rules_type' ==
//  CHECK_CMDU_RX_RULES they are simply removed (and freed) from the structure.
//  If you think about it, this is the correct behaviour: in transmission,
//  do not let invalid packets to be generated, while in reception, if invalid
//  packets are receive, ignore the unexpected pieces but process the rest.
//
//  In both cases, this function returns:
//    '0' --> If 'p' did not respect the rules and could not be "fixed"
//    '1' --> If 'p' was modified (ie. it is now valid). This can only happen
//            when 'rules_type' == CHECK_CMDU_RX_RULES
//    '2' --> If 'p' was not modifed (ie. it was valid from the beginning)
//
#define CHECK_CMDU_TX_RULES (1)
#define CHECK_CMDU_RX_RULES (2)
static uint8_t _check_CMDU_rules(const struct CMDU *p, uint8_t rules_type)
{
    unsigned  i;
    uint8_t  structure_has_been_modified;
    uint8_t  counter[TLV_TYPE_NUM];
    uint8_t  tlvs_to_remove[TLV_TYPE_NUM];

    if ((NULL == p) || (NULL == p->list_of_TLVs))
    {
        // Invalid arguments
        //
        PLATFORM_PRINTF_DEBUG_ERROR("Invalid CMDU structure\n");
        return 0;
    }

    // First of all, count how many times each type of TLV message appears in
    // the structure. We will use this information later
    //
    for (i=0; i<TLV_TYPE_NUM; i++)
    {
        counter[i]        = 0;
        tlvs_to_remove[i] = 0;
    }

    i = 0;
    while (NULL != p->list_of_TLVs[i])
    {
        counter[p->list_of_TLVs[i]->type]++;
        i++;
    }

    for (i=0; i<TLV_TYPE_NUM; i++)
    {
        enum count_required required_count = count_required_zero;

        // Search the required count
        if (p->message_id == CMDU_TYPE_VENDOR_SPECIFIC)
        {
            // Special case for vendor specific CMDU: it can contain any TLV
            required_count = count_required_zero_or_more;
        }
        else if (i == TLV_TYPE_VENDOR_SPECIFIC)
        {
            // Special case for vendor specific TLV: it is always allowed
            required_count = count_required_zero_or_more;
        }
        else if (_get_CMDU_tlv_required_counts(p->message_type) == NULL)
        {
            // No required counts specified for this CMDU, so required count is 0 for all TLVs
            required_count = count_required_zero;
        }
        else
        {
            const struct cmdu_tlv_count_required *count_required;
            for (count_required = _get_CMDU_tlv_required_counts(p->message_type);
                 count_required->count != count_required_sentinel;
                 count_required++)
            {
                if (count_required->type == i)
                {
                    required_count = count_required->count;
                    break;
                }
            }
            /* If not found in the list, required_count is still zero. */
        }

        switch (required_count)
        {
            case count_required_zero:
                // Rules 1.b and 2.b both check for the same thing (unexpected TLVs),
                // but they act in different ways:
                //
                //   * In case 'rules_type' == CHECK_CMDU_TX_RULES, return '0'
                //   * In case 'rules_type' == CHECK_CMDU_RX_RULES, remove the unexpected
                //     TLVs (and later, when all other checks have been performed, return
                //     '1' to indicate that the structure has been modified)
                if (counter[i] != 0)
                {
                    if (CHECK_CMDU_TX_RULES == rules_type)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("TLV %s should not appear on this CMDU, but it appears %d times\n", convert_1905_TLV_type_to_string(i), counter[i]);
                        return 0;
                    }
                    else
                    {
                        tlvs_to_remove[i] = 1;
                    }
                }
                break;
            case count_required_zero_or_more:
                // Nothing to check, always OK.
                break;
            case count_required_zero_or_one:
                // Rule 1.b requires this TLV to be present no more than once.
                // Rule 2.b requires us to ignore the unexpected TLVs. However, that rule doesn't say which one should
                // be ignored and which one to take into account. So it makes sense to ignore the entire CMDU instead.
                // So in both cases, we return 0 if the TLV occurs more than once.
                if (counter[i] > 1)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("TLV %s should appear at most once on this CMDU, but it appears %d times\n",
                                                  convert_1905_TLV_type_to_string(i), counter[i]);
                    return 0;
                }
                break;
            case count_required_one:
                // Rules 1.a and 2.c check the same thing : make sure the structure
                // contains, *at least*, the required TLVs
                //
                // If not, return '0'
                if (counter[i] != 1)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("TLV %s should appear once on this CMDU, but it appears %d times\n", convert_1905_TLV_type_to_string(i), counter[i]);
                    return 0;
                }
                break;

            case count_required_one_or_more:
                // Rules 1.a and 2.c check the same thing : make sure the structure
                // contains, *at least*, the required TLVs
                //
                // If not, return '0'
                if (counter[i] == 0)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("TLV %s should appear at least once on this CMDU, but it appears %d times\n", convert_1905_TLV_type_to_string(i), counter[i]);
                    return 0;
                }
                break;

            default:
                PLATFORM_PRINTF_DEBUG_ERROR("Programming error: invalid required count %u\n", required_count);
                return 0;
        }
    }

    i = 0;
    structure_has_been_modified = 0;
    while (NULL != p->list_of_TLVs[i])
    {
        // Here we will just traverse the list of TLVs and remove the ones
        // that shouldn't be there.
        // When this happens, mark the structure as 'modified' so that we can
        // later return the appropriate return code.
        //
        //   NOTE:
        //     When removing TLVs they are first freed and the list of
        //     pointers ('list_of_TLVs') is simply overwritten.
        //     The original piece of memory that holds all pointers is not
        //     redimensioned, though, as it would make things unnecessary more
        //     complex.
        //     In other words:
        //
        //       Before removal:
        //         list_of_TLVs --> [p1, p2, p3, NULL]
        //
        //       After removing p2:
        //         list_of_TLVs --> [p1, p3, NULL, NULL]
        //
        //       ...and not:
        //         list_of_TLVs --> [p1, p3, NULL]
        //
        if (1 == tlvs_to_remove[p->list_of_TLVs[i]->type])
        {
            uint8_t j;

            free_1905_TLV_structure(p->list_of_TLVs[i]);

            structure_has_been_modified = 1;
            j = i + 1;
            while (p->list_of_TLVs[j])
            {
                p->list_of_TLVs[j-1] = p->list_of_TLVs[j];
                j++;
            }
            p->list_of_TLVs[j-1] = p->list_of_TLVs[j];
        }
        else
        {
           i++;
        }
    }

    // Regarding rules 1.c and 2.a, we don't really have to do anything special,
    // thus we can return now
    //
    if (1 == structure_has_been_modified)
    {
        return 1;
    }
    else
    {
        return 2;
    }
}



////////////////////////////////////////////////////////////////////////////////
// Actual API functions
////////////////////////////////////////////////////////////////////////////////

struct CMDU *parse_1905_CMDU_from_packets(uint8_t **packet_streams, uint32_t *lens)
{
    struct CMDU *ret;

    uint8_t  fragments_nr;
    uint8_t  current_fragment;

    uint8_t  tlvs_nr;

    uint8_t  error;

    if (NULL == packet_streams)
    {
        // Invalid arguments
        //
        PLATFORM_PRINTF_DEBUG_ERROR("NULL packet_streams\n");
        return NULL;
    }

    // Find out how many streams/fragments we have received
    //
    fragments_nr = 0;
    while (*(packet_streams+fragments_nr))
    {
        fragments_nr++;
    }
    if (0 == fragments_nr)
    {
        // No streams supplied!
        //
        PLATFORM_PRINTF_DEBUG_ERROR("No fragments supplied\n");
        return NULL;
    }

    // Allocate the return structure.
    // Initially it will contain an empty list of TLVs that we will later
    // re-allocate and fill.
    //
    ret = new_CMDU();
    ret->list_of_TLVs = (struct tlv **)memalloc(sizeof(struct tlv *) * 1);
    ret->list_of_TLVs[0] = NULL;
    tlvs_nr = 0;

    // Next, parse each fragment
    //
    error = 0;
    for (current_fragment = 0; current_fragment<fragments_nr; current_fragment++)
    {
        const uint8_t *p, *e;
        uint8_t i;

        uint8_t   message_version;
        uint8_t   reserved_field;
        uint16_t  message_type;
        uint16_t  message_id;
        uint8_t   fragment_id;
        uint8_t   indicators;

        uint8_t   relay_indicator;
        uint8_t   last_fragment_indicator;

        struct tlv *parsed;

        // We want to traverse fragments in order, thus lets search for the
        // fragment whose 'fragment_id' matches 'current_fragment' (which will
        // monotonically increase starting at '0')
        //
        for (i=0; i<fragments_nr; i++)
        {
            p = *(packet_streams+i);
            e = p + *(lens + i);

            // The 'fragment_id' field is the 7th byte (offset 6)
            //
            if (current_fragment == *(p+6))
            {
                break;
            }
        }
        if (i == fragments_nr)
        {
            // One of the fragments is missing!
            //
            error = 1;
            break;
        }

        // At this point 'p' points to the stream whose 'fragment_id' is
        // 'current_fragment'

        // Let's parse the header fields
        //
        _E1B(&p, &message_version);
        _E1B(&p, &reserved_field);
        _E2B(&p, &message_type);
        _E2B(&p, &message_id);
        _E1B(&p, &fragment_id);
        _E1B(&p, &indicators);

        last_fragment_indicator = (indicators & 0x80) >> 7; // MSB and 2nd MSB
        relay_indicator         = (indicators & 0x40) >> 6; // of the
                                                            // 'indicators'
                                                            // field

        if (0 == current_fragment)
        {
            // This is the first fragment, thus fill the 'common' values.
            // We will later (in later fragments) check that their values always
            // remain the same
            //
            ret->message_version = message_version;
            ret->message_type    = message_type;
            ret->message_id      = message_id;
            ret->relay_indicator = relay_indicator;
            ret->extra_info.flag = _check_register_message_type(ret->message_type);
        }
        else
        {
            // Check for consistency in all 'common' values
            //
           if (
                (ret->message_version != message_version) ||
                (ret->message_type    != message_type)    ||
                (ret->message_id      != message_id)      ||
                (ret->relay_indicator != relay_indicator)
              )
           {
               // Fragments with different common fields were detected!
               //
               error = 2;
               break;
           }
        }

        // Regarding the 'last_fragment_indicator' flag, the following condition
        // must be met: the last fragement (and only it!) must have it set to
        // '1'
        //
        if ((1 == last_fragment_indicator) && (current_fragment < fragments_nr-1))
        {
            // 'last_fragment_indicator' appeared *before* the last fragment
            //
            error = 4;
            break;
        }
        if ((0 == last_fragment_indicator) && (current_fragment == fragments_nr-1))
        {
            // 'last_fragment_indicator' did not appear in the last fragment
            //
            error = 5;
            break;
        }

        // We can now parse the TLVs. 'p' is pointing to the first one at this
        // moment
        //
        while (e >= p + 1 + 2)
        {
            uint8_t  tlv_type;
            uint16_t tlv_len;

            _E1B(&p, &tlv_type);
            _E2B(&p, &tlv_len);

            if (e < p + tlv_len)
            {
                error = 8;
                PLATFORM_PRINTF_DEBUG_WARNING("Fail Parsing TLV type %u.: value len is not enough(%u < %u) \n", tlv_type, e - p, tlv_len);
                break;
            }

            parsed = parse_1905_TLV_from_packet(p - 1 - 2);
            if (NULL == parsed)
            {
                uint16_t len = tlv_len;
                // Error while parsing a TLV
                // Dump TLV for visual inspection
                PLATFORM_PRINTF_DEBUG_WARNING("Parsing error TLV type %u. Dumping bytes: \n", tlv_type);

                // Limit dump length
                //
                if (len > 200)
                {
                    len = 200;
                }

                print_callback(PLATFORM_PRINTF_RAW_WARNING, "", len, "Payload", "%02x", p);
                error = 6;
                break;
            }

            if (TLV_TYPE_END_OF_MESSAGE == parsed->type)
            {
                // No more TLVs
                //
                free_1905_TLV_structure(parsed);
                break;
            }

            if (ret->extra_info.flag & CMDU_EXTRAFLAG_NOTIFY_WITH_PAYLOAD) {
                struct tlv_raw *raw = memalloc(sizeof(struct tlv_raw)+tlv_len);
                raw->tlv_type = tlv_type;
                raw->tlv_len = tlv_len;
                memcpy(raw->tlv, p, tlv_len);
                dlist_add_tail(&ret->extra_info.tlv_raws, &raw->l);
            }

            // Advance 'p' to the next TLV.
            //
            p += tlv_len;

            // do not store the unknown TLVs
            if (TLV_TYPE_UNKNOWN == parsed->type)
            {
                free_1905_TLV_structure(parsed);
                continue;
            }

            // Add this new TLV to the list (the list needs to be re-allocated
            // with more space first)
            //
            tlvs_nr++;
            ret->list_of_TLVs = (struct tlv **)memrealloc(ret->list_of_TLVs, sizeof(struct tlv *) * (tlvs_nr+1));
            ret->list_of_TLVs[tlvs_nr-1] = parsed;
            ret->list_of_TLVs[tlvs_nr]   = NULL;

            // The vendor specific TLV (see Table 6-7) as the first TLV followed by zero or more TLVs
            // (either TLVs defined in this specification or any vendor specific TLVs).
            //
            if (CMDU_TYPE_VENDOR_SPECIFIC == ret->message_type)
            {
                if (0 == current_fragment
                    && 1 == tlvs_nr)
                {
                    if (TLV_TYPE_VENDOR_SPECIFIC != parsed->type)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Drop the Vendor Message: The first TLV(%02x) is not VENDOR SPECIFIC TLV\n", parsed->type);
                        error = 7;
                    }

                    // Per the spec "The vendor specific TLV as the first TLV followed by zero or more TLVs
                    // (either TLVs defined in this specification or any vendor specific TLVs)."
                    // So we should parse the message per the vendor defined spec
                    // todo: process the vendor message per the Vendor specific OUI in this TLV
                    //
                    goto __end;
                }
            }
        }
        if (0 != error)
        {
            break;
        }
    }

__end:
    if (0 == error)
    {
        // Ok then... we now have our output structure properly filled.
        // However, there is one last battery of checks we must perform:
        //
        //   - CMDU_TYPE_VENDOR_SPECIFIC: The first TLV *must* be of type
        //     TLV_TYPE_VENDOR_SPECIFIC
        //
        //   - All the other message types: Some TLVs (different for each of
        //     them) can only appear once, others can appear zero or more times
        //     and others must be ignored.
        //     The '_check_CMDU_rules()' takes care of this for us.
        //
        PLATFORM_PRINTF_DEBUG_DETAIL("CMDU type: %s\n", convert_1905_CMDU_type_to_string(ret->message_type));

        if (CMDU_TYPE_VENDOR_SPECIFIC == ret->message_type)
        {
            if (NULL == ret->list_of_TLVs[0] || TLV_TYPE_VENDOR_SPECIFIC != ret->list_of_TLVs[0]->type)
            {
                error = 7;
            }
        }
        else
        {

            switch (_check_CMDU_rules(ret, CHECK_CMDU_RX_RULES))
            {
                case 0:
                {
                    // The structure was missing some required TLVs. This is
                    // a malformed packet which must be ignored.
                    //
                    PLATFORM_PRINTF_DEBUG_WARNING("Structure is missing some required TLVs\n");
                    PLATFORM_PRINTF_DEBUG_WARNING("List of present TLVs:\n");

                    {
                        uint8_t i;

                        i = 0;
                        while (ret->list_of_TLVs[i])
                        {
                            PLATFORM_PRINTF_DEBUG_WARNING("  - %s\n", convert_1905_TLV_type_to_string(ret->list_of_TLVs[i]->type));
                            i++;
                        }
                        PLATFORM_PRINTF_DEBUG_WARNING("  - <END>\n");
                    }

                    free_1905_CMDU_structure(ret);
                    return NULL;
                }
                case 1:
                {
                    // The structure contained unxecpected TLVs. They have been
                    // removed for us.
                    //
                    break;
                }
                case 2:
                {
                    // The structure was perfect and '_check_CMDU_rules()' did
                    // not need to modify anything.
                    //
                    break;
                }
                default:
                {
                    // This point should never be reached
                    //
                    error = 8;
                    break;
                }
            }
        }
    }

    // Finally! If we get this far without errors we are already done, otherwise
    // free everything and return NULL
    //
    if (0 != error)
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Parsing error %d\n", error);
        free_1905_CMDU_structure(ret);
        return NULL;
    }
    return ret;
}


uint8_t **forge_1905_CMDU_from_structure(const struct CMDU *memory_structure, uint16_t **lens)
{
    uint8_t **ret;

    uint8_t tlv_start;
    uint8_t tlv_stop;

    uint8_t fragments_nr;

    uint32_t max_tlvs_block_size;

    uint8_t error;

    error = 0;

    if (NULL == memory_structure || NULL == lens)
    {
        // Invalid arguments
        //
        return NULL;
    }
    if (NULL == memory_structure->list_of_TLVs)
    {
        // Invalid arguments
        //
        return NULL;
    }

    // Before anything else, let's check that the CMDU 'rules' are satisfied:
    //
    if (0 == _check_CMDU_rules(memory_structure, CHECK_CMDU_TX_RULES))
    {
        // Invalid arguments
        //
        return NULL;
    }

    // Allocate the return streams.
    // Initially we will just have an empty list (ie. it contains a single
    // element marking the end-of-list: a NULL pointer)
    //
    ret = (uint8_t **)memalloc(sizeof(uint8_t *) * 1);
    ret[0] = NULL;

    *lens = (uint16_t *)memalloc(sizeof(uint16_t) * 1);
    (*lens)[0] = 0;

    fragments_nr = 0;

    // Let's create as many streams as needed so that all of them fit in
    // MAX_NETWORK_SEGMENT_SIZE bytes.
    //
    // More specifically, each of the fragments that we are going to generate
    // will have a size equal to the sum of:
    //
    //   - 6 bytes (destination MAC address)
    //   - 6 bytes (origin MAC address)
    //   - 2 bytes (ETH type)
    //   - 1 byte  (CMDU message version)
    //   - 1 byte  (CMDU reserved field)
    //   - 2 bytes (CMDU message type)
    //   - 2 bytes (CMDU message id)
    //   - 1 byte  (CMDU fragment id)
    //   - 1 byte  (CMDU flags/indicators)
    //   - X bytes (size of all TLVs contained in the fragment)
    //   - 3 bytes (TLV_TYPE_END_OF_MESSAGE TLV)
    //
    // In other words, X (the size of all the TLVs that are going to be inside
    // this fragmen) can not be greater than MAX_NETWORK_SEGMENT_SIZE - 6 - 6 -
    // 2 - 1 - 1 - 2 - 2 - 1 - 1 - 3 = MAX_NETWORK_SEGMENT_SIZE - 25 bytes.
    //
    max_tlvs_block_size = MAX_NETWORK_SEGMENT_SIZE - 25;
    tlv_start           = 0;
    tlv_stop            = 0;
    do
    {
        uint8_t *s;
        uint8_t  i;

        uint16_t current_X_size;

        uint8_t reserved_field;
        uint8_t fragment_id;
        uint8_t indicators;

        uint8_t no_space;

        current_X_size = 0;
        no_space       = 0;
        while(memory_structure->list_of_TLVs[tlv_stop])
        {
            struct tlv  *p;
            uint8_t  *tlv_stream;
            uint16_t  tlv_stream_size;

            p = memory_structure->list_of_TLVs[tlv_stop];

            tlv_stream = forge_1905_TLV_from_structure(p, &tlv_stream_size);
            free(tlv_stream);

            if (current_X_size + tlv_stream_size < max_tlvs_block_size)
            {
                tlv_stop++;
            }
            else
            {
                // There is no space for more TLVs
                //
                no_space = 1;
                break;
            }

            current_X_size += tlv_stream_size;
        }
        if (tlv_start == tlv_stop)
        {
            if (1 == no_space)
            {
                // One *single* TLV does not fit in a fragment!
                // This is an error... there is no way to split one single TLV into
                // several fragments according to the standard.
                //
                error = 1;
                break;
            }
            else
            {
                // If we end up here, it means tlv_start = tlv_stop = 0 --> this
                // CMDU contains no TLVs (which is something that can happen...
                // for example, in the "topology query" CMDU).
                // Just keep executing...
            }
        }

        // Now that we know how many TLVs are going to be embedded inside this
        // fragment (from 'tlv_start' up to -and not including- 'tlv_stop'),
        // let's build it
        //
        fragments_nr++;

        ret = (uint8_t **)memrealloc(ret, sizeof(uint8_t *) * (fragments_nr + 1));
        ret[fragments_nr-1] = (uint8_t *)memalloc(MAX_NETWORK_SEGMENT_SIZE);
        ret[fragments_nr]   = NULL;

        *lens = (uint16_t *)memrealloc(*lens, sizeof(uint16_t) * (fragments_nr + 1));
        (*lens)[fragments_nr-1] = 0; // To be updated a few lines later
        (*lens)[fragments_nr]   = 0;

        s = ret[fragments_nr-1];

        reserved_field = 0;
        fragment_id    = fragments_nr-1;
        indicators     = 0;

        // Set 'last_fragment_indicator' flag (bit #7)
        //
        if (NULL == memory_structure->list_of_TLVs[tlv_stop])
        {
            indicators |= 1 << 7;
        }

        // Set 'relay_indicator' flag (bit #6)
        //
        if (0xff == _get_CMDU_relay_indicator(memory_structure->message_type))
        {
            // Special, case. Respect what the caller told us
            //
            indicators |= memory_structure->relay_indicator << 6;
        }
        else
        {
            // Use the fixed value for this type of message according to the
            // standard
            //
            indicators |= _get_CMDU_relay_indicator(memory_structure->message_type) << 6;
        }

        _I1B(&memory_structure->message_version, &s);
        _I1B(&reserved_field,                    &s);
        _I2B(&memory_structure->message_type,    &s);
        _I2B(&memory_structure->message_id,      &s);
        _I1B(&fragment_id,                       &s);
        _I1B(&indicators,                        &s);

        for (i=tlv_start; i<tlv_stop; i++)
        {
            uint8_t  *tlv_stream;
            uint16_t  tlv_stream_size;

            tlv_stream = forge_1905_TLV_from_structure(memory_structure->list_of_TLVs[i], &tlv_stream_size);

            memcpy(s, tlv_stream, tlv_stream_size);
            free(tlv_stream);

            s += tlv_stream_size;
        }

        // Don't forget to add the last three octects representing the
        // TLV_TYPE_END_OF_MESSAGE message
        //
        *s = 0x0; s++;
        *s = 0x0; s++;
        *s = 0x0; s++;

        // Update the length return value
        //
        (*lens)[fragments_nr-1] = s - ret[fragments_nr-1];

        // And advance the TLV pointer so that, if more fragments are needed,
        // the next one starts where we have stopped.
        //
        tlv_start = tlv_stop;

    } while(memory_structure->list_of_TLVs[tlv_start]);

    // Finally! If we get this far without errors we are already done, otherwise
    // free everything and return NULL
    //
    if (0 != error)
    {
        free_1905_CMDU_packets(ret);
        free(*lens);
        return NULL;
    }

    return ret;
}


bool parse_1905_CMDU_header_from_packet(const uint8_t *packet_buffer, size_t len, struct CMDU_header *cmdu_header)
{
    uint16_t  ether_type;
    uint8_t   message_version;
    uint8_t   reserved_field;
    uint8_t   indicators;
    uint8_t   relay_indicator;

    if (NULL == packet_buffer || NULL == cmdu_header)
    {
        // Invalid params
        //
        return false;
    }

    if (len < 6+6+2+1+1+2+2+1+1)
    {
        // Not a valid CMDU, too small
        return false;
    }

    // Let's parse the header fields
    //
    _EnB(&packet_buffer, cmdu_header->dst_addr, 6);
    _EnB(&packet_buffer, cmdu_header->src_addr, 6);
    _E2B(&packet_buffer, &ether_type);
    if (ether_type != ETHERTYPE_1905)
    {
        // Wrong ether type, can't be a CMDU
        return false;
    }

    _E1B(&packet_buffer, &message_version);
    _E1B(&packet_buffer, &reserved_field);
    _E2B(&packet_buffer, &cmdu_header->message_type);
    _E2B(&packet_buffer, &cmdu_header->mid);
    _E1B(&packet_buffer, &cmdu_header->fragment_id);
    _E1B(&packet_buffer, &indicators);

    relay_indicator = (indicators & 0x40) >> 6;
    cmdu_header->last_fragment_indicator = (indicators & 0x80) >> 7; // MSB and 2nd MSB

    // Regarding the 'relay_indicator', depending on the message type, it
    // can only have a valid specific value
    //
    if (0xff == _get_CMDU_relay_indicator(cmdu_header->message_type))
    {
        // Special, case. All values are allowed
    }
    else
    {
        // Check if the value for this type of message is valid
        //
        // see the "Multi-AP Technical Specification" section 15.1 "CMDU reliable multicast transmission"
        if (_get_CMDU_relay_indicator(cmdu_header->message_type) != relay_indicator
                && (relay_indicator || !memcmp(MCAST_1905, cmdu_header->dst_addr, 6)))
        {
            // Malformed packet
            //
            PLATFORM_PRINTF_DEBUG_ERROR("drop the malformed packet: wrong relay indicator\n");
            return false;
        }
    }
    return true;
}

void free_1905_CMDU_tlv_raws(struct CMDU_extra_info *info)
{
    if (!dlist_empty(&info->tlv_raws)) {
        dlist_free_items(&info->tlv_raws, struct tlv_raw, l);
    }
}

void free_1905_CMDU_structure(struct CMDU *memory_structure)
{
    if (NULL != memory_structure) {
        if (NULL != memory_structure->list_of_TLVs) {
            uint8_t i;
            i = 0;
            while (memory_structure->list_of_TLVs[i])
            {
                free_1905_TLV_structure(memory_structure->list_of_TLVs[i]);
                i++;
            }
            free(memory_structure->list_of_TLVs);
        }
        free_1905_CMDU_tlv_raws(&memory_structure->extra_info);
        free(memory_structure);
    }
    return;
}


void free_1905_CMDU_packets(uint8_t **packet_streams)
{
    uint8_t i;

    if (NULL == packet_streams)
    {
        return;
    }

    i = 0;
    while (packet_streams[i])
    {
        free(packet_streams[i]);
        i++;
    }
    free(packet_streams);

    return;
}


uint8_t compare_1905_CMDU_structures(const struct CMDU *memory_structure_1, const struct CMDU *memory_structure_2)
{
    uint8_t i;

    if (NULL == memory_structure_1 || NULL == memory_structure_2)
    {
        return 1;
    }
    if (NULL == memory_structure_1->list_of_TLVs || NULL == memory_structure_2->list_of_TLVs)
    {
        return 1;
    }

    if (
         (memory_structure_1->message_version         != memory_structure_2->message_version)         ||
         (memory_structure_1->message_type            != memory_structure_2->message_type)            ||
         (memory_structure_1->message_id              != memory_structure_2->message_id)              ||
         (memory_structure_1->relay_indicator         != memory_structure_2->relay_indicator)
       )
    {
        return 1;
    }

    i = 0;
    while (1)
    {
        if (NULL == memory_structure_1->list_of_TLVs[i] && NULL == memory_structure_2->list_of_TLVs[i])
        {
            // No more TLVs to compare! Return '0' (structures are equal)
            //
            return 0;
        }

        if (0 != compare_1905_TLV_structures(memory_structure_1->list_of_TLVs[i], memory_structure_2->list_of_TLVs[i]))
        {
            // TLVs are not the same
            //
            return 1;
        }

        i++;
    }

    // This point should never be reached
    //
    return 1;
}


void visit_1905_CMDU_structure(const struct CMDU *memory_structure, visitor_callback callback, void (*write_function)(const char *fmt, ...), const char *prefix)
{
    // Buffer size to store a prefix string that will be used to show each
    // element of a structure on screen
    //
    #define MAX_PREFIX  100

    uint8_t i;

    if (NULL == memory_structure)
    {
        return;
    }

    callback(write_function, prefix, sizeof(memory_structure->message_version), "message_version", "%d",  &memory_structure->message_version);
    callback(write_function, prefix, sizeof(memory_structure->message_type),    "message_type",    "%d",  &memory_structure->message_type);
    callback(write_function, prefix, sizeof(memory_structure->message_id),      "message_id",      "%d",  &memory_structure->message_id);
    callback(write_function, prefix, sizeof(memory_structure->relay_indicator), "relay_indicator", "%d",  &memory_structure->relay_indicator);

    if (NULL == memory_structure->list_of_TLVs)
    {
        return;
    }


    i = 0;
    while (NULL != memory_structure->list_of_TLVs[i])
    {
        visit_1905_TLV_structure(memory_structure->list_of_TLVs[i], callback, write_function, prefix);
        i++;
    }

    return;
}

#define CMDU_TYPE_NAME_INITED(_a)    [CMDU_TYPE_##_a] = "CMDU_TYPE_" #_a
const char *_cmduTypeNames[] =
{
    CMDU_TYPE_NAME_INITED(TOPOLOGY_DISCOVERY),
    CMDU_TYPE_NAME_INITED(TOPOLOGY_NOTIFICATION),
    CMDU_TYPE_NAME_INITED(TOPOLOGY_QUERY),
    CMDU_TYPE_NAME_INITED(TOPOLOGY_RESPONSE),
    CMDU_TYPE_NAME_INITED(VENDOR_SPECIFIC),
    CMDU_TYPE_NAME_INITED(LINK_METRIC_QUERY),
    CMDU_TYPE_NAME_INITED(LINK_METRIC_RESPONSE),
    CMDU_TYPE_NAME_INITED(AP_AUTOCONFIGURATION_SEARCH),
    CMDU_TYPE_NAME_INITED(AP_AUTOCONFIGURATION_RESPONSE),
    CMDU_TYPE_NAME_INITED(AP_AUTOCONFIGURATION_WSC),
    CMDU_TYPE_NAME_INITED(AP_AUTOCONFIGURATION_RENEW),
    CMDU_TYPE_NAME_INITED(PUSH_BUTTON_EVENT_NOTIFICATION),
    CMDU_TYPE_NAME_INITED(PUSH_BUTTON_JOIN_NOTIFICATION),
    CMDU_TYPE_NAME_INITED(HIGHER_LAYER_QUERY),
    CMDU_TYPE_NAME_INITED(HIGHER_LAYER_RESPONSE),
    CMDU_TYPE_NAME_INITED(INTERFACE_POWER_CHANGE_REQUEST),
    CMDU_TYPE_NAME_INITED(INTERFACE_POWER_CHANGE_RESPONSE),
    CMDU_TYPE_NAME_INITED(GENERIC_PHY_QUERY),
    CMDU_TYPE_NAME_INITED(GENERIC_PHY_RESPONSE),
};


#define MAP_CMDU_TYPE_NAME_INITED(_a)    [CMDU_TYPE_##_a - CMDU_TYPE_DEFINED_IN_MAP_FIRST] = "CMDU_TYPE_" #_a
const char *_mapCmduTypeNames[] =
{
    MAP_CMDU_TYPE_NAME_INITED(ACK),
    MAP_CMDU_TYPE_NAME_INITED(AP_CAPABILITY_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(AP_CAPABILITY_REPORT),
    MAP_CMDU_TYPE_NAME_INITED(MAP_POLICY_CONFIG_REQUEST),
    MAP_CMDU_TYPE_NAME_INITED(CHANNEL_PREFERENCE_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(CHANNEL_PREFERENCE_REPORT),
    MAP_CMDU_TYPE_NAME_INITED(CHANNEL_SELECTION_REQUEST),
    MAP_CMDU_TYPE_NAME_INITED(CHANNEL_SELECTION_RESPONSE),
    MAP_CMDU_TYPE_NAME_INITED(OPERATING_CHANNEL_REPORT),
    MAP_CMDU_TYPE_NAME_INITED(CLIENT_CAPABILITY_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(CLIENT_CAPABILITY_REPORT),
    MAP_CMDU_TYPE_NAME_INITED(AP_METRICS_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(AP_METRICS_RESPONSE),
    MAP_CMDU_TYPE_NAME_INITED(ASSOCIATED_STA_LINK_METRICS_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(ASSOCIATED_STA_LINK_METRICS_RESPONSE),
    MAP_CMDU_TYPE_NAME_INITED(UNASSOCIATED_STA_LINK_METRICS_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(UNASSOCIATED_STA_LINK_METRICS_RESPONSE),
    MAP_CMDU_TYPE_NAME_INITED(BEACON_METRICS_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(BEACON_METRICS_RESPONSE),
    MAP_CMDU_TYPE_NAME_INITED(COMBINED_INFRASTRUCTURE_METRICS),
    MAP_CMDU_TYPE_NAME_INITED(CLIENT_STEERING_REQUEST),
    MAP_CMDU_TYPE_NAME_INITED(CLIENT_STEERING_BTM_REPORT),
    MAP_CMDU_TYPE_NAME_INITED(CLIENT_ASSOCIATION_CONTROL),
    MAP_CMDU_TYPE_NAME_INITED(STEERING_COMPLETED),
    MAP_CMDU_TYPE_NAME_INITED(HIGHER_LAYER_DATA),
    MAP_CMDU_TYPE_NAME_INITED(BACKHAUL_STEERING_REQUEST),
    MAP_CMDU_TYPE_NAME_INITED(BACKHAUL_STEERING_RESPONSE),

    MAP_CMDU_TYPE_NAME_INITED(CHANNEL_SCAN_REQUEST),
    MAP_CMDU_TYPE_NAME_INITED(CHANNEL_SCAN_REPORT),
    MAP_CMDU_TYPE_NAME_INITED(CAC_REQUEST),
    MAP_CMDU_TYPE_NAME_INITED(CAC_TERMINATION),
    MAP_CMDU_TYPE_NAME_INITED(CLIENT_DISASSOCIATION_STATS),
    MAP_CMDU_TYPE_NAME_INITED(ERROR_RESPONSE),
    MAP_CMDU_TYPE_NAME_INITED(ASSOCIATION_STATUS_NOTIFICATION),
    MAP_CMDU_TYPE_NAME_INITED(TUNNELED),
    MAP_CMDU_TYPE_NAME_INITED(BACKHAUL_STA_CAPABILITY_QUERY),
    MAP_CMDU_TYPE_NAME_INITED(BACKHAUL_STA_CAPABILITY_REPORT),
    MAP_CMDU_TYPE_NAME_INITED(FAILED_CONNECTION),
};

const char *convert_1905_CMDU_type_to_string(uint16_t cmdu_type)
{
    if (cmdu_type <= CMDU_TYPE_DEFINED_IN_1905_LAST)
        return _cmduTypeNames[cmdu_type];
    if (cmdu_type >= CMDU_TYPE_DEFINED_IN_MAP_FIRST
        && cmdu_type <= CMDU_TYPE_DEFINED_IN_MAP_LAST)
        return _mapCmduTypeNames[cmdu_type - CMDU_TYPE_DEFINED_IN_MAP_FIRST];
    return "Unknown";
}

struct tlv *get_CMDU_tlv(const struct CMDU *c, uint8_t tlv_type)
{
    struct tlv *p = NULL;
    int i = 0;

    if (NULL == c->list_of_TLVs)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Malformed structure.");
        return NULL;
    }
    while (NULL != (p = c->list_of_TLVs[i++]))
    {
        if (p->type == tlv_type)
            return p;
    }
    return NULL;
}

struct CMDU *new_CMDU()
{
   struct CMDU *c = (struct CMDU *)malloc(sizeof(struct CMDU));

   INIT_CMDU_EXTRA_INFO(&c->extra_info);
   return c;
}
