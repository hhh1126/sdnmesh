/*
 *  Broadband Forum IEEE 1905.1/1a stack
 *
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

#include "1905_alme.h"
#include "1905_tlvs.h"
#include "packet_tools.h"

#include <string.h> // memcmp()
#include <stdio.h>  // snprintf

////////////////////////////////////////////////////////////////////////////////
// Custom (non-standarized) packet structure for standard ALME primitives:
////////////////////////////////////////////////////////////////////////////////
//
// ALME-GET-INTF-LIST.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x01
//
//
// ALME-GET-INTF-LIST.response
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x02
//  byte # 1: interface_descriptors_nr
//
//  byte # 2: interface_address[0]                                         |
//  byte # 3: interface_address[1]                                         |
//  byte # 4: interface_address[2]                                         |
//  byte # 5: interface_address[3]                                         |
//  byte # 6: interface_address[4]                                         | repeat
//  byte # 7: interface_address[5]                                         | "interface_descriptors_nr"
//  byte # 8: interface_type MSB                                           | times
//  byte # 9: interface_type LSB                                           |
//  byte #10: bridge_flag                                                  |
//  byte #11: vendor_specific_info_nr                                      |
//                                                                         |
//  byte #12: ie_type MSB                  |                               |
//  byte #13: ie_type LSB                  |                               |
//  byte #14: length_field MSB             |                               |
//  byte #15: length_field LSB             |                               |
//  byte #16: oui[0]                       | repeat                        |
//  byte #17: oui[1]                       | "vendor_specific_info_nr"     |
//  byte #18: oui[2]                       | times                         |
//  byte #19: vendor_si[0]                 |                               |
//  byte #20: vendor_si[1]                 |                               |
//  ...                                    |                               |
//  byte #N : vendor_si[length_field-1]    |                               |
//
//
// ALME-SET-INTF-PWR-STATE.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x03
//  byte # 1: interface_address[0]
//  byte # 2: interface_address[1]
//  byte # 3: interface_address[2]
//  byte # 4: interface_address[3]
//  byte # 5: interface_address[4]
//  byte # 6: interface_address[5]
//  byte # 7: power_state
//
//
// ALME-SET-INTF-PWR-STATE.confirm
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x04
//  byte # 1: interface_address[0]
//  byte # 2: interface_address[1]
//  byte # 3: interface_address[2]
//  byte # 4: interface_address[3]
//  byte # 5: interface_address[4]
//  byte # 6: interface_address[5]
//  byte # 7: reason_code
//
//
// ALME-GET-INTF-PWR-STATE.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x05
//  byte # 1: interface_address[0]
//  byte # 2: interface_address[1]
//  byte # 3: interface_address[2]
//  byte # 4: interface_address[3]
//  byte # 5: interface_address[4]
//  byte # 6: interface_address[5]
//
//
// ALME-GET-INTF-PWR-STATE.response
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x06
//  byte # 1: interface_address[0]
//  byte # 2: interface_address[1]
//  byte # 3: interface_address[2]
//  byte # 4: interface_address[3]
//  byte # 5: interface_address[4]
//  byte # 6: interface_address[5]
//  byte # 7: reason_code
//
// ALME-SET-FWD-RULE.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x07
//  byte # 1: mac_da[0]
//  byte # 2: mac_da[1]
//  byte # 3: mac_da[2]
//  byte # 4: mac_da[3]
//  byte # 5: mac_da[4]
//  byte # 6: mac_da[5]
//  byte # 7: mac_da_flag
//  byte # 8: mac_sa[0]
//  byte # 9: mac_sa[1]
//  byte #10: mac_sa[2]
//  byte #11: mac_sa[3]
//  byte #12: mac_sa[4]
//  byte #13: mac_sa[5]
//  byte #14: mac_sa_flag
//  byte #15: ether_type MSB
//  byte #16: ether_type LSB
//  byte #17: ether_type_flag
//  byte #18: 0x00 | vid 4 MSbits   -> "vid" is
//  byte #19: vid LSB                  12 bits long
//  byte #20: vid_flag
//  byte #21: 0x00 | pcp 3 LSBits   -> "pcp" is 3 bits long
//  byte #22: pcp_flag
//  byte #23: addresses_nr
//
//  byte #24: addresses[0][0]    |
//  byte #25: addresses[0][1]    | repeat
//  byte #26: addresses[0][2]    | "addresses_nr"
//  byte #27: addresses[0][3]    | times
//  byte #28: addresses[0][4]    | (with addresses[1],
//  byte #29: addresses[0][5]    | addresses[2], etc...)
//
//
// ALME-SET-FWD-RULE.confirm
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x08
//  byte # 1: rule_id MSB
//  byte # 2: rule_id LSB
//  byte # 3: reason_code
//
//
// ALME-GET-FWD-RULE.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x09
//
//
// ALME-GET-FWD-RULE.response
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x10
//  byte # 1: rules_nr
//
//  byte # 2: mac_da[0]                                                    |
//  byte # 3: mac_da[1]                                                    |
//  byte # 4: mac_da[2]                                                    |
//  byte # 5: mac_da[3]                                                    |
//  byte # 6: mac_da[4]                                                    |
//  byte # 7: mac_da[5]                                                    |
//  byte # 8: mac_da_flag                                                  |
//  byte # 9: mac_sa[0]                                                    |
//  byte #10: mac_sa[1]                                                    |
//  byte #11: mac_sa[2]                                                    |
//  byte #12: mac_sa[3]                                                    | repeat
//  byte #13: mac_sa[4]                                                    | "rules_nr"
//  byte #14: mac_sa[5]                                                    | times
//  byte #15: mac_sa_flag                                                  |
//  byte #16: ether_type MSB                                               |
//  byte #17: ether_type LSB                                               |
//  byte #18: ether_type_flag                                              |
//  byte #19: 0x00 | vid 4 MSbits   -> "vid" is                            |
//  byte #20: vid LSB                  12 bits long                        |
//  byte #21: vid_flag                                                     |
//  byte #22: 0x00 | pcp 3 LSBits   -> "pcp" is 3 bits long                |
//  byte #23: pcp_flag                                                     |
//  byte #24: addresses_nr                                                 |
//                                                                         |
//  byte #25: addresses[0][0]    |                                         |
//  byte #26: addresses[0][1]    | repeat                                  |
//  byte #27: addresses[0][2]    | "addresses_nr"                          |
//  byte #28: addresses[0][3]    | times                                   |
//  byte #29: addresses[0][4]    | (with addresses[1],                     |
//  byte #30: addresses[0][5]    | addresses[2], etc...)                   |
//                                                                         |
//  byte #N  : last_matched MSB                                            |
//  byte #N+1: last_matched LSB                                            |
//
//
// ALME-MODIFY-FWD-RULE.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x0a
//  byte # 1: rule_id MSB
//  byte # 2: rule_id LSB
//  byte # 3: addresses_nr
//
//  byte #25: addresses[0][0]    |
//  byte #26: addresses[0][1]    | repeat
//  byte #27: addresses[0][2]    | "addresses_nr"
//  byte #28: addresses[0][3]    | times
//  byte #29: addresses[0][4]    | (with addresses[1],
//  byte #30: addresses[0][5]    | addresses[2], etc...)
//
//
// ALME-MODIFY-FWD-RULE.confirm
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x0b
//  byte # 1: rule_id MSB
//  byte # 2: rule_id LSB
//  byte # 3: reason_code
//
//
// ALME-REMOVE-FWD-RULE.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x0c
//  byte # 1: rule_id MSB
//  byte # 2: rule_id LSB
//
//
// ALME-REMOVE-FWD-RULE.confirm
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x0d
//  byte # 1: rule_id MSB
//  byte # 2: rule_id LSB
//  byte # 3: reason_code
//
//
// ALME-GET-METRIC.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x0e
//
//  byte # 1: interface_address[0]
//  byte # 2: interface_address[1]
//  byte # 3: interface_address[2]
//  byte # 4: interface_address[3]
//  byte # 5: interface_address[4]
//  byte # 6: interface_address[5]
//
//
// ALME-GET-METRIC.response
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0x0f
//  byte # 1: metrics_nr
//
//  byte # 2: neighbor_dev_address[0]                                      |
//  byte # 3: neighbor_dev_address[1]                                      | repeat
//  byte # 4: neighbor_dev_address[2]                                      | "metrics_nr"
//  byte # 5: neighbor_dev_address[3]                                      | times
//  byte # 6: neighbor_dev_address[4]                                      | (one time for
//  byte # 7: neighbor_dev_address[5]                                      | each local interface
//  byte # 8: local_intf_address[0]                                        | connected to a
//  byte # 9: local_intf_address[1]                                        | remote interface
//  byte #10: local_intf_address[2]                                        | of the neighbor
//  byte #11: local_intf_address[3]                                        | node)
//  byte #12: local_intf_address[4]                                        |
//  byte #13: local_intf_address[5]                                        |
//  byte #14: bridge_flag                                                  |
//                                                                         |
//  byte #15: tlv.type   = 0x9 (transmitter link metrics)                  |
//  byte #16: tlv_length = 12 + 29*1                                       |
//  byte #17: tlv_value[0]         | Only contains one metrics element:    |
//  ...                            | the one involving                     |
//  byte #57: tlv_value[12+29-1]   | "local_intf_address"                  |
//                                                                         |
//  byte #58: tlv.type   = 0x10 (receiver link metrics)                    |
//  byte #59: tlv_length = 12 + 23*1                                       |
//  byte #60: tlv_value[0]         | Only contains one metrics element:    |
//  ...                            | the one involving                     |
//  byte #94: tlv_value[12+23-1]   | "local_intf_address"                  |
//
//  NOTES:
//    * The contents of bytes #17 to #57 are defined in "IEEE Std 1905.1-2013
//      Table 6-17" with "n=1" (ie. only one connected interface -the one
//      that matches "local_intf_address"- is reported)
//    * The contents of bytes #60 to #94 are defined in "IEEE Std 1905.1-2013
//      Table 6-19" with "n=1" (ie. only one connected interface -the one
//      that matches "local_intf_address"- is reported)


////////////////////////////////////////////////////////////////////////////////
// Private (non-standarized) packet structure for custom (not present in the
// standard) ALME primitives:
////////////////////////////////////////////////////////////////////////////////
//
// NOTE: We are using "reserved" 'alme_type' values. We might have to remove
// these new "custom" ALMEs if the standard is ever updated to make use of these
// types.
//
// ALME-CUSTOM-COMMAND.request
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0xf0
//  byte # 1: command
//
// ALME-CUSTOM-COMMAND.response
// ----------------------------------------------------------------------------
//  byte # 0: alme_type = 0xf0
//  byte # 1: length MSB
//  byte # 2: length LSB
//  byte # 3: data[0]                         |
//  ...                                       | Custom response payload
//  byte # (length + 3 - 1) : data[length-1]  |



////////////////////////////////////////////////////////////////////////////////
// Actual API functions
////////////////////////////////////////////////////////////////////////////////

uint8_t *parse_1905_ALME_from_packet(const uint8_t *packet_stream)
{
    if (NULL == packet_stream)
    {
        return NULL;
    }

    // The first byte of the stream is the "Type" field from the ALME structure.
    // Valid values for this byte are the following ones...
    //
    switch (*packet_stream)
    {
        case ALME_TYPE_GET_INTF_LIST_REQUEST:
        {
            struct getIntfListRequestALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct getIntfListRequestALME *)memalloc(sizeof(struct getIntfListRequestALME));

            _E1B(&p, &ret->alme_type);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_GET_INTF_LIST_RESPONSE:
        {
            struct getIntfListResponseALME  *ret;

            const uint8_t *p;
            uint8_t i, j;

            p = packet_stream;

            ret = (struct getIntfListResponseALME *)memalloc(sizeof(struct getIntfListResponseALME));

            _E1B(&p, &ret->alme_type);
            _E1B(&p, &ret->interface_descriptors_nr);

            if (ret->interface_descriptors_nr > 0)
            {
                ret->interface_descriptors = (struct _intfDescriptorEntries *)memalloc(sizeof(struct _intfDescriptorEntries) * ret->interface_descriptors_nr);

                for (i=0; i<ret->interface_descriptors_nr; i++)
                {
                    _EnB(&p,  ret->interface_descriptors[i].interface_address, 6);
                    _E2B(&p, &ret->interface_descriptors[i].interface_type);
                    _E1B(&p, &ret->interface_descriptors[i].bridge_flag);
                    _E1B(&p, &ret->interface_descriptors[i].vendor_specific_info_nr);

                    if (ret->interface_descriptors[i].vendor_specific_info_nr > 0)
                    {
                        ret->interface_descriptors[i].vendor_specific_info = (struct _vendorSpecificInfoEntries *)memalloc(sizeof(struct _vendorSpecificInfoEntries) * ret->interface_descriptors[i].vendor_specific_info_nr);

                        for (j=0; j<ret->interface_descriptors[i].vendor_specific_info_nr; j++)
                        {
                            _E2B(&p, &ret->interface_descriptors[i].vendor_specific_info[j].ie_type);
                            _E2B(&p, &ret->interface_descriptors[i].vendor_specific_info[j].length_field);
                            _EnB(&p,  ret->interface_descriptors[i].vendor_specific_info[j].oui, 3);

                            if (ret->interface_descriptors[i].vendor_specific_info[j].length_field > 3)
                            {
                                ret->interface_descriptors[i].vendor_specific_info[j].vendor_si = (uint8_t *)memalloc(sizeof(uint8_t) * ((ret->interface_descriptors[i].vendor_specific_info[j].length_field - 3)));

                                _EnB(&p, ret->interface_descriptors[i].vendor_specific_info[j].vendor_si, ret->interface_descriptors[i].vendor_specific_info[j].length_field - 3);
                            }
                            else
                            {
                                ret->interface_descriptors[i].vendor_specific_info[j].vendor_si = NULL;
                            }
                        }
                    }
                }
            }

            return (uint8_t *)ret;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_REQUEST:
        {
            struct setIntfPwrStateRequestALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct setIntfPwrStateRequestALME *)memalloc(sizeof(struct setIntfPwrStateRequestALME));

            _E1B(&p, &ret->alme_type);
            _EnB(&p,  ret->interface_address, 6);
            _E1B(&p, &ret->power_state);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM:
        {
            struct setIntfPwrStateConfirmALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct setIntfPwrStateConfirmALME *)memalloc(sizeof(struct setIntfPwrStateConfirmALME));

            _E1B(&p, &ret->alme_type);
            _EnB(&p,  ret->interface_address, 6);
            _E1B(&p, &ret->reason_code);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_REQUEST:
        {
            struct getIntfPwrStateRequestALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct getIntfPwrStateRequestALME *)memalloc(sizeof(struct getIntfPwrStateRequestALME));

            _E1B(&p, &ret->alme_type);
            _EnB(&p,  ret->interface_address, 6);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE:
        {
            struct getIntfPwrStateResponseALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct getIntfPwrStateResponseALME *)memalloc(sizeof(struct getIntfPwrStateResponseALME));

            _E1B(&p, &ret->alme_type);
            _EnB(&p,  ret->interface_address, 6);
            _E1B(&p, &ret->power_state);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_SET_FWD_RULE_REQUEST:
        {
            struct setFwdRuleRequestALME  *ret;

            const uint8_t *p;
            uint8_t i;

            p = packet_stream;

            ret = (struct setFwdRuleRequestALME *)memalloc(sizeof(struct setFwdRuleRequestALME));

            _E1B(&p, &ret->alme_type);
            _EnB(&p,  ret->classification_set.mac_da, 6);
            _E1B(&p, &ret->classification_set.mac_da_flag);
            _EnB(&p,  ret->classification_set.mac_sa, 6);
            _E1B(&p, &ret->classification_set.mac_sa_flag);
            _E2B(&p, &ret->classification_set.ether_type);
            _E1B(&p, &ret->classification_set.ether_type_flag);
            _E2B(&p, &ret->classification_set.vid);
            _E1B(&p, &ret->classification_set.vid_flag);
            _E1B(&p, &ret->classification_set.pcp);
            _E1B(&p, &ret->classification_set.pcp_flag);
            _E1B(&p, &ret->addresses_nr);

            if (ret->addresses_nr > 0)
            {
                ret->addresses = (uint8_t (*)[6])memalloc(sizeof(uint8_t[6]) * ret->addresses_nr);

                for (i=0; i<ret->addresses_nr; i++)
                {
                    _EnB(&p, ret->addresses[i], 6);
                }
            }

            return (uint8_t *)ret;
        }

        case ALME_TYPE_SET_FWD_RULE_CONFIRM:
        {
            struct setFwdRuleConfirmALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct setFwdRuleConfirmALME *)memalloc(sizeof(struct setFwdRuleConfirmALME));

            _E1B(&p, &ret->alme_type);
            _E2B(&p, &ret->rule_id);
            _E1B(&p, &ret->reason_code);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_GET_FWD_RULES_REQUEST:
        {
            struct getFwdRulesRequestALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct getFwdRulesRequestALME *)memalloc(sizeof(struct getFwdRulesRequestALME));

            _E1B(&p, &ret->alme_type);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_GET_FWD_RULES_RESPONSE:
        {
            struct getFwdRulesResponseALME  *ret;

            const uint8_t *p;
            uint8_t i, j;

            p = packet_stream;

            ret = (struct getFwdRulesResponseALME *)memalloc(sizeof(struct getFwdRulesResponseALME));

            _E1B(&p, &ret->alme_type);
            _E1B(&p, &ret->rules_nr);

            if (ret->rules_nr > 0)
            {
                ret->rules = (struct _fwdRuleListEntries *)memalloc(sizeof(struct _fwdRuleListEntries) * ret->rules_nr);

                for (i=0; i<ret->rules_nr; i++)
                {
                    _EnB(&p,  ret->rules[i].classification_set.mac_da, 6);
                    _E1B(&p, &ret->rules[i].classification_set.mac_da_flag);
                    _EnB(&p,  ret->rules[i].classification_set.mac_sa, 6);
                    _E1B(&p, &ret->rules[i].classification_set.mac_sa_flag);
                    _E2B(&p, &ret->rules[i].classification_set.ether_type);
                    _E1B(&p, &ret->rules[i].classification_set.ether_type_flag);
                    _E2B(&p, &ret->rules[i].classification_set.vid);
                    _E1B(&p, &ret->rules[i].classification_set.vid_flag);
                    _E1B(&p, &ret->rules[i].classification_set.pcp);
                    _E1B(&p, &ret->rules[i].classification_set.pcp_flag);
                    _E1B(&p, &ret->rules[i].addresses_nr);

                    if (ret->rules[i].addresses_nr > 0)
                    {
                        ret->rules[i].addresses = (uint8_t (*)[6])memalloc(sizeof(uint8_t[6]) * ret->rules[i].addresses_nr);

                        for (j=0; j<ret->rules[i].addresses_nr; j++)
                        {
                            _EnB(&p, ret->rules[i].addresses[j], 6);
                        }
                    }

                    _E2B(&p, &ret->rules[i].last_matched);
                }
            }

            return (uint8_t *)ret;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_REQUEST:
        {
            struct modifyFwdRuleRequestALME  *ret;

            const uint8_t *p;
            uint8_t i;

            p = packet_stream;

            ret = (struct modifyFwdRuleRequestALME *)memalloc(sizeof(struct modifyFwdRuleRequestALME));

            _E1B(&p, &ret->alme_type);
            _E2B(&p, &ret->rule_id);
            _E1B(&p, &ret->addresses_nr);

            if (ret->addresses_nr > 0)
            {
                ret->addresses = (uint8_t (*)[6])memalloc(sizeof(uint8_t[6]) * ret->addresses_nr);

                for (i=0; i<ret->addresses_nr; i++)
                {
                    _EnB(&p, ret->addresses[i], 6);
                }
            }

            return (uint8_t *)ret;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_CONFIRM:
        {
            struct modifyFwdRuleConfirmALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct modifyFwdRuleConfirmALME *)memalloc(sizeof(struct modifyFwdRuleConfirmALME));

            _E1B(&p, &ret->alme_type);
            _E2B(&p, &ret->rule_id);
            _E1B(&p, &ret->reason_code);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_REQUEST:
        {
            struct removeFwdRuleRequestALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct removeFwdRuleRequestALME *)memalloc(sizeof(struct removeFwdRuleRequestALME));

            _E1B(&p, &ret->alme_type);
            _E2B(&p, &ret->rule_id);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_CONFIRM:
        {
            struct removeFwdRuleConfirmALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct removeFwdRuleConfirmALME *)memalloc(sizeof(struct removeFwdRuleConfirmALME));

            _E1B(&p, &ret->alme_type);
            _E2B(&p, &ret->rule_id);
            _E1B(&p, &ret->reason_code);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_GET_METRIC_REQUEST:
        {
            struct getMetricRequestALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct getMetricRequestALME *)memalloc(sizeof(struct getMetricRequestALME));

            _E1B(&p, &ret->alme_type);
            _EnB(&p,  ret->interface_address, 6);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_GET_METRIC_RESPONSE:
        {
            struct getMetricResponseALME  *ret;

            const uint8_t *p;
            uint8_t i;

            p = packet_stream;

            ret = (struct getMetricResponseALME *)memalloc(sizeof(struct getMetricResponseALME));

            _E1B(&p, &ret->alme_type);
            _E1B(&p, &ret->metrics_nr);

            if (ret->metrics_nr > 0)
            {
                ret->metrics = (struct _metricDescriptorsEntries *)memalloc(sizeof(struct _metricDescriptorsEntries) * ret->metrics_nr);

                for (i=0; i<ret->metrics_nr; i++)
                {
                    struct transmitterLinkMetricTLV *tx;
                    struct receiverLinkMetricTLV    *rx;

                    uint8_t  aux1;
                    uint16_t aux2;

                    _EnB(&p,  ret->metrics[i].neighbor_dev_address, 6);
                    _EnB(&p,  ret->metrics[i].local_intf_address,   6);
                    _E1B(&p, &ret->metrics[i].bridge_flag);

                    tx = (struct transmitterLinkMetricTLV *)parse_1905_TLV_from_packet(p);

                    if (
                                         NULL                                                     ==  tx                                       ||
                         memcmp(tx->neighbor_al_address,                                     ret->metrics[i].neighbor_dev_address, 6) ||
                                         1                                                        !=  tx->transmitter_link_metrics_nr          ||
                                         NULL                                                     ==  tx->transmitter_link_metrics             ||
                         memcmp(tx->transmitter_link_metrics[0].local_interface_address,    ret->metrics[i].local_intf_address, 6)
                       )
                    {
                        // Parsing error
                        //
                        if (NULL != tx)
                        {
                            free_1905_TLV_structure(&tx->tlv);
                        }
                        free(ret->metrics);
                        free(ret);
                        return NULL;
                    }

                    _E1B(&p, &aux1);
                    _E2B(&p, &aux2);
                    p += aux2;

                    rx = (struct receiverLinkMetricTLV *)parse_1905_TLV_from_packet(p);

                    if (
                                         NULL                                                     ==  rx                                       ||
                         memcmp(rx->neighbor_al_address,                                     ret->metrics[i].neighbor_dev_address, 6) ||
                                         1                                                        !=  rx->receiver_link_metrics_nr             ||
                                         NULL                                                     ==  rx->receiver_link_metrics                ||
                         memcmp(rx->receiver_link_metrics[0].local_interface_address,    ret->metrics[i].local_intf_address, 6)
                       )
                    {
                        // Parsing error
                        //
                        if (NULL != rx)
                        {
                            free_1905_TLV_structure(&rx->tlv);
                        }
                        free(ret->metrics);
                        free(ret);
                        return NULL;
                    }

                    _E1B(&p, &aux1);
                    _E2B(&p, &aux2);
                    p += aux2;

                    ret->metrics[i].tx_metric = tx;
                    ret->metrics[i].rx_metric = rx;
                }
            }

            _E1B(&p, &ret->reason_code);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_CUSTOM_COMMAND_REQUEST:
        {
            struct customCommandRequestALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct customCommandRequestALME *)memalloc(sizeof(struct customCommandRequestALME));

            _E1B(&p, &ret->alme_type);
            _E1B(&p, &ret->command);

            return (uint8_t *)ret;
        }

        case ALME_TYPE_CUSTOM_COMMAND_RESPONSE:
        {
            struct customCommandResponseALME  *ret;

            const uint8_t *p;

            p = packet_stream;

            ret = (struct customCommandResponseALME *)memalloc(sizeof(struct customCommandResponseALME));

            _E1B(&p, &ret->alme_type);
            _E2B(&p, &ret->bytes_nr);

            if (ret->bytes_nr > 0)
            {
                ret->bytes = (char *)memalloc(ret->bytes_nr);
                _EnB(&p, ret->bytes, ret->bytes_nr);
            }

            return (uint8_t *)ret;
        }

        default:
        {
            // Ignore
            //
            return NULL;
        }

    }

    // This code cannot be reached
    //
    return NULL;
}

uint8_t *forge_1905_ALME_from_structure(uint8_t *memory_structure, uint16_t *len)
{
    if (NULL == memory_structure)
    {
        return NULL;
    }

    // The first byte of any of the valid structures is always the "tlv.type"
    // field.
    //
    switch (*memory_structure)
    {
        case ALME_TYPE_GET_INTF_LIST_REQUEST:
        {
            uint8_t *ret, *p;
            struct getIntfListRequestALME *m;

            m = (struct getIntfListRequestALME *)memory_structure;

            *len = 1; // alme_type

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,  &p);

            return ret;
        }

        case ALME_TYPE_GET_INTF_LIST_RESPONSE:
        {
            uint8_t *ret, *p;
            struct getIntfListResponseALME *m;

            uint8_t i, j;

            m = (struct getIntfListResponseALME *)memory_structure;

            *len = 2; // alme_type + interface_descriptors_nr
            for (i=0; i<m->interface_descriptors_nr; i++)
            {
                *len += 6; // interface_address
                *len += 2; // interface_type
                *len += 1; // bridge_flag
                *len += 1; // vendor_specific_info_nr

                for (j=0; j<m->interface_descriptors[i].vendor_specific_info_nr; j++)
                {
                    *len += 7; //ie_type + length_field + oui
                    *len += m->interface_descriptors[i].vendor_specific_info[j].length_field - 3; // vendor_si
                }
            }

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,                 &p);
            _I1B(&m->interface_descriptors_nr,  &p);

            for (i=0; i<m->interface_descriptors_nr; i++)
            {
                _InB( m->interface_descriptors[i].interface_address,       &p, 6);
                _I2B(&m->interface_descriptors[i].interface_type,          &p);
                _I1B(&m->interface_descriptors[i].bridge_flag,             &p);
                _I1B(&m->interface_descriptors[i].vendor_specific_info_nr, &p);

                for (j=0; j<m->interface_descriptors[i].vendor_specific_info_nr; j++)
                {
                    _I2B(&m->interface_descriptors[i].vendor_specific_info[j].ie_type,      &p);
                    _I2B(&m->interface_descriptors[i].vendor_specific_info[j].length_field, &p);
                    _InB( m->interface_descriptors[i].vendor_specific_info[j].oui,          &p, 3);

                    if (m->interface_descriptors[i].vendor_specific_info[j].length_field > 3)
                    {
                        _InB( m->interface_descriptors[i].vendor_specific_info[j].vendor_si, &p, m->interface_descriptors[i].vendor_specific_info[j].length_field - 3);
                    }
                }
            }

            return ret;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_REQUEST:
        {
            uint8_t *ret, *p;
            struct setIntfPwrStateRequestALME *m;

            m = (struct setIntfPwrStateRequestALME *)memory_structure;

            *len = 8; // alme_type + interface_address + power_state

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,          &p);
            _InB( m->interface_address,  &p,  6);
            _I1B(&m->power_state,        &p);

            return ret;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM:
        {
            uint8_t *ret, *p;
            struct setIntfPwrStateConfirmALME *m;

            m = (struct setIntfPwrStateConfirmALME *)memory_structure;

            *len = 8; // alme_type + interface_address + reason_code

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,          &p);
            _InB( m->interface_address,  &p,  6);
            _I1B(&m->reason_code,        &p);

            return ret;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_REQUEST:
        {
            uint8_t *ret, *p;
            struct getIntfPwrStateRequestALME *m;

            m = (struct getIntfPwrStateRequestALME *)memory_structure;

            *len = 7; // alme_type + interface_address

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,          &p);
            _InB( m->interface_address,  &p,  6);

            return ret;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE:
        {
            uint8_t *ret, *p;
            struct getIntfPwrStateResponseALME *m;

            m = (struct getIntfPwrStateResponseALME *)memory_structure;

            *len = 8; // alme_type + interface_address + power_state

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,          &p);
            _InB( m->interface_address,  &p,  6);
            _I1B(&m->power_state,        &p);

            return ret;
        }

        case ALME_TYPE_SET_FWD_RULE_REQUEST:
        {
            uint8_t *ret, *p;
            struct setFwdRuleRequestALME *m;

            uint8_t i;

            m = (struct setFwdRuleRequestALME *)memory_structure;

            *len  = 24;  // alme_type + classification_set + addresses_nr
            *len += 6 * m->addresses_nr; // addresses

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,                           &p);
            _InB( m->classification_set.mac_da,           &p,  6);
            _I1B(&m->classification_set.mac_da_flag,      &p);
            _InB( m->classification_set.mac_sa,           &p,  6);
            _I1B(&m->classification_set.mac_sa_flag,      &p);
            _I2B(&m->classification_set.ether_type,       &p);
            _I1B(&m->classification_set.ether_type_flag,  &p);
            _I2B(&m->classification_set.vid,              &p);
            _I1B(&m->classification_set.vid_flag,         &p);
            _I1B(&m->classification_set.pcp,              &p);
            _I1B(&m->classification_set.pcp_flag,         &p);
            _I1B(&m->addresses_nr,                        &p);

            for (i=0; i<m->addresses_nr; i++)
            {
                _InB( m->addresses[i], &p, 6);
            }

            return ret;
        }

        case ALME_TYPE_SET_FWD_RULE_CONFIRM:
        {
            uint8_t *ret, *p;
            struct setFwdRuleConfirmALME *m;

            m = (struct setFwdRuleConfirmALME *)memory_structure;

            *len = 4; // alme_type + rule_id + reason_code

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,    &p);
            _I2B(&m->rule_id,      &p);
            _I1B(&m->reason_code,  &p);

            return ret;
        }

        case ALME_TYPE_GET_FWD_RULES_REQUEST:
        {
            uint8_t *ret, *p;
            struct getFwdRulesRequestALME *m;

            m = (struct getFwdRulesRequestALME *)memory_structure;

            *len = 1; // alme_type

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,          &p);

            return ret;
        }

        case ALME_TYPE_GET_FWD_RULES_RESPONSE:
        {
            uint8_t *ret, *p;
            struct getFwdRulesResponseALME *m;

            uint8_t i, j;

            m = (struct getFwdRulesResponseALME *)memory_structure;

            *len = 2;  // alme_type + rules_nr
            for (i=0; i<m->rules_nr; i++)
            {
                *len += 23; // classification_set + addresses_nr
                *len += 6 * m->rules[i].addresses_nr; // addresses
                *len += 2; // last_matched
            }

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type, &p);
            _I1B(&m->rules_nr,  &p);

            for (i=0; i<m->rules_nr; i++)
            {
                _InB( m->rules[i].classification_set.mac_da,           &p,  6);
                _I1B(&m->rules[i].classification_set.mac_da_flag,      &p);
                _InB( m->rules[i].classification_set.mac_sa,           &p,  6);
                _I1B(&m->rules[i].classification_set.mac_sa_flag,      &p);
                _I2B(&m->rules[i].classification_set.ether_type,       &p);
                _I1B(&m->rules[i].classification_set.ether_type_flag,  &p);
                _I2B(&m->rules[i].classification_set.vid,              &p);
                _I1B(&m->rules[i].classification_set.vid_flag,         &p);
                _I1B(&m->rules[i].classification_set.pcp,              &p);
                _I1B(&m->rules[i].classification_set.pcp_flag,         &p);
                _I1B(&m->rules[i].addresses_nr,                        &p);

                for (j=0; j<m->rules[i].addresses_nr; j++)
                {
                    _InB( m->rules[i].addresses[j], &p, 6);
                }

                _I2B(&m->rules[i].last_matched,                        &p);
            }

            return ret;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_REQUEST:
        {
            uint8_t *ret, *p;
            struct modifyFwdRuleRequestALME *m;

            uint8_t i;

            m = (struct modifyFwdRuleRequestALME *)memory_structure;

            *len  = 4;  // alme_type + rule_id + addresses_nr
            *len += 6 * m->addresses_nr; // addresses

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,    &p);
            _I2B(&m->rule_id,      &p);
            _I1B(&m->addresses_nr, &p);

            for (i=0; i<m->addresses_nr; i++)
            {
                _InB( m->addresses[i], &p, 6);
            }

            return ret;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_CONFIRM:
        {
            uint8_t *ret, *p;
            struct modifyFwdRuleConfirmALME *m;

            m = (struct modifyFwdRuleConfirmALME *)memory_structure;

            *len = 4;  // alme_type + rule_id + reason_code

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,    &p);
            _I2B(&m->rule_id,      &p);
            _I1B(&m->reason_code,  &p);

            return ret;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_REQUEST:
        {
            uint8_t *ret, *p;
            struct removeFwdRuleRequestALME *m;

            m = (struct removeFwdRuleRequestALME *)memory_structure;

            *len = 3;  // alme_type + rule_id

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,    &p);
            _I2B(&m->rule_id,      &p);

            return ret;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_CONFIRM:
        {
            uint8_t *ret, *p;
            struct removeFwdRuleConfirmALME *m;

            m = (struct removeFwdRuleConfirmALME *)memory_structure;

            *len = 4;  // alme_type + rule_id + reason_code

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,    &p);
            _I2B(&m->rule_id,      &p);
            _I1B(&m->reason_code,  &p);

            return ret;
        }

        case ALME_TYPE_GET_METRIC_REQUEST:
        {
            uint8_t *ret, *p;
            struct getMetricRequestALME *m;

            m = (struct getMetricRequestALME *)memory_structure;

            *len  = 7;  // alme_type + interface_address

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,         &p);
            _InB( m->interface_address, &p, 6);

            return ret;
        }

        case ALME_TYPE_GET_METRIC_RESPONSE:
        {
            uint8_t *ret, *p;
            struct getMetricResponseALME *m;

            uint8_t i;

            m = (struct getMetricResponseALME *)memory_structure;

            *len = 2;  // alme_type + metrics_nr
            for (i=0; i<m->metrics_nr; i++)
            {
                uint8_t  *metric_stream;
                uint16_t  metric_stream_len;

                *len += 6; // neighbor_dev_address
                *len += 6; // local_intf_address
                *len += 1; // bridge_flag

                metric_stream = forge_1905_TLV_from_structure(&m->metrics[i].tx_metric->tlv, &metric_stream_len);
                if (NULL == metric_stream || 0 == metric_stream_len)
                {
                    // Forging error
                    //
                    *len = 0;
                    return NULL;
                }

                *len += metric_stream_len;
                free_1905_TLV_packet(metric_stream);

                metric_stream = forge_1905_TLV_from_structure(&m->metrics[i].rx_metric->tlv, &metric_stream_len);
                if (NULL == metric_stream || 0 == metric_stream_len)
                {
                    // Forging error
                    //
                    *len = 0;
                    return NULL;
                }

                *len += metric_stream_len;
                free_1905_TLV_packet(metric_stream);
            }
            *len += 1;  // reason_code

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type,  &p);
            _I1B(&m->metrics_nr, &p);

            for (i=0; i<m->metrics_nr; i++)
            {
                uint8_t  *metric_stream;
                uint16_t  metric_stream_len;

                struct transmitterLinkMetricTLV *tx;
                struct receiverLinkMetricTLV    *rx;

                _InB( m->metrics[i].neighbor_dev_address, &p, 6);
                _InB( m->metrics[i].local_intf_address,   &p, 6);
                _I1B(&m->metrics[i].bridge_flag,          &p);

                tx = m->metrics[i].tx_metric;
                rx = m->metrics[i].rx_metric;

                if (
                                         NULL                                                     ==  tx                                     ||
                         memcmp(tx->neighbor_al_address,                                     m->metrics[i].neighbor_dev_address, 6) ||
                                         NULL                                                     ==  tx->transmitter_link_metrics           ||
                         memcmp(tx->transmitter_link_metrics[0].local_interface_address,     m->metrics[i].local_intf_address, 6)   ||

                                         NULL                                                     ==  rx                                     ||
                         memcmp(rx->neighbor_al_address,                                     m->metrics[i].neighbor_dev_address, 6) ||
                                         NULL                                                     ==  rx->receiver_link_metrics              ||
                         memcmp(rx->receiver_link_metrics[0].local_interface_address,        m->metrics[i].local_intf_address, 6)
                   )
                {
                    // Malformed packet
                    //
                    *len = 0;
                    free(ret);
                    return NULL;
                }

                metric_stream = forge_1905_TLV_from_structure(&tx->tlv, &metric_stream_len);
                if (NULL == metric_stream || 0 == metric_stream_len)
                {
                    // Forging error
                    //
                    *len = 0;
                    free(ret);
                    return NULL;
                }
                _InB( metric_stream,  &p, metric_stream_len);
                free_1905_TLV_packet(metric_stream);

                metric_stream = forge_1905_TLV_from_structure(&rx->tlv, &metric_stream_len);
                if (NULL == metric_stream || 0 == metric_stream_len)
                {
                    // Forging error
                    //
                    *len = 0;
                    free(ret);
                    return NULL;
                }
                _InB( metric_stream,  &p, metric_stream_len);
                free_1905_TLV_packet(metric_stream);
            }

            _I1B(&m->reason_code,  &p);

            return ret;
        }

        case ALME_TYPE_CUSTOM_COMMAND_REQUEST:
        {
            uint8_t *ret, *p;
            struct customCommandRequestALME *m;

            m = (struct customCommandRequestALME *)memory_structure;

            *len  = 2;  // alme_type + command

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type, &p);
            _I1B(&m->command,   &p);

            return ret;
        }

        case ALME_TYPE_CUSTOM_COMMAND_RESPONSE:
        {
            uint8_t *ret, *p;
            struct customCommandResponseALME *m;

            m = (struct customCommandResponseALME *)memory_structure;

            *len  = 3;  // alme_type + length
            *len += m->bytes_nr;

            p = ret = (uint8_t *)memalloc(*len);

            _I1B(&m->alme_type, &p);
            _I2B(&m->bytes_nr,  &p);

            if (m->bytes_nr > 0)
            {
                _InB( m->bytes,  &p, m->bytes_nr);
            }

            return ret;
        }

        default:
        {
            // Ignore
            //
            return NULL;
        }

    }

    // This code cannot be reached
    //
    return NULL;
}


void free_1905_ALME_structure(uint8_t *memory_structure)
{
    if (NULL == memory_structure)
    {
        return;
    }

    // The first byte of any of the valid structures is always the "alme_type"
    // field.
    //
    switch (*memory_structure)
    {
        case ALME_TYPE_GET_INTF_LIST_REQUEST:
        case ALME_TYPE_SET_INTF_PWR_STATE_REQUEST:
        case ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM:
        case ALME_TYPE_GET_INTF_PWR_STATE_REQUEST:
        case ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE:
        case ALME_TYPE_SET_FWD_RULE_CONFIRM:
        case ALME_TYPE_GET_FWD_RULES_REQUEST:
        case ALME_TYPE_MODIFY_FWD_RULE_CONFIRM:
        case ALME_TYPE_REMOVE_FWD_RULE_REQUEST:
        case ALME_TYPE_REMOVE_FWD_RULE_CONFIRM:
        case ALME_TYPE_GET_METRIC_REQUEST:
        case ALME_TYPE_CUSTOM_COMMAND_REQUEST:
        {
            free(memory_structure);

            return;
        }

        case ALME_TYPE_GET_INTF_LIST_RESPONSE:
        {
            struct getIntfListResponseALME *m;
            uint8_t i, j;

            m = (struct getIntfListResponseALME *)memory_structure;

            if (m->interface_descriptors_nr > 0 && NULL != m->interface_descriptors)
            {
                for (i=0; i < m->interface_descriptors_nr; i++)
                {
                    if (m->interface_descriptors[i].vendor_specific_info_nr > 0 && NULL != m->interface_descriptors[i].vendor_specific_info)
                    {
                        for (j=0; j < m->interface_descriptors[i].vendor_specific_info_nr; j++)
                        {
                            if (NULL != m->interface_descriptors[i].vendor_specific_info[j].vendor_si)
                            {
                                free(m->interface_descriptors[i].vendor_specific_info[j].vendor_si);
                            }
                        }
                        free(m->interface_descriptors[i].vendor_specific_info);
                    }
                }
                free(m->interface_descriptors);
            }
            free(m);

            return;
        }

        case ALME_TYPE_SET_FWD_RULE_REQUEST:
        {
            struct setFwdRuleRequestALME *m;

            m = (struct setFwdRuleRequestALME *)memory_structure;

            if (m->addresses_nr >0 && NULL != m->addresses)
            {
                free(m->addresses);
            }
            free(m);

            return;
        }

        case ALME_TYPE_GET_FWD_RULES_RESPONSE:
        {
            struct getFwdRulesResponseALME *m;
            uint8_t i;

            m = (struct getFwdRulesResponseALME *)memory_structure;

            if (m->rules_nr > 0 && NULL != m->rules)
            {
                for (i=0; i < m->rules_nr; i++)
                {
                    if (m->rules[i].addresses)
                    {
                        free(m->rules[i].addresses);
                    }
                }
                free(m->rules);
            }
            free(m);

            return;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_REQUEST:
        {
            struct modifyFwdRuleRequestALME *m;

            m = (struct modifyFwdRuleRequestALME *)memory_structure;

            if (m->addresses_nr > 0 && NULL != m->addresses)
            {
                free(m->addresses);
            }
            free(m);

            return;
        }

        case ALME_TYPE_GET_METRIC_RESPONSE:
        {
            struct getMetricResponseALME *m;
            uint8_t i;

            m = (struct getMetricResponseALME *)memory_structure;

            if (m->metrics_nr > 0 && NULL != m->metrics)
            {
                for (i=0; i < m->metrics_nr; i++)
                {
                    free_1905_TLV_structure(&m->metrics[i].tx_metric->tlv);
                    free_1905_TLV_structure(&m->metrics[i].rx_metric->tlv);
                }
                free(m->metrics);
            }
            free(m);


            return;
        }

        case ALME_TYPE_CUSTOM_COMMAND_RESPONSE:
        {
            struct customCommandResponseALME *m;

            m = (struct customCommandResponseALME *)memory_structure;

            if (m->bytes_nr > 0 && NULL != m->bytes)
            {
                free(m->bytes);
            }
            free(m);

            return;
        }


        default:
        {
            // Ignore
            //
            return;
        }
    }

    // This code cannot be reached
    //
    return;
}


uint8_t compare_1905_ALME_structures(uint8_t *memory_structure_1, uint8_t *memory_structure_2)
{
    if (NULL == memory_structure_1 || NULL == memory_structure_2)
    {
        return 1;
    }

    // The first byte of any of the valid structures is always the "tlv.type"
    // field.
    //
    if (*memory_structure_1 != *memory_structure_2)
    {
        return 1;
    }
    switch (*memory_structure_1)
    {
        case ALME_TYPE_GET_INTF_LIST_REQUEST:
        {
            // Nothing to compare (this ALME primitive is always empty)
            //
            return 0;
        }

        case ALME_TYPE_GET_INTF_LIST_RESPONSE:
        {
            struct getIntfListResponseALME *p1, *p2;
            uint8_t i, j;

            p1 = (struct getIntfListResponseALME *)memory_structure_1;
            p2 = (struct getIntfListResponseALME *)memory_structure_2;

            if (p1->interface_descriptors_nr !=  p2->interface_descriptors_nr)
            {
                return 1;
            }

            if (p1->interface_descriptors_nr > 0 && (NULL == p1->interface_descriptors || NULL == p2->interface_descriptors))
            {
                // Malformed structure
                //
                return 1;
            }

            for (i=0; i<p1->interface_descriptors_nr; i++)
            {
                if (
                     memcmp(p1->interface_descriptors[i].interface_address,           p2->interface_descriptors[i].interface_address, 6)    ||
                                     p1->interface_descriptors[i].interface_type           !=  p2->interface_descriptors[i].interface_type           ||
                                     p1->interface_descriptors[i].bridge_flag              !=  p2->interface_descriptors[i].bridge_flag              ||
                                     p1->interface_descriptors[i].vendor_specific_info_nr  !=  p2->interface_descriptors[i].vendor_specific_info_nr
                   )
                {
                    return 1;
                }

                if (p1->interface_descriptors[i].vendor_specific_info_nr > 0 && (NULL == p1->interface_descriptors[i].vendor_specific_info || NULL == p2->interface_descriptors[i].vendor_specific_info))
                {
                    // Malformed structure
                    //
                    return 1;
                }

                for (j=0; j<p1->interface_descriptors[i].vendor_specific_info_nr; j++)
                {
                    if (
                                         p1->interface_descriptors[i].vendor_specific_info[j].ie_type       !=  p2->interface_descriptors[i].vendor_specific_info[j].ie_type                  ||
                                         p1->interface_descriptors[i].vendor_specific_info[j].length_field  !=  p2->interface_descriptors[i].vendor_specific_info[j].length_field             ||
                         memcmp(p1->interface_descriptors[i].vendor_specific_info[j].oui,              p2->interface_descriptors[i].vendor_specific_info[j].oui, 3)                  ||
                         memcmp(p1->interface_descriptors[i].vendor_specific_info[j].vendor_si,        p2->interface_descriptors[i].vendor_specific_info[j].vendor_si, p1->interface_descriptors[i].vendor_specific_info[j].length_field - 3)
                       )
                    {
                        return 1;
                    }

                }
            }

            return 0;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_REQUEST:
        {
            struct setIntfPwrStateRequestALME *p1, *p2;

            p1 = (struct setIntfPwrStateRequestALME *)memory_structure_1;
            p2 = (struct setIntfPwrStateRequestALME *)memory_structure_2;

            if (
                 memcmp(p1->interface_address,      p2->interface_address, 6)    ||
                                 p1->power_state         !=  p2->power_state
               )
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM:
        {
            struct setIntfPwrStateConfirmALME *p1, *p2;

            p1 = (struct setIntfPwrStateConfirmALME *)memory_structure_1;
            p2 = (struct setIntfPwrStateConfirmALME *)memory_structure_2;

            if (
                 memcmp(p1->interface_address,      p2->interface_address, 6)    ||
                                 p1->reason_code         !=  p2->reason_code
               )
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_REQUEST:
        {
            struct getIntfPwrStateRequestALME *p1, *p2;

            p1 = (struct getIntfPwrStateRequestALME *)memory_structure_1;
            p2 = (struct getIntfPwrStateRequestALME *)memory_structure_2;

            if (memcmp(p1->interface_address, p2->interface_address, 6))
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE:
        {
            struct getIntfPwrStateResponseALME *p1, *p2;

            p1 = (struct getIntfPwrStateResponseALME *)memory_structure_1;
            p2 = (struct getIntfPwrStateResponseALME *)memory_structure_2;

            if (
                 memcmp(p1->interface_address,      p2->interface_address, 6)    ||
                                 p1->power_state         !=  p2->power_state
               )
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_SET_FWD_RULE_REQUEST:
        {
            struct setFwdRuleRequestALME *p1, *p2;
            uint8_t i;

            p1 = (struct setFwdRuleRequestALME *)memory_structure_1;
            p2 = (struct setFwdRuleRequestALME *)memory_structure_2;

            if (
                 memcmp(p1->classification_set.mac_da,              p2->classification_set.mac_da, 6)      ||
                                 p1->classification_set.mac_da_flag      !=  p2->classification_set.mac_da_flag     ||
                 memcmp(p1->classification_set.mac_sa,              p2->classification_set.mac_sa, 6)      ||
                                 p1->classification_set.mac_sa_flag      !=  p2->classification_set.mac_sa_flag     ||
                                 p1->classification_set.ether_type       !=  p2->classification_set.ether_type      ||
                                 p1->classification_set.ether_type_flag  !=  p2->classification_set.ether_type_flag ||
                                 p1->classification_set.vid              !=  p2->classification_set.vid             ||
                                 p1->classification_set.vid_flag         !=  p2->classification_set.vid_flag        ||
                                 p1->classification_set.pcp              !=  p2->classification_set.pcp             ||
                                 p1->classification_set.pcp_flag         !=  p2->classification_set.pcp_flag        ||
                                 p1->addresses_nr                        !=  p2->addresses_nr
               )
            {
                return 1;
            }

            if (p1->addresses_nr > 0 && (NULL == p1->addresses || NULL == p2->addresses))
            {
                // Malformed structure
                //
                return 1;
            }

            for (i=0; i<p1->addresses_nr; i++)
            {
                if (memcmp(p1->addresses[i], p2->addresses[i], 6))
                {
                    return 1;
                }
            }

            return 0;
        }

        case ALME_TYPE_SET_FWD_RULE_CONFIRM:
        {
            struct setFwdRuleConfirmALME *p1, *p2;

            p1 = (struct setFwdRuleConfirmALME *)memory_structure_1;
            p2 = (struct setFwdRuleConfirmALME *)memory_structure_2;

            if (
                 p1->rule_id      !=  p2->rule_id       ||
                 p1->reason_code  !=  p2->reason_code
               )
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_GET_FWD_RULES_REQUEST:
        {
            // Nothing to compare (this ALME primitive is always empty)
            //
            return 0;
        }

        case ALME_TYPE_GET_FWD_RULES_RESPONSE:
        {
            struct getFwdRulesResponseALME *p1, *p2;
            uint8_t i, j;

            p1 = (struct getFwdRulesResponseALME *)memory_structure_1;
            p2 = (struct getFwdRulesResponseALME *)memory_structure_2;

            if (p1->rules_nr != p2->rules_nr)
            {
                return 1;
            }

            if (p1->rules_nr > 0 && (NULL == p1->rules || NULL == p2->rules))
            {
                // Malformed structure
                //
                return 1;
            }

            for (i=0; i<p1->rules_nr; i++)
            {
                if (
                     memcmp(p1->rules[i].classification_set.mac_da,              p2->rules[i].classification_set.mac_da, 6)      ||
                                     p1->rules[i].classification_set.mac_da_flag      !=  p2->rules[i].classification_set.mac_da_flag     ||
                     memcmp(p1->rules[i].classification_set.mac_sa,              p2->rules[i].classification_set.mac_sa, 6)      ||
                                     p1->rules[i].classification_set.mac_sa_flag      !=  p2->rules[i].classification_set.mac_sa_flag     ||
                                     p1->rules[i].classification_set.ether_type       !=  p2->rules[i].classification_set.ether_type      ||
                                     p1->rules[i].classification_set.ether_type_flag  !=  p2->rules[i].classification_set.ether_type_flag ||
                                     p1->rules[i].classification_set.vid              !=  p2->rules[i].classification_set.vid             ||
                                     p1->rules[i].classification_set.vid_flag         !=  p2->rules[i].classification_set.vid_flag        ||
                                     p1->rules[i].classification_set.pcp              !=  p2->rules[i].classification_set.pcp             ||
                                     p1->rules[i].classification_set.pcp_flag         !=  p2->rules[i].classification_set.pcp_flag        ||
                                     p1->rules[i].addresses_nr                        !=  p2->rules[i].addresses_nr                       ||
                                     p1->rules[i].last_matched                        !=  p2->rules[i].last_matched
                   )
                {
                    return 1;
                }

                if (p1->rules[i].addresses_nr > 0 && (NULL == p1->rules[i].addresses || NULL == p2->rules[i].addresses))
                {
                    // Malformed structure
                    //
                    return 1;
                }

                for (j=0; j<p1->rules[i].addresses_nr; j++)
                {
                    if (memcmp(p1->rules[i].addresses[j], p2->rules[i].addresses[j], 6))
                    {
                        return 1;
                    }
                }
            }

            return 0;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_REQUEST:
        {
            struct modifyFwdRuleRequestALME *p1, *p2;
            uint8_t i;

            p1 = (struct modifyFwdRuleRequestALME *)memory_structure_1;
            p2 = (struct modifyFwdRuleRequestALME *)memory_structure_2;

            if (
                 p1->rule_id       !=  p2->rule_id      ||
                 p1->addresses_nr  !=  p2->addresses_nr
               )
            {
                return 1;
            }

            if (p1->addresses_nr > 0 && (NULL == p1->addresses || NULL == p2->addresses))
            {
                // Malformed structure
                //
                return 1;
            }

            for (i=0; i<p1->addresses_nr; i++)
            {
                if (memcmp(p1->addresses[i], p2->addresses[i], 6))
                {
                    return 1;
                }
            }

            return 0;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_CONFIRM:
        {
            struct modifyFwdRuleConfirmALME *p1, *p2;

            p1 = (struct modifyFwdRuleConfirmALME *)memory_structure_1;
            p2 = (struct modifyFwdRuleConfirmALME *)memory_structure_2;

            if (
                 p1->rule_id      !=  p2->rule_id      ||
                 p1->reason_code  !=  p2->reason_code
               )
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_REQUEST:
        {
            struct removeFwdRuleRequestALME *p1, *p2;

            p1 = (struct removeFwdRuleRequestALME *)memory_structure_1;
            p2 = (struct removeFwdRuleRequestALME *)memory_structure_2;

            if (p1->rule_id != p2->rule_id)
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_CONFIRM:
        {
            struct removeFwdRuleConfirmALME *p1, *p2;

            p1 = (struct removeFwdRuleConfirmALME *)memory_structure_1;
            p2 = (struct removeFwdRuleConfirmALME *)memory_structure_2;

            if (
                 p1->rule_id      !=  p2->rule_id      ||
                 p1->reason_code  !=  p2->reason_code
               )
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_GET_METRIC_REQUEST:
        {
            struct getMetricRequestALME *p1, *p2;

            p1 = (struct getMetricRequestALME *)memory_structure_1;
            p2 = (struct getMetricRequestALME *)memory_structure_2;

            if (memcmp(p1->interface_address, p2->interface_address, 6))
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_GET_METRIC_RESPONSE:
        {
            struct getMetricResponseALME *p1, *p2;
            uint8_t i;

            p1 = (struct getMetricResponseALME *)memory_structure_1;
            p2 = (struct getMetricResponseALME *)memory_structure_2;

            if (
                    p1->metrics_nr   !=  p2->metrics_nr   ||
                    p1->reason_code  !=  p2->reason_code
               )

            {
                return 1;
            }

            if (p1->metrics_nr > 0 && (NULL == p1->metrics || NULL == p2->metrics))
            {
                // Malformed structure
                //
                return 1;
            }

            for (i=0; i<p1->metrics_nr; i++)
            {
                if (
                                           memcmp(p1->metrics[i].neighbor_dev_address,               p2->metrics[i].neighbor_dev_address, 6)      ||
                                           memcmp(p1->metrics[i].local_intf_address,                 p2->metrics[i].local_intf_address,   6)      ||
                                                           p1->metrics[i].bridge_flag            !=           p2->metrics[i].bridge_flag                   ||
                     compare_1905_TLV_structures(&p1->metrics[i].tx_metric->tlv,                  &p2->metrics[i].tx_metric->tlv)                    ||
                     compare_1905_TLV_structures(&p1->metrics[i].rx_metric->tlv,                  &p2->metrics[i].rx_metric->tlv)

                   )
                {
                    return 1;
                }
            }

            return 0;
        }

        case ALME_TYPE_CUSTOM_COMMAND_REQUEST:
        {
            struct customCommandRequestALME *p1, *p2;

            p1 = (struct customCommandRequestALME *)memory_structure_1;
            p2 = (struct customCommandRequestALME *)memory_structure_2;

            if (p1->command !=  p2->command)
            {
                return 1;
            }

            return 0;
        }

        case ALME_TYPE_CUSTOM_COMMAND_RESPONSE:
        {
            struct customCommandResponseALME *p1, *p2;

            p1 = (struct customCommandResponseALME *)memory_structure_1;
            p2 = (struct customCommandResponseALME *)memory_structure_2;

            if (
                                 p1->bytes_nr  !=  p2->bytes_nr             ||
                 memcmp(p1->bytes,        p2->bytes, p1->bytes_nr)
               )

            {
                return 1;
            }

            return 0;
        }

        default:
        {
            // Unknown structure type
            //
            return 1;
        }
    }

    // This code cannot be reached
    //
    return 1;
}


void visit_1905_ALME_structure(uint8_t *memory_structure, visitor_callback callback, void (*write_function)(const char *fmt, ...), const char *prefix)
{
    // Buffer size to store a prefix string that will be used to show each
    // element of a structure on screen
    //
    #define MAX_PREFIX  100

    if (NULL == memory_structure)
    {
        return;
    }

    // The first byte of any of the valid structures is always the "tlv.type"
    // field.
    //
    switch (*memory_structure)
    {
        case ALME_TYPE_GET_INTF_LIST_REQUEST:
        {
            // There is nothing to visit. This TLV is always empty
            //
            return;
        }

        case ALME_TYPE_GET_INTF_LIST_RESPONSE:
        {
            struct getIntfListResponseALME *p;
            uint8_t i, j;

            p = (struct getIntfListResponseALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->interface_descriptors_nr), "interface_descriptors_nr",  "%d",  &p->interface_descriptors_nr);

            for (i=0; i < p->interface_descriptors_nr; i++)
            {
                char new_prefix[MAX_PREFIX];

                snprintf(new_prefix, MAX_PREFIX-1, "%sinterface_descriptors[%d]->", prefix, i);
                new_prefix[MAX_PREFIX-1] = 0x0;

                callback(write_function, new_prefix, sizeof(p->interface_descriptors[i].interface_address),       "interface_address",        "0x%02x", p->interface_descriptors[i].interface_address);
                callback(write_function, new_prefix, sizeof(p->interface_descriptors[i].interface_type),          "media_type",               "%d",    &p->interface_descriptors[i].interface_type);
                callback(write_function, new_prefix, sizeof(p->interface_descriptors[i].bridge_flag),             "bridge_flag",              "%d",    &p->interface_descriptors[i].bridge_flag);
                callback(write_function, new_prefix, sizeof(p->interface_descriptors[i].vendor_specific_info_nr), "vendor_specific_info_nr",  "%d",    &p->interface_descriptors[i].vendor_specific_info_nr);

                for (j=0; j < p->interface_descriptors[i].vendor_specific_info_nr; j++)
                {
                    snprintf(new_prefix, MAX_PREFIX-1, "%sinterface_descriptors[%d]->vendor_specific_info[%d]->", prefix, i, j);
                    new_prefix[MAX_PREFIX-1] = 0x0;

                    callback(write_function, new_prefix, sizeof(p->interface_descriptors[i].vendor_specific_info[j].ie_type),      "ie_type",      "%d",     &p->interface_descriptors[i].vendor_specific_info[j].ie_type);
                    callback(write_function, new_prefix, sizeof(p->interface_descriptors[i].vendor_specific_info[j].length_field), "length_field", "%d",     &p->interface_descriptors[i].vendor_specific_info[j].length_field);
                    callback(write_function, new_prefix, sizeof(p->interface_descriptors[i].vendor_specific_info[j].oui),          "oui",          "0x%02x",  p->interface_descriptors[i].vendor_specific_info[j].oui);
                    callback(write_function, new_prefix, p->interface_descriptors[i].vendor_specific_info[j].length_field - 3,     "vendor_si",    "0x%02x",  p->interface_descriptors[i].vendor_specific_info[j].vendor_si);
                }
            }

            return;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_REQUEST:
        {
            struct setIntfPwrStateRequestALME *p;

            p = (struct setIntfPwrStateRequestALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->interface_address),  "interface_address",  "0x%02x",  p->interface_address);
            callback(write_function, prefix, sizeof(p->power_state),        "power_state",        "%d",     &p->power_state);

            return;
        }

        case ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM:
        {
            struct setIntfPwrStateConfirmALME *p;

            p = (struct setIntfPwrStateConfirmALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->interface_address),  "interface_address",  "0x%02x",   p->interface_address);
            callback(write_function, prefix, sizeof(p->reason_code),        "reason_code",        "%d",      &p->reason_code);

            return;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_REQUEST:
        {
            struct getIntfPwrStateRequestALME *p;

            p = (struct getIntfPwrStateRequestALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->interface_address),  "interface_address",  "0x%02x",   p->interface_address);

            return;
        }

        case ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE:
        {
            struct getIntfPwrStateResponseALME *p;

            p = (struct getIntfPwrStateResponseALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->interface_address),  "interface_address",  "0x%02x",   p->interface_address);
            callback(write_function, prefix, sizeof(p->power_state),        "power_state",        "%d",      &p->power_state);

            return;
        }

        case ALME_TYPE_SET_FWD_RULE_REQUEST:
        {
            struct setFwdRuleRequestALME *p;
            uint8_t i;

            p = (struct setFwdRuleRequestALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->classification_set.mac_da),           "classification_set.mac_da",           "0x%02x",  p->classification_set.mac_da);
            callback(write_function, prefix, sizeof(p->classification_set.mac_da_flag),      "classification_set.mac_da_flag",      "%d",     &p->classification_set.mac_da_flag);
            callback(write_function, prefix, sizeof(p->classification_set.mac_sa),           "classification_set.mac_sa",           "0x%02x",  p->classification_set.mac_sa);
            callback(write_function, prefix, sizeof(p->classification_set.mac_sa_flag),      "classification_set.mac_sa_flag",      "%d",     &p->classification_set.mac_sa_flag);
            callback(write_function, prefix, sizeof(p->classification_set.ether_type),       "classification_set.ether_type",       "%d",     &p->classification_set.ether_type);
            callback(write_function, prefix, sizeof(p->classification_set.ether_type_flag),  "classification_set.ether_type_flag",  "%d",     &p->classification_set.ether_type_flag);
            callback(write_function, prefix, sizeof(p->classification_set.vid),              "classification_set.vid",              "%d",     &p->classification_set.vid);
            callback(write_function, prefix, sizeof(p->classification_set.vid_flag),         "classification_set.vid_flag",         "%d",     &p->classification_set.vid_flag);
            callback(write_function, prefix, sizeof(p->classification_set.pcp),              "classification_set.pcp",              "%d",     &p->classification_set.pcp);
            callback(write_function, prefix, sizeof(p->classification_set.pcp_flag),         "classification_set.pcp_flag",         "%d",     &p->classification_set.pcp_flag);
            callback(write_function, prefix, sizeof(p->addresses_nr),                        "addresses_nr",                        "%d",     &p->addresses_nr);

            for (i=0; i < p->addresses_nr; i++)
            {
                char new_prefix[MAX_PREFIX];

                snprintf(new_prefix, MAX_PREFIX-1, "%saddresses[%d]->", prefix, i);
                new_prefix[MAX_PREFIX-1] = 0x0;

                callback(write_function, new_prefix, sizeof(p->addresses[i]), "", "0x%02x",  p->addresses[i]);
            }

            return;
        }

        case ALME_TYPE_SET_FWD_RULE_CONFIRM:
        {
            struct setFwdRuleConfirmALME *p;

            p = (struct setFwdRuleConfirmALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->rule_id),      "rule_id",      "%d",  &p->reason_code);
            callback(write_function, prefix, sizeof(p->reason_code),  "reason_code",  "%d",  &p->reason_code);

            return;
        }

        case ALME_TYPE_GET_FWD_RULES_REQUEST:
        {
            // There is nothing to visit. This TLV is always empty
            //
            return;
        }

        case ALME_TYPE_GET_FWD_RULES_RESPONSE:
        {
            struct getFwdRulesResponseALME *p;
            uint8_t i, j;

            p = (struct getFwdRulesResponseALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->rules_nr), "rules_nr",  "%d",  &p->rules_nr);

            for (i=0; i < p->rules_nr; i++)
            {
                char new_prefix[MAX_PREFIX];

                snprintf(new_prefix, MAX_PREFIX-1, "%srules[%d]->", prefix, i);
                new_prefix[MAX_PREFIX-1] = 0x0;

                callback(write_function, new_prefix, sizeof(p->rules[i].addresses_nr), "addresses_nr",  "%d",  &p->rules[i].addresses_nr);

                for (j=0; j < p->rules[i].addresses_nr; j++)
                {
                    snprintf(new_prefix, MAX_PREFIX-1, "%srules[%d]->addresses[%d]", prefix, i, j);
                    new_prefix[MAX_PREFIX-1] = 0x0;

                    callback(write_function, new_prefix, sizeof(p->rules[i].addresses[j]), "", "0x%02x",  p->rules[i].addresses[j]);
                }

                callback(write_function, new_prefix, sizeof(p->rules[i].last_matched), "last_matched",  "%d",  &p->rules[i].last_matched);
            }

            return;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_REQUEST:
        {
            struct modifyFwdRuleRequestALME *p;
            uint8_t i;

            p = (struct modifyFwdRuleRequestALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->rule_id),      "rule_id",       "%d",  &p->rule_id);
            callback(write_function, prefix, sizeof(p->addresses_nr), "addresses_nr",  "%d",  &p->addresses_nr);

            for (i=0; i < p->addresses_nr; i++)
            {
                char new_prefix[MAX_PREFIX];

                snprintf(new_prefix, MAX_PREFIX-1, "%saddresses[%d]->", prefix, i);
                new_prefix[MAX_PREFIX-1] = 0x0;

                callback(write_function, new_prefix, sizeof(p->addresses[i]), "", "0x%02x",  p->addresses[i]);
            }

            return;
        }

        case ALME_TYPE_MODIFY_FWD_RULE_CONFIRM:
        {
            struct modifyFwdRuleConfirmALME *p;

            p = (struct modifyFwdRuleConfirmALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->rule_id),     "rule_id",      "%d",  &p->rule_id);
            callback(write_function, prefix, sizeof(p->reason_code), "reason_code",  "%d",  &p->reason_code);

            return;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_REQUEST:
        {
            struct removeFwdRuleRequestALME *p;

            p = (struct removeFwdRuleRequestALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->rule_id), "rule_id",      "%d",  &p->rule_id);

            return;
        }

        case ALME_TYPE_REMOVE_FWD_RULE_CONFIRM:
        {
            struct removeFwdRuleConfirmALME *p;

            p = (struct removeFwdRuleConfirmALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->rule_id),     "rule_id",      "%d",  &p->rule_id);
            callback(write_function, prefix, sizeof(p->reason_code), "reason_code",  "%d",  &p->reason_code);

            return;
        }

        case ALME_TYPE_GET_METRIC_REQUEST:
        {
            struct getMetricRequestALME *p;

            p = (struct getMetricRequestALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->interface_address),  "rule_id",  "0x%02x",  p->interface_address);

            return;
        }

        case ALME_TYPE_GET_METRIC_RESPONSE:
        {
            struct getMetricResponseALME *p;
            uint8_t i;

            p = (struct getMetricResponseALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->metrics_nr), "metrics_nr",  "%d",  &p->metrics_nr);

            for (i=0; i < p->metrics_nr; i++)
            {
                char new_prefix[MAX_PREFIX];

                snprintf(new_prefix, MAX_PREFIX-1, "%smetrics[%d]->", prefix, i);
                new_prefix[MAX_PREFIX-1] = 0x0;

                callback(write_function, new_prefix, sizeof(p->metrics[i].neighbor_dev_address), "neighbor_dev_address",        "0x%02x",   p->metrics[i].neighbor_dev_address);
                callback(write_function, new_prefix, sizeof(p->metrics[i].local_intf_address),   "local_intf_address",          "0x%02x",   p->metrics[i].local_intf_address);
                callback(write_function, new_prefix, sizeof(p->metrics[i].bridge_flag)   ,       "bridge_flag",                 "%d",      &p->metrics[i].bridge_flag);

                snprintf(new_prefix, MAX_PREFIX-1, "%smetrics[%d]->tx_metric->", prefix, i);
                new_prefix[MAX_PREFIX-1] = 0x0;

                visit_1905_TLV_structure(&p->metrics[i].tx_metric->tlv, callback, write_function, new_prefix);

                snprintf(new_prefix, MAX_PREFIX-1, "%smetrics[%d]->rx_metric->", prefix, i);
                new_prefix[MAX_PREFIX-1] = 0x0;

                visit_1905_TLV_structure(&p->metrics[i].rx_metric->tlv, callback, write_function, new_prefix);
            }

            return;
        }

        case ALME_TYPE_CUSTOM_COMMAND_REQUEST:
        {
            struct customCommandRequestALME *p;

            p = (struct customCommandRequestALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->command),  "command", "%d", &p->command);

            return;
        }

        case ALME_TYPE_CUSTOM_COMMAND_RESPONSE:
        {
            struct customCommandResponseALME *p;

            p = (struct customCommandResponseALME *)memory_structure;

            callback(write_function, prefix, sizeof(p->bytes_nr),  "bytes_nr", "%d",   &p->bytes_nr);
            callback(write_function, prefix, p->bytes_nr,          "bytes",    "%s",  p->bytes);

            return;
        }

        default:
        {
            // Ignore
            //
            return;
        }
    }

    // This code cannot be reached
    //
    return;
}

char *convert_1905_ALME_type_to_string(uint8_t alme_type)
{
    switch (alme_type)
    {
        case ALME_TYPE_GET_INTF_LIST_REQUEST:
            return "ALME_TYPE_GET_INTF_LIST_REQUEST";
        case ALME_TYPE_GET_INTF_LIST_RESPONSE:
            return "ALME_TYPE_GET_INTF_LIST_RESPONSE";
        case ALME_TYPE_SET_INTF_PWR_STATE_REQUEST:
            return "ALME_TYPE_SET_INTF_PWR_STATE_REQUEST";
        case ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM:
            return "ALME_TYPE_SET_INTF_PWR_STATE_CONFIRM";
        case ALME_TYPE_GET_INTF_PWR_STATE_REQUEST:
            return "ALME_TYPE_GET_INTF_PWR_STATE_REQUEST";
        case ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE:
            return "ALME_TYPE_GET_INTF_PWR_STATE_RESPONSE";
        case ALME_TYPE_SET_FWD_RULE_REQUEST:
            return "ALME_TYPE_SET_FWD_RULE_REQUEST";
        case ALME_TYPE_SET_FWD_RULE_CONFIRM:
            return "ALME_TYPE_SET_FWD_RULE_CONFIRM";
        case ALME_TYPE_GET_FWD_RULES_REQUEST:
            return "ALME_TYPE_GET_FWD_RULES_REQUEST";
        case ALME_TYPE_GET_FWD_RULES_RESPONSE:
            return "ALME_TYPE_GET_FWD_RULES_RESPONSE";
        case ALME_TYPE_MODIFY_FWD_RULE_REQUEST:
            return "ALME_TYPE_MODIFY_FWD_RULE_REQUEST";
        case ALME_TYPE_MODIFY_FWD_RULE_CONFIRM:
            return "ALME_TYPE_MODIFY_FWD_RULE_CONFIRM";
        case ALME_TYPE_REMOVE_FWD_RULE_REQUEST:
            return "ALME_TYPE_REMOVE_FWD_RULE_REQUEST";
        case ALME_TYPE_REMOVE_FWD_RULE_CONFIRM:
            return "ALME_TYPE_REMOVE_FWD_RULE_CONFIRM";
        case ALME_TYPE_GET_METRIC_REQUEST:
            return "ALME_TYPE_GET_METRIC_REQUEST";
        case ALME_TYPE_GET_METRIC_RESPONSE:
            return "ALME_TYPE_GET_METRIC_RESPONSE";
        default:
            return "Unknown";
    }
}
