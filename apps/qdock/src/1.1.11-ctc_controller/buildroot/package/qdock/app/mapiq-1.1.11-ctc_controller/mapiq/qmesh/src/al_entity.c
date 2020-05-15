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

// In the comments below, every time a reference is made (ex: "See Section 6.4"
// or "See Table 6-11") we are talking about the contents of the following
// document:
//
//   "IEEE Std 1905.1-2013"

#include "platform.h"
#include "utils.h"
#include "packet_tools.h"

#include "1905_tlvs.h"
#include "1905_cmdus.h"
#include "1905_alme.h"
#include "1905_l2.h"
#include "lldp_tlvs.h"
#include "lldp_payload.h"

#include "al.h"
#include "al_datamodel.h"
#include "al_send.h"
#include "al_recv.h"
#include "al_retry.h"
#include "al_utils.h"
#include "al_extension.h"
#include "al_cli.h"
#include "al_ubus_server.h"

#include <datamodel.h>

#include "platform_interfaces.h"
#include "platform_os.h"
#include "platform_alme_server.h"
#include "ubus_map.h"
#include <datamodel.h>

#include <string.h> // memcmp(), memcpy(), ...

#ifdef QDOCK
#include "linux/platform_os_priv.h"
#include "linux/platform_qdock.h"
#include <libubox/uloop.h>
#endif
#include "linux/platform_local.h"

#define TIMER_TOKEN_DISCOVERY          (1)
#define TIMER_TOKEN_GARBAGE_COLLECTOR  (2)
#define TIMER_TOKEN_AUTOCONFIG         (3)

////////////////////////////////////////////////////////////////////////////////
// Private functions and data
////////////////////////////////////////////////////////////////////////////////

// CMDUs can be received in multiple fragments/packets when they are too big to
// fit in a single "network transmission unit" (which is never bigger than
// MAX_NETWORK_SEGMENT_SIZE).
//
// Fragments that belong to one same CMDU contain the same 'mid' and different
// 'fragment id' values. In addition, the last fragment is the only one to
// contain the 'last fragment indicator' field set.
//
//   NOTE: This is all also explained in "Sections 7.1.1 and 7.1.2"
//
// This function will "buffer" fragments until either all pieces arrive or a
// timer expires (in which case all previous fragments are discarded/ignored)
//
//   NOTE: Instead of a timer, we will use a buffer that holds up to
//         MAX_MIDS_IN_FLIGHT CMDUs.
//         If we are still waiting for MAX_MIDS_IN_FLIGHT CMDUs to be completed
//         (ie. we haven't received all their fragments yet), and a new fragment
//         for a new CMDU arrives, we will discard all fragments from the
//         oldest one.
//
// Every time this function is called, two things can happen:
//
//   1. The just received fragment was the last one needed to complete a CMDU.
//      In this case, the CMDU structure result of all those fragments being
//      parsed is returned.
//
//   2. The just received fragment is not yet the last one needed to complete a
//      CMDU. In this case the fragment is internally buffered (ie. the caller
//      does not need to keep the passed buffer around in memory) and this
//      function returns NULL.
//
// This function received two arguments:
//
//   - 'packet_buffer' is a pointer to the received stream containing a
//     fragment (or a whole) CMDU
//
//   - 'len' is the length of this 'packet_buffer' in bytes
//
struct CMDU *_reAssembleFragmentedCMDUs(const uint8_t *packet_buffer, uint16_t len)
{
    #define MAX_MIDS_IN_FLIGHT     5
    #define MAX_FRAGMENTS_PER_MID  16

    // This is a static structure used to store the fragments belonging to up to
    // 'MAX_MIDS_IN_FLIGHT' CMDU messages.
    // Initially all entries are marked as "empty" by setting the 'in_use' field
    // to "0"
    //
    static struct _midsInFlight
    {
        uint8_t in_use;  // Is this entry free?

        uint16_t mid;     // 'mid' associated to this CMDU

        uint8_t src_addr[6];
        uint8_t dst_addr[6];
                       // These two (together with the 'mid' field) will be used
                       // to identify fragments belonging to one same CMDU.

        uint8_t fragments[MAX_FRAGMENTS_PER_MID];
                       // Each entry represents a fragment number.
                       //   - "1" means that fragment has been received
                       //   - "0" means no fragment with that number has been
                       //     received.

        uint8_t last_fragment;
                       // Number of the fragment carrying the
                       // 'last_fragment_indicator' flag.
                       // This is always a number between 0 and
                       // MAX_FRAGMENTS_PER_MID-1.
                       // Iniitally it is set to "MAX_FRAGMENTS_PER_MID",
                       // meaning that no fragment with the
                       // 'last_fragment_indicator' flag has been received yet.

        uint8_t *streams[MAX_FRAGMENTS_PER_MID+1];
        uint32_t streams_len[MAX_FRAGMENTS_PER_MID+1];
                       // Each of the bit streams associated to each fragment
                       //
                       // The size is "MAX_FRAGMENTS_PER_MID+1" instead of
                       // "MAX_FRAGMENTS_PER_MID" to store a final NULL entry
                       // (this makes it easier to later call
                       // "parse_1905_CMDU_from_packets()"

        uint32_t age;    // Used to keep track of which is the oldest CMDU for
                       // which a fragment was received (so that we can free
                       // it when the CMDUs buffer is full)

    } mids_in_flight[MAX_MIDS_IN_FLIGHT] = \
    {[ 0 ... MAX_MIDS_IN_FLIGHT-1 ] = (struct _midsInFlight) { .in_use = 0 }};

    static uint32_t current_age = 0;

    uint8_t  i, j;
    const uint8_t *p;
    struct CMDU_header cmdu_header;

    if (!parse_1905_CMDU_header_from_packet(packet_buffer, len, &cmdu_header))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Could not retrieve CMDU header from bit stream\n");
        return NULL;
    }
    PLATFORM_PRINTF_DEBUG_DETAIL("mid = %d, fragment_id = %d, last_fragment_indicator = %d\n",
                                 cmdu_header.mid, cmdu_header.fragment_id, cmdu_header.last_fragment_indicator);

    // Skip over ethernet header
    p = packet_buffer + (6+6+2);
    len -= (6+6+2);

    // Find the set of streams associated to this 'mid' and add the just
    // received stream to its set of streams
    //
    for (i = 0; i<MAX_MIDS_IN_FLIGHT; i++)
    {
        if (
                                              1        ==  mids_in_flight[i].in_use          &&
                                  cmdu_header.mid      ==  mids_in_flight[i].mid             &&
             0 == memcmp(cmdu_header.dst_addr,    mids_in_flight[i].dst_addr, 6)    &&
             0 == memcmp(cmdu_header.src_addr,    mids_in_flight[i].src_addr, 6)
           )
        {
            // Fragments for this 'mid' have previously been received. Add this
            // new one to the set.

            // ...but first check for errors
            //
            if (cmdu_header.fragment_id >= MAX_FRAGMENTS_PER_MID)
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Too many fragments (%d) for one same CMDU (max supported is %d)\n",
                                            cmdu_header.fragment_id, MAX_FRAGMENTS_PER_MID);
                PLATFORM_PRINTF_DEBUG_ERROR("  mid      = %d\n", cmdu_header.mid);
                PLATFORM_PRINTF_DEBUG_ERROR("  src_addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
                                            cmdu_header.src_addr[0], cmdu_header.src_addr[1], cmdu_header.src_addr[2],
                                            cmdu_header.src_addr[3], cmdu_header.src_addr[4], cmdu_header.src_addr[5]);
                PLATFORM_PRINTF_DEBUG_ERROR("  dst_addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
                                            cmdu_header.dst_addr[0], cmdu_header.dst_addr[1], cmdu_header.dst_addr[2],
                                            cmdu_header.dst_addr[3], cmdu_header.dst_addr[4], cmdu_header.dst_addr[5]);
                return NULL;
            }

            if (1 == mids_in_flight[i].fragments[cmdu_header.fragment_id])
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Ignoring duplicated fragment #%d\n", cmdu_header.fragment_id);
                PLATFORM_PRINTF_DEBUG_WARNING("  mid      = %d\n", cmdu_header.mid);
                PLATFORM_PRINTF_DEBUG_WARNING("  src_addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
                                              cmdu_header.src_addr[0], cmdu_header.src_addr[1], cmdu_header.src_addr[2],
                                              cmdu_header.src_addr[3], cmdu_header.src_addr[4], cmdu_header.src_addr[5]);
                PLATFORM_PRINTF_DEBUG_WARNING("  dst_addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
                                              cmdu_header.dst_addr[0], cmdu_header.dst_addr[1], cmdu_header.dst_addr[2],
                                              cmdu_header.dst_addr[3], cmdu_header.dst_addr[4], cmdu_header.dst_addr[5]);
                return NULL;
            }

            if (1 == cmdu_header.last_fragment_indicator && MAX_FRAGMENTS_PER_MID != mids_in_flight[i].last_fragment)
            {
                PLATFORM_PRINTF_DEBUG_WARNING("This fragment (#%d) and a previously received one (#%d) both contain the 'last_fragment_indicator' flag set. Ignoring...\n",
                                              cmdu_header.fragment_id, mids_in_flight[i].last_fragment);
                PLATFORM_PRINTF_DEBUG_WARNING("  mid      = %d\n", cmdu_header.mid);
                PLATFORM_PRINTF_DEBUG_WARNING("  src_addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
                                              cmdu_header.src_addr[0], cmdu_header.src_addr[1], cmdu_header.src_addr[2],
                                              cmdu_header.src_addr[3], cmdu_header.src_addr[4], cmdu_header.src_addr[5]);
                PLATFORM_PRINTF_DEBUG_WARNING("  dst_addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
                                              cmdu_header.dst_addr[0], cmdu_header.dst_addr[1], cmdu_header.dst_addr[2],
                                              cmdu_header.dst_addr[3], cmdu_header.dst_addr[4], cmdu_header.dst_addr[5]);
                return NULL;
            }

            // ...and now actually save the stream for later
            //
            mids_in_flight[i].fragments[cmdu_header.fragment_id] = 1;

            if (1 == cmdu_header.last_fragment_indicator)
            {
                mids_in_flight[i].last_fragment = cmdu_header.fragment_id;
            }

            mids_in_flight[i].streams[cmdu_header.fragment_id] = (uint8_t *)memalloc((sizeof(uint8_t) * len));
            memcpy(mids_in_flight[i].streams[cmdu_header.fragment_id], p, len);
            mids_in_flight[i].streams_len[cmdu_header.fragment_id] = len;

            mids_in_flight[i].age = current_age++;

            break;
        }
    }

    // If we get inside the next "if()", that means no previous entry matches
    // this 'mid' + 'src_addr' + 'dst_addr' tuple.
    // What we have to do then is to search for an empty slot and add this as
    // the first stream associated to this new tuple.
    //
    if (MAX_MIDS_IN_FLIGHT == i)
    {
        for (i = 0; i<MAX_MIDS_IN_FLIGHT; i++)
        {
            if (0 == mids_in_flight[i].in_use)
            {
                break;
            }
        }

        if (MAX_MIDS_IN_FLIGHT == i)
        {
            // All slots are in use!!
            //
            // We need to discard the oldest one (ie. the one with the lowest
            // 'age')
            //
            uint32_t lowest_age;

            lowest_age = mids_in_flight[0].age;
            j          = 0;

            for (i=1; i<MAX_MIDS_IN_FLIGHT; i++)
            {
                if (mids_in_flight[i].age < lowest_age)
                {
                    lowest_age = mids_in_flight[i].age;
                    j          = i;
                }
            }

            PLATFORM_PRINTF_DEBUG_WARNING("Discarding old CMDU fragments to make room for the just received one. CMDU being discarded:\n");
            PLATFORM_PRINTF_DEBUG_WARNING("  mid      = %d\n", mids_in_flight[j].mid);
            PLATFORM_PRINTF_DEBUG_WARNING("  mids_in_flight[j].src_addr = %02x:%02x:%02x:%02x:%02x:%02x\n", mids_in_flight[j].src_addr[0], mids_in_flight[j].src_addr[1], mids_in_flight[j].src_addr[2], mids_in_flight[j].src_addr[3], mids_in_flight[j].src_addr[4], mids_in_flight[j].src_addr[5]);
            PLATFORM_PRINTF_DEBUG_WARNING("  mids_in_flight[j].dst_addr = %02x:%02x:%02x:%02x:%02x:%02x\n", mids_in_flight[j].dst_addr[0], mids_in_flight[j].dst_addr[1], mids_in_flight[j].dst_addr[2], mids_in_flight[j].dst_addr[3], mids_in_flight[j].dst_addr[4], mids_in_flight[j].dst_addr[5]);

            for (i=0; i<MAX_FRAGMENTS_PER_MID; i++)
            {
                if (1 == mids_in_flight[j].fragments[i] && NULL != mids_in_flight[j].streams[i])
                {
                    free(mids_in_flight[j].streams[i]);
                }
            }

            mids_in_flight[j].in_use = 0;

            i = j;
        }

        // Now that we have our empty slot, initialize it and fill it with the
        // just received stream:
        //
        mids_in_flight[i].in_use = 1;
        mids_in_flight[i].mid    = cmdu_header.mid;

        memcpy(mids_in_flight[i].src_addr, cmdu_header.src_addr, 6);
        memcpy(mids_in_flight[i].dst_addr, cmdu_header.dst_addr, 6);

        for (j=0; j<MAX_FRAGMENTS_PER_MID; j++)
        {
            mids_in_flight[i].fragments[j] = 0;
            mids_in_flight[i].streams[j]   = NULL;
        }
        mids_in_flight[i].streams[MAX_FRAGMENTS_PER_MID] = NULL;

        mids_in_flight[i].fragments[cmdu_header.fragment_id]  = 1;
        mids_in_flight[i].streams[cmdu_header.fragment_id]    = (uint8_t *)memalloc((sizeof(uint8_t) * len));
        memcpy(mids_in_flight[i].streams[cmdu_header.fragment_id], p, len);
        mids_in_flight[i].streams_len[cmdu_header.fragment_id] = len;

        if (1 == cmdu_header.last_fragment_indicator)
        {
            mids_in_flight[i].last_fragment = cmdu_header.fragment_id;
        }
        else
        {
            mids_in_flight[i].last_fragment = MAX_FRAGMENTS_PER_MID;
              // NOTE: This means "no 'last_fragment_indicator' flag has been
              //       received yet.
        }

        mids_in_flight[i].age = current_age++;
    }

    // At this point we have an entry in the 'mids_in_flight' array (entry 'i')
    // where a new stream/fragment has been added.
    //
    // We now have to check if we have received all fragments for this 'mid'
    // and, if so, process them and obtain a CMDU structure that will be
    // returned to the caller of the function.
    //
    // Otherwise, return NULL.
    //
    if (MAX_FRAGMENTS_PER_MID != mids_in_flight[i].last_fragment)
    {
        struct CMDU *c;

        for (j=0; j<=mids_in_flight[i].last_fragment; j++)
        {
            if (0 == mids_in_flight[i].fragments[j])
            {
                PLATFORM_PRINTF_DEBUG_DETAIL("We still have to wait for more fragments to complete the CMDU message\n");
                return NULL;
            }
        }

        c = parse_1905_CMDU_from_packets(mids_in_flight[i].streams, mids_in_flight[i].streams_len);

        if (NULL == c)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("parse_1905_CMDU_header_from_packet() failed\n");
        }
        else
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("All fragments belonging to this CMDU have already been received and the CMDU structure is ready\n");
        }

        for (j=0; j<=mids_in_flight[i].last_fragment; j++)
        {
            free(mids_in_flight[i].streams[j]);
        }
        mids_in_flight[i].in_use = 0;

        return c;
    }

    PLATFORM_PRINTF_DEBUG_DETAIL("The last fragment has not yet been received\n");
    return NULL;
}

// Returns '1' if the packet has already been processed in the past and thus,
// should be discarded (to avoid network storms). '0' otherwise.
//
// According to what is explained in "Sections 7.5, 7.6 and 7.7" if a
// defragmented packet whose "AL MAC address TLV" and "message id" match one
// that has already been received in the past, then it should be discarded.
//
// I *personally* think the standard is "slightly" wrong here because *not* all
// CMDUs contain an "AL MAC address TLV".
// We could use the ethernet source address instead, however this would only
// work for those messages that are *not* relayed (one same duplicated relayed
// message can arrive at our local node with two different ethernet source
// addresses).
// Fortunately for us, all relayed CMDUs *do* contain an "AL MAC address TLV",
// thus this is what we are going to do:
//
//   1. If the CMDU is a relayed one, check against the "AL MAC" contained in
//      the "AL MAC address TLV"
//
//   2. If the CMDU is *not* a relayed one, check against the ethernet source
//      address
//
// This function keeps track of the latest MAX_DUPLICATES_LOG_ENTRIES tuples
// of ("mac_address", "message_id") and:
//
//   1. If the provided tuple matches an already existing one, this function
//      returns '1'
//
//   2. Otherwise, the entry is added (discarding, if needed, the oldest entry)
//      and this function returns '0'
//
uint8_t _checkDuplicates(uint8_t *src_mac_address, struct CMDU *c)
{
    #define MAX_DUPLICATES_LOG_ENTRIES 10

    static uint8_t  mac_addresses[MAX_DUPLICATES_LOG_ENTRIES][6];
    static uint16_t message_ids  [MAX_DUPLICATES_LOG_ENTRIES];
    static uint16_t message_types [MAX_DUPLICATES_LOG_ENTRIES];

    static uint8_t start = 0;
    static uint8_t total = 0;

    uint8_t mac_address[6];

    uint8_t i;

    // For relayed CMDUs, use the AL MAC, otherwise use the ethernet src MAC.
    //
    memcpy(mac_address, src_mac_address, 6);
    if (1 == c->relay_indicator)
    {
        uint8_t i;
        struct tlv *p;

        i = 0;
        while (NULL != (p = c->list_of_TLVs[i]))
        {
            if (TLV_TYPE_AL_MAC_ADDRESS_TYPE == p->type)
            {
                struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                memcpy(mac_address, t->al_mac_address, 6);
                break;
            }
            i++;
        }
    }

    // Also, discard relayed CMDUs whose AL MAC is our own (that means someone
    // is retrasnmitting us back a message we originally created)
    //
    if (1 == c->relay_indicator)
    {
        if (0 == memcmp(mac_address, DMalMacGet(), 6))
        {
            return 1;
        }
    }

    // Find if the ("mac_address", "message_id") tuple is already present in the
    // database
    //
    for (i=0; i<total; i++)
    {
        uint8_t index;

        index = (start + i) % MAX_DUPLICATES_LOG_ENTRIES;

        if (
             0 == memcmp(mac_addresses[index],    mac_address, 6) &&
                                  message_ids[index]    == c->message_id &&
                                  message_types[index]  == c->message_type
           )
        {
            // The entry already exists!
            //
            return 1;
        }
    }

    // This is a new entry, insert it into the cache and return "0"
    //
    if (total < MAX_DUPLICATES_LOG_ENTRIES)
    {
        // There is space for new entries
        //
        uint8_t index;

        index = (start + total) % MAX_DUPLICATES_LOG_ENTRIES;

        memcpy(mac_addresses[index], mac_address, 6);
        message_ids[index] = c->message_id;
        message_types[index] = c->message_type;

        total++;
    }
    else
    {
        // We need to replace the oldest entry
        //
        memcpy(mac_addresses[start], mac_address, 6);
        message_ids[start] = c->message_id;
        message_types[start] = c->message_type;

        start++;

        start = start % MAX_DUPLICATES_LOG_ENTRIES;
    }

    return 0;
}


// @brief Check if this type of 1905 CMDU be handled by this device map role.
//
// @return true if this type of 1905 CMDU can be handled and process next.
// @return false if this type of 1905 CMDU cannot be handled and drop it.
// @param c input CMDU info.
// @param map_role input device map role info.
//
static bool _checkHandle1905CmduTypeByRole(struct CMDU *c, uint8_t map_role)
{
    if (map_role & MAP_ROLE_CONTROLLER)
    {
        switch (c->message_type)
        {
            case CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE:
            case CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW:
            case CMDU_TYPE_AP_CAPABILITY_QUERY:
            case CMDU_TYPE_MAP_POLICY_CONFIG_REQUEST:
            case CMDU_TYPE_CHANNEL_PREFERENCE_QUERY:
            case CMDU_TYPE_CHANNEL_SELECTION_REQUEST:
            case CMDU_TYPE_AP_METRICS_QUERY:
            case CMDU_TYPE_ASSOCIATED_STA_LINK_METRICS_QUERY:
            case CMDU_TYPE_COMBINED_INFRASTRUCTURE_METRICS:
            case CMDU_TYPE_CLIENT_STEERING_REQUEST:
            case CMDU_TYPE_CLIENT_ASSOCIATION_CONTROL:
            case CMDU_TYPE_BACKHAUL_STEERING_REQUEST:
                return false;
            default:
                return true;
        }
    }
    else if (map_role == MAP_ROLE_AGENT)
    {
        switch (c->message_type)
        {
            case CMDU_TYPE_AP_CAPABILITY_REPORT:
            case CMDU_TYPE_CHANNEL_PREFERENCE_REPORT:
            case CMDU_TYPE_CHANNEL_SELECTION_RESPONSE:
            case CMDU_TYPE_OPERATING_CHANNEL_REPORT:
            case CMDU_TYPE_AP_METRICS_RESPONSE:
            case CMDU_TYPE_ASSOCIATED_STA_LINK_METRICS_RESPONSE:
            case CMDU_TYPE_STEERING_COMPLETED:
            case CMDU_TYPE_BACKHAUL_STEERING_RESPONSE:
                return false;
            default:
                return true;
        }
    }

    return true;
}

// According to "Section 7.6", if a received packet has the "relayed multicast"
// bit set, after processing, we must forward it on all authenticated 1905
// interfaces (except on the one where it was received).
//
// This function checks if the provided 'c' structure has that "relayed
// multicast" flag set and, if so, retransmits it on all local interfaces
// (except for the one whose MAC address matches 'receiving_interface_addr') to
// 'destination_mac_addr' and the same "message id" (MID) as the one contained
// in the originally received 'c' structure.
//
void _checkForwarding(uint32_t receiving_interface_index, uint8_t *source_mac_addr, uint8_t *destination_mac_addr, struct CMDU *c)
{
    if (!c->relay_indicator)
        return;

    // Retransmit message
    //
    const char *aux = convert_1905_CMDU_type_to_string(c->message_type);
    PLATFORM_PRINTF_DEBUG_DETAIL("Relay multicast flag set. Forwarding...\n");
    PLATFORM_PRINTF_DEBUG_INFO("--> %s (forwarding from %s to all other interfaces)\n", aux, DMinterfaceIndexToInterfaceName(receiving_interface_index));

    if (0 == send1905Multicast(c, receiving_interface_index, source_mac_addr))
    {
        PLATFORM_PRINTF_DEBUG_WARNING("Could not retransmit 1905 message on other interfaces\n");
    }
}

#ifdef QDOCK
void _checkReceiveToApp(uint8_t *src, uint8_t *dst, struct CMDU *c)
{
    dlist_head *tlv = NULL;
    if (c->extra_info.flag) {
        if (c->extra_info.flag & CMDU_EXTRAFLAG_NOTIFY_WITH_PAYLOAD)
            tlv = &c->extra_info.tlv_raws;
        mapapi_event_receive_frame(src, dst, c->message_type, tlv);
    }
}

#ifdef SPARTAN_PLATFORM
static void start_wps_on_iface(struct interfaceWifi* ifw, const char* iface_desc)
{
    PLATFORM_PRINTF_DEBUG_INFO("Push button configuration start on '%s' wireless interface(%s)\n",
                                iface_desc, ifw->i.name ? ifw->i.name : "unknown");
    IFW_START_WPS(ifw);
}
#endif

/* Follow the below sequence to pich interface to start WPS:
 * 1/ the unassociated backhaul sta interface
 * 2/ the first 5G fronthaul ap interface
 * 3/ the first 24G fronthaul ap interface
 * 4/ the other interface
 * TODO: our platform do not support fronthual 2.4G, so currently only
 * pick one interface to start wps. Should pick the same ssid interface
 * when we support the 2.4G fronthaul feature
 * */
static bool _pickAndstartWPSonInterface(void)
{
    struct interface *intf;
#ifndef SPARTAN_PLATFORM
    struct interfaceWifi *ifw;
#endif
    struct interfaceWifi *ifw_bSTA = NULL;
    struct interfaceWifi *ifw_5G_fBSS = NULL;
    struct interfaceWifi *ifw_24G_fBSS = NULL;
#ifdef SPARTAN_PLATFORM
    struct interfaceWifi *ifw_5G_nBSS = NULL;
    struct interfaceWifi *ifw_24G_nBSS = NULL;
    char buf[64];
    FILE *fp = NULL;
    const char* bh_if = "wifi0_7";
#endif

    dlist_for_each(intf, local_device->interfaces, l)
    {
        struct interfaceWifi *ifw = (struct interfaceWifi *)intf;
        if (intf->type != interface_type_wifi)
            continue;

        if (ifw->role == interface_wifi_role_sta && ifw->bssInfo.backhaul)
            ifw_bSTA = ifw;
        else if (ifw->role == interface_wifi_role_ap && ifw->bssInfo.fronthaul && ifw->radio)
        {
            if (!ifw_24G_fBSS && ifw->radio->band_supported == IEEE80211_FREQUENCY_BAND_2_4_GHZ)
                ifw_24G_fBSS = ifw;
            else if (!ifw_5G_fBSS && ifw->radio->band_supported == IEEE80211_FREQUENCY_BAND_5_GHZ)
                ifw_5G_fBSS = ifw;
        }
#ifdef SPARTAN_PLATFORM
        /* record 1st normal 5g and 2.4g interface for later use
	 * when sta is associated with fronthaul bss, local backhaul
	 * fronthaul status may not be correct which is not a vaid
	 * map scenarios, but may happen for spartan, we should not
	 * start wps on wifi0_7 which is backhaul interface.*/
        else if (ifw->role == interface_wifi_role_ap &&
                !ifw->bssInfo.fronthaul &&
                !ifw->bssInfo.backhaul && ifw->radio &&
		(ifw->i.name && strncmp(ifw->i.name, bh_if, strlen(bh_if) + 1))) {
            if (!ifw_24G_nBSS && ifw->radio->band_supported == IEEE80211_FREQUENCY_BAND_2_4_GHZ)
                ifw_24G_nBSS = ifw;
            else if (!ifw_5G_nBSS && ifw->radio->band_supported == IEEE80211_FREQUENCY_BAND_5_GHZ)
                ifw_5G_nBSS = ifw;
        }
#endif
    }

#ifdef SPARTAN_PLATFORM
    /* there is some issue bssInfo.bssid[i], sometimes even if STA interface is associated
      with backhaul ap, the bssid still return all ZERO, use .backhaul_info here instead */
    if (ifw_bSTA) {
        fp = fopen("/tmp/.backhaul_info", "r");
        if (fp) {
            if (fread(buf, 1, sizeof(buf), fp) <= sizeof(buf)) {
                if (strncmp(buf, "wifi", strlen("wifi")) &&
                    strncmp(buf, "ethernet", strlen("ethernet"))) {
                    start_wps_on_iface(ifw_bSTA, "bSTA");
                    fclose(fp);
                    return true;
                }
            }
            fclose(fp);
        }
    }

    if (ifw_5G_fBSS)
        start_wps_on_iface(ifw_5G_fBSS, "5G fBSS");
    else if (ifw_5G_nBSS)
        start_wps_on_iface(ifw_5G_nBSS, "5G normal");

    if (ifw_24G_fBSS)
        start_wps_on_iface(ifw_24G_fBSS, "2.4G fBSS");
    else if (ifw_24G_nBSS)
        start_wps_on_iface(ifw_24G_nBSS, "2.4G normal");

    return true;
#else
    ifw = ifw_5G_fBSS ? ifw_5G_fBSS : ifw_24G_fBSS;
    if (ifw_bSTA && ifw_bSTA->bssInfo.bssid[0] == 0x0
                && ifw_bSTA->bssInfo.bssid[1] == 0x0
                && ifw_bSTA->bssInfo.bssid[2] == 0x0
                && ifw_bSTA->bssInfo.bssid[3] == 0x0
                && ifw_bSTA->bssInfo.bssid[4] == 0x0
                && ifw_bSTA->bssInfo.bssid[5] == 0x0)
        ifw = ifw_bSTA;

    if (ifw)
    {
        PLATFORM_PRINTF_DEBUG_INFO("Push button configuration start on bSTA/fBSS wireless interface(%s)\n", ifw->i.name ? ifw->i.name : "unknown");
        IFW_START_WPS(ifw);
        return true;
    }
#endif

    PLATFORM_PRINTF_DEBUG_INFO("Push button configuration start on other interface\n");
    return false;
}

void process_ALEvent(uint8_t *queue_message, uint8_t queue_id);
void parse_AlEvent_callback(struct uloop_fd *fd, unsigned int events);
static void _addAlQueueIntoLoop(uint8_t queue_id)
{
    static struct uloop_fd fd = {
        .fd = -1,
        .cb = parse_AlEvent_callback,
    };
    fd.fd = getSdFromQueueId(queue_id);
    if (fd.fd < 0)
        return;

    uloop_fd_add(&fd, ULOOP_READ);
}
#endif

static uint8_t _triggerAPAutoConfigurationOnNextRadio(void)
{
    struct radio *radio;
    dlist_for_each(radio, local_device->radios, l)
    {
        if (!radio->configured)
        {
            PLATFORM_PRINTF_DEBUG_DETAIL("Radio %s is unconfigured and uses the same freq band. Sending WSC-M1...\n", radio->name);

            // Obtain WSC-M1 and send the WSC TLV
            //
            wscBuildM1(radio, &map_config.wsc_data);

            // Note that refer to Multi-AP_Specification v1.0
            // 17.1.3 1905 AP-Autoconfiguration WSC message format (extended)
            // If the message is sent by the Multi-AP Agent:
            // One AP Radio Basic Capabilities TLV (see section 17.2.7).
            // One WSC TLV (containing M1).
            // It's always need one AP Radio Basic Capabilities TLV in WSC M1 Packet
            if ( 0 == send1905APAutoconfigurationWSCM1Packet(registrar.d->receiving_interface_name, getNextMid(),
                     registrar.d->al_mac_addr, radio->wsc_info->m1, radio->wsc_info->m1_len, radio, 1))
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 'AP autoconfiguration WSC-M1' message\n");
                return 0;
            }
            return 1;
        }
    }

    /* All radios configured -> whole system is configured */
    local_device->configured = true;
    mapapi_event_agent_configured();
    PLATFORM_PRINTF_DEBUG_INFO("All the radios on local device are configured\n");
    return 0;
}

uint8_t triggerDeviceAPAutoConfiguration(bool imm)
{
    uint32_t now = PLATFORM_GET_TIMESTAMP();

    if (!registrar.d)
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Fail to trigger the AutoConfiguration: No controller found\n");
        return 0;
    }

    if (!imm && ((now - local_device->configure_ts) < map_config.autoconf_wait * 1000))
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Fail to trigger the AutoConfiguration: Still in AutoConfiguration process\n");
        return 0;
    }

    PLATFORM_PRINTF_DEBUG_INFO("Trigger the AutoConfiguration for the unconfigured radios on this device\n");

    local_device->configure_ts = now;
    return _triggerAPAutoConfigurationOnNextRadio();
}

void triggerAPSearchProcess(void)
{
    static uint8_t ind = 0;
    if (registrarIsLocal())
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Skipping AP Search on registrar device\n");
        return;
    }

    PLATFORM_PRINTF_DEBUG_INFO("Trigger AP Search for finding the controller/registrar\n");

    /* Some controller can not process the multi Searchs in same time.
     * Here we want to search the controller, so send Search each time with different band */
    if ((ind++) & 0x01)
        send1905APAutoconfigurationSearchPacket(getNextMid(), IEEE80211_FREQUENCY_BAND_5_GHZ);
    else
        send1905APAutoconfigurationSearchPacket(getNextMid(), IEEE80211_FREQUENCY_BAND_2_4_GHZ);
}

void tiggerAPAutoconfigurationRenewProcess(void)
{
    if (!registrarIsLocal())
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Skipping AP Auto-configuration Renew on agent device\n");
        return;
    }

    /* Assume freq_band info is IEEE80211_FREQUENCY_BAND_2_4_GHZ as default,
     * refer to Multi-AP_Specification v1.0  Chapter 7.1  AP configuration
     * Multi-AP Agent will ignore the value specified in the SupportedFreqBand TLV
     * of the AP-Autoconfiguration Renew message */
    send1905APAutoconfigurationRenewPacket(getNextMid(), IEEE80211_FREQUENCY_BAND_2_4_GHZ);
}

////////////////////////////////////////////////////////////////////////////////
// Public functions
////////////////////////////////////////////////////////////////////////////////

uint8_t start1905AL()
{
    uint8_t   queue_id;

    struct interface *interface;

    // Create a queue that will later be used by the platform code to notify us
    // when certain types of "events" take place
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Creating events queue...\n");
    queue_id = PLATFORM_CREATE_QUEUE("AL_events");
    if (0 == queue_id)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Could not create events queue\n");
        return AL_ERROR_OS;
    }

#ifdef QDOCK
    if (map_config.role & MAP_ROLE_AGENT)
    {
        qdock_platform_init();
        PLATFORM_PRINTF_DEBUG_DETAIL("Retrieving list of local radios and wirelese interfaces throught qdock...\n");
        qdock_collect_local_infos();
        qdock_collect_local_registar();
    } else {
        local_collect_local_registrar();
    }
#endif


    // We are interested in processing 1905 packets that arrive on any of the
    // 1905 interfaces.
    // For this we are going to tell the platform code that we want to receive
    // a message on the just created queue every time a new 1905 packet arrives
    // on any of those interfaces.
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering packet arrival event for each interface...\n");
    dlist_for_each(interface, local_device->interfaces, l)
    {
        struct event1905Packet aux;

#ifdef QDOCK
        if (interface->type == interface_type_wifi)
            continue;
#endif
        aux.interface_name = interface->name;
        memcpy(aux.interface_mac_address, interface->addr, 6);
        memcpy(aux.al_mac_address,        local_device->al_mac_addr, 6);

        if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_NEW_1905_PACKET, &aux))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("Could not register callback for 1905 packets in interface %s\n", interface->name);
            return AL_ERROR_OS;
        }
        PLATFORM_PRINTF_DEBUG_DETAIL("Register new 1905 packet to %s --> OK\n", interface->name);
    }

    // We are also interested in processing a 60 seconds timeout event (so that
    // we can send new discovery messages into the network)
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering DISCOVERY time out event (periodic)...\n");
    {
        struct eventTimeOut aux;

        aux.timeout_ms = 60000;  // 60 seconds
        aux.token      = TIMER_TOKEN_DISCOVERY;

        if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC, &aux))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("Could not register timer callback\n");
            return AL_ERROR_OS;
        }
    }

    // ...and a slighlty higher timeout to "clean" the database from nodes that
    // have left the network without notice
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering GARBAGE COLLECTOR time out event (periodic)...\n");
    {
        struct eventTimeOut aux;

        aux.timeout_ms = 70000;  // 70 seconds
        aux.token      = TIMER_TOKEN_GARBAGE_COLLECTOR;

        if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC, &aux))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("Could not register timer callback\n");
            return AL_ERROR_OS;
        }
    }

    // We are also interested in processing a 10 seconds timeout event to search the controller
    // and get the latest configuration from controller
    //
    if (!registrarIsLocal() && map_config.search_period)
    {
        PLATFORM_PRINTF_DEBUG_DETAIL("Registering AUTO CONFIURATION time out event (periodic)...\n");
        {
            struct eventTimeOut aux;

            aux.timeout_ms = map_config.search_period * 1000;  // default is 5 seconds
            aux.token      = TIMER_TOKEN_AUTOCONFIG;

            if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC, &aux))
            {
                PLATFORM_PRINTF_DEBUG_ERROR("Could not register timer callback\n");
                return AL_ERROR_OS;
            }
        }
    }

    // As soon as we enter the queue message processing loop we want to start
    // the discovery process as if a "DISCOVERY timeout" event had just
    // happened.
    // In other words, we want the first "DISCOVERY timeout" event to take place
    // at t=0 and then every 60 seconds.
    // In order to "force" this first event at t=0 we use a new timer event,
    // but this time this is a one time (ie. non-periodic) timer which will
    // time out in just one second from now.
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering a one time forced DISCOVERY event...\n");
    {
        struct eventTimeOut aux;

        aux.timeout_ms = 1;
        aux.token      = TIMER_TOKEN_DISCOVERY;

        if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_TIMEOUT, &aux))
        {
            PLATFORM_PRINTF_DEBUG_ERROR("Could not register timer callback\n");
            return AL_ERROR_OS;
        }
    }

    // Do also register the ALME interface (ie. we want ALME REQUEST messages to
    // be inserted into the queue so that we can process them)
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering the ALME interface...\n");
    if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_NEW_ALME_MESSAGE, NULL))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Could not register ALME messages callback\n");
        return AL_ERROR_OS;
    }

    // ...and the "push button" event, so that when the platform detects that
    // the user has pressed the button associated to the "push button"
    // configuration mechanism, we are notified.
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering the PUSH BUTTON event...\n");
    if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_PUSH_BUTTON, NULL))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Could not register 'push button' event\n");
        return AL_ERROR_OS;
    }

    // ...and the "new authenticated link" event, needed to produce the "push
    // button join notification" message.
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering the NEW AUTHENTICATED LINK event...\n");
    if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK, NULL))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Could not register 'authenticated link' event\n");
        return AL_ERROR_OS;
    }

    // ...and the "topology change notification" event, needed to inform the
    // other 1905 nodes that some aspect of our local topology has changed.
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Registering the TOPOLOGY CHANGE NOTIFICATION event...\n");
    if (0 == PLATFORM_REGISTER_QUEUE_EVENT(queue_id, PLATFORM_QUEUE_EVENT_TOPOLOGY_CHANGE_NOTIFICATION, NULL))
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Could not register 'topology change' event\n");
        return AL_ERROR_OS;
    }

    // Any third-party software based on ieee1905 can extend the protocol
    // behaviour
    //
    if (0 == start1905ALExtensions())
    {
        PLATFORM_PRINTF_DEBUG_ERROR("Could not register all 1905 protocol extensions\n");
        return AL_ERROR_PROTOCOL_EXTENSION;
    }

    initCmduRetry();
    mapcli_init();

    if (registrarIsLocal())
        REGISTRAR_SYNC_BSSCFGS();

#ifdef QDOCK
    mapapi_server_init();
    _addAlQueueIntoLoop(queue_id);
    PLATFORM_PRINTF_DEBUG_DETAIL("Waiting for new queue message...\n");
    uloop_run();

    PLATFORM_PRINTF_DEBUG_DETAIL("Exit uloop_run()\n");

    qdock_platform_deinit();
    deinitCmduRetry();
    mapcli_deinit();
    mapapi_server_deinit();
    uloop_done();
    return 0;
}
#else
    // Prepare the message queue
    //
    PLATFORM_PRINTF_DEBUG_DETAIL("Allocating memory to hold a queue message...\n");
    queue_message = (uint8_t *)memalloc(MAX_NETWORK_SEGMENT_SIZE+13);

    PLATFORM_PRINTF_DEBUG_DETAIL("Entering read-process loop...\n");
    while(1)
    {
#endif

#ifdef QDOCK
uint8_t queue_message[MAX_NETWORK_SEGMENT_SIZE+13];
void parse_AlEvent_callback(struct uloop_fd *fd, unsigned int events)
{
    uint8_t queue_id = getQueueIdFomrSd(fd->fd);
    if (0 == queue_id)
        return;
    {
#endif

#ifndef QDOCK
        const uint8_t  *p;
        uint8_t   message_type;
        uint16_t  message_len;

        PLATFORM_PRINTF_DEBUG_DETAIL("\n");
        PLATFORM_PRINTF_DEBUG_DETAIL("Waiting for new queue message...\n");
#endif
        /* coverity[tainted_data_argument] - ignor queue_message tainted */
        if (0 == PLATFORM_READ_QUEUE(queue_id, queue_message))
        {
            PLATFORM_PRINTF_DEBUG_WARNING("Something went wrong while trying to retrieve a new message from the queue. Ignoring...\n");
#ifdef QDOCK
            return;
#else
            continue;
#endif
        }

#ifdef QDOCK
    }
    process_ALEvent(queue_message, queue_id);
}

void process_ALEvent(uint8_t *queue_message, uint8_t queue_id)
{
    {
        uint8_t i;
#endif
        const uint8_t  *p;
        uint8_t   message_type;
        uint16_t  message_len;

        // The first byte of 'queue_message' tells us the type of message that
        // we have just received
        //
        p = &queue_message[0];
        _E1B(&p, &message_type);
        _E2B(&p, &message_len);

        PLATFORM_PRINTF_DEBUG_DETAIL("Process new queue message %u, len %u\n", message_type, message_len);
        switch(message_type)
        {
            case PLATFORM_QUEUE_EVENT_NEW_1905_PACKET:
            {
                const uint8_t *q;

                struct interfaceInfo *x;

                uint8_t  dst_addr[6];
                uint8_t  src_addr[6];
                uint16_t ether_type;
                uint32_t receiving_interface_index;

                uint8_t  receiving_interface_addr[6];
                const char  *receiving_interface_name;

                _E4B(&p, &receiving_interface_index);
                // The first six bytes of the message payload contain the MAC
                // address of the interface where the packet was received
                //
                _EnB(&p, receiving_interface_addr, 6);
                PLATFORM_PRINTF_DEBUG_DETAIL("receiving_interface_addr: " MACSTR " \n", MAC2STR(receiving_interface_addr));
                message_len -= 6;

                receiving_interface_name = DMinterfaceIndexToInterfaceName(receiving_interface_index);
                if (NULL == receiving_interface_name)
                {
                    PLATFORM_PRINTF_DEBUG_ERROR("A packet was receiving on interface_index %d, which does not match any local interface.\n", receiving_interface_index);
#ifdef QDOCK
                    return;
#else
                    continue;
#endif
                }
                PLATFORM_PRINTF_DEBUG_DETAIL("receiving_interface_name: %s\n", receiving_interface_name);

                x = PLATFORM_GET_1905_INTERFACE_INFO(receiving_interface_name);
                if (NULL == x)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not retrieve info of interface %s\n", receiving_interface_name);
#ifdef QDOCK
                    return;
#else
                    continue;
#endif
                }
                if (0 == x->is_secured)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("This interface (%s) is not secured. No packets should be received. Ignoring...\n", receiving_interface_name);
                    free_1905_INTERFACE_INFO(x);
#ifdef QDOCK
                    return;
#else
                    continue;
#endif
                }
                free_1905_INTERFACE_INFO(x);

                q = p;

                // The next bytes are the actual packet payload (ie. the
                // ethernet payload)
                //
                _EnB(&q, dst_addr, 6);
                _EnB(&q, src_addr, 6);
                _E2B(&q, &ether_type);

                PLATFORM_PRINTF_DEBUG_DETAIL("New queue message arrived: packet captured on interface %s\n", receiving_interface_name);
                PLATFORM_PRINTF_DEBUG_DETAIL("    Dst address: %02x:%02x:%02x:%02x:%02x:%02x\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_addr[4], dst_addr[5]);
                PLATFORM_PRINTF_DEBUG_DETAIL("    Src address: %02x:%02x:%02x:%02x:%02x:%02x\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_addr[4], src_addr[5]);
                PLATFORM_PRINTF_DEBUG_DETAIL("    Ether type : 0x%04x\n", ether_type);

                switch(ether_type)
                {
                    case ETHERTYPE_LLDP:
                    {
                        struct PAYLOAD *payload;

                        PLATFORM_PRINTF_DEBUG_DETAIL("LLDP message received.\n");

                        payload = parse_lldp_PAYLOAD_from_packet(q);

                        if (NULL == payload)
                        {
                            PLATFORM_PRINTF_DEBUG_INFO("Invalid bridge discovery message. Ignoring...\n");
                        }
                        else
                        {
                            PLATFORM_PRINTF_DEBUG_DETAIL("LLDP message contents:\n");
                            visit_lldp_PAYLOAD_structure(payload, print_callback, PLATFORM_PRINTF_RAW_DETAIL, "");

                            processLlpdPayload(payload, receiving_interface_index);

                            free_lldp_PAYLOAD_structure(payload);
                        }

                        break;
                    }

                    case ETHERTYPE_1905:
                    {
                        struct CMDU *c;

                        PLATFORM_PRINTF_DEBUG_DETAIL("CMDU message received. Reassembling...\n");

                        c = _reAssembleFragmentedCMDUs(p, message_len);

                        if (NULL == c)
                        {
                            // This was just a fragment part of a big CMDU.
                            // The data has been internally cached, waiting for
                            // the rest of pieces.
                        }
                        else
                        {
                            uint8_t res = 0;
                            if (
                                 1 == _checkDuplicates(src_addr, c)
                               )
                            {
                               PLATFORM_PRINTF_DEBUG_DETAIL("Receiving on %s a CMDU which is a duplicate of a previous one (mid = %d). Discarding...\n", receiving_interface_name, c->message_id);
                            }
                            // Filter 1905 CMDU type by map_role Controller or Agent
                            else if (map_config.filter_1905packet && !_checkHandle1905CmduTypeByRole(c, map_config.role))
                            {
                                PLATFORM_PRINTF_DEBUG_DETAIL("Receiving 1905 CMDU which type(0x%04x) is not belong to role(%s). Discarding...\n", c->message_type, map_config.role == MAP_ROLE_CONTROLLER ? "controller":"agent");
                            }
                            else
                            {
                                PLATFORM_PRINTF_DEBUG_DETAIL("CMDU message contents:\n");
                                visit_1905_CMDU_structure(c, print_callback, PLATFORM_PRINTF_RAW_DETAIL, "");

                                // Process the message on the local node
                                //
                                res = process1905Cmdu(c, receiving_interface_index, src_addr, dst_addr, queue_id);
                                if (PROCESS_CMDU_OK_TRIGGER_AP_SEARCH == (res & PROCESS_CMDU_RESULT_MASK))
                                {
                                    _triggerAPAutoConfigurationOnNextRadio();
                                }

                                // It might be necessary to retransmit this
                                // message on the rest of interfaces (depending
                                // on the "relayed multicast" flag
                                //
                                _checkForwarding(receiving_interface_index, src_addr, dst_addr, c);

                                _checkReceiveToApp(src_addr, dst_addr, c);
                            }

                            if (!(res & PROCESS_CMDU_CONSUMED))
                                free_1905_CMDU_structure(c);
                        }

                        break;
                    }

                    default:
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Unknown ethertype 0x%04x!! Ignoring...\n", ether_type);
                        break;
                    }
                }

                break;
            }

            case PLATFORM_QUEUE_EVENT_NEW_ALME_MESSAGE:
            {
                // ALME messages contain:
                //
                //   1- one byte with the "client id" (which must be used when
                //      later calling "PLATFORM_SEND_ALME_REPLY()")
                //
                //   2- the bit stream representation of an ALME TLV.
                //
                // We just need to convert it into a struct and process it:
                //
                uint8_t   alme_client_id;
                uint8_t  *alme_tlv;

                _E1B(&p, &alme_client_id);

                PLATFORM_PRINTF_DEBUG_DETAIL("New queue message arrived: ALME message (client ID = %d).\n", alme_client_id);

                alme_tlv = parse_1905_ALME_from_packet(p);
                if (NULL == alme_tlv)
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Invalid ALME message. Ignoring...\n");
                }

                PLATFORM_PRINTF_DEBUG_DETAIL("ALME message contents:\n");
                visit_1905_ALME_structure((uint8_t *)alme_tlv, print_callback, PLATFORM_PRINTF_RAW_DETAIL, "");

                process1905Alme(alme_tlv, alme_client_id);

                free_1905_ALME_structure(alme_tlv);

                break;
            }

            case PLATFORM_QUEUE_EVENT_TIMEOUT:
            case PLATFORM_QUEUE_EVENT_TIMEOUT_PERIODIC:
            {
                uint32_t  timer_id;

                // The message payload of this type of messages only contains
                // four bytes with the "timer ID" that expired.
                //
                _E4B(&p, &timer_id);

                PLATFORM_PRINTF_DEBUG_DETAIL("New queue message arrived: timer 0x%08x expired\n", timer_id);

                switch(timer_id)
                {
                    case TIMER_TOKEN_DISCOVERY:
                    {
                        uint16_t mid;

                        char **ifs_names;
                        uint8_t  ifs_nr;

                        PLATFORM_PRINTF_DEBUG_DETAIL("Running discovery...\n");

                        // According to "Section 8.2.1.1" and "Section 8.2.1.2"
                        // we now have to send a "Topology discovery message"
                        // followed by a "802.1 bridge discovery message" but,
                        // according to the rules in "Section 7.2", only on each
                        // and every of the *authenticated* 1905 interfaces
                        // that are in the state of "PWR_ON" or "PWR_SAVE"
                        //
                        ifs_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifs_nr);

                        PLATFORM_PRINTF_DEBUG_DETAIL("1905 interface number = %d\n", ifs_nr);

                        mid       = getNextMid();
                        for (i=0; i<ifs_nr; i++)
                        {
                            uint8_t authenticated;
                            uint8_t power_state;
                            bool mcast_forward;

                            struct interfaceInfo *x;

                            x = PLATFORM_GET_1905_INTERFACE_INFO(ifs_names[i]);
                            if (NULL == x)
                            {
                                PLATFORM_PRINTF_DEBUG_WARNING("Could not retrieve info of interface %s\n", ifs_names[i]);
                                authenticated = 0;
                                power_state   = INTERFACE_POWER_STATE_OFF;
                            }
                            else
                            {
                                authenticated = x->is_secured;
                                power_state   = x->power_state;
                                mcast_forward = x->mcast_forward;

                                free_1905_INTERFACE_INFO(x);
                            }

                            if (
                                (0 == authenticated) || (!mcast_forward) ||
                                ((power_state != INTERFACE_POWER_STATE_ON) && (power_state!= INTERFACE_POWER_STATE_SAVE))
                               )
                            {
                                // Do not send the discovery messages on this
                                // interface
                                //
                                PLATFORM_PRINTF_DEBUG_INFO("interface %s power off, so do not send discover message\n", ifs_names[i]);
                                continue;
                            }

                            // Topology discovery message
                            //
                            if (0 == send1905TopologyDiscoveryPacket(ifs_names[i], mid))
                            {
                                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology discovery message\n");
                            }
#ifndef Q_OPENWRT
                            // 802.1 bridge discovery message
                            //
                            if (0 == sendLLDPBridgeDiscoveryPacket(ifs_names[i]))
                            {
                                PLATFORM_PRINTF_DEBUG_WARNING("Could not send LLDP bridge discovery message\n");
                            }
#endif
                        }
                        free_LIST_OF_1905_INTERFACES(ifs_names, ifs_nr);

                        break;
                    }

                    case TIMER_TOKEN_GARBAGE_COLLECTOR:
                    {
                        PLATFORM_PRINTF_DEBUG_DETAIL("Running garbage collector...\n");

                        if (DMrunGarbageCollector() > 0)
                        {
                            uint16_t mid = getNextMid();

                            PLATFORM_PRINTF_DEBUG_DETAIL("Some elements were removed. Sending a topology change notification...\n");

                            // Topology notification message
                            //
                            if (0 == send1905TopologyNotificationPacket(mid, NULL, NULL, 0))
                            {
                                PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology notification message\n");
                            }
                        }
                        break;
                    }

                    case TIMER_TOKEN_AUTOCONFIG:
                    {
                        if (!registrar.d)
                            triggerAPSearchProcess();
                        else if (!local_device->configured)
                            triggerDeviceAPAutoConfiguration(false);
                        break;
                    }


                    default:
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Unknown timer ID!! Ignoring...\n");
                        break;
                    }
                }

                break;
            }

            case PLATFORM_QUEUE_EVENT_PUSH_BUTTON:
            {
                uint16_t mid;

                char **ifs_names;
                uint8_t  ifs_nr;

                uint8_t  *no_push_button;
                uint8_t   at_least_one_unsupported_interface;

                PLATFORM_PRINTF_DEBUG_DETAIL("New queue message arrived: push button event\n");

#ifdef QDOCK
                if (_pickAndstartWPSonInterface())
                    break;
#endif

                // According to "Section 9.2.2.1", we must first make sure that
                // none of the interfaces is in the middle of a previous "push
                // button" configuration sequence.
                //
                ifs_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifs_nr);
                mid       = getNextMid();

                for (i=0; i<ifs_nr; i++)
                {
                    struct interfaceInfo *x;

                    x = PLATFORM_GET_1905_INTERFACE_INFO(ifs_names[i]);
                    if (NULL == x)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Could not retrieve info of interface %s\n", ifs_names[i]);
                        break;
                    }
                    else
                    {
                        if (1 == x->push_button_on_going)
                        {
                            PLATFORM_PRINTF_DEBUG_INFO("Interface %s is in the middle of a previous 'push button' configuration sequence. Ignoring new event...\n", ifs_names[i]);

                            free_1905_INTERFACE_INFO(x);
                            break;
                        }
                        free_1905_INTERFACE_INFO(x);
                    }

                }
                if (i < ifs_nr)
                {
                    // Don't do anything
                    //
                    break;
                }

                // If we get here, none of the interfaces is in the middle of a
                // "push button" configuration process, thus we can initialize
                // the "push button event" on all of our interfaces that support
                // it.
                //
                // Let's see which interfaces support it and keep track of
                // those who don't by setting the corresponding byte in array
                // "no_push_button" to '1'
                //
                no_push_button = (uint8_t *)memalloc(sizeof(uint8_t) * ifs_nr);

                for (i=0; i<ifs_nr; i++)
                {
                    struct interfaceInfo *x;

                    x = PLATFORM_GET_1905_INTERFACE_INFO(ifs_names[i]);
                    if (NULL == x)
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Could not retrieve info of interface %s\n", ifs_names[i]);

                        no_push_button[i] = 1;
                        break;
                    }
                    else
                    {
                        if (POWER_STATE_PWR_OFF == x->power_state)
                        {
                            // Ignore interfaces that are switched off
                            //
                            PLATFORM_PRINTF_DEBUG_DETAIL("Skipping interface %s because it is powered off\n", ifs_names[i]);
                            no_push_button[i] = 1;
                        }
                        else if (2 == x->push_button_on_going)
                        {
                            // This interface does not support the "push button"
                            // configuration process
                            //
                            PLATFORM_PRINTF_DEBUG_DETAIL("Skipping interface %s because it does not support the push button configuration mechanism\n", ifs_names[i]);
                            no_push_button[i] = 2;

                            // NOTE: "2" will be used as a special marker to
                            //       later trigger the AP search process (see
                            //       below)
                        }
                        else if ((INTERFACE_TYPE_IS_IEEE_802_11(x->interface_type)) &&
                                  IEEE80211_ROLE_AP != x->interface_type_data.ieee80211.role   &&
                                  (0x0 != x->interface_type_data.ieee80211.bssid[0] ||
                                   0x0 != x->interface_type_data.ieee80211.bssid[1] ||
                                   0x0 != x->interface_type_data.ieee80211.bssid[2] ||
                                   0x0 != x->interface_type_data.ieee80211.bssid[3] ||
                                   0x0 != x->interface_type_data.ieee80211.bssid[4] ||
                                   0x0 != x->interface_type_data.ieee80211.bssid[5]
                                  )
                           )
                        {
                            // According to "Section 9.2.2.1", an 802.11 STA
                            // which is already paired with an AP must *not*
                            // start the "push button" configuration process.
                            //
                            PLATFORM_PRINTF_DEBUG_DETAIL("Skipping interface %s because it is a wifi STA already associated to an AP\n", ifs_names[i]);
                            no_push_button[i] = 1;
                        }
                        else
                        {
                            no_push_button[i] = 0;
                        }

                        free_1905_INTERFACE_INFO(x);
                    }
                }

                // We now have the list of interfaces that need to start their
                // "push button" configuration process. Let's do it:
                //
                at_least_one_unsupported_interface = 0;
                for (i=0; i<ifs_nr; i++)
                {
                    if (0 == no_push_button[i])
                    {
                        PLATFORM_PRINTF_DEBUG_INFO("Starting push button configuration process on interface %s\n", ifs_names[i]);
                    #ifdef QDOCK
                        PLATFORM_START_PUSH_BUTTON_CONFIGURATION(ifs_names[i]);
                    #else
                        PLATFORM_START_PUSH_BUTTON_CONFIGURATION(ifs_names[i], queue_id, DMalMacGet(), mid);
                    #endif
                    }
                    if (2 == no_push_button[i])
                    {
                        at_least_one_unsupported_interface = 1;
                    }
                }
                if (1 == at_least_one_unsupported_interface)
                {
                    // The reason for doing this is the next one:
                    //
                    // Imagine one device with two interfaces: an unconfigured
                    // AP wifi interface and an ethernet interface.
                    //
                    // If we press the button we *need*  to send the
                    // "AP search" CMDU... however, because the ethernet interface
                    // never starts the "push button configuration" process
                    // (because it is not supported!), the interface can never
                    // "become authenticated" and trigger the AP search
                    // process.
                    //
                    // That's why we do it here, manually
                    //
                    if (!registrar.d)
                        triggerAPSearchProcess();
                }

                // Finally, send the notification message (so that the rest of
                // 1905 nodes is aware of this situation) but only on already
                // authenticated interfaces.

                // Push button notification message
                //
                if (0 == send1905PushButtonEventNotificationPacket(mid, ifs_names, no_push_button, ifs_nr))
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 push button event notification message\n");
                }

                free(no_push_button);
                free_LIST_OF_1905_INTERFACES(ifs_names, ifs_nr);

                break;
            }

            case PLATFORM_QUEUE_EVENT_AUTHENTICATED_LINK:
            {
                // Two different things need to be done when a new interface is
                // authenticated:
                //
                //   1. According to "Section 9.2.2.3", a "push button join
                //      notification" message must be generated and sent.
                //
                //   2. According to "Section 10.1", the "AP-autoconfiguration"
                //      process is triggered.

                uint16_t mid;

                uint8_t   local_mac_addr[6];
                uint8_t   new_mac_addr[6];
                uint8_t   original_al_mac_addr[6];
                uint16_t  original_mid;
		uint32_t  interface_index;
                struct interfaceWifi   *ifw;

                // The first six bytes of the message payload contain the MAC
                // address of the interface where the "push button"
                // configuration process succeeded.
                //
                _EnB(&p, local_mac_addr, 6);

                // The next six bytes contain the MAC address of the interface
                // successfully authenticated at the other end.
                //
                _EnB(&p, new_mac_addr, 6);

                // The next six bytes contain the original AL MAC address that
                // started everything.
                //
                _EnB(&p, original_al_mac_addr, 6);

		// The next two bytes contains the MID of that original message
                //
                _E2B(&p, &original_mid);

		// Finally, the last four bytes contains the interface index of that original
                // message
                //
                _E4B(&p, &interface_index);

                PLATFORM_PRINTF_DEBUG_DETAIL("New queue message arrived: authenticated link\n");
                PLATFORM_PRINTF_DEBUG_DETAIL("    Local interface:        %02x:%02x:%02x:%02x:%02x:%02x\n", local_mac_addr[0], local_mac_addr[1], local_mac_addr[2], local_mac_addr[3], local_mac_addr[4], local_mac_addr[5]);
                PLATFORM_PRINTF_DEBUG_DETAIL("    New (remote) interface: %02x:%02x:%02x:%02x:%02x:%02x\n", new_mac_addr[0], new_mac_addr[1], new_mac_addr[2], new_mac_addr[3], new_mac_addr[4], new_mac_addr[5]);
                PLATFORM_PRINTF_DEBUG_DETAIL("    Original AL MAC       : %02x:%02x:%02x:%02x:%02x:%02x\n", original_al_mac_addr[0], original_al_mac_addr[1], original_al_mac_addr[2], original_al_mac_addr[3], original_al_mac_addr[4], original_al_mac_addr[5]);
                PLATFORM_PRINTF_DEBUG_DETAIL("    Original MID          : %d\n", original_mid);
		PLATFORM_PRINTF_DEBUG_ERROR("     Original IF_index     : %d\n", interface_index);

                // If "new_mac_addr" is NULL, this means the interface was
                // "authenticated" as a whole (not at "link level").
                // This happens for ethernet interfaces.
                // In these cases we must *not* send the "push button join
                // notification" message (note, however, that the "AP-
                // autoconfiguration" process does need to be triggered, which
                // is done later)
                //
                if (
                     new_mac_addr[0] == 0x00 &&
                     new_mac_addr[1] == 0x00 &&
                     new_mac_addr[2] == 0x00 &&
                     new_mac_addr[3] == 0x00 &&
                     new_mac_addr[4] == 0x00 &&
                     new_mac_addr[5] == 0x00
                   )
                {
                    PLATFORM_PRINTF_DEBUG_DETAIL("NULL new (remote) interface. No 'push button join notification' will be sent.\n");
                }
                else
                {
                    // Send the "push button join notification" message on all
                    // authenticated interfaces (except for the one just
                    // authenticated)
                    //
                    mid       = getNextMid();
                    if (0 == send1905PushButtonJoinNotificationPacket(mid, original_al_mac_addr, original_mid, local_mac_addr, new_mac_addr, interface_index))
                    {
                        PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology discovery message\n");
                    }
                }

                // IoT: Some controller do not response the AP Search before receiving the Topology Discovery
                // Send Topology Discovery on the new eatablished authenticated link
                //
                if (0 == send1905TopologyDiscoveryPacket(DMinterfaceIndexToInterfaceName(interface_index), getNextMid()))
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology discovery message\n");
                }

                // Finally, trigger the "AP-autoconfiguration" process
                //
                // triggering the "AP-autoconfiguration" process again if backhaul sta get reassociated
                // in case configuration get changed during disassociation
                ifw = findLocalWifiInterface(local_mac_addr, interface_wifi_role_sta);
                if (!registrar.d || ifw)
                {
                    struct radio *r;

                    local_device->configured = false;
                    dlist_for_each(r, local_device->radios, l)
                    {
                        r->backhaul_only_configured = false;
                        r->configured = false;
                    }
                    triggerAPSearchProcess();
                }

                break;
            }

            case PLATFORM_QUEUE_EVENT_TOPOLOGY_CHANGE_NOTIFICATION:
            {
                uint16_t mid = getNextMid();

                PLATFORM_PRINTF_DEBUG_DETAIL("New queue message arrived: topology change notification event\n");

                // TODO:
                //   1. Find which L2 neighbors are no longer available
                //   2. Set their timestamp to 0
                //   3. Call DMrunGarbageCollector() to remove them from the
                //      database
                //
                // Until this is done, nodes will only be removed from the
                // database when the "TIMER_TOKEN_GARBAGE_COLLECTOR" timer
                // expires.

                // Topology notification message
                //
                if (0 == send1905TopologyNotificationPacket(mid, NULL, NULL, 0))
                {
                    PLATFORM_PRINTF_DEBUG_WARNING("Could not send 1905 topology notification message\n");
                }
                break;
            }

            default:
            {
                PLATFORM_PRINTF_DEBUG_WARNING("Unknown queue message type (%d)\n", message_type);

                break;
            }
        }
    }

#ifndef QDOCK
    return 0;
#endif
}

void process_ALEvent_by_MainThread(uint8_t *queue_message)
{
    uint8_t queue_id = PLATFORM_FIND_QUEUE_ID_BY_NAME("AL_events");
    process_ALEvent(queue_message, queue_id);
}
