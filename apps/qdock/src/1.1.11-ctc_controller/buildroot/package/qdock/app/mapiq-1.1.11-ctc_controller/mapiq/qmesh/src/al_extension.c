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
#include "al_extension.h"

#include <string.h> // memcmp(), memcpy(), ...

////////////////////////////////////////////////////////////////////////////////
// Private definitions and data
////////////////////////////////////////////////////////////////////////////////

// Structure for CMDU extensions management
//
struct _ieee1905CmduExtension
{
    uint8_t  entries_nr;

    struct _cmduExtension
    {
        char name[MAX_EXTENSION_NAME_LEN];
        CMDU_EXTENSION_CBK process;
        CMDU_EXTENSION_CBK send;

    } *entries;

} ieee1905_cmdu_extension = {0, NULL};


// Structure for datamodel extensions management
//
struct _ieee1905DmExtension
{
    uint8_t  entries_nr;

    struct _dmExtension
    {
        char name[MAX_EXTENSION_NAME_LEN];
        DM_OBTAIN_LOCAL_INFO_CBK obtain;
        DM_UPDATE_LOCAL_INFO_CBK update;
        DM_EXTENSION_CBK         dump;

    } *entries;

} ieee1905_dm_extension = {0, NULL};


////////////////////////////////////////////////////////////////////////////////
// Public functions (CMDU Rx/Tx callback processing).
////////////////////////////////////////////////////////////////////////////////

// - process1905CmduExtensions(): Run through all the registered entities to
//                                process the non-standard data embedded in the
//                                incoming CMDU
// - send1905CmduExtensions()   : Run through all the registered entities to
//                                extend the outgoing CMDU with the
//                                non-standard data
// - free1905CmduExtensions()   : Free no longer used resources allocated by
//                                send1905CmduExtensions().
//
uint8_t process1905CmduExtensions(struct CMDU *c)
{
    uint32_t                          i;
    struct _ieee1905CmduExtension  *t;

    if (NULL == c)
    {
        return 0;
    }

    t = &ieee1905_cmdu_extension;

    if (NULL != t->entries)
    {
        for (i=0; i<t->entries_nr; i++)
        {
            if (NULL != t->entries[i].process)
            {
                t->entries[i].process(c);
            }
        }
    }

    return 1;
}

uint8_t send1905CmduExtensions(struct CMDU *c)
{
    uint32_t                          i;
    struct _ieee1905CmduExtension  *t;

    if (NULL == c)
    {
        return 0;
    }

    t = &ieee1905_cmdu_extension;

    if (NULL != t->entries)
    {
        for (i=0; i<t->entries_nr; i++)
        {
            if (NULL != t->entries[i].send)
            {
                t->entries[i].send(c);
            }
        }
    }

    return 1;
}

// Free allocated resources in 'send1905CmduExtensions' which are a list of
// Vendor Specific TLVs. There is no need for a registered 'free' callback for
// each actor (a Vendor Specific TLV is always released the same way)
//
uint8_t free1905CmduExtensions(struct CMDU *c)
{
    // all tlv will be freed later when free cmdu structure
#if 0
    uint32_t                      i;
    struct tlv                   *p;
    struct vendorSpecificTLV   *vs_tlv;

    if ((NULL == c) || (NULL == c->list_of_TLVs))
    {
        return 0;
    }

    i = 0;
    while (NULL != (p = c->list_of_TLVs[i]))
    {
        // Protocol extension is always embedded inside a Vendor Specific
        // TLV. Ignore other TLVs
        //
        if (p->type == TLV_TYPE_VENDOR_SPECIFIC)
        {
            vs_tlv = (struct vendorSpecificTLV *)p;

            if (vs_tlv->m)
            {
                free(vs_tlv->m);
            }
            free(vs_tlv);
        }
        i++;
    }
#endif
    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// Public functions (data model callback processing).
////////////////////////////////////////////////////////////////////////////////

// - obtainExtendedLocalInfo(): Run through all the registered entities to
//                              obtain the local non-standard data (embedded in
//                              Vendor Specific TLVs)
// - updateExtendedInfo()     : Run through all the registered entities to
//                              update the non-standard data in the datamodel.
// - dumpExtendedInfo()       : Run through all the registered entities to
//                              extend the 'dnd' ALME response (non-standard
//                              data from datamodel)
// - freeExtendedLocalInfo()  : Free no longer used resources allocated by
//                              obtainExtendedLocalInfo()
//
uint8_t obtainExtendedLocalInfo(struct vendorSpecificTLV ***extensions, uint8_t *nr)
{
    uint32_t                        i;
    uint32_t                        j;
    struct _ieee1905DmExtension  *t;

    struct vendorSpecificTLV **total_tlvs;      // The returned TLVs from all
                                                // the registered actors
    uint8_t                      total_tlvs_nr;

    struct vendorSpecificTLV **tlvs;            // TLVs returned by some
                                                // registered actor
    uint8_t                      tlvs_nr;

    if ((NULL == extensions) || (NULL == nr))
    {
        return 0;
    }

    // For each registered actor, obtain the extended local info data
    //
    total_tlvs_nr = 0;
    total_tlvs = NULL;
    tlvs_nr = 0;
    tlvs = NULL;

    t = &ieee1905_dm_extension;

    if (NULL != t->entries)
    {
        for (i=0; i<t->entries_nr; i++)
        {
            if (NULL != t->entries[i].obtain)
            {
                // Obtain particular extensions from this actor
                //
                t->entries[i].obtain(&tlvs, &tlvs_nr);

                // Keep all the obtained extensions stacked together
                //
                if (NULL == total_tlvs)
                {
                    total_tlvs = (struct vendorSpecificTLV **)memalloc(sizeof(struct vendorSpecificTLV*) * (total_tlvs_nr + tlvs_nr) );
                }
                else
                {
                    total_tlvs = (struct vendorSpecificTLV **)memrealloc(total_tlvs, sizeof(struct vendorSpecificTLV*) * (total_tlvs_nr + tlvs_nr) );
                }

                for (j=0; j<tlvs_nr; j++)
                {
                    total_tlvs[total_tlvs_nr] = tlvs[j];
                    total_tlvs_nr++;
                }

                // Free no longer used resources
                //
                free(tlvs);
                tlvs = NULL;
            }
        }
    }

    *extensions = total_tlvs;
    *nr = total_tlvs_nr;

    return 1;
}

// Free the contents of the pointers filled by a previous call to
// "obtainExtendedLocalInfo()".
// This function is called with the same three last arguments as
// "obtainExtendedLocalInfo()"
// There is no need for a registered 'free' callback for each actor (a Vendor
// Specific TLV is always released the same way)
//
void freeExtendedLocalInfo(struct vendorSpecificTLV ***extensions, uint8_t *nr)
{
    uint8_t  i;

    if ((NULL != extensions) && (NULL != *extensions) && (NULL != nr))
    {
        for (i=0; i<*nr; i++)
        {
            if (NULL != (*extensions)[i])
            {
                if ((*extensions)[i]->m)
                {
                    free((*extensions)[i]->m);
                }
                free((*extensions)[i]);
            }
        }
        free(*extensions);
    }
}

uint8_t updateExtendedInfo(struct vendorSpecificTLV **extensions, uint8_t nr, uint8_t *al_mac_address)
{
    uint32_t                        i;
    struct _ieee1905DmExtension  *t;

    if ((NULL == extensions) || (NULL == al_mac_address))
    {
        return 0;
    }

    t = &ieee1905_dm_extension;

    if (NULL != t->entries)
    {
        for (i=0; i<t->entries_nr; i++)
        {
            if (NULL != t->entries[i].update)
            {
                t->entries[i].update(extensions, nr, al_mac_address);
            }
        }
    }

    return 1;
}


uint8_t dumpExtendedInfo(uint8_t **memory_structure,
                       uint8_t   structure_nr,
                       visitor_callback callback,
                       void  (*write_function)(const char *fmt, ...),
                       const char *prefix)
{
    uint32_t                        i;
    struct _ieee1905DmExtension  *t;

    if ((NULL == memory_structure) || (NULL == callback) || (NULL == write_function) || (NULL == prefix))
    {
        return 0;
    }

    t = &ieee1905_dm_extension;

    if (NULL != t->entries)
    {
        for (i=0; i<t->entries_nr; i++)
        {
            if (NULL != t->entries[i].dump)
            {
                t->entries[i].dump(memory_structure, structure_nr, callback, write_function, prefix);
            }
        }
    }

    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// Public functions (to insert non-standard TLVs in a CMDU).
////////////////////////////////////////////////////////////////////////////////

// - VendorSpecificTLVEmbedExtension():   Embed a non-standard TLV inside a
//                                        Vendor Specific TLV
//
// - VendorSpecificTLVInsertInCDMU():     Add a Vendor Specific TLV to the CMDU
//
// - VendorSpecificTLVDuplicate():        Clone a Vendor Specific TLV
//
struct vendorSpecificTLV *vendorSpecificTLVEmbedExtension(struct tlv *memory_structure, uint8_t *forge(struct tlv *memory_structure, uint16_t *len), uint8_t oui[3])
{
    struct vendorSpecificTLV   *vendor_specific;
    uint8_t                      *stream;
    uint16_t                      stream_len;

    if ((NULL == memory_structure) || (NULL == forge) || (NULL == oui))
    {
        return NULL;
    }

    stream = forge(memory_structure, &stream_len);
    if (NULL == stream)
    {
        // Could not forge the packet. Error?
        //
        PLATFORM_PRINTF_DEBUG_WARNING("forge extended TLV failed!\n");
        return NULL;
    }

    vendor_specific                = X1905_TLV_ALLOC(vendorSpecific, TLV_TYPE_VENDOR_SPECIFIC, NULL);
    memcpy(vendor_specific->vendorOUI, oui, 3);
    vendor_specific->tlv.type      = TLV_TYPE_VENDOR_SPECIFIC;
    vendor_specific->m_nr          = stream_len;
    vendor_specific->m             = stream;

    return vendor_specific;
}

uint8_t vendorSpecificTLVInsertInCDMU(struct CMDU *memory_structure, struct vendorSpecificTLV *vendor_specific)
{
    uint8_t      tlv_stop;

    if ((NULL == memory_structure) || (NULL == memory_structure->list_of_TLVs) ||
        (NULL == vendor_specific)  || (*(uint8_t *)vendor_specific != TLV_TYPE_VENDOR_SPECIFIC))
    {
        // Invalid params
        //
        return 0;
    }

    // Point at the end of the TLV list (NULL pointer)
    //
    tlv_stop = 0;
    while(memory_structure->list_of_TLVs[tlv_stop++]);
    tlv_stop--;

    // Insert TLV
    //
    memory_structure->list_of_TLVs             = (struct tlv **)memrealloc(memory_structure->list_of_TLVs, sizeof(struct tlv *) * (tlv_stop+2));
    memory_structure->list_of_TLVs[tlv_stop++] = &vendor_specific->tlv;
    memory_structure->list_of_TLVs[tlv_stop]   = NULL;

    return 1;
}

struct vendorSpecificTLV *vendorSpecificTLVDuplicate(struct vendorSpecificTLV *tlv)
{
  struct vendorSpecificTLV *vs_tlv;

  if (NULL == tlv)
  {
      return NULL;
  }

  // Clone the Vendor Specific TLV
  //
  vs_tlv = X1905_TLV_ALLOC(vendorSpecific, TLV_TYPE_VENDOR_SPECIFIC, NULL);
  vs_tlv->vendorOUI[0] = tlv->vendorOUI[0];
  vs_tlv->vendorOUI[1] = tlv->vendorOUI[1];
  vs_tlv->vendorOUI[2] = tlv->vendorOUI[2];
  vs_tlv->m_nr = tlv->m_nr;

  vs_tlv->m = (uint8_t *)memalloc(vs_tlv->m_nr);
  memcpy(vs_tlv->m, tlv->m, vs_tlv->m_nr);

  return vs_tlv;
}


////////////////////////////////////////////////////////////////////////////////
// Public functions (callbacks registration).
////////////////////////////////////////////////////////////////////////////////

// - register1905CmduExtension()    : Register callbacks to manage the CMDU
//                                    extensions
//
// - register1905AlmeDumpExtension(): Register callbacks to manage the ALME
//                                    'dnd' extended info response
//
uint8_t register1905CmduExtension(char *name,
                                CMDU_EXTENSION_CBK process,
                                CMDU_EXTENSION_CBK send)
{
    uint32_t                          i;
    struct _ieee1905CmduExtension  *t;

    if ((NULL == name) || (NULL == process) || (NULL == send))
    {
        return 0;
    }

    t = &ieee1905_cmdu_extension;

    // Check if this extension group is already registered
    //
    if (NULL != t->entries)
    {
        for (i=0; i<t->entries_nr; i++)
        {
            if (0 == memcmp(t->entries[i].name, name, strlen(name) + 1))
            {
                // Already exists!
                //
                PLATFORM_PRINTF_DEBUG_WARNING("[PLATFORM] A protocol extension with the name %s already exists. Ignoring...\n", name);
                return 0;
            }
        }
    }

    if (0 == t->entries_nr)
    {
        t->entries = (struct _cmduExtension *)memalloc(sizeof(struct _cmduExtension) * 1);
    }
    else
    {
        t->entries = (struct _cmduExtension *)memrealloc(t->entries, sizeof(struct _cmduExtension) * (t->entries_nr + 1));
    }

    memcpy(t->entries[t->entries_nr].name, name, MAX_EXTENSION_NAME_LEN-1);
    t->entries[t->entries_nr].name[MAX_EXTENSION_NAME_LEN-1] = 0x0;
    t->entries[t->entries_nr].process = process;
    t->entries[t->entries_nr].send    = send;

    t->entries_nr++;

    return 1;
}

uint8_t register1905AlmeDumpExtension(char *name,
                                    DM_OBTAIN_LOCAL_INFO_CBK obtain,
                                    DM_UPDATE_LOCAL_INFO_CBK update,
                                    DM_EXTENSION_CBK         dump)
{
    uint32_t                              i;
    struct _ieee1905DmExtension  *t;

    if ((NULL == name) || (NULL == obtain) || (NULL == update) || (NULL == dump))
    {
        return 0;
    }

    t = &ieee1905_dm_extension;

    for (i=0; i<t->entries_nr; i++)
    {
        if (0 == memcmp(t->entries[i].name, name, strlen(name) + 1))
        {
            // Already exists!
            //
            PLATFORM_PRINTF_DEBUG_WARNING("[PLATFORM] A dump protocol extension with the name %s already exists. Ignoring...\n", name);
            return 0;
        }
    }

    if (0 == t->entries_nr)
    {
        t->entries = (struct _dmExtension *)memalloc(sizeof(struct _dmExtension) * 1);
    }
    else
    {
        t->entries = (struct _dmExtension *)memrealloc(t->entries, sizeof(struct _dmExtension) * (t->entries_nr + 1));
    }

    memcpy(t->entries[t->entries_nr].name, name, MAX_EXTENSION_NAME_LEN-1);
    t->entries[t->entries_nr].name[MAX_EXTENSION_NAME_LEN-1] = 0x0;
    t->entries[t->entries_nr].obtain = obtain;
    t->entries[t->entries_nr].update = update;
    t->entries[t->entries_nr].dump   = dump;

    t->entries_nr++;

    return 1;
}