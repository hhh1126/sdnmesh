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

#include "tlv.h"

#include "packet_tools.h"
#include <utils.h>
#include <platform.h>

#include <errno.h> // errno
#include <stdlib.h> // malloc
#include <string.h> // memcpy, strerror
#include <stdio.h>  // snprintf

const struct tlv_def *tlv_find_def(tlv_defs_t defs, uint8_t tlv_type)
{
    return &defs[tlv_type];
}

ssize_t tlv_struct_length_field(const uint8_t *field, const struct tlv_struct_field_description *desc)
{
    ssize_t size = desc->size;
    switch (desc->type)
    {
        case TLV_FIELD_FORMAT_LV_BYTES:
            size = (field)[0] + 1;
            break;
        case TLV_FIELD_FORMAT_TLV_BYTES:
            size = (field)[1] + 2;
            break;
        case TLV_FIELD_FORMAT_LV_DBYTES:
            size = (field)[0] * 2 + 1;
            break;
    }

    return size;
}

bool tlv_struct_parse_field(struct tlv_struct *item, const struct tlv_struct_field_description *desc,
                            const uint8_t **buffer, size_t *length)
{
    char *pfield = (char*)item + desc->offset;
    ssize_t size;

    switch (desc->size)
    {
        case 1:
            return _E1BL(buffer, (uint8_t*)pfield, length);
        case 2:
            return _E2BL(buffer, (uint16_t*)pfield, length);
        case 4:
            return _E4BL(buffer, (uint32_t*)pfield, length);
        default:
            size = tlv_struct_length_field(*buffer, desc);
            return _EnBL(buffer, (uint8_t*)pfield, size, length);
    }
}

static struct tlv_struct *tlv_struct_parse_single(const struct tlv_struct_description *desc, dlist_head *parent,
                                                  const uint8_t **buffer, size_t *length)
{
    size_t i;

    if (desc->parse != NULL)
        return desc->parse(desc, parent, buffer, length);

    struct tlv_struct *item = container_of(hlist_alloc(desc->size, parent), struct tlv_struct, h);
    item->desc = desc;
    for (i = 0; i < ARRAY_SIZE(item->desc->fields) && item->desc->fields[i].name != NULL; i++)
    {
        if (!tlv_struct_parse_field(item, &item->desc->fields[i], buffer, length))
            goto err_out;
    }
    for (i = 0; i < ARRAY_SIZE(item->h.children) && item->desc->children[i] != NULL; i++)
    {
        tlv_struct_parse_list(item->desc->children[i], &item->h.children[i], buffer, length);
    }

    return item;

err_out:
    hlist_delete_item(&item->h);
    return NULL;
}

bool tlv_struct_parse_list(const struct tlv_struct_description *desc, dlist_head *parent,
                           const uint8_t **buffer, size_t *length)
{
    uint32_t children_nr = 0;
    uint8_t j;

    switch (desc->count_field)
    {
        case TLV_COUNT_FIELD_4_BYTES:
            _E4BL(buffer, &children_nr, length);
            break;
        case TLV_COUNT_FIELD_2_BYTES:
#if _HOST_IS_BIG_ENDIAN_ == 1
            _E2BL(buffer, ((uint16_t *)(&children_nr)) + 1, length);
#else
            _E2BL(buffer, ((uint16_t *)(&children_nr)), length);
#endif
            break;
        default:
#if _HOST_IS_BIG_ENDIAN_ == 1
            _E1BL(buffer, ((uint8_t *)(&children_nr)) + 3, length);
#else
            _E1BL(buffer, ((uint8_t *)(&children_nr)), length);
#endif
            break;
    }

    for (j = 0; j < children_nr; j++)
    {
        const struct tlv_struct *child = tlv_struct_parse_single(desc, parent, buffer, length);
        if (child == NULL)
            return false; /* Caller will delete parent */
    }
    return true;
}

bool tlv_parse(tlv_defs_t defs, dlist_head *tlvs, const uint8_t *buffer, size_t length)
{
    while (length >= 3)    // Minimal TLV: 1 byte type, 2 bytes length
    {
        uint8_t tlv_type;
        uint16_t tlv_length_uint16;
        size_t tlv_length;
        const struct tlv_def *tlv_def;
        struct tlv *tlv_new;

        _E1BL(&buffer, &tlv_type, &length);
        _E2BL(&buffer, &tlv_length_uint16, &length);
        tlv_length = tlv_length_uint16;
        if (tlv_length > length)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("TLV(%u) of length %u but only %u bytes left in buffer\n",
                                        tlv_type, (unsigned)tlv_length, (unsigned)length);
            goto err_out;
        }

        tlv_def = tlv_find_def(defs, tlv_type);
        if (tlv_def->desc.name == NULL)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("Unknown TLV type %u of length %u\n",
                                          (unsigned)tlv_type, (unsigned)tlv_length);
            tlv_new = malloc(sizeof(struct tlv));
            /* for internal check all the unknow TLVs */
            tlv_type = TLV_TYPE_UNKNOWN;
        }
        else
        {
                /* @todo clean this up */
                length -= tlv_length;
                struct tlv_struct *tlv_new_item = tlv_struct_parse_single(&tlv_def->desc, NULL, &buffer, &tlv_length);
                if (tlv_new_item == NULL)
                    goto err_out;
                if (tlv_length != 0)
                {
                    PLATFORM_PRINTF_DEBUG_ERROR("Remaining garbage (%u bytes) after parsing TLV %s\n",
                                                (unsigned)tlv_length, tlv_def->desc.name);
                    hlist_delete_item(&tlv_new_item->h);
                    goto err_out;
                }
                tlv_new = container_of(tlv_new_item, struct tlv, s);
        }
        if (tlv_new == NULL)
        {
            goto err_out;
        }
        tlv_new->type = tlv_type;
        if (!tlv_add(defs, tlvs, tlv_new))
        {
            /* tlv_add already prints an error */
            hlist_delete_item(&tlv_new->s.h);
            goto err_out;
        }
        buffer += tlv_length;
        length -= tlv_length;
    }

    return true;

err_out:
    hlist_delete(tlvs);
    return false;
}


bool tlv_struct_forge_field(const struct tlv_struct *item, const struct tlv_struct_field_description *desc,
                            uint8_t **buffer, size_t *length)
{
    const uint8_t *pfield = (const uint8_t*)item + desc->offset;
    ssize_t size;

    switch (desc->size)
    {
        case 1:
            return _I1BL((const uint8_t*)pfield, buffer, length);
        case 2:
            return _I2BL((const uint16_t*)pfield, buffer, length);
        case 4:
            return _I4BL((const uint32_t*)pfield, buffer, length);
        default:
            size = tlv_struct_length_field(pfield, desc);
            return _InBL((const uint8_t*)pfield, buffer, size, length);
    }
}

static bool tlv_struct_forge_single(const struct tlv_struct *item, uint8_t **buffer, size_t *length)
{
    size_t i;
    if (item->desc->forge != NULL)
        return item->desc->forge(item, buffer, length);

    for (i = 0; i < ARRAY_SIZE(item->desc->fields) && item->desc->fields[i].name != NULL; i++)
    {
        if (!tlv_struct_forge_field(item, &item->desc->fields[i], buffer, length))
            return false;
    }
    for (i = 0; i < ARRAY_SIZE(item->h.children) && item->desc->children[i] != NULL; i++)
    {
        tlv_struct_forge_list(item->desc->children[i], &item->h.children[i], buffer, length);
    }
    return true;
}

bool tlv_struct_forge_list(const struct tlv_struct_description *desc, const dlist_head *parent, uint8_t **buffer, size_t *length)
{
    const struct tlv_struct *child;
    uint32_t children_nr = dlist_count(parent);

    switch (desc->count_field)
    {
        case TLV_COUNT_FIELD_4_BYTES:
            _I4BL(&children_nr, buffer, length);
            break;
        case TLV_COUNT_FIELD_2_BYTES:
#if _HOST_IS_BIG_ENDIAN_ == 1
            _I2BL((uint16_t *)(&children_nr) + 1, buffer, length);
#else
            _I2BL((uint16_t *)(&children_nr), buffer, length);
#endif
            break;
        default:
#if _HOST_IS_BIG_ENDIAN_ == 1
            _I1BL((uint8_t *)(&children_nr) + 3, buffer, length);
#else
            _I1BL((uint8_t *)(&children_nr), buffer, length);
#endif
            break;
    }

    hlist_for_each(child, *parent, const struct tlv_struct, h)
    {
        if (!tlv_struct_forge_single(child, buffer, length))
            return false;
    }
    return true;
}

static size_t tlv_length_single(const struct tlv_struct *item)
{
    size_t length = 0;
    size_t i;

    if (item->desc->length != NULL)
        return item->desc->length(item);

    for (i = 0; i < ARRAY_SIZE(item->desc->fields) && item->desc->fields[i].name != NULL; i++)
    {
        /* If one of the fields has a different size in serialisation than in the struct, the length() method must be
         * overridden. */
        const uint8_t *pfield = (const uint8_t *)item + item->desc->fields[i].offset;
        length += tlv_struct_length_field(pfield, &item->desc->fields[i]);
    }
    /* Next print the children. */
    for (i = 0; i < ARRAY_SIZE(item->h.children) && item->desc->children[i] != NULL; i++)
    {
        length += tlv_struct_length_list(item->desc->children[i], &item->h.children[i]);
    }

    return length;
}

size_t tlv_struct_length_list(const struct tlv_struct_description *desc, const dlist_head *parent)
{
    size_t length = 0;
    const struct tlv_struct *child;

    switch (desc->count_field)
    {
        case TLV_COUNT_FIELD_4_BYTES:
            length += 4;
            break;
        case TLV_COUNT_FIELD_2_BYTES:
            length += 2;
            break;
        default:
            length += 1;
            break;
    }

    hlist_for_each(child, *parent, const struct tlv_struct, h)
    {
        length += tlv_length_single(child);
    }
    return length;
}


bool tlv_forge(tlv_defs_t defs, const dlist_head *tlvs, size_t max_length, uint8_t **buffer, size_t *length)
{
    size_t total_length;
    uint8_t *p;
    const struct tlv *tlv;

    /* First, calculate total_length. */
    total_length = 0;
    hlist_for_each(tlv, *tlvs, struct tlv, s.h)
    {
        const struct tlv_def *tlv_def = tlv_find_def(defs, tlv->type);
        if (tlv_def->desc.name == NULL)
        {
            PLATFORM_PRINTF_DEBUG_WARNING("tlv_forge: skipping unknown TLV %u\n", tlv->type);
        }
        else
        {
            /* Add 3 bytes for type + length */
            total_length += 3;
            total_length += tlv_length_single(&tlv->s);
        }
    }

    /* Now, allocate the buffer and fill it. */
    /** @todo support splitting over packets. */
    if (total_length > max_length)
    {
        PLATFORM_PRINTF_DEBUG_ERROR("TLV list doesn't fit, %u > %u.\n", (unsigned)total_length, (unsigned)max_length);
        return false;
    }

    /** @todo foresee headroom */
    *length = total_length;
    *buffer = malloc(total_length);
    p = *buffer;
    hlist_for_each(tlv, *tlvs, struct tlv, s.h)
    {
        size_t tlv_length = tlv_length_single(&tlv->s);
        uint16_t tlv_length_u16 = (uint16_t)tlv_length;

        if (tlv_length > UINT16_MAX)
        {
            PLATFORM_PRINTF_DEBUG_ERROR("TLV length for %s to large: %llu\n",
                                        tlv->s.desc->name, (unsigned long long) tlv_length);
            goto err_out;
        }

        if (!_I1BL(&tlv->type, &p, &total_length))
            goto err_out;
        if (!_I2BL(&tlv_length_u16, &p, &total_length))
            goto err_out;
        if (!tlv_struct_forge_single(&tlv->s, &p, &total_length))
            goto err_out;
    }
    if (total_length != 0)
        goto err_out;
    return true;

err_out:
    PLATFORM_PRINTF_DEBUG_ERROR("TLV list forging implementation error.\n");
    free(*buffer);
    return false;
}

bool tlv_add(tlv_defs_t defs, dlist_head *tlvs, struct tlv *tlv)
{
    /** @todo keep ordered, check for duplicates, handle aggregation */
    dlist_add_tail(tlvs, &tlv->s.h.l);
    return true;
}


int tlv_struct_compare_list(const dlist_head *h1, const dlist_head *h2)
{
    int ret = 0;
    dlist_head *cur1;
    dlist_head *cur2;
    /* Open-code hlist_for_each because we need to iterate over both at once. */
    for (cur1 = h1->next, cur2 = h2->next;
         ret == 0 && cur1 != h1 && cur2 != h2;
         cur1 = cur1->next, cur2 = cur2->next)
    {
        ret = tlv_struct_compare(container_of(cur1, struct tlv_struct, h.l), container_of(cur2, struct tlv_struct, h.l));
    }
    if (ret == 0)
    {
        /* We reached the end of the list. Check if one of the lists is longer. */
        if (cur1 != h1)
            ret = 1;
        else if (cur2 != h2)
            ret = -1;
        else
            ret = 0;
    }
    return ret;
}

int tlv_struct_compare(const struct tlv_struct *item1, const struct tlv_struct *item2)
{
    int ret;
    unsigned i;

    if (item1->desc->compare != NULL)
        return item1->desc->compare(item1, item2);

    assert(item1->desc == item2->desc);

    ret = memcmp((char*)item1 + sizeof(struct tlv_struct), (char*)item2 + sizeof(struct tlv_struct),
                 item1->desc->size - sizeof(struct tlv_struct));
    for (i = 0; ret == 0 && i < ARRAY_SIZE(item1->h.children); i++)
    {
        ret = tlv_struct_compare_list(&item1->h.children[i], &item2->h.children[i]);
    }
    return ret;
}

void tlv_struct_print_list(const dlist_head *list, bool include_index, void (*write_function)(const char *fmt, ...), const char *prefix)
{
    const struct tlv_struct *child;
    char new_prefix[100];
    unsigned i = 0;

    hlist_for_each(child, *list, const struct tlv_struct, h)
    {
        if (include_index)
        {
            snprintf(new_prefix, sizeof(new_prefix)-1, "%s%s[%u]", prefix, child->desc->name, i);
        } else {
            snprintf(new_prefix, sizeof(new_prefix)-1, "%s%s", prefix, child->desc->name);
        }
        tlv_struct_print(child, write_function, new_prefix);
        i++;
    }
}

void tlv_struct_print(const struct tlv_struct *item, void (*write_function)(const char *fmt, ...), const char *prefix)
{
    size_t i;
    char new_prefix[100];

    /* Construct the new prefix. */
    snprintf(new_prefix, sizeof(new_prefix)-1, "%s->", prefix);

    if (item->desc->print != NULL)
    {
        item->desc->print(item, write_function, new_prefix);
        return;
    }

    /* First print the fields. */
    for (i = 0; i < ARRAY_SIZE(item->desc->fields) && item->desc->fields[i].name != NULL; i++)
    {
        tlv_struct_print_field(item, &item->desc->fields[i], write_function, new_prefix);
    }
    /* Next print the children. */
    for (i = 0; i < ARRAY_SIZE(item->h.children) && item->desc->children[i] != NULL; i++)
    {
        tlv_struct_print_list(&item->h.children[i], true, write_function, new_prefix);
    }
}

void tlv_struct_print_hex_field(const char *name, const uint8_t *value, size_t length,
                                void (*write_function)(const char *fmt, ...), const char *prefix)
{
    size_t i, buf_len = length * 3 + strlen(prefix) + 3;
    char *buf = malloc(buf_len);
    char *pos = buf, *end = buf + buf_len;

    pos += snprintf(pos, buf_len, "%s: ", prefix);
    /* @todo Break off long lines */
    for (i = 0; i < length; i++)
    {
        pos += snprintf(pos, end - pos, "%02x ", value[i]);
    }
    write_function("%s\n", buf);
    free(buf);
}
void tlv_struct_print_field(const struct tlv_struct *item, const struct tlv_struct_field_description *field_desc,
                       void (*write_function)(const char *fmt, ...), const char *prefix)
{
    unsigned value;
    char *pvalue = ((char*)item) + field_desc->offset;
    uint8_t *uvalue = (uint8_t *)pvalue;
    ssize_t size;
    char new_prefix[100];

    snprintf(new_prefix, sizeof(new_prefix)-1, "%s%s", prefix, field_desc->name);
    switch (field_desc->format)
    {
        case tlv_struct_print_format_hex:
        case tlv_struct_print_format_dec:
        case tlv_struct_print_format_unsigned:
            switch (field_desc->size)
            {
                case 1:
                    value = *(const uint8_t*)pvalue;
                    break;
                case 2:
                    value = *(const uint16_t*)pvalue;
                    break;
                case 4:
                    value = *(const uint32_t*)pvalue;
                    break;
                default:
                    size = tlv_struct_length_field(uvalue, field_desc);
                    assert(field_desc->format == tlv_struct_print_format_hex);
                    tlv_struct_print_hex_field(field_desc->name, uvalue, size, write_function, new_prefix);
                    return;
            }

            switch (field_desc->format)
            {
                case tlv_struct_print_format_hex:
                    write_function("%s: 0x%02x\n", new_prefix, value);
                    break;
                case tlv_struct_print_format_dec:
                    write_function("%s: %d\n", new_prefix, value);
                    break;
                case tlv_struct_print_format_unsigned:
                    write_function("%s: %u\n", new_prefix, value);
                    break;
                default:
                    assert(0);
                    break;
            }
            break;

        case tlv_struct_print_format_mac:
            assert(field_desc->size == 6);
            write_function("%s: "MACSTR"\n", new_prefix, MAC2STR(uvalue));
            break;

        case tlv_struct_print_format_ipv4:
            assert(field_desc->size == 4);
            write_function("%s: %u.%u.%u.%u\n", new_prefix, uvalue[0], uvalue[1], uvalue[2], uvalue[3]);
            break;

        case tlv_struct_print_format_ipv6:
            assert(field_desc->size == 16);
            write_function("%s: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", new_prefix,
                           uvalue[0], uvalue[1], uvalue[2], uvalue[3], uvalue[4], uvalue[5], uvalue[6], uvalue[7],
                           uvalue[8], uvalue[9], uvalue[10], uvalue[11], uvalue[12], uvalue[13], uvalue[14],
                           uvalue[15]);
            break;

        default:
            assert(0);
            break;
    }
}

void tlv_free(tlv_defs_t defs, dlist_head *tlvs)
{
    struct tlv_struct *item, *tmp;

    hlist_for_each_safe(item, tmp, *tlvs, struct tlv_struct, h)
    {
        struct tlv *tlv = (struct tlv *)item;
        const struct tlv_def *tlv_def = tlv_find_def(defs, tlv->type);

        dlist_remove(&item->h.l);

        /* TLV is not alloced by TLV_STRUCT_ALLOC, eg: all the legacy 1905 TLV
         * TODO: use the new malloc function to alloc these TLVs? */
        if (!tlv_def->desc.name)
        {
            int i;
            for (i = 0; i < HLIST_MAX_CHILDREN; i++)
                dlist_head_init(&tlv->s.h.children[i]);
        }

        if (tlv_def->desc.name && item->desc && item->desc->free)
            item->desc->free(item);
        else
            hlist_delete_item(&item->h);
    }
}
