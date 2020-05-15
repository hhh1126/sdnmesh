# Copyright (c) 2018-2020, Semiconductor Components Industries, LLC
# ("ON Semiconductor")   f/k/a Quantenna. All rights reserved.
# This software and/or documentation is licensed by ON Semiconductor under
# limited terms and conditions.  The terms and conditions pertaining to the
# software and/or documentation are available at
# http://www.onsemi.com/site/pdf/ONSEMI_T&C.pdf ("ON Semiconductor Standard
# Terms and Conditions of Sale, Section 8 Software").  Reproduction and
# redistribution in binary form, without modification, for use solely in
# conjunction with a Quantenna chipset, is permitted with an executed
# Quantenna Software Licensing Agreement and in compliance with the terms
# therein and all applicable laws. Do not use this software and/or
# documentation unless you have carefully read and you agree to the limited
# terms and conditions.  By using this software and/or documentation, you
# agree to the limited terms and conditions.
#
# Portions of this software may include:
# prplMesh Wi-Fi Multi-AP
# Copyright (c) 2018, prpl Foundation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# Subject to the terms and conditions of this license, each copyright
# holder and contributor hereby grants to those receiving rights under
# this license a perpetual, worldwide, non-exclusive, no-charge,
# royalty-free, irrevocable (except for failure to satisfy the
# conditions of this license) patent license to make, have made, use,
# offer to sell, sell, import, and otherwise transfer this software,
# where such license applies only to those patent claims, already
# acquired or hereafter acquired, licensable by such copyright holder or
# contributor that are necessarily infringed by:
#
# (a) their Contribution(s) (the licensed copyrights of copyright holders
#     and non-copyrightable additions of contributors, in source or binary
#     form) alone; or
#
# (b) combination of their Contribution(s) with the work of authorship to
#     which such Contribution(s) was added by such copyright holder or
#     contributor, if, at the time the Contribution is added, such addition
#     causes such combination to be necessarily infringed. The patent
#     license shall not apply to any other combinations which include the
#     Contribution.
#
# Except as expressly stated above, no rights or licenses from any
# copyright holder or contributor is granted under this license, whether
# expressly, by implication, estoppel or otherwise.
#
# DISCLAIMER
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

add_library(${libname} STATIC
    1905_alme.c
    1905_cmdus.c
    1905_tlvs.c
    map_80211.c
    al_datamodel.c
    al_entity.c
    al_extension.c
    al_extension_register.c
    al_recv.c
    al_send.c
    al_retry.c
    al_utils.c
    al_wsc.c
    datamodel.c
    hlist.c
    lldp_payload.c
    lldp_tlvs.c
    mac_address.c
    media_specific_blobs.c
    tlv.c
    map_steering.c
    al_cli.c
    al_ubus_server.c
    ubus_map.c
    ubus_map_controller.c
    ubus_map_local.c
    ubus_map_network.c
    ubus_map_config.c
    utils.c
    ini.c)

install(TARGETS ${libname} DESTINATION lib COMPONENT Devel)

if (${CMAKE_SYSTEM_NAME} MATCHES Linux)

    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)

    find_package(PkgConfig)
    if (OPENWRT)
        pkg_check_modules(NL3 libnl-3.0 libnl-genl-3.0 REQUIRED)
    endif (OPENWRT)

    find_library(LIBRT rt)

    target_include_directories(${libname} PRIVATE ${OPENSSL_INCLUDE_DIR})
    if (OPENWRT)
        target_include_directories(${libname} PRIVATE ${NL3_INCLUDE_DIRS})
        set_property(TARGET ${libname} APPEND PROPERTY COMPILE_OPTIONS ${NL3_CFLAGS_OTHER})
    endif (OPENWRT)

    if (OPENWRT)
    target_sources(${libname} PRIVATE
         linux/netlink_collect.c
         linux/netlink_socks.c
         linux/netlink_utils.c)
    endif (OPENWRT)
    target_sources(${libname} PRIVATE
         linux/platform.c
         linux/platform_alme_server.c
         linux/platform_crypto.c
         linux/platform_interfaces.c
         # @todo make these configurable
         # linux/platform_interfaces_ghnspirit.c
         # linux/platform_interfaces_simulated.c
         linux/platform_os.c)

    target_link_libraries(${libname} OpenSSL::Crypto Threads::Threads)
    if (OPENWRT)
        target_link_libraries(${libname} ${NL3_LIBRARIES})
    endif (OPENWRT)
    if (LIBRT)
        target_link_libraries(${libname} rt)
    endif (LIBRT)

    if (OPENWRT)
        find_library(UBOX ubox)
        if (NOT UBOX)
            message(SEND_ERROR "OpenWRT integration requires ubox")
        endif (NOT UBOX)
        find_library(UBUS ubus)
        if (NOT UBUS)
            message(SEND_ERROR "OpenWRT integration requires ubus")
        endif (NOT UBUS)
        find_library(BLOBMSG_JSON blobmsg_json)
        if (NOT BLOBMSG_JSON)
            message(SEND_ERROR "OpenWRT integration requires blobmsg_json")
        endif (NOT BLOBMSG_JSON)
        find_library(JSON-C json-c)
        if (NOT JSON-C)
            message(SEND_ERROR "OpenWRT integration requires json-c")
        endif (NOT JSON-C)
        target_sources(${libname} PRIVATE
            linux/platform_uci.c
            linux/platform_interfaces_openwrt.c)
        target_link_libraries(${libname} ${UBUS} ${UBOX} ${BLOBMSG_JSON} ${JSON-C})
    elseif (QDOCK)
        if (FLAVOUR MATCHES "^qsr")
            target_sources(${libname} PRIVATE
                linux/platform_interfaces_qsr1000.c)
        endif ()
        find_library(UBOX ubox)
        if (NOT UBOX)
            message(SEND_ERROR "QDOCK integration requires ubox")
        endif (NOT UBOX)
        find_library(UBUS ubus)
        if (NOT UBUS)
            message(SEND_ERROR "QDOCK integration requires ubus")
        endif (NOT UBUS)
        find_library(BLOBMSG_JSON blobmsg_json)
        if (NOT BLOBMSG_JSON)
            message(SEND_ERROR "QDOCK integration requires blobmsg_json")
        endif (NOT BLOBMSG_JSON)
        if (Q_OPENWRT)
            find_library(JSON-C json-c)
            if (NOT JSON-C)
                message(SEND_ERROR "QDOCK OpenWRT integration requires json-c")
            endif (NOT JSON-C)
        else ()
            find_library(JSON-C json-c)
            if (NOT JSON-C)
                message(SEND_ERROR "QDOCK integration requires json")
            endif (NOT JSON-C)
        endif (Q_OPENWRT)
        target_sources(${libname} PRIVATE
            linux/platform_qdock.c
            linux/platform_local.c)
        if (Q_OPENWRT)
            target_link_libraries(${libname} ${UBUS} ${UBOX} ${BLOBMSG_JSON} ${JSON-C})
        else ()
            target_link_libraries(${libname} ${UBUS} ${UBOX} ${BLOBMSG_JSON} ${JSON})
        endif (Q_OPENWRT)
    endif (OPENWRT)

    add_executable(al_entity linux/al_entity/al_entity_main.c)
    target_link_libraries(al_entity ${libname})
    install(TARGETS al_entity DESTINATION bin)

    if (OPENWRT)
        add_executable(prplmesh linux/al_entity/al_entity_openwrt.c)
        target_link_libraries(prplmesh ${libname})
        install(TARGETS prplmesh DESTINATION bin)
    endif (OPENWRT)


    add_executable(hl_entity linux/hl_entity/hl_entity_main.c)
    target_link_libraries(hl_entity ${libname} OpenSSL::Crypto Threads::Threads)
    install(TARGETS hl_entity DESTINATION bin)

endif (${CMAKE_SYSTEM_NAME} MATCHES Linux)

