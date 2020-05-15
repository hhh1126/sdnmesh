# Copyright (c) 2018-2019, Semiconductor Components Industries, LLC
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

cmake_minimum_required(VERSION 3.4)
project(prplMesh LANGUAGES C VERSION 0.9)

set(libname "prplMesh" CACHE STRING
    "Name of the generated library. Includes are installed in a subdirectory of the same name.\
     This allows to install it as e.g. 'lib1905.a' if only 1905 functionality is needed.")
set(INCLUDE_INSTALL_DIR include/ CACHE PATH
    "Installation directory for includes (relative to CMAKE_INSTALL_PREFIX)")
set(LIB_INSTALL_DIR lib/ CACHE PATH
    "Installation directory for the library (relative to CMAKE_INSTALL_PREFIX)")
set(CMAKE_INSTALL_DIR ${LIB_INSTALL_DIR}/cmake CACHE PATH
    "Installation directory for CMake files (relative to CMAKE_INSTALL_PREFIX)")
set(OPENWRT FALSE CACHE BOOL
    "Enable OpenWrt integration")
set(QDOCK TRUE CACHE BOOL
    "Enable QDOCK integration")
set(FLAVOUR "qsr1000" CACHE STRING
    "Name of FLAVOUR")
set(REPORT_MONITOR_STATS FALSE CACHE BOOL
	"Enable report monitor stats(unassoc stas infos) periodical")
set(UTEST FALSE CACHE BOOL
    "Enable the Unit test")
set(Q_STEERING_LOGIC TRUE CACHE BOOL
    "Enable Q_STEERING_LOGIC integration")

set(CMAKE_BUILD_TYPE Debug)

set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS _BUILD_NUMBER_=\"${prplMesh_VERSION}\")

include(TestBigEndian)
TEST_BIG_ENDIAN(BIGENDIAN)
if(BIGENDIAN)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS _HOST_IS_BIG_ENDIAN_=1)
else()
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS _HOST_IS_LITTLE_ENDIAN_=1)
endif(BIGENDIAN)

# @todo make these configurable
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS
    MAX_NETWORK_SEGMENT_SIZE=1500
    SEND_EMPTY_TLVS
    FIX_BROKEN_TLVS
    SPEED_UP_DISCOVERY
    )

if (OPENWRT)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS OPENWRT)
endif (OPENWRT)

if (Q_OPENWRT)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS Q_OPENWRT)
endif (Q_OPENWRT)

if (MUSL_LIBC)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS MUSL_LIBC)
endif (MUSL_LIBC)

if (QDOCK)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS QDOCK)
endif (QDOCK)

if (Q_STEERING_LOGIC)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS Q_STEERING_LOGIC)
endif (Q_STEERING_LOGIC)

if (FLAVOUR STREQUAL "qsr1000")
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS _FLAVOUR_QSR1000_)
endif ()
if (FLAVOUR STREQUAL "qsr10k")
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS _FLAVOUR_QSR10K_)
endif ()

if (REPORT_MONITOR_STATS)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS REPORT_MONITOR_STATS)
endif(REPORT_MONITOR_STATS)

if (MAPIQ_DEVID_STRING_FORMAT)
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS MAPIQ_DEVID_STRING_FORMAT)
endif(MAPIQ_DEVID_STRING_FORMAT)

include_directories(include)

add_subdirectory(src)

if (UTEST)
if (${CMAKE_SYSTEM_NAME} MATCHES Linux)
    enable_testing()
    add_subdirectory(tests)
endif (${CMAKE_SYSTEM_NAME} MATCHES Linux)
endif (UTEST)


# Installation

include(CMakePackageConfigHelpers)

install(DIRECTORY include/ DESTINATION ${INCLUDE_INSTALL_DIR}/${libname} COMPONENT Devel FILES_MATCHING PATTERN "*.h")

configure_package_config_file(prplMeshConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${libname}Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_DIR}
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
    PATH_VARS INCLUDE_INSTALL_DIR LIB_INSTALL_DIR)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${libname}ConfigVersion.cmake"
  VERSION ${prplMesh_VERSION}
  COMPATIBILITY AnyNewerVersion)
configure_file(prplMesh.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/${libname}.pc
    @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${libname}Config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${libname}ConfigVersion.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${libname}.pc
        DESTINATION ${CMAKE_INSTALL_DIR}
        COMPONENT Devel)
