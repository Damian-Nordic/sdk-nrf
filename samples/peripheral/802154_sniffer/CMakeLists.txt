#
# Copyright (c) 2023 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

list(APPEND DTS_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(802154_sniffer)

target_sources(app PRIVATE
	src/main.c
	src/sniffer_uart.c
)

if(CONFIG_IEEE802154_SNIFFER_TIME_SYNC)
	target_sources(app PRIVATE src/time_sync.c)
endif()
