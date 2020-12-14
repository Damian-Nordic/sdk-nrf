/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#pragma once

#include "AppDelegate.h"
#include <inet/InetConfig.h>
#include <transport/TransportMgr.h>
#include <transport/raw/UDP.h>

#if INET_CONFIG_ENABLE_IPV4
using DemoTransportMgr = chip::TransportMgr<chip::Transport::UDP, chip::Transport::UDP>;
#else
using DemoTransportMgr = chip::TransportMgr<chip::Transport::UDP>;
#endif

/**
 * Initialize DataModelHandler and start CHIP datamodel server, the server
 * assumes the platform's networking has been setup already.
 *
 * @param [in] delegate   An optional AppDelegate
 */
void InitServer(AppDelegate *delegate = nullptr);
