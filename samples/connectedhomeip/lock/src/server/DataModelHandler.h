/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/**
 * @file
 *   This file defines the API for the handler for data model messages.
 */

#pragma once

#include <system/SystemPacketBuffer.h>
#include <transport/SecureSessionMgr.h>
#include <transport/raw/MessageHeader.h>

/**
 * Handle a message that should be processed via CHIP data model processing
 * codepath.
 *
 * @param [in] buffer The buffer holding the message.  This function guarantees
 *                    that it will free the buffer before returning.
 */
void HandleDataModelMessage(const chip::PacketHeader & header, chip::System::PacketBufferHandle buffer,
			    chip::SecureSessionMgr *mgr);
void InitDataModelHandler();
