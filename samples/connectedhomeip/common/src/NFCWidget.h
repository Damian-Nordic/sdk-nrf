/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#pragma once

#include <platform/CHIPDeviceLayer.h>

#include <nfc_t2t_lib.h>

class NFCWidget {
public:
	int Init(chip::DeviceLayer::ConnectivityManager & mgr);
	int StartTagEmulation(const char *tagPayload, uint8_t tagPayloadLength);
	int StopTagEmulation();

private:
	static void FieldDetectionHandler(void *context, enum nfc_t2t_event event, const uint8_t *data, size_t data_length);

	constexpr static uint8_t mNdefBufferSize = 128;

	uint8_t mNdefBuffer[mNdefBufferSize];
};
