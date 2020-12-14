/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#pragma once

#include <setup_payload/SetupPayload.h>

void PrintQRCode(chip::RendezvousInformationFlags rendezvousFlags);
CHIP_ERROR GetQRCode(uint32_t & setupPinCode, std::string & QRCode, chip::RendezvousInformationFlags rendezvousFlags);

/**
 * Initialize DataModelHandler and start CHIP datamodel server, the server
 * assumes the platform's networking has been setup already.
 *
 * Method verifies if every character of the QR Code is valid for the url encoding
 * and otherwise it encodes the invalid character using available ones.
 *
 * @param QRCode address of the array storing QR Code to encode.
 * @param len length of the given QR Code.
 * @param url address of the location where encoded url should be stored.
 * @param maxSize maximal size of the array where encoded url should be stored.
 * @return CHIP_NO_ERROR on success and other values on error.
 */
CHIP_ERROR EncodeQRCodeToUrl(const char *QRCode, size_t len, char *url, size_t maxSize);
