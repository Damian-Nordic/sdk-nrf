/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef TIME_SYNC_H_
#define TIME_SYNC_H_

#include <stdint.h>

int time_sync_master_start(uint32_t interval_ms);

int time_sync_slave_start(uint8_t sniffer_id);

void time_sync_stop(void);

#endif /* TIME_SYNC_H_ */
