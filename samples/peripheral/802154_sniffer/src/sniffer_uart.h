/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SNIFFER_UART_H_
#define SNIFFER_UART_H_

#include <stdint.h>

void sniffer_uart_init(void);

/** Packet / high-volume lines (may drop when queue is full). */
void sniffer_uart_emit(const char *fmt, ...);

/** Sync lines — never dropped; drained before packet lines. */
void sniffer_uart_emit_sync(const char *fmt, ...);

#endif /* SNIFFER_UART_H_ */
