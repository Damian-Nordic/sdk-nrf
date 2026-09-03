/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SNIFFER_UART_H_
#define SNIFFER_UART_H_

#include <stdint.h>

/** Maximum length of one emitted line, including the CRLF terminator.
 *
 * The longest line carries a maximum size frame without its FCS, which is 253
 * bytes and 340 base64 characters, plus about 30 characters of metadata.
 */
#define SNIFFER_UART_LINE_MAX 384

void sniffer_uart_init(void);

/** Packet lines. Dropped when the buffer is full, and discarded rather than
 * queued while the host keeps the port closed.
 */
void sniffer_uart_emit(const char *fmt, ...);

/** Sync lines: drained before packet lines, and when the sync queue is full the
 * oldest pending sync line is evicted rather than the new one.
 */
void sniffer_uart_emit_sync(const char *fmt, ...);

#endif /* SNIFFER_UART_H_ */
