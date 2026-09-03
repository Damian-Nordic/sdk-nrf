/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "sniffer_uart.h"

#include <errno.h>
#include <stddef.h>
#include <stdarg.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#include <zephyr/sys/ring_buffer.h>

#define SNIFFER_UART_SYNC_QUEUE_DEPTH 16
#define SNIFFER_UART_DATA_DRAIN_BATCH 4
#define SNIFFER_UART_DRAIN_STACK_SIZE 2048
#define SNIFFER_UART_SHELL_LOCK_MS 50
#define SNIFFER_UART_LINE_TX_TIMEOUT_MS 100

struct sniffer_uart_line {
	uint16_t len;
	char data[SNIFFER_UART_LINE_MAX];
};

/* Packet lines are stored as length prefixed records in a byte ring buffer. */
BUILD_ASSERT(offsetof(struct sniffer_uart_line, data) == sizeof(uint16_t),
	     "line length prefix must be contiguous with the payload");

static struct k_msgq sync_msgq;
static char __aligned(4) sync_msgq_buffer[SNIFFER_UART_SYNC_QUEUE_DEPTH *
					   sizeof(struct sniffer_uart_line)];

RING_BUF_DECLARE(data_rb, CONFIG_IEEE802154_SNIFFER_UART_BUFFER_SIZE);

static const struct device *const shell_uart_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_shell_uart));
static const struct shell *uart_shell;
static struct k_mutex format_lock;
static struct sniffer_uart_line format_line;
static struct k_sem drain_wake;
static struct k_thread drain_thread;
static K_KERNEL_STACK_MEMBER(drain_stack, SNIFFER_UART_DRAIN_STACK_SIZE);

static bool host_port_ready(void)
{
	int dtr = 0;

	if (!IS_ENABLED(CONFIG_UART_LINE_CTRL) || !device_is_ready(shell_uart_dev)) {
		return true;
	}

	if (uart_line_ctrl_get(shell_uart_dev, UART_LINE_CTRL_DTR, &dtr) != 0) {
		/* Plain UART backend - no host-side flow information. */
		return true;
	}

	return dtr != 0;
}

/* shell_fprintf() would block the drain thread on the TXDONE signal that only the shell
 * thread services, so lines are written through the transport under ctx->lock_sem, the
 * semaphore behind z_shell_lock().
 */
static bool shell_tx_lock(void)
{
	if (uart_shell == NULL || uart_shell->ctx == NULL) {
		return false;
	}

	return k_sem_take(&uart_shell->ctx->lock_sem, K_MSEC(SNIFFER_UART_SHELL_LOCK_MS)) == 0;
}

static void shell_tx_unlock(void)
{
	if (uart_shell != NULL && uart_shell->ctx != NULL) {
		k_sem_give(&uart_shell->ctx->lock_sem);
	}
}

struct drain_slot {
	struct sniffer_uart_line line;
	bool valid;
};

/* The backend accepts only what currently fits in its ring buffer, so a line
 * can be split. Releasing the lock in between would let a sync line or a shell
 * response land in the middle of the frame, so the lock is held until the line
 * is complete. The deadline bounds how long that blocks shell commands when the
 * host stops draining the port.
 */
static size_t shell_tx_write_line(const struct sniffer_uart_line *line)
{
	const struct shell_transport *iface = uart_shell->iface;
	k_timepoint_t deadline = sys_timepoint_calc(K_MSEC(SNIFFER_UART_LINE_TX_TIMEOUT_MS));
	size_t offset = 0;

	while (offset < line->len) {
		size_t cnt = 0;

		if (iface->api->write(iface, &line->data[offset],
				      line->len - offset, &cnt) != 0) {
			break;
		}

		offset += cnt;

		if (offset == 0) {
			break;
		}

		if (offset < line->len) {
			if (sys_timepoint_expired(deadline) || !host_port_ready()) {
				break;
			}
			k_msleep(1);
		}
	}

	return offset;
}

static int uart_format_line(struct sniffer_uart_line *line, const char *fmt, va_list args)
{
	int len;

	len = vsnprintk(line->data, sizeof(line->data) - 2, fmt, args);
	if (len <= 0) {
		return -EINVAL;
	}

	len = MIN(len, (int)sizeof(line->data) - 3);

	if (len >= 2 && line->data[len - 2] == '\r' && line->data[len - 1] == '\n') {
		line->len = len;
	} else if (len >= 1 && line->data[len - 1] == '\n') {
		line->data[len - 1] = '\r';
		line->data[len++] = '\n';
		line->len = len;
	} else {
		line->data[len++] = '\r';
		line->data[len++] = '\n';
		line->len = len;
	}

	return 0;
}

/* ring_buf_put() commits the whole record with one ring_buf_put_finish(),
 * so the consumer never observes a half written line.
 */
static bool data_rb_put(const struct sniffer_uart_line *line)
{
	uint32_t record = sizeof(line->len) + line->len;

	if (ring_buf_space_get(&data_rb) < record) {
		return false;
	}

	return ring_buf_put(&data_rb, (const uint8_t *)&line->len, record) == record;
}

static bool data_rb_get(struct sniffer_uart_line *line)
{
	uint16_t len;

	if (ring_buf_get(&data_rb, (uint8_t *)&len, sizeof(len)) != sizeof(len)) {
		return false;
	}

	/* Bounds the copy into the fixed size line buffer. */
	if (len > SNIFFER_UART_LINE_MAX ||
	    ring_buf_get(&data_rb, (uint8_t *)line->data, len) != len) {
		return false;
	}

	line->len = len;

	return true;
}

static void uart_emit_common(bool sync, const char *fmt, va_list args)
{
	bool queued;

	k_mutex_lock(&format_lock, K_FOREVER);
	if (uart_format_line(&format_line, fmt, args) != 0) {
		k_mutex_unlock(&format_lock);
		return;
	}

	if (sync) {
		queued = k_msgq_put(&sync_msgq, &format_line, K_NO_WAIT) == 0;
		if (!queued) {
			struct sniffer_uart_line dropped;

			(void)k_msgq_get(&sync_msgq, &dropped, K_NO_WAIT);
			queued = k_msgq_put(&sync_msgq, &format_line, K_NO_WAIT) == 0;
		}
	} else {
		queued = data_rb_put(&format_line);
	}
	k_mutex_unlock(&format_lock);

	if (!queued) {
		return;
	}

	k_sem_give(&drain_wake);
}

static struct drain_slot sync_slot;
static struct drain_slot data_slot;

static bool slot_load(struct drain_slot *slot, bool sync)
{
	if (sync) {
		return k_msgq_get(&sync_msgq, &slot->line, K_NO_WAIT) == 0;
	}

	return data_rb_get(&slot->line);
}

static bool drain_line(struct drain_slot *slot, bool sync)
{
	if (!slot->valid) {
		if (!slot_load(slot, sync)) {
			return false;
		}
		slot->valid = true;

		if (!host_port_ready()) {
			slot->valid = false;
			return true;
		}
	}

	if (!shell_tx_lock()) {
		return false;
	}

	size_t written = shell_tx_write_line(&slot->line);

	shell_tx_unlock();

	if (written == 0) {
		return false;
	}

	/* A line that was cut short cannot be resumed once the lock is released,
	 * so drop the remainder instead of duplicating the prefix.
	 */
	slot->valid = false;

	return true;
}

static bool drain_pending(void)
{
	return sync_slot.valid || data_slot.valid ||
	       k_msgq_num_used_get(&sync_msgq) > 0 ||
	       !ring_buf_is_empty(&data_rb);
}

static bool drain_once(void)
{
	unsigned int data_drained = 0;

	while (sync_slot.valid || k_msgq_num_used_get(&sync_msgq) > 0) {
		if (!drain_line(&sync_slot, true)) {
			return false;
		}
	}

	while (data_drained < SNIFFER_UART_DATA_DRAIN_BATCH &&
	       (data_slot.valid || !ring_buf_is_empty(&data_rb))) {
		if (!drain_line(&data_slot, false)) {
			return false;
		}
		data_drained++;
	}

	return true;
}

static void drain_thread_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		(void)k_sem_take(&drain_wake, K_FOREVER);

		while (drain_pending()) {
			if (drain_once()) {
				k_yield();
			} else {
				/* Shell TX is busy elsewhere, back off instead of spinning. */
				k_msleep(1);
			}
		}
	}
}

void sniffer_uart_init(void)
{
	k_mutex_init(&format_lock);
	k_msgq_init(&sync_msgq, sync_msgq_buffer, sizeof(struct sniffer_uart_line),
		    SNIFFER_UART_SYNC_QUEUE_DEPTH);
	k_sem_init(&drain_wake, 0, 1);

	uart_shell = shell_backend_uart_get_ptr();

	k_thread_create(&drain_thread, drain_stack, K_KERNEL_STACK_SIZEOF(drain_stack),
			drain_thread_entry, NULL, NULL, NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0,
			K_NO_WAIT);
	k_thread_name_set(&drain_thread, "sniffer_uart");
}

void sniffer_uart_emit(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	uart_emit_common(false, fmt, args);
	va_end(args);
}

void sniffer_uart_emit_sync(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	uart_emit_common(true, fmt, args);
	va_end(args);
}
