/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "sniffer_uart.h"

#include <stdarg.h>
#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>

#define SNIFFER_UART_LINE_MAX 384
#define SNIFFER_UART_SYNC_QUEUE_DEPTH 16
#define SNIFFER_UART_DATA_QUEUE_DEPTH 96
#define SNIFFER_UART_DATA_DRAIN_BATCH 4
#define SNIFFER_UART_DRAIN_STACK_SIZE 2048
#define SNIFFER_UART_SHELL_LOCK_MS 50

struct sniffer_uart_line {
	uint16_t len;
	char data[SNIFFER_UART_LINE_MAX];
};

static struct k_msgq sync_msgq;
static struct k_msgq data_msgq;
static char __aligned(4) sync_msgq_buffer[SNIFFER_UART_SYNC_QUEUE_DEPTH *
					   sizeof(struct sniffer_uart_line)];
static char __aligned(4) data_msgq_buffer[SNIFFER_UART_DATA_QUEUE_DEPTH *
					  sizeof(struct sniffer_uart_line)];

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

static void shell_tx_write_line(const struct sniffer_uart_line *line)
{
	z_shell_print_stream(uart_shell, line->data, line->len);
}

static int uart_format_line(struct sniffer_uart_line *line, const char *fmt, va_list args)
{
	int len;

	len = vsnprintk(line->data, sizeof(line->data) - 2, fmt, args);
	if (len <= 0) {
		return len;
	}

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

static void drain_wake_up(void)
{
	k_sem_give(&drain_wake);
}

static void uart_emit_common(struct k_msgq *msgq, bool sync, const char *fmt, va_list args)
{
	int err;

	k_mutex_lock(&format_lock, K_FOREVER);
	if (uart_format_line(&format_line, fmt, args) != 0) {
		k_mutex_unlock(&format_lock);
		return;
	}

	err = k_msgq_put(msgq, &format_line, K_NO_WAIT);
	if (err != 0 && sync) {
		struct sniffer_uart_line dropped;

		(void)k_msgq_get(msgq, &dropped, K_NO_WAIT);
		err = k_msgq_put(msgq, &format_line, K_NO_WAIT);
	}
	k_mutex_unlock(&format_lock);

	if (err != 0) {
		return;
	}

	drain_wake_up();
}

static bool drain_line(struct k_msgq *msgq)
{
	struct sniffer_uart_line line;

	/* Peek first and only dequeue once the line has 
	 * actually been handed to the shell. 
	 */
	if (k_msgq_peek(msgq, &line) != 0) {
		return false;
	}

	if (!host_port_ready()) {
		(void)k_msgq_get(msgq, &line, K_NO_WAIT);
		return true;
	}

	if (!shell_tx_lock()) {
		return false;
	}

	shell_tx_write_line(&line);
	shell_tx_unlock();

	(void)k_msgq_get(msgq, &line, K_NO_WAIT);

	return true;
}

static bool drain_once(void)
{
	unsigned int data_drained = 0;

	while (k_msgq_num_used_get(&sync_msgq) > 0) {
		if (!drain_line(&sync_msgq)) {
			return false;
		}
	}

	while (data_drained < SNIFFER_UART_DATA_DRAIN_BATCH &&
	       k_msgq_num_used_get(&data_msgq) > 0) {
		if (!drain_line(&data_msgq)) {
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

		while (k_msgq_num_used_get(&sync_msgq) > 0 ||
		       k_msgq_num_used_get(&data_msgq) > 0) {
			if (drain_once()) {
				k_yield();
			} else {
				/* Shell TX is busy elsewhere - back off instead
				 * of spinning on the lock.
				 */
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
	k_msgq_init(&data_msgq, data_msgq_buffer, sizeof(struct sniffer_uart_line),
		    SNIFFER_UART_DATA_QUEUE_DEPTH);
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
	uart_emit_common(&data_msgq, false, fmt, args);
	va_end(args);
}

void sniffer_uart_emit_sync(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	uart_emit_common(&sync_msgq, true, fmt, args);
	va_end(args);
}
