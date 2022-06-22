/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#if defined(CONFIG_BT)
#include "ble.h"
#endif

#include <zephyr/drivers/uart.h>
#include <zephyr/usb/usb_device.h>

#include <zephyr/net/openthread.h>
#include <openthread/ip6.h>
#include <openthread/udp.h>

LOG_MODULE_REGISTER(cli_sample, CONFIG_OT_COMMAND_LINE_INTERFACE_LOG_LEVEL);

#define WELLCOME_TEXT \
	"\n\r"\
	"\n\r"\
	"OpenThread Command Line Interface is now running.\n\r" \
	"Use the 'ot' keyword to invoke OpenThread commands e.g. " \
	"'ot thread start.'\n\r" \
	"For the full commands list refer to the OpenThread CLI " \
	"documentation at:\n\r" \
	"https://github.com/openthread/openthread/blob/master/src/cli/README.md\n\r"

struct perf_test {
	size_t total_bytes_received;
	size_t last_1s_bytes_received;
	int64_t first_block_received_ts;
} g_perf_test;

otUdpSocket g_socket;
otMessageInfo g_rx_message_info;

void send_reminder()
{
	if (!g_rx_message_info.mPeerPort) {
		LOG_INF("No peer info");
		return;
	}

	otInstance *instance = openthread_get_default_instance();
	otMessage *message = otUdpNewMessage(instance, NULL);

	if (!message) {
		LOG_ERR("No free message");
		return;
	}

	otError error = otMessageAppend(message, "ABCD", 4);

	if (error != OT_ERROR_NONE) {
		LOG_ERR("Failed to append message: %d", (int)error);
		return;
	}

	otMessageInfo messageInfo;
	memset(&messageInfo, 0, sizeof(messageInfo));
	messageInfo.mSockAddr = g_rx_message_info.mSockAddr;
	messageInfo.mPeerAddr = g_rx_message_info.mPeerAddr;
	messageInfo.mPeerPort = g_rx_message_info.mPeerPort;

	error = otUdpSend(instance, &g_socket, message, &messageInfo);

	if (error != OT_ERROR_NONE) {
		LOG_ERR("Failed to send message: %d", (int)error);
		return;
	}
}

void on_message_received(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
	const int64_t now = k_uptime_get();
	const uint16_t length = otMessageGetLength(aMessage);

	if (g_perf_test.first_block_received_ts == 0) {
		g_perf_test.first_block_received_ts = now;
	}

	g_perf_test.last_1s_bytes_received += length;
	g_perf_test.total_bytes_received += length;
	memcpy(&g_rx_message_info, aMessageInfo, sizeof(g_rx_message_info));
	send_reminder();
}

void print_report()
{
	openthread_api_mutex_lock(openthread_get_default_context());

	const struct perf_test stat = g_perf_test;
	g_perf_test.last_1s_bytes_received = 0;

	if (stat.last_1s_bytes_received == 0) {
		send_reminder();
	}

	openthread_api_mutex_unlock(openthread_get_default_context());

	const unsigned throughput = (unsigned)(stat.last_1s_bytes_received);
	const int64_t total_duration = (k_uptime_get() - stat.first_block_received_ts) / 1000;
	const unsigned total_throughput = (unsigned)(stat.total_bytes_received / total_duration);

	LOG_INF("Throughput: %7uB/s [%4ukB/s], total: %7uB/s [%4ukB/s], traffic: %u kB", throughput,
		throughput >> 10, total_throughput, total_throughput >> 10,
		(unsigned)(stat.total_bytes_received >> 10));
}

void main(void)
{
#if DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_shell_uart), zephyr_cdc_acm_uart)
	int ret;
	const struct device *dev;
	uint32_t dtr = 0U;

	ret = usb_enable(NULL);
	if (ret != 0) {
		LOG_ERR("Failed to enable USB");
		return;
	}

	dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_shell_uart));
	if (dev == NULL) {
		LOG_ERR("Failed to find specific UART device");
		return;
	}

	LOG_INF("Waiting for host to be ready to communicate");

	/* Data Terminal Ready - check if host is ready to communicate */
	while (!dtr) {
		ret = uart_line_ctrl_get(dev, UART_LINE_CTRL_DTR, &dtr);
		if (ret) {
			LOG_ERR("Failed to get Data Terminal Ready line state: %d",
				ret);
			continue;
		}
		k_msleep(100);
	}

	/* Data Carrier Detect Modem - mark connection as established */
	(void)uart_line_ctrl_set(dev, UART_LINE_CTRL_DCD, 1);
	/* Data Set Ready - the NCP SoC is ready to communicate */
	(void)uart_line_ctrl_set(dev, UART_LINE_CTRL_DSR, 1);
#endif

	LOG_INF(WELLCOME_TEXT);

	otInstance *instance = openthread_get_default_instance();
	otSockAddr addr = { .mPort = 5540 };

	otError err = otUdpOpen(instance, &g_socket, on_message_received, NULL);

	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to open socket: %d", (int)err);
		return;
	}

	err = otUdpBind(instance, &g_socket, &addr, OT_NETIF_THREAD);

	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to bind socket");
	}

	while (1) {
		k_sleep(K_SECONDS(1));
		print_report();
	}

#if CONFIG_BT
	ble_enable();
#endif

}
