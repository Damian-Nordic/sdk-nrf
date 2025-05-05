/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#include <zephyr/sys/util.h>
#include <nrf_802154.h>
#include <nrf_802154_const.h>
#include <stdlib.h>
#include <dk_buttons_and_leds.h>

#if defined(CONFIG_BOARD_NRF52840DONGLE)
#include <zephyr/drivers/gpio.h>
static const struct device *const gpio_dev = DEVICE_DT_GET(DT_NODELABEL(gpio0));
#endif

#define HEX_STRING_LENGTH (2 * MAX_PACKET_SIZE + 1)

static const struct device *radio_dev =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_ieee802154));
static struct ieee802154_radio_api *radio_api;
static const struct shell *uart_shell;
static char hex_string[HEX_STRING_LENGTH];
static bool heartbeat_led_state;
static bool packet_led_state;
static k_timeout_t heartbeat_interval;

static void heartbeat(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(heartbeat_work, heartbeat);

static uint16_t ed_duration_ms;
static uint16_t ed_count;
static int16_t ed_max;
static void ed_done_func(struct k_work *work);
static K_WORK_DEFINE(ed_done_work, ed_done_func);

static int8_t rssi_max = INT8_MIN;
static int rssi_sum;
static int rssi_num;
static void rssi_sample(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(rssi_sample_work, rssi_sample);
static void rssi_collect(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(rssi_collect_work, rssi_collect);

static void heartbeat(struct k_work *work)
{
	ARG_UNUSED(work);

	heartbeat_led_state = !heartbeat_led_state;
	dk_set_led(DK_LED1, heartbeat_led_state);
	k_work_reschedule(&heartbeat_work, heartbeat_interval);
}

enum net_verdict ieee802154_handle_ack(struct net_if *iface,
				       struct net_pkt *pkt)
{
	ARG_UNUSED(iface);
	ARG_UNUSED(pkt);

	return NET_DROP;
}

int net_recv_data(struct net_if *iface, struct net_pkt *pkt)
{
	if (!pkt) {
		return -EINVAL;
	}

	if (net_pkt_is_empty(pkt)) {
		return -ENODATA;
	}

	uint8_t *psdu = net_buf_frag_last(pkt->buffer)->data;
	size_t length = net_buf_frags_len(pkt->buffer);
	uint8_t lqi = net_pkt_ieee802154_lqi(pkt);
	int8_t rssi = net_pkt_ieee802154_rssi_dbm(pkt);
	struct net_ptp_time *pkt_time = net_pkt_timestamp(pkt);
	uint64_t timestamp =
		pkt_time->second * USEC_PER_SEC + pkt_time->nanosecond / NSEC_PER_USEC;

	packet_led_state = !packet_led_state;
	dk_set_led(DK_LED4, packet_led_state);
	bin2hex(psdu, length, hex_string, HEX_STRING_LENGTH);

	shell_print(uart_shell,
		    "received: %s power: %d lqi: %u time: %llu",
		    hex_string,
		    rssi,
		    lqi,
		    timestamp);

	net_pkt_unref(pkt);

	return 0;
}

static int cmd_channel(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t channel;

	switch (argc) {
	case 1:
		shell_print(shell, "%d", nrf_802154_channel_get());
		break;
	case 2:
		channel = atoi(argv[1]);
		radio_api->set_channel(radio_dev, channel);
		break;
	default:
		shell_print(shell, "invalid number of parameters: %d", argc);
		break;
	}

	return 0;
}
SHELL_CMD_ARG_REGISTER(channel, NULL, "Set radio channel", cmd_channel, 1, 1);

static int cmd_receive(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	heartbeat_interval = K_MSEC(250);
	radio_api->start(radio_dev);

	return 0;
}
SHELL_CMD_ARG_REGISTER(receive, NULL, "Put radio in receive state", cmd_receive, 1, 0);

static int cmd_sleep(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	heartbeat_interval = K_SECONDS(1);
	radio_api->stop(radio_dev);

	return 0;
}
SHELL_CMD_ARG_REGISTER(sleep, NULL, "Disable the radio", cmd_sleep, 1, 0);

static void ed_done(const struct device *dev, int16_t max_ed)
{
	ed_max = max_ed;
	k_work_submit(&ed_done_work);
}

static void ed_done_func(struct k_work *work)
{
	shell_print(uart_shell, "ED max %d, left %u", ed_max, ed_count);

	if (ed_count) {
		--ed_count;
		radio_api->ed_scan(radio_dev, ed_duration_ms, ed_done);
	}
}

static void rssi_sample(struct k_work *work)
{
	int8_t rssi;

	if (nrf_802154_rssi_measure_begin()) {
		k_busy_wait(30);
		rssi = nrf_802154_rssi_last_get();

		if (rssi != INT8_MAX) {
			rssi_max = MAX(rssi, rssi_max);
			rssi_sum += rssi;
			rssi_num++;
		}
	}

	k_work_schedule(&rssi_sample_work, K_MSEC(1));
}

static void rssi_collect(struct k_work *work)
{
	int8_t rssi_avg;

	rssi_avg = (rssi_num > 0) ? (rssi_sum / rssi_num) : 127;

	shell_print(uart_shell, "RSSI max %d avg %d, left %u", rssi_max, rssi_avg, ed_count);

	rssi_max = INT8_MIN;
	rssi_sum = 0;
	rssi_num = 0;

	if (ed_count) {
		--ed_count;
		k_work_schedule(&rssi_collect_work, K_MSEC(ed_duration_ms));
	} else {
		k_work_cancel_delayable(&rssi_sample_work);
	}
}

static int cmd_ed(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ed_duration_ms = atoi(argv[1]);
	ed_count = atoi(argv[2]);

	if (ed_count) {
		--ed_count;
		radio_api->ed_scan(radio_dev, ed_duration_ms, ed_done);
	}

	return 0;
}
SHELL_CMD_ARG_REGISTER(ed, NULL, "Run energy detection <duration-ms> <count>", cmd_ed, 3, 0);

static int cmd_rssi(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ed_duration_ms = atoi(argv[1]);
	ed_count = atoi(argv[2]);

	if (ed_count) {
		--ed_count;
		k_work_schedule(&rssi_sample_work, K_MSEC(1));
		k_work_schedule(&rssi_collect_work, K_MSEC(ed_duration_ms));
	}

	return 0;
}
SHELL_CMD_ARG_REGISTER(rssi, NULL, "Run RSSI measurement <duration-ms> <count>", cmd_rssi, 3, 0);

#if defined(CONFIG_BOARD_NRF52840DONGLE)
static int cmd_bootloader(const struct shell *shell, size_t argc, char **argv)
{
	/*
	 * nRF52840 dongle has pin P0.19 connected to reset. By setting it
	 * in `GPIO_OUTPUT_LOW` mode, reset is pulled to GND,
	 * which results in device rebooting without skipping the bootloader.
	 */
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!device_is_ready(gpio_dev)) {
		shell_print(shell, "GPIO device not ready");
		return 0;
	}

	int err = gpio_pin_configure(gpio_dev, 19, GPIO_OUTPUT_LOW);

	if (err) {
		shell_print(shell, "Failed to configure GPIO pin. Error code: %d", err);
	}

	return 0;
}
SHELL_CMD_ARG_REGISTER(bootloader, NULL, "Reboot into bootloader", cmd_bootloader, 1, 0);
#endif /* CONFIG_BOARD_NRF52840DONGLE */

int main(void)
{
	(void) dk_leds_init();

	uart_shell = shell_backend_uart_get_ptr();
	heartbeat_interval = K_SECONDS(1);
	k_work_reschedule(&heartbeat_work, heartbeat_interval);

	struct ieee802154_config config = {
		.promiscuous = true
	};

	radio_api = (struct ieee802154_radio_api *)radio_dev->api;
	__ASSERT_NO_MSG(radio_api);

#if !IS_ENABLED(CONFIG_NRF_802154_SERIALIZATION)
	/* The serialization API does not support disabling the auto-ack. */
	nrf_802154_auto_ack_set(false);
#endif

	radio_api->configure(radio_dev, IEEE802154_CONFIG_PROMISCUOUS, &config);

	return 0;
}
