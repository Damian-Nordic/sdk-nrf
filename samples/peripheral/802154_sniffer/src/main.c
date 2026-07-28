/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>
#include <nrf_802154.h>
#include <nrf_802154_const.h>
#include <stdlib.h>
#include <dk_buttons_and_leds.h>
#include "sniffer_uart.h"

#if IS_ENABLED(CONFIG_IEEE802154_SNIFFER_TIME_SYNC)
#include "time_sync.h"
#endif

#if defined(CONFIG_BOARD_NRF52840DONGLE)
#include <zephyr/drivers/gpio.h>
static const struct device *const gpio_dev = DEVICE_DT_GET(DT_NODELABEL(gpio0));
#endif

#define HEX_STRING_LENGTH (2 * MAX_PACKET_SIZE + 1)

/* Constant RX-timestamp bias of the nRF54L radio relative to nRF52 (us). */
#define NRF54L_RX_TIMESTAMP_BIAS_US 10

static const struct device *radio_dev =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_ieee802154));
static struct ieee802154_radio_api *radio_api;
static char hex_string[HEX_STRING_LENGTH];
static bool heartbeat_led_state;
static bool packet_led_state;
static k_timeout_t heartbeat_interval;

static void heartbeat(struct k_work *work);

static K_WORK_DELAYABLE_DEFINE(heartbeat_work, heartbeat);

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

#if defined(CONFIG_SOC_SERIES_NRF54L)
	timestamp += NRF54L_RX_TIMESTAMP_BIAS_US;
#endif

	packet_led_state = !packet_led_state;
	dk_set_led(DK_LED4, packet_led_state);
	bin2hex(psdu, length, hex_string, HEX_STRING_LENGTH);

	sniffer_uart_emit("received: %s power: %d lqi: %u time: %llu",
			  hex_string, rssi, lqi, timestamp);

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

static int cmd_phy(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);

	nrf_802154_phy_t phy;

	if (strcmp(argv[1], "2m") == 0) {
		phy = NRF_802154_PHY_EXP1_GFSK_2MBPS;
	} else if (strcmp(argv[1], "250k") == 0) {
		phy = NRF_802154_PHY_OQPSK_250KBPS;
	} else {
		shell_error(shell, "unknown phy: %s (use 2m or 250k)", argv[1]);
		return -EINVAL;
	}

	nrf_802154_phy_set(phy);

	return 0;
}

SHELL_CMD_ARG_REGISTER(phy, NULL, "Set radio PHY <2m|250k>", cmd_phy, 2, 0);

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

#if IS_ENABLED(CONFIG_IEEE802154_SNIFFER_TIME_SYNC)
	time_sync_stop();
#endif

	heartbeat_interval = K_SECONDS(1);
	radio_api->stop(radio_dev);

	return 0;
}
SHELL_CMD_ARG_REGISTER(sleep, NULL, "Disable the radio", cmd_sleep, 1, 0);

#if IS_ENABLED(CONFIG_IEEE802154_SNIFFER_TIME_SYNC)
static int cmd_sync_stop(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	time_sync_stop();
	shell_print(shell, "sync stopped");
	return 0;
}

static int cmd_sync_master_start(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t interval_ms = CONFIG_IEEE802154_SNIFFER_SYNC_INTERVAL_MS;

	if (argc >= 2) {
		interval_ms = (uint32_t)atoi(argv[1]);
	}

	int err = time_sync_master_start(interval_ms);

	if (err != 0) {
		shell_error(shell, "sync master start failed: %d", err);
		return err;
	}

	shell_print(shell, "sync master started interval_ms=%u", interval_ms);
	return 0;
}

static int cmd_sync_slave(const struct shell *shell, size_t argc, char **argv)
{
	uint8_t sniffer_id = 1;

	if (argc >= 2) {
		sniffer_id = (uint8_t)atoi(argv[1]);
	}

	int err = time_sync_slave_start(sniffer_id);

	if (err != 0) {
		shell_error(shell, "sync slave start failed: %d", err);
		return err;
	}

	shell_print(shell, "sync slave started id=%u", sniffer_id);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_sync_master,
	SHELL_CMD_ARG(start, NULL,
		      "sync master start [interval_ms]",
		      cmd_sync_master_start, 1, 1),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_sync,
	SHELL_CMD(master, &sub_sync_master, "Master sync role", NULL),
	SHELL_CMD_ARG(slave, NULL,
		      "Start sync slave [id]",
		      cmd_sync_slave, 1, 1),
	SHELL_CMD_ARG(stop, NULL, "Stop time sync", cmd_sync_stop, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(sync, &sub_sync, "Hardware time sync commands", NULL);
#endif /* CONFIG_IEEE802154_SNIFFER_TIME_SYNC */

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
	(void)dk_leds_init();

	sniffer_uart_init();
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
