/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "time_sync.h"
#include "sniffer_uart.h"

#include <errno.h>

#if defined(CONFIG_SOC_SERIES_NRF54L)
#include <zephyr/drivers/timer/nrf_grtc_timer.h>
#elif defined(CONFIG_NRF_RTC_TIMER)
#include <zephyr/drivers/timer/nrf_rtc_timer.h>
#include <nrf_802154_sl_utils.h>
#include <nrfx_timer.h>
#else
#error "Unsupported SoC for time sync"
#endif

#include <gpiote_nrfx.h>
#include <helpers/nrfx_gppi.h>
#include <nrfx_gpiote.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>

#define SNIFFER_SYNC_NODE DT_NODELABEL(sniffer_sync)

#if !DT_NODE_HAS_STATUS(SNIFFER_SYNC_NODE, okay)
#error "sniffer_sync devicetree node is required for time sync"
#endif

#define SYNC_GPIO_PIN NRF_DT_GPIOS_TO_PSEL(SNIFFER_SYNC_NODE, sync_gpios)
#define GPIOTE_INST   NRF_DT_GPIOTE_INST(SNIFFER_SYNC_NODE, sync_gpios)
#define GPIOTE_NODE   DT_NODELABEL(_CONCAT(gpiote, GPIOTE_INST))
#define GPIOTE_CH_INVALID UINT8_MAX

typedef void (*compare_handler_t)(int32_t chan, uint64_t expire_time, void *user_data);

struct sync_timer {
	int32_t compare_chan;
	int32_t capture_chan;
};

enum sync_mode {
	SYNC_MODE_NONE,
	SYNC_MODE_PRIMARY,
	SYNC_MODE_SECONDARY,
};

static nrfx_gpiote_t *const gpiote = &GPIOTE_NRFX_INST_BY_NODE(GPIOTE_NODE);
static enum sync_mode active_mode;
static bool gpiote_ready;
static uint8_t gpiote_output_ch = GPIOTE_CH_INVALID;
static uint8_t gpiote_input_ch = GPIOTE_CH_INVALID;

/* GPPI task endpoint that the sync pin edge is routed to. */
static uint32_t sync_capture_tep;

static int gpiote_init(void)
{
	int err;

	if (gpiote_ready) {
		return 0;
	}

	err = nrfx_gpiote_init(gpiote, 0);
	if (err != 0 && err != -EALREADY) {
		return err;
	}

	gpiote_ready = true;
	return 0;
}

static int gpiote_output_init(void)
{
	uint8_t ch;
	int err;

	if (gpiote_output_ch != GPIOTE_CH_INVALID) {
		return 0;
	}

	err = nrfx_gpiote_channel_alloc(gpiote, &ch);
	if (err != 0) {
		return err;
	}

	const nrfx_gpiote_output_config_t output_cfg = {
		.drive = NRF_GPIO_PIN_S0S1,
		.input_connect = NRF_GPIO_PIN_INPUT_DISCONNECT,
		.pull = NRF_GPIO_PIN_NOPULL,
	};
	const nrfx_gpiote_task_config_t task_cfg = {
		.task_ch = ch,
		.polarity = NRF_GPIOTE_POLARITY_LOTOHI,
		.init_val = NRF_GPIOTE_INITIAL_VALUE_LOW,
	};

	err = nrfx_gpiote_output_configure(gpiote, SYNC_GPIO_PIN, &output_cfg, &task_cfg);
	if (err != 0) {
		(void)nrfx_gpiote_channel_free(gpiote, ch);
		return err;
	}

	nrfx_gpiote_out_task_enable(gpiote, SYNC_GPIO_PIN);
	gpiote_output_ch = ch;
	return 0;
}

static void gpiote_output_deinit(void)
{
	if (gpiote_output_ch == GPIOTE_CH_INVALID) {
		return;
	}

	nrfx_gpiote_out_task_disable(gpiote, SYNC_GPIO_PIN);
	(void)nrfx_gpiote_pin_uninit(gpiote, SYNC_GPIO_PIN);
	(void)nrfx_gpiote_channel_free(gpiote, gpiote_output_ch);
	gpiote_output_ch = GPIOTE_CH_INVALID;
}

static int gpiote_input_init(nrfx_gpiote_interrupt_handler_t handler)
{
	uint8_t ch;
	int err;

	if (gpiote_input_ch != GPIOTE_CH_INVALID) {
		return 0;
	}

	err = nrfx_gpiote_channel_alloc(gpiote, &ch);
	if (err != 0) {
		return err;
	}

	static const nrf_gpio_pin_pull_t pull = NRF_GPIO_PIN_PULLDOWN;
	nrfx_gpiote_trigger_config_t trigger_cfg = {
		.trigger = NRFX_GPIOTE_TRIGGER_LOTOHI,
		.p_in_channel = &ch,
	};
	const nrfx_gpiote_handler_config_t handler_cfg = {
		.handler = handler,
	};
	nrfx_gpiote_input_pin_config_t input_cfg = {
		.p_pull_config = &pull,
		.p_trigger_config = &trigger_cfg,
		.p_handler_config = &handler_cfg,
	};

	err = nrfx_gpiote_input_configure(gpiote, SYNC_GPIO_PIN, &input_cfg);
	if (err != 0) {
		(void)nrfx_gpiote_channel_free(gpiote, ch);
		return err;
	}

	nrfx_gpiote_trigger_enable(gpiote, SYNC_GPIO_PIN, true);
	gpiote_input_ch = ch;
	return 0;
}

static void gpiote_input_deinit(void)
{
	if (gpiote_input_ch == GPIOTE_CH_INVALID) {
		return;
	}

	nrfx_gpiote_trigger_disable(gpiote, SYNC_GPIO_PIN);
	(void)nrfx_gpiote_pin_uninit(gpiote, SYNC_GPIO_PIN);
	(void)nrfx_gpiote_channel_free(gpiote, gpiote_input_ch);
	gpiote_input_ch = GPIOTE_CH_INVALID;
}

static void gpiote_pulse_clear(void)
{
	nrfx_gpiote_clr_task_trigger(gpiote, SYNC_GPIO_PIN);
}

static int ppi_connect(uint32_t eep, uint32_t tep, nrfx_gppi_handle_t *handle, bool *connected)
{
	int err = nrfx_gppi_conn_alloc(eep, tep, handle);

	if (err != 0) {
		*connected = false;
		return err;
	}

	nrfx_gppi_conn_enable(*handle);
	*connected = true;
	return 0;
}

static void ppi_disconnect(nrfx_gppi_handle_t handle, uint32_t eep, uint32_t tep, bool *connected)
{
	if (!*connected) {
		return;
	}

	nrfx_gppi_conn_disable(handle);
	nrfx_gppi_conn_free(eep, tep, handle);
	*connected = false;
}

#if defined(CONFIG_SOC_SERIES_NRF54L)
/*
 * GRTC-based periodic/capture timer helpers.
 */
static int timer_alloc_compare(struct sync_timer *timer)
{
	timer->compare_chan = -1;
	timer->capture_chan = -1;
	timer->compare_chan = z_nrf_grtc_timer_ext_chan_alloc();

	return timer->compare_chan < 0 ? -ENOMEM : 0;
}

static int timer_alloc_capture(struct sync_timer *timer)
{
	timer->compare_chan = -1;
	timer->capture_chan = -1;
	timer->capture_chan = z_nrf_grtc_timer_chan_alloc();

	return timer->capture_chan < 0 ? -ENOMEM : 0;
}

static void timer_free(struct sync_timer *timer)
{
	if (timer->compare_chan >= 0) {
		z_nrf_grtc_timer_interval_stop(timer->compare_chan);
		z_nrf_grtc_timer_abort(timer->compare_chan);
		z_nrf_grtc_timer_chan_free(timer->compare_chan);
		timer->compare_chan = -1;
	}

	if (timer->capture_chan >= 0) {
		z_nrf_grtc_timer_chan_free(timer->capture_chan);
		timer->capture_chan = -1;
	}
}

static uint64_t timer_read(void)
{
	return z_nrf_grtc_timer_read();
}

static uint64_t timer_ticks_to_us(uint64_t ticks)
{
	return ticks;
}

static uint64_t timer_ms_to_ticks(uint32_t ms)
{
	return (uint64_t)ms * 1000ULL;
}

static int timer_interval_start(int32_t chan, uint32_t interval_ticks,
				compare_handler_t handler, void *user_data)
{
	return z_nrf_grtc_timer_set(chan, timer_read() + interval_ticks, handler, user_data);
}

static void timer_interval_stop(int32_t chan)
{
	z_nrf_grtc_timer_abort(chan);
}

static int timer_set(int32_t chan, uint64_t target_ticks, compare_handler_t handler,
		     void *user_data)
{
	return z_nrf_grtc_timer_set(chan, target_ticks, handler, user_data);
}

static uint32_t timer_compare_evt_address_get(int32_t chan)
{
	return z_nrf_grtc_timer_compare_evt_address_get(chan);
}
#endif /* CONFIG_SOC_SERIES_NRF54L */

#if !defined(CONFIG_SOC_SERIES_NRF54L)
/*
 * TIMER1 must NOT be used here as it would corrupt radio
 * timestamp precision and internal driver timing.
 */
#define HF_TIMER_NODE DT_NODELABEL(timer2)

/* The instance is driven directly through nrfx, so no Zephyr driver may own it.
 * Enabling the node would install a second handler on the same interrupt line.
 */
BUILD_ASSERT(!DT_NODE_HAS_STATUS(HF_TIMER_NODE, okay),
	     "timer2 is claimed by a Zephyr driver, but the sniffer sync path needs it");

static nrfx_timer_t hf_timer = NRFX_TIMER_INSTANCE(NRF_TIMER2);

struct domain_link {
	uint64_t rtc_ticks;
	uint32_t hf_ticks;
};

static int hf_timer_start(nrfx_timer_event_handler_t handler)
{
	nrfx_timer_config_t cfg = NRFX_TIMER_DEFAULT_CONFIG(1000000);
	int err;

	cfg.bit_width = NRF_TIMER_BIT_WIDTH_32;
	err = nrfx_timer_init(&hf_timer, &cfg, handler);
	if (err != 0 && err != -EALREADY) {
		return err;
	}

	if (err != -EALREADY) {
		nrfx_timer_clear(&hf_timer);
	}
	nrfx_timer_enable(&hf_timer);

	return 0;
}

static void hf_timer_stop(void)
{
	if (nrfx_timer_init_check(&hf_timer)) {
		nrfx_timer_disable(&hf_timer);
		nrfx_timer_uninit(&hf_timer);
	}
}

static void domain_link_sample(struct domain_link *link)
{
	unsigned int key = irq_lock();

	link->hf_ticks = nrfx_timer_capture(&hf_timer, NRF_TIMER_CC_CHANNEL1);
	link->rtc_ticks = z_nrf_rtc_timer_read();

	irq_unlock(key);
}

/* Single-shot HF -> radio conversion, used only as a fallback until the
 * calibrated mapping below is populated. Carries up to one RTC tick (~30 us) of
 * error because it samples the RTC once.
 */
static uint64_t hf_to_radio_us_raw(uint32_t hf_capture)
{
	struct domain_link link;
	int64_t d_hf_us;
	uint64_t now_rtc_us;

	domain_link_sample(&link);

	/* Signed delta naturally handles the HF timer's 32-bit wrap-around. */
	d_hf_us = (int64_t)(int32_t)(hf_capture - link.hf_ticks);
	now_rtc_us = NRF_802154_SL_RTC_TICKS_TO_US(link.rtc_ticks);

	if (d_hf_us >= 0) {
		return now_rtc_us + (uint64_t)d_hf_us;
	}

	if (now_rtc_us > (uint64_t)(-d_hf_us)) {
		return now_rtc_us - (uint64_t)(-d_hf_us);
	}

	return 0;
}

/*
 * Calibrated HF-timer -> radio-time mapping.
 *
 * The HF timer captures the edge with 1 us resolution, but the reported
 * timestamp must share the time base of the radio frame timestamps, which are
 * derived from the RTC. Reading the RTC once per edge in ISR context costs up
 * to ~30 us of error, from the 30.5 us RTC quantization and the ISR latency.
 *
 * A low-rate worker instead collects atomic (hf, rtc) pairs and fits
 * radio_us = ratio * hf + offset over them. Worker jitter only moves a sample
 * along the fitted line, so the RTC quantization is the only noise left and it
 * averages down with the sample count. Converting an edge is then arithmetic on
 * a hardware-captured tick, with no sampling at conversion time.
 *
 * The fit uses double, which is soft-float here because CONFIG_FPU is disabled.
 * Enabling the FPU without CONFIG_FPU_SHARING would make this unsafe in ISR
 * context.
 */
#define HF_MAP_SAMPLES          64
#define HF_MAP_MIN_SAMPLES      8
#define HF_MAP_SAMPLE_PERIOD_MS 20

struct hf_sample {
	uint32_t hf;
	uint64_t radio_us;
};

static struct {
	struct hf_sample buf[HF_MAP_SAMPLES];
	uint16_t count;
	uint16_t head;
	/* Published model, read from ISR under irq_lock. */
	uint32_t hf_ref;
	int64_t radio_ref_us;
	double ratio;
	bool valid;
	bool active;
} hf_map;

static struct k_work_delayable hf_map_work;

static void hf_map_recalc(void)
{
	uint16_t n = hf_map.count;
	uint16_t oldest = (hf_map.head + HF_MAP_SAMPLES - n) % HF_MAP_SAMPLES;
	uint32_t hf_base = hf_map.buf[oldest].hf;
	uint64_t radio_base = hf_map.buf[oldest].radio_us;
	double sx = 0.0, sy = 0.0, sxx = 0.0, sxy = 0.0;
	double dn = (double)n;
	double denom, a, b;
	unsigned int key;

	for (uint16_t i = 0; i < n; i++) {
		uint16_t idx = (oldest + i) % HF_MAP_SAMPLES;
		double x = (double)(int32_t)(hf_map.buf[idx].hf - hf_base);
		double y = (double)((int64_t)(hf_map.buf[idx].radio_us - radio_base));

		sx += x;
		sy += y;
		sxx += x * x;
		sxy += x * y;
	}

	denom = dn * sxx - sx * sx;
	if (denom < 1.0) {
		return;
	}

	a = (dn * sxy - sx * sy) / denom;
	b = (sy - a * sx) / dn;

	/* HFCLK vs LFCLK share a nominal 1 us/us relationship; reject an obviously
	 * bad fit (e.g. from a transient) instead of publishing it.
	 */
	if (a < 0.9 || a > 1.1) {
		return;
	}

	key = irq_lock();
	hf_map.hf_ref = hf_base;
	hf_map.radio_ref_us = (int64_t)radio_base + (int64_t)(b + (b < 0.0 ? -0.5 : 0.5));
	hf_map.ratio = a;
	hf_map.valid = true;
	irq_unlock(key);
}

static void hf_map_work_handler(struct k_work *work)
{
	struct domain_link link;

	ARG_UNUSED(work);

	domain_link_sample(&link);

	hf_map.buf[hf_map.head].hf = link.hf_ticks;
	hf_map.buf[hf_map.head].radio_us = NRF_802154_SL_RTC_TICKS_TO_US(link.rtc_ticks);
	hf_map.head = (hf_map.head + 1) % HF_MAP_SAMPLES;
	if (hf_map.count < HF_MAP_SAMPLES) {
		hf_map.count++;
	}

	if (hf_map.count >= HF_MAP_MIN_SAMPLES) {
		hf_map_recalc();
	}

	k_work_schedule(&hf_map_work, K_MSEC(HF_MAP_SAMPLE_PERIOD_MS));
}

static void hf_map_start(void)
{
	if (hf_map.active) {
		return;
	}

	hf_map.count = 0;
	hf_map.head = 0;
	hf_map.valid = false;
	hf_map.active = true;

	k_work_init_delayable(&hf_map_work, hf_map_work_handler);
	k_work_schedule(&hf_map_work, K_NO_WAIT);
}

static void hf_map_stop(void)
{
	struct k_work_sync sync;

	if (!hf_map.active) {
		return;
	}

	hf_map.active = false;
	k_work_cancel_delayable_sync(&hf_map_work, &sync);
	hf_map.valid = false;
}

static uint64_t hf_capture_to_radio_us(uint32_t hf_capture)
{
	uint32_t hf_ref;
	int64_t radio_ref_us;
	double ratio;
	bool valid;
	unsigned int key;
	double r;

	key = irq_lock();
	valid = hf_map.valid;
	hf_ref = hf_map.hf_ref;
	radio_ref_us = hf_map.radio_ref_us;
	ratio = hf_map.ratio;
	irq_unlock(key);

	if (!valid) {
		return hf_to_radio_us_raw(hf_capture);
	}

	r = (double)radio_ref_us + (double)(int32_t)(hf_capture - hf_ref) * ratio;
	if (r < 0.0) {
		return 0;
	}

	return (uint64_t)(r + 0.5);
}
#endif

static int sync_capture_init(struct sync_timer *timer)
{
#if defined(CONFIG_SOC_SERIES_NRF54L)
	int err;

	err = timer_alloc_capture(timer);
	if (err != 0) {
		return err;
	}

	err = z_nrf_grtc_timer_capture_prepare(timer->capture_chan);
	if (err != 0) {
		timer_free(timer);
		return err;
	}

	sync_capture_tep = z_nrf_grtc_timer_capture_task_address_get(timer->capture_chan);
	return 0;
#else
	int err;

	ARG_UNUSED(timer);

	err = hf_timer_start(NULL);
	if (err != 0) {
		return err;
	}

	sync_capture_tep = nrfx_timer_capture_task_address_get(&hf_timer,
							       NRF_TIMER_CC_CHANNEL0);
	return 0;
#endif
}

static int sync_capture_read_us(struct sync_timer *timer, uint64_t *t_us)
{
#if defined(CONFIG_SOC_SERIES_NRF54L)
	return z_nrf_grtc_timer_capture_read(timer->capture_chan, t_us);
#else
	ARG_UNUSED(timer);

	*t_us = hf_capture_to_radio_us(
		nrfx_timer_capture_get(&hf_timer, NRF_TIMER_CC_CHANNEL0));
	return 0;
#endif
}

static void sync_capture_deinit(struct sync_timer *timer)
{
#if defined(CONFIG_SOC_SERIES_NRF54L)
	timer_free(timer);
#else
	ARG_UNUSED(timer);
	hf_timer_stop();
#endif
}

/* ---------- Primary ---------- */

#if defined(CONFIG_SOC_SERIES_NRF54L)
static struct sync_timer primary_timer;
#endif
static uint32_t primary_interval_ms;
static uint32_t primary_seq;
static bool primary_running;
static nrfx_gppi_handle_t primary_edge_ppi;
static uint32_t primary_edge_ppi_eep;
static uint32_t primary_edge_ppi_tep;
static bool primary_edge_ppi_valid;

static struct k_work primary_tick_work;
static struct k_work_delayable primary_pulse_clear_work;

#define SYNC_REPORT_QUEUE_DEPTH 16

#define SYNC_MIN_INTERVAL_MS 10
#define SYNC_MAX_INTERVAL_MS 60000

struct primary_report {
	uint32_t seq;
	uint64_t t_us;
};

K_MSGQ_DEFINE(primary_report_q, sizeof(struct primary_report),
	      SYNC_REPORT_QUEUE_DEPTH, 4);

static void primary_tick_handler(struct k_work *work)
{
	struct primary_report report;

	ARG_UNUSED(work);

	while (k_msgq_get(&primary_report_q, &report, K_NO_WAIT) == 0) {
		sniffer_uart_emit_sync("sync role=primary seq=%u t=%llu",
				       report.seq, report.t_us);
	}
}

static void primary_pulse_clear_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	gpiote_pulse_clear();
}

/* Runs in ISR context for every rising edge, which is generated in hardware:
 * timer compare event -> GPPI -> GPIOTE SET task. Must not block or log.
 */
static void primary_report_edge(uint64_t t_us)
{
	struct primary_report report;

	report.seq = ++primary_seq;
	report.t_us = t_us;

	k_work_reschedule(&primary_pulse_clear_work,
			  K_USEC(CONFIG_IEEE802154_SNIFFER_SYNC_PULSE_US));

	/* Report every edge: the host pairs secondary edge N with primary seq N. */
	(void)k_msgq_put(&primary_report_q, &report, K_NO_WAIT);
	k_work_submit(&primary_tick_work);
}

#if defined(CONFIG_SOC_SERIES_NRF54L)
static void primary_compare_handler(int32_t id, uint64_t expire_time, void *user_data)
{
	int err;

	ARG_UNUSED(id);
	ARG_UNUSED(user_data);

	err = timer_set(primary_timer.compare_chan,
			expire_time + timer_ms_to_ticks(primary_interval_ms),
			primary_compare_handler, NULL);
	if (err != 0) {
		/* Rearm was rejected. Reschedule relative to "now" so periodic pulses do not
		 * silently stop.
		 */
		(void)timer_set(primary_timer.compare_chan,
				timer_read() + timer_ms_to_ticks(primary_interval_ms),
				primary_compare_handler, NULL);
	}

	primary_report_edge(timer_ticks_to_us(expire_time));
}
#else
/*
 * nRF52/nRF53 primary timer backend. All RTC compare channels are owned by the
 * 802.15.4 stack, so the primary device drives the periodic pulse from the free-running HF
 * timer (TIMER2, shared with the capture path of a secondary device): its compare event is
 * routed to the GPIOTE SET task over GPPI, and the compare interrupt advances the next fire
 * time and reports the edge.
 */
#define PRIMARY_HF_CC_CHANNEL     NRF_TIMER_CC_CHANNEL2
#define PRIMARY_HF_CC_EVENT       NRF_TIMER_EVENT_COMPARE2
#define PRIMARY_HF_TIMER_IRQ_PRIO 5

static uint32_t primary_interval_us;
static uint32_t primary_cc_value;

static void primary_hf_handler(nrf_timer_event_t event, void *ctx)
{
	uint32_t cc;

	ARG_UNUSED(ctx);

	if (event != PRIMARY_HF_CC_EVENT) {
		return;
	}

	/* Advance the next compare target while the just-fired threshold is still known. */
	cc = primary_cc_value;
	primary_cc_value = cc + primary_interval_us;
	nrfx_timer_compare(&hf_timer, PRIMARY_HF_CC_CHANNEL, primary_cc_value, true);

	primary_report_edge(hf_capture_to_radio_us(cc));
}

static void primary_hf_isr(const void *arg)
{
	ARG_UNUSED(arg);

	nrfx_timer_irq_handler(&hf_timer);
}
#endif

static int primary_start(uint32_t interval_ms)
{
	int err;

	if (primary_running) {
		return -EALREADY;
	}

	/* The pin is set by hardware, but cleared from a workqueue item, so it
	 * stays high for at least one system tick. With a shorter interval the
	 * next pulse would be due while the pin is still high: the GPIOTE SET
	 * task would then produce no rising edge and the secondary devices would
	 * miss it.
	 */
	if (interval_ms < SYNC_MIN_INTERVAL_MS || interval_ms > SYNC_MAX_INTERVAL_MS) {
		return -EINVAL;
	}

	primary_interval_ms = interval_ms;
	primary_seq = 0;
	k_msgq_purge(&primary_report_q);

	k_work_init(&primary_tick_work, primary_tick_handler);
	k_work_init_delayable(&primary_pulse_clear_work, primary_pulse_clear_handler);

	err = gpiote_init();
	if (err != 0) {
		return err;
	}

	err = gpiote_output_init();
	if (err != 0) {
		return err;
	}

	primary_edge_ppi_tep = nrfx_gpiote_set_task_address_get(gpiote, SYNC_GPIO_PIN);

#if defined(CONFIG_SOC_SERIES_NRF54L)
	err = timer_alloc_compare(&primary_timer);
	if (err != 0) {
		gpiote_output_deinit();
		return err;
	}
	primary_edge_ppi_eep = timer_compare_evt_address_get(primary_timer.compare_chan);

	err = timer_interval_start(primary_timer.compare_chan,
				   (uint32_t)timer_ms_to_ticks(interval_ms),
				   primary_compare_handler, NULL);
	if (err != 0) {
		timer_free(&primary_timer);
		gpiote_output_deinit();
		return err;
	}
#else
	err = hf_timer_start(primary_hf_handler);
	if (err != 0) {
		gpiote_output_deinit();
		return err;
	}
	primary_edge_ppi_eep = nrfx_timer_compare_event_address_get(&hf_timer,
								    PRIMARY_HF_CC_CHANNEL);

	primary_interval_us = interval_ms * 1000U;
	primary_cc_value = nrfx_timer_capture(&hf_timer, PRIMARY_HF_CC_CHANNEL) +
			   primary_interval_us;

	/* The capture above writes the running counter into the compare register
	 * and can therefore raise the compare event. Arm the compare first: it
	 * clears that event and moves the threshold into the future, so the GPPI
	 * connected below cannot emit a pulse that the primary device does not
	 * count. A pulse seen only by the secondary devices would shift edge N
	 * against seq N for the rest of the capture, and the host cannot detect
	 * that.
	 */
	nrfx_timer_compare(&hf_timer, PRIMARY_HF_CC_CHANNEL, primary_cc_value, true);
#endif

	primary_edge_ppi = 0;
	err = ppi_connect(primary_edge_ppi_eep, primary_edge_ppi_tep, &primary_edge_ppi,
			 &primary_edge_ppi_valid);
	if (err != 0) {
#if defined(CONFIG_SOC_SERIES_NRF54L)
		timer_interval_stop(primary_timer.compare_chan);
		timer_free(&primary_timer);
#else
		nrfx_timer_compare_int_disable(&hf_timer, PRIMARY_HF_CC_CHANNEL);
		hf_timer_stop();
#endif
		gpiote_output_deinit();
		return err;
	}

#if !defined(CONFIG_SOC_SERIES_NRF54L)
	/* Enabling the interrupt after the GPPI connection is safe: a compare
	 * that fires in between is latched as pending by the NVIC and runs the
	 * handler as soon as the interrupt is enabled, so no edge is lost.
	 */
	IRQ_CONNECT(DT_IRQN(HF_TIMER_NODE), PRIMARY_HF_TIMER_IRQ_PRIO, primary_hf_isr, NULL, 0);
	irq_enable(DT_IRQN(HF_TIMER_NODE));

	hf_map_start();
#endif

	primary_running = true;
	return 0;
}

static void primary_stop(void)
{
	struct k_work_sync work_sync;

	if (!primary_running) {
		return;
	}

#if defined(CONFIG_SOC_SERIES_NRF54L)
	timer_interval_stop(primary_timer.compare_chan);
#else
	hf_map_stop();
	nrfx_timer_compare_int_disable(&hf_timer, PRIMARY_HF_CC_CHANNEL);
	irq_disable(DT_IRQN(HF_TIMER_NODE));
#endif
	ppi_disconnect(primary_edge_ppi, primary_edge_ppi_eep, primary_edge_ppi_tep,
		       &primary_edge_ppi_valid);
	k_work_cancel_sync(&primary_tick_work, &work_sync);
	k_work_cancel_delayable_sync(&primary_pulse_clear_work, &work_sync);
	k_msgq_purge(&primary_report_q);
	gpiote_pulse_clear();
#if defined(CONFIG_SOC_SERIES_NRF54L)
	timer_free(&primary_timer);
#else
	hf_timer_stop();
#endif
	gpiote_output_deinit();
	primary_running = false;
}

/* ---------- Secondary ---------- */

static uint8_t secondary_id;
static uint32_t secondary_edge;
static bool secondary_running;

static struct k_work secondary_report_work;

static struct sync_timer secondary_timer;
static nrfx_gppi_handle_t secondary_ppi;
static uint32_t secondary_ppi_eep;
static uint32_t secondary_ppi_tep;
static bool secondary_ppi_valid;

struct secondary_report {
	uint32_t edge;
	uint64_t t_us;
};

K_MSGQ_DEFINE(secondary_report_q, sizeof(struct secondary_report),
	      SYNC_REPORT_QUEUE_DEPTH, 4);

static void secondary_report_handler(struct k_work *work)
{
	struct secondary_report report;

	ARG_UNUSED(work);

	while (k_msgq_get(&secondary_report_q, &report, K_NO_WAIT) == 0) {
		sniffer_uart_emit_sync("sync role=secondary id=%u edge=%u t=%llu",
				       secondary_id, report.edge, report.t_us);
	}
}

static void secondary_gpio_handler(nrfx_gpiote_pin_t pin, nrfx_gpiote_trigger_t trigger,
				   void *context)
{
	uint64_t t_us;
	struct secondary_report report;

	ARG_UNUSED(pin);
	ARG_UNUSED(trigger);
	ARG_UNUSED(context);

	if (sync_capture_read_us(&secondary_timer, &t_us) != 0) {
		return;
	}

#if defined(CONFIG_SOC_SERIES_NRF54L)
	/* Rearm GRTC capture immediately, before the next edge. */
	(void)z_nrf_grtc_timer_capture_prepare(secondary_timer.capture_chan);
#endif

	/* Report every edge to keep secondary edge N aligned with primary seq N. */
	report.edge = ++secondary_edge;
	report.t_us = t_us;
	(void)k_msgq_put(&secondary_report_q, &report, K_NO_WAIT);
	k_work_submit(&secondary_report_work);
}

static int secondary_start(uint8_t id)
{
	int err;

	if (secondary_running) {
		return -EALREADY;
	}

	secondary_id = id;
	secondary_edge = 0;
	k_msgq_purge(&secondary_report_q);

	k_work_init(&secondary_report_work, secondary_report_handler);

	err = gpiote_init();
	if (err != 0) {
		return err;
	}

	err = gpiote_input_init(secondary_gpio_handler);
	if (err != 0) {
		return err;
	}

	err = sync_capture_init(&secondary_timer);
	if (err != 0) {
		gpiote_input_deinit();
		return err;
	}

	secondary_ppi_tep = sync_capture_tep;

	secondary_ppi_eep = nrfx_gpiote_in_event_address_get(gpiote, SYNC_GPIO_PIN);
	secondary_ppi = 0;
	err = ppi_connect(secondary_ppi_eep, secondary_ppi_tep, &secondary_ppi,
			  &secondary_ppi_valid);
	if (err != 0) {
		unsigned int key;

		/* Disable the GPIOTE trigger before freeing capture resources so a
		 * stray edge cannot reach the ISR while they are being torn down.
		 */
		key = irq_lock();
		gpiote_input_deinit();
		sync_capture_deinit(&secondary_timer);
		irq_unlock(key);
		return err;
	}

#if !defined(CONFIG_SOC_SERIES_NRF54L)
	hf_map_start();
#endif

	secondary_running = true;
	return 0;
}

static void secondary_stop(void)
{
	struct k_work_sync work_sync;
	unsigned int key;

	if (!secondary_running) {
		return;
	}

#if !defined(CONFIG_SOC_SERIES_NRF54L)
	/* Stop the calibration worker before the capture/timer
	 * teardown below runs under irq_lock.
	 */
	hf_map_stop();
#endif

	/* Disable the GPIOTE trigger first so a stray edge cannot fire the ISR
	 * while capture/PPI resources are being freed below.
	 */
	key = irq_lock();
	gpiote_input_deinit();
	ppi_disconnect(secondary_ppi, secondary_ppi_eep, secondary_ppi_tep, &secondary_ppi_valid);
	sync_capture_deinit(&secondary_timer);
	irq_unlock(key);

	k_work_cancel_sync(&secondary_report_work, &work_sync);
	k_msgq_purge(&secondary_report_q);
	secondary_running = false;
}

/* ---------- Public API ---------- */

int time_sync_primary_start(uint32_t interval_ms)
{
	int err;

	time_sync_stop();
	err = primary_start(interval_ms);
	if (err != 0) {
		return err;
	}

	active_mode = SYNC_MODE_PRIMARY;
	return 0;
}

int time_sync_secondary_start(uint8_t sniffer_id)
{
	int err;

	time_sync_stop();
	err = secondary_start(sniffer_id);
	if (err != 0) {
		return err;
	}

	active_mode = SYNC_MODE_SECONDARY;
	return 0;
}

void time_sync_stop(void)
{
	switch (active_mode) {
	case SYNC_MODE_PRIMARY:
		primary_stop();
		break;
	case SYNC_MODE_SECONDARY:
		secondary_stop();
		break;
	default:
		break;
	}

	active_mode = SYNC_MODE_NONE;
}
