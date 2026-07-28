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
#include <hal/nrf_rtc.h>
#include <nrfx_timer.h>
#else
#error "Unsupported SoC for time sync"
#endif

#include <gpiote_nrfx.h>
#include <helpers/nrfx_gppi.h>
#include <nrfx_gpiote.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>

#define SNIFTER_SYNC_NODE DT_NODELABEL(sniffer_sync)

#if !DT_NODE_HAS_STATUS(SNIFTER_SYNC_NODE, okay)
#error "sniffer_sync devicetree node is required for time sync"
#endif

#define SYNC_GPIO_PIN NRF_DT_GPIOS_TO_PSEL(SNIFTER_SYNC_NODE, sync_gpios)
#define GPIOTE_INST   NRF_DT_GPIOTE_INST(SNIFTER_SYNC_NODE, sync_gpios)
#define GPIOTE_NODE   DT_NODELABEL(_CONCAT(gpiote, GPIOTE_INST))
#define GPIOTE_CH_INVALID UINT8_MAX

typedef void (*compare_handler_t)(int32_t chan, uint64_t expire_time, void *user_data);

struct sync_timer {
	int32_t compare_chan;
	int32_t capture_chan;
};

struct sync_capture_ctx {
	uint32_t tep;
};

enum sync_mode {
	SYNC_MODE_NONE,
	SYNC_MODE_MASTER,
	SYNC_MODE_SLAVE,
};

static nrfx_gpiote_t *const gpiote = &GPIOTE_NRFX_INST_BY_NODE(GPIOTE_NODE);
static enum sync_mode active_mode;
static bool gpiote_ready;
static uint8_t gpiote_output_ch = GPIOTE_CH_INVALID;
static uint8_t gpiote_input_ch = GPIOTE_CH_INVALID;
static struct sync_capture_ctx sync_capture;

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
 * The HF timer (1 MHz, hardware-captured at the pulse edge) gives 1 us edge
 * resolution, but the reported timestamp must live in the same time base as the
 * radio frame timestamps (RTC-derived microseconds). Reading the RTC once per
 * edge in ISR context injects up to ~30 us of error (RTC 30.5 us quantization
 * plus the ISR-latency-dependent sub-tick phase).
 *
 * Instead we continuously fit a line radio_us = ratio * hf + offset from many
 * atomic (hf, rtc) sample pairs taken by a low-rate worker. Each pair is a
 * simultaneous snapshot, so worker scheduling jitter only changes *where* on the
 * line a sample lands, not the fitted line; the RTC quantization is the only
 * per-sample noise and averages down as 1/sqrt(N) (the jitter even dithers it).
 * Converting an edge is then pure arithmetic on a hardware-captured tick - no
 * sampling and no ISR jitter at conversion time.
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

	sync_capture.tep = z_nrf_grtc_timer_capture_task_address_get(timer->capture_chan);
	return 0;
#else
	int err;

	ARG_UNUSED(timer);

	err = hf_timer_start(NULL);
	if (err != 0) {
		return err;
	}

	sync_capture.tep = nrfx_timer_capture_task_address_get(&hf_timer,
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

/* ---------- Master ---------- */

#if defined(CONFIG_SOC_SERIES_NRF54L)
static struct sync_timer master_timer;
#endif
static uint32_t master_interval_ms;
static uint32_t master_seq;
static bool master_running;
static nrfx_gppi_handle_t master_edge_ppi;
static uint32_t master_edge_ppi_eep;
static uint32_t master_edge_ppi_tep;
static bool master_edge_ppi_valid;

static struct k_work master_tick_work;
static struct k_work_delayable master_pulse_clear_work;

#define SYNC_REPORT_QUEUE_DEPTH 16

struct master_report {
	uint32_t seq;
	uint64_t t_us;
};

K_MSGQ_DEFINE(master_report_q, sizeof(struct master_report),
	      SYNC_REPORT_QUEUE_DEPTH, 4);

static void master_tick_handler(struct k_work *work)
{
	struct master_report report;

	ARG_UNUSED(work);

	while (k_msgq_get(&master_report_q, &report, K_NO_WAIT) == 0) {
		sniffer_uart_emit_sync("sync role=master seq=%u t=%llu",
				       report.seq, report.t_us);
	}
}

static void master_pulse_clear_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	gpiote_pulse_clear();
}

/* Runs from the periodic timer ISR for every emitted rising edge. The edge itself is
 * generated in hardware (timer compare event -> GPPI -> GPIOTE SET task); here we only
 * record the timestamp, schedule the software pulse clear and hand the report to a
 * workqueue. Must not block or log directly: this runs in ISR context.
 */
static void master_report_edge(uint64_t t_us)
{
	struct master_report report;

	report.seq = ++master_seq;
	report.t_us = t_us;

	k_work_schedule(&master_pulse_clear_work,
			K_USEC(CONFIG_IEEE802154_SNIFFER_SYNC_PULSE_US));

	/* Report every edge: the host pairs slave edge N with master seq N. */
	(void)k_msgq_put(&master_report_q, &report, K_NO_WAIT);
	k_work_submit(&master_tick_work);
}

#if defined(CONFIG_SOC_SERIES_NRF54L)
static void master_compare_handler(int32_t id, uint64_t expire_time, void *user_data)
{
	int err;

	ARG_UNUSED(id);
	ARG_UNUSED(user_data);

	err = timer_set(master_timer.compare_chan,
			expire_time + timer_ms_to_ticks(master_interval_ms),
			master_compare_handler, NULL);
	if (err != 0) {
		/* Rearm was rejected (e.g. requested target too close/late by the time it
		 * reached hardware). Reschedule relative to "now" so periodic pulses do not
		 * silently stop.
		 */
		(void)timer_set(master_timer.compare_chan,
				timer_read() + timer_ms_to_ticks(master_interval_ms),
				master_compare_handler, NULL);
	}

	master_report_edge(timer_ticks_to_us(expire_time));
}
#else
/*
 * nRF52/nRF53 master timer backend. All RTC compare channels are owned by the
 * 802.15.4 stack (RTC1 has one system channel plus three user channels, and the
 * radio SL LP timer claims all three at init), so the master drives the periodic
 * pulse from the free-running HF timer (TIMER2, shared with the slave capture
 * path): its compare event is routed to the GPIOTE SET task over GPPI, and the
 * compare interrupt advances the next fire time and reports the edge.
 */
#define MASTER_HF_CC_CHANNEL     NRF_TIMER_CC_CHANNEL2
#define MASTER_HF_CC_EVENT       NRF_TIMER_EVENT_COMPARE2
#define MASTER_HF_TIMER_IRQ_PRIO 5

static uint32_t master_interval_us;
static uint32_t master_cc_value;

static void master_hf_handler(nrf_timer_event_t event, void *ctx)
{
	uint32_t cc;

	ARG_UNUSED(ctx);

	if (event != MASTER_HF_CC_EVENT) {
		return;
	}

	/* Advance the next compare target while the just-fired threshold is still known. */
	cc = master_cc_value;
	master_cc_value = cc + master_interval_us;
	nrfx_timer_compare(&hf_timer, MASTER_HF_CC_CHANNEL, master_cc_value, true);

	master_report_edge(hf_capture_to_radio_us(cc));
}

static void master_hf_isr(const void *arg)
{
	ARG_UNUSED(arg);

	nrfx_timer_irq_handler(&hf_timer);
}
#endif


static int master_start(uint32_t interval_ms)
{
	int err;

	if (master_running) {
		return -EALREADY;
	}

	sniffer_uart_emit_sync("meta role=master id=0");

	master_interval_ms = interval_ms;
	master_seq = 0;
	k_msgq_purge(&master_report_q);

	k_work_init(&master_tick_work, master_tick_handler);
	k_work_init_delayable(&master_pulse_clear_work, master_pulse_clear_handler);

	err = gpiote_init();
	if (err != 0) {
		return err;
	}

	err = gpiote_output_init();
	if (err != 0) {
		return err;
	}

	master_edge_ppi_tep = nrfx_gpiote_set_task_address_get(gpiote, SYNC_GPIO_PIN);

#if defined(CONFIG_SOC_SERIES_NRF54L)
	err = timer_alloc_compare(&master_timer);
	if (err != 0) {
		gpiote_output_deinit();
		return err;
	}
	master_edge_ppi_eep = timer_compare_evt_address_get(master_timer.compare_chan);
#else
	err = hf_timer_start(master_hf_handler);
	if (err != 0) {
		gpiote_output_deinit();
		return err;
	}
	master_edge_ppi_eep = nrfx_timer_compare_event_address_get(&hf_timer,
								   MASTER_HF_CC_CHANNEL);
#endif

	master_edge_ppi = 0;
	err = ppi_connect(master_edge_ppi_eep, master_edge_ppi_tep, &master_edge_ppi,
			 &master_edge_ppi_valid);
	if (err != 0) {
#if defined(CONFIG_SOC_SERIES_NRF54L)
		timer_free(&master_timer);
#else
		hf_timer_stop();
#endif
		gpiote_output_deinit();
		return err;
	}

#if defined(CONFIG_SOC_SERIES_NRF54L)
	err = timer_interval_start(master_timer.compare_chan,
				   (uint32_t)timer_ms_to_ticks(interval_ms),
				   master_compare_handler, NULL);
	if (err != 0) {
		ppi_disconnect(master_edge_ppi, master_edge_ppi_eep, master_edge_ppi_tep,
			       &master_edge_ppi_valid);
		timer_free(&master_timer);
		gpiote_output_deinit();
		return err;
	}
#else
	master_interval_us = interval_ms * 1000U;
	master_cc_value = nrfx_timer_capture(&hf_timer, MASTER_HF_CC_CHANNEL) +
			  master_interval_us;

	IRQ_CONNECT(TIMER2_IRQn, MASTER_HF_TIMER_IRQ_PRIO, master_hf_isr, NULL, 0);
	irq_enable(TIMER2_IRQn);

	nrfx_timer_compare(&hf_timer, MASTER_HF_CC_CHANNEL, master_cc_value, true);
	hf_map_start();
#endif

	master_running = true;
	return 0;
}

static void master_stop(void)
{
	if (!master_running) {
		return;
	}

#if defined(CONFIG_SOC_SERIES_NRF54L)
	timer_interval_stop(master_timer.compare_chan);
#else
	hf_map_stop();
	nrfx_timer_compare_int_disable(&hf_timer, MASTER_HF_CC_CHANNEL);
	irq_disable(TIMER2_IRQn);
#endif
	ppi_disconnect(master_edge_ppi, master_edge_ppi_eep, master_edge_ppi_tep,
		       &master_edge_ppi_valid);
	k_work_cancel(&master_tick_work);
	k_work_cancel_delayable(&master_pulse_clear_work);
	k_msgq_purge(&master_report_q);
	gpiote_pulse_clear();
#if defined(CONFIG_SOC_SERIES_NRF54L)
	timer_free(&master_timer);
#else
	hf_timer_stop();
#endif
	gpiote_output_deinit();
	master_running = false;
}

/* ---------- Slave ---------- */

static uint8_t slave_id;
static uint32_t slave_edge;
static bool slave_running;

static struct k_work slave_report_work;

static struct sync_timer slave_timer;
static nrfx_gppi_handle_t slave_ppi;
static uint32_t slave_ppi_eep;
static uint32_t slave_ppi_tep;
static bool slave_ppi_valid;

struct slave_report {
	uint32_t edge;
	uint64_t t_us;
};

K_MSGQ_DEFINE(slave_report_q, sizeof(struct slave_report),
	      SYNC_REPORT_QUEUE_DEPTH, 4);

static void slave_report_handler(struct k_work *work)
{
	struct slave_report report;

	ARG_UNUSED(work);

	while (k_msgq_get(&slave_report_q, &report, K_NO_WAIT) == 0) {
		sniffer_uart_emit_sync("sync role=slave id=%u edge=%u t=%llu",
				       slave_id, report.edge, report.t_us);
	}
}

static void slave_gpio_handler(nrfx_gpiote_pin_t pin, nrfx_gpiote_trigger_t trigger,
			       void *context)
{
	uint64_t t_us;
	struct slave_report report;

	ARG_UNUSED(pin);
	ARG_UNUSED(trigger);
	ARG_UNUSED(context);

	if (sync_capture_read_us(&slave_timer, &t_us) != 0) {
		return;
	}

#if defined(CONFIG_SOC_SERIES_NRF54L)
	/* Rearm GRTC capture immediately, before the next edge. */
	(void)z_nrf_grtc_timer_capture_prepare(slave_timer.capture_chan);
#endif

	/* Report every edge to keep slave edge N aligned with master seq N. */
	report.edge = ++slave_edge;
	report.t_us = t_us;
	(void)k_msgq_put(&slave_report_q, &report, K_NO_WAIT);
	k_work_submit(&slave_report_work);
}

static int slave_start(uint8_t id)
{
	int err;

	if (slave_running) {
		return -EALREADY;
	}

	slave_id = id;
	slave_edge = 0;
	k_msgq_purge(&slave_report_q);

	k_work_init(&slave_report_work, slave_report_handler);

	err = gpiote_init();
	if (err != 0) {
		sniffer_uart_emit_sync("sync slave fail stage=gpiote_init err=%d", err);
		return err;
	}

	err = gpiote_input_init(slave_gpio_handler);
	if (err != 0) {
		sniffer_uart_emit_sync("sync slave fail stage=gpiote_input_init err=%d", err);
		return err;
	}

	err = sync_capture_init(&slave_timer);
	if (err != 0) {
		sniffer_uart_emit_sync("sync slave fail stage=sync_capture_init err=%d", err);
		gpiote_input_deinit();
		return err;
	}

	slave_ppi_tep = sync_capture.tep;

	slave_ppi_eep = nrfx_gpiote_in_event_address_get(gpiote, SYNC_GPIO_PIN);
	slave_ppi = 0;
	err = ppi_connect(slave_ppi_eep, slave_ppi_tep, &slave_ppi, &slave_ppi_valid);
	if (err != 0) {
		unsigned int key;

		sniffer_uart_emit_sync("sync slave fail stage=ppi_connect err=%d", err);

		/* Disable the GPIOTE trigger before freeing capture resources so a
		 * stray edge cannot reach the ISR while they are being torn down.
		 */
		key = irq_lock();
		gpiote_input_deinit();
		sync_capture_deinit(&slave_timer);
		irq_unlock(key);
		return err;
	}

	sniffer_uart_emit_sync("meta role=slave id=%u", slave_id);

#if !defined(CONFIG_SOC_SERIES_NRF54L)
	hf_map_start();
#endif

	slave_running = true;
	return 0;
}

static void slave_stop(void)
{
	struct k_work_sync work_sync;
	unsigned int key;

	if (!slave_running) {
		return;
	}

#if !defined(CONFIG_SOC_SERIES_NRF54L)
	/* Stop the calibration worker (thread context, may block) before the
	 * capture/timer teardown below runs under irq_lock.
	 */
	hf_map_stop();
#endif

	/* Disable the GPIOTE trigger first so a stray edge cannot fire the ISR
	 * while capture/PPI resources are being freed below (the ISR would
	 * otherwise dereference an already-freed timer channel/instance).
	 */
	key = irq_lock();
	gpiote_input_deinit();
	ppi_disconnect(slave_ppi, slave_ppi_eep, slave_ppi_tep, &slave_ppi_valid);
	sync_capture_deinit(&slave_timer);
	irq_unlock(key);

	k_work_cancel_sync(&slave_report_work, &work_sync);
	k_msgq_purge(&slave_report_q);
	slave_running = false;
}

/* ---------- Public API ---------- */

int time_sync_master_start(uint32_t interval_ms)
{
	int err;

	time_sync_stop();
	err = master_start(interval_ms);
	if (err != 0) {
		return err;
	}

	active_mode = SYNC_MODE_MASTER;
	return 0;
}

int time_sync_slave_start(uint8_t sniffer_id)
{
	int err;

	time_sync_stop();
	err = slave_start(sniffer_id);
	if (err != 0) {
		return err;
	}

	active_mode = SYNC_MODE_SLAVE;
	return 0;
}

void time_sync_stop(void)
{
	switch (active_mode) {
	case SYNC_MODE_MASTER:
		master_stop();
		break;
	case SYNC_MODE_SLAVE:
		slave_stop();
		break;
	default:
		break;
	}

	active_mode = SYNC_MODE_NONE;
}
