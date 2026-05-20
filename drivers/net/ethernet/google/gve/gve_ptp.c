// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/* Google virtual Ethernet (gve) driver
 *
 * Copyright (C) 2025 Google LLC
 */

#include "gve.h"
#include "gve_adminq.h"

/* Interval to schedule a nic timestamp calibration, 250ms. */
#define GVE_NIC_TS_SYNC_INTERVAL_MS 250

/*
 * Stores cycle counter samples in get_cycles() units from a
 * sandwiched NIC clock read
 */
struct gve_sysclock_sample {
	/* Cycle counter from NIC before clock read */
	u64 nic_pre_cycles;
	/* Cycle counter from NIC after clock read */
	u64 nic_post_cycles;
	/* Cycle counter from host before issuing AQ command */
	cycles_t host_pre_cycles;
	/* Cycle counter from host after AQ command returns */
	cycles_t host_post_cycles;
};

/*
 * Read NIC clock by issuing the AQ command. The command is subject to
 * rate limiting and may need to be retried. Requires nic_ts_read_lock
 * to be held.
 */
static int gve_ptp_read_timestamp(struct gve_ptp *ptp, cycles_t *pre_cycles,
				  cycles_t *post_cycles)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(100);
	unsigned long delay_us = 1000;
	int err;

	lockdep_assert_held(&ptp->nic_ts_read_lock);

	do {
		*pre_cycles = get_cycles();
		err = gve_adminq_report_nic_ts(ptp->priv,
					       ptp->nic_ts_report_bus);

		/* Prevent get_cycles() from being speculatively executed
		 * before the AdminQ command
		 */
		rmb();
		*post_cycles = get_cycles();
		if (likely(err != -EAGAIN))
			return err;

		fsleep(delay_us);

		/* Exponential backoff */
		delay_us *= 2;
	} while (time_before(jiffies, deadline));

	return -ETIMEDOUT;
}

/* Read the nic timestamp from hardware via the admin queue. */
static int gve_clock_nic_ts_read(struct gve_ptp *ptp, u64 *nic_raw,
				 struct gve_sysclock_sample *sysclock)
{
	cycles_t host_pre_cycles, host_post_cycles;
	struct gve_nic_ts_report *ts_report;
	int err;

	mutex_lock(&ptp->nic_ts_read_lock);
	err = gve_ptp_read_timestamp(ptp, &host_pre_cycles, &host_post_cycles);
	if (err) {
		dev_err_ratelimited(&ptp->priv->pdev->dev,
				    "AdminQ timestamp read failed: %d\n", err);
		goto out;
	}

	ts_report = ptp->nic_ts_report;
	*nic_raw = be64_to_cpu(ts_report->nic_timestamp);

	if (sysclock) {
		sysclock->nic_pre_cycles = be64_to_cpu(ts_report->pre_cycles);
		sysclock->nic_post_cycles = be64_to_cpu(ts_report->post_cycles);
		sysclock->host_pre_cycles = host_pre_cycles;
		sysclock->host_post_cycles = host_post_cycles;
	}

out:
	mutex_unlock(&ptp->nic_ts_read_lock);
	return err;
}

struct gve_cycles_to_clock_callback_ctx {
	u64 cycles;
};

static int gve_cycles_to_clock_fn(ktime_t *device_time,
				  struct system_counterval_t *system_counterval,
				  void *ctx)
{
	struct gve_cycles_to_clock_callback_ctx *context = ctx;

	*device_time = 0;

	system_counterval->cycles = context->cycles;
	system_counterval->use_nsecs = false;

	if (IS_ENABLED(CONFIG_X86))
		system_counterval->cs_id = CSID_X86_TSC;
	else if (IS_ENABLED(CONFIG_ARM64))
		system_counterval->cs_id = CSID_ARM_ARCH_COUNTER;
	else
		return -EOPNOTSUPP;

	return 0;
}

/*
 * Convert a raw cycle count (e.g. from get_cycles()) to the system clock
 * type specified by clockid. The system_time_snapshot must be taken before
 * the cycle counter is sampled.
 */
static int gve_cycles_to_timespec64(struct gve_priv *priv, clockid_t clockid,
				    struct system_time_snapshot *snap,
				    u64 cycles, struct timespec64 *ts)
{
	struct gve_cycles_to_clock_callback_ctx ctx = {0};
	struct system_device_crosststamp xtstamp;
	int err;

	ctx.cycles = cycles;
	err = get_device_system_crosststamp(gve_cycles_to_clock_fn, &ctx, snap,
					    &xtstamp);
	if (err) {
		dev_err_ratelimited(&priv->pdev->dev,
				    "get_device_system_crosststamp() failed to convert %llu cycles to system time: %d\n",
				    cycles,
				    err);
		return err;
	}

	switch (clockid) {
	case CLOCK_REALTIME:
		*ts = ktime_to_timespec64(xtstamp.sys_realtime);
		break;
	case CLOCK_MONOTONIC_RAW:
		*ts = ktime_to_timespec64(xtstamp.sys_monoraw);
		break;
	default:
		dev_err_ratelimited(&priv->pdev->dev,
				    "Cycle count conversion to clockid %d not supported\n",
				    clockid);
		return -EOPNOTSUPP;
	}

	return 0;
}

static bool
gve_can_use_system_ts_from_device(enum clocksource_ids system_clock_source,
				  clockid_t clockid)
{
	if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC_RAW)
		return false;

	/* If the system clock source matches the system clock
	 * returned by the AdminQ command, we can use the system
	 * timestamps returned by the device, otherwise we have to
	 * fall back to sampling system time from the host which
	 * is less accurate.
	 */
	if (IS_ENABLED(CONFIG_X86))
		return system_clock_source == CSID_X86_TSC;
	else if (IS_ENABLED(CONFIG_ARM64))
		return system_clock_source == CSID_ARM_ARCH_COUNTER;

	return false;
}

static int gve_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	return -EOPNOTSUPP;
}

static int gve_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	return -EOPNOTSUPP;
}

static int gve_ptp_gettimex64(struct ptp_clock_info *info,
			      struct timespec64 *ts,
			      struct ptp_system_timestamp *sts)
{
	struct gve_ptp *ptp = container_of(info, struct gve_ptp, info);
	struct gve_sysclock_sample sysclock = {0};
	bool use_system_ts_from_device = false;
	struct gve_priv *priv = ptp->priv;
	struct system_time_snapshot snap;
	u64 nic_ts;
	int err;

	if (sts) {
		/* This snapshot is used both to query the current system
		 * clocksource and to convert the cycle counts returned
		 * by the AdminQ command to ktime. It does not need to be
		 * taken inside the retry loop because retries and lock
		 * contention are expected to be extremely rare.
		 *
		 * If the system clock source changes between here and
		 * when get_device_system_crosststamp() is called,
		 * get_device_system_crosststamp() will fail which will
		 * cause one failed sample, and the next one will succeed.
		 */
		ktime_get_snapshot(&snap);
		use_system_ts_from_device =
			gve_can_use_system_ts_from_device(snap.cs_id,
							  sts->clockid);
		if (use_system_ts_from_device)
			priv->ptp_precise_xtstamps++;
		else
			priv->ptp_fallback_xtstamps++;
	}

	if (unlikely(!use_system_ts_from_device))
		ptp_read_system_prets(sts);

	err = gve_clock_nic_ts_read(ptp, &nic_ts, sts ? &sysclock : NULL);
	if (err)
		return err;

	if (unlikely(!use_system_ts_from_device))
		ptp_read_system_postts(sts);

	if (sts && likely(use_system_ts_from_device)) {
		/* Reject samples with out of order system clock values.
		 * Firmware must return valid non-zero cycle counts.
		 */
		if (!(sysclock.host_pre_cycles <= sysclock.nic_pre_cycles &&
		      sysclock.nic_pre_cycles  <= sysclock.nic_post_cycles &&
		      sysclock.nic_post_cycles <= sysclock.host_post_cycles)) {
			dev_err_ratelimited(&priv->pdev->dev,
					    "AdminQ system clock cycle counts out of order. Expecting %llu <= %llu <= %llu <= %llu\n",
					    (u64)sysclock.host_pre_cycles,
					    sysclock.nic_pre_cycles,
					    sysclock.nic_post_cycles,
					    (u64)sysclock.host_post_cycles);
			return -EBADMSG;
		}

		err = gve_cycles_to_timespec64(priv, sts->clockid, &snap,
					       sysclock.nic_pre_cycles,
					       &sts->pre_ts);
		if (err)
			return err;

		err = gve_cycles_to_timespec64(priv, sts->clockid, &snap,
					       sysclock.nic_post_cycles,
					       &sts->post_ts);
		if (err)
			return err;
	}

	*ts = ns_to_timespec64(nic_ts);

	return 0;
}

static int gve_ptp_settime64(struct ptp_clock_info *info,
			     const struct timespec64 *ts)
{
	return -EOPNOTSUPP;
}

static long gve_ptp_do_aux_work(struct ptp_clock_info *info)
{
	struct gve_ptp *ptp = container_of(info, struct gve_ptp, info);
	struct gve_priv *priv = ptp->priv;
	u64 nic_raw;
	int err;

	if (gve_get_reset_in_progress(priv) || !gve_get_admin_queue_ok(priv))
		goto out;

	err = gve_clock_nic_ts_read(ptp, &nic_raw, NULL);
	if (err) {
		dev_err_ratelimited(&priv->pdev->dev, "%s read err %d\n",
				    __func__, err);
		goto out;
	}
	WRITE_ONCE(priv->last_sync_nic_counter, nic_raw);

out:
	return msecs_to_jiffies(GVE_NIC_TS_SYNC_INTERVAL_MS);
}

static const struct ptp_clock_info gve_ptp_caps = {
	.owner          = THIS_MODULE,
	.name		= "gve clock",
	.adjfine	= gve_ptp_adjfine,
	.adjtime	= gve_ptp_adjtime,
	.gettimex64	= gve_ptp_gettimex64,
	.settime64	= gve_ptp_settime64,
	.do_aux_work	= gve_ptp_do_aux_work,
};

int gve_init_clock(struct gve_priv *priv)
{
	struct gve_ptp *ptp;
	u64 nic_raw;
	int err;

	ptp = kzalloc_obj(*priv->ptp);
	if (!ptp)
		return -ENOMEM;

	ptp->info = gve_ptp_caps;
	ptp->priv = priv;
	mutex_init(&ptp->nic_ts_read_lock);
	ptp->nic_ts_report =
		dma_alloc_coherent(&priv->pdev->dev,
				   sizeof(struct gve_nic_ts_report),
				   &ptp->nic_ts_report_bus, GFP_KERNEL);
	if (!ptp->nic_ts_report) {
		dev_err(&priv->pdev->dev, "%s dma alloc error\n", __func__);
		err = -ENOMEM;
		goto free_ptp;
	}

	err = gve_clock_nic_ts_read(ptp, &nic_raw, NULL);
	if (err) {
		dev_err(&priv->pdev->dev, "failed to read NIC clock %d\n", err);
		goto free_dma_mem;
	}
	WRITE_ONCE(priv->last_sync_nic_counter, nic_raw);

	ptp->clock = ptp_clock_register(&ptp->info, &priv->pdev->dev);
	if (IS_ERR(ptp->clock)) {
		dev_err(&priv->pdev->dev, "PTP clock registration failed\n");
		err = PTR_ERR(ptp->clock);
		goto free_dma_mem;
	}

	priv->ptp = ptp;
	ptp_schedule_worker(ptp->clock,
			    msecs_to_jiffies(GVE_NIC_TS_SYNC_INTERVAL_MS));

	return 0;

free_dma_mem:
	dma_free_coherent(&priv->pdev->dev, sizeof(struct gve_nic_ts_report),
			  ptp->nic_ts_report, ptp->nic_ts_report_bus);
	ptp->nic_ts_report = NULL;
free_ptp:
	mutex_destroy(&ptp->nic_ts_read_lock);
	kfree(ptp);
	return err;
}

void gve_teardown_clock(struct gve_priv *priv)
{
	struct gve_ptp *ptp = priv->ptp;

	if (!ptp)
		return;

	priv->ptp = NULL;
	ptp_clock_unregister(ptp->clock);
	dma_free_coherent(&priv->pdev->dev, sizeof(struct gve_nic_ts_report),
			  ptp->nic_ts_report, ptp->nic_ts_report_bus);
	ptp->nic_ts_report = NULL;
	mutex_destroy(&ptp->nic_ts_read_lock);
	kfree(ptp);
}
