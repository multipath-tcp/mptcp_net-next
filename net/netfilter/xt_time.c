// SPDX-License-Identifier: GPL-2.0
/*
 *	xt_time
 *	Copyright © CC Computer Consultants GmbH, 2007
 *
 *	based on ipt_time by Fabrice MARIE <fabrice@netfilter.org>
 *	This is a module which is used for time matching
 *	It is using some modified code from dietlibc (localtime() function)
 *	that you can find at https://www.fefe.de/dietlibc/
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_time.h>

struct xtm {
	u_int8_t month;    /* (1-12) */
	u_int8_t monthday; /* (1-31) */
	u_int8_t weekday;  /* (1-7) */
	u_int8_t hour;     /* (0-23) */
	u_int8_t minute;   /* (0-59) */
	u_int8_t second;   /* (0-59) */
	unsigned int dse;
};

extern struct timezone sys_tz; /* ouch */

#define SECONDS_PER_DAY 86400

/*
 * Each network packet has a (nano)seconds-since-the-epoch (SSTE) timestamp.
 * Since we match against days and daytime, the SSTE value needs to be
 * computed back into human-readable dates.
 *
 * This is done in three separate functions so that the most expensive
 * calculations are done last, in case a "simple match" can be found earlier.
 */
static inline unsigned int localtime_1(struct xtm *r, time64_t time)
{
	unsigned int v, w;

	/* Each day has 86400s, so finding the hour/minute is actually easy. */
	div_u64_rem(time, SECONDS_PER_DAY, &v);
	r->second = v % 60;
	w         = v / 60;
	r->minute = w % 60;
	r->hour   = w / 60;
	return v;
}

static inline void localtime_2(struct xtm *r, time64_t time)
{
	/*
	 * Here comes the rest (weekday, monthday). First, divide the SSTE
	 * by seconds-per-day to get the number of _days_ since the epoch.
	 */
	r->dse = div_u64(time, SECONDS_PER_DAY);

	/*
	 * 1970-01-01 (w=0) was a Thursday (4).
	 * -1 and +1 map Sunday properly onto 7.
	 */
	r->weekday = (4 + r->dse - 1) % 7 + 1;
}

static void localtime_3(struct xtm *r, time64_t time)
{
	struct tm tm;

	time64_to_tm(time, 0, &tm);

	r->monthday = tm.tm_mday;	/* 1-31 */
	r->month    = tm.tm_mon + 1;	/* 1-12 */
}

static bool
time_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_time_info *info = par->matchinfo;
	unsigned int packet_time;
	struct xtm current_time;
	time64_t stamp;

	/*
	 * We need real time here, but we can neither use skb->tstamp
	 * nor __net_timestamp().
	 *
	 * skb->tstamp and skb->skb_mstamp_ns overlap, however, they
	 * use different clock types (real vs monotonic).
	 *
	 * Suppose you have two rules:
	 *	1. match before 13:00
	 *	2. match after 13:00
	 *
	 * If you match against processing time (ktime_get_real_seconds) it
	 * may happen that the same packet matches both rules if
	 * it arrived at the right moment before 13:00, so it would be
	 * better to check skb->tstamp and set it via __net_timestamp()
	 * if needed.  This however breaks outgoing packets tx timestamp,
	 * and causes them to get delayed forever by fq packet scheduler.
	 */
	stamp = ktime_get_real_seconds();

	if (info->flags & XT_TIME_LOCAL_TZ)
		/* Adjust for local timezone */
		stamp -= 60 * sys_tz.tz_minuteswest;

	/*
	 * xt_time will match when _all_ of the following hold:
	 *   - 'now' is in the global time range date_start..date_end
	 *   - 'now' is in the monthday mask
	 *   - 'now' is in the weekday mask
	 *   - 'now' is in the daytime range time_start..time_end
	 * (and by default, libxt_time will set these so as to match)
	 *
	 * note: info->date_start/stop are unsigned 32-bit values that
	 *	 can hold values beyond y2038, but not after y2106.
	 */

	if (stamp < info->date_start || stamp > info->date_stop)
		return false;

	packet_time = localtime_1(&current_time, stamp);

	if (info->daytime_start < info->daytime_stop) {
		if (packet_time < info->daytime_start ||
		    packet_time > info->daytime_stop)
			return false;
	} else {
		if (packet_time < info->daytime_start &&
		    packet_time > info->daytime_stop)
			return false;

		/** if user asked to ignore 'next day', then e.g.
		 *  '1 PM Wed, August 1st' should be treated
		 *  like 'Tue 1 PM July 31st'.
		 *
		 * This also causes
		 * 'Monday, "23:00 to 01:00", to match for 2 hours, starting
		 * Monday 23:00 to Tuesday 01:00.
		 */
		if ((info->flags & XT_TIME_CONTIGUOUS) &&
		     packet_time <= info->daytime_stop)
			stamp -= SECONDS_PER_DAY;
	}

	localtime_2(&current_time, stamp);

	if (!(info->weekdays_match & (1U << current_time.weekday)))
		return false;

	/* Do not spend time computing monthday if all days match anyway */
	if (info->monthdays_match != XT_TIME_ALL_MONTHDAYS) {
		localtime_3(&current_time, stamp);
		if (!(info->monthdays_match & (1U << current_time.monthday)))
			return false;
	}

	return true;
}

static int time_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_time_info *info = par->matchinfo;

	if (info->daytime_start > XT_TIME_MAX_DAYTIME ||
	    info->daytime_stop > XT_TIME_MAX_DAYTIME) {
		pr_info_ratelimited("invalid argument - start or stop time greater than 23:59:59\n");
		return -EDOM;
	}

	if (info->flags & ~XT_TIME_ALL_FLAGS) {
		pr_info_ratelimited("unknown flags 0x%x\n",
				    info->flags & ~XT_TIME_ALL_FLAGS);
		return -EINVAL;
	}

	if ((info->flags & XT_TIME_CONTIGUOUS) &&
	     info->daytime_start < info->daytime_stop)
		return -EINVAL;

	return 0;
}

static struct xt_match xt_time_mt_reg __read_mostly = {
	.name       = "time",
	.family     = NFPROTO_UNSPEC,
	.match      = time_mt,
	.checkentry = time_mt_check,
	.matchsize  = sizeof(struct xt_time_info),
	.me         = THIS_MODULE,
};

static int __init time_mt_init(void)
{
	int minutes = sys_tz.tz_minuteswest;

	if (minutes < 0) /* east of Greenwich */
		pr_info("kernel timezone is +%02d%02d\n",
			-minutes / 60, -minutes % 60);
	else /* west of Greenwich */
		pr_info("kernel timezone is -%02d%02d\n",
			minutes / 60, minutes % 60);

	return xt_register_match(&xt_time_mt_reg);
}

static void __exit time_mt_exit(void)
{
	xt_unregister_match(&xt_time_mt_reg);
}

module_init(time_mt_init);
module_exit(time_mt_exit);
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_DESCRIPTION("Xtables: time-based matching");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_time");
MODULE_ALIAS("ip6t_time");
