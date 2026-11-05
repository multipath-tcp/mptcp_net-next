// SPDX-License-Identifier: GPL-2.0+
/* Microchip Sparx5 Switch driver
 *
 * Copyright (c) 2023 Microchip Technology Inc. and its subsidiaries.
 */

#include <linux/iopoll.h>

#include "sparx5_main_regs.h"
#include "sparx5_main.h"

#define SPX5_PORT_POLICER_FILTER_COUNTER 1
#define SPX5_PORT_POLICER_PASS_COUNTER 2

/* The port policer statistics counters are 40 bits wide (32-bit LSB + 8-bit
 * MSB register pair).
 */
#define SPX5_PORT_STAT_CNT_MASK GENMASK_ULL(39, 0)

#define SPX5_PORT_POLICER_0_FILTER_EVENT BIT(4)
#define SPX5_PORT_POLICER_1_FILTER_EVENT BIT(5)
#define SPX5_PORT_POLICER_2_FILTER_EVENT BIT(6)
#define SPX5_PORT_POLICER_3_FILTER_EVENT BIT(7)
#define SPX5_PORT_POLICER_0_PASS_EVENT BIT(8)
#define SPX5_PORT_POLICER_1_PASS_EVENT BIT(9)
#define SPX5_PORT_POLICER_2_PASS_EVENT BIT(10)
#define SPX5_PORT_POLICER_3_PASS_EVENT BIT(11)

/* Do not add preamble and inter-frame gap to the metered frame size, so that
 * the rate is a data rate, as tc police expects.
 */
#define SPX5_POLICER_DATA_RATE_GAP 0

/* Bit rate unit for the port policer (bits/sec) */
#define SPX5_POLICER_RATE_UNIT 25040
/* Burst size unit for the port policer (bytes) */
#define SPX5_POLICER_BYTE_BURST_UNIT 8192

enum sparx5_port_policer_stat_event_mask {
	SPX5_PPEM_NONE,
	SPX5_PPEM_EVENT_NO_ERROR,
	SPX5_PPEM_EVENT_AND_ERROR,
	SPX5_PPEM_EVENT,
	SPX5_PPEM_ERROR_NO_EVENT,
	SPX5_PPEM_ERROR,
};

static int sparx5_policer_service_conf_set(struct sparx5 *sparx5,
					   struct sparx5_policer *pol)
{
	u32 idx, pup_tokens, max_pup_tokens, burst, thres;
	const struct sparx5_ops *ops = sparx5->data->ops;
	struct sparx5_sdlb_group *g;
	u64 rate;

	g = ops->get_sdlb_group(pol->group);
	idx = pol->idx;

	rate = pol->rate * 1000;
	burst = pol->burst;

	pup_tokens = sparx5_sdlb_pup_token_get(sparx5, g->pup_interval, rate);
	max_pup_tokens =
		sparx5_sdlb_pup_token_get(sparx5, g->pup_interval, g->max_rate);

	thres = DIV_ROUND_UP(burst, g->min_burst);

	spx5_wr(ANA_AC_SDLB_PUP_TOKENS_PUP_TOKENS_SET(pup_tokens), sparx5,
		ANA_AC_SDLB_PUP_TOKENS(idx, 0));

	spx5_rmw(ANA_AC_SDLB_INH_CTRL_PUP_TOKENS_MAX_SET(max_pup_tokens),
		 ANA_AC_SDLB_INH_CTRL_PUP_TOKENS_MAX, sparx5,
		 ANA_AC_SDLB_INH_CTRL(idx, 0));

	spx5_rmw(ANA_AC_SDLB_THRES_THRES_SET(thres), ANA_AC_SDLB_THRES_THRES,
		 sparx5, ANA_AC_SDLB_THRES(idx, 0));

	return 0;
}

static int sparx5_port_policer_conf_set(struct sparx5 *sparx5,
					struct sparx5_policer *pol)
{
	u32 portno = pol->idx / SPX5_POLICERS_PER_PORT;
	u32 polidx = pol->idx % SPX5_POLICERS_PER_PORT;
	u32 rate, burst, mask, cfg;
	int cnt;

	rate = DIV_ROUND_UP_ULL(pol->rate, SPX5_POLICER_RATE_UNIT);
	burst = DIV_ROUND_UP(pol->burst, SPX5_POLICER_BYTE_BURST_UNIT);

	/* Disable the policer when rate and burst are both zero, otherwise
	 * police known and unknown unicast, multicast and broadcast frames.
	 */
	mask = (rate == 0 && burst == 0) ? 0 : 0x7f;
	if (mask) {
		/* Program the bucket before enabling the policer */
		spx5_wr(rate, sparx5, ANA_AC_POL_PORT_RATE_CFG(pol->idx));
		spx5_wr(burst, sparx5, ANA_AC_POL_PORT_THRES_CFG_0(pol->idx));
		spx5_rmw(ANA_AC_POL_PORT_CFG_TRAFFIC_TYPE_MASK_SET(mask),
			 ANA_AC_POL_PORT_CFG_TRAFFIC_TYPE_MASK,
			 sparx5, ANA_AC_POL_PORT_CFG(portno, polidx));
	} else {
		/* Disable the policer before zeroing the bucket */
		spx5_rmw(ANA_AC_POL_PORT_CFG_TRAFFIC_TYPE_MASK_SET(0),
			 ANA_AC_POL_PORT_CFG_TRAFFIC_TYPE_MASK,
			 sparx5, ANA_AC_POL_PORT_CFG(portno, polidx));
		spx5_wr(rate, sparx5, ANA_AC_POL_PORT_RATE_CFG(pol->idx));
		spx5_wr(burst, sparx5, ANA_AC_POL_PORT_THRES_CFG_0(pol->idx));
	}

	/* Count policer events, not bytes, for all eight priorities on the
	 * port's filter and pass counters, which are shared by all of the
	 * port's policer instances.
	 */
	cfg = ANA_AC_PORT_STAT_CFG_CFG_PRIO_MASK_SET(0xff) |
	      ANA_AC_PORT_STAT_CFG_CFG_CNT_FRM_TYPE_SET(SPX5_PPEM_EVENT) |
	      ANA_AC_PORT_STAT_CFG_CFG_CNT_BYTE_SET(0);

	for (cnt = SPX5_PORT_POLICER_FILTER_COUNTER;
	     cnt <= SPX5_PORT_POLICER_PASS_COUNTER; cnt++)
		spx5_rmw(cfg,
			 ANA_AC_PORT_STAT_CFG_CFG_PRIO_MASK |
			 ANA_AC_PORT_STAT_CFG_CFG_CNT_FRM_TYPE |
			 ANA_AC_PORT_STAT_CFG_CFG_CNT_BYTE,
			 sparx5, ANA_AC_PORT_STAT_CFG(portno, cnt));

	spx5_rmw(ANA_AC_POL_PORT_GAP_GAP_VALUE_SET(SPX5_POLICER_DATA_RATE_GAP),
		 ANA_AC_POL_PORT_GAP_GAP_VALUE,
		 sparx5, ANA_AC_POL_PORT_GAP(portno));

	return 0;
}

int sparx5_policer_conf_set(struct sparx5 *sparx5, struct sparx5_policer *pol)
{
	switch (pol->type) {
	case SPX5_POL_PORT:
		return sparx5_port_policer_conf_set(sparx5, pol);
	case SPX5_POL_SERVICE:
		return sparx5_policer_service_conf_set(sparx5, pol);
	default:
		break;
	}

	return 0;
}

static u64 sparx5_port_policer_cnt_get(struct sparx5_port *port, u32 cnt)
{
	struct sparx5 *sparx5 = port->sparx5;
	u32 lsb, msb;

	/* The MSB is latched when the LSB is read, so read the LSB first */
	lsb = spx5_rd(sparx5, ANA_AC_PORT_STAT_LSB_CNT(port->portno, cnt));
	msb = spx5_rd(sparx5, ANA_AC_PORT_STAT_MSB_CNT(port->portno, cnt));

	return (u64)msb << 32 | lsb;
}

static void sparx5_port_policer_cnt_accum(struct sparx5_port *port, u32 cnt,
					  u64 *raw, u64 *total)
{
	u64 cur = sparx5_port_policer_cnt_get(port, cnt);

	*total += (cur - *raw) & SPX5_PORT_STAT_CNT_MASK;
	*raw = cur;
}

static void sparx5_port_policer_stats_update(struct sparx5_port *port,
					     int polidx)
{
	struct sparx5_port_policer *pp = &port->tc.port_policer[polidx];

	lockdep_assert_held(&port->sparx5->queue_stats_lock);

	sparx5_port_policer_cnt_accum(port, SPX5_PORT_POLICER_FILTER_COUNTER,
				      &pp->raw.drops, &pp->stats.drops);
	sparx5_port_policer_cnt_accum(port, SPX5_PORT_POLICER_PASS_COUNTER,
				      &pp->raw.pkts, &pp->stats.pkts);
}

static void sparx5_policer_stats_update(struct sparx5 *sparx5,
					struct sparx5_policer *pol)
{
	u32 portno, polidx;

	switch (pol->type) {
	case SPX5_POL_PORT:
		portno = pol->idx / SPX5_POLICERS_PER_PORT;
		polidx = pol->idx % SPX5_POLICERS_PER_PORT;

		sparx5_port_policer_stats_update(sparx5->ports[portno], polidx);
		break;
	default:
		break;
	}
}

static int sparx5_get_port_policer_idx(struct sparx5_port *port,
				       unsigned long cookie)
{
	if (port->tc.port_policer[0].policer == cookie)
		return 0;

	return -ENOENT;
}

static int sparx5_alloc_port_policer_idx(struct sparx5_port *port,
					 unsigned long cookie)
{
	/* Only one port policer per port is supported: the port's filter
	 * and pass statistics counters are shared by all four hardware
	 * policer instances, so stats can only be attributed correctly to
	 * a single active policer.
	 */
	if (!port->tc.port_policer[0].policer ||
	    port->tc.port_policer[0].policer == cookie)
		return 0;

	return -EEXIST;
}

static void sparx5_get_port_policer_stats(struct sparx5_port *port,
					  int polidx)
{
	struct sparx5_policer pol = { 0 };

	pol.type = SPX5_POL_PORT;
	pol.idx = port->portno * SPX5_POLICERS_PER_PORT + polidx;

	sparx5_policer_stats_update(port->sparx5, &pol);
}

static void sparx5_init_port_policer_stats(struct sparx5_port *port,
					   int polidx)
{
	struct sparx5_port_policer *pp = &port->tc.port_policer[polidx];

	mutex_lock(&port->sparx5->queue_stats_lock);

	pp->raw.drops = sparx5_port_policer_cnt_get(port,
						    SPX5_PORT_POLICER_FILTER_COUNTER);
	pp->raw.pkts = sparx5_port_policer_cnt_get(port,
						   SPX5_PORT_POLICER_PASS_COUNTER);

	memset(&pp->stats, 0, sizeof(pp->stats));
	memset(&pp->prev, 0, sizeof(pp->prev));

	mutex_unlock(&port->sparx5->queue_stats_lock);
}

/* Called once a second from the stats worker, so that a wrap of the 40-bit
 * counters is never missed. Only one port policer per port is used.
 */
void sparx5_port_policer_stats_poll(struct sparx5_port *port)
{
	mutex_lock(&port->sparx5->queue_stats_lock);
	sparx5_get_port_policer_stats(port, 0);
	mutex_unlock(&port->sparx5->queue_stats_lock);
}

int sparx5_update_port_policer_stats(struct net_device *ndev,
				     struct tc_cls_matchall_offload *tmo)
{
	struct sparx5_port *port = netdev_priv(ndev);
	struct flow_stats *prev_stats;
	struct flow_stats *stats;
	u64 pkts, drops;
	int polidx;

	polidx = sparx5_get_port_policer_idx(port, tmo->cookie);
	if (polidx < 0)
		return polidx;

	stats = &port->tc.port_policer[polidx].stats;
	prev_stats = &port->tc.port_policer[polidx].prev;

	mutex_lock(&port->sparx5->queue_stats_lock);

	sparx5_get_port_policer_stats(port, polidx);

	pkts = stats->pkts - prev_stats->pkts;
	drops = stats->drops - prev_stats->drops;

	prev_stats->pkts = stats->pkts;
	prev_stats->drops = stats->drops;

	mutex_unlock(&port->sparx5->queue_stats_lock);

	if (!pkts && !drops)
		return 0;

	flow_stats_update(&tmo->stats,
			  0,
			  pkts + drops,
			  drops,
			  jiffies,
			  FLOW_ACTION_HW_STATS_IMMEDIATE);

	return 0;
}

int sparx5_add_port_policer(struct sparx5_mall_entry *entry,
			    struct netlink_ext_ack *extack)
{
	struct flow_action_police *police = &entry->port_policer.police;
	struct sparx5_port *port = entry->port;
	struct sparx5 *sparx5 = port->sparx5;
	struct sparx5_policer pol = { 0 };
	int idx, err;

	if (!entry->ingress) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer is not supported on egress");
		return -EOPNOTSUPP;
	}

	if (entry->port->tc.ingress_block_shared) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer is not supported on shared ingress blocks");
		return -EOPNOTSUPP;
	}

	if (police->exceed.act_id != FLOW_ACTION_DROP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer parameters are not supported");
		return -EOPNOTSUPP;
	}

	if (police->notexceed.act_id != FLOW_ACTION_PIPE &&
	    police->notexceed.act_id != FLOW_ACTION_ACCEPT) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer parameters are not supported");
		return -EOPNOTSUPP;
	}

	if (police->peakrate_bytes_ps || police->avrate ||
	    police->overhead) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer parameters are not supported");
		return -EOPNOTSUPP;
	}

	if (police->rate_pkt_ps) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer parameters are not supported");
		return -EOPNOTSUPP;
	}

	if (!police->rate_bytes_ps) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer requires a rate");
		return -EOPNOTSUPP;
	}

	if (police->burst > ANA_AC_POL_PORT_THRES_CFG_0_PORT_THRES0 *
			    SPX5_POLICER_BYTE_BURST_UNIT) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer parameters are not supported");
		return -EOPNOTSUPP;
	}

	if (police->rate_bytes_ps >
	    div_u64((u64)ANA_AC_POL_PORT_RATE_CFG_PORT_RATE *
		    SPX5_POLICER_RATE_UNIT, BITS_PER_BYTE)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Policer parameters are not supported");
		return -EOPNOTSUPP;
	}

	idx = sparx5_alloc_port_policer_idx(port, entry->cookie);
	if (idx < 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Only one port policer per port is supported");
		return idx;
	}

	pol.type = SPX5_POL_PORT;
	pol.rate = police->rate_bytes_ps * BITS_PER_BYTE;
	pol.burst = police->burst;
	pol.idx = port->portno * SPX5_POLICERS_PER_PORT + idx;

	sparx5_init_port_policer_stats(port, idx);

	err = sparx5_policer_conf_set(sparx5, &pol);
	if (err)
		return err;

	port->tc.port_policer[idx].policer = entry->cookie;

	return 0;
}

int sparx5_delete_port_policer(struct sparx5_mall_entry *entry)
{
	struct sparx5_port *port = entry->port;
	struct sparx5 *sparx5 = port->sparx5;
	struct sparx5_policer pol = { 0 };
	int idx, err;

	if (!entry->ingress)
		return -EINVAL;

	idx = sparx5_get_port_policer_idx(port, entry->cookie);
	if (idx < 0)
		return idx;

	pol.type = SPX5_POL_PORT;
	pol.idx = port->portno * SPX5_POLICERS_PER_PORT + idx;

	err = sparx5_policer_conf_set(sparx5, &pol);
	if (err)
		return err;

	port->tc.port_policer[idx].policer = 0;

	return 0;
}

int sparx5_port_policer_init(struct sparx5 *sparx5)
{
	u32 value;
	int err;

	/* Initialize all port policers before usage */
	spx5_rmw(ANA_AC_POL_ALL_CFG_ACL_FORCE_INIT_SET(1) |
		 ANA_AC_POL_ALL_CFG_FORCE_INIT_SET(1),
		 ANA_AC_POL_ALL_CFG_ACL_FORCE_INIT |
		 ANA_AC_POL_ALL_CFG_FORCE_INIT,
		 sparx5, ANA_AC_POL_ALL_CFG);

	err = read_poll_timeout(spx5_rd, value,
				!(ANA_AC_POL_ALL_CFG_ACL_FORCE_INIT_GET(value) |
				  ANA_AC_POL_ALL_CFG_FORCE_INIT_GET(value)),
				500, 10000, false, sparx5, ANA_AC_POL_ALL_CFG);
	if (err)
		return err;

	/* Configure the port policer filter and pass statistics counters.
	 * Counter 0 is owned by sparx5_ethtool.c (SPX5_PORT_POLICER_DROPS).
	 */
	spx5_wr(SPX5_PORT_POLICER_0_FILTER_EVENT |
		SPX5_PORT_POLICER_1_FILTER_EVENT |
		SPX5_PORT_POLICER_2_FILTER_EVENT |
		SPX5_PORT_POLICER_3_FILTER_EVENT,
		sparx5, ANA_AC_PORT_SGE_CFG(SPX5_PORT_POLICER_FILTER_COUNTER));

	spx5_wr(SPX5_PORT_POLICER_0_PASS_EVENT |
		SPX5_PORT_POLICER_1_PASS_EVENT |
		SPX5_PORT_POLICER_2_PASS_EVENT |
		SPX5_PORT_POLICER_3_PASS_EVENT,
		sparx5, ANA_AC_PORT_SGE_CFG(SPX5_PORT_POLICER_PASS_COUNTER));

	return 0;
}
