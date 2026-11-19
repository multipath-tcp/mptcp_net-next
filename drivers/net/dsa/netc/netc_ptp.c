// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * NXP NETC switch driver
 * Copyright 2025-2026 NXP
 */

#include <linux/ptp_classify.h>
#include <linux/ptp_clock_kernel.h>

#include "netc_switch.h"

#define NETC_NUM_TS_REQ_ID		16
#define NETC_TSTAMP_TIMEOUT		(5 * HZ)
#define NETC_MAX_STEP_OFFSET		0x1ff
#define NETC_ONESTEP_QTH		512
/* The 30-bit timestamp of the To_Port subtype 3 tag lets the hardware
 * account for a single wrap, so the correction field of a one-step Sync
 * frame is only correct if it is sent out within 2^30 ns after the
 * software timestamp is read. Past this window, the in-flight frame is
 * already invalid, whether it has been dropped or not, so PM_SINGLE_STEP
 * can be reprogrammed for the next frame.
 */
#define NETC_ONESTEP_VALID_WINDOW	0x40000000 /* ns */

static void netc_port_tstamp_timeout_work(struct work_struct *work)
{
	struct netc_port *np = container_of(work, struct netc_port,
					    tstamp_timeout_work.work);
	struct sk_buff_head free_list;
	struct sk_buff *skb, *skb_tmp;
	bool resume_onestep = false;

	__skb_queue_head_init(&free_list);

	spin_lock_bh(&np->onestep_lock);
	spin_lock_bh(&np->tstamp_lock);
	skb_queue_walk_safe(&np->tstamp_queue, skb, skb_tmp) {
		if (time_is_after_jiffies64(NETC_SKB_CB(skb)->ptp_tx_time +
					    NETC_TSTAMP_TIMEOUT))
			continue;

		dev_dbg_ratelimited(np->switch_priv->dev,
				    "Port %d ts_req_id %u which seems lost\n",
				    np->dp->index, NETC_SKB_CB(skb)->ts_req_id);

		/* If the timed-out skb is the one holding the in-flight
		 * one-step frame's ts_req_id, resume the drain. Otherwise
		 * the frames queued on onestep_queue would never be sent or
		 * freed unless new traffic happened to arrive.
		 */
		if (NETC_SKB_CB(skb)->ptp_flag == NETC_PTP_FLAG_ONESTEP &&
		    NETC_SKB_CB(skb)->ts_req_id == np->onestep_ts_req_id &&
		    np->onestep_state == NETC_ONESTEP_IN_FLIGHT)
			resume_onestep = true;

		__skb_unlink(skb, &np->tstamp_queue);
		__skb_queue_tail(&free_list, skb);
	}

	/* Reschedule if there are still pending clones that have not
	 * timed out yet.
	 */
	if (!skb_queue_empty(&np->tstamp_queue))
		schedule_delayed_work(&np->tstamp_timeout_work,
				      NETC_TSTAMP_TIMEOUT);

	spin_unlock_bh(&np->tstamp_lock);

	if (resume_onestep) {
		np->onestep_state = NETC_ONESTEP_SCHEDULED;
		schedule_work(&np->onestep_work);
	}

	spin_unlock_bh(&np->onestep_lock);
	__skb_queue_purge(&free_list);
}

static int netc_get_ts_req_id(struct netc_port *np)
{
	DECLARE_BITMAP(ts_req_id_bitmap, NETC_NUM_TS_REQ_ID);
	struct sk_buff *skb, *skb_tmp;
	unsigned long ts_req_id;

	bitmap_zero(ts_req_id_bitmap, NETC_NUM_TS_REQ_ID);

	skb_queue_walk_safe(&np->tstamp_queue, skb, skb_tmp)
		__set_bit(NETC_SKB_CB(skb)->ts_req_id, ts_req_id_bitmap);

	ts_req_id = find_first_zero_bit(ts_req_id_bitmap, NETC_NUM_TS_REQ_ID);
	if (ts_req_id == NETC_NUM_TS_REQ_ID) {
		dev_dbg_ratelimited(np->switch_priv->dev,
				    "Port %d has no available ts_req_id\n",
				    np->dp->index);
		return -ENOSPC;
	}

	return ts_req_id;
}

static int netc_get_phc_time(struct netc_switch *priv, u64 *ns)
{
	if (unlikely(!priv->tmr_dev))
		return -ENODEV;

	return netc_timer_get_current_time(priv->tmr_dev, ns);
}

static void netc_port_set_onestep_control(struct netc_port *np,
					  bool csum_update, int offset)
{
	u32 val;

	val = PM_SINGLE_STEP_EN | FIELD_PREP(PM_SINGLE_STEP_OFFSET, offset);
	if (csum_update)
		val |= PM_SINGLE_STEP_CH;
	netc_mac_port_wr(np, NETC_PM_SINGLE_STEP(0), val);
}

static void netc_port_program_onestep(struct netc_port *np,
				      struct sk_buff *skb)
{
	u16 correction_offset = NETC_SKB_CB(skb)->correction_offset;
	u16 tstamp_offset = NETC_SKB_CB(skb)->timestamp_offset;
	u64 tstamp = NETC_SKB_CB(skb)->tstamp;
	u8 *hdr = skb_mac_header(skb);
	bool csum_update = false;
	__be32 new_sec_l, new_ns;
	__be16 new_sec_h;
	u64 sec;
	u32 ns;

	/* Update originTimestamp field of Sync packet
	 * - 48 bits seconds field
	 * - 32 bits nanoseconds field
	 */
	sec = div_u64_rem(tstamp, NSEC_PER_SEC, &ns);
	new_sec_h = htons((sec >> 32) & 0xffff);
	new_sec_l = htonl(sec & 0xffffffff);
	new_ns = htonl(ns);

	if (NETC_SKB_CB(skb)->is_udp) {
		__be32 old_sec_l, old_ns;
		struct udphdr *uh;
		__be16 old_sec_h;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			csum_update = true;
			goto update_timestamp;
		}

		uh = (struct udphdr *)(hdr + tstamp_offset - UDP_HLEN -
				       sizeof(struct ptp_header));

		/* For IPv4, a UDP checksum of zero on the wire means "no
		 * checksum". For IPv6, its UDP checksum is mandatory and
		 * never zero.
		 */
		if (!uh->check)
			goto update_timestamp;

		old_sec_h = __get_unaligned_t(__be16, hdr + tstamp_offset);
		old_sec_l = __get_unaligned_t(__be32, hdr + tstamp_offset + 2);
		old_ns = __get_unaligned_t(__be32, hdr + tstamp_offset + 6);
		inet_proto_csum_replace2(&uh->check, skb, old_sec_h,
					 new_sec_h, false);
		inet_proto_csum_replace4(&uh->check, skb, old_sec_l,
					 new_sec_l, false);
		inet_proto_csum_replace4(&uh->check, skb, old_ns,
					 new_ns, false);
		csum_update = true;
	}

update_timestamp:
	__put_unaligned_t(__be16, new_sec_h, hdr + tstamp_offset);
	__put_unaligned_t(__be32, new_sec_l, hdr + tstamp_offset + 2);
	__put_unaligned_t(__be32, new_ns, hdr + tstamp_offset + 6);

	netc_port_set_onestep_control(np, csum_update, correction_offset);
}

static void netc_tx_dropped_add(struct net_device *ndev, u32 cnt)
{
	for (u32 i = 0; i < cnt; i++)
		dev_core_stats_tx_dropped_inc(ndev);
}

void netc_port_disable_onestep(struct netc_port *np)
{
	struct sk_buff_head free_list;

	if (!dsa_port_is_user(np->dp))
		return;

	__skb_queue_head_init(&free_list);

	spin_lock_bh(&np->onestep_lock);
	skb_queue_splice_init(&np->onestep_queue, &free_list);
	np->onestep_state = NETC_ONESTEP_PORT_INACTIVE;
	spin_unlock_bh(&np->onestep_lock);

	cancel_work_sync(&np->onestep_work);
	netc_tx_dropped_add(np->dp->user, skb_queue_len(&free_list));
	__skb_queue_purge(&free_list);
}

void netc_port_enable_onestep(struct netc_port *np)
{
	if (!dsa_port_is_user(np->dp))
		return;

	spin_lock_bh(&np->onestep_lock);
	np->onestep_state = NETC_ONESTEP_IDLE;
	spin_unlock_bh(&np->onestep_lock);
}

static void netc_port_purge_onestep_queue(struct netc_port *np)
{
	struct sk_buff_head free_list;

	__skb_queue_head_init(&free_list);

	spin_lock_bh(&np->onestep_lock);
	skb_queue_splice_init(&np->onestep_queue, &free_list);
	spin_unlock_bh(&np->onestep_lock);

	netc_tx_dropped_add(np->dp->user, skb_queue_len(&free_list));
	__skb_queue_purge(&free_list);
}

static void netc_port_onestep_work(struct work_struct *work)
{
	struct netc_port *np = container_of(work, struct netc_port,
					    onestep_work);
	struct netc_switch *priv = np->switch_priv;
	struct net_device *ndev = np->dp->user;
	struct netc_tagger_data *tagger_data;
	struct sk_buff *dummy_skb = NULL;
	struct sk_buff *skb = NULL;
	int ts_req_id;
	u32 qlen = 0;
	u64 tstamp;

	spin_lock_bh(&np->onestep_lock);

	if (unlikely(np->onestep_state == NETC_ONESTEP_PORT_INACTIVE))
		goto purge_onestep_queue;

skb_dequeue:
	skb = __skb_dequeue(&np->onestep_queue);
	if (!skb)
		goto set_onestep_state_idle;

	/* dummy_skb is a ts_req_id token only, it doesn't need any payload */
	dummy_skb = alloc_skb(0, GFP_ATOMIC);
	if (unlikely(!dummy_skb)) {
		kfree_skb(skb);
		dev_core_stats_tx_dropped_inc(ndev);
		goto skb_dequeue;
	}

	spin_lock_bh(&np->tstamp_lock);
	ts_req_id = netc_get_ts_req_id(np);
	if (unlikely(ts_req_id < 0)) {
		spin_unlock_bh(&np->tstamp_lock);

		/* The ts_req_id pool may stay exhausted, so re-queuing and
		 * rescheduling could spin the work forever. Drop this frame
		 * and move on, even if that ends up draining the whole queue.
		 * This only occurs in the extreme case, once the ts_req_id
		 * pool recovers, later frames are handled normally and PTP
		 * re-converges.
		 */
		np->onestep_state = NETC_ONESTEP_SCHEDULED;
		dev_core_stats_tx_dropped_inc(ndev);
		schedule_work(&np->onestep_work);

		goto onestep_unlock;
	}

	/* PHC is unavailable, drop the whole queue */
	if (unlikely(netc_get_phc_time(priv, &tstamp))) {
		spin_unlock_bh(&np->tstamp_lock);
		dev_core_stats_tx_dropped_inc(ndev);
		goto set_onestep_state_idle;
	}

	NETC_SKB_CB(skb)->tstamp = tstamp;
	NETC_SKB_CB(skb)->ts_req_id = ts_req_id;
	NETC_SKB_CB(skb)->ptp_flag = NETC_PTP_FLAG_ONESTEP;
	NETC_SKB_CB(dummy_skb)->ts_req_id = ts_req_id;
	NETC_SKB_CB(dummy_skb)->ptp_tx_time = get_jiffies_64();
	NETC_SKB_CB(dummy_skb)->ptp_flag = NETC_PTP_FLAG_ONESTEP;
	np->onestep_tx_time = NETC_SKB_CB(dummy_skb)->ptp_tx_time;
	np->onestep_ts_req_id = ts_req_id;

	__skb_queue_tail(&np->tstamp_queue, dummy_skb);
	if (!delayed_work_pending(&np->tstamp_timeout_work))
		schedule_delayed_work(&np->tstamp_timeout_work,
				      NETC_TSTAMP_TIMEOUT);

	spin_unlock_bh(&np->tstamp_lock);

	np->onestep_state = NETC_ONESTEP_IN_FLIGHT;
	spin_unlock_bh(&np->onestep_lock);

	netc_port_program_onestep(np, skb);
	tagger_data = priv->ds->tagger_data;
	tagger_data->onestep_sync_xmit(skb, ndev);

	return;

set_onestep_state_idle:
	np->onestep_state = NETC_ONESTEP_IDLE;
purge_onestep_queue:
	qlen = skb_queue_len(&np->onestep_queue);
	__skb_queue_purge(&np->onestep_queue);
onestep_unlock:
	spin_unlock_bh(&np->onestep_lock);
	netc_tx_dropped_add(ndev, qlen);
	kfree_skb(skb);
	kfree_skb(dummy_skb);
}

static bool netc_onestep_timeout(struct netc_port *np)
{
	u64 expire_time;

	/* Use monotonic jiffies_64, as the PHC may be stepped backwards */
	expire_time = np->onestep_tx_time + 1 +
		      nsecs_to_jiffies64(NETC_ONESTEP_VALID_WINDOW);
	if (np->onestep_state == NETC_ONESTEP_IN_FLIGHT &&
	    time_is_before_jiffies64(expire_time))
		return true;

	return false;
}

void netc_port_onestep_sync_enqueue(struct dsa_switch *ds, int port,
				    struct sk_buff *skb)
{
	struct netc_port *np = NETC_PORT(ds, port);

	spin_lock_bh(&np->onestep_lock);
	if (unlikely(np->onestep_state == NETC_ONESTEP_PORT_INACTIVE))
		goto free_skb;

	if (unlikely(skb_queue_len(&np->onestep_queue) >= NETC_ONESTEP_QTH))
		goto free_skb;

	__skb_queue_tail(&np->onestep_queue, skb);
	if (likely(np->onestep_state == NETC_ONESTEP_IDLE) ||
	    netc_onestep_timeout(np)) {
		np->onestep_state = NETC_ONESTEP_SCHEDULED;
		schedule_work(&np->onestep_work);
	}

	spin_unlock_bh(&np->onestep_lock);

	return;

free_skb:
	kfree_skb(skb);
	dev_core_stats_tx_dropped_inc(np->dp->user);
	spin_unlock_bh(&np->onestep_lock);
}

void netc_port_ptp_init(struct netc_port *np)
{
	spin_lock_init(&np->onestep_lock);
	__skb_queue_head_init(&np->onestep_queue);
	INIT_WORK(&np->onestep_work, netc_port_onestep_work);

	np->onestep_state = NETC_ONESTEP_PORT_INACTIVE;
	spin_lock_init(&np->tstamp_lock);
	__skb_queue_head_init(&np->tstamp_queue);
	INIT_DELAYED_WORK(&np->tstamp_timeout_work,
			  netc_port_tstamp_timeout_work);
}

void netc_port_purge_tstamp_queue(struct netc_port *np)
{
	struct sk_buff_head free_list;

	__skb_queue_head_init(&free_list);

	spin_lock_bh(&np->tstamp_lock);
	skb_queue_splice_init(&np->tstamp_queue, &free_list);
	spin_unlock_bh(&np->tstamp_lock);

	__skb_queue_purge(&free_list);
}

static int netc_get_phc_index(struct netc_switch *priv)
{
	if (!priv->tmr_dev)
		return -1;

	return ptp_clock_index_by_dev(&priv->tmr_dev->dev);
}

int netc_get_ts_info(struct dsa_switch *ds, int port,
		     struct kernel_ethtool_ts_info *info)
{
	struct netc_switch *priv = ds->priv;

	info->so_timestamping |= SOF_TIMESTAMPING_TX_SOFTWARE;
	info->phc_index = netc_get_phc_index(priv);
	if (info->phc_index < 0)
		return 0;

	info->so_timestamping |= SOF_TIMESTAMPING_TX_HARDWARE |
				 SOF_TIMESTAMPING_RX_HARDWARE |
				 SOF_TIMESTAMPING_RAW_HARDWARE;

	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON) |
			 BIT(HWTSTAMP_TX_ONESTEP_SYNC);

	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT);

	return 0;
}

static int netc_port_del_ptp_filter(struct netc_port *np)
{
	struct netc_switch *priv = np->switch_priv;
	int ret = 0;
	int err;

	for (int i = 0; i < NETC_PTP_MAX; i++) {
		if (np->ptp_ipft_eid[i] == NTMP_NULL_ENTRY_ID)
			continue;

		/* No -ETIMEDOUT here: with the command BD ring enabled, the
		 * hardware execution time for a command is much less than
		 * 1ms, so no timeout error will occur. Any remaining error
		 * means the entry is still present in the table.
		 */
		err = ntmp_ipft_delete_entry(&priv->ntmp,
					     np->ptp_ipft_eid[i]);
		if (likely(!err)) {
			np->ptp_ipft_eid[i] = NTMP_NULL_ENTRY_ID;
			continue;
		}

		ret = err;
		dev_err(priv->dev,
			"Delete PTP entry 0x%x (type %d) on port %d failed\n",
			np->ptp_ipft_eid[i], i, np->dp->index);
	}

	return ret;
}

static int netc_build_ptp_ipft_keye(struct ipft_keye_data *keye, int port,
				    enum netc_ptp_type type)
{
	u16 src_port, frm_attr_flags;

	keye->precedence = cpu_to_le16(NETC_IPFT_PTP_PRECEDENCE);
	src_port = FIELD_PREP(IPFT_SRC_PORT, port);
	src_port |= IPFT_SRC_PORT_MASK;
	keye->src_port = cpu_to_le16(src_port);

	switch (type) {
	case NETC_PTP_L2:
		keye->ethertype = htons(ETH_P_1588);
		keye->ethertype_mask = htons(0xffff);
		break;
	case NETC_PTP_L4_IPV4_EVENT:
	case NETC_PTP_L4_IPV4_GENERAL:
	case NETC_PTP_L4_IPV6_EVENT:
	case NETC_PTP_L4_IPV6_GENERAL:
		frm_attr_flags = IPFT_FAF_IP_HDR | FIELD_PREP(IPFT_FAF_L4_CODE,
				 IPFT_FAF_UDP_HDR);
		if (type == NETC_PTP_L4_IPV6_EVENT ||
		    type == NETC_PTP_L4_IPV6_GENERAL)
			frm_attr_flags |= IPFT_FAF_IP_VER6;

		keye->frm_attr_flags = cpu_to_le16(frm_attr_flags);

		/* Update frm_attr_flags to reuse it as the mask */
		frm_attr_flags |= IPFT_FAF_IP_VER6 | IPFT_FAF_L4_CODE;
		keye->frm_attr_flags_mask = cpu_to_le16(frm_attr_flags);
		keye->ip_protocol = IPPROTO_UDP;
		keye->ip_protocol_mask = 0xff;

		if (type == NETC_PTP_L4_IPV4_EVENT ||
		    type == NETC_PTP_L4_IPV6_EVENT)
			keye->l4_dst_port = htons(PTP_EV_PORT);
		else
			keye->l4_dst_port = htons(PTP_GEN_PORT);

		keye->l4_dst_port_mask = htons(0xffff);
		break;
	default:
		return -ERANGE;
	}

	return 0;
}

static int netc_port_add_ipft_ptp_entry(struct netc_port *np,
					enum netc_ptp_type type)
{
	struct netc_switch *priv = np->switch_priv;
	struct ipft_entry_data *entry;
	struct ipft_keye_data *keye;
	u32 cfg;
	int err;

	entry = kzalloc_obj(*entry);
	if (!entry)
		return -ENOMEM;

	keye = &entry->keye;
	err = netc_build_ptp_ipft_keye(keye, np->dp->index, type);
	if (err)
		goto free_entry;

	cfg = FIELD_PREP(IPFT_FLTFA, IPFT_FLTFA_REDIRECT);
	cfg |= FIELD_PREP(IPFT_HR, NETC_HR_PTP_TRAP);
	cfg |= IPFT_TIMECAPE | IPFT_RRT;
	entry->cfge.cfg = cpu_to_le32(cfg);

	err = ntmp_ipft_add_entry(&priv->ntmp, entry);
	if (err)
		goto free_entry;

	np->ptp_ipft_eid[type] = entry->entry_id;

free_entry:
	kfree(entry);

	return err;
}

static int netc_port_add_l2_ptp_filter(struct netc_port *np)
{
	return netc_port_add_ipft_ptp_entry(np, NETC_PTP_L2);
}

static int netc_port_add_l4_ptp_filter(struct netc_port *np)
{
	int err;

	err = netc_port_add_ipft_ptp_entry(np, NETC_PTP_L4_IPV4_EVENT);
	if (err)
		return err;

	err = netc_port_add_ipft_ptp_entry(np, NETC_PTP_L4_IPV4_GENERAL);
	if (err)
		goto del_ptp_filter;

	err = netc_port_add_ipft_ptp_entry(np, NETC_PTP_L4_IPV6_EVENT);
	if (err)
		goto del_ptp_filter;

	err = netc_port_add_ipft_ptp_entry(np, NETC_PTP_L4_IPV6_GENERAL);
	if (err)
		goto del_ptp_filter;

	return 0;

del_ptp_filter:
	netc_port_del_ptp_filter(np);

	return err;
}

static int netc_port_add_l2_l4_ptp_filter(struct netc_port *np)
{
	int err;

	err = netc_port_add_l2_ptp_filter(np);
	if (err)
		return err;

	err = netc_port_add_l4_ptp_filter(np);
	if (err)
		goto del_ptp_filter;

	return 0;

del_ptp_filter:
	netc_port_del_ptp_filter(np);

	return err;
}

static int netc_port_set_ptp_filter(struct netc_port *np, int rx_filter)
{
	int err;

	err = netc_port_del_ptp_filter(np);
	if (err)
		return err;

	switch (rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		break;
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
		err = netc_port_add_l2_ptp_filter(np);
		break;
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
		err = netc_port_add_l4_ptp_filter(np);
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
		err = netc_port_add_l2_l4_ptp_filter(np);
		break;
	default:
		err = -ERANGE;
	}

	return err;
}

int netc_port_hwtstamp_set(struct dsa_switch *ds, int port,
			   struct kernel_hwtstamp_config *config,
			   struct netlink_ext_ack *extack)
{
	struct netc_port *np = NETC_PORT(ds, port);
	struct netc_switch *priv = ds->priv;
	int rx_filter, err;

	if ((config->tx_type != HWTSTAMP_TX_OFF ||
	     config->rx_filter != HWTSTAMP_FILTER_NONE) &&
	    netc_get_phc_index(priv) < 0)
		return -EOPNOTSUPP;

	switch (config->tx_type) {
	case HWTSTAMP_TX_ONESTEP_SYNC:
	case HWTSTAMP_TX_ON:
	case HWTSTAMP_TX_OFF:
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		rx_filter = HWTSTAMP_FILTER_NONE;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
		rx_filter = HWTSTAMP_FILTER_PTP_V2_L2_EVENT;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		break;
	default:
		return -ERANGE;
	}

	err = netc_port_set_ptp_filter(np, rx_filter);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to set PTP filter");
		return err;
	}

	WRITE_ONCE(np->ptp_tx_type, config->tx_type);
	if (config->tx_type != HWTSTAMP_TX_ONESTEP_SYNC)
		netc_port_purge_onestep_queue(np);

	config->rx_filter = rx_filter;

	return 0;
}

static int netc_port_current_rx_filter(struct netc_port *np)
{
	bool l2, l4_v4_ev, l4_v4_gen, l4_v6_ev, l4_v6_gen, l4_any;

	l2 = np->ptp_ipft_eid[NETC_PTP_L2] != NTMP_NULL_ENTRY_ID;
	l4_v4_ev = np->ptp_ipft_eid[NETC_PTP_L4_IPV4_EVENT] != NTMP_NULL_ENTRY_ID;
	l4_v4_gen = np->ptp_ipft_eid[NETC_PTP_L4_IPV4_GENERAL] != NTMP_NULL_ENTRY_ID;
	l4_v6_ev = np->ptp_ipft_eid[NETC_PTP_L4_IPV6_EVENT] != NTMP_NULL_ENTRY_ID;
	l4_v6_gen = np->ptp_ipft_eid[NETC_PTP_L4_IPV6_GENERAL] != NTMP_NULL_ENTRY_ID;

	l4_any = l4_v4_ev || l4_v4_gen || l4_v6_ev || l4_v6_gen;

	if (l2 && l4_any)
		return HWTSTAMP_FILTER_PTP_V2_EVENT;
	if (l4_any)
		return HWTSTAMP_FILTER_PTP_V2_L4_EVENT;
	if (l2)
		return HWTSTAMP_FILTER_PTP_V2_L2_EVENT;

	return HWTSTAMP_FILTER_NONE;
}

int netc_port_hwtstamp_get(struct dsa_switch *ds, int port,
			   struct kernel_hwtstamp_config *config)
{
	struct netc_port *np = NETC_PORT(ds, port);

	if (netc_get_phc_index(ds->priv) < 0)
		return -EOPNOTSUPP;

	config->tx_type = READ_ONCE(np->ptp_tx_type);
	config->rx_filter = netc_port_current_rx_filter(np);

	return 0;
}

static void netc_port_prepare_onestep_sync(struct netc_port *np,
					   struct sk_buff *skb,
					   u32 ptp_class, bool *twostep)
{
	struct netc_switch *priv = np->switch_priv;
	u16 correction_offset, tstamp_offset;
	struct ptp_header *ptp_hdr;
	u8 msg_type, twostep_flag;
	bool is_udp = false;
	u32 pkt_type;
	u8 *pkt_hdr;

	/* Ensure the buffer is linear and writable so the packet can be
	 * parsed and updated in place. Otherwise, fall back to two-step.
	 */
	if (unlikely(skb_linearize_cow(skb))) {
		*twostep = true;
		return;
	}

	ptp_hdr = ptp_parse_header(skb, ptp_class);
	if (unlikely(!ptp_hdr)) {
		*twostep = true;
		return;
	}

	msg_type = ptp_get_msgtype(ptp_hdr, ptp_class);
	twostep_flag = ptp_hdr->flag_field[0] & 0x2;
	if (msg_type != PTP_MSGTYPE_SYNC || twostep_flag != 0) {
		*twostep = true;
		return;
	}

	pkt_hdr = skb_mac_header(skb);
	correction_offset = (u8 *)&ptp_hdr->correction - pkt_hdr;
	tstamp_offset = (u8 *)ptp_hdr + sizeof(*ptp_hdr) - pkt_hdr;

	/* Ensure that the entire originTimestamp field is present in the
	 * linear buffer of the skb and the correction_offset must be within
	 * the hardware capability.
	 */
	if (unlikely(tstamp_offset + 10 > skb_headlen(skb) ||
		     correction_offset > NETC_MAX_STEP_OFFSET)) {
		NETC_SKB_CB(skb)->ptp_flag = NETC_PTP_FLAG_DROP;
		dev_core_stats_tx_dropped_inc(np->dp->user);
		dev_dbg_ratelimited(priv->dev,
				    "Port %d: PTP frame dropped in error\n",
				    np->dp->index);
		return;
	}

	pkt_type = ptp_class & PTP_CLASS_PMASK;
	if (pkt_type == PTP_CLASS_IPV4 || pkt_type == PTP_CLASS_IPV6)
		is_udp = true;

	NETC_SKB_CB(skb)->correction_offset = correction_offset;
	NETC_SKB_CB(skb)->timestamp_offset = tstamp_offset;
	NETC_SKB_CB(skb)->is_udp = is_udp;
	NETC_SKB_CB(skb)->ptp_flag = NETC_PTP_FLAG_ONESTEP;
}

static void netc_port_prepare_twostep(struct netc_port *np,
				      struct sk_buff *nskb)
{
	struct sk_buff *clone = skb_clone_sk(nskb);
	int ts_req_id;

	if (unlikely(!clone))
		return;

	spin_lock_bh(&np->tstamp_lock);

	ts_req_id = netc_get_ts_req_id(np);
	if (ts_req_id < 0) {
		spin_unlock_bh(&np->tstamp_lock);
		kfree_skb(clone);
		return;
	}

	NETC_SKB_CB(nskb)->ptp_flag = NETC_PTP_FLAG_TWOSTEP;
	NETC_SKB_CB(nskb)->ts_req_id = ts_req_id;
	NETC_SKB_CB(clone)->ts_req_id = ts_req_id;
	NETC_SKB_CB(clone)->ptp_tx_time = get_jiffies_64();
	NETC_SKB_CB(clone)->ptp_flag = NETC_PTP_FLAG_TWOSTEP;
	skb_shinfo(clone)->tx_flags |= SKBTX_IN_PROGRESS;
	__skb_queue_tail(&np->tstamp_queue, clone);
	if (!delayed_work_pending(&np->tstamp_timeout_work))
		schedule_delayed_work(&np->tstamp_timeout_work,
				      NETC_TSTAMP_TIMEOUT);

	spin_unlock_bh(&np->tstamp_lock);
}

void netc_port_txtstamp_handler(struct dsa_switch *ds, int port,
				u8 ts_req_id, u64 ts)
{
	struct sk_buff *skb, *skb_tmp, *skb_match = NULL;
	struct netc_port *np = NETC_PORT(ds, port);
	struct skb_shared_hwtstamps hwtstamps;

	spin_lock_bh(&np->onestep_lock);

	spin_lock_bh(&np->tstamp_lock);
	skb_queue_walk_safe(&np->tstamp_queue, skb, skb_tmp) {
		if (NETC_SKB_CB(skb)->ts_req_id != ts_req_id)
			continue;

		__skb_unlink(skb, &np->tstamp_queue);
		skb_match = skb;
		break;
	}
	spin_unlock_bh(&np->tstamp_lock);

	if (!skb_match) {
		spin_unlock_bh(&np->onestep_lock);
		dev_dbg_ratelimited(np->switch_priv->dev,
				    "Port %d ts_req_id %u which seems lost\n",
				    port, ts_req_id);
		return;
	}

	if (NETC_SKB_CB(skb_match)->ptp_flag == NETC_PTP_FLAG_ONESTEP) {
		if (likely(np->onestep_state == NETC_ONESTEP_IN_FLIGHT &&
			   np->onestep_ts_req_id == ts_req_id) ||
		    np->onestep_state == NETC_ONESTEP_IDLE) {
			np->onestep_state = NETC_ONESTEP_SCHEDULED;
			schedule_work(&np->onestep_work);
		}
		spin_unlock_bh(&np->onestep_lock);
		consume_skb(skb_match);
		return;
	}

	spin_unlock_bh(&np->onestep_lock);

	hwtstamps.hwtstamp = ns_to_ktime(ts);
	skb_complete_tx_timestamp(skb_match, &hwtstamps);
}

bool netc_port_rxtstamp(struct dsa_switch *ds, int port, struct sk_buff *skb,
			unsigned int type)
{
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);

	if (!NETC_SKB_CB(skb)->rx_tstamp_valid)
		return false;

	hwtstamps->hwtstamp = ns_to_ktime(NETC_SKB_CB(skb)->tstamp);

	return false;
}

void netc_port_txtstamp(struct dsa_switch *ds, int port, struct sk_buff *skb)
{
	struct netc_port *np = NETC_PORT(ds, port);
	bool twostep = false;
	u32 ptp_class;
	int tx_type;

	NETC_SKB_CB(skb)->ptp_flag = 0;
	ptp_class = ptp_classify_raw(skb);
	if (ptp_class == PTP_CLASS_NONE)
		return;

	/* Only supports PTP v2 */
	if (unlikely(ptp_class & PTP_CLASS_V1))
		return;

	tx_type = READ_ONCE(np->ptp_tx_type);
	if (tx_type == HWTSTAMP_TX_ONESTEP_SYNC)
		netc_port_prepare_onestep_sync(np, skb, ptp_class, &twostep);

	if (tx_type == HWTSTAMP_TX_ON || twostep)
		netc_port_prepare_twostep(np, skb);
}
