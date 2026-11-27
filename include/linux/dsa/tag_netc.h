/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2025-2026 NXP
 */

#ifndef __NET_DSA_TAG_NETC_H
#define __NET_DSA_TAG_NETC_H

#include <linux/skbuff.h>
#include <net/dsa.h>

#define NETC_TAG_MAX_LEN			14
#define NETC_PTP_FLAG_ONESTEP			BIT(0)
#define NETC_PTP_FLAG_TWOSTEP			BIT(1)
#define NETC_PTP_FLAG_DROP			BIT(2)

struct netc_skb_cb {
	u64 ptp_tx_time;
	u64 tstamp;
	bool rx_tstamp_valid;
	u8 ptp_flag;
	u8 ts_req_id;
	bool is_udp;
	u16 correction_offset;
	u16 timestamp_offset;
};

#define NETC_SKB_CB(skb)	((struct netc_skb_cb *)((skb)->cb))

/**
 * struct netc_tagger_data - NETC tagger/switch-driver shared operations
 * @txtstamp_handler: Called by the tagger when a two-step transmit timestamp
 *	response is received, to deliver the timestamp to the switch driver.
 * @onestep_sync_enqueue: Called from the tagger xmit path for a one-step Sync
 *	frame. The switch driver takes ownership of the skb and queues it for
 *	deferred transmission from process context, where the shared
 *	PM_SINGLE_STEP register can be programmed and the PTP timer read. The
 *	tagger must not touch the skb after this call and returns NULL to
 *	dsa_user_xmit().
 * @onestep_sync_xmit: Called by the switch driver to transmit a deferred
 *	one-step Sync frame directly to the conduit, bypassing dsa_user_xmit().
 */
struct netc_tagger_data {
	void (*txtstamp_handler)(struct dsa_switch *ds, int port,
				 u8 ts_req_id, u64 ts);
	void (*onestep_sync_enqueue)(struct dsa_switch *ds, int port,
				     struct sk_buff *skb);
	netdev_tx_t (*onestep_sync_xmit)(struct sk_buff *skb,
					 struct net_device *ndev);
};

#endif
