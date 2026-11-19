/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2025-2026 NXP
 */

#ifndef __NET_DSA_TAG_NETC_H
#define __NET_DSA_TAG_NETC_H

#include <linux/skbuff.h>
#include <net/dsa.h>

#define NETC_TAG_MAX_LEN			14
#define NETC_PTP_FLAG_TWOSTEP			BIT(1)

struct netc_skb_cb {
	u64 ptp_tx_time;
	u64 tstamp;
	bool rx_tstamp_valid;
	u8 ptp_flag;
	u8 ts_req_id;
};

#define NETC_SKB_CB(skb)	((struct netc_skb_cb *)((skb)->cb))

/**
 * struct netc_tagger_data - NETC tagger/switch-driver shared operations
 * @txtstamp_handler: Called by the tagger when a two-step transmit timestamp
 *	response is received, to deliver the timestamp to the switch driver.
 */
struct netc_tagger_data {
	void (*txtstamp_handler)(struct dsa_switch *ds, int port,
				 u8 ts_req_id, u64 ts);
};

#endif
