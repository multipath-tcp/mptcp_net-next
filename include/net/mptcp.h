/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __NET_MPTCP_H
#define __NET_MPTCP_H

#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>

/* MPTCP sk_buff extension data */
struct mptcp_ext {
	u64		data_ack;
	u64		data_seq;
	u32		subflow_seq;
	u16		data_len;
	u8		use_map:1,
			dsn64:1,
			data_fin:1,
			use_ack:1,
			ack64:1,
			__unused:2;
};

struct mptcp_out_options {
#if IS_ENABLED(CONFIG_MPTCP)
	u16 suboptions;
	u64 sndr_key;
	u64 rcvr_key;
#endif
};

#ifdef CONFIG_MPTCP

void mptcp_init(void);

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct tcp_options_received *opt_rx);
void mptcp_write_options(__be32 *ptr, struct mptcp_out_options *opts);

static inline bool mptcp_skb_ext_exist(const struct sk_buff *skb)
{
	return skb_ext_exist(skb, SKB_EXT_MPTCP);
}

#else

static inline void mptcp_init(void)
{
}

static inline void mptcp_parse_option(const unsigned char *ptr, int opsize,
				      struct tcp_options_received *opt_rx)
{
}

static inline bool mptcp_skb_ext_exist(const struct sk_buff *skb)
{
	return false;
}

#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
