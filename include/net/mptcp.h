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
	struct mptcp_ext ext_copy;
#endif
};

#ifdef CONFIG_MPTCP

void mptcp_init(void);

static inline bool sk_is_mptcp(const struct sock *sk)
{
	return tcp_sk(sk)->is_mptcp;
}

static inline bool rsk_is_mptcp(const struct request_sock *req)
{
	return tcp_rsk(req)->is_mptcp;
}

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct tcp_options_received *opt_rx);
bool mptcp_syn_options(struct sock *sk, unsigned int *size,
		       struct mptcp_out_options *opts);
void mptcp_rcv_synsent(struct sock *sk);
bool mptcp_synack_options(const struct request_sock *req, unsigned int *size,
			  struct mptcp_out_options *opts);
bool mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct mptcp_out_options *opts);
void mptcp_incoming_options(struct sock *sk, struct sk_buff *skb,
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

static inline bool sk_is_mptcp(const struct sock *sk)
{
	return false;
}

static inline bool rsk_is_mptcp(const struct request_sock *req)
{
	return false;
}

static inline void mptcp_parse_option(const unsigned char *ptr, int opsize,
				      struct tcp_options_received *opt_rx)
{
}

static inline bool mptcp_syn_options(struct sock *sk, unsigned int *size,
				     struct mptcp_out_options *opts)
{
	return false;
}

static inline void mptcp_rcv_synsent(struct sock *sk)
{
}

static inline bool mptcp_synack_options(const struct request_sock *req,
					unsigned int *size,
					struct mptcp_out_options *opts)
{
	return false;
}

static inline bool mptcp_established_options(struct sock *sk,
					     struct sk_buff *skb,
					     unsigned int *size,
					     unsigned int remaining,
					     struct mptcp_out_options *opts)
{
	return false;
}

static inline void mptcp_incoming_options(struct sock *sk,
					  struct sk_buff *skb,
					  struct tcp_options_received *opt_rx)
{
}

static inline bool mptcp_skb_ext_exist(const struct sk_buff *skb)
{
	return false;
}

#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
