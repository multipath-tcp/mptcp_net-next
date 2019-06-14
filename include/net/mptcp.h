/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __NET_MPTCP_H
#define __NET_MPTCP_H

/* MPTCP DSS flags */

#define MPTCP_DSS_DATA_FIN	BIT(4)
#define MPTCP_DSS_DSN64		BIT(3)
#define MPTCP_DSS_HAS_MAP	BIT(2)
#define MPTCP_DSS_ACK64		BIT(1)
#define MPTCP_DSS_HAS_ACK	BIT(0)

/* MPTCP sk_buff extension data */
struct mptcp_ext {
	u64		data_ack;
	u64		data_seq;
	u32		subflow_seq;
	u16		data_len;
	__sum16		checksum;
	u8		use_map:1,
			dsn64:1,
			use_checksum:1,
			data_fin:1,
			use_ack:1,
			ack64:1,
			__unused:2;
};

/* MPTCP option subtypes */
#define OPTION_MPTCP_MPC_SYN	BIT(0)
#define OPTION_MPTCP_MPC_SYNACK	BIT(1)
#define OPTION_MPTCP_MPC_ACK	BIT(2)

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

static inline bool mptcp_skb_ext_exist(const struct sk_buff *skb)
{
	return skb_ext_exist(skb, SKB_EXT_MPTCP);
}

void mptcp_write_options(__be32 *ptr, struct mptcp_out_options *opts);

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

static inline bool mptcp_skb_ext_exist(const struct sk_buff *skb)
{
	return false;
}

#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
