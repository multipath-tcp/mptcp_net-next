/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __NET_MPTCP_H
#define __NET_MPTCP_H

/* MPTCP option subtypes */

#define MPTCPOPT_MP_CAPABLE	0
#define MPTCPOPT_MP_JOIN	1
#define MPTCPOPT_DSS		2
#define MPTCPOPT_ADD_ADDR	3
#define MPTCPOPT_REMOVE_ADDR	4
#define MPTCPOPT_MP_PRIO	5
#define MPTCPOPT_MP_FAIL	6
#define MPTCPOPT_MP_FASTCLOSE	7

#define MPTCPOPT_VERSION_MASK	0x0F

/* MPTCP handshake flags */

#define MPTCP_CAP_CHECKSUM_REQD	(1 << 7)
#define MPTCP_CAP_EXTENSIBILITY	(1 << 6)
#define MPTCP_CAP_HMAC_SHA1	(1 << 0)

/* MPTCP DSS flags */

#define MPTCP_DSS_DATA_FIN	BIT(4)
#define MPTCP_DSS_DSN64		BIT(3)
#define MPTCP_DSS_HAS_MAP	BIT(2)
#define MPTCP_DSS_ACK64		BIT(1)
#define MPTCP_DSS_HAS_ACK	BIT(0)
#define MPTCP_DSS_FLAG_MASK	(0x1F)

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct inet_connection_sock sk;
	u64		local_key;
	u64		remote_key;
	u64		write_seq;
	atomic64_t	ack_seq;
	u32		token;
	struct socket	*connection_list; /* @@ needs to be a list */
	struct socket	*subflow; /* outgoing connect/listener/!mp_capable */
};

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

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

/* MPTCP subflow sock structure */
struct subflow_sock {
	/* tcp_sock must be the first member */
	struct	tcp_sock sk;
	u64	local_key;
	u64	map_seq;
	u32	map_subflow_seq;
	u32	token;
	u64	idsn;
	u64	remote_key;
	u32	rel_write_seq;
	u32	ssn_offset;
	u16	map_data_len;
	u8	version;
	bool	request_mptcp;	// send MP_CAPABLE
	bool	checksum;
	bool	mp_capable;	// remote is MPTCP capable
	bool	fourth_ack;	// send initial DSS
	bool	conn_finished;
	bool	map_valid;
	struct	sock *conn;	// parent mptcp_sock
	void	(*tcp_sk_data_ready)(struct sock *sk);
};

static inline struct subflow_sock *subflow_sk(const struct sock *sk)
{
	return (struct subflow_sock *)sk;
}

static inline struct subflow_sock *subflow_tp(const struct tcp_sock *tp)
{
	return (struct subflow_sock *)tp;
}

static inline struct sock *sock_sk(const struct subflow_sock *sk)
{
	return (struct sock *)sk;
}

struct subflow_request_sock {
	struct	tcp_request_sock sk;
	u8	mp_capable : 1,
		mp_join : 1,
		checksum : 1,
		backup : 1,
		version : 4;
	u64	local_key;
	u32	token;
	u64	idsn;
	u64	remote_key;
	u32	ssn_offset;
};

static inline
struct subflow_request_sock *subflow_rsk(const struct request_sock *rsk)
{
	return (struct subflow_request_sock *)rsk;
}

/* MPTCP option subtypes */
#define OPTION_MPTCP_MPC_SYN	BIT(0)
#define OPTION_MPTCP_MPC_SYNACK	BIT(1)
#define OPTION_MPTCP_MPC_ACK	BIT(2)
#define OPTION_MPTCP_DSS_MAP	BIT(3)
#define OPTION_MPTCP_DSS_ACK	BIT(4)

struct mptcp_out_options {
	u16 suboptions;
	u64 sndr_key;
	u64 rcvr_key;
};

#ifdef CONFIG_MPTCP

static inline struct mptcp_ext *mptcp_get_ext(struct sk_buff *skb)
{
	return (struct mptcp_ext *)skb_ext_find(skb, SKB_EXT_MPTCP);
}

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct mptcp_options_received *opt_rx);
unsigned int mptcp_syn_options(struct sock *sk, u64 *local_key);
void mptcp_rcv_synsent(struct sock *sk);
unsigned int mptcp_established_options(struct sock *sk, u64 *local_key,
				       u64 *remote_key);
unsigned int mptcp_synack_options(const struct request_sock *req,
				  u64 *local_key, u64 *remote_key);

void mptcp_finish_connect(struct sock *sk, int mp_capable);

int mptcp_subflow_init(void);
void mptcp_subflow_exit(void);

void mptcp_get_options(const struct sk_buff *skb,
		       struct mptcp_options_received *opt_rx);

void mptcp_attach_dss(struct sock *sk, struct sk_buff *skb,
		      struct mptcp_options_received *opt_rx);

static inline bool mptcp_skb_ext_exist(const struct sk_buff *skb)
{
	return skb_ext_exist(skb, SKB_EXT_MPTCP);
}

void token_init(void);
void token_new_request(struct request_sock *req, const struct sk_buff *skb);
void token_destroy_request(u32 token);
void token_new_connect(struct sock *sk);
void token_new_accept(struct sock *sk);
void token_update_accept(struct sock *sk, struct sock *conn);
void token_destroy(u32 token);

void crypto_init(void);
u32 crypto_v4_get_nonce(__be32 saddr, __be32 daddr,
			__be16 sport, __be16 dport);
u64 crypto_v4_get_key(__be32 saddr, __be32 daddr,
			__be16 sport, __be16 dport);
u64 crypto_v6_get_key(const struct in6_addr *saddr,
		      const struct in6_addr *daddr,
		      __be16 sport, __be16 dport);
u32 crypto_v6_get_nonce(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__be16 sport, __be16 dport);
void crypto_key_sha1(u64 key, u32 *token, u64 *idsn);
void crypto_hmac_sha1(u64 key1, u64 key2, u32 *hash_out,
		     int arg_num, ...);

void mptcp_options_write(__be32 *ptr, struct sk_buff *skb, struct tcp_sock *tp,
			 struct mptcp_out_options *opts);

#else

static inline void mptcp_parse_option(const unsigned char *ptr, int opsize,
				      struct mptcp_options_received *opt_rx)
{
}

static inline unsigned int mptcp_syn_options(struct sock *sk, u64 *local_key)
{
	return 0;
}

static inline void mptcp_rcv_synsent(struct sock *sk)
{
}

static inline unsigned int mptcp_synack_options(struct request_sock *sk,
						u64 *local_key,
						u64 *remote_key)
{
	return 0;
}

static inline unsigned int mptcp_established_options(struct sock *sk,
						     u64 *local_key,
						     u64 *remote_key)
{
	return 0;
}

static inline void mptcp_attach_dss(struct sock *sk, struct sk_buff *skb,
				    struct tcp_options_received *opt_rx)
{
}

static inline bool mptcp_skb_ext_exist(const struct sk_buff *skb)
{
	return false;
}

static void mptcp_options_write(__be32 *ptr, struct sk_buff *skb,
				struct tcp_sock *tp,
				struct tmpcp_out_options *opts)
{
}

#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
