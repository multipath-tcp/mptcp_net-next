/*
 * Multipath TCP
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __NET_MPTCP_H
#define __NET_MPTCP_H

#include <linux/tcp.h>

/* MPTCP option subtypes */

#define MPTCPOPT_MP_CAPABLE	0
#define MPTCPOPT_MP_JOIN	1
#define MPTCPOPT_DSS		2
#define MPTCPOPT_ADD_ADDR	3
#define MPTCPOPT_REMOVE_ADDR	4
#define MPTCPOPT_MP_PRIO	5
#define MPTCPOPT_MP_FAIL	6
#define MPTCPOPT_MP_FASTCLOSE	7

/* MPTCP handshake flags */

#define MPTCP_CAP_CHECKSUM_REQD	(1 << 7)
#define MPTCP_CAP_EXTENSIBILITY	(1 << 6)
#define MPTCP_CAP_HMAC_SHA1	(1 << 0)

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
	struct socket	*subflow; /* outgoing connect, listener or !mp_capable */
};

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

/* MPTCP sk_buff private control buffer */
struct mptcp_skb_cb {
	refcount_t	refcnt;
	u64		data_ack;
	u64		data_seq;
	u32		subflow_seq;
	u16		dll;
	__sum16		checksum;
	u8		use_map:1,
			dsn64:1,
			use_checksum:1,
			data_fin:1,
			use_ack:1,
			ack64:1,
			__unused:2;
};

static inline struct mptcp_skb_cb *mptcp_skb_priv_cb(struct sk_buff *skb)
{
	BUG_ON(!skb->priv_used);
	return (struct mptcp_skb_cb *)skb->priv;
}

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
	u16	map_dll;
	bool	request_mptcp;	// send MP_CAPABLE
	bool	checksum;
	bool	version;
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

#ifdef CONFIG_MPTCP

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct tcp_options_received *opt_rx);
unsigned int mptcp_syn_options(struct sock *sk, u64 *local_key);
void mptcp_rcv_synsent(struct sock *sk);
unsigned int mptcp_established_options(struct sock *sk, u64 *local_key,
				       u64 *remote_key);
unsigned int mptcp_synack_options(struct request_sock *req,
				  u64 *local_key, u64 *remote_key);

void mptcp_finish_connect(struct sock *sk, int mp_capable);

int mptcp_subflow_init(void);
void mptcp_subflow_exit(void);

void mptcp_get_options(const struct sk_buff *skb,
		       struct tcp_options_received *options);

void mptcp_cb_copy(const struct sk_buff *from, struct sk_buff *to);
void mptcp_cb_set(struct sk_buff *skb, struct mptcp_skb_cb *mcb);

void mptcp_attach_dss(struct sock *sk, struct sk_buff *original_skb,
		      struct tcp_options_received *opt_rx);

extern const struct tcp_request_sock_ops tcp_request_sock_ipv4_ops;

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

#else

static inline void mptcp_parse_option(const unsigned char *ptr, int opsize,
				      struct tcp_options_received *opt_rx)
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

void mptcp_cb_copy(const struct sk_buff *from, struct sk_buff *to)
{
}

static inline void mptcp_queue_headers(struct sock *sk,
				       struct sk_buff *original_skb)
{
}

#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
