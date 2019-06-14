/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __MPTCP_PROTOCOL_H
#define __MPTCP_PROTOCOL_H

/* MPTCP option subtypes */
#define MPTCPOPT_MP_CAPABLE	0
#define MPTCPOPT_MP_JOIN	1
#define MPTCPOPT_DSS		2
#define MPTCPOPT_ADD_ADDR	3
#define MPTCPOPT_REMOVE_ADDR	4
#define MPTCPOPT_MP_PRIO	5
#define MPTCPOPT_MP_FAIL	6
#define MPTCPOPT_MP_FASTCLOSE	7

/* MPTCP suboption lengths */
#define TCPOLEN_MPTCP_MPC_SYN		12
#define TCPOLEN_MPTCP_MPC_SYNACK	20
#define TCPOLEN_MPTCP_MPC_ACK		20

/* MPTCP MP_CAPABLE flags */
#define MPTCP_VERSION_MASK	(0x0F)
#define MPTCP_CAP_CHECKSUM_REQD	BIT(7)
#define MPTCP_CAP_EXTENSIBILITY	BIT(6)
#define MPTCP_CAP_HMAC_SHA1	BIT(0)
#define MPTCP_CAP_FLAG_MASK	(0x3F)

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct	inet_connection_sock sk;
	u64	local_key;
	u64	remote_key;
	u32	token;
	struct	socket *connection_list; /* @@ needs to be a list */
	struct	socket *subflow; /* outgoing connect, listener or !mp_capable */
};

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

struct subflow_request_sock {
	struct	tcp_request_sock sk;
	u8	mp_capable : 1,
		mp_join : 1,
		checksum : 1,
		backup : 1,
		version : 4;
	u64	local_key;
	u64	remote_key;
	u32	token;
};

static inline
struct subflow_request_sock *subflow_rsk(const struct request_sock *rsk)
{
	return (struct subflow_request_sock *)rsk;
}

/* MPTCP subflow context */
struct subflow_context {
	u64	local_key;
	u64	remote_key;
	u32	token;
	u32	request_mptcp : 1,  /* send MP_CAPABLE */
		request_cksum : 1,
		mp_capable : 1,	    /* remote is MPTCP capable */
		fourth_ack : 1,     /* send initial DSS */
		version : 4,
		conn_finished : 1;
	struct  socket *tcp_sock;  /* underlying tcp_sock */
	struct  sock *conn;        /* parent mptcp_sock */
};

static inline struct subflow_context *subflow_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	return (struct subflow_context *)icsk->icsk_ulp_data;
}

static inline struct socket *mptcp_subflow_tcp_socket(const struct subflow_context *subflow)
{
	return subflow->tcp_sock;
}

void subflow_init(void);

extern const struct inet_connection_sock_af_ops ipv4_specific;

void mptcp_get_options(const struct sk_buff *skb,
		       struct tcp_options_received *opt_rx);

void mptcp_finish_connect(struct sock *sk, int mp_capable);

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

#endif /* __MPTCP_PROTOCOL_H */
