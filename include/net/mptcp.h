/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
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

#define MPTCPOPT_VERSION_MASK	0x0F

/* MPTCP handshake flags */

#define MPTCP_CAP_CHECKSUM_REQD	(1 << 7)
#define MPTCP_CAP_EXTENSIBILITY	(1 << 6)
#define MPTCP_CAP_HMAC_SHA1	(1 << 0)

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct	inet_connection_sock sk;
	u64	local_key;
	u64	remote_key;
	struct	socket *connection_list; /* @@ needs to be a list */
	struct	socket *subflow; /* outgoing connect, listener or !mp_capable */
};

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

/* MPTCP subflow sock structure */
struct subflow_sock {
	/* tcp_sock must be the first member */
	struct	tcp_sock sk;
	u64	local_key;
	u64	remote_key;
	bool	request_mptcp;	// send MP_CAPABLE
	bool	checksum;
	bool	version;
	bool	mp_capable;	// remote is MPTCP capable
	bool	fourth_ack;	// send initial DSS
	struct	sock *conn;	// parent mptcp_sock
};

static inline struct subflow_sock *subflow_sk(const struct sock *sk)
{
	return (struct subflow_sock *)sk;
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
		       struct tcp_options_received *opt_rx);

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

#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
