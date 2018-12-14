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
	struct	inet_connection_sock sk;
	struct	socket *subflow;
};

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

#ifdef CONFIG_MPTCP

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct tcp_options_received *opt_rx);

void mptcp_get_options(const struct sk_buff *skb,
		       struct tcp_options_received *options);

extern const struct tcp_request_sock_ops tcp_request_sock_ipv4_ops;

#else

static inline void mptcp_parse_option(const unsigned char *ptr, int opsize,
				      struct tcp_options_received *opt_rx)
{
}



#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
