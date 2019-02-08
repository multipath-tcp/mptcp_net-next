/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __NET_MPTCP_H
#define __NET_MPTCP_H

#include <linux/tcp.h>

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

#endif /* __NET_MPTCP_H */
