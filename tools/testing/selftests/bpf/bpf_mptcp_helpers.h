/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022, SUSE. */

#ifndef __BPF_MPTCP_HELPERS_H
#define __BPF_MPTCP_HELPERS_H

#include "bpf_tcp_helpers.h"

struct mptcp_sock {
	struct inet_connection_sock	sk;

	__u32		token;
	struct sock	*first;
	char		ca_name[TCP_CA_NAME_MAX];
} __attribute__((preserve_access_index));

#define MPTCP_SCHED_NAME_MAX 16

struct mptcp_sched_ops {
	char name[MPTCP_SCHED_NAME_MAX];

	void (*init)(struct mptcp_sock *msk);
	void (*release)(struct mptcp_sock *msk);

	struct sock *(*get_subflow)(struct mptcp_sock *msk, bool retrans);
	void *owner;
};

#endif
