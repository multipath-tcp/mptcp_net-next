/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022, SUSE. */

#ifndef __BPF_MPTCP_HELPERS_H
#define __BPF_MPTCP_HELPERS_H

#include "bpf_tcp_helpers.h"

#define MPTCP_SCHED_NAME_MAX	16

struct mptcp_sched_data {
	struct sock	*sock;
	bool		call_again;
};

struct mptcp_sched_ops {
	char name[MPTCP_SCHED_NAME_MAX];

	void (*init)(const struct mptcp_sock *msk);
	void (*release)(const struct mptcp_sock *msk);

	void (*get_subflow)(const struct mptcp_sock *msk, bool reinject,
			    struct mptcp_sched_data *data);
	void *owner;
};

struct mptcp_sock {
	struct inet_connection_sock	sk;

	__u32		token;
	struct sock	*first;
	struct mptcp_sched_ops *sched;
	char		ca_name[TCP_CA_NAME_MAX];
} __attribute__((preserve_access_index));

#endif
