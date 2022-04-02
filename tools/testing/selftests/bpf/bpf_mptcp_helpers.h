/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022, SUSE. */

#ifndef __BPF_MPTCP_HELPERS_H
#define __BPF_MPTCP_HELPERS_H

#include "bpf_tcp_helpers.h"

struct mptcp_sock {
	struct inet_connection_sock	sk;

	__u32		token;
} __attribute__((preserve_access_index));

#endif
