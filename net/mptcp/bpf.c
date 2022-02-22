// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2020, Tessares SA.
 *
 * Author: Nicolas Rybowski <nicolas.rybowski@tessares.net>
 *
 */

#include <linux/bpf.h>

#include "protocol.h"

bool bpf_mptcp_sock_is_valid_access(int off, int size, enum bpf_access_type type,
				    struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= offsetofend(struct bpf_mptcp_sock, token))
		return false;

	if (off % size != 0)
		return false;

	switch (off) {
	default:
		return size == sizeof(__u32);
	}
}

struct sock *msk_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk)) {
		struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

		return subflow->conn;
	}
	return NULL;
}
EXPORT_SYMBOL(msk_from_subflow);
