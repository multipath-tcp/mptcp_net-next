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

BPF_CALL_1(bpf_mptcp_sock, struct sock *, sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk)) {
		struct mptcp_subflow_context *mptcp_sfc = mptcp_subflow_ctx(sk);

		return (unsigned long)mptcp_sfc->conn;
	}
	return (unsigned long)NULL;
}

const struct bpf_func_proto bpf_mptcp_sock_proto = {
	.func           = bpf_mptcp_sock,
	.gpl_only       = false,
	.ret_type       = RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type      = ARG_PTR_TO_SOCK_COMMON,
};
