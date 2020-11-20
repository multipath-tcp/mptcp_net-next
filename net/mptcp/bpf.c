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

u32 bpf_mptcp_sock_convert_ctx_access(enum bpf_access_type type,
				      const struct bpf_insn *si,
				      struct bpf_insn *insn_buf,
				      struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

#define BPF_MPTCP_SOCK_GET_COMMON(FIELD)							\
	do {											\
		BUILD_BUG_ON(sizeof_field(struct mptcp_sock, FIELD) >				\
				sizeof_field(struct bpf_mptcp_sock, FIELD));			\
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct mptcp_sock, FIELD),		\
							si->dst_reg, si->src_reg,		\
							offsetof(struct mptcp_sock, FIELD));	\
	} while (0)

	if (insn > insn_buf)
		return insn - insn_buf;

	switch (si->off) {
	case offsetof(struct bpf_mptcp_sock, token):
		BPF_MPTCP_SOCK_GET_COMMON(token);
		break;
	}

	return insn - insn_buf;
}

BPF_CALL_1(bpf_mptcp_sock, struct sock *, sk)
{
	if (sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk)) {
		struct mptcp_subflow_context *mptcp_sfc = mptcp_subflow_ctx(sk);

		return (unsigned long)mptcp_sfc->conn;
	}
	return (unsigned long)NULL;
}

const struct bpf_func_proto bpf_mptcp_sock_proto = {
	.func           = bpf_mptcp_sock,
	.gpl_only       = false,
	.ret_type       = RET_PTR_TO_MPTCP_SOCK_OR_NULL,
	.arg1_type      = ARG_PTR_TO_SOCK_COMMON,
};
