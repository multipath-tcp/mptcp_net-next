// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2020, Tessares SA.
 * Copyright (c) 2022, SUSE.
 *
 * Author: Nicolas Rybowski <nicolas.rybowski@tessares.net>
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/bpf.h>
#include "protocol.h"

struct mptcp_sock *bpf_mptcp_sock_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_sk(mptcp_subflow_ctx(sk)->conn);

	return NULL;
}

BTF_SET8_START(bpf_mptcp_fmodret_ids)
BTF_ID_FLAGS(func, update_socket_protocol)
BTF_SET8_END(bpf_mptcp_fmodret_ids)

static const struct btf_kfunc_id_set bpf_mptcp_fmodret_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_mptcp_fmodret_ids,
};

__bpf_kfunc_start_defs();

__bpf_kfunc static struct mptcp_sock *bpf_mptcp_sk(struct sock *sk)
{
	return mptcp_sk(sk);
}

__bpf_kfunc static struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk)
{
	return mptcp_subflow_ctx(sk);
}

__bpf_kfunc static struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return mptcp_subflow_tcp_sock(subflow);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mptcp_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_mptcp_sk)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_ctx)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_tcp_sock)
BTF_KFUNCS_END(bpf_mptcp_common_kfunc_ids)

static const struct btf_kfunc_id_set bpf_mptcp_common_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_common_kfunc_ids,
};

static int __init bpf_mptcp_kfunc_init(void)
{
	int ret;

	ret = register_btf_fmodret_id_set(&bpf_mptcp_fmodret_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					       &bpf_mptcp_common_kfunc_set);

	return ret;
}
late_initcall(bpf_mptcp_kfunc_init);
