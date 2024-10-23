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

struct bpf_iter_mptcp_subflow {
	__u64 __opaque[2];
} __aligned(8);

struct bpf_iter_mptcp_subflow_kern {
	struct mptcp_sock *msk;
	struct list_head *pos;
} __aligned(8);

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

__bpf_kfunc static int
bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,
			   struct mptcp_sock *msk)
{
	struct bpf_iter_mptcp_subflow_kern *kit = (void *)it;

	kit->msk = msk;
	if (!msk)
		return -EINVAL;

	msk_owned_by_me(msk);

	kit->pos = &msk->conn_list;
	return 0;
}

__bpf_kfunc static struct mptcp_subflow_context *
bpf_iter_mptcp_subflow_next(struct bpf_iter_mptcp_subflow *it)
{
	struct bpf_iter_mptcp_subflow_kern *kit = (void *)it;

	if (!kit->msk || list_is_last(kit->pos, &kit->msk->conn_list))
		return NULL;

	kit->pos = kit->pos->next;
	return list_entry(kit->pos, struct mptcp_subflow_context, node);
}

__bpf_kfunc static void
bpf_iter_mptcp_subflow_destroy(struct bpf_iter_mptcp_subflow *it)
{
}

__bpf_kfunc static struct
mptcp_sock *bpf_mptcp_sock_acquire(struct mptcp_sock *msk)
{
	struct sock *sk = (struct sock *)msk;

	if (sk && refcount_inc_not_zero(&sk->sk_refcnt))
		return msk;
	return NULL;
}

__bpf_kfunc static void bpf_mptcp_sock_release(struct mptcp_sock *msk)
{
	struct sock *sk = (struct sock *)msk;

	WARN_ON_ONCE(!sk || !refcount_dec_not_one(&sk->sk_refcnt));
}

__bpf_kfunc struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx_by_pos(const struct mptcp_sched_data *data, unsigned int pos)
{
	if (pos >= MPTCP_SUBFLOWS_MAX)
		return NULL;
	return data->contexts[pos];
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mptcp_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_mptcp_sk)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_ctx)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_tcp_sock)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_mptcp_sock_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_mptcp_sock_release, KF_RELEASE)
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
