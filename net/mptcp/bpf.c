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
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/skmsg.h>
#include <net/bpf_sk_storage.h>
#include "protocol.h"

#ifdef CONFIG_BPF_JIT
static struct bpf_struct_ops bpf_mptcp_sched_ops;
static u32 mptcp_sock_id,
	   mptcp_subflow_id;

/* MPTCP BPF packet scheduler */

static const struct bpf_func_proto *
bpf_mptcp_sched_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	case BPF_FUNC_skc_to_tcp6_sock:
		return &bpf_skc_to_tcp6_sock_proto;
	case BPF_FUNC_skc_to_tcp_sock:
		return &bpf_skc_to_tcp_sock_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static int bpf_mptcp_sched_btf_struct_access(struct bpf_verifier_log *log,
					     const struct bpf_reg_state *reg,
					     int off, int size)
{
	u32 id = reg->btf_id;
	size_t end;

	if (id == mptcp_sock_id) {
		switch (off) {
		case offsetof(struct mptcp_sock, snd_burst):
			end = offsetofend(struct mptcp_sock, snd_burst);
			break;
		default:
			bpf_log(log, "no write support to mptcp_sock at off %d\n",
				off);
			return -EACCES;
		}
	} else if (id == mptcp_subflow_id) {
		switch (off) {
		case offsetof(struct mptcp_subflow_context, avg_pacing_rate):
			end = offsetofend(struct mptcp_subflow_context, avg_pacing_rate);
			break;
		default:
			bpf_log(log, "no write support to mptcp_subflow_context at off %d\n",
				off);
			return -EACCES;
		}
	} else {
		bpf_log(log, "only access to mptcp sock or subflow is supported\n");
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log, "access beyond %s at off %u size %u ended at %zu",
			id == mptcp_sock_id ? "mptcp_sock" : "mptcp_subflow_context",
			off, size, end);
		return -EACCES;
	}

	return NOT_INIT;
}

static const struct bpf_verifier_ops bpf_mptcp_sched_verifier_ops = {
	.get_func_proto		= bpf_mptcp_sched_get_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
	.btf_struct_access	= bpf_mptcp_sched_btf_struct_access,
};

static int bpf_mptcp_sched_reg(void *kdata, struct bpf_link *link)
{
	return mptcp_register_scheduler(kdata);
}

static void bpf_mptcp_sched_unreg(void *kdata, struct bpf_link *link)
{
	mptcp_unregister_scheduler(kdata);
}

static int bpf_mptcp_sched_check_member(const struct btf_type *t,
					const struct btf_member *member,
					const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_mptcp_sched_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	const struct mptcp_sched_ops *usched;
	struct mptcp_sched_ops *sched;
	u32 moff;

	usched = (const struct mptcp_sched_ops *)udata;
	sched = (struct mptcp_sched_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct mptcp_sched_ops, name):
		if (bpf_obj_name_cpy(sched->name, usched->name,
				     sizeof(sched->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int bpf_mptcp_sched_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_sock",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_sock_id = type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_subflow_context",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_subflow_id = type_id;

	return 0;
}

static int bpf_mptcp_sched_validate(void *kdata)
{
	return mptcp_validate_scheduler(kdata);
}

static int __bpf_mptcp_sched_get_send(struct mptcp_sock *msk)
{
	return 0;
}

static int __bpf_mptcp_sched_get_retrans(struct mptcp_sock *msk)
{
	return 0;
}

static void __bpf_mptcp_sched_init(struct mptcp_sock *msk)
{
}

static void __bpf_mptcp_sched_release(struct mptcp_sock *msk)
{
}

static struct mptcp_sched_ops __bpf_mptcp_sched_ops = {
	.get_send	= __bpf_mptcp_sched_get_send,
	.get_retrans	= __bpf_mptcp_sched_get_retrans,
	.init		= __bpf_mptcp_sched_init,
	.release	= __bpf_mptcp_sched_release,
};

static struct bpf_struct_ops bpf_mptcp_sched_ops = {
	.verifier_ops	= &bpf_mptcp_sched_verifier_ops,
	.reg		= bpf_mptcp_sched_reg,
	.unreg		= bpf_mptcp_sched_unreg,
	.check_member	= bpf_mptcp_sched_check_member,
	.init_member	= bpf_mptcp_sched_init_member,
	.init		= bpf_mptcp_sched_init,
	.validate	= bpf_mptcp_sched_validate,
	.name		= "mptcp_sched_ops",
	.cfi_stubs	= &__bpf_mptcp_sched_ops,
};
#endif /* CONFIG_BPF_JIT */

struct mptcp_sock *bpf_mptcp_sock_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk_is_tcp(sk) && sk_is_mptcp(sk))
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

__bpf_kfunc static struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_type == SOCK_STREAM &&
	    sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_subflow_ctx(sk);

	return NULL;
}

__bpf_kfunc static struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	if (!subflow)
		return NULL;

	return mptcp_subflow_tcp_sock(subflow);
}

__bpf_kfunc static int
bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,
			   struct sock *sk)
{
	struct bpf_iter_mptcp_subflow_kern *kit = (void *)it;
	struct mptcp_sock *msk;

	BUILD_BUG_ON(sizeof(struct bpf_iter_mptcp_subflow_kern) >
		     sizeof(struct bpf_iter_mptcp_subflow));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_mptcp_subflow_kern) !=
		     __alignof__(struct bpf_iter_mptcp_subflow));

	if (unlikely(!sk || !sk_fullsock(sk))) {
		kit->msk = NULL;
		kit->pos = NULL;
		return -EINVAL;
	}

	if (sk->sk_type != SOCK_STREAM ||
	    sk->sk_protocol != IPPROTO_MPTCP) {
		kit->msk = NULL;
		kit->pos = NULL;
		return -EINVAL;
	}

	msk = mptcp_sk(sk);

	msk_owned_by_me(msk);

	kit->msk = msk;
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

__bpf_kfunc static bool
bpf_sk_stream_memory_free(const struct mptcp_subflow_context *subflow)
{
	const struct sock *sk = mptcp_subflow_tcp_sock(subflow);

	if (sk && sk_fullsock(sk) && sk->sk_type == SOCK_STREAM &&
	    sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return sk_stream_memory_free(sk);

	return false;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mptcp_iter_kfunc_ids)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_new, KF_ITER_NEW)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_destroy, KF_ITER_DESTROY)
BTF_KFUNCS_END(bpf_mptcp_iter_kfunc_ids)

static const struct btf_kfunc_id_set bpf_mptcp_iter_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_iter_kfunc_ids,
};

BTF_KFUNCS_START(bpf_mptcp_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_ctx, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_tcp_sock, KF_RET_NULL)
BTF_ID_FLAGS(func, mptcp_subflow_set_scheduled)
BTF_ID_FLAGS(func, mptcp_subflow_active)
BTF_ID_FLAGS(func, mptcp_set_timeout)
BTF_ID_FLAGS(func, mptcp_wnd_end)
BTF_ID_FLAGS(func, bpf_sk_stream_memory_free)
BTF_KFUNCS_END(bpf_mptcp_common_kfunc_ids)

static int bpf_mptcp_common_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&bpf_mptcp_common_kfunc_ids, kfunc_id))
		return 0;

	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return -EACCES;

#ifdef CONFIG_BPF_JIT
	if (prog->aux->st_ops == &bpf_mptcp_sched_ops)
		return 0;
#endif
	return -EACCES;
}

static const struct btf_kfunc_id_set bpf_mptcp_common_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_common_kfunc_ids,
	.filter	= bpf_mptcp_common_kfunc_filter,
};

static int __init bpf_mptcp_kfunc_init(void)
{
	int ret;

	ret = register_btf_fmodret_id_set(&bpf_mptcp_fmodret_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &bpf_mptcp_iter_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &bpf_mptcp_common_kfunc_set);
#ifdef CONFIG_BPF_JIT
	ret = ret ?: register_bpf_struct_ops(&bpf_mptcp_sched_ops, mptcp_sched_ops);
#endif

	return ret;
}
late_initcall(bpf_mptcp_kfunc_init);

enum {
	MPTCP_BPF_IPV4,
	MPTCP_BPF_IPV6,
	MPTCP_BPF_NUM_PROTS,
};

enum {
	MPTCP_BPF_BASE,
	MPTCP_BPF_TX,
	MPTCP_BPF_RX,
	MPTCP_BPF_TXRX,
	MPTCP_BPF_NUM_CFGS,
};

static struct proto mptcp_bpf_prots[MPTCP_BPF_NUM_PROTS][MPTCP_BPF_NUM_CFGS];

static void mptcp_bpf_rebuild_protos(struct proto prot[MPTCP_BPF_NUM_CFGS],
				     struct proto *base)
{
	prot[MPTCP_BPF_BASE]			= *base;
	prot[MPTCP_BPF_BASE].destroy		= sock_map_destroy;
	prot[MPTCP_BPF_BASE].close		= sock_map_close;
	prot[MPTCP_BPF_BASE].sock_is_readable	= sk_msg_is_readable;

	prot[MPTCP_BPF_TX]			= prot[MPTCP_BPF_BASE];
	prot[MPTCP_BPF_RX]			= prot[MPTCP_BPF_BASE];
	prot[MPTCP_BPF_TXRX]			= prot[MPTCP_BPF_BASE];
}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
static struct proto *mptcpv6_prot_saved __read_mostly;
static DEFINE_SPINLOCK(mptcpv6_prot_lock);

static void mptcp_bpf_check_v6_needs_rebuild(struct proto *ops)
{
	/* Load with acquire semantics to ensure we see the latest protocol
	 * structure before checking for rebuild.
	 */
	if (unlikely(ops != smp_load_acquire(&mptcpv6_prot_saved))) {
		spin_lock_bh(&mptcpv6_prot_lock);
		if (likely(ops != mptcpv6_prot_saved)) {
			struct proto *v6_prots;

			v6_prots = mptcp_bpf_prots[MPTCP_BPF_IPV6];
			mptcp_bpf_rebuild_protos(v6_prots, ops);
			/* Ensure mptcpv6_prot_saved update is visible before
			 * releasing lock
			 */
			smp_store_release(&mptcpv6_prot_saved, ops);
		}
		spin_unlock_bh(&mptcpv6_prot_lock);
	}
}

static int mptcp_bpf_assert_proto_ops(struct proto *ops)
{
	/* In order to avoid retpoline, we make assumptions when we call
	 * into ops if e.g. a psock is not present. Make sure they are
	 * indeed valid assumptions.
	 */
	return ops->recvmsg == mptcp_recvmsg &&
	       ops->sendmsg == mptcp_sendmsg ? 0 : -EOPNOTSUPP;
}
#endif

int mptcp_bpf_update_proto(struct sock *sk, struct sk_psock *psock,
			   bool restore)
{
	int family = sk->sk_family == AF_INET6 ? MPTCP_BPF_IPV6 :
						 MPTCP_BPF_IPV4;
	int config = psock->progs.msg_parser   ? MPTCP_BPF_TX   :
						 MPTCP_BPF_BASE;

	if (psock->progs.stream_verdict || psock->progs.skb_verdict)
		config = (config == MPTCP_BPF_TX) ? MPTCP_BPF_TXRX :
						    MPTCP_BPF_RX;

	if (restore) {
		WRITE_ONCE(sk->sk_write_space, psock->saved_write_space);
		/* Pairs with lockless read in sk_clone() */
		sock_replace_proto(sk, psock->sk_proto);
		return 0;
	}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	if (sk->sk_family == AF_INET6) {
		if (mptcp_bpf_assert_proto_ops(psock->sk_proto))
			return -EINVAL;

		mptcp_bpf_check_v6_needs_rebuild(psock->sk_proto);
	}
#endif

	/* Pairs with lockless read in sk_clone() */
	sock_replace_proto(sk, &mptcp_bpf_prots[family][config]);
	return 0;
}

static int __init mptcp_bpf_v4_build_proto(void)
{
	mptcp_bpf_rebuild_protos(mptcp_bpf_prots[MPTCP_BPF_IPV4], &mptcp_prot);
	return 0;
}
late_initcall(mptcp_bpf_v4_build_proto);
