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
#include <net/bpf_sk_storage.h>
#include "protocol.h"

#ifdef CONFIG_BPF_JIT
static struct bpf_struct_ops bpf_mptcp_pm_ops,
			     bpf_mptcp_sched_ops;
static u32 mptcp_sock_id,
	   mptcp_entry_id,
	   mptcp_subflow_id;

/* MPTCP BPF path manager */

static const struct bpf_func_proto *
bpf_mptcp_pm_get_func_proto(enum bpf_func_id func_id,
			    const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static int bpf_mptcp_pm_btf_struct_access(struct bpf_verifier_log *log,
					  const struct bpf_reg_state *reg,
					  int off, int size)
{
	u32 id = reg->btf_id;
	size_t end;

	if (id == mptcp_sock_id) {
		switch (off) {
		case offsetof(struct mptcp_sock, pm.remote.id):
			end = offsetofend(struct mptcp_sock, pm.remote.id);
			break;
		case offsetof(struct mptcp_sock, pm.remote.family):
			end = offsetofend(struct mptcp_sock, pm.remote.family);
			break;
		case offsetof(struct mptcp_sock, pm.remote.port):
			end = offsetofend(struct mptcp_sock, pm.remote.port);
			break;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[0]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[0]);
			break;
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[1]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[1]);
			break;
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[2]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[2]);
			break;
		case offsetof(struct mptcp_sock, pm.remote.addr6.s6_addr32[3]):
			end = offsetofend(struct mptcp_sock, pm.remote.addr6.s6_addr32[3]);
			break;
#else
		case offsetof(struct mptcp_sock, pm.remote.addr.s_addr):
			end = offsetofend(struct mptcp_sock, pm.remote.addr.s_addr);
			break;
#endif
		case offsetof(struct mptcp_sock, pm.work_pending):
			end = offsetofend(struct mptcp_sock, pm.work_pending);
			break;
		case offsetof(struct mptcp_sock, pm.accept_addr):
			end = offsetofend(struct mptcp_sock, pm.accept_addr);
			break;
		case offsetof(struct mptcp_sock, pm.accept_subflow):
			end = offsetofend(struct mptcp_sock, pm.accept_subflow);
			break;
		case offsetof(struct mptcp_sock, pm.add_addr_signaled):
			end = offsetofend(struct mptcp_sock, pm.add_addr_signaled);
			break;
		case offsetof(struct mptcp_sock, pm.local_addr_used):
			end = offsetofend(struct mptcp_sock, pm.local_addr_used);
			break;
		case offsetof(struct mptcp_sock, pm.subflows):
			end = offsetofend(struct mptcp_sock, pm.subflows);
			break;
		default:
			bpf_log(log, "no write support to mptcp_sock at off %d\n",
				off);
			return -EACCES;
		}
	} else if (id == mptcp_entry_id) {
		switch (off) {
		case offsetof(struct mptcp_pm_addr_entry, addr.id):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.id);
			break;
		case offsetof(struct mptcp_pm_addr_entry, addr.port):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.port);
			break;
		default:
			bpf_log(log, "no write support to mptcp_pm_addr_entry at off %d\n",
				off);
			return -EACCES;
		}
	} else {
		bpf_log(log, "only access to mptcp sock or addr or entry is supported\n");
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log, "access beyond %s at off %u size %u ended at %zu",
			id == mptcp_sock_id ? "mptcp_sock" :
			(id == mptcp_entry_id ? "mptcp_pm_addr_entry" : "mptcp_addr_info"),
			off, size, end);
		return -EACCES;
	}

	return NOT_INIT;
}

static const struct bpf_verifier_ops bpf_mptcp_pm_verifier_ops = {
	.get_func_proto		= bpf_mptcp_pm_get_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
	.btf_struct_access	= bpf_mptcp_pm_btf_struct_access,
};

static int bpf_mptcp_pm_reg(void *kdata, struct bpf_link *link)
{
	return mptcp_pm_register(kdata);
}

static void bpf_mptcp_pm_unreg(void *kdata, struct bpf_link *link)
{
	mptcp_pm_unregister(kdata);
}

static int bpf_mptcp_pm_check_member(const struct btf_type *t,
				     const struct btf_member *member,
				     const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_mptcp_pm_init_member(const struct btf_type *t,
				    const struct btf_member *member,
				    void *kdata, const void *udata)
{
	const struct mptcp_pm_ops *upm;
	struct mptcp_pm_ops *pm;
	u32 moff;

	upm = (const struct mptcp_pm_ops *)udata;
	pm = (struct mptcp_pm_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct mptcp_pm_ops, name):
		if (bpf_obj_name_cpy(pm->name, upm->name,
				     sizeof(pm->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int bpf_mptcp_pm_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_sock",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_sock_id = type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_pm_addr_entry",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_entry_id = type_id;

	return 0;
}

static int bpf_mptcp_pm_validate(void *kdata)
{
	return mptcp_pm_validate(kdata);
}

static int __bpf_mptcp_pm_get_local_id(struct mptcp_sock *msk,
				       struct mptcp_pm_addr_entry *skc)
{
	return 0;
}

static bool __bpf_mptcp_pm_get_priority(struct mptcp_sock *msk,
					struct mptcp_addr_info *skc)
{
	return false;
}

static void __bpf_mptcp_pm_established(struct mptcp_sock *msk)
{
}

static void __bpf_mptcp_pm_subflow_established(struct mptcp_sock *msk)
{
}

static bool __bpf_mptcp_pm_allow_new_subflow(struct mptcp_sock *msk)
{
	return false;
}

static bool __bpf_mptcp_pm_accept_new_subflow(const struct mptcp_sock *msk)
{
	return false;
}

static bool __bpf_mptcp_pm_add_addr_echo(struct mptcp_sock *msk,
					 const struct mptcp_addr_info *addr)
{
	return false;
}

static int __bpf_mptcp_pm_add_addr_received(struct mptcp_sock *msk,
					    const struct mptcp_addr_info *addr)
{
	return 0;
}

static void __bpf_mptcp_pm_rm_addr_received(struct mptcp_sock *msk)
{
}

static void __bpf_mptcp_pm_init(struct mptcp_sock *msk)
{
}

static void __bpf_mptcp_pm_release(struct mptcp_sock *msk)
{
}

static struct mptcp_pm_ops __bpf_mptcp_pm_ops = {
	.get_local_id		= __bpf_mptcp_pm_get_local_id,
	.get_priority		= __bpf_mptcp_pm_get_priority,
	.established		= __bpf_mptcp_pm_established,
	.subflow_established	= __bpf_mptcp_pm_subflow_established,
	.allow_new_subflow      = __bpf_mptcp_pm_allow_new_subflow,
	.accept_new_subflow     = __bpf_mptcp_pm_accept_new_subflow,
	.add_addr_echo		= __bpf_mptcp_pm_add_addr_echo,
	.add_addr_received	= __bpf_mptcp_pm_add_addr_received,
	.rm_addr_received	= __bpf_mptcp_pm_rm_addr_received,
	.init			= __bpf_mptcp_pm_init,
	.release		= __bpf_mptcp_pm_release,
};

static struct bpf_struct_ops bpf_mptcp_pm_ops = {
	.verifier_ops	= &bpf_mptcp_pm_verifier_ops,
	.reg		= bpf_mptcp_pm_reg,
	.unreg		= bpf_mptcp_pm_unreg,
	.check_member	= bpf_mptcp_pm_check_member,
	.init_member	= bpf_mptcp_pm_init_member,
	.init		= bpf_mptcp_pm_init,
	.validate	= bpf_mptcp_pm_validate,
	.name		= "mptcp_pm_ops",
	.cfi_stubs	= &__bpf_mptcp_pm_ops,
};

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

__bpf_kfunc static struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk__ign)
{
	const struct sock *sk = sk__ign;

	if (sk && sk_fullsock(sk) &&
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

	if (unlikely(!sk || !sk_fullsock(sk)))
		return -EINVAL;

	if (sk->sk_protocol != IPPROTO_MPTCP)
		return -EINVAL;

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

__bpf_kfunc static struct mptcp_pm_addr_entry *
bpf_kmemdup_entry(struct mptcp_pm_addr_entry *entry, int size, gfp_t priority)
{
	return kmemdup(entry, size, priority);
}

__bpf_kfunc static void
bpf_kfree_entry(struct mptcp_pm_addr_entry *entry)
{
	kfree(entry);
}

__bpf_kfunc static void bpf_set_bit(unsigned long nr, unsigned long *addr__ign)
{
	__set_bit(nr, addr__ign);
}

__bpf_kfunc static void bpf_bitmap_fill(unsigned long *dst__ign, unsigned int nbits)
{
	bitmap_fill(dst__ign, nbits);
}

__bpf_kfunc static void bpf_spin_lock_bh(spinlock_t *lock)
{
	spin_lock_bh(lock);
}

__bpf_kfunc static void bpf_spin_unlock_bh(spinlock_t *lock)
{
	spin_unlock_bh(lock);
}

__bpf_kfunc static bool bpf_mptcp_subflow_queues_empty(struct sock *sk)
{
	return tcp_rtx_queue_empty(sk);
}

__bpf_kfunc static bool bpf_sk_stream_memory_free(const struct sock *sk__ign)
{
	const struct sock *sk = sk__ign;

	if (sk && sk_fullsock(sk) &&
	    sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return sk_stream_memory_free(sk);

	return NULL;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mptcp_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_ctx, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_tcp_sock, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_kmemdup_entry)
BTF_ID_FLAGS(func, bpf_kfree_entry)
BTF_ID_FLAGS(func, bpf_set_bit)
BTF_ID_FLAGS(func, bpf_bitmap_fill)
BTF_ID_FLAGS(func, bpf_spin_lock_bh)
BTF_ID_FLAGS(func, bpf_spin_unlock_bh)
BTF_ID_FLAGS(func, mptcp_pm_nl_lookup_addr)
BTF_ID_FLAGS(func, mptcp_pm_nl_append_new_local_addr_msk)
BTF_ID_FLAGS(func, mptcp_pm_get_add_addr_signal_max)
BTF_ID_FLAGS(func, mptcp_pm_get_add_addr_accept_max)
BTF_ID_FLAGS(func, mptcp_pm_get_subflows_max)
BTF_ID_FLAGS(func, mptcp_pm_get_local_addr_max)
BTF_ID_FLAGS(func, mptcp_pm_add_addr_recv)
BTF_ID_FLAGS(func, mptcp_pm_is_init_remote_addr)
BTF_ID_FLAGS(func, mptcp_pm_create_subflow_or_signal_addr)
BTF_ID_FLAGS(func, mptcp_pm_rm_addr_recv)
BTF_ID_FLAGS(func, mptcp_subflow_set_scheduled)
BTF_ID_FLAGS(func, mptcp_subflow_active)
BTF_ID_FLAGS(func, mptcp_set_timeout)
BTF_ID_FLAGS(func, mptcp_wnd_end)
BTF_ID_FLAGS(func, bpf_sk_stream_memory_free, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_queues_empty)
BTF_ID_FLAGS(func, mptcp_pm_subflow_chk_stale, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_mptcp_common_kfunc_ids)

static const struct btf_kfunc_id_set bpf_mptcp_common_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_common_kfunc_ids,
};

static int __init bpf_mptcp_kfunc_init(void)
{
	int ret;

	ret = register_btf_fmodret_id_set(&bpf_mptcp_fmodret_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_CGROUP_SOCKOPT,
					       &bpf_mptcp_common_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &bpf_mptcp_common_kfunc_set);
#ifdef CONFIG_BPF_JIT
	ret = ret ?: register_bpf_struct_ops(&bpf_mptcp_pm_ops, mptcp_pm_ops);
	ret = ret ?: register_bpf_struct_ops(&bpf_mptcp_sched_ops, mptcp_sched_ops);
#endif

	return ret;
}
late_initcall(bpf_mptcp_kfunc_init);
