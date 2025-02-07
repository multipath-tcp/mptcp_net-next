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
static struct bpf_struct_ops bpf_mptcp_pm_ops;
static u32 mptcp_sock_id,
	   mptcp_entry_id;

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
		case offsetof(struct mptcp_pm_addr_entry, addr.family):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.family);
			break;
		case offsetof(struct mptcp_pm_addr_entry, addr.port):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.port);
			break;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		case offsetof(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[0]):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[0]);
			break;
		case offsetof(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[1]):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[1]);
			break;
		case offsetof(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[2]):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[2]);
			break;
		case offsetof(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[3]):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.addr6.s6_addr32[3]);
			break;
#else
		case offsetof(struct mptcp_pm_addr_entry, addr.addr.s_addr):
			end = offsetofend(struct mptcp_pm_addr_entry, addr.addr.s_addr);
			break;
#endif
		case offsetof(struct mptcp_pm_addr_entry, flags):
			end = offsetofend(struct mptcp_pm_addr_entry, flags);
			break;
		case offsetof(struct mptcp_pm_addr_entry, ifindex):
			end = offsetofend(struct mptcp_pm_addr_entry, ifindex);
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
	case offsetof(struct mptcp_pm_ops, type):
		pm->type = upm->type;
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

static int __bpf_mptcp_pm_address_created(struct mptcp_sock *msk)
{
	return 0;
}

static int __bpf_mptcp_pm_address_established(struct mptcp_sock *msk)
{
	return 0;
}

static int __bpf_mptcp_pm_address_closed(struct mptcp_sock *msk)
{
	return 0;
}

static int __bpf_mptcp_pm_address_announced(struct mptcp_sock *msk,
					    struct mptcp_pm_addr_entry *addr)
{
	return 0;
}

static int __bpf_mptcp_pm_address_removed(struct mptcp_sock *msk, u8 id)
{
	return 0;
}

static int __bpf_mptcp_pm_subflow_established(struct mptcp_sock *msk,
					      struct mptcp_pm_addr_entry *local,
					      struct mptcp_addr_info *remote)
{
	return 0;
}

static int __bpf_mptcp_pm_subflow_closed(struct mptcp_sock *msk,
					 struct mptcp_pm_addr_entry *local,
					 struct mptcp_addr_info *remote)
{
	return 0;
}

static int __bpf_mptcp_pm_get_local_id(struct mptcp_sock *msk,
				       struct mptcp_pm_addr_entry *skc)
{
	return 0;
}

static bool __bpf_mptcp_pm_get_priority(struct mptcp_sock *msk,
					struct mptcp_addr_info *skc)
{
	return 0;
}

static int __bpf_mptcp_pm_set_priority(struct mptcp_sock *msk,
				       struct mptcp_pm_addr_entry *local,
				       struct mptcp_addr_info *remote)
{
	return 0;
}

static int __bpf_mptcp_pm_address_listener_created(struct mptcp_sock *msk)
{
	return 0;
}

static int __bpf_mptcp_pm_address_listener_closed(struct mptcp_sock *msk)
{
	return 0;
}

static void __bpf_mptcp_pm_init(struct mptcp_sock *msk)
{
}

static void __bpf_mptcp_pm_release(struct mptcp_sock *msk)
{
}

static struct mptcp_pm_ops __bpf_mptcp_pm_ops = {
	.created		= __bpf_mptcp_pm_address_created,
	.established		= __bpf_mptcp_pm_address_established,
	.closed			= __bpf_mptcp_pm_address_closed,
	.address_announced	= __bpf_mptcp_pm_address_announced,
	.address_removed	= __bpf_mptcp_pm_address_removed,
	.subflow_established	= __bpf_mptcp_pm_subflow_established,
	.subflow_closed		= __bpf_mptcp_pm_subflow_closed,
	.get_local_id		= __bpf_mptcp_pm_get_local_id,
	.get_priority		= __bpf_mptcp_pm_get_priority,
	.set_priority		= __bpf_mptcp_pm_set_priority,
	.listener_created	= __bpf_mptcp_pm_address_listener_created,
	.listener_closed	= __bpf_mptcp_pm_address_listener_closed,
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

static struct bpf_struct_ops bpf_mptcp_sched_ops;
static const struct btf_type *mptcp_sock_type, *mptcp_subflow_type __read_mostly;
static u32 mptcp_subflow_id;

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
	const struct btf_type *t;
	size_t end;

	t = btf_type_by_id(reg->btf, reg->btf_id);

	if (t == mptcp_sock_type) {
		switch (off) {
		case offsetof(struct mptcp_sock, snd_burst):
			end = offsetofend(struct mptcp_sock, snd_burst);
			break;
		default:
			bpf_log(log, "no write support to mptcp_sock at off %d\n",
				off);
			return -EACCES;
		}
	} else if (t == mptcp_subflow_type) {
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
			t == mptcp_sock_type ? "mptcp_sock" : "mptcp_subflow_context",
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
	int ret;

	usched = (const struct mptcp_sched_ops *)udata;
	sched = (struct mptcp_sched_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct mptcp_sched_ops, name):
		if (bpf_obj_name_cpy(sched->name, usched->name,
				     sizeof(sched->name)) <= 0)
			return -EINVAL;

		rcu_read_lock();
		ret = mptcp_sched_find(usched->name) ? -EEXIST : 1;
		rcu_read_unlock();

		return ret;
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
	mptcp_sock_type = btf_type_by_id(btf, mptcp_sock_id);

	type_id = btf_find_by_name_kind(btf, "mptcp_subflow_context",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_subflow_id = type_id;
	mptcp_subflow_type = btf_type_by_id(btf, mptcp_subflow_id);

	return 0;
}

static int __bpf_mptcp_sched_get_send(struct mptcp_sock *msk,
				      struct mptcp_sched_data *data)
{
	return 0;
}

static int __bpf_mptcp_sched_get_retrans(struct mptcp_sock *msk,
					 struct mptcp_sched_data *data)
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
	.name		= "mptcp_sched_ops",
	.cfi_stubs	= &__bpf_mptcp_sched_ops,
};
#endif /* CONFIG_BPF_JIT */

struct mptcp_sock *bpf_mptcp_sock_from_sock(struct sock *sk)
{
	if (unlikely(!sk || !sk_fullsock(sk)))
		return NULL;

	if (sk->sk_protocol == IPPROTO_MPTCP)
		return mptcp_sk(sk);

	if (sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
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

struct bpf_iter_mptcp_userspace_pm_addr {
	__u64 __opaque[2];
} __aligned(8);

struct bpf_iter_mptcp_userspace_pm_addr_kern {
	struct mptcp_sock *msk;
	struct list_head *pos;
} __aligned(8);

__bpf_kfunc_start_defs();

__bpf_kfunc static struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk)
{
	if (sk && sk_fullsock(sk) &&
	    sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_subflow_ctx(sk);

	return NULL;
}

__bpf_kfunc static int
bpf_iter_mptcp_subflow_new(struct bpf_iter_mptcp_subflow *it,
			   struct mptcp_sock *msk)
{
	struct bpf_iter_mptcp_subflow_kern *kit = (void *)it;
	struct sock *sk = (struct sock *)msk;

	BUILD_BUG_ON(sizeof(struct bpf_iter_mptcp_subflow_kern) >
		     sizeof(struct bpf_iter_mptcp_subflow));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_mptcp_subflow_kern) !=
		     __alignof__(struct bpf_iter_mptcp_subflow));

	kit->msk = msk;
	if (!msk)
		return -EINVAL;

	if (!sock_owned_by_user_nocheck(sk) &&
	    !spin_is_locked(&sk->sk_lock.slock))
		return -EINVAL;

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

__bpf_kfunc static int
bpf_iter_mptcp_userspace_pm_addr_new(struct bpf_iter_mptcp_userspace_pm_addr *it,
				     struct sock *sk)
{
	struct bpf_iter_mptcp_userspace_pm_addr_kern *kit = (void *)it;
	struct mptcp_sock *msk;

	BUILD_BUG_ON(sizeof(struct bpf_iter_mptcp_userspace_pm_addr_kern) >
		     sizeof(struct bpf_iter_mptcp_userspace_pm_addr));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_mptcp_userspace_pm_addr_kern) !=
		     __alignof__(struct bpf_iter_mptcp_userspace_pm_addr));

	msk = bpf_mptcp_sock_from_sock(sk);
	if (!msk)
		return -EINVAL;

	if (!spin_is_locked(&msk->pm.lock))
		return -EINVAL;

	kit->msk = msk;
	kit->pos = &msk->pm.userspace_pm_local_addr_list;
	return 0;
}

__bpf_kfunc static struct mptcp_pm_addr_entry *
bpf_iter_mptcp_userspace_pm_addr_next(struct bpf_iter_mptcp_userspace_pm_addr *it)
{
	struct bpf_iter_mptcp_userspace_pm_addr_kern *kit = (void *)it;

	if (!kit->msk || list_is_last(kit->pos,
				      &kit->msk->pm.userspace_pm_local_addr_list))
		return NULL;

	kit->pos = kit->pos->next;
	return list_entry(kit->pos, struct mptcp_pm_addr_entry, list);
}

__bpf_kfunc static void
bpf_iter_mptcp_userspace_pm_addr_destroy(struct bpf_iter_mptcp_userspace_pm_addr *it)
{
}

__bpf_kfunc static void bpf_spin_lock_bh(spinlock_t *lock)
{
	spin_lock_bh(lock);
}

__bpf_kfunc static void bpf_spin_unlock_bh(spinlock_t *lock)
{
	spin_unlock_bh(lock);
}

__bpf_kfunc static bool bpf_ipv4_is_private_10(__be32 addr)
{
	return ipv4_is_private_10(addr);
}

__bpf_kfunc static bool bpf_mptcp_subflow_queues_empty(struct sock *sk)
{
	return tcp_rtx_queue_empty(sk);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mptcp_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_ctx, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_subflow_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_iter_mptcp_userspace_pm_addr_new, KF_ITER_NEW | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_iter_mptcp_userspace_pm_addr_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_mptcp_userspace_pm_addr_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_spin_lock_bh)
BTF_ID_FLAGS(func, bpf_spin_unlock_bh)
BTF_ID_FLAGS(func, bpf_ipv4_is_private_10)
BTF_ID_FLAGS(func, bpf_mptcp_sock_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_mptcp_sock_release, KF_RELEASE)
BTF_KFUNCS_END(bpf_mptcp_common_kfunc_ids)

static const struct btf_kfunc_id_set bpf_mptcp_common_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_common_kfunc_ids,
};

BTF_KFUNCS_START(bpf_mptcp_sched_kfunc_ids)
BTF_ID_FLAGS(func, mptcp_subflow_set_scheduled)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_ctx_by_pos)
BTF_ID_FLAGS(func, mptcp_subflow_active)
BTF_ID_FLAGS(func, mptcp_set_timeout)
BTF_ID_FLAGS(func, mptcp_wnd_end)
BTF_ID_FLAGS(func, tcp_stream_memory_free)
BTF_ID_FLAGS(func, bpf_mptcp_subflow_queues_empty)
BTF_ID_FLAGS(func, mptcp_pm_subflow_chk_stale, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_mptcp_sched_kfunc_ids)

static const struct btf_kfunc_id_set bpf_mptcp_sched_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_sched_kfunc_ids,
};

static int __init bpf_mptcp_kfunc_init(void)
{
	int ret;

	ret = register_btf_fmodret_id_set(&bpf_mptcp_fmodret_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_CGROUP_SOCKOPT,
					       &bpf_mptcp_common_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &bpf_mptcp_sched_kfunc_set);
#ifdef CONFIG_BPF_JIT
	ret = ret ?: register_bpf_struct_ops(&bpf_mptcp_pm_ops, mptcp_pm_ops);
	ret = ret ?: register_bpf_struct_ops(&bpf_mptcp_sched_ops, mptcp_sched_ops);
#endif

	return ret;
}
late_initcall(bpf_mptcp_kfunc_init);
