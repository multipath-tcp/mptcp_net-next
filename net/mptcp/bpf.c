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
#include <linux/bpf_local_storage.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include "protocol.h"

#ifdef CONFIG_BPF_JIT
extern struct bpf_struct_ops bpf_mptcp_sched_ops;
extern struct btf *btf_vmlinux;
static const struct btf_type *mptcp_sched_type __read_mostly;
static u32 mptcp_sched_id;

static u32 optional_sched_ops[] = {
	offsetof(struct mptcp_sched_ops, init),
	offsetof(struct mptcp_sched_ops, release),
};

static const struct bpf_func_proto *
bpf_mptcp_sched_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id);
}

static int bpf_mptcp_sched_btf_struct_access(struct bpf_verifier_log *log,
					     const struct bpf_reg_state *reg,
					     int off, int size)
{
	const struct btf_type *t;
	size_t end;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t != mptcp_sched_type) {
		bpf_log(log, "only access to mptcp_subflow_context is supported\n");
		return -EACCES;
	}

	switch (off) {
	case offsetof(struct mptcp_subflow_context, scheduled):
		end = offsetofend(struct mptcp_subflow_context, scheduled);
		break;
	case offsetofend(struct mptcp_subflow_context, map_csum_len):
		end = offsetof(struct mptcp_subflow_context, data_avail);
		break;
	case offsetof(struct mptcp_subflow_context, avg_pacing_rate):
		end = offsetofend(struct mptcp_subflow_context, avg_pacing_rate);
		break;
	default:
		bpf_log(log, "no write support to mptcp_subflow_context at off %d\n", off);
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log, "access beyond mptcp_subflow_context at off %u size %u ended at %zu",
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

static int bpf_mptcp_sched_reg(void *kdata)
{
	return mptcp_register_scheduler(kdata);
}

static void bpf_mptcp_sched_unreg(void *kdata)
{
	mptcp_unregister_scheduler(kdata);
}

static int bpf_mptcp_sched_check_member(const struct btf_type *t,
					const struct btf_member *member,
					const struct bpf_prog *prog)
{
	return 0;
}

static bool is_optional_sched(u32 member_offset)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(optional_sched_ops); i++) {
		if (member_offset == optional_sched_ops[i])
			return true;
	}

	return false;
}

static int bpf_mptcp_sched_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	const struct mptcp_sched_ops *usched;
	struct mptcp_sched_ops *sched;
	int prog_fd;
	u32 moff;

	usched = (const struct mptcp_sched_ops *)udata;
	sched = (struct mptcp_sched_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct mptcp_sched_ops, name):
		if (bpf_obj_name_cpy(sched->name, usched->name,
				     sizeof(sched->name)) <= 0)
			return -EINVAL;
		if (mptcp_sched_find(usched->name))
			return -EEXIST;
		return 1;
	}

	if (!btf_type_resolve_func_ptr(btf_vmlinux, member->type, NULL))
		return 0;

	/* Ensure bpf_prog is provided for compulsory func ptr */
	prog_fd = (int)(*(unsigned long *)(udata + moff));
	if (!prog_fd && !is_optional_sched(moff))
		return -EINVAL;

	return 0;
}

static int bpf_mptcp_sched_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "mptcp_subflow_context",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_sched_id = type_id;
	mptcp_sched_type = btf_type_by_id(btf, mptcp_sched_id);

	return 0;
}

struct bpf_struct_ops bpf_mptcp_sched_ops = {
	.verifier_ops	= &bpf_mptcp_sched_verifier_ops,
	.reg		= bpf_mptcp_sched_reg,
	.unreg		= bpf_mptcp_sched_unreg,
	.check_member	= bpf_mptcp_sched_check_member,
	.init_member	= bpf_mptcp_sched_init_member,
	.init		= bpf_mptcp_sched_init,
	.name		= "mptcp_sched_ops",
};

BTF_SET8_START(bpf_mptcp_sched_kfunc_ids)
BTF_ID_FLAGS(func, mptcp_subflow_set_scheduled)
BTF_ID_FLAGS(func, mptcp_sched_data_set_contexts)
BTF_ID_FLAGS(func, mptcp_subflow_ctx_by_pos)
BTF_SET8_END(bpf_mptcp_sched_kfunc_ids)

static const struct btf_kfunc_id_set bpf_mptcp_sched_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &bpf_mptcp_sched_kfunc_ids,
};

static int __init bpf_mptcp_sched_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					 &bpf_mptcp_sched_kfunc_set);
}
late_initcall(bpf_mptcp_sched_kfunc_init);

/* mptcp sched storage */
DEFINE_BPF_STORAGE_CACHE(mptcp_cache);

static DEFINE_PER_CPU(int, bpf_mptcp_storage_busy);

BTF_ID_LIST_GLOBAL_SINGLE(bpf_mptcp_btf_id, struct, mptcp_sock)

static void bpf_mptcp_storage_lock(void)
{
	migrate_disable();
	this_cpu_inc(bpf_mptcp_storage_busy);
}

static void bpf_mptcp_storage_unlock(void)
{
	this_cpu_dec(bpf_mptcp_storage_busy);
	migrate_enable();
}

static bool bpf_mptcp_storage_trylock(void)
{
	migrate_disable();
	if (unlikely(this_cpu_inc_return(bpf_mptcp_storage_busy) != 1)) {
		this_cpu_dec(bpf_mptcp_storage_busy);
		migrate_enable();
		return false;
	}
	return true;
}

static struct bpf_local_storage __rcu **mptcp_storage_ptr(void *owner)
{
	struct mptcp_sock *msk = owner;

	return &msk->bpf_storage;
}

static struct bpf_local_storage_data *
mptcp_storage_lookup(struct mptcp_sock *msk, struct bpf_map *map,
		     bool cacheit_lockit)
{
	struct bpf_local_storage *msk_storage;
	struct bpf_local_storage_map *smap;

	msk_storage = rcu_dereference_check(msk->bpf_storage, bpf_rcu_lock_held());
	if (!msk_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(msk_storage, smap, cacheit_lockit);
}

static void *bpf_mptcp_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct mptcp_sock *msk;
	struct socket *sock;
	int err, fd;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return NULL;

	msk = bpf_mptcp_sock_from_subflow(sock->sk);
	if (!msk)
		return NULL;

	bpf_mptcp_storage_lock();
	sdata = mptcp_storage_lookup(msk, map, true);
	bpf_mptcp_storage_unlock();
	fput(sock->file);
	return sdata ? sdata->data : NULL;
}

static long bpf_mptcp_storage_update_elem(struct bpf_map *map, void *key,
					  void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct mptcp_sock *msk;
	struct socket *sock;
	int err, fd;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return PTR_ERR(sock);

	msk = bpf_mptcp_sock_from_subflow(sock->sk);
	if (IS_ERR(msk))
		return PTR_ERR(msk);

	bpf_mptcp_storage_lock();
	sdata = bpf_local_storage_update(msk, (struct bpf_local_storage_map *)map,
					 value, map_flags, GFP_ATOMIC);
	bpf_mptcp_storage_unlock();
	fput(sock->file);
	return PTR_ERR_OR_ZERO(sdata);
}

static int mptcp_storage_delete(struct mptcp_sock *msk, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = mptcp_storage_lookup(msk, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata), false);
	return 0;
}

static long bpf_mptcp_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct mptcp_sock *msk;
	struct socket *sock;
	int ret, err, fd;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return PTR_ERR(sock);

	msk = bpf_mptcp_sock_from_subflow(sock->sk);
	if (IS_ERR(msk))
		return PTR_ERR(msk);

	bpf_mptcp_storage_lock();
	ret = mptcp_storage_delete(msk, map);
	bpf_mptcp_storage_unlock();
	fput(sock->file);
	return ret;
}

/* Called by bpf_mptcp_storage_get*() helpers */
static void *__bpf_mptcp_storage_get(struct bpf_map *map,
				     struct mptcp_sock *msk, void *value,
				     u64 flags, gfp_t gfp_flags, bool nobusy)
{
        struct bpf_local_storage_data *sdata;

        sdata = mptcp_storage_lookup(msk, map, nobusy);
        if (sdata)
                return sdata->data;

        if ((flags & BPF_LOCAL_STORAGE_GET_F_CREATE) && nobusy) {
                sdata = bpf_local_storage_update(
                        msk, (struct bpf_local_storage_map *)map, value,
                        BPF_NOEXIST, gfp_flags);
                return IS_ERR(sdata) ? NULL : sdata->data;
        }

        return NULL;
}

/* *gfp_flags* is a hidden argument provided by the verifier */
BPF_CALL_5(bpf_mptcp_storage_get, struct bpf_map *, map, struct mptcp_sock *, msk,
	   void *, value, u64, flags, gfp_t, gfp_flags)
{
	void *data;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (flags & ~BPF_LOCAL_STORAGE_GET_F_CREATE || !msk)
		return (unsigned long)NULL;

	bpf_mptcp_storage_lock();
	data = __bpf_mptcp_storage_get(map, msk, value, flags, gfp_flags, true);
	bpf_mptcp_storage_unlock();
	return (unsigned long)data;
}

BPF_CALL_2(bpf_mptcp_storage_delete, struct bpf_map *, map, struct mptcp_sock *, msk)
{
	int ret;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!msk)
		return -EINVAL;

	if (!bpf_mptcp_storage_trylock())
		return -EBUSY;

	ret = mptcp_storage_delete(msk, map);
	bpf_mptcp_storage_unlock();
	return ret;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *mptcp_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &mptcp_cache, true);
}

static void mptcp_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &mptcp_cache, &bpf_mptcp_storage_busy);
}

const struct bpf_map_ops mptcp_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = mptcp_storage_map_alloc,
	.map_free = mptcp_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_mptcp_storage_lookup_elem,
	.map_update_elem = bpf_mptcp_storage_update_elem,
	.map_delete_elem = bpf_mptcp_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_mem_usage = bpf_local_storage_map_mem_usage,
	.map_btf_id = &bpf_local_storage_map_btf_id[0],
	.map_owner_storage_ptr = mptcp_storage_ptr,
};

const struct bpf_func_proto bpf_mptcp_storage_get_proto = {
	.func = bpf_mptcp_storage_get,
	.gpl_only = false,
	.ret_type = RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id = &bpf_mptcp_btf_id[0],
	.arg3_type = ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_mptcp_storage_delete_proto = {
	.func           = bpf_mptcp_storage_delete,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id    = &bpf_mptcp_btf_id[0],
};
#endif /* CONFIG_BPF_JIT */

struct mptcp_sock *bpf_mptcp_sock_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_sk(mptcp_subflow_ctx(sk)->conn);

	return NULL;
}
