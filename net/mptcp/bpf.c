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
#include "protocol.h"

#ifdef CONFIG_BPF_JIT
extern struct bpf_struct_ops bpf_mptcp_sched_ops;
extern struct btf *btf_vmlinux;
static const struct btf_type *mptcp_context_type __read_mostly;
static const struct btf_type *mptcp_data_type __read_mostly;
static u32 mptcp_context_id, mptcp_data_id;

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
	if (t != mptcp_context_type && t != mptcp_data_type) {
		bpf_log(log, "only access to subflow_context or sched_data is supported\n");
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
	case offsetof(struct mptcp_sched_data, snd_burst):
		end = offsetofend(struct mptcp_sched_data, snd_burst);
		break;
	default:
		bpf_log(log, "no write support to %s at off %d\n",
			t == mptcp_context_type ? "subflow_context" : "sched_data", off);
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log, "access beyond %s at off %u size %u ended at %zu",
			t == mptcp_context_type ? "subflow_context" : "sched_data", off, size, end);
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
	mptcp_context_id = type_id;
	mptcp_context_type = btf_type_by_id(btf, mptcp_context_id);

	type_id = btf_find_by_name_kind(btf, "mptcp_sched_data",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	mptcp_data_id = type_id;
	mptcp_data_type = btf_type_by_id(btf, mptcp_data_id);

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

bool bpf_sk_stream_memory_free(struct mptcp_subflow_context *subflow)
{
	const struct sock *ssk = mptcp_subflow_tcp_sock(subflow);

	return sk_stream_memory_free(ssk);
}

bool bpf_tcp_rtx_and_write_queues_empty(const struct sock *sk)
{
	return tcp_rtx_and_write_queues_empty(sk);
}

BTF_SET8_START(bpf_mptcp_sched_kfunc_ids)
BTF_ID_FLAGS(func, mptcp_subflow_set_scheduled)
BTF_ID_FLAGS(func, mptcp_sched_data_set_contexts)
BTF_ID_FLAGS(func, mptcp_subflow_active)
BTF_ID_FLAGS(func, mptcp_timeout_from_subflow)
BTF_ID_FLAGS(func, mptcp_set_timer)
BTF_ID_FLAGS(func, mptcp_wnd_end)
BTF_ID_FLAGS(func, bpf_sk_stream_memory_free)
BTF_ID_FLAGS(func, bpf_tcp_rtx_and_write_queues_empty)
BTF_ID_FLAGS(func, mptcp_pm_subflow_chk_stale)
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
#endif /* CONFIG_BPF_JIT */

struct mptcp_sock *bpf_mptcp_sock_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_sk(mptcp_subflow_ctx(sk)->conn);

	return NULL;
}
