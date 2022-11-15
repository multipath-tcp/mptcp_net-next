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
					     const struct btf *btf,
					     const struct btf_type *t, int off,
					     int size, enum bpf_access_type atype,
					     u32 *next_btf_id,
					     enum bpf_type_flag *flag)
{
	size_t end;

	if (atype == BPF_READ) {
		return btf_struct_access(log, btf, t, off, size, atype,
					 next_btf_id, flag);
	}

	if (t != mptcp_sched_type) {
		bpf_log(log, "only access to mptcp_subflow_context is supported\n");
		return -EACCES;
	}

	switch (off) {
	case offsetof(struct mptcp_subflow_context, scheduled):
		end = offsetofend(struct mptcp_subflow_context, scheduled);
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
					const struct btf_member *member)
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
#endif /* CONFIG_BPF_JIT */

struct mptcp_sock *bpf_mptcp_sock_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_sk(mptcp_subflow_ctx(sk)->conn);

	return NULL;
}
