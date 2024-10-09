// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct mptcp_rr_storage {
	struct sock *last_snd;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mptcp_rr_storage);
} mptcp_rr_map SEC(".maps");

SEC("struct_ops")
void BPF_PROG(mptcp_sched_rr_init, struct mptcp_sock *msk)
{
	bpf_sk_storage_get(&mptcp_rr_map, msk, 0,
			   BPF_LOCAL_STORAGE_GET_F_CREATE);
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_rr_release, struct mptcp_sock *msk)
{
	bpf_sk_storage_delete(&mptcp_rr_map, msk);
}

SEC("struct_ops")
int BPF_PROG(bpf_rr_get_subflow, struct mptcp_sock *msk,
	     struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow, *next;
	struct mptcp_rr_storage *ptr;
	struct sock *last_snd = NULL;

	ptr = bpf_sk_storage_get(&mptcp_rr_map, msk, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return -1;

	last_snd = ptr->last_snd;
	next = bpf_mptcp_subflow_ctx(msk->first);

	bpf_for_each(mptcp_subflow, subflow, msk) {
		if (!last_snd)
			break;

		if (bpf_mptcp_subflow_tcp_sock(subflow) == last_snd) {
			subflow = bpf_iter_mptcp_subflow_next(&___it);
			if (!subflow)
				break;

			next = subflow;
			break;
		}
	}

	mptcp_subflow_set_scheduled(next, true);
	ptr->last_snd = bpf_mptcp_subflow_tcp_sock(next);
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops rr = {
	.init		= (void *)mptcp_sched_rr_init,
	.release	= (void *)mptcp_sched_rr_release,
	.get_subflow	= (void *)bpf_rr_get_subflow,
	.name		= "bpf_rr",
};
