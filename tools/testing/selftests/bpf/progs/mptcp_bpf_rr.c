// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

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

SEC("struct_ops/mptcp_sched_rr_init")
void BPF_PROG(mptcp_sched_rr_init, struct mptcp_sock *msk)
{
	bpf_sk_storage_get(&mptcp_rr_map, msk, 0,
			   BPF_LOCAL_STORAGE_GET_F_CREATE);
}

SEC("struct_ops/mptcp_sched_rr_release")
void BPF_PROG(mptcp_sched_rr_release, struct mptcp_sock *msk)
{
	bpf_sk_storage_delete(&mptcp_rr_map, msk);
}

int BPF_STRUCT_OPS(bpf_rr_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_rr_storage *ptr;
	struct sock *last_snd = NULL;
	int nr = 0;

	ptr = bpf_sk_storage_get(&mptcp_rr_map, msk, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return -1;

	last_snd = ptr->last_snd;

	for (int i = 0; i < data->subflows && i < MPTCP_SUBFLOWS_MAX; i++) {
		subflow = bpf_mptcp_subflow_ctx_by_pos(data, i);
		if (!last_snd || !subflow)
			break;

		if (mptcp_subflow_tcp_sock(subflow) == last_snd) {
			if (i + 1 == MPTCP_SUBFLOWS_MAX ||
			    !bpf_mptcp_subflow_ctx_by_pos(data, i + 1))
				break;

			nr = i + 1;
			break;
		}
	}

	subflow = bpf_mptcp_subflow_ctx_by_pos(data, nr);
	if (!subflow)
		return -1;
	mptcp_subflow_set_scheduled(subflow, true);
	ptr->last_snd = mptcp_subflow_tcp_sock(subflow);
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops rr = {
	.init		= (void *)mptcp_sched_rr_init,
	.release	= (void *)mptcp_sched_rr_release,
	.get_subflow	= (void *)bpf_rr_get_subflow,
	.name		= "bpf_rr",
};
