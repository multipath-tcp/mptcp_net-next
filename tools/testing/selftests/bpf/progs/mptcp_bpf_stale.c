// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

static void mptcp_subflow_set_stale(struct mptcp_subflow_context *subflow,
				    int stale)
{
	subflow->stale = stale;
}

SEC("struct_ops/mptcp_sched_stale_init")
void BPF_PROG(mptcp_sched_stale_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_stale_release")
void BPF_PROG(mptcp_sched_stale_release, const struct mptcp_sock *msk)
{
}

void BPF_STRUCT_OPS(bpf_stale_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;

	mptcp_sched_data_set_contexts(msk, data);
	subflow = mptcp_subflow_ctx_by_pos(msk, 1);
	if (subflow)
		mptcp_subflow_set_stale(subflow, 1);
}

int BPF_STRUCT_OPS(bpf_stale_get_subflow, const struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	int nr = 0;

	for (int i = 0; i < data->subflows && i < MPTCP_SUBFLOWS_MAX; i++) {
		struct mptcp_subflow_context *subflow;

		subflow = mptcp_subflow_ctx_by_pos(msk, i);
		if (!subflow)
			break;

		if (!BPF_CORE_READ_BITFIELD_PROBED(subflow, stale))
			break;

		nr = i;
	}

	mptcp_subflow_set_scheduled(mptcp_subflow_ctx_by_pos(msk, nr), true);
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops stale = {
	.init		= (void *)mptcp_sched_stale_init,
	.release	= (void *)mptcp_sched_stale_release,
	.data_init	= (void *)bpf_stale_data_init,
	.get_subflow	= (void *)bpf_stale_get_subflow,
	.name		= "bpf_stale",
};
