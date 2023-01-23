// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/mptcp_sched_rr_init")
void BPF_PROG(mptcp_sched_rr_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_rr_release")
void BPF_PROG(mptcp_sched_rr_release, const struct mptcp_sock *msk)
{
}

void BPF_STRUCT_OPS(bpf_rr_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
	mptcp_sched_data_set_contexts(msk, data);
}

int BPF_STRUCT_OPS(bpf_rr_get_subflow, const struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	int nr = 0;

	for (int i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		if (!msk->last_snd || !data->contexts[i])
			break;

		if (data->contexts[i]->tcp_sock == msk->last_snd) {
			if (i + 1 == MPTCP_SUBFLOWS_MAX || !data->contexts[i + 1])
				break;

			nr = i + 1;
			break;
		}
	}

	mptcp_subflow_set_scheduled(data->contexts[nr], true);
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops rr = {
	.init		= (void *)mptcp_sched_rr_init,
	.release	= (void *)mptcp_sched_rr_release,
	.data_init	= (void *)bpf_rr_data_init,
	.get_subflow	= (void *)bpf_rr_get_subflow,
	.name		= "bpf_rr",
};
