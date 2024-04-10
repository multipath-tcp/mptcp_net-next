// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */
/* Copyright (c) 2024, Kylin Software */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/mptcp_sched_bkup_init")
void BPF_PROG(mptcp_sched_bkup_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_bkup_release")
void BPF_PROG(mptcp_sched_bkup_release, struct mptcp_sock *msk)
{
}

int BPF_STRUCT_OPS(bpf_bkup_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	int nr = -1;

	for (int i = 0; i < data->subflows && i < MPTCP_SUBFLOWS_MAX; i++) {
		struct mptcp_subflow_context *subflow;

		subflow = bpf_mptcp_subflow_ctx_by_pos(data, i);
		if (!subflow)
			break;

		if (!BPF_CORE_READ_BITFIELD_PROBED(subflow, backup)) {
			nr = i;
			break;
		}
	}

	if (nr != -1) {
		mptcp_subflow_set_scheduled(bpf_mptcp_subflow_ctx_by_pos(data, nr), true);
		return -1;
	}
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops bkup = {
	.init		= (void *)mptcp_sched_bkup_init,
	.release	= (void *)mptcp_sched_bkup_release,
	.get_subflow	= (void *)bpf_bkup_get_subflow,
	.name		= "bpf_bkup",
};
