// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops")
void BPF_PROG(mptcp_sched_first_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_first_release, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
int BPF_PROG(bpf_first_get_subflow, struct mptcp_sock *msk,
	     struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		mptcp_subflow_set_scheduled(subflow, true);
		break;
	}

	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops first = {
	.init		= (void *)mptcp_sched_first_init,
	.release	= (void *)mptcp_sched_first_release,
	.get_subflow	= (void *)bpf_first_get_subflow,
	.name		= "bpf_first",
};
