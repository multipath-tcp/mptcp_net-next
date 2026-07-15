// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026, MPTCP. */

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops")
void BPF_PROG(mptcp_sched_avoid_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_avoid_release, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
int BPF_PROG(bpf_avoid_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	int i = 0;

	/* bench every subflow except the first one */
	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		if (i++ > 0)
			mptcp_subflow_set_avoid(subflow, true);
	}

	/* only schedule a subflow that is NOT avoided */
	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		if (subflow->avoid)
			continue;
		if (mptcp_subflow_active(subflow)) {
			mptcp_subflow_set_scheduled(subflow, true);
			break;
		}
	}
	return 0;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops avoid = {
	.init		= (void *)mptcp_sched_avoid_init,
	.release	= (void *)mptcp_sched_avoid_release,
	.get_send	= (void *)bpf_avoid_get_send,
	.name		= "bpf_avoid",
};
