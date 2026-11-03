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
int BPF_PROG(bpf_first_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	struct sock *ssk;

	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		ssk = bpf_mptcp_subflow_tcp_sock(subflow);
		if (ssk == msk->first) {
			mptcp_subflow_set_scheduled(subflow, true);
			return 0;
		}
	}
	return -1;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops first = {
	.init		= (void *)mptcp_sched_first_init,
	.release	= (void *)mptcp_sched_first_release,
	.get_send	= (void *)bpf_first_get_send,
	.name		= "bpf_first",
};
