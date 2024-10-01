// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Kylin Software */

/* vmlinux.h, bpf_helpers.h and other 'define' */
#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";
int subflows;
int pid;

SEC("fentry/mptcp_sched_get_send")
int BPF_PROG(trace_mptcp_sched_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	msk = bpf_mptcp_sock_acquire(msk);
	if (!msk)
		return 0;

	subflows = 0;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		if (subflow->token != msk->token)
			break;

		if (!mptcp_subflow_active(subflow))
			continue;

		mptcp_subflow_set_scheduled(subflow, false);
		subflows++;
	}
	bpf_mptcp_sock_release(msk);

	return 0;
}
