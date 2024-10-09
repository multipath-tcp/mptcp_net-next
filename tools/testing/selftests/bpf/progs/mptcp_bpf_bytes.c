// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Kylin Software */

/* vmlinux.h, bpf_helpers.h and other 'define' */
#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";
u64 bytes_sent_1 = 0;
u64 bytes_sent_2 = 0;
int pid;

SEC("fexit/mptcp_sched_get_send")
int BPF_PROG(trace_mptcp_sched_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	if (!msk->pm.server_side)
		return 0;

	mptcp_for_each_subflow(msk, subflow) {
		struct tcp_sock *tp;
		struct sock *ssk;

		subflow = bpf_core_cast(subflow, struct mptcp_subflow_context);
		ssk = mptcp_subflow_tcp_sock(subflow);
		tp = bpf_core_cast(ssk, struct tcp_sock);

		if (subflow->subflow_id == 1)
			bytes_sent_1 = tp->bytes_sent;
		else if (subflow->subflow_id == 2)
			bytes_sent_2 = tp->bytes_sent;
	}

	return 0;
}
