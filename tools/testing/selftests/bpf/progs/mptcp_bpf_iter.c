// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Kylin Software */

/* vmlinux.h, bpf_helpers.h and other 'define' */
#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";
int subflows;
int pid;

SEC("cgroup/getsockopt")
int mptcp_getsockopt(struct bpf_sockopt *ctx)
{
	struct mptcp_subflow_context *subflow;
	struct bpf_sock *sk = ctx->sk;
	struct mptcp_sock *msk;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 1;

	if (!sk || sk->protocol != IPPROTO_MPTCP ||
	    ctx->level != SOL_TCP || ctx->optname != TCP_CONGESTION)
		return 1;

	msk = bpf_mptcp_sock_acquire(bpf_mptcp_sk((struct sock *)sk));
	if (!msk)
		return 1;

	subflows = 0;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		if (subflow->token != msk->token) {
			ctx->retval = -1;
			break;
		}

		if (!mptcp_subflow_active(subflow))
			continue;

		subflows++;
	}
	bpf_mptcp_sock_release(msk);

	return 1;
}
