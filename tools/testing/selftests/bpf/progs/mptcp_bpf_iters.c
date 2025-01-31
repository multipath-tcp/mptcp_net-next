// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Kylin Software */

/* vmlinux.h, bpf_helpers.h and other 'define' */
#include "bpf_tracing_net.h"
#include "mptcp_bpf.h"

char _license[] SEC("license") = "GPL";
int ids;

#ifndef TCP_IS_MPTCP
#define TCP_IS_MPTCP		43	/* Is MPTCP being used? */
#endif

SEC("cgroup/getsockopt")
int iters_subflow(struct bpf_sockopt *ctx)
{
	struct mptcp_subflow_context *subflow;
	struct bpf_sock *sk = ctx->sk;
	struct sock *ssk = NULL;
	struct mptcp_sock *msk;
	int local_ids = 0;

	if (ctx->level != SOL_TCP || ctx->optname != TCP_IS_MPTCP)
		return 1;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (!msk || msk->pm.server_side || !msk->pm.subflows)
		return 1;

	msk = bpf_mptcp_sock_acquire(msk);
	if (!msk)
		return 1;
	bpf_for_each(mptcp_subflow, subflow, msk) {
		/* Here MPTCP-specific packet scheduler kfunc can be called:
		 * this test is not doing anything really useful, only to
		 * verify the iteration works.
		 */

		local_ids += subflow->subflow_id;

		/* only to check the following kfunc works */
		ssk = mptcp_subflow_tcp_sock(subflow);
	}

	if (!ssk)
		goto out;

	/* assert: if not OK, something wrong on the kernel side */
	if (ssk->sk_dport != ((struct sock *)msk)->sk_dport)
		goto out;

	/* only to check the following kfunc works */
	subflow = bpf_mptcp_subflow_ctx(ssk);
	if (!subflow || subflow->token != msk->token)
		goto out;

	ids = local_ids;

out:
	bpf_mptcp_sock_release(msk);
	return 1;
}
