// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026, Mpiric Software. */

/* A scheduler that passes a subflow TCP socket to bpf_mptcp_set_timeout(),
 * which takes a struct mptcp_sock *. The verifier must reject this at load
 * time; see the bad_sched subtest in prog_tests/mptcp.c.
 */
#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern void bpf_mptcp_set_timeout(struct mptcp_sock *msk) __ksym;

SEC("struct_ops")
void BPF_PROG(bad_sched_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(bad_sched_release, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
int BPF_PROG(bad_sched_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	struct sock *ssk;

	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		ssk = bpf_mptcp_subflow_tcp_sock(subflow);
		if (!ssk)
			return -1;
		/* ssk is a subflow TCP socket (struct sock *), not an msk.
		 * Passing it to bpf_mptcp_set_timeout(), which takes a
		 * struct mptcp_sock *, is a socket type confusion that the
		 * verifier must reject at load time ("expected pointer to
		 * STRUCT mptcp_sock").
		 */
		bpf_mptcp_set_timeout((struct mptcp_sock *)ssk);
		mptcp_subflow_set_scheduled(subflow, true);
		return 0;
	}
	return -1;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops bad_sched = {
	.init		= (void *)bad_sched_init,
	.release	= (void *)bad_sched_release,
	.get_send	= (void *)bad_sched_get_send,
	.name		= "bpf_bad_sched",
};
