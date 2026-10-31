// SPDX-License-Identifier: GPL-2.0

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* get_retrans calls, by msk->sched_retrans */
__u64 calls[4] = {};

SEC("struct_ops")
void BPF_PROG(mptcp_sched_reinject_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_reinject_release, struct mptcp_sock *msk)
{
}

/* new data only on the first subflow, as bpf_first */
SEC("struct_ops")
int BPF_PROG(bpf_reinject_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		if (bpf_mptcp_subflow_tcp_sock(subflow) == msk->first) {
			mptcp_subflow_set_scheduled(subflow, true);
			return 0;
		}
	}
	return -1;
}

/* On an MPTCP RTO, resend on the first subflow. When the core asks because
 * a subflow is idle, resend up to 64 KB of what the first subflow holds on
 * another one, so the second address only carries reinjected data.
 */
SEC("struct_ops")
int BPF_PROG(bpf_reinject_get_retrans, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	__u8 reason = msk->sched_retrans;
	bool idle = reason != MPTCP_SCHED_RETRANS_RTO;

	if (reason < 4)
		__sync_fetch_and_add(&calls[reason], 1);

	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		bool first = bpf_mptcp_subflow_tcp_sock(subflow) == msk->first;

		if (first == idle)
			continue;
		if (idle)
			subflow->reinject_limit = 64 * 1024;
		mptcp_subflow_set_scheduled(subflow, true);
		return 0;
	}
	return -1;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops reinject = {
	.init		= (void *)mptcp_sched_reinject_init,
	.release	= (void *)mptcp_sched_reinject_release,
	.get_send	= (void *)bpf_reinject_get_send,
	.get_retrans	= (void *)bpf_reinject_get_retrans,
	.name		= "bpf_reinject",
};
