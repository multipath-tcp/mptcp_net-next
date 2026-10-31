// SPDX-License-Identifier: GPL-2.0

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define LIMIT	4096

__u64 calls = 0;
/* the most bytes a subflow was given for one decision */
__u32 max_given = 0;

/* the subflow picked last time, by position, and its write_seq then */
int last_pick = -1;
__u32 last_seq = 0;

SEC("struct_ops")
void BPF_PROG(mptcp_sched_limit_init, struct mptcp_sock *msk)
{
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_limit_release, struct mptcp_sock *msk)
{
}

/* round robin, at most LIMIT bytes per decision */
SEC("struct_ops")
int BPF_PROG(bpf_limit_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow, *first = NULL, *pick = NULL;
	const struct tcp_sock *tp;
	__u64 n = calls++;
	struct sock *ssk;
	int i = 0, p = 0;

	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		if (i == last_pick) {
			ssk = bpf_mptcp_subflow_tcp_sock(subflow);
			tp = ssk ? bpf_skc_to_tcp_sock(ssk) : NULL;
			if (tp && tp->write_seq - last_seq > max_given)
				max_given = tp->write_seq - last_seq;
		}
		if (!first)
			first = subflow;
		if (!pick && i == (n & 1)) {
			pick = subflow;
			p = i;
		}
		i++;
	}
	/* a single subflow so far */
	if (!pick) {
		pick = first;
		p = 0;
	}
	if (!pick)
		return -1;

	ssk = bpf_mptcp_subflow_tcp_sock(pick);
	tp = ssk ? bpf_skc_to_tcp_sock(ssk) : NULL;
	last_pick = tp ? p : -1;
	last_seq = tp ? tp->write_seq : 0;

	pick->send_limit = LIMIT;
	mptcp_subflow_set_scheduled(pick, true);
	return 0;
}

/* An MPTCP-level retransmission is not one of our decisions: do not count
 * what it sends.
 */
SEC("struct_ops")
int BPF_PROG(bpf_limit_get_retrans, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	last_pick = -1;
	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		mptcp_subflow_set_scheduled(subflow, true);
		return 0;
	}
	return -1;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops limit = {
	.init		= (void *)mptcp_sched_limit_init,
	.release	= (void *)mptcp_sched_limit_release,
	.get_send	= (void *)bpf_limit_get_send,
	.get_retrans	= (void *)bpf_limit_get_retrans,
	.name		= "bpf_limit",
};
