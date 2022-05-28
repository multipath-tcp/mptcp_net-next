// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/mptcp_sched_rr_init")
void BPF_PROG(mptcp_sched_rr_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_rr_release")
void BPF_PROG(mptcp_sched_rr_release, const struct mptcp_sock *msk)
{
}

void BPF_STRUCT_OPS(bpf_rr_get_subflow, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
	int nr = 0;

	for (int i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		if (!msk->last_snd || !data->subflows[i].context)
			break;

		if (data->subflows[i].context->tcp_sock == msk->last_snd) {
			if (i + 1 == MPTCP_SUBFLOWS_MAX || !data->subflows[i + 1].context)
				break;

			nr = i + 1;
			break;
		}
	}

	data->subflows[nr].is_scheduled = 1;
}

SEC(".struct_ops")
struct mptcp_sched_ops rr = {
	.init		= (void *)mptcp_sched_rr_init,
	.release	= (void *)mptcp_sched_rr_release,
	.get_subflow	= (void *)bpf_rr_get_subflow,
	.name		= "bpf_rr",
};
