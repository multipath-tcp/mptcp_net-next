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

static int bpf_first_get_subflow(struct mptcp_sock *msk,
				 struct mptcp_sched_data *data)
{
	mptcp_subflow_set_scheduled(bpf_mptcp_subflow_ctx_by_pos(data, 0), true);
	return 0;
}

SEC("struct_ops")
int BPF_PROG(bpf_first_get_send, struct mptcp_sock *msk,
	     struct mptcp_sched_data *data)
{
	return bpf_first_get_subflow(msk, data);
}

SEC("struct_ops")
int BPF_PROG(bpf_first_get_retrans, struct mptcp_sock *msk,
	     struct mptcp_sched_data *data)
{
	return bpf_first_get_subflow(msk, data);
}

SEC(".struct_ops.link")
struct mptcp_sched_ops first = {
	.init		= (void *)mptcp_sched_first_init,
	.release	= (void *)mptcp_sched_first_release,
	.get_send	= (void *)bpf_first_get_send,
	.get_retrans	= (void *)bpf_first_get_retrans,
	.name		= "bpf_first",
};
