// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/mptcp_sched_first_init")
void BPF_PROG(mptcp_sched_first_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_first_release")
void BPF_PROG(mptcp_sched_first_release, const struct mptcp_sock *msk)
{
}

void BPF_STRUCT_OPS(bpf_first_get_subflow, const struct mptcp_sock *msk,
		    bool reinject, struct mptcp_sched_data *data)
{
	unsigned long bitmap = 0;

	set_bit(0, &bitmap);
	data->bitmap = bitmap;
}

SEC(".struct_ops")
struct mptcp_sched_ops first = {
	.init		= (void *)mptcp_sched_first_init,
	.release	= (void *)mptcp_sched_first_release,
	.get_subflow	= (void *)bpf_first_get_subflow,
	.name		= "bpf_first",
};
