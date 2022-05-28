// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, SUSE. */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops/mptcp_sched_backup_init")
void BPF_PROG(mptcp_sched_backup_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_backup_release")
void BPF_PROG(mptcp_sched_backup_release, const struct mptcp_sock *msk)
{
}

void BPF_STRUCT_OPS(bpf_backup_get_subflow, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
	int nr = 0;

	for (int i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		if (!data->subflows[i].context)
			break;

		if (!data->subflows[i].context->backup) {
			nr = i;
			break;
		}
	}

	data->subflows[nr].is_scheduled = 1;
}

SEC(".struct_ops")
struct mptcp_sched_ops backup = {
	.init		= (void *)mptcp_sched_backup_init,
	.release	= (void *)mptcp_sched_backup_release,
	.get_subflow	= (void *)bpf_backup_get_subflow,
	.name		= "bpf_backup",
};
