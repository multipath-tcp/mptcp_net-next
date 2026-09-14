// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026, MPTCP. */

#include "mptcp_bpf.h"
#include <bpf/bpf_tracing.h>

extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;
extern void mptcp_subflow_set_avoid(struct mptcp_subflow_context *subflow,
				    bool avoid) __ksym;

char _license[] SEC("license") = "GPL";

struct mptcp_avoid_storage {
	bool avoid_marked;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mptcp_avoid_storage);
} mptcp_avoid_map SEC(".maps");

SEC("struct_ops")
void BPF_PROG(mptcp_sched_avoid_init, struct mptcp_sock *msk)
{
	bpf_sk_storage_get(&mptcp_avoid_map, msk, 0,
			   BPF_LOCAL_STORAGE_GET_F_CREATE);
}

SEC("struct_ops")
void BPF_PROG(mptcp_sched_avoid_release, struct mptcp_sock *msk)
{
	bpf_sk_storage_delete(&mptcp_avoid_map, msk);
}

SEC("struct_ops")
int BPF_PROG(bpf_avoid_get_send, struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_avoid_storage *ptr;

	ptr = bpf_sk_storage_get(&mptcp_avoid_map, msk, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return -1;

	/*
	 * set once, on the first scheduling round, never touched again --
	 * this is what makes "avoid" different from "scheduled": nothing
	 * here re-asserts the decision, and the core doesn't clear it
	 * either.
	 */
	if (!ptr->avoid_marked) {
		int i = 0;

		/* bench every subflow but the first, once */
		bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
			if (i++ > 0)
				mptcp_subflow_set_avoid(subflow, true);
		}
		ptr->avoid_marked = true;
	}

	/*
	 * every round -- including this one -- just reads back state set
	 * at most once above. no re-assertion, ever.
	 */
	bpf_for_each(mptcp_subflow, subflow, (struct sock *)msk) {
		if (subflow->avoid)
			continue;
		if (mptcp_subflow_active(subflow)) {
			mptcp_subflow_set_scheduled(subflow, true);
			break;
		}
	}
	return 0;
}

SEC(".struct_ops.link")
struct mptcp_sched_ops avoid = {
	.init		= (void *)mptcp_sched_avoid_init,
	.release	= (void *)mptcp_sched_avoid_release,
	.get_send	= (void *)bpf_avoid_get_send,
	.name		= "bpf_avoid",
};
