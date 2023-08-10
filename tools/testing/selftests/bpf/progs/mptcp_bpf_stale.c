// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <linux/bpf.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

struct mptcp_stale_storage {
	__u8 nr;
	__u32 ids[MPTCP_SUBFLOWS_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mptcp_stale_storage);
} mptcp_stale_map SEC(".maps");

static void mptcp_subflow_set_stale(struct mptcp_stale_storage *storage,
				    __u32 subflow_id)
{
	if (!subflow_id)
		return;

	for (int i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (storage->ids[i] == subflow_id)
			return;
	}

	if (storage->nr < MPTCP_SUBFLOWS_MAX - 1)
		storage->ids[storage->nr++] = subflow_id;
}

static void mptcp_subflow_clear_stale(struct mptcp_stale_storage *storage,
				      __u32 subflow_id)
{
	if (!subflow_id)
		return;

	for (int i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (storage->ids[i] == subflow_id) {
			for (int j = i; j < MPTCP_SUBFLOWS_MAX - 1; j++) {
				if (!storage->ids[j + 1])
					break;
				storage->ids[j] = storage->ids[j + 1];
				storage->ids[j + 1] = 0;
			}
			storage->nr--;
			return;
		}
	}
}

static bool mptcp_subflow_is_stale(struct mptcp_stale_storage *storage,
				   __u32 subflow_id)
{
	for (int i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (storage->ids[i] == subflow_id)
			return true;
	}

	return false;
}

static bool mptcp_subflow_is_active(struct mptcp_sched_data *data,
				    __u32 subflow_id)
{
	for (int i = 0; i < data->subflows && i < MPTCP_SUBFLOWS_MAX; i++) {
		struct mptcp_subflow_context *subflow;

		subflow = mptcp_subflow_ctx_by_pos(data, i);
		if (!subflow)
			break;
		if (subflow->subflow_id == subflow_id)
			return true;
	}

	return false;
}

SEC("struct_ops/mptcp_sched_stale_init")
void BPF_PROG(mptcp_sched_stale_init, struct mptcp_sock *msk)
{
	struct mptcp_stale_storage *storage;

	storage = bpf_sk_storage_get(&mptcp_stale_map, msk, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage)
		return;

	storage->nr = 0;
}

SEC("struct_ops/mptcp_sched_stale_release")
void BPF_PROG(mptcp_sched_stale_release, struct mptcp_sock *msk)
{
	bpf_sk_storage_delete(&mptcp_stale_map, msk);
}

void BPF_STRUCT_OPS(bpf_stale_data_init, struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_stale_storage *storage;

	mptcp_sched_data_set_contexts(msk, data);

	storage = bpf_sk_storage_get(&mptcp_stale_map, msk, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage)
		return;

	for (int i = 0; i < storage->nr && i < MPTCP_SUBFLOWS_MAX; i++) {
		if (!mptcp_subflow_is_active(data, storage->ids[i]))
			mptcp_subflow_clear_stale(storage, storage->ids[i]);
	}

	subflow = mptcp_subflow_ctx_by_pos(data, 1);
	if (subflow)
		mptcp_subflow_set_stale(storage, subflow->subflow_id);
}

int BPF_STRUCT_OPS(bpf_stale_get_subflow, struct mptcp_sock *msk,
		   const struct mptcp_sched_data *data)
{
	struct mptcp_stale_storage *storage;
	int nr = -1;

	storage = bpf_sk_storage_get(&mptcp_stale_map, msk, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!storage)
		return -1;

	for (int i = 0; i < data->subflows && i < MPTCP_SUBFLOWS_MAX; i++) {
		struct mptcp_subflow_context *subflow;

		subflow = mptcp_subflow_ctx_by_pos(data, i);
		if (!subflow)
			break;

		if (mptcp_subflow_is_stale(storage, subflow->subflow_id))
			continue;

		nr = i;
	}

	if (nr != -1) {
		mptcp_subflow_set_scheduled(mptcp_subflow_ctx_by_pos(data, nr), true);
		return -1;
	}
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops stale = {
	.init		= (void *)mptcp_sched_stale_init,
	.release	= (void *)mptcp_sched_stale_release,
	.data_init	= (void *)bpf_stale_data_init,
	.get_subflow	= (void *)bpf_stale_get_subflow,
	.name		= "bpf_stale",
};
