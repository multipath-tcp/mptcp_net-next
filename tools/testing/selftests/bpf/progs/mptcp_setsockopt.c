// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, SUSE. */

/* Test that bpf_setsockopt() called from a cgroup/setsockopt BPF program
 * on an MPTCP socket returns -EOPNOTSUPP when the target option requires
 * subflow-level locking (e.g. SO_RCVLOWAT via mptcp_set_rcvlowat).
 *
 * Flow:
 *   userspace: setsockopt(mptcp_fd, SOL_SOCKET, SO_RCVLOWAT, &large_val, ...)
 *     -> do_sock_setsockopt()
 *        -> BPF_CGROUP_RUN_PROG_SETSOCKOPT(sk)    // sk = MPTCP meta socket
 *           BPF prog: read val from ctx->optval,
 *                     bpf_setsockopt(sk, SOL_SOCKET, SO_RCVLOWAT, &val, 4)
 *             -> sk_setsockopt()
 *                -> ops->set_rcvlowat = mptcp_set_rcvlowat()
 *                   -> has_current_bpf_ctx() == true
 *                   -> return -EOPNOTSUPP
 */

#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s32);
} results SEC(".maps");

SEC("cgroup/setsockopt")
int mptcp_setsockopt(struct bpf_sockopt *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	__s32 val, ret;
	__u32 key = 0;

	/* Only interested in MPTCP + SO_RCVLOWAT */
	if (!sk || sk->protocol != IPPROTO_MPTCP)
		return 1;

	if (ctx->level != SOL_SOCKET || ctx->optname != SO_RCVLOWAT)
		return 1;

	/* Read value from ctx, verifier needs bounds check.
	 * Save optval pointer to local var so the verifier tracks
	 * the same register through bounds check and dereference.
	 */
	void *optval = ctx->optval;

	if (ctx->optlen < sizeof(val))
		return 1;
	if (optval + sizeof(val) > ctx->optval_end)
		return 1;
	val = *(__s32 *)optval;

	/* Forward the setsockopt via bpf_setsockopt.
	 * This reaches mptcp_set_rcvlowat() which checks has_current_bpf_ctx()
	 * and should return -EOPNOTSUPP.
	 */
	ret = bpf_setsockopt(sk, SOL_SOCKET, SO_RCVLOWAT, &val, sizeof(val));
	bpf_map_update_elem(&results, &key, &ret, BPF_ANY);

	/* BPF handled this, don't invoke kernel handler */
	return 1;
}

char _license[] SEC("license") = "GPL";
