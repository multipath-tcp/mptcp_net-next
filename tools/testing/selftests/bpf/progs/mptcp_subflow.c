// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Tessares SA. */
/* Author: Nicolas Rybowski <nicolas.rybowski@tessares.net> */

#include <asm/socket.h>	// SOL_SOCKET, SO_MARK, ...
#include <linux/tcp.h>	// TCP_CONGESTION
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX 16
#endif

char cc[TCP_CA_NAME_MAX] = "reno";

/* Associate a subflow counter to each token */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 100);
} mptcp_sf SEC(".maps");

SEC("sockops")
int mptcp_subflow(struct bpf_sock_ops *skops)
{
	__u32 init = 1, key, mark, *cnt;
	struct mptcp_sock *msk;
	struct bpf_sock *sk;
	int err;

	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 1;

	sk = skops->sk;
	if (!sk)
		return 1;

	msk = bpf_skc_to_mptcp_sock(sk);
	if (!msk)
		return 1;

	key = msk->token;
	cnt = bpf_map_lookup_elem(&mptcp_sf, &key);
	if (cnt) {
		/* A new subflow is added to an existing MPTCP connection */
		__sync_fetch_and_add(cnt, 1);
		mark = *cnt;
	} else {
		/* A new MPTCP connection is just initiated and this is its primary
		 *  subflow
		 */
		bpf_map_update_elem(&mptcp_sf, &key, &init, BPF_ANY);
		mark = init;
	}

	/* Set the mark of the subflow's socket to its apparition order */
	err = bpf_setsockopt(skops, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	if (err < 0)
		return 1;
	if (mark == 1)
		err = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, TCP_CA_NAME_MAX);

	return 1;
}
