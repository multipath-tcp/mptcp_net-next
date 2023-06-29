// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";
__u16 protocol = 0;

SEC("sockops")
int _sockops(struct bpf_sock_ops *ctx)
{
	int op = (int)ctx->op;
	struct bpf_sock *bsk;
	struct sock *sk;

	if (op != BPF_SOCK_OPS_TCP_CONNECT_CB &&
	    op != BPF_SOCK_OPS_TCP_LISTEN_CB)
		return 1;

	bsk = ctx->sk;
	if (!bsk)
		return 1;

	sk = bpf_mptcpify(bsk);
	if (!sk)
		return 1;

	protocol = sk->sk_protocol;
	return 0;
}
