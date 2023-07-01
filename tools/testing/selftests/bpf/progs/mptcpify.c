// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <sys/socket.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";
__u16 protocol = 0;

SEC("cgroup/sock_create")
int sock(struct bpf_sock *ctx)
{
	struct sock *sk;

	if (ctx->type != SOCK_STREAM)
		return 1;

	sk = bpf_mptcpify(ctx);
	if (!sk)
		return 1;

	protocol = sk->sk_protocol;
	return 1;
}
