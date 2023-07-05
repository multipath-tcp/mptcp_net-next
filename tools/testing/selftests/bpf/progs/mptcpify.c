// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

#define	AF_INET		2
#define	AF_INET6	10
#define	SOCK_STREAM	1
#define	IPPROTO_TCP	6
#define	IPPROTO_MPTCP	262

SEC("cgroup/sockinit")
int mptcpify(struct bpf_sockinit_ctx *ctx)
{
	if ((ctx->family == AF_INET || ctx->family == AF_INET6) &&
	    ctx->type == SOCK_STREAM &&
	    (!ctx->protocol || ctx->protocol == IPPROTO_TCP)) {
		ctx->protocol = IPPROTO_MPTCP;
	}

	return 1;
}
