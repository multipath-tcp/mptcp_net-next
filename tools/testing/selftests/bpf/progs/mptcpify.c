// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, SUSE. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";

SEC("fentry/socket_create")
int BPF_PROG(trace_socket_create, void *args,
		struct socket **res)
{
	bpf_mptcpify(args);
	return 0;
}
