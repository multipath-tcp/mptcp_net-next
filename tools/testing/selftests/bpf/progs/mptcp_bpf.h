/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MPTCP_BPF_H__
#define __MPTCP_BPF_H__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#define MPTCP_SUBFLOWS_MAX 8

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;

extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx_by_pos(const struct mptcp_sched_data *data, unsigned int pos) __ksym;

static __always_inline struct sock *
mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

#endif
