/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MPTCP_BPF_H__
#define __MPTCP_BPF_H__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

#define MPTCP_SUBFLOWS_MAX 8

static inline int list_is_head(const struct list_head *list,
			       const struct list_head *head)
{
	return list == head;
}

#define list_entry(ptr, type, member)					\
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member)				\
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member)					\
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_entry_is_head(pos, head, member)				\
	list_is_head(&pos->member, (head))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     cond_break, !list_entry_is_head(pos, head, member);	\
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     cond_break, !list_entry_is_head(pos, head, member);	\
	     pos = n, n = list_next_entry(n, member))

#define mptcp_for_each_subflow(__msk, __subflow)			\
	list_for_each_entry(__subflow, &((__msk)->conn_list), node)
#define mptcp_for_each_subflow_safe(__msk, __subflow, __tmp)		\
	list_for_each_entry_safe(__subflow, __tmp, &((__msk)->conn_list), node)

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
