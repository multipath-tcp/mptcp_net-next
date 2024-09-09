/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MPTCP_BPF_H__
#define __MPTCP_BPF_H__

#include "bpf_experimental.h"

/* mptcp helpers from include/net/mptcp.h */
#define MPTCP_SUBFLOWS_MAX 8

/* list helpers from include/linux/list.h */
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

/* small difference: 'cond_break' has been added in the conditions */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     cond_break, !list_entry_is_head(pos, head, member);	\
	     pos = list_next_entry(pos, member))

/* mptcp helpers from protocol.h */
#define mptcp_for_each_subflow(__msk, __subflow)			\
	list_for_each_entry(__subflow, &((__msk)->conn_list), node)

static __always_inline struct sock *
mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

/* ksym */
extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;
extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx_by_pos(const struct mptcp_sched_data *data, unsigned int pos) __ksym;

#endif
