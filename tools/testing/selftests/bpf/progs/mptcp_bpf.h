/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MPTCP_BPF_H__
#define __MPTCP_BPF_H__

#include "bpf_experimental.h"

#define READ_ONCE(x)  (*(const volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *) &(x)) = (val))

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

/* small difference: 'can_loop' has been added in the conditions */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member) && can_loop;	\
	     pos = list_next_entry(pos, member))

/* mptcp helpers from protocol.h */
#define mptcp_for_each_subflow(__msk, __subflow)			\
	list_for_each_entry(__subflow, &((__msk)->conn_list), node)

/* errno macros from include/uapi/asm-generic/errno-base.h */
#define	ESRCH		3	/* No such process */
#define	ENOMEM		12	/* Out of Memory */
#define	EINVAL		22	/* Invalid argument */

/* GFP macros from include/linux/gfp_types.h */
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _UL(x)		(_AC(x, UL))
#define UL(x)		(_UL(x))
#define BIT(nr)		(UL(1) << (nr))

#define ___GFP_HIGH		BIT(___GFP_HIGH_BIT)
#define __GFP_HIGH		((gfp_t)___GFP_HIGH)
#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)
#define __GFP_KSWAPD_RECLAIM	((gfp_t)___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
#define GFP_ATOMIC		(__GFP_HIGH|__GFP_KSWAPD_RECLAIM)

static __always_inline struct sock *
mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

/* ksym */
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

extern void bpf_spin_lock_bh(spinlock_t *lock) __ksym;
extern void bpf_spin_unlock_bh(spinlock_t *lock) __ksym;

extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;
extern struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow) __ksym;

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;

#endif
