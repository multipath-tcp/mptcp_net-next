/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MPTCP_BPF_H__
#define __MPTCP_BPF_H__

#include "bpf_experimental.h"
#include "bpf_tracing_net.h"

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

static __always_inline struct sock *
mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

/* ksym */
extern struct mptcp_sock *bpf_mptcp_sock_acquire(struct mptcp_sock *msk) __ksym;
extern void bpf_mptcp_sock_release(struct mptcp_sock *msk) __ksym;

extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;
extern struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow) __ksym;

extern void bpf_spin_lock_bh(spinlock_t *lock) __ksym;
extern void bpf_spin_unlock_bh(spinlock_t *lock) __ksym;

extern bool bpf_ipv4_is_private_10(__be32 addr) __ksym;

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;

extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx_by_pos(const struct mptcp_sched_data *data, unsigned int pos) __ksym;

/* reimplemented BPF helpers */
static __always_inline void
mptcp_pm_copy_addr(struct mptcp_addr_info *dst,
		   struct mptcp_addr_info *src)
{
	dst->id = src->id;
	dst->family = src->family;
	dst->port = src->port;

	if (src->family == AF_INET) {
		dst->addr.s_addr = src->addr.s_addr;
	} else if (src->family == AF_INET6) {
		dst->addr6.s6_addr32[0] = src->addr6.s6_addr32[0];
		dst->addr6.s6_addr32[1] = src->addr6.s6_addr32[1];
		dst->addr6.s6_addr32[2] = src->addr6.s6_addr32[2];
		dst->addr6.s6_addr32[3] = src->addr6.s6_addr32[3];
	}
}

static __always_inline void
mptcp_pm_copy_entry(struct mptcp_pm_addr_entry *dst,
		    struct mptcp_pm_addr_entry *src)
{
	mptcp_pm_copy_addr(&dst->addr, &src->addr);

	dst->flags = src->flags;
	dst->ifindex = src->ifindex;
}

#define inet_sk(ptr) container_of(ptr, struct inet_sock, sk)

#define ipv6_addr_equal(a, b)	((a).s6_addr32[0] == (b).s6_addr32[0] &&	\
				 (a).s6_addr32[1] == (b).s6_addr32[1] &&	\
				 (a).s6_addr32[2] == (b).s6_addr32[2] &&	\
				 (a).s6_addr32[3] == (b).s6_addr32[3])

static __always_inline bool
mptcp_addresses_equal(const struct mptcp_addr_info *a,
		      const struct mptcp_addr_info *b, bool use_port)
{
	bool addr_equals = false;

	if (a->family == b->family) {
		if (a->family == AF_INET)
			addr_equals = a->addr.s_addr == b->addr.s_addr;
		else
			addr_equals = ipv6_addr_equal(a->addr6, b->addr6);
	}

	if (!addr_equals)
		return false;
	if (!use_port)
		return true;

	return a->port == b->port;
}

static __always_inline struct sock *
mptcp_pm_find_ssk(struct mptcp_sock *msk,
		  const struct mptcp_addr_info *local,
		  const struct mptcp_addr_info *remote)
{
	struct mptcp_subflow_context *subflow;

	if (local->family != remote->family)
		return NULL;

	bpf_for_each(mptcp_subflow, subflow, msk) {
		const struct inet_sock *issk;
		struct sock *ssk;

		ssk = bpf_mptcp_subflow_tcp_sock(subflow);
		if (!ssk)
			continue;

		if (local->family != ssk->sk_family)
			continue;

		issk = bpf_core_cast(inet_sk(ssk), struct inet_sock);

		switch (ssk->sk_family) {
		case AF_INET:
			if (issk->inet_saddr != local->addr.s_addr ||
			    issk->inet_daddr != remote->addr.s_addr)
				continue;
			break;
		case AF_INET6: {
			if (!ipv6_addr_equal(local->addr6, issk->pinet6->saddr) ||
			    !ipv6_addr_equal(remote->addr6, ssk->sk_v6_daddr))
				continue;
			break;
		}
		default:
			continue;
		}

		if (issk->inet_sport == local->port &&
		    issk->inet_dport == remote->port)
			return ssk;
	}

	return NULL;
}

#endif
