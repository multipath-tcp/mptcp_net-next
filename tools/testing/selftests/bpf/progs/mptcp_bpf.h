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

/* mptcp helpers from include/net/mptcp.h */
#define U8_MAX		((u8)~0U)

/* max value of mptcp_addr_info.id */
#define MPTCP_PM_MAX_ADDR_ID		U8_MAX

/* mptcp macros from include/uapi/linux/mptcp.h */
#define MPTCP_PM_ADDR_FLAG_SIGNAL			(1 << 0)
#define MPTCP_PM_ADDR_FLAG_SUBFLOW			(1 << 1)
#define MPTCP_PM_ADDR_FLAG_BACKUP			(1 << 2)
#define MPTCP_PM_ADDR_FLAG_FULLMESH			(1 << 3)
#define MPTCP_PM_ADDR_FLAG_IMPLICIT			(1 << 4)

/* address families macros from include/linux/socket.h */
#define AF_UNSPEC	0
#define AF_INET		2
#define AF_INET6	10

/* shutdown macros from include/net/sock.h */
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

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
extern struct mptcp_sock *bpf_mptcp_sock_acquire(struct mptcp_sock *msk) __ksym;
extern void bpf_mptcp_sock_release(struct mptcp_sock *msk) __ksym;

extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;
extern struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow) __ksym;

extern void bpf_spin_lock_bh(spinlock_t *lock) __ksym;
extern void bpf_spin_unlock_bh(spinlock_t *lock) __ksym;

extern bool bpf_ipv4_is_private_10(__be32 addr) __ksym;

extern struct mptcp_pm_addr_entry *
bpf_sock_kmalloc_entry(struct sock *sk, int size, gfp_t priority) __ksym;
extern void
bpf_sock_kfree_entry(struct sock *sk, struct mptcp_pm_addr_entry *entry,
		     int size) __ksym;

extern bool mptcp_pm_alloc_anno_list(struct mptcp_sock *msk,
				     const struct mptcp_addr_info *addr) __ksym;
extern int mptcp_pm_announce_addr(struct mptcp_sock *msk,
				  const struct mptcp_addr_info *addr,
				  bool echo) __ksym;
extern void mptcp_pm_nl_addr_send_ack(struct mptcp_sock *msk) __ksym;

extern void bpf_bitmap_zero(unsigned long *dst, unsigned int nbits) __ksym;
extern void bpf_set_bit(unsigned long nr, unsigned long *addr) __ksym;
extern u8 bpf_find_next_zero_bit(const unsigned long *addr,
				 unsigned long size, unsigned long offset) __ksym;

extern int mptcp_pm_remove_addr(struct mptcp_sock *msk,
				const struct mptcp_rm_list *rm_list) __ksym;
extern void mptcp_pm_remove_addr_entry(struct mptcp_sock *msk,
				       struct mptcp_pm_addr_entry *entry) __ksym;

extern int bpf_mptcp_subflow_connect(struct sock *sk,
				     const struct mptcp_pm_addr_entry *entry,
				     const struct mptcp_addr_info *remote) __ksym;

extern void
mptcp_subflow_shutdown(struct sock *sk, struct sock *ssk, int how) __ksym;
extern void mptcp_close_ssk(struct sock *sk, struct sock *ssk,
			    struct mptcp_subflow_context *subflow) __ksym;
extern struct net *bpf_sock_net(const struct sock *sk) __ksym;
extern void BPF_MPTCP_INC_STATS(struct net *net,
				enum linux_mptcp_mib_field field) __ksym;

extern int mptcp_pm_nl_mp_prio_send_ack(struct mptcp_sock *msk,
					struct mptcp_addr_info *addr,
					struct mptcp_addr_info *rem,
					u8 bkup) __ksym;

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
