/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __MPTCP_BPF_H__
#define __MPTCP_BPF_H__

#include <string.h>
#include "bpf_experimental.h"

/* mptcp helpers from include/net/mptcp.h */
#define MPTCP_SUBFLOWS_MAX 8

extern bool CONFIG_MPTCP_IPV6 __kconfig __weak;

#define MPTCP_PM_ADDR_FLAG_SIGNAL			(1 << 0)
#define MPTCP_PM_ADDR_FLAG_SUBFLOW			(1 << 1)
#define MPTCP_PM_ADDR_FLAG_BACKUP			(1 << 2)
#define MPTCP_PM_ADDR_FLAG_FULLMESH			(1 << 3)
#define MPTCP_PM_ADDR_FLAG_IMPLICIT			(1 << 4)

#define AF_UNSPEC	0
#define AF_INET		2
#define AF_INET6	10

#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

#define	ENOMEM		12	/* Out of Memory */
#define	EINVAL		22	/* Invalid argument */

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

#define mptcp_for_each_address(__msk, __entry)			\
	list_for_each_entry(__entry, &((__msk)->pm.userspace_pm_local_addr_list), list)

static __always_inline struct sock *
mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow)
{
	return subflow->tcp_sock;
}

/* ksym */
extern struct mptcp_sock *bpf_mptcp_sock_acquire(struct mptcp_sock *msk) __ksym;
extern void bpf_mptcp_sock_release(struct mptcp_sock *msk) __ksym;

extern struct mptcp_sock *bpf_mptcp_sk(struct sock *sk) __ksym;
extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx(const struct sock *sk) __ksym;
extern struct sock *
bpf_mptcp_subflow_tcp_sock(const struct mptcp_subflow_context *subflow) __ksym;

extern void bpf_spin_lock_bh(spinlock_t *lock) __ksym;
extern void bpf_spin_unlock_bh(spinlock_t *lock) __ksym;

extern bool bpf_ipv6_addr_v4mapped(const struct mptcp_addr_info *a) __ksym;

extern void bpf_list_add_tail_rcu(struct list_head *new,
				  struct list_head *head) __ksym;
extern void bpf_list_del_rcu(struct list_head *entry) __ksym;

extern struct mptcp_pm_addr_entry *
bpf_pm_alloc_entry(struct sock *sk, struct mptcp_pm_addr_entry *entry) __ksym;
extern void bpf_pm_free_entry(struct sock *sk,
			      struct mptcp_pm_addr_entry *entry) __ksym;

extern bool bpf_mptcp_addresses_equal(const struct mptcp_addr_info *a,
				      const struct mptcp_addr_info *b, bool use_port) __ksym;
extern bool mptcp_pm_alloc_anno_list(struct mptcp_sock *msk,
				     const struct mptcp_addr_info *addr) __ksym;
extern int mptcp_pm_announce_addr(struct mptcp_sock *msk,
				  const struct mptcp_addr_info *addr,
				  bool echo) __ksym;
extern void mptcp_pm_nl_addr_send_ack(struct mptcp_sock *msk) __ksym;

extern void bpf_bitmap_zero(struct mptcp_id_bitmap *bitmap) __ksym;
extern bool bpf_test_bit(u8 nr, struct mptcp_id_bitmap *bitmap) __ksym;
extern void bpf_set_bit(u8 nr, struct mptcp_id_bitmap *bitmap) __ksym;
extern u8 bpf_next_bit(struct mptcp_id_bitmap *bitmap) __ksym;

extern int mptcp_pm_remove_addr(struct mptcp_sock *msk,
				const struct mptcp_rm_list *rm_list) __ksym;
extern void mptcp_pm_remove_addr_entry(struct mptcp_sock *msk,
				       struct mptcp_pm_addr_entry *entry) __ksym;

extern bool bpf_mptcp_pm_addr_families_match(const struct sock *sk,
					     const struct mptcp_addr_info *loc,
					     const struct mptcp_addr_info *rem) __ksym;
extern int __mptcp_subflow_connect(struct sock *sk,
				   const struct mptcp_pm_addr_entry *local,
				   const struct mptcp_addr_info *remote) __ksym;

extern struct ipv6_pinfo *bpf_inet6_sk(const struct sock *sk) __ksym;
extern bool bpf_ipv6_addr_equal(const struct mptcp_addr_info *a1,
				const struct in6_addr *a2) __ksym;
extern void bpf_ipv6_addr_set_v4mapped(const __be32 addr,
				       struct mptcp_addr_info *v4mapped) __ksym;
extern void mptcp_subflow_shutdown(struct sock *sk, struct sock *ssk, int how) __ksym;
extern void mptcp_close_ssk(struct sock *sk, struct sock *ssk,
			    struct mptcp_subflow_context *subflow) __ksym;

extern int mptcp_pm_nl_mp_prio_send_ack(struct mptcp_sock *msk,
					struct mptcp_addr_info *addr,
					struct mptcp_addr_info *rem,
					u8 bkup) __ksym;

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;

extern struct mptcp_subflow_context *
bpf_mptcp_subflow_ctx_by_pos(const struct mptcp_sched_data *data, unsigned int pos) __ksym;

#endif
