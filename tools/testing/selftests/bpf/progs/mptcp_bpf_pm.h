/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __MPTCP_BPF_PM_H__
#define __MPTCP_BPF_PM_H__

#include "bpf_tracing_net.h"

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

extern void bpf_set_bit(unsigned long nr, unsigned long *addr) __ksym;

extern int mptcp_pm_remove_addr(struct mptcp_sock *msk,
				const struct mptcp_rm_list *rm_list) __ksym;

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

#endif
