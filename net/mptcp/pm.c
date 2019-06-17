// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Intel Corporation.
 */
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

void pm_new_connection(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void pm_fully_established(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void pm_connection_closed(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void pm_subflow_established(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void pm_subflow_closed(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void pm_add_addr(struct mptcp_sock *msk, const struct in_addr *addr, u8 id)
{
	pr_debug("msk=%p", msk);
}

void pm_add_addr6(struct mptcp_sock *msk, const struct in6_addr *addr, u8 id)
{
	pr_debug("msk=%p", msk);
}

void pm_rm_addr(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

bool pm_addr_signal(struct mptcp_sock *msk, unsigned int *size,
		    unsigned int remaining, struct mptcp_out_options *opts)
{
	if (!msk || !msk->addr_signal)
		return false;

	if (msk->pm.family == AF_INET && remaining < TCPOLEN_MPTCP_ADD_ADDR)
		return false;

	pr_debug("msk=%p", msk);
	opts->suboptions |= OPTION_MPTCP_ADD_ADDR;
	opts->addr_id = msk->pm.addr_id;
	opts->addr.s_addr = msk->pm.addr.s_addr;

	return true;
}
