// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Intel Corporation.
 */
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

/* path manager command handlers */

int mptcp_pm_announce_addr(u32 token, sa_family_t family, u8 local_id,
			   struct in_addr *addr)
{
	return -ENOTSUPP;
}

int mptcp_pm_remove_addr(u32 token, u8 local_id)
{
	return -ENOTSUPP;
}

int mptcp_pm_create_subflow(u32 token, u8 remote_id)
{
	return -ENOTSUPP;
}

int mptcp_pm_remove_subflow(u32 token, u8 remote_id)
{
	return -ENOTSUPP;
}

/* path manager event handlers */

void mptcp_pm_new_connection(struct mptcp_sock *msk, int server_side)
{
	pr_debug("msk=%p", msk);

	msk->pm.server_side = server_side;
}

void mptcp_pm_fully_established(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);

	msk->pm.fully_established = 1;
}

void mptcp_pm_connection_closed(struct mptcp_sock *msk)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_subflow_established(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_subflow_closed(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_add_addr(struct mptcp_sock *msk, const struct in_addr *addr,
		       u8 id)
{
	pr_debug("msk=%p, addr=%x, remote_id=%d", msk, addr->s_addr, id);

	msk->pm.remote_addr.s_addr = addr->s_addr;
	msk->pm.remote_id = id;
	msk->pm.remote_family = AF_INET;
	msk->pm.remote_valid = 1;
}

void mptcp_pm_add_addr6(struct mptcp_sock *msk, const struct in6_addr *addr,
			u8 id)
{
	pr_debug("msk=%p", msk);
}

void mptcp_pm_rm_addr(struct mptcp_sock *msk, u8 id)
{
	pr_debug("msk=%p", msk);
}

/* path manager helpers */

int mptcp_pm_addr_signal(struct mptcp_sock *msk, u8 *id,
			 struct sockaddr_storage *saddr)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)saddr;

	if (!msk->pm.local_valid)
		return -1;

	if (msk->pm.local_family != AF_INET)
		return -1;

	*id = msk->pm.local_id;
	addr->sin_family = msk->pm.local_family;
	addr->sin_addr.s_addr = msk->pm.local_addr.s_addr;

	return 0;
}

int mptcp_pm_get_local_id(struct request_sock *req, struct sock *sk,
			  const struct sk_buff *skb)
{
	struct mptcp_subflow_request_sock *subflow_req = mptcp_subflow_rsk(req);
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (!msk->pm.local_valid)
		return -1;

	/* @@ check if address actually matches... */

	pr_debug("msk=%p, addr_id=%d", msk, msk->pm.local_id);
	subflow_req->local_id = msk->pm.local_id;

	return 0;
}

void mptcp_pm_init(void)
{
}
