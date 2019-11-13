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

int mptcp_pm_announce_addr(u32 token, u8 local_id, struct in_addr *addr)
{
	return -ENOTSUPP;
}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
int mptcp_pm_announce_addr6(u32 token, u8 local_id, struct in6_addr *addr)
{
	return -ENOTSUPP;
}
#endif

int mptcp_pm_remove_addr(u32 token, u8 local_id)
{
	return -ENOTSUPP;
}

int mptcp_pm_create_subflow(u32 token, u8 remote_id, struct in_addr *addr)
{
	return -ENOTSUPP;
}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
int mptcp_pm_create_subflow6(u32 token, u8 remote_id, struct in6_addr *addr)
{
	return -ENOTSUPP;
}
#endif

int mptcp_pm_remove_subflow(u32 token, u8 remote_id)
{
	return -ENOTSUPP;
}

/* path manager event handlers */

void mptcp_pm_new_connection(struct mptcp_sock *msk, int server_side)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, token=%u", msk, msk->token);

	pm->server_side = server_side;
	pm->token = msk->token;
}

void mptcp_pm_fully_established(struct mptcp_sock *msk)
{
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p", msk);

	pm->fully_established = 1;
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
	struct mptcp_pm_data *pm = &msk->pm;

	pr_debug("msk=%p, addr=%x, remote_id=%d", msk, addr->s_addr, id);

	pm->remote_addr = *addr;
	pm->remote_id = id;
	pm->remote_family = AF_INET;
	pm->remote_valid = 1;
}

void mptcp_pm_add_addr6(struct mptcp_sock *msk, const struct in6_addr *addr,
			u8 id)
{
	pr_debug("msk=%p", msk);
}

/* path manager helpers */

int mptcp_pm_addr_signal(struct mptcp_sock *msk, u8 *id,
			 struct sockaddr_storage *saddr)
{
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)saddr;
#endif
	struct sockaddr_in *addr = (struct sockaddr_in *)saddr;

	if (!msk->pm.local_valid)
		return -1;

	if (msk->pm.local_family == AF_INET) {
		addr->sin_family = msk->pm.local_family;
		addr->sin_addr = msk->pm.local_addr;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	} else if (msk->pm.local_family == AF_INET6) {
		addr6->sin6_family = msk->pm.local_family;
		addr6->sin6_addr = msk->pm.local_addr6;
#endif
	} else {
		return -1;
	}
	*id = msk->pm.local_id;

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
