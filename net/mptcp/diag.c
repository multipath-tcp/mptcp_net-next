// SPDX-License-Identifier: GPL-2.0
/* MPTCP socket monitoring support
 *
 * Copyright (c) 2019 Red Hat
 *
 * Author: Davide Caratti <dcaratti@redhat.com>
 */

#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/inet_diag.h>
#include <net/netlink.h>
#include "protocol.h"

static int subflow_get_info(struct sock *sk, struct sk_buff *skb)
{
	struct mptcp_subflow_context *sf;
	struct nlattr *start;
	u32 flags = 0;
	bool slow;
	int err;

	if (inet_sk_state_load(sk) == TCP_LISTEN)
		return 0;

	start = nla_nest_start_noflag(skb, INET_ULP_INFO_MPTCP);
	if (!start)
		return -EMSGSIZE;

	slow = lock_sock_fast(sk);
	rcu_read_lock();
	sf = rcu_dereference(inet_csk(sk)->icsk_ulp_data);
	if (!sf) {
		err = 0;
		goto nla_failure;
	}

	if (sf->mp_capable)
		flags |= MPTCP_SUBFLOW_FLAG_MCAP_REM;
	if (sf->request_mptcp)
		flags |= MPTCP_SUBFLOW_FLAG_MCAP_LOC;
	if (sf->mp_join)
		flags |= MPTCP_SUBFLOW_FLAG_JOIN_REM;
	if (sf->request_join)
		flags |= MPTCP_SUBFLOW_FLAG_JOIN_LOC;
	if (sf->backup)
		flags |= MPTCP_SUBFLOW_FLAG_BKUP_REM;
	if (sf->request_bkup)
		flags |= MPTCP_SUBFLOW_FLAG_BKUP_LOC;
	if (READ_ONCE(sf->fully_established))
		flags |= MPTCP_SUBFLOW_FLAG_FULLY_ESTABLISHED;
	if (sf->conn_finished)
		flags |= MPTCP_SUBFLOW_FLAG_CONNECTED;
	if (sf->map_valid)
		flags |= MPTCP_SUBFLOW_FLAG_MAPVALID;

	if (nla_put_u32(skb, MPTCP_SUBFLOW_ATTR_TOKEN_REM, sf->remote_token) ||
	    nla_put_u32(skb, MPTCP_SUBFLOW_ATTR_TOKEN_LOC, sf->token) ||
	    nla_put_u32(skb, MPTCP_SUBFLOW_ATTR_RELWRITE_SEQ,
			sf->rel_write_seq) ||
	    nla_put_u64_64bit(skb, MPTCP_SUBFLOW_ATTR_MAP_SEQ, sf->map_seq,
			      MPTCP_SUBFLOW_ATTR_PAD) ||
	    nla_put_u32(skb, MPTCP_SUBFLOW_ATTR_MAP_SFSEQ,
			sf->map_subflow_seq) ||
	    nla_put_u32(skb, MPTCP_SUBFLOW_ATTR_SSN_OFFSET, sf->ssn_offset) ||
	    nla_put_u16(skb, MPTCP_SUBFLOW_ATTR_MAP_DATALEN,
			sf->map_data_len) ||
	    nla_put_u32(skb, MPTCP_SUBFLOW_ATTR_FLAGS, flags) ||
	    nla_put_u8(skb, MPTCP_SUBFLOW_ATTR_ID_REM, sf->remote_id) ||
	    nla_put_u8(skb, MPTCP_SUBFLOW_ATTR_ID_LOC, subflow_get_local_id(sf))) {
		err = -EMSGSIZE;
		goto nla_failure;
	}

	rcu_read_unlock();
	unlock_sock_fast(sk, slow);
	nla_nest_end(skb, start);
	return 0;

nla_failure:
	rcu_read_unlock();
	unlock_sock_fast(sk, slow);
	nla_nest_cancel(skb, start);
	return err;
}

void mptcp_diag_subflow_init(struct tcp_ulp_ops *ops)
{
	ops->get_info = subflow_get_info;
}
