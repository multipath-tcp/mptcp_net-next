// SPDX-License-Identifier: GPL-2.0
/* MPTCP Fast Open Mechanism
 *
 * Copyright (c) 2021-2022, Dmytro SHYTYI
 */

#include "protocol.h"

void mptcp_fastopen_subflow_synack_set_params(struct mptcp_subflow_context *subflow,
					      struct request_sock *req)
{
	struct mptcp_sock *msk;
	struct sock *sk, *ssk;
	struct sk_buff *skb;
	struct tcp_sock *tp;
	bool has_rxtstamp;

	/* on early fallback the subflow context is deleted by
	 * subflow_syn_recv_sock()
	 */
	if (!subflow)
		return;

	ssk = subflow->tcp_sock;
	sk = subflow->conn;
	tp = tcp_sk(ssk);

	/* A valid TFO cookie does not guarantee SYN data. */
	skb = skb_peek(&ssk->sk_receive_queue);
	if (!skb)
		return;

	subflow->is_mptfo = 1;

	/* dequeue the skb from sk receive queue */
	__skb_unlink(skb, &ssk->sk_receive_queue);
	skb_ext_reset(skb);

	mptcp_subflow_lend_fwdmem(subflow, skb);

	/* We copy the fastopen data, but that don't belong to the mptcp sequence
	 * space, need to offset it in the subflow sequence, see mptcp_subflow_get_map_offset()
	 */
	tp->copied_seq += skb->len;
	subflow->ssn_offset += skb->len;
	has_rxtstamp = TCP_SKB_CB(skb)->has_rxtstamp;

	/* The TFO segment data sits before the IASN; before receiving
	 * the remote key, IASN is assumed being 0.
	 */
	MPTCP_SKB_CB(skb)->map_seq64 = -(u64)skb->len;
	MPTCP_SKB_CB(skb)->map_seq = MPTCP_SKB_CB(skb)->map_seq64;
	MPTCP_SKB_CB(skb)->end_seq = 0;
	MPTCP_SKB_CB(skb)->flags = 0;
	MPTCP_SKB_CB(skb)->has_rxtstamp = has_rxtstamp;

	mptcp_data_lock(sk);
	DEBUG_NET_WARN_ON_ONCE(sock_owned_by_user_nocheck(sk));

	msk = mptcp_sk(sk);
	msk->rcvd_dummy_seq = true;
	msk->copied_seq = MPTCP_SKB_CB(skb)->map_seq64;
	msk->tfo_skb_len = skb->len;
	mptcp_borrow_fwdmem(sk, skb);
	skb_set_owner_r(skb, sk);
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	msk->bytes_received += skb->len;

	sk->sk_data_ready(sk);

	mptcp_data_unlock(sk);
}
