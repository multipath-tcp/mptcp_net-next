/* SPDX-License-Identifier: GPL-2.0
 * MPTCP Fast Open Mechanism. Copyright (c) 2021-2022, Dmytro SHYTYI
 */

#include "protocol.h"

void subflow_fastopen_send_synack_set_params(struct mptcp_subflow_context *subflow,
					     struct request_sock *req)
{
	struct tcp_request_sock *treq = tcp_rsk(req);
	struct sock *ssk = subflow->tcp_sock;
	struct sock *sk = subflow->conn;
	struct mptcp_sock *msk;
	struct sk_buff *skb;
	struct tcp_sock *tp;
	u32 offset;

	msk = mptcp_sk(sk);
	tp = tcp_sk(ssk);

	/* mark subflow/msk as "mptfo" */
	msk->is_mptfo = 1;

	skb = skb_peek(&ssk->sk_receive_queue);

	/* dequeue the skb from sk receive queue */
	__skb_unlink(skb, &ssk->sk_receive_queue);
	skb_ext_reset(skb);
	skb_orphan(skb);

	/* set the skb mapping */
	tp->copied_seq += tp->rcv_nxt - treq->rcv_isn - 1;
	subflow->map_seq = mptcp_subflow_get_mapped_dsn(subflow);
	subflow->ssn_offset = tp->copied_seq - 1;

	/* initialize MPTCP_CB */
	offset = tp->copied_seq - TCP_SKB_CB(skb)->seq;
	MPTCP_SKB_CB(skb)->map_seq = mptcp_subflow_get_mapped_dsn(subflow);
	MPTCP_SKB_CB(skb)->end_seq = MPTCP_SKB_CB(skb)->map_seq +
				     (skb->len - offset);
	MPTCP_SKB_CB(skb)->offset = offset;
	MPTCP_SKB_CB(skb)->has_rxtstamp = TCP_SKB_CB(skb)->has_rxtstamp;

	mptcp_data_lock(sk);

	mptcp_set_owner_r(skb, sk);
	__skb_queue_tail(&msk->receive_queue, skb);

	(sk)->sk_data_ready(sk);

	mptcp_data_unlock(sk);
}

void mptcp_gen_msk_ackseq_fastopen(struct mptcp_sock *msk, struct mptcp_subflow_context *subflow,
				   const struct mptcp_options_received *mp_opt)
{
	struct sock *sk = (struct sock *)msk;
	struct sk_buff *skb;
	u64 ack_seq;

	mptcp_crypto_key_sha(mp_opt->sndr_key, NULL, &ack_seq);
	ack_seq++;

	mptcp_data_lock(sk);
	WRITE_ONCE(msk->can_ack, true);
	WRITE_ONCE(msk->ack_seq, ack_seq);
	atomic64_set(&msk->rcv_wnd_sent, ack_seq);
	msk->remote_key = mp_opt->sndr_key;
	skb = skb_peek_tail(&sk->sk_receive_queue);
	if (skb) {
		WARN_ON_ONCE(MPTCP_SKB_CB(skb)->end_seq);
		pr_debug("msk %p moving seq %llx -> %llx end_seq %llx -> %llx", sk,
			MPTCP_SKB_CB(skb)->map_seq,  msk->ack_seq + MPTCP_SKB_CB(skb)->map_seq,
			MPTCP_SKB_CB(skb)->end_seq, MPTCP_SKB_CB(skb)->end_seq + msk->ack_seq);
		MPTCP_SKB_CB(skb)->map_seq += msk->ack_seq;
		MPTCP_SKB_CB(skb)->end_seq += msk->ack_seq;
	}

	pr_debug("msk=%p ack_seq=%llx", msk, msk->ack_seq);
	mptcp_data_unlock(sk);
}
