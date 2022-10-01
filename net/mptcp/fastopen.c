/* SPDX-License-Identifier: GPL-2.0
 * MPTCP Fast Open Mechanism. Copyright (c) 2021-2022, Dmytro SHYTYI
 */

#include "protocol.h"

struct mptcp_skb_cb {
	u64 map_seq;
	u64 end_seq;
	u32 offset;
	u8  has_rxtstamp:1;
};

#define MPTCP_SKB_CB(__skb)	((struct mptcp_skb_cb *)&((__skb)->cb[0]))

void subflow_fastopen_send_synack_set_params(struct mptcp_subflow_context *subflow,
					     struct request_sock *treq)
{
	struct tcp_request_sock *tcp_r_sock = tcp_rsk(treq);
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
	tp->copied_seq += tp->rcv_nxt - tcp_r_sock->rcv_isn - 1;
	subflow->map_seq = mptcp_subflow_get_mapped_dsn(subflow);
	subflow->ssn_offset = tp->copied_seq - 1;

	/* innitialize MPTCP_CB */
	offset = tp->copied_seq - TCP_SKB_CB(skb)->seq;
	MPTCP_SKB_CB(skb)->map_seq = mptcp_subflow_get_mapped_dsn(subflow);
	MPTCP_SKB_CB(skb)->end_seq = msk->ack_seq;
	MPTCP_SKB_CB(skb)->offset = offset;
	MPTCP_SKB_CB(skb)->has_rxtstamp = TCP_SKB_CB(skb)->has_rxtstamp;

	mptcp_data_lock(sk);

	mptcp_set_owner_r(skb, sk);
	__skb_queue_tail(&msk->receive_queue, skb);

	(sk)->sk_data_ready(sk);

	mptcp_data_unlock(sk);
}

void __mptcp_pre_connect(struct mptcp_sock *msk, struct sock *ssk,
			 struct msghdr *msg, size_t size)
{
	struct tcp_sock *tp;
	struct sk_buff *skb;
	struct ubuf_info *uarg;

	lock_sock(ssk);

	tp = tcp_sk(ssk);

	skb = tcp_write_queue_tail(ssk);
	uarg = msg_zerocopy_realloc(ssk, size, skb_zcopy(skb));
	tp->fastopen_req = kzalloc(sizeof(*tp->fastopen_req),
				   ssk->sk_allocation);
	tp->fastopen_req->data = msg;
	tp->fastopen_req->size = size;
	tp->fastopen_req->uarg = uarg;

	release_sock(ssk);
}

void mptcp_gen_msk_ackseq_fastopen(struct mptcp_sock *msk, struct mptcp_subflow_context *subflow,
				   struct mptcp_options_received mp_opt)
{
	u64 ack_seq;

	WRITE_ONCE(msk->can_ack, true);
	WRITE_ONCE(msk->remote_key, mp_opt.sndr_key);
	mptcp_crypto_key_sha(msk->remote_key, NULL, &ack_seq);
	ack_seq++;
	WRITE_ONCE(msk->ack_seq, ack_seq);
	pr_debug("ack_seq=%llu sndr_key=%llu", msk->ack_seq, mp_opt.sndr_key);
	atomic64_set(&msk->rcv_wnd_sent, ack_seq);
}
