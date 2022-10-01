/* SPDX-License-Identifier: GPL-2.0
 * MPTCP Fast Open Mechanism. Copyright (c) 2021-2022, Dmytro SHYTYI
 */

#include "protocol.h"

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
