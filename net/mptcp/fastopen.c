/* SPDX-License-Identifier: GPL-2.0
 * MPTCP Fast Open Mechanism. Copyright (c) 2021-2022, Dmytro SHYTYI
 */

#include "protocol.h"

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
