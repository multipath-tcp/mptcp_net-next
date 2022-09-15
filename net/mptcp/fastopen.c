/* SPDX-License-Identifier: GPL-2.0
 * MPTCP Fast Open Mechanism. Copyright (c) 2021-2022, Dmytro SHYTYI
 */

#include "protocol.h"

int mptcp_sendmsg_fastopen(struct sock *sk, struct msghdr *msg,
			   size_t len, struct mptcp_sock *msk,
			   size_t *copied)
{
	const struct iphdr *iph;
	struct ubuf_info *uarg;
	struct sockaddr *uaddr;
	struct sk_buff *skb;
	struct tcp_sock *tp;
	struct socket *ssk;
	int ret;

	lock_sock((struct sock *)msk);
	ssk = __mptcp_nmpc_socket(msk);
	if (unlikely(!ssk))
		goto out_EFAULT;
	skb = tcp_stream_alloc_skb(ssk->sk, 0, ssk->sk->sk_allocation, true);
	if (unlikely(!skb))
		goto out_EFAULT;
	iph = ip_hdr(skb);
	if (unlikely(!iph))
		goto out_EFAULT;
	uarg = msg_zerocopy_realloc(sk, len, skb_zcopy(skb));
	if (unlikely(!uarg))
		goto out_EFAULT;
	uaddr = msg->msg_name;

	lock_sock(ssk->sk);

	tp = tcp_sk(ssk->sk);
	if (unlikely(!tp))
		goto out_lock_EFAULT;
	if (!tp->fastopen_req)
		tp->fastopen_req = kzalloc(sizeof(*tp->fastopen_req),
					   ssk->sk->sk_allocation);

	if (unlikely(!tp->fastopen_req))
		goto out_lock_EFAULT;
	tp->fastopen_req->data = msg;
	tp->fastopen_req->size = len;
	tp->fastopen_req->uarg = uarg;

	release_sock(ssk->sk);
	release_sock((struct sock *)msk);

	/* requests a cookie */
	ret = mptcp_stream_connect(sk->sk_socket, uaddr,
				   msg->msg_namelen, msg->msg_flags);
	if (!ret)
		*copied = len;
	return ret;

out_lock_EFAULT:
	release_sock(ssk->sk);
out_EFAULT:
	release_sock((struct sock *)msk);
	ret = -EFAULT;
	return ret;
}

int mptcp_setsockopt_sol_tcp_fastopen(struct mptcp_sock *msk, sockptr_t optval,
				      unsigned int optlen)
{
	struct sock *sk = (struct sock *)msk;
	struct net *net = sock_net(sk);
	int val;
	int ret;

	ret = 0;

	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	lock_sock(sk);

	if (val >= 0 && ((1 << sk->sk_state) & (TCPF_CLOSE |
	    TCPF_LISTEN))) {
		tcp_fastopen_init_key_once(net);
		fastopen_queue_tune(sk, val);
	} else {
		ret = -EINVAL;
	}

	release_sock(sk);

	return ret;
}

void mptcp_treat_hshake_ack_fastopen(struct mptcp_sock *msk, struct mptcp_subflow_context *subflow,
				 struct mptcp_options_received mp_opt)
{
	u64 ack_seq;

	if (mp_opt.suboptions & OPTIONS_MPTCP_MPC && mp_opt.is_mptfo && msk->is_mptfo) {
		msk->can_ack = true;
		msk->remote_key = mp_opt.sndr_key;
		mptcp_crypto_key_sha(msk->remote_key, NULL, &ack_seq);
		ack_seq++;
		WRITE_ONCE(msk->ack_seq, ack_seq);
		pr_debug("ack_seq=%llu sndr_key=%llu", msk->ack_seq, mp_opt.sndr_key);
		atomic64_set(&msk->rcv_wnd_sent, ack_seq);
	}
}

void mptcp_fastopen_add_skb(struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct tcp_request_sock *tcp_r_sock = tcp_rsk(req);
	struct sock *socket = mptcp_subflow_ctx(sk)->conn;
	struct mptcp_sock *msk = mptcp_sk(socket);
	struct tcp_sock *tp = tcp_sk(sk);

	if (TCP_SKB_CB(skb)->end_seq == tp->rcv_nxt)
		return;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		return;

	skb_dst_drop(skb);

	tp->segs_in = 0;
	tcp_segs_in(tp, skb);
	__skb_pull(skb, tcp_hdrlen(skb));
	sk_forced_mem_schedule(sk, skb->truesize);

	TCP_SKB_CB(skb)->seq++;
	TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_SYN;

	tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;

	msk->is_mptfo = 1;

	//Solves: WARNING: at 704 _mptcp_move_skbs_from_subflow+0x5d0/0x651
	tp->copied_seq += tp->rcv_nxt - tcp_r_sock->rcv_isn - 1;

	TCP_SKB_CB(skb)->seq += tp->rcv_nxt - tcp_r_sock->rcv_isn - 1;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq;

	TCP_SKB_CB(skb)->seq += tp->rcv_nxt - tcp_r_sock->rcv_isn - 1;
	TCP_SKB_CB(skb)->end_seq =  TCP_SKB_CB(skb)->seq;

	subflow->map_seq = mptcp_subflow_get_mapped_dsn(subflow);

	//Solves: BAD mapping: ssn=0 map_seq=1 map_data_len=3
	subflow->ssn_offset = tp->copied_seq - 1;

	skb_ext_reset(skb);

	//mptcp_set_owner_r begin
	skb_orphan(skb);
	skb->sk = socket;
	skb->destructor = mptcp_rfree;
	atomic_add(skb->truesize, &socket->sk_rmem_alloc);
	msk->rmem_fwd_alloc -= skb->truesize;
	//mptcp_set owner_r end

	__skb_queue_tail(&msk->receive_queue, skb);

	atomic64_set(&msk->rcv_wnd_sent, mptcp_subflow_get_mapped_dsn(subflow));

	tp->syn_data_acked = 1;

	tp->bytes_received = skb->len;

	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		tcp_fin(sk);
}
