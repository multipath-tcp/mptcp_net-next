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
