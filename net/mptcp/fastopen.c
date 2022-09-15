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

	tp = tcp_sk(ssk->sk);
	if (unlikely(!tp))
		goto out_EFAULT;
	if (!tp->fastopen_req)
		tp->fastopen_req = kzalloc(sizeof(*tp->fastopen_req),
					   ssk->sk->sk_allocation);

	if (unlikely(!tp->fastopen_req))
		goto out_EFAULT;
	tp->fastopen_req->data = msg;
	tp->fastopen_req->size = len;
	tp->fastopen_req->uarg = uarg;

	/* requests a cookie */
	ret = mptcp_stream_connect(sk->sk_socket, uaddr,
				   msg->msg_namelen, msg->msg_flags);
	if (!ret)
		*copied = len;
	return ret;
out_EFAULT:
	ret = -EFAULT;
	return ret;
}
