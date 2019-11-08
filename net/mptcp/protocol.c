// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

static struct socket *__mptcp_fallback_get_ref(const struct mptcp_sock *msk)
{
	sock_owned_by_me((const struct sock *)msk);

	if (!msk->subflow)
		return NULL;

	sock_hold(msk->subflow->sk);
	return msk->subflow;
}

static struct socket *mptcp_fallback_get_ref(const struct mptcp_sock *msk)
{
	struct socket *ssock;

	lock_sock((struct sock *)msk);
	ssock = __mptcp_fallback_get_ref(msk);
	release_sock((struct sock *)msk);

	return ssock;
}

static struct sock *mptcp_subflow_get(const struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	sock_owned_by_me((const struct sock *)msk);

	mptcp_for_each_subflow(msk, subflow) {
		return mptcp_subflow_tcp_socket(subflow)->sk;
	}

	return NULL;
}

static int mptcp_sendmsg_frag(struct sock *sk, struct sock *ssk,
			      struct msghdr *msg, long *timeo)
{
	int mss_now = 0, size_goal = 0, ret = 0;
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_ext *mpext = NULL;
	struct page_frag *pfrag;
	struct sk_buff *skb;
	size_t psize;

	/* use the mptcp page cache so that we can easily move the data
	 * from one substream to another, but do per subflow memory accounting
	 */
	pfrag = sk_page_frag(sk);
	while (!sk_page_frag_refill(ssk, pfrag)) {
		ret = sk_stream_wait_memory(ssk, timeo);
		if (ret)
			return ret;
	}

	/* compute copy limit */
	mss_now = tcp_send_mss(ssk, &size_goal, msg->msg_flags);
	psize = min_t(int, pfrag->size - pfrag->offset, size_goal);

	pr_debug("left=%zu", msg_data_left(msg));
	psize = copy_page_from_iter(pfrag->page, pfrag->offset,
				    min_t(size_t, msg_data_left(msg), psize),
				    &msg->msg_iter);
	pr_debug("left=%zu", msg_data_left(msg));
	if (!psize)
		return -EINVAL;

	/* Mark the end of the previous write so the beginning of the
	 * next write (with its own mptcp skb extension data) is not
	 * collapsed.
	 */
	skb = tcp_write_queue_tail(ssk);
	if (skb)
		TCP_SKB_CB(skb)->eor = 1;

	ret = do_tcp_sendpages(ssk, pfrag->page, pfrag->offset, psize,
			       msg->msg_flags | MSG_SENDPAGE_NOTLAST);
	if (ret <= 0)
		return ret;
	if (unlikely(ret < psize))
		iov_iter_revert(&msg->msg_iter, psize - ret);

	skb = tcp_write_queue_tail(ssk);
	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);
	if (mpext) {
		memset(mpext, 0, sizeof(*mpext));
		mpext->data_seq = msk->write_seq;
		mpext->subflow_seq = mptcp_subflow_ctx(ssk)->rel_write_seq;
		mpext->data_len = ret;
		mpext->use_map = 1;
		mpext->dsn64 = 1;

		pr_debug("data_seq=%llu subflow_seq=%u data_len=%u dsn64=%d",
			 mpext->data_seq, mpext->subflow_seq, mpext->data_len,
			 mpext->dsn64);
	} /* TODO: else fallback */

	pfrag->offset += ret;
	msk->write_seq += ret;
	mptcp_subflow_ctx(ssk)->rel_write_seq += ret;

	tcp_push(ssk, msg->msg_flags, mss_now, tcp_sk(ssk)->nonagle, size_goal);
	return ret;
}

static int mptcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *ssock;
	size_t copied = 0;
	struct sock *ssk;
	int ret = 0;
	long timeo;

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL))
		return -EOPNOTSUPP;

	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sk);
		pr_debug("fallback passthrough");
		ret = sock_sendmsg(ssock, msg);
		sock_put(ssock->sk);
		return ret;
	}

	ssk = mptcp_subflow_get(msk);
	if (!ssk) {
		release_sock(sk);
		return -ENOTCONN;
	}

	if (!msg_data_left(msg)) {
		pr_debug("empty send");
		ret = sock_sendmsg(ssk->sk_socket, msg);
		goto out;
	}

	pr_debug("conn_list->subflow=%p", ssk);

	lock_sock(ssk);
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	while (msg_data_left(msg)) {
		ret = mptcp_sendmsg_frag(sk, ssk, msg, &timeo);
		if (ret < 0)
			break;

		copied += ret;
	}

	if (copied > 0)
		ret = copied;

	release_sock(ssk);

out:
	release_sock(sk);
	return ret;
}

static int mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *ssock;
	struct sock *ssk;
	int copied = 0;

	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sk);
		pr_debug("fallback-read subflow=%p",
			 mptcp_subflow_ctx(ssock->sk));
		copied = sock_recvmsg(ssock, msg, flags);
		sock_put(ssock->sk);
		return copied;
	}

	ssk = mptcp_subflow_get(msk);
	if (!ssk) {
		release_sock(sk);
		return -ENOTCONN;
	}

	copied = sock_recvmsg(ssk->sk_socket, msg, flags);

	release_sock(sk);

	return copied;
}

static int mptcp_init_sock(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct net *net = sock_net(sk);
	struct socket *sf;
	int err;

	err = sock_create_kern(net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sf);
	if (!err) {
		pr_debug("subflow=%p", sf->sk);
		msk->subflow = sf;
	}

	INIT_LIST_HEAD(&msk->conn_list);

	return err;
}

static void mptcp_close(struct sock *sk, long timeout)
{
	struct mptcp_subflow_context *subflow, *tmp;
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *ssk = NULL;

	mptcp_token_destroy(msk->token);
	inet_sk_state_store(sk, TCP_CLOSE);

	lock_sock(sk);

	if (msk->subflow) {
		ssk = msk->subflow;
		msk->subflow = NULL;
	}

	if (ssk) {
		pr_debug("subflow=%p", ssk->sk);
		sock_release(ssk);
	}

	list_for_each_entry_safe(subflow, tmp, &msk->conn_list, node) {
		pr_debug("conn_list->subflow=%p", subflow);
		sock_release(mptcp_subflow_tcp_socket(subflow));
	}

	release_sock(sk);
	sk_common_release(sk);
}

static struct sock *mptcp_accept(struct sock *sk, int flags, int *err,
				 bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_subflow_context *subflow;
	struct socket *new_sock;
	struct socket *listener;
	struct sock *newsk;

	listener = msk->subflow;

	pr_debug("msk=%p, listener=%p", msk, mptcp_subflow_ctx(listener->sk));
	*err = kernel_accept(listener, &new_sock, flags);
	if (*err < 0)
		return NULL;

	subflow = mptcp_subflow_ctx(new_sock->sk);
	pr_debug("msk=%p, new subflow=%p, ", msk, subflow);

	if (subflow->mp_capable) {
		struct sock *new_mptcp_sock;
		u64 ack_seq;

		lock_sock(sk);

		local_bh_disable();
		new_mptcp_sock = sk_clone_lock(sk, GFP_ATOMIC);
		if (!new_mptcp_sock) {
			*err = -ENOBUFS;
			local_bh_enable();
			release_sock(sk);
			kernel_sock_shutdown(new_sock, SHUT_RDWR);
			sock_release(new_sock);
			return NULL;
		}

		mptcp_init_sock(new_mptcp_sock);

		msk = mptcp_sk(new_mptcp_sock);
		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;

		mptcp_token_update_accept(new_sock->sk, new_mptcp_sock);
		msk->subflow = NULL;

		mptcp_crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		msk->write_seq = subflow->idsn + 1;
		ack_seq++;
		msk->ack_seq = ack_seq;
		subflow->rel_write_seq = 1;
		newsk = new_mptcp_sock;
		subflow->conn = new_mptcp_sock;
		list_add(&subflow->node, &msk->conn_list);
		bh_unlock_sock(new_mptcp_sock);
		local_bh_enable();
		inet_sk_state_store(newsk, TCP_ESTABLISHED);
		release_sock(sk);
	} else {
		newsk = new_sock->sk;
		tcp_sk(newsk)->is_mptcp = 0;
		new_sock->sk = NULL;
		sock_release(new_sock);
	}

	return newsk;
}

static void mptcp_destroy(struct sock *sk)
{
}

static int mptcp_setsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, unsigned int optlen)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	char __kernel *optval;
	struct socket *ssock;
	int ret;

	/* will be treated as __user in tcp_setsockopt */
	optval = (char __kernel __force *)uoptval;

	pr_debug("msk=%p", msk);
	ssock = mptcp_fallback_get_ref(msk);
	if (ssock) {
		pr_debug("subflow=%p", ssock->sk);
		ret = kernel_setsockopt(ssock, level, optname, optval, optlen);
		sock_put(ssock->sk);
		return ret;
	}

	/* @@ the meaning of setsockopt() when the socket is connected and
	 * there are multiple subflows is not defined.
	 */
	return -EOPNOTSUPP;
}

static int mptcp_getsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, int __user *uoption)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	char __kernel *optval;
	int __kernel *option;
	struct socket *ssock;
	int ret;

	/* will be treated as __user in tcp_getsockopt */
	optval = (char __kernel __force *)uoptval;
	option = (int __kernel __force *)uoption;

	pr_debug("msk=%p", msk);
	ssock = mptcp_fallback_get_ref(msk);
	if (ssock) {
		pr_debug("subflow=%p", ssock->sk);
		ret = kernel_getsockopt(ssock, level, optname, optval, option);
		sock_put(ssock->sk);
		return ret;
	}

	/* @@ the meaning of getsockopt() when the socket is connected and
	 * there are multiple subflows is not defined.
	 */
	return -EOPNOTSUPP;
}

static int mptcp_get_port(struct sock *sk, unsigned short snum)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p, subflow=%p", msk,
		 mptcp_subflow_ctx(msk->subflow->sk));

	return inet_csk_get_port(msk->subflow->sk, snum);
}

void mptcp_finish_connect(struct sock *sk, int mp_capable)
{
	struct mptcp_subflow_context *subflow;
	struct mptcp_sock *msk = mptcp_sk(sk);

	subflow = mptcp_subflow_ctx(msk->subflow->sk);

	if (mp_capable) {
		u64 ack_seq;

		/* sk (new subflow socket) is already locked, but we need
		 * to lock the parent (mptcp) socket now to add the tcp socket
		 * to the subflow list.
		 *
		 * From lockdep point of view, this creates an ABBA type
		 * deadlock: Normally (sendmsg, recvmsg, ..), we lock the mptcp
		 * socket, then acquire a subflow lock.
		 * Here we do the reverse: "subflow lock, then mptcp lock".
		 *
		 * Its alright to do this here, because this subflow is not yet
		 * on the mptcp sockets subflow list.
		 *
		 * IOW, if another CPU has this mptcp socket locked, it cannot
		 * acquire this particular subflow, because subflow->sk isn't
		 * on msk->conn_list.
		 *
		 * This function can be called either from backlog processing
		 * (BH will be enabled) or from softirq, so we need to use BH
		 * locking scheme.
		 */
		local_bh_disable();
		bh_lock_sock_nested(sk);

		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		msk->write_seq = subflow->idsn + 1;
		subflow->rel_write_seq = 1;
		mptcp_crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		ack_seq++;
		msk->ack_seq = ack_seq;
		list_add(&subflow->node, &msk->conn_list);
		msk->subflow = NULL;
		bh_unlock_sock(sk);
		local_bh_enable();
	}
	inet_sk_state_store(sk, TCP_ESTABLISHED);
}

static struct proto mptcp_prot = {
	.name		= "MPTCP",
	.owner		= THIS_MODULE,
	.init		= mptcp_init_sock,
	.close		= mptcp_close,
	.accept		= mptcp_accept,
	.setsockopt	= mptcp_setsockopt,
	.getsockopt	= mptcp_getsockopt,
	.shutdown	= tcp_shutdown,
	.destroy	= mptcp_destroy,
	.sendmsg	= mptcp_sendmsg,
	.recvmsg	= mptcp_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= mptcp_get_port,
	.obj_size	= sizeof(struct mptcp_sock),
	.no_autobind	= 1,
};

static struct socket *mptcp_socket_create_get(struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	struct sock *sk = (struct sock *)msk;
	struct socket *ssock;
	int err;

	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock)
		goto release;

	err = mptcp_subflow_create_socket(sk, &ssock);
	if (err) {
		ssock = ERR_PTR(err);
		goto release;
	}

	msk->subflow = ssock;
	subflow = mptcp_subflow_ctx(msk->subflow->sk);
	subflow->request_mptcp = 1; /* @@ if MPTCP enabled */
	subflow->request_version = 0; /* currently only v0 supported */

	sock_hold(ssock->sk);

release:
	release_sock(sk);
	return ssock;
}

static int mptcp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err = -ENOTSUPP;

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	ssock = mptcp_socket_create_get(msk);
	if (IS_ERR(ssock))
		return PTR_ERR(ssock);

	err = ssock->ops->bind(ssock, uaddr, addr_len);
	sock_put(ssock->sk);
	return err;
}

static int mptcp_stream_connect(struct socket *sock, struct sockaddr *uaddr,
				int addr_len, int flags)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err = -ENOTSUPP;

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	ssock = mptcp_socket_create_get(msk);
	if (IS_ERR(ssock))
		return PTR_ERR(ssock);

	err = ssock->ops->connect(ssock, uaddr, addr_len, flags);
	sock_put(ssock->sk);
	return err;
}

static int mptcp_getname(struct socket *sock, struct sockaddr *uaddr,
			 int peer)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	struct sock *ssk;
	int ret;

	lock_sock(sock->sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sock->sk);
		pr_debug("subflow=%p", ssock->sk);
		ret = ssock->ops->getname(ssock, uaddr, peer);
		sock_put(ssock->sk);
		return ret;
	}

	/* @@ the meaning of getname() for the remote peer when the socket
	 * is connected and there are multiple subflows is not defined.
	 * For now just use the first subflow on the list.
	 */
	ssk = mptcp_subflow_get(msk);
	if (!ssk) {
		release_sock(sock->sk);
		return -ENOTCONN;
	}

	ret = ssk->sk_socket->ops->getname(ssk->sk_socket, uaddr, peer);
	release_sock(sock->sk);
	return ret;
}

static int mptcp_v4_getname(struct socket *sock, struct sockaddr *uaddr,
			    int peer)
{
	int ret;

	if (sock->sk->sk_prot == &tcp_prot) {
		/* we are being invoked from __sys_accept4, after
		 * mptcp_accept() has just accepted a non-mp-capable
		 * flow: sk is a tcp_sk, not an mptcp one.
		 *
		 * Hand the socket over to tcp so all further socket ops
		 * bypass mptcp.
		 */
		sock->ops = &inet_stream_ops;
		return sock->ops->getname(sock, uaddr, peer);
	}

	ret = mptcp_getname(sock, uaddr, peer);

	return ret;
}

static int mptcp_listen(struct socket *sock, int backlog)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err;

	pr_debug("msk=%p", msk);

	ssock = mptcp_socket_create_get(msk);
	if (IS_ERR(ssock))
		return PTR_ERR(ssock);

	err = ssock->ops->listen(ssock, backlog);
	sock_put(ssock->sk);
	return err;
}

static int mptcp_stream_accept(struct socket *sock, struct socket *newsock,
			       int flags, bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *ssock;
	int err;

	pr_debug("msk=%p", msk);

	ssock = mptcp_fallback_get_ref(msk);
	if (!ssock)
		return -EINVAL;

	err = ssock->ops->accept(sock, newsock, flags, kern);
	sock_put(ssock->sk);
	return err;
}

static __poll_t mptcp_poll(struct file *file, struct socket *sock,
			   struct poll_table_struct *wait)
{
	struct mptcp_subflow_context *subflow;
	const struct mptcp_sock *msk;
	struct sock *sk = sock->sk;
	struct socket *ssock;
	__poll_t ret = 0;

	msk = mptcp_sk(sk);
	lock_sock(sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sk);
		ret = ssock->ops->poll(file, ssock, wait);
		sock_put(ssock->sk);
		return ret;
	}

	release_sock(sk);
	sock_poll_wait(file, sock, wait);
	lock_sock(sk);

	mptcp_for_each_subflow(msk, subflow) {
		struct socket *tcp_sock;

		tcp_sock = mptcp_subflow_tcp_socket(subflow);
		ret |= __tcp_poll(tcp_sock->sk);
	}
	release_sock(sk);

	return ret;
}

static int mptcp_shutdown(struct socket *sock, int how)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct mptcp_subflow_context *subflow;
	struct socket *ssock;
	int ret = 0;

	pr_debug("sk=%p, how=%d", msk, how);

	lock_sock(sock->sk);
	ssock = __mptcp_fallback_get_ref(msk);
	if (ssock) {
		release_sock(sock->sk);
		pr_debug("subflow=%p", ssock->sk);
		ret = kernel_sock_shutdown(ssock, how);
		sock_put(ssock->sk);
		return ret;
	}

	mptcp_for_each_subflow(msk, subflow) {
		struct socket *tcp_socket;

		tcp_socket = mptcp_subflow_tcp_socket(subflow);
		pr_debug("conn_list->subflow=%p", subflow);
		ret = kernel_sock_shutdown(tcp_socket, how);
	}
	release_sock(sock->sk);

	return ret;
}

static struct proto_ops mptcp_stream_ops;

static struct inet_protosw mptcp_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_MPTCP,
	.prot		= &mptcp_prot,
	.ops		= &mptcp_stream_ops,
	.flags		= INET_PROTOSW_ICSK,
};

void __init mptcp_init(void)
{
	mptcp_prot.h.hashinfo = tcp_prot.h.hashinfo;
	mptcp_stream_ops = inet_stream_ops;
	mptcp_stream_ops.bind = mptcp_bind;
	mptcp_stream_ops.connect = mptcp_stream_connect;
	mptcp_stream_ops.poll = mptcp_poll;
	mptcp_stream_ops.accept = mptcp_stream_accept;
	mptcp_stream_ops.getname = mptcp_v4_getname;
	mptcp_stream_ops.listen = mptcp_listen;
	mptcp_stream_ops.shutdown = mptcp_shutdown;

	mptcp_subflow_init();

	if (proto_register(&mptcp_prot, 1) != 0)
		panic("Failed to register MPTCP proto.\n");

	inet_register_protosw(&mptcp_protosw);
}
