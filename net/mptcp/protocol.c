// SPDX-License-Identifier: GPL-2.0
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

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

static int mptcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	int mss_now, size_goal, poffset, ret;
	struct mptcp_ext *mpext = NULL;
	struct page *page = NULL;
	struct sk_buff *skb;
	struct sock *ssk;
	size_t psize;

	pr_debug("msk=%p", msk);
	if (!msk->connection_list && msk->subflow) {
		pr_debug("fallback passthrough");
		return sock_sendmsg(msk->subflow, msg);
	}

	if (!msg_data_left(msg)) {
		pr_debug("empty send");
		return sock_sendmsg(msk->connection_list, msg);
	}

	ssk = msk->connection_list->sk;

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL))
		return -ENOTSUPP;

	/* Initial experiment: new page per send.  Real code will
	 * maintain list of active pages and DSS mappings, append to the
	 * end and honor zerocopy
	 */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	/* Copy to page */
	poffset = 0;
	pr_debug("left=%zu", msg_data_left(msg));
	psize = copy_page_from_iter(page, poffset,
				    min_t(size_t, msg_data_left(msg),
					  PAGE_SIZE),
				    &msg->msg_iter);
	pr_debug("left=%zu", msg_data_left(msg));

	if (!psize) {
		put_page(page);
		return -EINVAL;
	}

	lock_sock(sk);
	lock_sock(ssk);

	/* Mark the end of the previous write so the beginning of the
	 * next write (with its own mptcp skb extension data) is not
	 * collapsed.
	 */
	skb = tcp_write_queue_tail(ssk);
	if (skb)
		TCP_SKB_CB(skb)->eor = 1;

	mss_now = tcp_send_mss(ssk, &size_goal, msg->msg_flags);

	ret = do_tcp_sendpages(ssk, page, poffset, min_t(int, size_goal, psize),
			       msg->msg_flags | MSG_SENDPAGE_NOTLAST);
	put_page(page);
	if (ret <= 0)
		goto error_out;

	if (skb == tcp_write_queue_tail(ssk))
		pr_err("no new skb %p/%p", sk, ssk);

	skb = tcp_write_queue_tail(ssk);

	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);

	if (mpext) {
		memset(mpext, 0, sizeof(*mpext));
		mpext->data_ack = msk->ack_seq;
		mpext->data_seq = msk->write_seq;
		mpext->subflow_seq = subflow_ctx(ssk)->rel_write_seq;
		mpext->data_len = ret;
		mpext->checksum = 0xbeef;
		mpext->use_map = 1;
		mpext->dsn64 = 1;
		mpext->use_ack = 1;
		mpext->ack64 = 1;

		pr_debug("data_seq=%llu subflow_seq=%u data_len=%u checksum=%u, dsn64=%d",
			 mpext->data_seq, mpext->subflow_seq, mpext->data_len,
			 mpext->checksum, mpext->dsn64);
	} /* TODO: else fallback */

	msk->write_seq += ret;
	subflow_ctx(ssk)->rel_write_seq += ret;

	tcp_push(ssk, msg->msg_flags, mss_now, tcp_sk(ssk)->nonagle, size_goal);

error_out:
	release_sock(ssk);
	release_sock(sk);

	return ret;
}

static int mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow;

	if (msk->connection_list) {
		subflow = msk->connection_list;
		pr_debug("conn_list->subflow=%p", subflow_ctx(subflow->sk));
	} else {
		subflow = msk->subflow;
		pr_debug("subflow=%p", subflow_ctx(subflow->sk));
	}

	return sock_recvmsg(subflow, msg, flags);
}

static int mptcp_init_sock(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p", msk);

	return 0;
}

static void mptcp_close(struct sock *sk, long timeout)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (msk->subflow) {
		pr_debug("subflow=%p", subflow_ctx(msk->subflow->sk));
		sock_release(msk->subflow);
	}

	if (msk->connection_list) {
		pr_debug("conn_list->subflow=%p", subflow_ctx(msk->connection_list->sk));
		sock_release(msk->connection_list);
	}
}

static struct sock *mptcp_accept(struct sock *sk, int flags, int *err,
				 bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *listener = msk->subflow;
	struct socket *new_sock;
	struct socket *new_mptcp_sock;
	struct subflow_context *subflow;

	pr_debug("msk=%p, listener=%p", msk, subflow_ctx(listener->sk));
	*err = kernel_accept(listener, &new_sock, flags);
	if (*err < 0)
		return NULL;

	subflow = subflow_ctx(new_sock->sk);
	pr_debug("new subflow=%p", subflow);

	*err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_MPTCP, &new_mptcp_sock);
	if (*err < 0) {
		kernel_sock_shutdown(new_sock, SHUT_RDWR);
		sock_release(new_sock);
		return NULL;
	}

	msk = mptcp_sk(new_mptcp_sock->sk);
	pr_debug("new msk=%p", msk);
	subflow->conn = new_mptcp_sock->sk;

	if (subflow->mp_capable) {
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		token_update_accept(new_sock->sk, new_mptcp_sock->sk);
		msk->write_seq = subflow->idsn + 1;
		subflow->rel_write_seq = 1;
		msk->remote_key = subflow->remote_key;
		crypto_key_sha1(msk->remote_key, NULL, &msk->ack_seq);
		msk->ack_seq++;
		msk->connection_list = new_sock;
	} else {
		msk->subflow = new_sock;
	}

	return new_mptcp_sock->sk;
}

static void mptcp_destroy(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p, subflow=%p", sk, msk->subflow->sk);

	token_destroy(msk->token);
}

static int mptcp_setsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, unsigned int optlen)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow;
	char __kernel *optval;

	pr_debug("msk=%p", msk);
	if (msk->connection_list) {
		subflow = msk->connection_list;
		pr_debug("conn_list->subflow=%p", subflow_ctx(subflow->sk));
	} else {
		subflow = msk->subflow;
		pr_debug("subflow=%p", subflow_ctx(subflow->sk));
	}

	/* will be treated as __user in tcp_setsockopt */
	optval = (char __kernel __force *)uoptval;

	return kernel_setsockopt(subflow, level, optname, optval, optlen);
}

static int mptcp_getsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, int __user *uoption)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow;
	char __kernel *optval;
	int __kernel *option;

	pr_debug("msk=%p", msk);
	if (msk->connection_list) {
		subflow = msk->connection_list;
		pr_debug("conn_list->subflow=%p", subflow_ctx(subflow->sk));
	} else {
		subflow = msk->subflow;
		pr_debug("subflow=%p", subflow_ctx(subflow->sk));
	}

	/* will be treated as __user in tcp_getsockopt */
	optval = (char __kernel __force *)uoptval;
	option = (int __kernel __force *)uoption;

	return kernel_getsockopt(subflow, level, optname, optval, option);
}

static int mptcp_get_port(struct sock *sk, unsigned short snum)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p, subflow=%p", msk, subflow_ctx(msk->subflow->sk));

	return inet_csk_get_port(msk->subflow->sk, snum);
}

void mptcp_finish_connect(struct sock *sk, int mp_capable)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct subflow_context *subflow = subflow_ctx(msk->subflow->sk);

	pr_debug("msk=%p", msk);

	if (mp_capable) {
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		msk->write_seq = subflow->idsn + 1;
		subflow->rel_write_seq = 1;
		msk->remote_key = subflow->remote_key;
		crypto_key_sha1(msk->remote_key, NULL, &msk->ack_seq);
		msk->ack_seq++;
		msk->connection_list = msk->subflow;
		msk->subflow = NULL;
	}
	sk->sk_state = TCP_ESTABLISHED;
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

static int mptcp_subflow_create(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct net *net = sock_net(sk);
	struct socket *sf;
	int err;

	pr_debug("msk=%p", msk);
	err = sock_create_kern(net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sf);
	if (!err) {
		lock_sock(sf->sk);
		err = tcp_set_ulp(sf->sk, "mptcp");
		release_sock(sf->sk);
		if (!err) {
			struct subflow_context *subflow = subflow_ctx(sf->sk);

			pr_debug("subflow=%p", subflow);
			msk->subflow = sf;
			subflow->conn = sk;
			subflow->request_mptcp = 1; // @@ if MPTCP enabled
			subflow->request_cksum = 1; // @@ if checksum enabled
			subflow->version = 0;
		}
	}
	return err;
}

static int mptcp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err = -ENOTSUPP;

	pr_debug("msk=%p", msk);

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	if (!msk->subflow) {
	        err = mptcp_subflow_create(sock->sk);
	        if (err)
	                return err;
	}
	return inet_bind(msk->subflow, uaddr, addr_len);
}

static int mptcp_stream_connect(struct socket *sock, struct sockaddr *uaddr,
				int addr_len, int flags)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err = -ENOTSUPP;

	pr_debug("msk=%p", msk);

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	if (!msk->subflow) {
		err = mptcp_subflow_create(sock->sk);
		if (err)
			return err;
	}

	return inet_stream_connect(msk->subflow, uaddr, addr_len, flags);
}

static int mptcp_getname(struct socket *sock, struct sockaddr *uaddr,
			 int peer)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *subflow;
	int err = -EPERM;

	if (msk->connection_list)
		subflow = msk->connection_list;
	else
		subflow = msk->subflow;

	err = inet_getname(subflow, uaddr, peer);

	return err;
}

static int mptcp_listen(struct socket *sock, int backlog)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err;

	pr_debug("msk=%p", msk);

	if (!msk->subflow) {
		err = mptcp_subflow_create(sock->sk);
		if (err)
			return err;
	}
	return inet_listen(msk->subflow, backlog);
}

static int mptcp_stream_accept(struct socket *sock, struct socket *newsock,
			       int flags, bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);

	pr_debug("msk=%p", msk);

	if (!msk->subflow)
		return -EINVAL;

	return inet_accept(sock, newsock, flags, kern);
}

static __poll_t mptcp_poll(struct file *file, struct socket *sock,
			   struct poll_table_struct *wait)
{
	const struct mptcp_sock *msk;
	struct sock *sk = sock->sk;

	msk = mptcp_sk(sk);
	if (msk->subflow)
		return tcp_poll(file, msk->subflow, wait);

	return tcp_poll(file, msk->connection_list, wait);
}

static int mptcp_shutdown(struct socket *sock, int how)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int ret = 0;

	pr_debug("sk=%p, how=%d", msk, how);

	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		ret = kernel_sock_shutdown(msk->subflow, how);
	}

	if (msk->connection_list) {
		pr_debug("conn_list->subflow=%p", msk->connection_list->sk);
		ret = kernel_sock_shutdown(msk->connection_list, how);
	}

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

static int __init mptcp_init(void)
{
	int err;

	mptcp_prot.h.hashinfo = tcp_prot.h.hashinfo;
	mptcp_stream_ops = inet_stream_ops;
	mptcp_stream_ops.bind = mptcp_bind;
	mptcp_stream_ops.connect = mptcp_stream_connect;
	mptcp_stream_ops.poll = mptcp_poll;
	mptcp_stream_ops.accept = mptcp_stream_accept;
	mptcp_stream_ops.getname = mptcp_getname;
	mptcp_stream_ops.listen = mptcp_listen;
	mptcp_stream_ops.shutdown = mptcp_shutdown;

	token_init();
	crypto_init();

	err = subflow_init();
	if (err)
		goto subflow_failed;

	err = proto_register(&mptcp_prot, 1);
	if (err)
		goto proto_failed;

	inet_register_protosw(&mptcp_protosw);

	return 0;

proto_failed:
	subflow_exit();

subflow_failed:
	return err;
}

static void __exit mptcp_exit(void)
{
	inet_unregister_protosw(&mptcp_protosw);
	proto_unregister(&mptcp_prot);

	subflow_exit();
}

module_init(mptcp_init);
module_exit(mptcp_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_INET, IPPROTO_MPTCP);
MODULE_ALIAS_NET_PF_PROTO(PF_INET6, IPPROTO_MPTCP);
