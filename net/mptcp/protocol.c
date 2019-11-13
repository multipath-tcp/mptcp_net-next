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

static int mptcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow = msk->subflow;

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL))
		return -EOPNOTSUPP;

	return sock_sendmsg(subflow, msg);
}

static int mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow = msk->subflow;

	return sock_recvmsg(subflow, msg, flags);
}

static int mptcp_init_sock(struct sock *sk)
{
	return 0;
}

static void mptcp_close(struct sock *sk, long timeout)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	inet_sk_state_store(sk, TCP_CLOSE);

	if (msk->subflow) {
		pr_debug("subflow=%p", mptcp_subflow_ctx(msk->subflow->sk));
		sock_release(msk->subflow);
	}

	sock_orphan(sk);
	sock_put(sk);
}

static int mptcp_connect(struct sock *sk, struct sockaddr *saddr, int len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	int err;

	saddr->sa_family = AF_INET;

	pr_debug("msk=%p, subflow=%p", msk,
		 mptcp_subflow_ctx(msk->subflow->sk));

	err = kernel_connect(msk->subflow, saddr, len, 0);

	sk->sk_state = TCP_ESTABLISHED;

	return err;
}

static struct proto mptcp_prot = {
	.name		= "MPTCP",
	.owner		= THIS_MODULE,
	.init		= mptcp_init_sock,
	.close		= mptcp_close,
	.accept		= inet_csk_accept,
	.connect	= mptcp_connect,
	.shutdown	= tcp_shutdown,
	.sendmsg	= mptcp_sendmsg,
	.recvmsg	= mptcp_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
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

	mptcp_subflow_init();

	if (proto_register(&mptcp_prot, 1) != 0)
		panic("Failed to register MPTCP proto.\n");

	inet_register_protosw(&mptcp_protosw);
}
