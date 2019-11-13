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
		pr_debug("subflow=%p", msk->subflow->sk);
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

	pr_debug("msk=%p, subflow=%p", msk, msk->subflow->sk);

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

static struct inet_protosw mptcp_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_MPTCP,
	.prot		= &mptcp_prot,
	.ops		= &inet_stream_ops,
};

void __init mptcp_init(void)
{
	if (proto_register(&mptcp_prot, 1) != 0)
		panic("Failed to register MPTCP proto.\n");

	inet_register_protosw(&mptcp_protosw);
}
