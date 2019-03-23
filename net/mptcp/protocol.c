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

static int mptcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow;

	if (msk->connection_list) {
		subflow = msk->connection_list;
		pr_debug("conn_list->subflow=%p", subflow->sk);
	} else {
		subflow = msk->subflow;
		pr_debug("subflow=%p", subflow->sk);
	}

	return sock_sendmsg(subflow, msg);
}

static int mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow;

	if (msk->connection_list) {
		subflow = msk->connection_list;
		pr_debug("conn_list->subflow=%p", subflow->sk);
	} else {
		subflow = msk->subflow;
		pr_debug("subflow=%p", subflow->sk);
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
		pr_debug("subflow=%p", msk->subflow->sk);
		sock_release(msk->subflow);
	}

	if (msk->connection_list) {
		pr_debug("conn_list->subflow=%p", msk->connection_list->sk);
		sock_release(msk->connection_list);
	}
}

static int mptcp_get_port(struct sock *sk, unsigned short snum)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct sock *subflow = msk->subflow->sk;

	pr_debug("msk=%p, subflow=%p", sk, subflow);

	return inet_csk_get_port(subflow, snum);
}

void mptcp_finish_connect(struct sock *sk, int mp_capable)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct subflow_sock *subflow = subflow_sk(msk->subflow->sk);

	pr_debug("msk=%p", msk);

	if (mp_capable) {
		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->connection_list = msk->subflow;
		msk->subflow = NULL;
	}
	sk->sk_state = TCP_ESTABLISHED;
}

static int subflow_create(struct sock *sock)
{
	struct mptcp_sock *msk = mptcp_sk(sock);
	struct socket *sf;
	int err;

	err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_SUBFLOW,
			       &sf);
	if (!err) {
		struct subflow_sock *subflow = subflow_sk(sf->sk);

		pr_debug("subflow=%p", subflow);
		msk->subflow = sf;
		subflow->conn = sock;
		subflow->request_mptcp = 1; // @@ if MPTCP enabled
		subflow->checksum = 1; // @@ if checksum enabled
		subflow->version = 0;
	}
	return err;
}

int mptcp_stream_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *subflow = msk->subflow;

	pr_debug("msk=%p, subflow=%p", msk, subflow->sk);

	return inet_bind(subflow, uaddr, addr_len);
}

int mptcp_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			 int addr_len, int flags)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err;

	pr_debug("msk=%p", msk);

	if (!msk->subflow) {
		err = subflow_create(sock->sk);
		if (err)
			return err;
	}

	return inet_stream_connect(msk->subflow, uaddr, addr_len, flags);
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

static struct proto mptcp_prot = {
	.name		= "MPTCP",
	.owner		= THIS_MODULE,
	.init		= mptcp_init_sock,
	.close		= mptcp_close,
	.accept		= inet_csk_accept,
	.shutdown	= tcp_shutdown,
	.sendmsg	= mptcp_sendmsg,
	.recvmsg	= mptcp_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= mptcp_get_port,
	.obj_size	= sizeof(struct mptcp_sock),
	.no_autobind	= 1,
};

const struct proto_ops mptcp_stream_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = mptcp_stream_bind,
	.connect	   = mptcp_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,
	.poll		   = mptcp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
	.splice_read	   = tcp_splice_read,
	.read_sock	   = tcp_read_sock,
	.peek_len	   = tcp_peek_len,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};

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

	err = mptcp_subflow_init();
	if (err)
		goto subflow_failed;

	err = proto_register(&mptcp_prot, 1);
	if (err)
		goto proto_failed;

	inet_register_protosw(&mptcp_protosw);

	return 0;

proto_failed:
	mptcp_subflow_exit();

subflow_failed:
	return err;
}

static void __exit mptcp_exit(void)
{
	inet_unregister_protosw(&mptcp_protosw);
	proto_unregister(&mptcp_prot);

	mptcp_subflow_exit();
}

module_init(mptcp_init);
module_exit(mptcp_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_INET, IPPROTO_MPTCP);
MODULE_ALIAS_NET_PF_PROTO(PF_INET6, IPPROTO_MPTCP);
