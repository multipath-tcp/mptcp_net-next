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

static int subflow_connect(struct sock *sk, struct sockaddr *saddr, int len)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	saddr->sa_family = AF_INET; // @@ presume IPv4 for now

	pr_debug("subflow=%p", subflow);

	return tcp_v4_connect(sk, saddr, len);
}

static int subflow_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	pr_debug("subflow=%p", subflow);

	return tcp_sendmsg(sk, msg, len);
}

static int subflow_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			   int nonblock, int flags, int *addr_len)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	pr_debug("subflow=%p", subflow);

	return tcp_recvmsg(sk, msg, len, nonblock, flags, addr_len);
}

static void subflow_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	inet_sk_rx_dst_set(sk, skb);

	pr_debug("subflow=%p", subflow);

	if (subflow->conn) {
		pr_debug("remote_key=%llu", subflow->remote_key);
		mptcp_finish_connect(subflow->conn, subflow->mp_capable);
		subflow->conn = NULL;
	}
}

const struct inet_connection_sock_af_ops subflow_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.sk_rx_dst_set	   = subflow_finish_connect,
	.conn_request	   = tcp_v4_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
	.mtu_reduced	   = tcp_v4_mtu_reduced,
};

static int subflow_init_sock(struct sock *sk)
{
	struct subflow_sock *subflow = subflow_sk(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int err;

	pr_debug("subflow=%p", subflow);

	err = tcp_v4_init_sock(sk);
	if (!err) { // @@ AND mptcp is enabled
		tsk->is_mptcp = 1;
		icsk->icsk_af_ops = &subflow_specific;
	}

	return err;
}

static void subflow_close(struct sock *sk, long timeout)
{
	pr_debug("subflow=%p", sk);

	tcp_close(sk, timeout);
}

static void subflow_destroy(struct sock *sk)
{
	pr_debug("subflow=%p", sk);

	tcp_v4_destroy_sock(sk);
}

static struct proto subflow_prot = {
	.name		= "SUBFLOW",
	.owner		= THIS_MODULE,
	.close		= subflow_close,
	.connect	= subflow_connect,
	.disconnect	= tcp_disconnect,
	.accept		= inet_csk_accept,
	.ioctl		= tcp_ioctl,
	.init		= subflow_init_sock,
	.destroy	= subflow_destroy,
	.shutdown	= tcp_shutdown,
	.keepalive	= tcp_set_keepalive,
	.recvmsg	= subflow_recvmsg,
	.sendmsg	= subflow_sendmsg,
	.sendpage	= tcp_sendpage,
	.backlog_rcv	= tcp_v4_do_rcv,
	.release_cb	= tcp_release_cb,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.stream_memory_free	= tcp_stream_memory_free,
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_wmem),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_rmem),
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct subflow_sock),
	.slab_flags		= SLAB_TYPESAFE_BY_RCU,

	.no_autobind		= true,
};

static struct inet_protosw subflow_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_SUBFLOW,
	.prot		= &subflow_prot,
	.ops		= &inet_stream_ops,
	.flags		= INET_PROTOSW_ICSK,
};

int mptcp_subflow_init(void)
{
	int err = -ENOMEM;

	/* TODO: Register path manager callbacks. */

	subflow_prot.twsk_prot		= tcp_prot.twsk_prot;
	subflow_prot.h.hashinfo		= tcp_prot.h.hashinfo;
	err = proto_register(&subflow_prot, 1);
	if (err)
		goto fail;

	inet_register_protosw(&subflow_protosw);

	return 0;

fail:
	return err;
}

void mptcp_subflow_exit(void)
{
	inet_unregister_protosw(&subflow_protosw);
	proto_unregister(&subflow_prot);
}

MODULE_LICENSE("GPL");
