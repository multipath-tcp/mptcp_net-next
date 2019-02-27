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

static int subflow_rebuild_header(struct sock *sk)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	if (subflow->request_mptcp && !subflow->token) {
		pr_debug("subflow=%p", sk);
		token_new_connect(sk);
	}

	return inet_sk_rebuild_header(sk);
}

static void subflow_req_destructor(struct request_sock *req)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);

	pr_debug("subflow_req=%p", subflow_req);

	if (subflow_req->mp_capable)
		token_destroy_request(subflow_req->token);
	tcp_request_sock_ops.destructor(req);
}

static void subflow_v4_init_req(struct request_sock *req,
				const struct sock *sk_listener,
				struct sk_buff *skb)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct subflow_sock *listener = subflow_sk(sk_listener);
	struct tcp_options_received rx_opt;

	tcp_rsk(req)->is_mptcp = 1;
	pr_debug("subflow_req=%p, listener=%p", subflow_req, listener);

	tcp_request_sock_ipv4_ops.init_req(req, sk_listener, skb);

	rx_opt.mptcp.flags = 0;
	rx_opt.mptcp.mp_capable = 0;
	rx_opt.mptcp.mp_join = 0;
	rx_opt.mptcp.dss = 0;
	mptcp_get_options(skb, &rx_opt);

	if (rx_opt.mptcp.mp_capable && listener->request_mptcp) {
		subflow_req->mp_capable = 1;
		if (rx_opt.mptcp.version >= listener->version)
			subflow_req->version = listener->version;
		else
			subflow_req->version = rx_opt.mptcp.version;
		if ((rx_opt.mptcp.flags & MPTCP_CAP_CHECKSUM_REQD) ||
		    listener->checksum)
			subflow_req->checksum = 1;
		subflow_req->remote_key = rx_opt.mptcp.sndr_key;
		pr_debug("remote_key=%llu", subflow_req->remote_key);
		token_new_request(req, skb);
		pr_debug("syn seq=%u", TCP_SKB_CB(skb)->seq);
		subflow_req->ssn_offset = TCP_SKB_CB(skb)->seq;
	} else {
		subflow_req->mp_capable = 0;
	}
}

static void subflow_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	inet_sk_rx_dst_set(sk, skb);

	pr_debug("subflow=%p", subflow);

	if (subflow->conn && !subflow->conn_finished) {
		pr_debug("remote_key=%llu", subflow->remote_key);
		mptcp_finish_connect(subflow->conn, subflow->mp_capable);
		subflow->conn_finished = 1;

		if (skb) {
			pr_debug("synack seq=%u", TCP_SKB_CB(skb)->seq);
			subflow->ssn_offset = TCP_SKB_CB(skb)->seq;
		}
	}
}

static struct request_sock_ops subflow_request_sock_ops;
static struct tcp_request_sock_ops subflow_request_sock_ipv4_ops;

static int subflow_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	pr_debug("subflow=%p", subflow);

	/* Never answer to SYNs sent to broadcast or multicast */
	if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		goto drop;

	return tcp_conn_request(&subflow_request_sock_ops,
				&subflow_request_sock_ipv4_ops,
				sk, skb);
drop:
	tcp_listendrop(sk);
	return 0;
}

static struct sock *subflow_syn_recv_sock(const struct sock *sk,
					  struct sk_buff *skb,
					  struct request_sock *req,
					  struct dst_entry *dst,
					  struct request_sock *req_unhash,
					  bool *own_req)
{
	struct subflow_sock *listener = subflow_sk(sk);
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct sock *child;

	pr_debug("listener=%p, req=%p, conn=%p", sk, req, listener->conn);

	child = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);

	if (child) {
		struct subflow_sock *subflow = subflow_sk(child);

		pr_debug("child=%p", child);
		if (subflow_req->mp_capable) {
			subflow->mp_capable = 1;
			subflow->fourth_ack = 1;
			subflow->remote_key = subflow_req->remote_key;
			subflow->local_key = subflow_req->local_key;
			subflow->ssn_offset = subflow_req->ssn_offset;
			subflow->token = subflow_req->token;
			subflow->idsn = subflow_req->idsn;
			pr_debug("token=%u", subflow->token);
			token_new_accept(child);
		} else {
			subflow->mp_capable = 0;
		}
	}

	return child;
}

const struct inet_connection_sock_af_ops subflow_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = subflow_rebuild_header,
	.sk_rx_dst_set	   = subflow_finish_connect,
	.conn_request	   = subflow_conn_request,
	.syn_recv_sock	   = subflow_syn_recv_sock,
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

static void subflow_data_ready(struct sock *sk)
{
	struct subflow_sock *subflow = subflow_sk(sk);
	struct sock *parent = subflow->conn;

	pr_debug("sk=%p", sk);
	subflow->tcp_sk_data_ready(sk);

	if (parent) {
		pr_debug("parent=%p", parent);
		parent->sk_data_ready(parent);
	}
}

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
		subflow->tcp_sk_data_ready = sk->sk_data_ready;
		sk->sk_data_ready = subflow_data_ready;
	}

	return err;
}

static void subflow_close(struct sock *sk, long timeout)
{
	pr_debug("subflow=%p", sk);

	tcp_close(sk, timeout);
}

static struct sock *subflow_accept(struct sock *sk, int flags, int *err,
				   bool kern)
{
	struct subflow_sock *subflow = subflow_sk(sk);
	struct sock *child;

	pr_debug("subflow=%p, conn=%p", subflow, subflow->conn);

	child = inet_csk_accept(sk, flags, err, kern);

	pr_debug("child=%p", child);

	return child;
}

static void subflow_destroy(struct sock *sk)
{
	pr_debug("subflow=%p", sk);

	tcp_v4_destroy_sock(sk);
}

static int subflow_setsockopt(struct sock *sk, int level, int optname,
			      char __user *optval, unsigned int optlen)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	pr_debug("subflow=%p", subflow);

	return tcp_setsockopt(sk, level, optname, optval, optlen);
}

static int subflow_getsockopt(struct sock *sk, int level, int optname,
			      char __user *optval, int __user *option)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	pr_debug("subflow=%p", subflow);

	return tcp_getsockopt(sk, level, optname, optval, option);
}

static struct proto subflow_prot = {
	.name		= "SUBFLOW",
	.owner		= THIS_MODULE,
	.close		= subflow_close,
	.connect	= subflow_connect,
	.disconnect	= tcp_disconnect,
	.accept		= subflow_accept,
	.ioctl		= tcp_ioctl,
	.init		= subflow_init_sock,
	.destroy	= subflow_destroy,
	.shutdown	= tcp_shutdown,
	.setsockopt	= subflow_setsockopt,
	.getsockopt	= subflow_getsockopt,
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

	subflow_request_sock_ops = tcp_request_sock_ops;
	subflow_request_sock_ops.obj_size = sizeof(struct subflow_request_sock),
	subflow_request_sock_ops.destructor = subflow_req_destructor;

	subflow_request_sock_ipv4_ops = tcp_request_sock_ipv4_ops;
	subflow_request_sock_ipv4_ops.init_req = subflow_v4_init_req;

	subflow_prot.twsk_prot		= tcp_prot.twsk_prot;
	subflow_prot.rsk_prot		= &subflow_request_sock_ops;
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
