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

static void subflow_v4_init_req(struct request_sock *req,
				const struct sock *sk_listener,
				struct sk_buff *skb)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct subflow_context *listener = subflow_ctx(sk_listener);
	struct tcp_options_received rx_opt;

	tcp_rsk(req)->is_mptcp = 1;
	pr_debug("subflow_req=%p, listener=%p", subflow_req, listener);

	tcp_request_sock_ipv4_ops.init_req(req, sk_listener, skb);

	memset(&rx_opt.mptcp, 0, sizeof(rx_opt.mptcp));
	mptcp_get_options(skb, &rx_opt);

	if (rx_opt.mptcp.mp_capable && listener->request_mptcp) {
		subflow_req->mp_capable = 1;
		if (rx_opt.mptcp.version >= listener->version)
			subflow_req->version = listener->version;
		else
			subflow_req->version = rx_opt.mptcp.version;
		if ((rx_opt.mptcp.flags & MPTCP_CAP_CHECKSUM_REQD) ||
		    listener->request_cksum)
			subflow_req->checksum = 1;
		subflow_req->remote_key = rx_opt.mptcp.sndr_key;
	} else {
		subflow_req->mp_capable = 0;
	}
}

static void subflow_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	inet_sk_rx_dst_set(sk, skb);

	if (subflow->conn && !subflow->conn_finished) {
		pr_debug("subflow=%p, remote_key=%llu", subflow_ctx(sk),
			 subflow->remote_key);
		mptcp_finish_connect(subflow->conn, subflow->mp_capable);
		subflow->conn_finished = 1;
	}
}

static struct request_sock_ops subflow_request_sock_ops;
static struct tcp_request_sock_ops subflow_request_sock_ipv4_ops;

static int subflow_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct subflow_context *subflow = subflow_ctx(sk);

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
	struct subflow_context *listener = subflow_ctx(sk);
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct tcp_options_received opt_rx;
	struct sock *child;

	pr_debug("listener=%p, req=%p, conn=%p", listener, req, listener->conn);

	if (subflow_req->mp_capable) {
		opt_rx.mptcp.mp_capable = 0;
		mptcp_get_options(skb, &opt_rx);
		if ((!opt_rx.mptcp.mp_capable) ||
		    (subflow_req->local_key != opt_rx.mptcp.rcvr_key) ||
		    (subflow_req->remote_key != opt_rx.mptcp.sndr_key))
			return NULL;
	}

	child = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);

	if (child && *own_req) {
		if (!subflow_ctx(child)) {
			pr_debug("Closing child socket");
			inet_sk_set_state(child, TCP_CLOSE);
			sock_set_flag(child, SOCK_DEAD);
			inet_csk_destroy_sock(child);
			child = NULL;
		}
	}

	return child;
}

static struct inet_connection_sock_af_ops subflow_specific;

static struct subflow_context *subflow_create_ctx(struct sock *sk,
						  struct socket *sock,
						  gfp_t priority)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct subflow_context *ctx;

	ctx = kzalloc(sizeof(*ctx), priority);
	icsk->icsk_ulp_data = ctx;

	if (!ctx)
		return NULL;

	pr_debug("subflow=%p", ctx);

	/* might be NULL */
	ctx->tcp_sock = sock;

	return ctx;
}

static int subflow_ulp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct subflow_context *ctx;
	int err = 0;

	ctx = subflow_create_ctx(sk, sk->sk_socket, GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}

	pr_debug("subflow=%p", ctx);

	tp->is_mptcp = 1;
	icsk->icsk_af_ops = &subflow_specific;
out:
	return err;
}

static void subflow_ulp_release(struct sock *sk)
{
	struct subflow_context *ctx = subflow_ctx(sk);

	pr_debug("subflow=%p", ctx);

	kfree(ctx);
}

static void subflow_ulp_clone(const struct request_sock *req,
			      struct sock *newsk,
			      const gfp_t priority)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);

	/* newsk->sk_socket is NULL at this point */
	struct subflow_context *subflow = subflow_create_ctx(newsk, NULL,
							     priority);

	if (!subflow)
		return;

	subflow->conn = NULL;
	subflow->conn_finished = 1;

	if (subflow_req->mp_capable) {
		subflow->mp_capable = 1;
		subflow->fourth_ack = 1;
		subflow->remote_key = subflow_req->remote_key;
		subflow->local_key = subflow_req->local_key;
	}
}

static struct tcp_ulp_ops subflow_ulp_ops __read_mostly = {
	.name		= "mptcp",
	.owner		= THIS_MODULE,
	.init		= subflow_ulp_init,
	.release	= subflow_ulp_release,
	.clone		= subflow_ulp_clone,
};

static int subflow_ops_init(struct request_sock_ops *subflow_ops)
{
	subflow_ops->obj_size = sizeof(struct subflow_request_sock);
	subflow_ops->slab_name = "request_sock_subflow";

	subflow_ops->slab = kmem_cache_create(subflow_ops->slab_name,
					      subflow_ops->obj_size, 0,
					      SLAB_ACCOUNT |
					      SLAB_TYPESAFE_BY_RCU,
					      NULL);
	if (!subflow_ops->slab)
		return -ENOMEM;

	return 0;
}

void subflow_init(void)
{
	subflow_request_sock_ops = tcp_request_sock_ops;
	if (subflow_ops_init(&subflow_request_sock_ops) != 0)
		panic("MPTCP: failed to init subflow request sock ops\n");

	subflow_request_sock_ipv4_ops = tcp_request_sock_ipv4_ops;
	subflow_request_sock_ipv4_ops.init_req = subflow_v4_init_req;

	subflow_specific = ipv4_specific;
	subflow_specific.conn_request = subflow_conn_request;
	subflow_specific.syn_recv_sock = subflow_syn_recv_sock;
	subflow_specific.sk_rx_dst_set = subflow_finish_connect;

	if (tcp_register_ulp(&subflow_ulp_ops) != 0)
		panic("MPTCP: failed to register subflows to ULP\n");
}
