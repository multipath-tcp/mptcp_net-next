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

static void subflow_finish_connect(struct sock *sk, const struct sk_buff *skb)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	inet_sk_rx_dst_set(sk, skb);

	pr_debug("subflow=%p", subflow_ctx(sk));

	if (subflow->conn && !subflow->conn_finished) {
		pr_debug("remote_key=%llu", subflow->remote_key);
		mptcp_finish_connect(subflow->conn, subflow->mp_capable);
		subflow->conn_finished = 1;
	}
}

static struct inet_connection_sock_af_ops subflow_specific;

static struct subflow_context *subflow_create_ctx(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct subflow_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	pr_debug("subflow=%p", ctx);

	icsk->icsk_ulp_data = ctx;
	ctx->sk = sk;

	return ctx;
}

static int subflow_ulp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct subflow_context *ctx;
	int err = 0;

	ctx = subflow_create_ctx(sk);
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

static struct tcp_ulp_ops subflow_ulp_ops __read_mostly = {
	.name		= "mptcp",
	.owner		= THIS_MODULE,
	.init		= subflow_ulp_init,
	.release	= subflow_ulp_release,
};

int subflow_init(void)
{
	subflow_specific = ipv4_specific;
	subflow_specific.sk_rx_dst_set = subflow_finish_connect;

	return tcp_register_ulp(&subflow_ulp_ops);
}

void subflow_exit(void)
{
	tcp_unregister_ulp(&subflow_ulp_ops);
}

MODULE_LICENSE("GPL");
