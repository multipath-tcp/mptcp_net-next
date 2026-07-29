// SPDX-License-Identifier: GPL-2.0
/* MPTCP socket monitoring support
 *
 * Copyright (c) 2020 Red Hat
 *
 * Author: Paolo Abeni <pabeni@redhat.com>
 */

/* Process a bounded number of listeners per bucket lock hold. */
#define MPTCP_DIAG_BULK_SZ 16

#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/inet_diag.h>
#include <net/netlink.h>
#include "protocol.h"

static void mptcp_diag_save_cursor(struct inet_diag_dump_data *cb_data,
				   unsigned int slot, struct sock *sk)
{
	sock_hold(sk);
	inet_diag_dump_clear_cursor(cb_data);
	cb_data->dump_cursor = sk;
	cb_data->dump_cursor_slot = slot;
	cb_data->dump_cursor_type = INET_DIAG_DUMP_CURSOR_MPTCP_LISTEN;
}

static int sk_diag_dump(struct sock *sk, struct sk_buff *skb,
			struct netlink_callback *cb,
			const struct inet_diag_req_v2 *req,
			bool net_admin)
{
	if (!inet_diag_bc_sk(cb->data, sk))
		return 0;

	return inet_sk_diag_fill(sk, inet_csk(sk), skb, cb, req, NLM_F_MULTI,
				 net_admin);
}

static int mptcp_diag_dump_one(struct netlink_callback *cb,
			       const struct inet_diag_req_v2 *req)
{
	struct sk_buff *in_skb = cb->skb;
	struct mptcp_sock *msk = NULL;
	struct sk_buff *rep;
	int err = -ENOENT;
	struct net *net;
	struct sock *sk;

	net = sock_net(in_skb->sk);
	msk = mptcp_token_get_sock(net, req->id.idiag_cookie[0]);
	if (!msk)
		goto out_nosk;

	err = -ENOMEM;
	sk = (struct sock *)msk;
	rep = nlmsg_new(nla_total_size(sizeof(struct inet_diag_msg)) +
			inet_diag_msg_attrs_size() +
			nla_total_size(sizeof(struct mptcp_info)) +
			nla_total_size(sizeof(struct inet_diag_meminfo)) + 64,
			GFP_KERNEL);
	if (!rep)
		goto out;

	err = inet_sk_diag_fill(sk, inet_csk(sk), rep, cb, req, 0,
				netlink_net_capable(in_skb, CAP_NET_ADMIN));
	if (err < 0) {
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(rep);
		goto out;
	}
	err = nlmsg_unicast(net->diag_nlsk, rep, NETLINK_CB(in_skb).portid);

out:
	sock_put(sk);

out_nosk:
	return err;
}

struct mptcp_diag_ctx {
	long s_slot;
	long s_num;
	unsigned int l_slot;
	unsigned int l_num;
};

static void mptcp_diag_dump_listeners(struct sk_buff *skb, struct netlink_callback *cb,
				      const struct inet_diag_req_v2 *r,
				      bool net_admin)
{
	struct mptcp_diag_ctx *diag_ctx = (void *)cb->ctx;
	struct inet_diag_dump_data *cb_data = cb->data;
	struct net *net = sock_net(skb->sk);
	struct inet_hashinfo *hinfo;
	int i;

	hinfo = net->ipv4.tcp_death_row.hashinfo;

	for (i = diag_ctx->l_slot; i <= hinfo->lhash2_mask; i++) {
		struct inet_listen_hashbucket *ilb;
		struct hlist_nulls_node *node;
		struct sock *tmp, *sk, *sk_arr[MPTCP_DIAG_BULK_SZ];
		struct sock *cursor;
		int accum, idx, num, ret;
		int num_arr[MPTCP_DIAG_BULK_SZ];
		bool use_cursor;

resume_listen_walk:
		num = 0;
		accum = 0;
		ilb = &hinfo->lhash2[i];
		ret = 0;

		rcu_read_lock();
		spin_lock(&ilb->lock);
		cursor = cb_data->dump_cursor;
		use_cursor = cursor &&
			     cb_data->dump_cursor_type ==
			     INET_DIAG_DUMP_CURSOR_MPTCP_LISTEN &&
			     cb_data->dump_cursor_slot == i &&
			     !hlist_nulls_unhashed(&cursor->sk_nulls_node) &&
			     cursor->sk_nulls_node.pprev != LIST_POISON2;
		node = use_cursor ? cursor->sk_nulls_node.next :
				    ilb->nulls_head.first;
		hlist_nulls_for_each_entry_from(sk, node, sk_nulls_node) {
			if (!use_cursor && num < diag_ctx->l_num)
				goto next_listen;

			if (!refcount_inc_not_zero(&sk->sk_refcnt))
				goto next_listen;

			num_arr[accum] = num;
			sk_arr[accum] = sk;
			if (++accum == MPTCP_DIAG_BULK_SZ)
				break;
next_listen:
			++num;
		}
		spin_unlock(&ilb->lock);
		rcu_read_unlock();

		for (idx = 0; idx < accum; idx++) {
			const struct tcp_ulp_ops *ulp_ops;
			const struct mptcp_subflow_context *ctx;
			struct inet_sock *inet;

			sk = sk_arr[idx];
			rcu_read_lock();
			ctx = mptcp_subflow_ctx(sk);
			ulp_ops = READ_ONCE(inet_csk(sk)->icsk_ulp_ops);
			inet = inet_sk(sk);
			tmp = ctx ? ctx->conn : NULL;
			if (!ctx || !ulp_ops || strcmp(ulp_ops->name, "mptcp") ||
			    !tmp || !net_eq(sock_net(tmp), net) ||
			    (r->sdiag_family != AF_UNSPEC &&
			     tmp->sk_family != r->sdiag_family) ||
			    (r->id.idiag_sport != inet->inet_sport &&
			     r->id.idiag_sport) ||
			    !refcount_inc_not_zero(&tmp->sk_refcnt)) {
				rcu_read_unlock();
				goto processed_listener_sk;
			}
			rcu_read_unlock();
			if (ret >= 0) {
				ret = sk_diag_dump(tmp, skb, cb, r, net_admin);
				if (ret < 0)
					num = num_arr[idx];
			}
			sock_put(tmp);
processed_listener_sk:
			if (ret >= 0)
				mptcp_diag_save_cursor(cb_data, i, sk);
			sock_put(sk);
		}

		if (ret < 0) {
			diag_ctx->l_slot = i;
			diag_ctx->l_num = num;
			return;
		}

		cond_resched();

		if (accum == MPTCP_DIAG_BULK_SZ) {
			diag_ctx->l_num = 0;
			goto resume_listen_walk;
		}

		inet_diag_dump_clear_cursor(cb_data);
		diag_ctx->l_num = 0;
	}

	inet_diag_dump_clear_cursor(cb_data);
	diag_ctx->l_num = 0;
	diag_ctx->l_slot = i;
}

static void mptcp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			    const struct inet_diag_req_v2 *r)
{
	bool net_admin = netlink_net_capable(cb->skb, CAP_NET_ADMIN);
	struct mptcp_diag_ctx *diag_ctx = (void *)cb->ctx;
	struct net *net = sock_net(skb->sk);
	struct mptcp_sock *msk;

	BUILD_BUG_ON(sizeof(cb->ctx) < sizeof(*diag_ctx));

	while ((msk = mptcp_token_iter_next(net, &diag_ctx->s_slot,
					    &diag_ctx->s_num)) != NULL) {
		struct inet_sock *inet = (struct inet_sock *)msk;
		struct sock *sk = (struct sock *)msk;
		int ret = 0;

		if (!(r->idiag_states & (1 << sk->sk_state)))
			goto next;
		if (r->sdiag_family != AF_UNSPEC &&
		    sk->sk_family != r->sdiag_family)
			goto next;
		if (r->id.idiag_sport != inet->inet_sport &&
		    r->id.idiag_sport)
			goto next;
		if (r->id.idiag_dport != inet->inet_dport &&
		    r->id.idiag_dport)
			goto next;

		ret = sk_diag_dump(sk, skb, cb, r, net_admin);
next:
		sock_put(sk);
		if (ret < 0) {
			/* will retry on the same position */
			diag_ctx->s_num--;
			break;
		}
		cond_resched();
	}

	if ((r->idiag_states & TCPF_LISTEN) && r->id.idiag_dport == 0)
		mptcp_diag_dump_listeners(skb, cb, r, net_admin);
}

static void mptcp_diag_get_info(struct sock *sk, struct inet_diag_msg *r,
				void *_info)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct mptcp_info *info = _info;

	r->idiag_rqueue = sk_rmem_alloc_get(sk) +
			  READ_ONCE(mptcp_sk(sk)->backlog_len);
	r->idiag_wqueue = sk_wmem_alloc_get(sk);

	if (inet_sk_state_load(sk) == TCP_LISTEN) {
		struct sock *lsk = READ_ONCE(msk->first);

		if (lsk) {
			/* override with settings from tcp listener,
			 * so Send-Q will show accept queue.
			 */
			r->idiag_rqueue = READ_ONCE(lsk->sk_ack_backlog);
			r->idiag_wqueue = READ_ONCE(lsk->sk_max_ack_backlog);
		}
	}

	if (!info)
		return;

	mptcp_diag_fill_info(msk, info);
}

static const struct inet_diag_handler mptcp_diag_handler = {
	.owner		 = THIS_MODULE,
	.dump		 = mptcp_diag_dump,
	.dump_one	 = mptcp_diag_dump_one,
	.idiag_get_info  = mptcp_diag_get_info,
	.idiag_type	 = IPPROTO_MPTCP,
	.idiag_info_size = sizeof(struct mptcp_info),
};

static int __init mptcp_diag_init(void)
{
	return inet_diag_register(&mptcp_diag_handler);
}

static void __exit mptcp_diag_exit(void)
{
	inet_diag_unregister(&mptcp_diag_handler);
}

module_init(mptcp_diag_init);
module_exit(mptcp_diag_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP socket monitoring via SOCK_DIAG");
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 2-262 /* AF_INET - IPPROTO_MPTCP */);
