/*
 * Copyright (c) 2008-2009 Patrick McHardy <kaber@trash.net>
 * Copyright (c) 2014 Intel Corporation
 * Author: Tomasz Bursztyka <tomasz.bursztyka@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/smp.h>
#include <linux/static_key.h>
#include <net/dst.h>
#include <net/sock.h>
#include <net/tcp_states.h> /* for TCP_TIME_WAIT */
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>

#include <uapi/linux/netfilter_bridge.h> /* NF_BR_PRE_ROUTING */

struct nft_meta {
	enum nft_meta_keys	key:8;
	union {
		enum nft_registers	dreg:8;
		enum nft_registers	sreg:8;
	};
};

static DEFINE_PER_CPU(struct rnd_state, nft_prandom_state);

#ifdef CONFIG_NF_TABLES_BRIDGE
#include "../bridge/br_private.h"
#endif

void nft_meta_get_eval(const struct nft_expr *expr,
		       struct nft_regs *regs,
		       const struct nft_pktinfo *pkt)
{
	const struct nft_meta *priv = nft_expr_priv(expr);
	const struct sk_buff *skb = pkt->skb;
	const struct net_device *in = nft_in(pkt), *out = nft_out(pkt);
	struct sock *sk;
	u32 *dest = &regs->data[priv->dreg];
#ifdef CONFIG_NF_TABLES_BRIDGE
	const struct net_bridge_port *p;
#endif

	switch (priv->key) {
	case NFT_META_LEN:
		*dest = skb->len;
		break;
	case NFT_META_PROTOCOL:
		nft_reg_store16(dest, (__force u16)skb->protocol);
		break;
	case NFT_META_NFPROTO:
		nft_reg_store8(dest, nft_pf(pkt));
		break;
	case NFT_META_L4PROTO:
		if (!pkt->tprot_set)
			goto err;
		nft_reg_store8(dest, pkt->tprot);
		break;
	case NFT_META_PRIORITY:
		*dest = skb->priority;
		break;
	case NFT_META_MARK:
		*dest = skb->mark;
		break;
	case NFT_META_IIF:
		if (in == NULL)
			goto err;
		*dest = in->ifindex;
		break;
	case NFT_META_OIF:
		if (out == NULL)
			goto err;
		*dest = out->ifindex;
		break;
	case NFT_META_IIFNAME:
		if (in == NULL)
			goto err;
		strncpy((char *)dest, in->name, IFNAMSIZ);
		break;
	case NFT_META_OIFNAME:
		if (out == NULL)
			goto err;
		strncpy((char *)dest, out->name, IFNAMSIZ);
		break;
	case NFT_META_IIFTYPE:
		if (in == NULL)
			goto err;
		nft_reg_store16(dest, in->type);
		break;
	case NFT_META_OIFTYPE:
		if (out == NULL)
			goto err;
		nft_reg_store16(dest, out->type);
		break;
	case NFT_META_SKUID:
		sk = skb_to_full_sk(skb);
		if (!sk || !sk_fullsock(sk) ||
		    !net_eq(nft_net(pkt), sock_net(sk)))
			goto err;

		read_lock_bh(&sk->sk_callback_lock);
		if (sk->sk_socket == NULL ||
		    sk->sk_socket->file == NULL) {
			read_unlock_bh(&sk->sk_callback_lock);
			goto err;
		}

		*dest =	from_kuid_munged(&init_user_ns,
				sk->sk_socket->file->f_cred->fsuid);
		read_unlock_bh(&sk->sk_callback_lock);
		break;
	case NFT_META_SKGID:
		sk = skb_to_full_sk(skb);
		if (!sk || !sk_fullsock(sk) ||
		    !net_eq(nft_net(pkt), sock_net(sk)))
			goto err;

		read_lock_bh(&sk->sk_callback_lock);
		if (sk->sk_socket == NULL ||
		    sk->sk_socket->file == NULL) {
			read_unlock_bh(&sk->sk_callback_lock);
			goto err;
		}
		*dest =	from_kgid_munged(&init_user_ns,
				 sk->sk_socket->file->f_cred->fsgid);
		read_unlock_bh(&sk->sk_callback_lock);
		break;
#ifdef CONFIG_IP_ROUTE_CLASSID
	case NFT_META_RTCLASSID: {
		const struct dst_entry *dst = skb_dst(skb);

		if (dst == NULL)
			goto err;
		*dest = dst->tclassid;
		break;
	}
#endif
#ifdef CONFIG_NETWORK_SECMARK
	case NFT_META_SECMARK:
		*dest = skb->secmark;
		break;
#endif
	case NFT_META_PKTTYPE:
		if (skb->pkt_type != PACKET_LOOPBACK) {
			nft_reg_store8(dest, skb->pkt_type);
			break;
		}

		switch (nft_pf(pkt)) {
		case NFPROTO_IPV4:
			if (ipv4_is_multicast(ip_hdr(skb)->daddr))
				nft_reg_store8(dest, PACKET_MULTICAST);
			else
				nft_reg_store8(dest, PACKET_BROADCAST);
			break;
		case NFPROTO_IPV6:
			nft_reg_store8(dest, PACKET_MULTICAST);
			break;
		case NFPROTO_NETDEV:
			switch (skb->protocol) {
			case htons(ETH_P_IP): {
				int noff = skb_network_offset(skb);
				struct iphdr *iph, _iph;

				iph = skb_header_pointer(skb, noff,
							 sizeof(_iph), &_iph);
				if (!iph)
					goto err;

				if (ipv4_is_multicast(iph->daddr))
					nft_reg_store8(dest, PACKET_MULTICAST);
				else
					nft_reg_store8(dest, PACKET_BROADCAST);

				break;
			}
			case htons(ETH_P_IPV6):
				nft_reg_store8(dest, PACKET_MULTICAST);
				break;
			default:
				WARN_ON_ONCE(1);
				goto err;
			}
			break;
		default:
			WARN_ON_ONCE(1);
			goto err;
		}
		break;
	case NFT_META_CPU:
		*dest = raw_smp_processor_id();
		break;
	case NFT_META_IIFGROUP:
		if (in == NULL)
			goto err;
		*dest = in->group;
		break;
	case NFT_META_OIFGROUP:
		if (out == NULL)
			goto err;
		*dest = out->group;
		break;
#ifdef CONFIG_CGROUP_NET_CLASSID
	case NFT_META_CGROUP:
		sk = skb_to_full_sk(skb);
		if (!sk || !sk_fullsock(sk) ||
		    !net_eq(nft_net(pkt), sock_net(sk)))
			goto err;
		*dest = sock_cgroup_classid(&sk->sk_cgrp_data);
		break;
#endif
	case NFT_META_PRANDOM: {
		struct rnd_state *state = this_cpu_ptr(&nft_prandom_state);
		*dest = prandom_u32_state(state);
		break;
	}
#ifdef CONFIG_XFRM
	case NFT_META_SECPATH:
		nft_reg_store8(dest, secpath_exists(skb));
		break;
#endif
#ifdef CONFIG_NF_TABLES_BRIDGE
	case NFT_META_BRI_IIFNAME:
		if (in == NULL || (p = br_port_get_rcu(in)) == NULL)
			goto err;
		strncpy((char *)dest, p->br->dev->name, IFNAMSIZ);
		return;
	case NFT_META_BRI_OIFNAME:
		if (out == NULL || (p = br_port_get_rcu(out)) == NULL)
			goto err;
		strncpy((char *)dest, p->br->dev->name, IFNAMSIZ);
		return;
#endif
	default:
		WARN_ON(1);
		goto err;
	}
	return;

err:
	regs->verdict.code = NFT_BREAK;
}

static void nft_meta_set_eval(const struct nft_expr *expr,
			      struct nft_regs *regs,
			       const struct nft_pktinfo *pkt)
{
	const struct nft_meta *meta = nft_expr_priv(expr);
	struct sk_buff *skb = pkt->skb;
	u32 *sreg = &regs->data[meta->sreg];
	u32 value = *sreg;
	u8 value8;

	switch (meta->key) {
	case NFT_META_MARK:
		skb->mark = value;
		break;
	case NFT_META_PRIORITY:
		skb->priority = value;
		break;
	case NFT_META_PKTTYPE:
		value8 = nft_reg_load8(sreg);

		if (skb->pkt_type != value8 &&
		    skb_pkt_type_ok(value8) &&
		    skb_pkt_type_ok(skb->pkt_type))
			skb->pkt_type = value8;
		break;
	case NFT_META_NFTRACE:
		value8 = nft_reg_load8(sreg);

		skb->nf_trace = !!value8;
		break;
#ifdef CONFIG_NETWORK_SECMARK
	case NFT_META_SECMARK:
		skb->secmark = value;
		break;
#endif
	default:
		WARN_ON(1);
	}
}

static const struct nla_policy nft_meta_policy[NFTA_META_MAX + 1] = {
	[NFTA_META_DREG]	= { .type = NLA_U32 },
	[NFTA_META_KEY]		= { .type = NLA_U32 },
	[NFTA_META_SREG]	= { .type = NLA_U32 },
};

static int nft_meta_get_init(const struct nft_ctx *ctx,
			     const struct nft_expr *expr,
			     const struct nlattr * const tb[])
{
	struct nft_meta *priv = nft_expr_priv(expr);
	unsigned int len;

	priv->key = ntohl(nla_get_be32(tb[NFTA_META_KEY]));
	switch (priv->key) {
	case NFT_META_PROTOCOL:
	case NFT_META_IIFTYPE:
	case NFT_META_OIFTYPE:
		len = sizeof(u16);
		break;
	case NFT_META_NFPROTO:
	case NFT_META_L4PROTO:
	case NFT_META_LEN:
	case NFT_META_PRIORITY:
	case NFT_META_MARK:
	case NFT_META_IIF:
	case NFT_META_OIF:
	case NFT_META_SKUID:
	case NFT_META_SKGID:
#ifdef CONFIG_IP_ROUTE_CLASSID
	case NFT_META_RTCLASSID:
#endif
#ifdef CONFIG_NETWORK_SECMARK
	case NFT_META_SECMARK:
#endif
	case NFT_META_PKTTYPE:
	case NFT_META_CPU:
	case NFT_META_IIFGROUP:
	case NFT_META_OIFGROUP:
#ifdef CONFIG_CGROUP_NET_CLASSID
	case NFT_META_CGROUP:
#endif
		len = sizeof(u32);
		break;
	case NFT_META_IIFNAME:
	case NFT_META_OIFNAME:
		len = IFNAMSIZ;
		break;
	case NFT_META_PRANDOM:
		prandom_init_once(&nft_prandom_state);
		len = sizeof(u32);
		break;
#ifdef CONFIG_XFRM
	case NFT_META_SECPATH:
		len = sizeof(u8);
		break;
#endif
#ifdef CONFIG_NF_TABLES_BRIDGE
	case NFT_META_BRI_IIFNAME:
	case NFT_META_BRI_OIFNAME:
		if (ctx->family != NFPROTO_BRIDGE)
			return -EOPNOTSUPP;
		len = IFNAMSIZ;
		break;
#endif
	default:
		return -EOPNOTSUPP;
	}

	priv->dreg = nft_parse_register(tb[NFTA_META_DREG]);
	return nft_validate_register_store(ctx, priv->dreg, NULL,
					   NFT_DATA_VALUE, len);
}

static int nft_meta_get_validate(const struct nft_ctx *ctx,
				 const struct nft_expr *expr,
				 const struct nft_data **data)
{
#ifdef CONFIG_XFRM
	const struct nft_meta *priv = nft_expr_priv(expr);
	unsigned int hooks;

	if (priv->key != NFT_META_SECPATH)
		return 0;

	switch (ctx->family) {
	case NFPROTO_NETDEV:
		hooks = 1 << NF_NETDEV_INGRESS;
		break;
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
	case NFPROTO_INET:
		hooks = (1 << NF_INET_PRE_ROUTING) |
			(1 << NF_INET_LOCAL_IN) |
			(1 << NF_INET_FORWARD);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return nft_chain_validate_hooks(ctx->chain, hooks);
#else
	return 0;
#endif
}

static int nft_meta_set_validate(const struct nft_ctx *ctx,
				 const struct nft_expr *expr,
				 const struct nft_data **data)
{
	struct nft_meta *priv = nft_expr_priv(expr);
	unsigned int hooks;

	if (priv->key != NFT_META_PKTTYPE)
		return 0;

	switch (ctx->family) {
	case NFPROTO_BRIDGE:
		hooks = 1 << NF_BR_PRE_ROUTING;
		break;
	case NFPROTO_NETDEV:
		hooks = 1 << NF_NETDEV_INGRESS;
		break;
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
	case NFPROTO_INET:
		hooks = 1 << NF_INET_PRE_ROUTING;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return nft_chain_validate_hooks(ctx->chain, hooks);
}

static int nft_meta_set_init(const struct nft_ctx *ctx,
			     const struct nft_expr *expr,
			     const struct nlattr * const tb[])
{
	struct nft_meta *priv = nft_expr_priv(expr);
	unsigned int len;
	int err;

	priv->key = ntohl(nla_get_be32(tb[NFTA_META_KEY]));
	switch (priv->key) {
	case NFT_META_MARK:
	case NFT_META_PRIORITY:
#ifdef CONFIG_NETWORK_SECMARK
	case NFT_META_SECMARK:
#endif
		len = sizeof(u32);
		break;
	case NFT_META_NFTRACE:
		len = sizeof(u8);
		break;
	case NFT_META_PKTTYPE:
		len = sizeof(u8);
		break;
	default:
		return -EOPNOTSUPP;
	}

	priv->sreg = nft_parse_register(tb[NFTA_META_SREG]);
	err = nft_validate_register_load(priv->sreg, len);
	if (err < 0)
		return err;

	if (priv->key == NFT_META_NFTRACE)
		static_branch_inc(&nft_trace_enabled);

	return 0;
}

static int nft_meta_get_dump(struct sk_buff *skb,
			     const struct nft_expr *expr)
{
	const struct nft_meta *priv = nft_expr_priv(expr);

	if (nla_put_be32(skb, NFTA_META_KEY, htonl(priv->key)))
		goto nla_put_failure;
	if (nft_dump_register(skb, NFTA_META_DREG, priv->dreg))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}

static int nft_meta_set_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	const struct nft_meta *priv = nft_expr_priv(expr);

	if (nla_put_be32(skb, NFTA_META_KEY, htonl(priv->key)))
		goto nla_put_failure;
	if (nft_dump_register(skb, NFTA_META_SREG, priv->sreg))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static void nft_meta_set_destroy(const struct nft_ctx *ctx,
				 const struct nft_expr *expr)
{
	const struct nft_meta *priv = nft_expr_priv(expr);

	if (priv->key == NFT_META_NFTRACE)
		static_branch_dec(&nft_trace_enabled);
}

static const struct nft_expr_ops nft_meta_get_ops = {
	.type		= &nft_meta_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_meta)),
	.eval		= nft_meta_get_eval,
	.init		= nft_meta_get_init,
	.dump		= nft_meta_get_dump,
	.validate	= nft_meta_get_validate,
};

static const struct nft_expr_ops nft_meta_set_ops = {
	.type		= &nft_meta_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_meta)),
	.eval		= nft_meta_set_eval,
	.init		= nft_meta_set_init,
	.destroy	= nft_meta_set_destroy,
	.dump		= nft_meta_set_dump,
	.validate	= nft_meta_set_validate,
};

static const struct nft_expr_ops *
nft_meta_select_ops(const struct nft_ctx *ctx,
		    const struct nlattr * const tb[])
{
	if (tb[NFTA_META_KEY] == NULL)
		return ERR_PTR(-EINVAL);

	if (tb[NFTA_META_DREG] && tb[NFTA_META_SREG])
		return ERR_PTR(-EINVAL);

	if (tb[NFTA_META_DREG])
		return &nft_meta_get_ops;

	if (tb[NFTA_META_SREG])
		return &nft_meta_set_ops;

	return ERR_PTR(-EINVAL);
}

struct nft_expr_type nft_meta_type __read_mostly = {
	.name		= "meta",
	.select_ops	= nft_meta_select_ops,
	.policy		= nft_meta_policy,
	.maxattr	= NFTA_META_MAX,
	.owner		= THIS_MODULE,
};

#ifdef CONFIG_NETWORK_SECMARK
struct nft_secmark {
	u32 secid;
	char *ctx;
};

static const struct nla_policy nft_secmark_policy[NFTA_SECMARK_MAX + 1] = {
	[NFTA_SECMARK_CTX]     = { .type = NLA_STRING, .len = NFT_SECMARK_CTX_MAXLEN },
};

static int nft_secmark_compute_secid(struct nft_secmark *priv)
{
	u32 tmp_secid = 0;
	int err;

	err = security_secctx_to_secid(priv->ctx, strlen(priv->ctx), &tmp_secid);
	if (err)
		return err;

	if (!tmp_secid)
		return -ENOENT;

	err = security_secmark_relabel_packet(tmp_secid);
	if (err)
		return err;

	priv->secid = tmp_secid;
	return 0;
}

static void nft_secmark_obj_eval(struct nft_object *obj, struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	const struct nft_secmark *priv = nft_obj_data(obj);
	struct sk_buff *skb = pkt->skb;

	skb->secmark = priv->secid;
}

static int nft_secmark_obj_init(const struct nft_ctx *ctx,
				const struct nlattr * const tb[],
				struct nft_object *obj)
{
	struct nft_secmark *priv = nft_obj_data(obj);
	int err;

	if (tb[NFTA_SECMARK_CTX] == NULL)
		return -EINVAL;

	priv->ctx = nla_strdup(tb[NFTA_SECMARK_CTX], GFP_KERNEL);
	if (!priv->ctx)
		return -ENOMEM;

	err = nft_secmark_compute_secid(priv);
	if (err) {
		kfree(priv->ctx);
		return err;
	}

	security_secmark_refcount_inc();

	return 0;
}

static int nft_secmark_obj_dump(struct sk_buff *skb, struct nft_object *obj,
				bool reset)
{
	struct nft_secmark *priv = nft_obj_data(obj);
	int err;

	if (nla_put_string(skb, NFTA_SECMARK_CTX, priv->ctx))
		return -1;

	if (reset) {
		err = nft_secmark_compute_secid(priv);
		if (err)
			return err;
	}

	return 0;
}

static void nft_secmark_obj_destroy(const struct nft_ctx *ctx, struct nft_object *obj)
{
	struct nft_secmark *priv = nft_obj_data(obj);

	security_secmark_refcount_dec();

	kfree(priv->ctx);
}

static const struct nft_object_ops nft_secmark_obj_ops = {
	.type		= &nft_secmark_obj_type,
	.size		= sizeof(struct nft_secmark),
	.init		= nft_secmark_obj_init,
	.eval		= nft_secmark_obj_eval,
	.dump		= nft_secmark_obj_dump,
	.destroy	= nft_secmark_obj_destroy,
};
struct nft_object_type nft_secmark_obj_type __read_mostly = {
	.type		= NFT_OBJECT_SECMARK,
	.ops		= &nft_secmark_obj_ops,
	.maxattr	= NFTA_SECMARK_MAX,
	.policy		= nft_secmark_policy,
	.owner		= THIS_MODULE,
};
#endif /* CONFIG_NETWORK_SECMARK */
