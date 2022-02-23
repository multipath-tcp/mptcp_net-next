// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Tessares SA.
 */

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "protocol.h"
#include "mib.h"

#define MPTCP_SYSCTL_PATH "net/mptcp"

static int mptcp_pernet_id;

#ifdef CONFIG_SYSCTL
static int mptcp_pm_type_max = __MPTCP_PM_TYPE_MAX;
#endif

struct mptcp_join_sk {
	struct sock *sk;
	struct inet_bind_bucket *tb;
	struct inet_bind_hashbucket head;
};

struct mptcp_pernet {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *ctl_table_hdr;
#endif

	unsigned int add_addr_timeout;
	unsigned int stale_loss_cnt;
	u8 mptcp_enabled;
	u8 checksum_enabled;
	u8 allow_join_initial_addr_port;
	u8 pm_type;

	/* pernet listener to handle mptcp join requests
	 * based on the mptcp token.
	 *
	 * Has to be pernet because tcp uses
	 * sock_net(sk_listener) to obtain the net namespace for
	 * the syn/ack route lookup.
	 */
	struct mptcp_join_sk join4;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	struct mptcp_join_sk join6;
#endif
};

static struct mptcp_pernet *mptcp_get_pernet(const struct net *net)
{
	return net_generic(net, mptcp_pernet_id);
}

int mptcp_is_enabled(const struct net *net)
{
	return mptcp_get_pernet(net)->mptcp_enabled;
}

unsigned int mptcp_get_add_addr_timeout(const struct net *net)
{
	return mptcp_get_pernet(net)->add_addr_timeout;
}

int mptcp_is_checksum_enabled(const struct net *net)
{
	return mptcp_get_pernet(net)->checksum_enabled;
}

int mptcp_allow_join_id0(const struct net *net)
{
	return mptcp_get_pernet(net)->allow_join_initial_addr_port;
}

unsigned int mptcp_stale_loss_cnt(const struct net *net)
{
	return mptcp_get_pernet(net)->stale_loss_cnt;
}

int mptcp_get_pm_type(const struct net *net)
{
	return mptcp_get_pernet(net)->pm_type;
}

static void mptcp_pernet_set_defaults(struct mptcp_pernet *pernet)
{
	pernet->mptcp_enabled = 1;
	pernet->add_addr_timeout = TCP_RTO_MAX;
	pernet->checksum_enabled = 0;
	pernet->allow_join_initial_addr_port = 1;
	pernet->stale_loss_cnt = 4;
	pernet->pm_type = MPTCP_PM_TYPE_KERNEL;
}

#ifdef CONFIG_SYSCTL
static struct ctl_table mptcp_sysctl_table[] = {
	{
		.procname = "enabled",
		.maxlen = sizeof(u8),
		.mode = 0644,
		/* users with CAP_NET_ADMIN or root (not and) can change this
		 * value, same as other sysctl or the 'net' tree.
		 */
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = SYSCTL_ONE
	},
	{
		.procname = "add_addr_timeout",
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_dointvec_jiffies,
	},
	{
		.procname = "checksum_enabled",
		.maxlen = sizeof(u8),
		.mode = 0644,
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = SYSCTL_ONE
	},
	{
		.procname = "allow_join_initial_addr_port",
		.maxlen = sizeof(u8),
		.mode = 0644,
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = SYSCTL_ONE
	},
	{
		.procname = "stale_loss_cnt",
		.maxlen = sizeof(unsigned int),
		.mode = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname = "pm_type",
		.maxlen = sizeof(u8),
		.mode = 0644,
		.proc_handler = proc_dou8vec_minmax,
		.extra1       = SYSCTL_ZERO,
		.extra2       = &mptcp_pm_type_max
	},
	{}
};

static int mptcp_pernet_new_table(struct net *net, struct mptcp_pernet *pernet)
{
	struct ctl_table_header *hdr;
	struct ctl_table *table;

	table = mptcp_sysctl_table;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(mptcp_sysctl_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;
	}

	table[0].data = &pernet->mptcp_enabled;
	table[1].data = &pernet->add_addr_timeout;
	table[2].data = &pernet->checksum_enabled;
	table[3].data = &pernet->allow_join_initial_addr_port;
	table[4].data = &pernet->stale_loss_cnt;
	table[5].data = &pernet->pm_type;

	hdr = register_net_sysctl(net, MPTCP_SYSCTL_PATH, table);
	if (!hdr)
		goto err_reg;

	pernet->ctl_table_hdr = hdr;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static void mptcp_pernet_del_table(struct mptcp_pernet *pernet)
{
	struct ctl_table *table = pernet->ctl_table_hdr->ctl_table_arg;

	unregister_net_sysctl_table(pernet->ctl_table_hdr);

	kfree(table);
}

#else

static int mptcp_pernet_new_table(struct net *net, struct mptcp_pernet *pernet)
{
	return 0;
}

static void mptcp_pernet_del_table(struct mptcp_pernet *pernet) {}

#endif /* CONFIG_SYSCTL */

static void add_mptcp_rst(struct sk_buff *skb)
{
	struct mptcp_ext *ext = skb_ext_add(skb, SKB_EXT_MPTCP);

	if (ext) {
		memset(ext, 0, sizeof(*ext));
		ext->reset_reason = MPTCP_RST_EMPTCP;
	}
}

struct sock *__mptcp_handle_join(int af, struct sk_buff *skb)
{
	struct mptcp_options_received mp_opt;
	struct mptcp_pernet *pernet;
	struct mptcp_sock *msk;
	struct socket *ssock;
	struct sock *lsk;
	struct net *net;

	/* paranoia check: don't allow 0 destination port,
	 * else __inet_inherit_port will insert the child socket
	 * into the phony hash slot of the pernet listener.
	 */
	if (tcp_hdr(skb)->dest == 0)
		return NULL;

	mptcp_get_options(skb, &mp_opt);

	if (!(mp_opt.suboptions & OPTIONS_MPTCP_MPJ))
		return NULL;

	net = dev_net(skb_dst(skb)->dev);
	if (!mptcp_is_enabled(net))
		return NULL;

	/* RFC8684: If the token is unknown [..], the receiver will send
	 * back a reset (RST) signal, analogous to an unknown port in TCP,
	 * containing an MP_TCPRST option (Section 3.6) [..]
	 */
	msk = mptcp_token_get_sock(net, mp_opt.token);
	if (!msk) {
		add_mptcp_rst(skb);
		return NULL;
	}

	if (!mptcp_pm_sport_in_anno_list(msk, af, skb)) {
		sock_put((struct sock *)msk);
		MPTCP_INC_STATS(net, MPTCP_MIB_MISMATCHPORTSYNRX);
		add_mptcp_rst(skb);
		return NULL;
	}

	sock_put((struct sock *)msk);
	pernet = mptcp_get_pernet(net);

	switch (af) {
	case AF_INET:
		lsk = pernet->join4.sk;
		break;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	case AF_INET6:
		lsk = pernet->join6.sk;
		break;
#endif
	default:
		WARN_ON_ONCE(1);
		return NULL;
	}

	ssock = __mptcp_nmpc_socket(mptcp_sk(lsk));
	if (WARN_ON(!ssock))
		return NULL;

	return ssock->sk;
}

static struct socket *mptcp_create_join_listen_socket(struct net *net, int af)
{
	struct socket *s, *ssock;
	int err;

	err = sock_create_kern(net, af, SOCK_STREAM, IPPROTO_MPTCP, &s);
	if (err)
		return ERR_PTR(err);

	ssock = __mptcp_nmpc_socket(mptcp_sk(s->sk));
	if (!ssock) {
		err = -EINVAL;
		goto out;
	}

	ssock->sk->sk_max_ack_backlog = SOMAXCONN;
	inet_sk_state_store(ssock->sk, TCP_LISTEN);

	s->sk->sk_max_ack_backlog = SOMAXCONN;
	inet_sk_state_store(s->sk, TCP_LISTEN);

	s->sk->sk_net_refcnt = 1;
	get_net_track(net, &s->sk->ns_tracker, GFP_KERNEL);
	sock_inuse_add(net, 1);

	return s;
out:
	sock_release(s);
	return ERR_PTR(err);
}

static int mptcp_init_join_sk(struct net *net, struct sock *sk, struct mptcp_join_sk *join_sk)
{
	struct socket *ssock = __mptcp_nmpc_socket(mptcp_sk(sk));
	struct inet_hashinfo *table = ssock->sk->sk_prot->h.hashinfo;
	struct inet_bind_bucket *tb;

	spin_lock_init(&join_sk->head.lock);
	INIT_HLIST_HEAD(&join_sk->head.chain);

	/* Our "listen socket" isn't bound to any address or port.
	 * Conceptually, SYN packet with mptcp join request are steered to
	 * this pernet socket just like TPROXY steals arbitrary connection
	 * requests to assign them to listening socket with different
	 * address or port.
	 *
	 * The bind_bucket is needed for sake of __inet_inherit_port(),
	 * so it can place the new child socket in the correct
	 * bind_bucket slot.
	 *
	 * A phony head is used to hide this socket from normal sk loookup.
	 */
	tb = inet_bind_bucket_create(table->bind_bucket_cachep,
				     net, &join_sk->head, 0, 0);
	if (!tb)
		return -ENOMEM;

	inet_csk(ssock->sk)->icsk_bind_hash = tb;
	return 0;
}

static int __net_init mptcp_net_init(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);
	struct socket *sock;
	int err;

	mptcp_pernet_set_defaults(pernet);

	err = mptcp_pernet_new_table(net, pernet);
	if (err)
		return err;

	sock = mptcp_create_join_listen_socket(net, AF_INET);
	if (IS_ERR(sock)) {
		err = PTR_ERR(sock);
		goto out_table;
	}

	err = mptcp_init_join_sk(net, sock->sk, &pernet->join4);
	if (err) {
		sock_release(sock);
		goto out_table;
	}

	/* struct sock is still reachable via sock->sk_socket backpointer */
	pernet->join4.sk = sock->sk;
	return err;

out_table:
	if (!net_eq(net, &init_net))
		mptcp_pernet_del_table(pernet);
	return err;
}

static void __net_exit mptcp_exit_join_sk(struct mptcp_join_sk *jsk)
{
	struct socket *ssock = __mptcp_nmpc_socket(mptcp_sk(jsk->sk));
	struct inet_bind_bucket *tb;
	struct inet_hashinfo *table;

	table = ssock->sk->sk_prot->h.hashinfo;

	tb = inet_csk(ssock->sk)->icsk_bind_hash;
	inet_bind_bucket_destroy(table->bind_bucket_cachep, tb);

	ssock = jsk->sk->sk_socket;
	sock_release(ssock);
}

/* Note: the callback will only be called per extra netns */
static void __net_exit mptcp_net_exit(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);

	mptcp_pernet_del_table(pernet);
	mptcp_exit_join_sk(&pernet->join4);
}

static struct pernet_operations mptcp_pernet_ops = {
	.init = mptcp_net_init,
	.exit = mptcp_net_exit,
	.id = &mptcp_pernet_id,
	.size = sizeof(struct mptcp_pernet),
};

void __init mptcp_init(void)
{
	mptcp_join_cookie_init();
	mptcp_proto_init();

	if (register_pernet_subsys(&mptcp_pernet_ops) < 0)
		panic("Failed to register MPTCP pernet subsystem.\n");
}

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
int __net_init mptcpv6_init_net(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);
	struct socket *sock;
	int err;

	if (net_eq(net, &init_net)) {
		err = mptcp_proto_v6_init();
		if (err)
			return err;
	}

	sock = mptcp_create_join_listen_socket(net, AF_INET6);
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	err = mptcp_init_join_sk(net, sock->sk, &pernet->join6);
	if (err) {
		sock_release(sock);
		return err;
	}

	pernet->join6.sk = sock->sk;
	return 0;
}

void __net_exit mptcpv6_exit_net(struct net *net)
{
	struct mptcp_pernet *pernet = mptcp_get_pernet(net);

	mptcp_exit_join_sk(&pernet->join6);
}
#endif
