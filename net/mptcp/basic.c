// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2019, Intel Corporation.
 */
#include <linux/inet.h>
#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/netns/generic.h>
#include <net/mptcp.h>
#include "protocol.h"

static int basic_pernet_id;

struct basic_pernet {
	struct ctl_table_header *ctl_table_hdr;

	union {
		struct in_addr announce_v4_addr;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		struct in6_addr announce_v6_addr;
#endif
	};
	u8	has_announce_v4 : 1,
		has_announce_v6 : 1;
};

static struct workqueue_struct *basic_wq;
static void announce_addr_worker(struct work_struct *work);
static void create_subflow_worker(struct work_struct *work);

static int parse_addr(struct basic_pernet *pernet, const char *addr)
{
	if (in4_pton(addr, -1, (u8 *)&pernet->announce_v4_addr.s_addr, '\0',
		     NULL) > 0) {
		pernet->has_announce_v4 = 1;
		pernet->has_announce_v6 = 0;
		return 0;
	}
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	if (in6_pton(addr, -1, (u8 *)&pernet->announce_v6_addr.s6_addr, '\0',
		     NULL) > 0) {
		pernet->has_announce_v4 = 0;
		pernet->has_announce_v6 = 1;
		return 0;
	}
#endif
	pernet->has_announce_v4 = 0;
	pernet->has_announce_v6 = 0;

	return -1;
}

static int proc_parse_addr(struct ctl_table *ctl, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct net *net = current->nsproxy->net_ns;
	struct basic_pernet *pernet = net_generic(net, basic_pernet_id);
	struct ctl_table tbl;

	char *none = "none";
	char tmp[INET6_ADDRSTRLEN] = { 0 };
	int ret;

	memset(&tbl, 0, sizeof(struct ctl_table));

	if (write) {
		tbl.data = tmp;
		tbl.maxlen = sizeof(tmp);
	} else {
		if (pernet->has_announce_v4) {
			snprintf(tmp, INET_ADDRSTRLEN, "%pI4",
				 &pernet->announce_v4_addr);
			tbl.data = tmp;
		}
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		else if (pernet->has_announce_v6) {
			snprintf(tmp, INET6_ADDRSTRLEN, "%pI6c",
				 &pernet->announce_v6_addr);
			tbl.data = tmp;
		}
#endif
		else {
			tbl.data = none;
		}
		tbl.maxlen = strlen(tbl.data);
	}

	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0) {
		/* "none" string: we want to remove it */
		if (strncmp(none, tmp, 5) == 0) {
			pernet->has_announce_v4 = 0;
			pernet->has_announce_v6 = 0;
		} else if (parse_addr(pernet, tmp) < 0) {
			ret = -EINVAL;
		}
	}

	return ret;
}

static struct ctl_table basic_sysctl_table[] = {
	{
		.procname = "announce_addr",
		.maxlen = sizeof(char) * (INET6_ADDRSTRLEN),
		.mode = 0644,
		.proc_handler = proc_parse_addr
	},
	{}
};

static int basic_pernet_create_table(struct net *net,
				     struct basic_pernet *pernet)
{
	struct ctl_table *table;
	struct ctl_table_header *hdr;

	table = basic_sysctl_table;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(basic_sysctl_table),
				GFP_KERNEL);
		if (!table)
			goto err_alloc;
	}

	hdr = register_net_sysctl(net, "net/mptcp/pm", table);
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

static int __net_init basic_init_net(struct net *net)
{
	struct basic_pernet *pernet = net_generic(net, basic_pernet_id);
	int ret;

	ret = basic_pernet_create_table(net, pernet);
	if (ret < 0)
		return ret;

	return 0;
}

static void __net_exit basic_exit_net(struct net *net)
{
	struct basic_pernet *pernet = net_generic(net, basic_pernet_id);
	struct ctl_table *table = pernet->ctl_table_hdr->ctl_table_arg;

	unregister_net_sysctl_table(pernet->ctl_table_hdr);

	/* Note: the callback will only be called per extra netns */
	kfree(table);
}

static struct pernet_operations basic_pernet_ops = {
	.init = basic_init_net,
	.exit = basic_exit_net,
	.id = &basic_pernet_id,
	.size = sizeof(struct basic_pernet),
};

void mptcp_basic_init(void)
{
	if (register_pernet_subsys(&basic_pernet_ops) < 0)
		panic("Failed to register MPTCP PM pernet subsystem.\n");

	basic_wq = alloc_workqueue("basic_wq",
				   WQ_UNBOUND | WQ_MEM_RECLAIM, 8);
	if (!basic_wq)
		panic("Failed to allocate workqueue");
}

static void announce_addr_worker(struct work_struct *work)
{
	struct mptcp_pm_data *pm = container_of(work, struct mptcp_pm_data,
						addr_work);
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);
	struct sock *sk = (struct sock *)msk;
	struct basic_pernet *pernet;

	pernet = net_generic(sock_net((struct sock *)msk), basic_pernet_id);

	/* Only announce addresses in the same family as listening socket.
	 * When the listening socket can accept connections from both
	 * families this restriction may be removed.
	 */
	if (pernet->has_announce_v4 && sk->sk_family == AF_INET)
		mptcp_pm_announce_addr(pm->token, 1,
				       &pernet->announce_v4_addr);
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	else if (pernet->has_announce_v6 && sk->sk_family == AF_INET6)
		mptcp_pm_announce_addr6(pm->token, 1,
					&pernet->announce_v6_addr);
#endif
	sock_put((struct sock *)msk);
}

static void create_subflow_worker(struct work_struct *work)
{
	struct mptcp_pm_data *pm = container_of(work, struct mptcp_pm_data,
						subflow_work);
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);
	struct basic_pernet *pernet;

	pernet = net_generic(sock_net((struct sock *)msk), basic_pernet_id);

	if (pm->remote_family == AF_INET) {
		if (pernet->has_announce_v4)
			mptcp_pm_create_subflow(pm->token, pm->remote_id,
						&pernet->announce_v4_addr);
		else
			mptcp_pm_create_subflow(pm->token, pm->remote_id,
						NULL);
	}
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
	else if (pm->remote_family == AF_INET6) {
		if (pernet->has_announce_v6)
			mptcp_pm_create_subflow6(pm->token, pm->remote_id,
						 &pernet->announce_v6_addr);
		else
			mptcp_pm_create_subflow6(pm->token, pm->remote_id,
						 NULL);
	}
#endif

	sock_put((struct sock *)msk);
}

void mptcp_basic_new_connection(struct mptcp_pm_data *pm)
{
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);

	if (pm->server_side) {
		INIT_WORK(&pm->addr_work, announce_addr_worker);
		if (queue_work(basic_wq, &pm->addr_work))
			sock_hold((struct sock *)msk);
	}
}

void mptcp_basic_fully_established(struct mptcp_pm_data *pm)
{
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);

	if (!pm->server_side && !pm->fully_established && pm->remote_valid) {
		INIT_WORK(&pm->subflow_work, create_subflow_worker);
		if (queue_work(basic_wq, &pm->subflow_work))
			sock_hold((struct sock *)msk);
	}
}

void mptcp_basic_add_addr(struct mptcp_pm_data *pm)
{
	struct mptcp_sock *msk = container_of(pm, struct mptcp_sock, pm);

	if (!pm->server_side && !pm->remote_valid && pm->fully_established) {
		INIT_WORK(&pm->subflow_work, create_subflow_worker);
		if (queue_work(basic_wq, &pm->subflow_work))
			sock_hold((struct sock *)msk);
	}
}
