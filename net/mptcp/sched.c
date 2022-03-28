// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2022, SUSE.
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include <net/netns/generic.h>
#include "protocol.h"

static int sched_pernet_id;

struct sched_pernet {
	/* protects pernet updates */
	spinlock_t		lock;
	struct list_head	sched_list;
};

static struct sched_pernet *sched_get_pernet(const struct net *net)
{
	return net_generic(net, sched_pernet_id);
}

struct mptcp_sched_ops *mptcp_sched_find(const struct net *net,
					 const char *name)
{
	struct sched_pernet *pernet = sched_get_pernet(net);
	struct mptcp_sched_ops *sched, *ret = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &pernet->sched_list, list) {
		if (!strcmp(sched->name, name)) {
			ret = sched;
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}

int mptcp_register_scheduler(const struct net *net,
			     struct mptcp_sched_ops *sched)
{
	struct sched_pernet *pernet = sched_get_pernet(net);

	if (!sched->get_subflow)
		return -EINVAL;

	if (mptcp_sched_find(net, sched->name))
		return -EEXIST;

	spin_lock(&pernet->lock);
	list_add_tail_rcu(&sched->list, &pernet->sched_list);
	spin_unlock(&pernet->lock);

	pr_debug("%s registered", sched->name);
	return 0;
}

void mptcp_unregister_scheduler(const struct net *net,
				struct mptcp_sched_ops *sched)
{
	struct sched_pernet *pernet = sched_get_pernet(net);

	spin_lock(&pernet->lock);
	list_del_rcu(&sched->list);
	spin_unlock(&pernet->lock);

	/* avoid workqueue lockup */
	synchronize_rcu();
}

static int __net_init sched_init_net(struct net *net)
{
	struct sched_pernet *pernet = sched_get_pernet(net);

	INIT_LIST_HEAD_RCU(&pernet->sched_list);
	spin_lock_init(&pernet->lock);

	return 0;
}

static void __net_exit sched_exit_net(struct net *net)
{
	struct sched_pernet *pernet = sched_get_pernet(net);
	struct mptcp_sched_ops *sched;

	spin_lock(&pernet->lock);
	list_for_each_entry_rcu(sched, &pernet->sched_list, list)
		list_del_rcu(&sched->list);
	spin_unlock(&pernet->lock);
}

static struct pernet_operations mptcp_sched_pernet_ops = {
	.init = sched_init_net,
	.exit = sched_exit_net,
	.id = &sched_pernet_id,
	.size = sizeof(struct sched_pernet),
};

void mptcp_sched_init(void)
{
	if (register_pernet_subsys(&mptcp_sched_pernet_ops) < 0)
		panic("Failed to register MPTCP sched pernet subsystem.\n");
}
