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
#include "protocol.h"

static DEFINE_SPINLOCK(mptcp_sched_list_lock);
static LIST_HEAD(mptcp_sched_list);

/* Must be called with rcu read lock held */
struct mptcp_sched_ops *mptcp_sched_find(const char *name)
{
	struct mptcp_sched_ops *sched, *ret = NULL;

	list_for_each_entry_rcu(sched, &mptcp_sched_list, list) {
		if (!strcmp(sched->name, name)) {
			ret = sched;
			break;
		}
	}

	return ret;
}

int mptcp_register_scheduler(struct mptcp_sched_ops *sched)
{
	if (!sched->get_subflow)
		return -EINVAL;

	spin_lock(&mptcp_sched_list_lock);
	if (mptcp_sched_find(sched->name)) {
		spin_unlock(&mptcp_sched_list_lock);
		return -EEXIST;
	}
	list_add_tail_rcu(&sched->list, &mptcp_sched_list);
	spin_unlock(&mptcp_sched_list_lock);

	pr_debug("%s registered", sched->name);
	return 0;
}

void mptcp_unregister_scheduler(struct mptcp_sched_ops *sched)
{
	spin_lock(&mptcp_sched_list_lock);
	list_del_rcu(&sched->list);
	spin_unlock(&mptcp_sched_list_lock);
}

int mptcp_init_sched(struct mptcp_sock *msk,
		     struct mptcp_sched_ops *sched)
{
	if (!sched)
		goto out;

	if (!bpf_try_module_get(sched, sched->owner))
		return -EBUSY;

	msk->sched = sched;
	if (msk->sched->init)
		msk->sched->init(msk);

	pr_debug("sched=%s", msk->sched->name);

out:
	return 0;
}

void mptcp_release_sched(struct mptcp_sock *msk)
{
	struct mptcp_sched_ops *sched = msk->sched;

	if (!sched)
		return;

	msk->sched = NULL;
	if (sched->release)
		sched->release(msk);

	bpf_module_put(sched, sched->owner);
}

void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
				 bool scheduled)
{
	WRITE_ONCE(subflow->scheduled, scheduled);
}

static int mptcp_sched_data_init(struct mptcp_sock *msk, bool reinject,
				 struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;
	int i = 0;

	data->reinject = reinject;

	mptcp_for_each_subflow(msk, subflow) {
		if (i == MPTCP_SUBFLOWS_MAX) {
			pr_warn_once("too many subflows");
			break;
		}
		mptcp_subflow_set_scheduled(subflow, false);
		data->contexts[i++] = subflow;
	}

	for (; i < MPTCP_SUBFLOWS_MAX; i++)
		data->contexts[i] = NULL;

	return 0;
}

struct sock *mptcp_sched_get_send(struct mptcp_sock *msk)
{
	struct mptcp_sched_data data;
	struct sock *ssk = NULL;
	int i;

	sock_owned_by_me((struct sock *)msk);

	/* the following check is moved out of mptcp_subflow_get_send */
	if (__mptcp_check_fallback(msk)) {
		if (!msk->first)
			return NULL;
		return sk_stream_memory_free(msk->first) ? msk->first : NULL;
	}

	if (!msk->sched)
		return mptcp_subflow_get_send(msk);

	mptcp_sched_data_init(msk, false, &data);
	msk->sched->get_subflow(msk, &data);

	for (i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		if (data.contexts[i] && READ_ONCE(data.contexts[i]->scheduled)) {
			ssk = data.contexts[i]->tcp_sock;
			msk->last_snd = ssk;
			break;
		}
	}

	return ssk;
}

struct sock *mptcp_sched_get_retrans(struct mptcp_sock *msk)
{
	struct mptcp_sched_data data;
	struct sock *ssk = NULL;
	int i;

	sock_owned_by_me((const struct sock *)msk);

	/* the following check is moved out of mptcp_subflow_get_retrans */
	if (__mptcp_check_fallback(msk))
		return NULL;

	if (!msk->sched)
		return mptcp_subflow_get_retrans(msk);

	mptcp_sched_data_init(msk, true, &data);
	msk->sched->get_subflow(msk, &data);

	for (i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		if (data.contexts[i] && READ_ONCE(data.contexts[i]->scheduled)) {
			ssk = data.contexts[i]->tcp_sock;
			msk->last_snd = ssk;
			break;
		}
	}

	return ssk;
}
