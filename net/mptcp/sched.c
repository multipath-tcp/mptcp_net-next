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

static void mptcp_sched_default_data_init(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data)
{
	data->snd_burst = 0;
}

static int mptcp_sched_default_get_subflow(const struct mptcp_sock *msk,
					   struct mptcp_sched_data *data)
{
	struct sock *ssk;

	ssk = data->reinject ? mptcp_subflow_get_retrans(msk) :
			       mptcp_subflow_get_send(msk, data);
	if (!ssk)
		return -EINVAL;

	mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
	return 0;
}

static struct mptcp_sched_ops mptcp_sched_default = {
	.data_init	= mptcp_sched_default_data_init,
	.get_subflow	= mptcp_sched_default_get_subflow,
	.name		= "default",
	.owner		= THIS_MODULE,
};

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
	if (!sched->data_init || !sched->get_subflow)
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
	if (sched == &mptcp_sched_default)
		return;

	spin_lock(&mptcp_sched_list_lock);
	list_del_rcu(&sched->list);
	spin_unlock(&mptcp_sched_list_lock);
}

void mptcp_sched_init(void)
{
	mptcp_register_scheduler(&mptcp_sched_default);
}

int mptcp_init_sched(struct mptcp_sock *msk,
		     struct mptcp_sched_ops *sched,
		     gfp_t gfp)
{
	if (!sched)
		sched = &mptcp_sched_default;

	if (!bpf_try_module_get(sched, sched->owner))
		return -EBUSY;

	msk->sched_data = kzalloc(sizeof(struct mptcp_sched_data), gfp);
	if (!msk->sched_data) {
		bpf_module_put(sched, sched->owner);
		return -ENOMEM;
	}

	msk->sched = sched;
	if (msk->sched->init)
		msk->sched->init(msk);

	pr_debug("sched=%s", msk->sched->name);

	return 0;
}

void mptcp_release_sched(struct mptcp_sock *msk)
{
	struct mptcp_sched_ops *sched = msk->sched;

	if (!sched)
		return;

	if (msk->sched_data) {
		if (msk->sched_data->last_snd)
			msk->sched_data->last_snd = NULL;
		kfree(msk->sched_data);
		msk->sched_data = NULL;
	}
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

void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
				   struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;
	int i = 0;

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
}

int mptcp_sched_get_send(struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	msk_owned_by_me(msk);

	/* the following check is moved out of mptcp_subflow_get_send */
	if (__mptcp_check_fallback(msk)) {
		if (msk->first &&
		    __tcp_can_send(msk->first) &&
		    sk_stream_memory_free(msk->first)) {
			mptcp_subflow_set_scheduled(mptcp_subflow_ctx(msk->first), true);
			return 0;
		}
		return -EINVAL;
	}

	mptcp_for_each_subflow(msk, subflow) {
		if (READ_ONCE(subflow->scheduled))
			return 0;
	}

	if (!msk->sched) {
		struct sock *ssk;

		ssk = mptcp_subflow_get_send(msk, msk->sched_data);
		if (!ssk)
			return -EINVAL;
		mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
		return 0;
	}

	msk->sched_data->reinject = false;
	msk->sched->data_init(msk, msk->sched_data);
	return msk->sched->get_subflow(msk, msk->sched_data);
}

int mptcp_sched_get_retrans(struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;

	msk_owned_by_me(msk);

	/* the following check is moved out of mptcp_subflow_get_retrans */
	if (__mptcp_check_fallback(msk))
		return -EINVAL;

	mptcp_for_each_subflow(msk, subflow) {
		if (READ_ONCE(subflow->scheduled))
			return 0;
	}

	if (!msk->sched) {
		struct sock *ssk;

		ssk = mptcp_subflow_get_retrans(msk);
		if (!ssk)
			return -EINVAL;
		mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
		return 0;
	}

	msk->sched_data->reinject = true;
	msk->sched->data_init(msk, msk->sched_data);
	return msk->sched->get_subflow(msk, msk->sched_data);
}
