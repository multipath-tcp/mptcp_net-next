// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitmap.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/netdev_lock.h>
#include <net/psp.h>

#include "psp.h"

#define PSP_TX_GRACE_POLL_MS	1000

struct psp_txq_state {
	unsigned int num_tx_queues;
	unsigned long *drained_queues;
	unsigned int to_complete[];
};

static void psp_txq_state_free(struct psp_txq_state *state)
{
	if (!state)
		return;

	bitmap_free(state->drained_queues);
	kvfree(state);
}

static struct psp_txq_state *
psp_txq_state_alloc(unsigned int max_tx_queues)
{
	struct psp_txq_state *state;

	state = kvzalloc_flex(*state, to_complete, max_tx_queues);
	if (!state)
		return NULL;

	state->drained_queues = bitmap_zalloc(max_tx_queues, GFP_KERNEL);
	if (!state->drained_queues) {
		psp_txq_state_free(state);
		return NULL;
	}

	return state;
}

static void psp_tx_grace_start(struct psp_dev *psd)
{
	struct psp_txq_state *state = psd->tx_del.txq_state;
	struct net_device *dev = psd->main_netdev;
	unsigned int i;

	netdev_assert_locked(dev);

	/* Any instances of ndo_start_xmit() that observed these keys through
	 * psp_skb_get_assoc_rcu() must already be accounted in BQL's queued
	 * byte count. ndo_start_xmit() runs with BHs disabled, which forms an
	 * implicit RCU read-side critical section, and we are now at least one
	 * grace period after any of these psp_assocs have been cleared from
	 * sk->psp_assoc.
	 */
	state->num_tx_queues = dev->real_num_tx_queues;
	bitmap_zero(state->drained_queues, state->num_tx_queues);
	for (i = 0; i < state->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		state->to_complete[i] = READ_ONCE(txq->dql.num_queued);
	}
}

static bool psp_tx_grace_done(struct psp_dev *psd)
{
	struct psp_txq_state *state = psd->tx_del.txq_state;
	struct net_device *dev = psd->main_netdev;
	bool all_completed = true;
	unsigned int i;

	netdev_assert_locked(dev);

	if (dev->real_num_tx_queues < state->num_tx_queues)
		state->num_tx_queues = dev->real_num_tx_queues;

	for (i = 0; i < state->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		unsigned int completed;
		unsigned int queued;

		if (test_bit(i, state->drained_queues))
			continue;

		/* Drivers must meet the requirements documented in
		 * Documentation/networking/psp.rst to guarantee forward
		 * progress and avoid ending the grace period prematurely.
		 *
		 * We snapshotted num_queued in psp_tx_grace_start() and need
		 * to determine whether num_completed has since reached or
		 * passed that mark. For a given queue, we can consider first
		 * whether or not dql_reset() was called at any point between
		 * when we read num_queued until we read num_completed and
		 * num_queued here and then separate the space of possible
		 * states based on that.
		 *
		 * Not reset: num_queued and num_completed only increase, and
		 * dql keeps num_queued - num_completed <= INT_MAX at all
		 * times. We can form three exhaustive sub cases:
		 *
		 * (int)(to_complete - completed) <= 0: completion reached or
		 * passed the mark. At the time to_complete was read,
		 * completed was in [to_complete - INT_MAX, to_complete].
		 *
		 * (int)(to_complete - queued) > 0: to_complete and queued are
		 * both snapshots of num_queued, so queued has advanced more
		 * than INT_MAX + 1 past to_complete. num_completed lags
		 * queued by at most INT_MAX, so num_completed must have
		 * crossed to_complete.
		 *
		 * Otherwise the mark may still be in flight, so poll again.
		 *
		 * Reset: By the driver conditions laid out in
		 * Documentation/networking/psp.rst, if a dql_reset()
		 * occurred, and we are holding the instance lock, then we
		 * know the actual state of the queue is drained. The check
		 * below is then conservative because there is no risk of
		 * falsely declaring the queue drained. As long as dql makes
		 * forward progress the check should eventually report
		 * drained.
		 */
		completed = READ_ONCE(txq->dql.num_completed);
		queued = READ_ONCE(txq->dql.num_queued);

		if ((int)(state->to_complete[i] - completed) <= 0 ||
		    (int)(state->to_complete[i] - queued) > 0)
			__set_bit(i, state->drained_queues);
		else
			all_completed = false;
	}

	return all_completed;
}

static bool psp_tx_grace_active(struct psp_dev *psd)
{
	return !list_empty(&psd->tx_del.active);
}

static void psp_deferred_del_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct psp_assoc *pas, *tmp;
	bool need_reschedule;
	struct psp_dev *psd;
	LIST_HEAD(to_free);

	psd = container_of(dwork, struct psp_dev, tx_del.work);

	mutex_lock(&psd->lock);
	netdev_lock(psd->main_netdev);

	if (psp_tx_grace_active(psd) && psp_tx_grace_done(psd))
		list_splice_init(&psd->tx_del.active, &to_free);

	if (!psp_tx_grace_active(psd) && !list_empty(&psd->tx_del.next)) {
		psp_tx_grace_start(psd);
		list_splice_init(&psd->tx_del.next, &psd->tx_del.active);
	}

	netdev_unlock(psd->main_netdev);

	list_for_each_entry(pas, &to_free, assocs_list)
		psp_dev_tx_key_del(psd, pas);

	need_reschedule = psp_tx_grace_active(psd);
	mutex_unlock(&psd->lock);

	if (need_reschedule)
		mod_delayed_work(system_percpu_wq, &psd->tx_del.work,
				 msecs_to_jiffies(PSP_TX_GRACE_POLL_MS));

	list_for_each_entry_safe(pas, tmp, &to_free, assocs_list) {
		list_del(&pas->assocs_list);
		psp_dev_put(psd);
		kfree(pas);
	}
}

int psp_deferred_del_init(struct psp_dev *psd)
{
	INIT_LIST_HEAD(&psd->tx_del.active);
	INIT_LIST_HEAD(&psd->tx_del.next);
	INIT_DELAYED_WORK(&psd->tx_del.work, psp_deferred_del_work);

	if (!psd->ops->tx_key_del)
		return 0;

	psd->tx_del.txq_state =
		psp_txq_state_alloc(psd->main_netdev->num_tx_queues);

	return psd->tx_del.txq_state ? 0 : -ENOMEM;
}

void psp_deferred_del_stop(struct psp_dev *psd)
{
	disable_delayed_work_sync(&psd->tx_del.work);
}

void psp_deferred_del_uninit(struct psp_dev *psd, bool unpublished)
{
	struct psp_assoc *pas, *next;

	lockdep_assert(unpublished || lockdep_is_held(&psd->lock));

	psp_txq_state_free(psd->tx_del.txq_state);
	psd->tx_del.txq_state = NULL;

	list_splice_init(&psd->tx_del.active, &psd->tx_del.next);
	list_for_each_entry_safe(pas, next, &psd->tx_del.next, assocs_list) {
		list_del(&pas->assocs_list);
		psp_dev_tx_key_del(psd, pas);
		psp_dev_put(psd);
		kfree(pas);
	}
}

void psp_deferred_del_queue(struct psp_dev *psd, struct psp_assoc *pas)
{
	lockdep_assert_held(&psd->lock);

	list_move_tail(&pas->assocs_list, &psd->tx_del.next);
	schedule_delayed_work(&psd->tx_del.work, 0);
}
