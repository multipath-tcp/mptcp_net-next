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

static int mptcp_sched_default_get_send(struct mptcp_sock *msk)
{
	struct sock *ssk;

	ssk = mptcp_subflow_get_send(msk);
	if (!ssk)
		return -EINVAL;

	mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
	return 0;
}

/* the active subflow with nothing to send or retransmit and the lowest RTT */
static struct sock *mptcp_sched_oppr_idle_ssk(struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	struct sock *pick = NULL;
	u32 best = U32_MAX;

	mptcp_for_each_subflow(msk, subflow) {
		struct sock *ssk = mptcp_subflow_tcp_sock(subflow);
		u32 rtt = READ_ONCE(tcp_sk(ssk)->srtt_us);

		if (!__mptcp_subflow_active(subflow) || subflow->backup ||
		    subflow->request_bkup || subflow->stale || !rtt)
			continue;
		/* racy on a DATA_ACK, only a hint: the worker checks again */
		if (!data_race(tcp_rtx_and_write_queues_empty(ssk)))
			continue;
		if (rtt < best) {
			best = rtt;
			pick = ssk;
		}
	}
	return pick;
}

static int mptcp_sched_default_get_retrans(struct mptcp_sock *msk)
{
	struct sock *ssk;

	ssk = mptcp_subflow_get_retrans(msk);
	if (!ssk)
		return -EINVAL;

	mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
	return 0;
}

static struct mptcp_sched_ops mptcp_sched_default = {
	.get_send	= mptcp_sched_default_get_send,
	.get_retrans	= mptcp_sched_default_get_retrans,
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

/* Build string with list of available scheduler values.
 * Similar to tcp_get_available_congestion_control()
 */
void mptcp_get_available_schedulers(char *buf, size_t maxlen)
{
	struct mptcp_sched_ops *sched;
	size_t offs = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(sched, &mptcp_sched_list, list) {
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", sched->name);

		if (WARN_ON_ONCE(offs >= maxlen))
			break;
	}
	rcu_read_unlock();
}

int mptcp_validate_scheduler(struct mptcp_sched_ops *sched)
{
	if (!sched->get_send) {
		pr_err("%s does not implement required ops\n", sched->name);
		return -EINVAL;
	}

	return 0;
}

int mptcp_register_scheduler(struct mptcp_sched_ops *sched)
{
	int ret;

	ret = mptcp_validate_scheduler(sched);
	if (ret)
		return ret;

	spin_lock(&mptcp_sched_list_lock);
	if (mptcp_sched_find(sched->name)) {
		spin_unlock(&mptcp_sched_list_lock);
		return -EEXIST;
	}
	list_add_tail_rcu(&sched->list, &mptcp_sched_list);
	spin_unlock(&mptcp_sched_list_lock);

	pr_debug("%s registered\n", sched->name);
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
		     struct mptcp_sched_ops *sched)
{
	if (!sched)
		sched = &mptcp_sched_default;

	if (!bpf_try_module_get(sched, sched->owner))
		return -EBUSY;

	msk->sched = sched;
	if (msk->sched->init)
		msk->sched->init(msk);

	pr_debug("sched=%s\n", msk->sched->name);

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

	if (msk->sched == &mptcp_sched_default || !msk->sched)
		return mptcp_sched_default_get_send(msk);

	/* limits are per decision: a retransmission can leave some behind */
	mptcp_for_each_subflow(msk, subflow)
		subflow->send_limit = 0;
	return msk->sched->get_send(msk);
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

	if (msk->sched == &mptcp_sched_default || !msk->sched)
		return mptcp_sched_default_get_retrans(msk);
	if (msk->sched->get_retrans)
		return msk->sched->get_retrans(msk);
	return msk->sched->get_send(msk);
}

/* Opportunistic reinjection, "opportunistic retransmission" in section 4.2
 * of Raiciu et al., NSDI 2012.
 *
 * With paths of different speeds, data sent on a slow or lossy path holds
 * back the DATA_ACK while the fast path keeps delivering what comes after
 * it. Once the receive window or the send buffer is used up, nothing new
 * can be sent: the fast path drains and stays idle until the slow path
 * delivers, or until the MPTCP-level RTO fires. The same happens when the
 * application has nothing more to send for now: the end of what it wrote
 * waits on the slow path, and so does the application if it expects an
 * answer.
 *
 * That state can be seen when a DATA_ACK comes in: no new data can go out,
 * and an active subflow has nothing queued or in flight. The data at
 * snd_una is then held by another subflow, so resend on the idle subflow
 * the ranges that the other subflows still hold, taken from the DSS
 * mappings in their queues, instead of everything from snd_una: most of
 * that already reached the peer.
 *
 * The scheduler decides on which subflow, and how much, through get_retrans
 * with the reason in msk->sched_retrans. This is done at most once per
 * snd_una value.
 */
#define MPTCP_OPPR_MIN		(16 * 1024)

/* can the scheduler be asked to reinject: see mptcp_sched_get_reinject() */
static bool mptcp_sched_has_reinject(const struct mptcp_sock *msk)
{
	const struct mptcp_sched_ops *sched = READ_ONCE(msk->sched);

	return sched && sched != &mptcp_sched_default && sched->get_retrans;
}

/* Ask the scheduler where to resend the data other subflows hold, because a
 * subflow is idle while nothing new can be sent, for @reason: see
 * MPTCP_SCHED_RETRANS_IDLE_WND. Only a scheduler with its own get_retrans is
 * asked; the default one does not reinject.
 */
static int mptcp_sched_get_reinject(struct mptcp_sock *msk, u8 reason)
{
	struct mptcp_subflow_context *subflow;
	int err;

	msk_owned_by_me(msk);

	if (__mptcp_check_fallback(msk))
		return -EINVAL;

	mptcp_for_each_subflow(msk, subflow) {
		if (READ_ONCE(subflow->scheduled))
			return -EBUSY;
		subflow->reinject_limit = 0;
	}

	if (!mptcp_sched_has_reinject(msk))
		return -EOPNOTSUPP;

	msk->sched_retrans = reason;
	err = msk->sched->get_retrans(msk);
	msk->sched_retrans = MPTCP_SCHED_RETRANS_RTO;
	return err;
}

/* Why nothing new can go out while the peer waits for data: an
 * MPTCP_SCHED_RETRANS_IDLE_* reason, or 0 when new data can still go out
 * (the scheduler will then use the idle subflow) or nothing is waiting.
 * Read without the msk socket lock when called from a DATA_ACK.
 */
static u8 mptcp_sched_oppr_reason(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	u64 snd_una = READ_ONCE(msk->snd_una);
	struct socket *sock;

	/* with csum, a resend must spool a complete DSS */
	if (snd_una == READ_ONCE(msk->snd_nxt) ||
	    snd_una == READ_ONCE(msk->oppr_una) ||
	    READ_ONCE(msk->csum_enabled) || __mptcp_check_fallback(msk))
		return 0;

	/* only the DATA_FIN is waiting */
	if (snd_una + 1 == READ_ONCE(msk->snd_nxt) &&
	    mptcp_data_fin_enabled(msk))
		return 0;

	if (mptcp_send_head(sk)) {
		if (mptcp_wnd_end(msk) - READ_ONCE(msk->snd_nxt) >= MPTCP_OPPR_MIN)
			return 0;
		return MPTCP_SCHED_RETRANS_IDLE_WND;
	}

	/* everything written so far was handed to a subflow */
	sock = READ_ONCE(sk->sk_socket);
	if (sock && test_bit(SOCK_NOSPACE, &sock->flags))
		return MPTCP_SCHED_RETRANS_IDLE_SNDBUF;
	return MPTCP_SCHED_RETRANS_IDLE_APP;
}

/* Add what @skb holds to @r, sorted by start. When @r is full, keep the lowest
 * ones: the data at snd_una is the one the peer is waiting for.
 */
static int mptcp_sched_oppr_add_skb(const struct sk_buff *skb, u64 una,
				    u64 *last, struct mptcp_oppr_range *r,
				    int n)
{
	const struct mptcp_ext *mpext = mptcp_get_ext(skb);
	u64 start, end;
	int i;

	if (!mpext || !mpext->use_map || !mpext->data_len ||
	    mpext->data_seq == *last)
		return n;

	/* one mapping can span several skbs after a TCP split */
	*last = mpext->data_seq;
	start = mpext->data_seq;
	end = start + mpext->data_len;
	if (!after64(end, una))
		return n;
	if (before64(start, una))
		start = una;

	if (n == MPTCP_OPPR_MAX_RANGES) {
		if (!before64(start, r[n - 1].start))
			return n;
		n--;
	}

	for (i = n; i > 0 && after64(r[i - 1].start, start); i--)
		r[i] = r[i - 1];
	r[i].start = start;
	r[i].end = end;
	return n + 1;
}

/* The DSN ranges at or after @una that the subflows other than @idle still
 * hold, sent or not: the data the peer is waiting for. Sorted by start, and
 * merged: data resent before can sit on more than one subflow.
 */
static int mptcp_sched_oppr_collect(struct mptcp_sock *msk, struct sock *idle,
				    u64 una, struct mptcp_oppr_range *r)
{
	struct mptcp_subflow_context *subflow;
	int n = 0, i, k;

	mptcp_for_each_subflow(msk, subflow) {
		struct sock *ssk = mptcp_subflow_tcp_sock(subflow);
		struct sk_buff *skb;
		u64 last = 0;

		if (ssk == idle)
			continue;

		lock_sock(ssk);
		skb_rbtree_walk(skb, &ssk->tcp_rtx_queue)
			n = mptcp_sched_oppr_add_skb(skb, una, &last, r, n);
		skb_queue_walk(&ssk->sk_write_queue, skb)
			n = mptcp_sched_oppr_add_skb(skb, una, &last, r, n);
		release_sock(ssk);
	}

	for (i = 1, k = 0; i < n; i++) {
		if (!after64(r[i].start, r[k].end)) {
			if (after64(r[i].end, r[k].end))
				r[k].end = r[i].end;
		} else {
			r[++k] = r[i];
		}
	}
	return n ? k + 1 : 0;
}

/* What to resend from @oppr->una for an opportunistic reinjection, if anything:
 * ask the scheduler, then take the ranges from the subflows. Called from the
 * worker.
 */
bool mptcp_sched_oppr_get(struct mptcp_sock *msk,
			  struct mptcp_sched_oppr *oppr)
{
	struct mptcp_subflow_context *subflow;
	struct sock *sk = (struct sock *)msk;
	u8 reason;
	int err;

	/* no subflow to use yet: the next DATA_ACK checks again */
	reason = mptcp_sched_oppr_reason(sk);
	if (!reason || !mptcp_sched_oppr_idle_ssk(msk))
		return false;

	/* same with a send pending: new data is about to go out */
	err = mptcp_sched_get_reinject(msk, reason);
	if (err == -EBUSY)
		return false;

	oppr->ssk = NULL;
	oppr->limit = 0;
	oppr->n = 0;
	mptcp_for_each_subflow(msk, subflow) {
		if (!READ_ONCE(subflow->scheduled))
			continue;
		if (!err && !oppr->ssk && subflow->reinject_limit) {
			oppr->ssk = mptcp_subflow_tcp_sock(subflow);
			oppr->limit = subflow->reinject_limit;
		}
		mptcp_subflow_set_scheduled(subflow, false);
	}

	/* the scheduler declined, or nothing to resend: not again for this
	 * snd_una
	 */
	if (oppr->ssk)
		oppr->n = mptcp_sched_oppr_collect(msk, oppr->ssk, oppr->una,
						   oppr->r);
	if (!oppr->n) {
		WRITE_ONCE(msk->oppr_una, oppr->una);
		return false;
	}
	return true;
}
