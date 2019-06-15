// SPDX-License-Identifier: GPL-2.0
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched/signal.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

static inline bool before64(__u64 seq1, __u64 seq2)
{
	return (__s64)(seq1 - seq2) < 0;
}

#define after64(seq2, seq1)	before64(seq1, seq2)

static struct sock *mptcp_subflow_get_ref(const struct mptcp_sock *msk)
{
	struct subflow_context *subflow;

	sock_owned_by_me((const struct sock *)msk);

	mptcp_for_each_subflow(msk, subflow) {
		struct sock *sk;

		sk = mptcp_subflow_tcp_socket(subflow)->sk;
		sock_hold(sk);
		return sk;
	}

	return NULL;
}

static inline bool mptcp_skb_can_collapse_to(const struct mptcp_sock *msk,
					     const struct sk_buff *skb,
					     const struct mptcp_ext *mpext)
{
	if (!tcp_skb_can_collapse_to(skb))
		return false;

	/* can collapse only if MPTCP level sequence is in order */
	return mpext && mpext->data_seq + mpext->data_len == msk->write_seq;
}

static int mptcp_sendmsg_frag(struct sock *sk, struct sock *ssk,
			      struct msghdr *msg, long *timeo, int *pmss_now,
			      int *ps_goal)
{
	int mss_now, avail_size, size_goal, ret;
	struct mptcp_sock *msk = mptcp_sk(sk);
	bool collapsed, can_collapse = false;
	struct mptcp_ext *mpext = NULL;
	struct page_frag *pfrag;
	struct sk_buff *skb;
	size_t psize;

	/* use the mptcp page cache so that we can easily move the data
	 * from one substream to another, but do per subflow memory accounting
	 */
	pfrag = sk_page_frag(sk);
	while (!sk_page_frag_refill(ssk, pfrag)) {
		ret = sk_stream_wait_memory(ssk, timeo);
		if (ret)
			return ret;
	}

	/* compute copy limit */
	mss_now = tcp_send_mss(ssk, &size_goal, msg->msg_flags);
	*pmss_now = mss_now;
	*ps_goal = size_goal;
	avail_size = size_goal;
	skb = tcp_write_queue_tail(ssk);
	if (skb) {
		mpext = skb_ext_find(skb, SKB_EXT_MPTCP);

		/* Limit the write to the size available in the
		 * current skb, if any, so that we create at most a new skb.
		 * If we run out of space in the current skb (e.g. the window
		 * size shrunk from last sent) a new skb will be allocated even
		 * is collapsing was allowed: collapsing is effectively
		 * disabled.
		 */
		can_collapse = mptcp_skb_can_collapse_to(msk, skb, mpext);
		if (!can_collapse)
			TCP_SKB_CB(skb)->eor = 1;
		else if (size_goal - skb->len > 0)
			avail_size = size_goal - skb->len;
		else
			can_collapse = false;
	}
	psize = min_t(size_t, pfrag->size - pfrag->offset, avail_size);

	/* Copy to page */
	pr_debug("left=%zu", msg_data_left(msg));
	psize = copy_page_from_iter(pfrag->page, pfrag->offset,
				    min_t(size_t, msg_data_left(msg), psize),
				    &msg->msg_iter);
	pr_debug("left=%zu", msg_data_left(msg));
	if (!psize)
		return -EINVAL;

	/* tell the TCP stack to delay the push so that we can safely
	 * access the skb after the sendpages call
	 */
	ret = do_tcp_sendpages(ssk, pfrag->page, pfrag->offset, psize,
			       msg->msg_flags | MSG_SENDPAGE_NOTLAST);
	if (ret <= 0)
		return ret;
	if (unlikely(ret < psize))
		iov_iter_revert(&msg->msg_iter, psize - ret);

	collapsed = skb == tcp_write_queue_tail(ssk);
	BUG_ON(collapsed && !can_collapse);
	if (collapsed) {
		/* when collapsing mpext always exists */
		mpext->data_len += ret;
		goto out;
	}

	skb = tcp_write_queue_tail(ssk);
	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);
	if (mpext) {
		memset(mpext, 0, sizeof(*mpext));
		mpext->data_seq = msk->write_seq;
		mpext->subflow_seq = subflow_ctx(ssk)->rel_write_seq;
		mpext->data_len = ret;
		mpext->checksum = 0xbeef;
		mpext->use_map = 1;
		mpext->dsn64 = 1;

		pr_debug("data_seq=%llu subflow_seq=%u data_len=%u checksum=%u, dsn64=%d",
			 mpext->data_seq, mpext->subflow_seq, mpext->data_len,
			 mpext->checksum, mpext->dsn64);
	}
	/* TODO: else fallback; allocation can fail, but we can't easily retire
	 * skbs from the write_queue, as we need to roll-back TCP status
	 */

out:
	pfrag->offset += ret;
	msk->write_seq += ret;
	subflow_ctx(ssk)->rel_write_seq += ret;

	return ret;
}

static int mptcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	int mss_now = 0, size_goal = 0, ret = 0;
	struct mptcp_sock *msk = mptcp_sk(sk);
	size_t copied = 0;
	struct sock *ssk;
	long timeo;

	pr_debug("msk=%p", msk);
	if (msk->subflow) {
		pr_debug("fallback passthrough");
		return sock_sendmsg(msk->subflow, msg);
	}

	lock_sock(sk);
	ssk = mptcp_subflow_get_ref(msk);
	if (!ssk) {
		release_sock(sk);
		return -ENOTCONN;
	}

	if (!msg_data_left(msg)) {
		pr_debug("empty send");
		ret = sock_sendmsg(ssk->sk_socket, msg);
		goto put_out;
	}

	pr_debug("conn_list->subflow=%p", ssk);

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL)) {
		ret = -ENOTSUPP;
		goto put_out;
	}

	lock_sock(ssk);
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	while (msg_data_left(msg)) {
		ret = mptcp_sendmsg_frag(sk, ssk, msg, &timeo, &mss_now,
					 &size_goal);
		if (ret < 0)
			break;

		copied += ret;
	}
	if (copied) {
		ret = copied;
		tcp_push(ssk, msg->msg_flags, mss_now, tcp_sk(ssk)->nonagle,
			 size_goal);
	}

	release_sock(ssk);

put_out:
	release_sock(sk);
	sock_put(ssk);
	return ret;
}

struct mptcp_read_arg {
	struct msghdr *msg;
};

static u64 expand_seq(u64 old_seq, u16 old_data_len, u64 seq)
{
	if ((u32)seq == (u32)old_seq)
		return old_seq;

	/* Assume map covers data not mapped yet. */
	return seq | ((old_seq + old_data_len + 1) & GENMASK_ULL(63,32));
}

static u64 get_map_offset(struct subflow_context *subflow)
{
	return tcp_sk(mptcp_subflow_tcp_socket(subflow)->sk)->copied_seq -
		      subflow->ssn_offset -
		      subflow->map_subflow_seq;
}

static u64 get_mapped_dsn(struct subflow_context *subflow)
{
	return subflow->map_seq + get_map_offset(subflow);
}

static int mptcp_read_actor(read_descriptor_t *desc, struct sk_buff *skb,
			    unsigned int offset, size_t len)
{
	struct mptcp_read_arg *arg = desc->arg.data;
	size_t copy_len;

	copy_len = min(desc->count, len);

	if (likely(arg->msg)) {
		int err;

		err = skb_copy_datagram_msg(skb, offset, arg->msg, copy_len);
		if (err) {
			pr_debug("error path");
			desc->error = err;
			return err;
		}
	} else {
		pr_debug("Flushing skb payload");
	}

	// MSG_PEEK support? Other flags? MSG_TRUNC?

	desc->count -= copy_len;

	pr_debug("consumed %zu bytes, %zu left", copy_len, desc->count);
	return copy_len;
}

static int mptcp_flush_actor(read_descriptor_t *desc, struct sk_buff *skb,
			     unsigned int offset, size_t len)
{
	pr_debug("Flushing one skb with %zu of %zu bytes remaining",
		 len, len + offset);

	desc->count = 0;

	return len;
}

enum mapping_status {
	MAPPING_ADDED,
	MAPPING_MISSING,
	MAPPING_EMPTY,
	MAPPING_DATA_FIN
};

static enum mapping_status mptcp_get_mapping(struct sock *ssk)
{
	struct subflow_context *subflow = subflow_ctx(ssk);
	struct mptcp_ext *mpext;
	enum mapping_status ret;
	struct sk_buff *skb;
	u64 map_seq;

	skb = skb_peek(&ssk->sk_receive_queue);
	if (!skb) {
		pr_debug("Empty queue");
		return MAPPING_EMPTY;
	}

	mpext = mptcp_get_ext(skb);

	if (!mpext) {
		/* This is expected for non-DSS data packets */
		return MAPPING_MISSING;
	}

	if (!mpext->use_map) {
		ret = MAPPING_MISSING;
		goto del_out;
	}

	pr_debug("seq=%llu is64=%d ssn=%u data_len=%u ck=%u",
		 mpext->data_seq, mpext->dsn64, mpext->subflow_seq,
		 mpext->data_len, mpext->checksum);

	if (mpext->data_len == 0) {
		pr_err("Infinite mapping not handled");
		ret = MAPPING_MISSING;
		goto del_out;
	} else if (mpext->subflow_seq == 0 &&
		   mpext->data_fin == 1) {
		pr_debug("DATA_FIN with no payload");
		ret = MAPPING_DATA_FIN;
		goto del_out;
	}

	if (!mpext->dsn64) {
		map_seq = expand_seq(subflow->map_seq, subflow->map_data_len,
				     mpext->data_seq);
		pr_debug("expanded seq=%llu", subflow->map_seq);
	} else {
		map_seq = mpext->data_seq;
	}

	if (subflow->map_valid) {
		/* due to GSO/TSO we can receive the same mapping multiple
		 * times, before it's expiration.
		 */
		if (subflow->map_seq != map_seq ||
		    subflow->map_subflow_seq != mpext->subflow_seq ||
		    subflow->map_data_len != mpext->data_len)
			pr_warn("Replaced mapping before it was done");
	}

	subflow->map_seq = map_seq;
	subflow->map_subflow_seq = mpext->subflow_seq;
	subflow->map_data_len = mpext->data_len;
	subflow->map_valid = 1;
	ret = MAPPING_ADDED;
	pr_debug("new map seq=%llu subflow_seq=%u data_len=%u",
		 subflow->map_seq, subflow->map_subflow_seq,
		 subflow->map_data_len);

del_out:
	__skb_ext_del(skb, SKB_EXT_MPTCP);
	return ret;;
}

static int mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct subflow_context *subflow;
	struct mptcp_read_arg arg;
	read_descriptor_t desc;
	struct tcp_sock *tp;
	struct sock *ssk;
	int copied = 0;
	long timeo;

	if (msk->subflow) {
		pr_debug("fallback-read subflow=%p", subflow_ctx(msk->subflow->sk));
		return sock_recvmsg(msk->subflow, msg, flags);
	}

	lock_sock(sk);
	ssk = mptcp_subflow_get_ref(msk);
	if (!ssk) {
		release_sock(sk);
		return -ENOTCONN;
	}

	subflow = subflow_ctx(ssk);
	tp = tcp_sk(ssk);

	lock_sock(ssk);

	desc.arg.data = &arg;
	desc.error = 0;

	timeo = sock_rcvtimeo(sk, nonblock);

	len = min_t(size_t, len, INT_MAX);

	while (copied < len) {
		enum mapping_status status;
		size_t discard_len = 0;
		u32 map_remaining;
		int bytes_read;
		u64 ack_seq;
		u64 old_ack;
		u32 ssn;

		status = mptcp_get_mapping(ssk);

		if (status == MAPPING_ADDED) {
			/* Common case, but nothing to do here */
		} else if (status == MAPPING_MISSING) {
			if (!subflow->map_valid) {
				pr_debug("Mapping missing, trying next skb");

				arg.msg = NULL;
				desc.count = SIZE_MAX;

				bytes_read = tcp_read_sock(ssk, &desc,
							   mptcp_flush_actor);

				if (bytes_read < 0)
					break;

				continue;
			}
		} else if (status == MAPPING_EMPTY) {
			goto wait_for_data;
		} else if (status == MAPPING_DATA_FIN) {
			/* TODO: Handle according to RFC 6824 */
			if (!copied) {
				pr_err("Can't read after DATA_FIN");
				copied = -ENOTCONN;
			}

			break;
		}

		ssn = tcp_sk(ssk)->copied_seq - subflow->ssn_offset;
		old_ack = msk->ack_seq;

		if (unlikely(before(ssn, subflow->map_subflow_seq))) {
			/* Mapping covers data later in the subflow stream,
			 * discard unmapped data.
			 */
			pr_debug("Mapping covers data later in stream");
			discard_len = subflow->map_subflow_seq - ssn;
		} else if (unlikely(!before(ssn, (subflow->map_subflow_seq +
						  subflow->map_data_len)))) {
			/* Mapping ends earlier in the subflow stream.
			 * Invalidate the mapping and try again.
			 */
			subflow->map_valid = 0;
			pr_debug("Invalid mapping ssn=%d map_seq=%d map_data_len=%d",
				 ssn, subflow->map_subflow_seq,
				 subflow->map_data_len);
			continue;
		} else {
			ack_seq = get_mapped_dsn(subflow);

			if (before64(ack_seq, old_ack)) {
				/* Mapping covers data already received,
				 * discard data in the current mapping
				 * and invalidate the map
				 */
				u64 map_end_dsn = subflow->map_seq +
					subflow->map_data_len;
				discard_len = min(map_end_dsn - ack_seq,
						  old_ack - ack_seq);
				subflow->map_valid = 0;
				pr_debug("Duplicate MPTCP data found");
			}
		}

		if (discard_len) {
			/* Discard data for the current mapping.
			 */
			pr_debug("Discard %zu bytes", discard_len);

			arg.msg = NULL;
			desc.count = discard_len;

			bytes_read = tcp_read_sock(ssk, &desc,
						   mptcp_read_actor);

			if (bytes_read < 0)
				break;
			else if (bytes_read == discard_len)
				continue;
			else
				goto wait_for_data;
		}

		/* Read mapped data */
		map_remaining = subflow->map_data_len - get_map_offset(subflow);
		desc.count = min_t(size_t, len - copied, map_remaining);
		arg.msg = msg;
		bytes_read = tcp_read_sock(ssk, &desc, mptcp_read_actor);
		if (bytes_read < 0)
			break;

		/* Refresh current MPTCP sequence number based on subflow seq */
		ack_seq = get_mapped_dsn(subflow);

		if (before64(old_ack, ack_seq))
			msk->ack_seq = ack_seq;

		if (!before(tcp_sk(ssk)->copied_seq - subflow->ssn_offset,
			    subflow->map_subflow_seq + subflow->map_data_len)) {
			subflow->map_valid = 0;
			pr_debug("Done with mapping: seq=%u data_len=%u",
				 subflow->map_subflow_seq,
				 subflow->map_data_len);
		}

		copied += bytes_read;

wait_for_data:
		if (copied)
			break;

		if (tp->urg_data && tp->urg_seq == tp->copied_seq) {
			pr_err("Urgent data present, cannot proceed");
			break;
		}

		if (ssk->sk_err || ssk->sk_state == TCP_CLOSE ||
		    (ssk->sk_shutdown & RCV_SHUTDOWN) || !timeo ||
		    signal_pending(current)) {
			pr_debug("nonblock or error");
			break;
		}

		/* Handle blocking and retry read if needed.
		 *
		 * Wait on MPTCP sock, the subflow will notify via data ready.
		 */

		pr_debug("block");
		release_sock(ssk);
		sk_wait_data(sk, &timeo, NULL);
		lock_sock(ssk);
	}

	release_sock(ssk);
	release_sock(sk);

	sock_put(ssk);

	return copied;
}

static int mptcp_init_sock(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p", msk);

	INIT_LIST_HEAD(&msk->conn_list);

	return 0;
}

static void mptcp_close(struct sock *sk, long timeout)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct subflow_context *subflow, *tmp;
	struct socket *ssk = NULL;

	inet_sk_state_store(sk, TCP_CLOSE);

	lock_sock(sk);

	if (msk->subflow) {
		ssk = msk->subflow;
		msk->subflow = NULL;
	}

	if (ssk != NULL) {
		pr_debug("subflow=%p", ssk->sk);
		sock_release(ssk);
	}

	list_for_each_entry_safe(subflow, tmp, &msk->conn_list, node) {
		pr_debug("conn_list->subflow=%p", subflow);
		sock_release(mptcp_subflow_tcp_socket(subflow));
	}
	release_sock(sk);

	sock_orphan(sk);
	sock_put(sk);
}

static struct sock *mptcp_accept(struct sock *sk, int flags, int *err,
				 bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *listener = msk->subflow;
	struct subflow_context *subflow;
	struct socket *new_sock;
	struct sock *newsk;

	pr_debug("msk=%p, listener=%p", msk, subflow_ctx(listener->sk));
	*err = kernel_accept(listener, &new_sock, flags);
	if (*err < 0)
		return NULL;

	subflow = subflow_ctx(new_sock->sk);
	pr_debug("msk=%p, new subflow=%p, ", msk, subflow);

	if (subflow->mp_capable) {
		struct sock *new_mptcp_sock;
		u64 ack_seq;

		lock_sock(sk);

		local_bh_disable();
		new_mptcp_sock = sk_clone_lock(sk, GFP_ATOMIC);
		if (!new_mptcp_sock) {
			*err = -ENOBUFS;
			local_bh_enable();
			release_sock(sk);
			kernel_sock_shutdown(new_sock, SHUT_RDWR);
			sock_release(new_sock);
			return NULL;
		}

		mptcp_init_sock(new_mptcp_sock);

		msk = mptcp_sk(new_mptcp_sock);
		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		token_update_accept(new_sock->sk, new_mptcp_sock);
		msk->subflow = NULL;

		pm_new_connection(msk);

		crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		msk->write_seq = subflow->idsn + 1;
		ack_seq++;
		msk->ack_seq = ack_seq;
		subflow->map_seq = ack_seq;
		subflow->map_subflow_seq = 1;
		subflow->rel_write_seq = 1;
		subflow->tcp_sock = new_sock;
		newsk = new_mptcp_sock;
		subflow->conn = new_mptcp_sock;
		list_add(&subflow->node, &msk->conn_list);
		bh_unlock_sock(new_mptcp_sock);
		local_bh_enable();
		inet_sk_state_store(newsk, TCP_ESTABLISHED);
		release_sock(sk);
	} else {
		newsk = new_sock->sk;
		tcp_sk(newsk)->is_mptcp = 0;
		new_sock->sk = NULL;
		sock_release(new_sock);
	}

	return newsk;
}

static void mptcp_destroy(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p, subflow=%p", sk, msk->subflow->sk);

	token_destroy(msk->token);
}

static int mptcp_setsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, unsigned int optlen)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	char __kernel *optval;

	/* will be treated as __user in tcp_setsockopt */
	optval = (char __kernel __force *)uoptval;

	pr_debug("msk=%p", msk);
	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		return kernel_setsockopt(msk->subflow, level, optname, optval,
					 optlen);
	}

	/* @@ the meaning of setsockopt() when the socket is connected and
	 * there are multiple subflows is not defined.
	 */
	return 0;
}

static int mptcp_getsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, int __user *uoption)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	char __kernel *optval;
	int __kernel *option;

	/* will be treated as __user in tcp_getsockopt */
	optval = (char __kernel __force *)uoptval;
	option = (int __kernel __force *)uoption;

	pr_debug("msk=%p", msk);
	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		return kernel_getsockopt(msk->subflow, level, optname, optval,
					 option);
	}

	/* @@ the meaning of setsockopt() when the socket is connected and
	 * there are multiple subflows is not defined.
	 */
	return 0;
}

static int mptcp_get_port(struct sock *sk, unsigned short snum)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p, subflow=%p", msk, subflow_ctx(msk->subflow->sk));

	return inet_csk_get_port(msk->subflow->sk, snum);
}

void mptcp_finish_connect(struct sock *sk, int mp_capable)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct subflow_context *subflow = subflow_ctx(msk->subflow->sk);

	if (mp_capable) {
		u64 ack_seq;

		/* sk (new subflow socket) is already locked, but we need
		 * to lock the parent (mptcp) socket now to add the tcp socket
		 * to the subflow list.
		 *
		 * From lockdep point of view, this creates an ABBA type
		 * deadlock: Normally (sendmsg, recvmsg, ..), we lock the mptcp
		 * socket, then acquire a subflow lock.
		 * Here we do the reverse: "subflow lock, then mptcp lock".
		 *
		 * Its alright to do this here, because this subflow is not yet
		 * on the mptcp sockets subflow list.
		 *
		 * IOW, if another CPU has this mptcp socket locked, it cannot
		 * acquire this particular subflow, because subflow->sk isn't
		 * on msk->conn_list.
		 *
		 * This function can be called either from backlog processing
		 * (BH will be enabled) or from softirq, so we need to use BH
		 * locking scheme.
		 */
		local_bh_disable();
		bh_lock_sock_nested(sk);

		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		pr_debug("msk=%p, token=%u", msk, msk->token);

		pm_new_connection(msk);

		crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		msk->write_seq = subflow->idsn + 1;
		ack_seq++;
		msk->ack_seq = ack_seq;
		subflow->map_seq = ack_seq;
		subflow->map_subflow_seq = 1;
		subflow->rel_write_seq = 1;

		list_add(&subflow->node, &msk->conn_list);
		msk->subflow = NULL;
		bh_unlock_sock(sk);
		local_bh_enable();
	}
	inet_sk_state_store(sk, TCP_ESTABLISHED);
}

static struct proto mptcp_prot = {
	.name		= "MPTCP",
	.owner		= THIS_MODULE,
	.init		= mptcp_init_sock,
	.close		= mptcp_close,
	.accept		= mptcp_accept,
	.setsockopt	= mptcp_setsockopt,
	.getsockopt	= mptcp_getsockopt,
	.shutdown	= tcp_shutdown,
	.destroy	= mptcp_destroy,
	.sendmsg	= mptcp_sendmsg,
	.recvmsg	= mptcp_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= mptcp_get_port,
	.obj_size	= sizeof(struct mptcp_sock),
	.no_autobind	= 1,
};

static int mptcp_subflow_create(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct net *net = sock_net(sk);
	struct socket *sf;
	int err;

	pr_debug("msk=%p", msk);
	err = sock_create_kern(net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sf);
	if (!err) {
		lock_sock(sf->sk);
		err = tcp_set_ulp(sf->sk, "mptcp");
		release_sock(sf->sk);
		if (!err) {
			struct subflow_context *subflow = subflow_ctx(sf->sk);

			pr_debug("subflow=%p", subflow);
			msk->subflow = sf;
			subflow->conn = sk;
			subflow->request_mptcp = 1; // @@ if MPTCP enabled
			subflow->request_cksum = 1; // @@ if checksum enabled
			subflow->version = 0;
		}
	}
	return err;
}

static int mptcp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err = -ENOTSUPP;

	pr_debug("msk=%p", msk);

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	if (!msk->subflow) {
	        err = mptcp_subflow_create(sock->sk);
	        if (err)
	                return err;
	}
	return inet_bind(msk->subflow, uaddr, addr_len);
}

static int mptcp_stream_connect(struct socket *sock, struct sockaddr *uaddr,
				int addr_len, int flags)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err = -ENOTSUPP;

	pr_debug("msk=%p", msk);

	if (uaddr->sa_family != AF_INET) // @@ allow only IPv4 for now
		return err;

	if (!msk->subflow) {
		err = mptcp_subflow_create(sock->sk);
		if (err)
			return err;
	}

	return inet_stream_connect(msk->subflow, uaddr, addr_len, flags);
}

static int mptcp_getname(struct socket *sock, struct sockaddr *uaddr,
			 int peer)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct sock *ssk;
	int ret;

	pr_debug("msk=%p", msk);

	if (sock->sk->sk_prot == &tcp_prot) {
		/* we are being invoked from __sys_accept4, after
		 * mptcp_accept() has just accepted a non-mp-capable
		 * flow: sk is a tcp_sk, not an mptcp one.
		 *
		 * Hand the socket over to tcp so all further socket ops
		 * bypass mptcp.
		 */
		sock->ops = &inet_stream_ops;
		return inet_getname(sock, uaddr, peer);
	}

	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		return inet_getname(msk->subflow, uaddr, peer);
	}

	/* @@ the meaning of getname() for the remote peer when the socket
	 * is connected and there are multiple subflows is not defined.
	 * For now just use the first subflow on the list.
	 */
	lock_sock(sock->sk);
	ssk = mptcp_subflow_get_ref(msk);
	if (!ssk) {
		release_sock(sock->sk);
		return -ENOTCONN;
	}

	ret = inet_getname(ssk->sk_socket, uaddr, peer);
	release_sock(sock->sk);
	sock_put(ssk);
	return ret;
}

static int mptcp_listen(struct socket *sock, int backlog)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err;

	pr_debug("msk=%p", msk);

	if (!msk->subflow) {
		err = mptcp_subflow_create(sock->sk);
		if (err)
			return err;
	}
	return inet_listen(msk->subflow, backlog);
}

static int mptcp_stream_accept(struct socket *sock, struct socket *newsock,
			       int flags, bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);

	pr_debug("msk=%p", msk);

	if (!msk->subflow)
		return -EINVAL;

	return inet_accept(sock, newsock, flags, kern);
}

static __poll_t mptcp_poll(struct file *file, struct socket *sock,
			   struct poll_table_struct *wait)
{
	struct subflow_context *subflow;
	const struct mptcp_sock *msk;
	struct sock *sk = sock->sk;
	__poll_t ret = 0;

	msk = mptcp_sk(sk);
	if (msk->subflow)
		return tcp_poll(file, msk->subflow, wait);

	lock_sock(sk);
	mptcp_for_each_subflow(msk, subflow) {
		struct socket *tcp_sock;

		tcp_sock = mptcp_subflow_tcp_socket(subflow);
		ret |= tcp_poll(file, tcp_sock, wait);
	}
	release_sock(sk);

	return ret;
}

static int mptcp_shutdown(struct socket *sock, int how)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct subflow_context *subflow;
	int ret = 0;

	pr_debug("sk=%p, how=%d", msk, how);

	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		return kernel_sock_shutdown(msk->subflow, how);
	}

	/* protect against concurrent mptcp_close(), so that nobody can
	 * remove entries from the conn list and walking the list
	 * is still safe.
	 *
	 * We can't use MPTCP socket lock to protect conn_list changes,
	 * as we need to update it from the BH via the mptcp_finish_connect()
	 */
	lock_sock(sock->sk);
	mptcp_for_each_subflow(msk, subflow) {
		struct socket *tcp_socket;

		tcp_socket = mptcp_subflow_tcp_socket(subflow);
		pr_debug("conn_list->subflow=%p", subflow);
		ret = kernel_sock_shutdown(tcp_socket, how);
	}
	release_sock(sock->sk);

	return ret;
}

static struct proto_ops mptcp_stream_ops;

static struct inet_protosw mptcp_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_MPTCP,
	.prot		= &mptcp_prot,
	.ops		= &mptcp_stream_ops,
	.flags		= INET_PROTOSW_ICSK,
};

void __init mptcp_init(void)
{
	mptcp_prot.h.hashinfo = tcp_prot.h.hashinfo;
	mptcp_stream_ops = inet_stream_ops;
	mptcp_stream_ops.bind = mptcp_bind;
	mptcp_stream_ops.connect = mptcp_stream_connect;
	mptcp_stream_ops.poll = mptcp_poll;
	mptcp_stream_ops.accept = mptcp_stream_accept;
	mptcp_stream_ops.getname = mptcp_getname;
	mptcp_stream_ops.listen = mptcp_listen;
	mptcp_stream_ops.shutdown = mptcp_shutdown;

	token_init();
	crypto_init();
	subflow_init();

	if (proto_register(&mptcp_prot, 1) != 0)
		panic("Failed to register MPTCP proto.\n");

	inet_register_protosw(&mptcp_protosw);
}
