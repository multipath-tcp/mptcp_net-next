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

static inline bool before64(__u64 seq1, __u64 seq2)
{
	return (__s64)(seq1 - seq2) < 0;
}

#define after64(seq2, seq1)	before64(seq1, seq2)

static int mptcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	int mss_now, size_goal, poffset, ret;
	struct mptcp_ext *mpext = NULL;
	struct page *page = NULL;
	struct sk_buff *skb;
	struct sock *ssk;
	size_t psize;

	pr_debug("msk=%p", msk);
	if (!msk->connection_list && msk->subflow) {
		pr_debug("fallback passthrough");
		return sock_sendmsg(msk->subflow, msg);
	}

	if (!msg_data_left(msg)) {
		pr_debug("empty send");
		return sock_sendmsg(msk->connection_list, msg);
	}

	ssk = msk->connection_list->sk;

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL))
		return -ENOTSUPP;

	/* Initial experiment: new page per send.  Real code will
	 * maintain list of active pages and DSS mappings, append to the
	 * end and honor zerocopy
	 */
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	/* Copy to page */
	poffset = 0;
	pr_debug("left=%zu", msg_data_left(msg));
	psize = copy_page_from_iter(page, poffset,
				    min_t(size_t, msg_data_left(msg),
					  PAGE_SIZE),
				    &msg->msg_iter);
	pr_debug("left=%zu", msg_data_left(msg));

	if (!psize) {
		put_page(page);
		return -EINVAL;
	}

	lock_sock(sk);
	lock_sock(ssk);

	/* Mark the end of the previous write so the beginning of the
	 * next write (with its own mptcp skb extension data) is not
	 * collapsed.
	 */
	skb = tcp_write_queue_tail(ssk);
	if (skb)
		TCP_SKB_CB(skb)->eor = 1;

	mss_now = tcp_send_mss(ssk, &size_goal, msg->msg_flags);

	ret = do_tcp_sendpages(ssk, page, poffset, min_t(int, size_goal, psize),
			       msg->msg_flags | MSG_SENDPAGE_NOTLAST);
	put_page(page);
	if (ret <= 0)
		goto error_out;

	if (skb == tcp_write_queue_tail(ssk))
		pr_err("no new skb %p/%p", sk, ssk);

	skb = tcp_write_queue_tail(ssk);

	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);

	if (mpext) {
		memset(mpext, 0, sizeof(*mpext));
		mpext->data_seq = msk->write_seq;
		mpext->subflow_seq = subflow_sk(ssk)->rel_write_seq;
		mpext->dll = ret;
		mpext->checksum = 0xbeef;
		mpext->use_map = 1;
		mpext->dsn64 = 1;

		pr_debug("data_seq=%llu subflow_seq=%u dll=%u checksum=%u, dsn64=%d",
			 mpext->data_seq, mpext->subflow_seq, mpext->dll,
			 mpext->checksum, mpext->dsn64);
	} /* TODO: else fallback */

	msk->write_seq += ret;
	subflow_sk(ssk)->rel_write_seq += ret;

	tcp_push(ssk, msg->msg_flags, mss_now, tcp_sk(ssk)->nonagle, size_goal);

error_out:
	release_sock(ssk);
	release_sock(sk);

	return ret;
}

struct mptcp_read_arg {
	struct msghdr *msg;
};

static u64 expand_seq(u64 old_seq, u16 old_dll, u64 seq)
{
	if ((u32)seq == (u32)old_seq)
		return old_seq;

	/* Assume map covers data not mapped yet. */
	return seq | ((old_seq + old_dll + 1) & ~0xFFFFFFFFULL);
}

static u64 get_mapped_dsn(struct subflow_sock *subflow)
{
	u32 map_offset = (tcp_sk(sock_sk(subflow))->copied_seq -
			  subflow->ssn_offset -
			  subflow->map_subflow_seq);

	return subflow->map_seq + map_offset;
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
	struct subflow_sock *subflow = subflow_sk(ssk);
	struct mptcp_ext *mpext;
	enum mapping_status ret;
	struct sk_buff *skb;

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

	pr_debug("seq=%llu is64=%d ssn=%u dll=%u ck=%u",
		 mpext->data_seq, mpext->dsn64, mpext->subflow_seq, mpext->dll,
		 mpext->checksum);

	if (mpext->dll == 0) {
		pr_err("Infinite mapping not handled");
		ret = MAPPING_MISSING;
		goto del_out;
	} else if (mpext->subflow_seq == 0 &&
		   mpext->data_fin == 1) {
		pr_debug("DATA_FIN with no payload");
		ret = MAPPING_DATA_FIN;
		goto del_out;
	}

	if (subflow->map_valid)
		pr_warn("Replaced mapping before it was done");

	if (!mpext->dsn64) {
		subflow->map_seq = expand_seq(subflow->map_seq,
					      subflow->map_dll,
					      mpext->data_seq);
		pr_debug("expanded seq=%llu", subflow->map_seq);
	} else {
		subflow->map_seq = mpext->data_seq;
	}

	subflow->map_subflow_seq = mpext->subflow_seq;
	subflow->map_dll = mpext->dll;
	subflow->map_valid = true;
	ret = MAPPING_ADDED;
	pr_debug("new map seq=%llu subflow_seq=%u dll=%u",
		 subflow->map_seq, subflow->map_subflow_seq,
		 subflow->map_dll);

del_out:
	__skb_ext_del(skb, SKB_EXT_MPTCP);
	return ret;;
}

static int mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			 int nonblock, int flags, int *addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct subflow_sock *subflow;
	struct mptcp_read_arg arg;
	read_descriptor_t desc;
	struct tcp_sock *tp;
	struct sock *ssk;
	int copied = 0;
	long timeo;

	if (!msk->connection_list) {
		pr_debug("fallback-read subflow=%p", msk->subflow->sk);
		return sock_recvmsg(msk->subflow, msg, flags);
	}

	ssk = msk->connection_list->sk;
	subflow = subflow_sk(ssk);
	tp = tcp_sk(ssk);

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
		old_ack = atomic64_read(&msk->ack_seq);

		if (unlikely(before(ssn, subflow->map_subflow_seq))) {
			/* Mapping covers data later in the subflow stream,
			 * discard unmapped data.
			 */
			pr_debug("Mapping covers data later in stream");
			discard_len = subflow->map_subflow_seq - ssn;
		} else if (unlikely(!before(ssn, (subflow->map_subflow_seq +
						  subflow->map_dll)))) {
			/* Mapping ends earlier in the subflow stream.
			 * Invalidate the mapping and try again.
			 */
			subflow->map_valid = false;
			pr_debug("Invalid mapping ssn=%d map_seq=%d map_dll=%d",
				 ssn, subflow->map_subflow_seq,
				 subflow->map_dll);
			continue;
		} else {
			ack_seq = get_mapped_dsn(subflow);

			if (before64(ack_seq, old_ack)) {
				/* Mapping covers data already received,
				 * discard data in the current mapping
				 * and invalidate the map
				 */
				u64 map_end_dsn = subflow->map_seq +
					subflow->map_dll;
				discard_len = min(map_end_dsn - ack_seq,
						  old_ack - ack_seq);
				subflow->map_valid = false;
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
		map_remaining = (ssn - subflow->map_subflow_seq +
				 subflow->map_dll);
		desc.count = min_t(size_t, len - copied, map_remaining);
		arg.msg = msg;
		bytes_read = tcp_read_sock(ssk, &desc, mptcp_read_actor);
		if (bytes_read < 0)
			break;

		/* Refresh current MPTCP sequence number based on subflow seq */
		ack_seq = get_mapped_dsn(subflow);

		if (before64(old_ack, ack_seq))
			atomic64_set(&msk->ack_seq, ack_seq);

		if (!before(tcp_sk(ssk)->copied_seq - subflow->ssn_offset,
			    subflow->map_subflow_seq + subflow->map_dll)) {
			subflow->map_valid = false;
			pr_debug("Done with mapping: seq=%u dll=%u",
				 subflow->map_subflow_seq, subflow->map_dll);
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

	return copied;
}

static int mptcp_init_sock(struct sock *sk)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	pr_debug("msk=%p", msk);

	return 0;
}

static void mptcp_close(struct sock *sk, long timeout)
{
	struct mptcp_sock *msk = mptcp_sk(sk);

	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		sock_release(msk->subflow);
	}

	if (msk->connection_list) {
		pr_debug("conn_list->subflow=%p", msk->connection_list->sk);
		sock_release(msk->connection_list);
	}
}

static struct sock *mptcp_accept(struct sock *sk, int flags, int *err,
				 bool kern)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *listener = msk->subflow;
	struct socket *new_sock;
	struct socket *mp;
	struct subflow_sock *subflow;

	pr_debug("msk=%p, listener=%p", msk, listener->sk);
	*err = kernel_accept(listener, &new_sock, flags);
	if (*err < 0)
		return NULL;

	subflow = subflow_sk(new_sock->sk);
	pr_debug("new_sock=%p", subflow);

	*err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_MPTCP, &mp);
	if (*err < 0) {
		kernel_sock_shutdown(new_sock, SHUT_RDWR);
		sock_release(new_sock);
		return NULL;
	}

	msk = mptcp_sk(mp->sk);
	pr_debug("msk=%p", msk);
	subflow->conn = mp->sk;

	if (subflow->mp_capable) {
		u64 ack_seq;

		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		pr_debug("token=%u", msk->token);
		token_update_accept(new_sock->sk, mp->sk);
		msk->connection_list = new_sock;

		crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		msk->write_seq = subflow->idsn + 1;
		ack_seq++;
		atomic64_set(&msk->ack_seq, ack_seq);
		subflow->map_seq = ack_seq;
		subflow->map_subflow_seq = 1;
		subflow->rel_write_seq = 1;
		subflow->conn = mp->sk;
	} else {
		msk->subflow = new_sock;
	}
	inet_sk_state_store(sk, TCP_ESTABLISHED);

	return mp->sk;
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
	struct socket *subflow;
	char __kernel *optval;

	pr_debug("msk=%p", msk);
	if (msk->connection_list) {
		subflow = msk->connection_list;
		pr_debug("conn_list->subflow=%p", subflow->sk);
	} else {
		subflow = msk->subflow;
		pr_debug("subflow=%p", subflow->sk);
	}

	/* will be treated as __user in subflow_setsockopt */
	optval = (char __kernel __force *)uoptval;

	return kernel_setsockopt(subflow, level, optname, optval, optlen);
}

static int mptcp_getsockopt(struct sock *sk, int level, int optname,
			    char __user *uoptval, int __user *uoption)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct socket *subflow;
	char __kernel *optval;
	int __kernel *option;

	pr_debug("msk=%p", msk);
	if (msk->connection_list) {
		subflow = msk->connection_list;
		pr_debug("conn_list->subflow=%p", subflow->sk);
	} else {
		subflow = msk->subflow;
		pr_debug("subflow=%p", subflow->sk);
	}

	/* will be treated as __user in subflow_getsockopt */
	optval = (char __kernel __force *)uoptval;
	option = (int __kernel __force *)uoption;

	return kernel_getsockopt(subflow, level, optname, optval, option);
}

static int mptcp_get_port(struct sock *sk, unsigned short snum)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct sock *subflow = msk->subflow->sk;

	pr_debug("msk=%p, subflow=%p", sk, subflow);

	return inet_csk_get_port(subflow, snum);
}

void mptcp_finish_connect(struct sock *sk, int mp_capable)
{
	struct mptcp_sock *msk = mptcp_sk(sk);
	struct subflow_sock *subflow = subflow_sk(msk->subflow->sk);

	pr_debug("msk=%p", msk);

	if (mp_capable) {
		u64 ack_seq;

		msk->remote_key = subflow->remote_key;
		msk->local_key = subflow->local_key;
		msk->token = subflow->token;
		pr_debug("token=%u", msk->token);
		msk->connection_list = msk->subflow;
		msk->subflow = NULL;

		crypto_key_sha1(msk->remote_key, NULL, &ack_seq);
		msk->write_seq = subflow->idsn + 1;
		ack_seq++;
		atomic64_set(&msk->ack_seq, ack_seq);
		subflow->map_seq = ack_seq;
		subflow->map_subflow_seq = 1;
		subflow->rel_write_seq = 1;
	}
	inet_sk_state_store(sk, TCP_ESTABLISHED);
}

static int subflow_create(struct sock *sock)
{
	struct mptcp_sock *msk = mptcp_sk(sock);
	struct socket *sf;
	int err;

	err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_SUBFLOW,
			       &sf);
	if (!err) {
		struct subflow_sock *subflow = subflow_sk(sf->sk);

		pr_debug("subflow=%p", subflow);
		msk->subflow = sf;
		subflow->conn = sock;
		subflow->request_mptcp = 1; // @@ if MPTCP enabled
		subflow->checksum = 1; // @@ if checksum enabled
		subflow->version = 0;
	}
	return err;
}

int mptcp_stream_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err;

	pr_debug("msk=%p", msk);

	if (!msk->subflow) {
		err = subflow_create(sock->sk);
		if (err)
			return err;
	}
	return inet_bind(msk->subflow, uaddr, addr_len);
}

int mptcp_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			 int addr_len, int flags)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err;

	pr_debug("msk=%p", msk);

	if (!msk->subflow) {
		err = subflow_create(sock->sk);
		if (err)
			return err;
	}

	return inet_stream_connect(msk->subflow, uaddr, addr_len, flags);
}

int mptcp_stream_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	struct socket *subflow;
	int err = -EPERM;

	if (msk->connection_list)
		subflow = msk->connection_list;
	else
		subflow = msk->subflow;

	err = inet_getname(subflow, uaddr, peer);

	return err;
}

int mptcp_stream_listen(struct socket *sock, int backlog)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int err;

	pr_debug("msk=%p", msk);

	if (!msk->subflow) {
		err = subflow_create(sock->sk);
		if (err)
			return err;
	}
	return inet_listen(msk->subflow, backlog);
}

int mptcp_stream_accept(struct socket *sock, struct socket *newsock, int flags,
			bool kern)
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
	const struct mptcp_sock *msk;
	struct sock *sk = sock->sk;

	msk = mptcp_sk(sk);
	if (msk->subflow)
		return tcp_poll(file, msk->subflow, wait);

	return tcp_poll(file, msk->connection_list, wait);
}

int mptcp_stream_shutdown(struct socket *sock, int how)
{
	struct mptcp_sock *msk = mptcp_sk(sock->sk);
	int ret = 0;

	pr_debug("sk=%p, how=%d", msk, how);

	if (msk->subflow) {
		pr_debug("subflow=%p", msk->subflow->sk);
		ret = kernel_sock_shutdown(msk->subflow, how);
	}
	if (msk->connection_list) {
		pr_debug("conn_list->subflow=%p", msk->connection_list->sk);
		ret = kernel_sock_shutdown(msk->connection_list, how);
	}

	return ret;
}

static struct proto mptcp_prot = {
	.name		= "MPTCP",
	.owner		= THIS_MODULE,
	.init		= mptcp_init_sock,
	.close		= mptcp_close,
	.accept		= mptcp_accept,
	.shutdown	= tcp_shutdown,
	.destroy	= mptcp_destroy,
	.setsockopt	= mptcp_setsockopt,
	.getsockopt	= mptcp_getsockopt,
	.sendmsg	= mptcp_sendmsg,
	.recvmsg	= mptcp_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= mptcp_get_port,
	.obj_size	= sizeof(struct mptcp_sock),
	.no_autobind	= 1,
};

const struct proto_ops mptcp_stream_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = mptcp_stream_bind,
	.connect	   = mptcp_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = mptcp_stream_accept,
	.getname	   = mptcp_stream_getname,
	.poll		   = mptcp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = mptcp_stream_listen,
	.shutdown	   = mptcp_stream_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
	.splice_read	   = tcp_splice_read,
	.read_sock	   = tcp_read_sock,
	.peek_len	   = tcp_peek_len,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};

static struct inet_protosw mptcp_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_MPTCP,
	.prot		= &mptcp_prot,
	.ops		= &mptcp_stream_ops,
	.flags		= INET_PROTOSW_ICSK,
};

static int __init mptcp_init(void)
{
	int err;

	mptcp_prot.h.hashinfo = tcp_prot.h.hashinfo;

	token_init();
	crypto_init();

	err = mptcp_subflow_init();
	if (err)
		goto subflow_failed;

	err = proto_register(&mptcp_prot, 1);
	if (err)
		goto proto_failed;

	inet_register_protosw(&mptcp_protosw);

	return 0;

proto_failed:
	mptcp_subflow_exit();

subflow_failed:
	return err;
}

static void __exit mptcp_exit(void)
{
	inet_unregister_protosw(&mptcp_protosw);
	proto_unregister(&mptcp_prot);

	mptcp_subflow_exit();
}

module_init(mptcp_init);
module_exit(mptcp_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_INET, IPPROTO_MPTCP);
MODULE_ALIAS_NET_PF_PROTO(PF_INET6, IPPROTO_MPTCP);
