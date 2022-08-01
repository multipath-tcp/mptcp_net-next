#include "mptcp_fastopen.h"

int mptcp_sendmsg_fastopen(struct sock *sk, struct msghdr *msg,
			   size_t len, struct mptcp_sock *msk,
			   size_t *copied)
{
	const struct iphdr *iph;
	struct ubuf_info *uarg;
	struct sockaddr *uaddr;
	struct sk_buff *skb;
	struct tcp_sock *tp;
	struct socket *ssk;
	int ret;

	ssk = __mptcp_nmpc_socket(msk);
	if (unlikely(!ssk))
		goto out_EFAULT;
	skb = tcp_stream_alloc_skb(ssk->sk, 0, ssk->sk->sk_allocation, true);
	if (unlikely(!skb))
		goto out_EFAULT;
	iph = ip_hdr(skb);
	if (unlikely(!iph))
		goto out_EFAULT;
	uarg = msg_zerocopy_realloc(sk, len, skb_zcopy(skb));
	if (unlikely(!uarg))
		goto out_EFAULT;
	uaddr = msg->msg_name;

	tp = tcp_sk(ssk->sk);
	if (unlikely(!tp))
		goto out_EFAULT;
	if (!tp->fastopen_req)
		tp->fastopen_req = kzalloc(sizeof(*tp->fastopen_req),
					   ssk->sk->sk_allocation);

	if (unlikely(!tp->fastopen_req))
		goto out_EFAULT;
	tp->fastopen_req->data = msg;
	tp->fastopen_req->size = len;
	tp->fastopen_req->uarg = uarg;

	/* requests a cookie */
	*copied = mptcp_stream_connect(sk->sk_socket, uaddr,
				   msg->msg_namelen, msg->msg_flags);

	return 0;
out_EFAULT:
	ret = -EFAULT;
	return ret;
}

void mptcp_reqsk_record_syn(const struct sock *sk,
			    struct request_sock *req,
			    const struct sk_buff *skb)
{
	if (tcp_sk(sk)->save_syn) {
		u32 length = skb_network_header_len(skb) + tcp_hdrlen(skb);
		struct saved_syn *svd_syn;
		u32 mac_headerlen;
		void *base;

		if (tcp_sk(sk)->save_syn == 2) {
			base = skb_mac_header(skb);
			mac_headerlen = skb_mac_header_len(skb);
			length += mac_headerlen;
		} else {
			base = skb_network_header(skb);
			mac_headerlen = 0;
		}

		svd_syn = kmalloc(struct_size(svd_syn, data, length),
				    GFP_ATOMIC);
		if (svd_syn) {
			svd_syn->mac_hdrlen = mac_headerlen;
			svd_syn->network_hdrlen = skb_network_header_len(skb);
			svd_syn->tcp_hdrlen = tcp_hdrlen(skb);
			memcpy(svd_syn->data, base, length);
			req->saved_syn = svd_syn;
		}
	}
}

void mptcp_ecn_create_request(struct request_sock *req,
			      const struct sk_buff *skb,
			      const struct sock *listen_sk,
			      const struct dst_entry *dst)
{
	const struct tcphdr *thdr = tcp_hdr(skb);
	const struct net *net = sock_net(listen_sk);
	bool thdr_ecn = thdr->ece && thdr->cwr;
	bool ect_stat, ecn_okay;
	u32 ecn_okay_dst;

	if (!thdr_ecn)
		return;

	ect_stat = !INET_ECN_is_not_ect(TCP_SKB_CB(skb)->ip_dsfield);
	ecn_okay_dst = dst_feature(dst, DST_FEATURE_ECN_MASK);
	ecn_okay = net->ipv4.sysctl_tcp_ecn || ecn_okay_dst;

	if (((!ect_stat || thdr->res1) && ecn_okay) || tcp_ca_needs_ecn(listen_sk) ||
	    (ecn_okay_dst & DST_FEATURE_ECN_CA) ||
	    tcp_bpf_ca_needs_ecn((struct sock *)req))
		inet_rsk(req)->ecn_ok = 1;
}

void mptcp_openreq_init(struct request_sock *req,
			const struct tcp_options_received *rx_opt,
			struct sk_buff *skb, const struct sock *sk)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	req->rsk_rcv_wnd = 0;
	tcp_rsk(req)->rcv_isn = TCP_SKB_CB(skb)->seq;
	tcp_rsk(req)->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
	tcp_rsk(req)->snt_synack = 0;
	tcp_rsk(req)->last_oow_ack_time = 0;
	req->mss = rx_opt->mss_clamp;
	req->ts_recent = rx_opt->saw_tstamp ? rx_opt->rcv_tsval : 0;
	ireq->tstamp_ok = rx_opt->tstamp_ok;
	ireq->sack_ok = rx_opt->sack_ok;
	ireq->snd_wscale = rx_opt->snd_wscale;
	ireq->wscale_ok = rx_opt->wscale_ok;
	ireq->acked = 0;
	ireq->ecn_ok = 0;
	ireq->ir_rmt_port = tcp_hdr(skb)->source;
	ireq->ir_num = ntohs(tcp_hdr(skb)->dest);
	ireq->ir_mark = inet_request_mark(sk, skb);
}

void mptcp_fastopen_add_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sock *msk = mptcp_subflow_ctx(sk)->conn;
	struct tcp_sock *tp = tcp_sk(sk);

	if (TCP_SKB_CB(skb)->end_seq == tp->rcv_nxt)
		return;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		return;

	skb_dst_drop(skb);

	tp->segs_in = 0;
	tcp_segs_in(tp, skb);
	__skb_pull(skb, tcp_hdrlen(skb));
	sk_forced_mem_schedule(sk, skb->truesize);
	skb_set_owner_r(skb, sk);

	TCP_SKB_CB(skb)->seq++;
	TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_SYN;

	tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;

	__skb_queue_tail(&msk->sk_receive_queue, skb);

	tp->syn_data_acked = 1;

	tp->bytes_received = skb->len;

	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		tcp_fin(sk);
}

struct sock *mptcp_fastopen_create_child(struct sock *sk,
					 struct sk_buff *skb,
					 struct request_sock *req)
{
	struct request_sock_queue *r_sock_queue = &inet_csk(sk)->icsk_accept_queue;
	struct tcp_sock *tp;
	struct sock *child_sock;
	bool own_req;

	child_sock = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL,
							 NULL, &own_req);
	if (!child_sock)
		return NULL;

	spin_lock(&r_sock_queue->fastopenq.lock);
	r_sock_queue->fastopenq.qlen++;
	spin_unlock(&r_sock_queue->fastopenq.lock);

	tp = tcp_sk(child_sock);

	rcu_assign_pointer(tp->fastopen_rsk, req);
	tcp_rsk(req)->tfo_listener = true;

	tp->snd_wnd = ntohs(tcp_hdr(skb)->window);
	tp->max_window = tp->snd_wnd;

	inet_csk_reset_xmit_timer(child_sock, ICSK_TIME_RETRANS,
				  TCP_TIMEOUT_INIT, TCP_RTO_MAX);

	refcount_set(&req->rsk_refcnt, 2);

	tcp_init_transfer(child_sock, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, skb);


	tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
	//tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
	//tp->copied_seq = 4;//3

	mptcp_fastopen_add_skb(child_sock, skb);

	tcp_rsk(req)->rcv_nxt = tp->rcv_nxt;
	tp->rcv_wup = tp->rcv_nxt;

	return child_sock;
}

bool mptcp_fastopen_queue_check(struct sock *sk)
{
	struct fastopen_queue *fo_queue;
	struct request_sock *req_sock;

	fo_queue = &inet_csk(sk)->icsk_accept_queue.fastopenq;
	if (fo_queue->max_qlen == 0)
		return false;

	if (fo_queue->qlen >= fo_queue->max_qlen) {

		spin_lock(&fo_queue->lock);
		req_sock = fo_queue->rskq_rst_head;
		if (!req_sock || time_after(req_sock->rsk_timer.expires, jiffies)) {
			spin_unlock(&fo_queue->lock);
			return false;
		}
		fo_queue->rskq_rst_head = req_sock->dl_next;
		fo_queue->qlen--;
		spin_unlock(&fo_queue->lock);
		reqsk_put(req_sock);
	}
	return true;
}

bool mptcp_fastopen_cookie_gen_cipher(struct request_sock *req,
				      struct sk_buff *syn,
				      const siphash_key_t *key,
				      struct tcp_fastopen_cookie *foc)
{
	if (req->rsk_ops->family == AF_INET) {
		const struct iphdr *iph = ip_hdr(syn);

		foc->val[0] = cpu_to_le64(siphash(&iph->saddr,
					  sizeof(iph->saddr) +
					  sizeof(iph->daddr),
					  key));
		foc->len = TCP_FASTOPEN_COOKIE_SIZE;
		return true;
	}

	return false;
}


void mptcp_fastopen_cookie_gen(struct sock *sk,
			       struct request_sock *req,
			       struct sk_buff *syn,
			       struct tcp_fastopen_cookie *foc)
{
	struct tcp_fastopen_context *ctx;

	rcu_read_lock();
	ctx = tcp_fastopen_get_ctx(sk);
	if (ctx)
		mptcp_fastopen_cookie_gen_cipher(req, syn, &ctx->key[0], foc);
	rcu_read_unlock();
}

int mptcp_fastopen_cookie_gen_check(struct sock *sk,
				    struct request_sock *req,
				    struct sk_buff *syn,
				    struct tcp_fastopen_cookie *orig,
				    struct tcp_fastopen_cookie *valid_foc)
{
	struct tcp_fastopen_cookie mptcp_search_foc = { .len = -1 };
	struct tcp_fastopen_cookie *mptcp_foc = valid_foc;
	struct tcp_fastopen_context *mptcp_fo_ctx;
	int i, ret = 0;

	rcu_read_lock();
	mptcp_fo_ctx = tcp_fastopen_get_ctx(sk);
	if (!mptcp_fo_ctx)
		goto out;
	for (i = 0; i < tcp_fastopen_context_len(mptcp_fo_ctx); i++) {
		mptcp_fastopen_cookie_gen_cipher(req, syn, &mptcp_fo_ctx->key[i], mptcp_foc);
		if (tcp_fastopen_cookie_match(mptcp_foc, orig)) {
			ret = i + 1;
			goto out;
		}
		mptcp_foc = &mptcp_search_foc;
	}
out:
	rcu_read_unlock();
	return ret;
}


bool mptcp_fastopen_no_cookie(const struct sock *sk,
			      const struct dst_entry *dst,
			      int flag)
{
	return (sock_net(sk)->ipv4.sysctl_tcp_fastopen & flag) ||
	       tcp_sk(sk)->fastopen_no_cookie ||
	       (dst && dst_metric(dst, RTAX_FASTOPEN_NO_COOKIE));
}

struct sock *mptcp_try_fastopen(struct sock *sk, struct sk_buff *skb,
				struct request_sock *req,
				struct tcp_fastopen_cookie *foc,
				const struct dst_entry *dst)
{
	bool syn_data_status = TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq + 1;
	struct tcp_fastopen_cookie valid_mptcp_foc = { .len = -1 };
	struct sock *child_sock;
	int ret = 0;


	if ((syn_data_status || foc->len >= 0) &&
	      mptcp_fastopen_queue_check(sk)) {
		foc->len = -1;
		return NULL;
	}

	if (mptcp_fastopen_no_cookie(sk, dst, TFO_SERVER_COOKIE_NOT_REQD))
		goto fastopen;

	if (foc->len == 0) {
		mptcp_fastopen_cookie_gen(sk, req, skb, &valid_mptcp_foc);
	} else if (foc->len > 0) {
		ret = mptcp_fastopen_cookie_gen_check(sk, req, skb, foc,
						    &valid_mptcp_foc);
		if (!ret) {
			__asm__ ("NOP");
		} else {
fastopen:
			child_sock = mptcp_fastopen_create_child(sk, skb, req);
			if (child_sock) {
				if (ret == 2) {
					valid_mptcp_foc.exp = foc->exp;
					*foc = valid_mptcp_foc;
				} else {
					foc->len = -1;
				}
				return child_sock;
			}
		}
	}
	valid_mptcp_foc.exp = foc->exp;
	*foc = valid_mptcp_foc;
	return NULL;
}

int mptcp_conn_request(struct request_sock_ops *rsk_ops,
		       const struct tcp_request_sock_ops *af_ops,
		       struct sock *sk, struct sk_buff *skb)
{
	struct tcp_fastopen_cookie mptcp_foc = { .len = -1 };
	struct tcp_options_received tmp_opt_rcvd;
	__u32 isn = TCP_SKB_CB(skb)->tcp_tw_isn;
	struct tcp_sock *tp_sock = tcp_sk(sk);
	struct sock *mptcp_fo_sk = NULL;
	struct net *net = sock_net(sk);
	struct request_sock *req_sock;
	bool want_cookie = false;
	struct dst_entry *dst;
	struct flowi fl;

	if (sk_acceptq_is_full(sk)) {
		goto drop;
	}

	req_sock = inet_reqsk_alloc(rsk_ops, sk, !want_cookie);
	if (!req_sock)
		goto drop;

	req_sock->syncookie = want_cookie;
	tcp_rsk(req_sock)->af_specific = af_ops;
	tcp_rsk(req_sock)->ts_off = 0;
	tcp_rsk(req_sock)->is_mptcp = 1;

	tcp_clear_options(&tmp_opt_rcvd);
	tmp_opt_rcvd.mss_clamp = af_ops->mss_clamp;
	tmp_opt_rcvd.user_mss  = tp_sock->rx_opt.user_mss;
	tcp_parse_options(sock_net(sk), skb, &tmp_opt_rcvd, 0,
			  want_cookie ? NULL : &mptcp_foc);

	if (want_cookie && !tmp_opt_rcvd.saw_tstamp)
		tcp_clear_options(&tmp_opt_rcvd);

	if (IS_ENABLED(CONFIG_SMC) && want_cookie)
		tmp_opt_rcvd.smc_ok = 0;

	tmp_opt_rcvd.tstamp_ok = tmp_opt_rcvd.saw_tstamp;
	mptcp_openreq_init(req_sock, &tmp_opt_rcvd, skb, sk);
	inet_rsk(req_sock)->no_srccheck = inet_sk(sk)->transparent;

	inet_rsk(req_sock)->ir_iif = inet_request_bound_dev_if(sk, skb);

	dst = af_ops->route_req(sk, skb, &fl, req_sock);
	if (!dst)
		goto drop_and_free;

	if (tmp_opt_rcvd.tstamp_ok)
		tcp_rsk(req_sock)->ts_off = af_ops->init_ts_off(net, skb);

	if (!want_cookie && !isn) {
		if (!net->ipv4.sysctl_tcp_syncookies &&
		    (net->ipv4.sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk) <
		     (net->ipv4.sysctl_max_syn_backlog >> 2)) &&
		    !tcp_peer_is_proven(req_sock, dst)) {
			goto drop_and_release;
		}

		isn = af_ops->init_seq(skb);
	}

	mptcp_ecn_create_request(req_sock, skb, sk, dst);

	if (want_cookie) {
		isn = cookie_init_sequence(af_ops, sk, skb, &req_sock->mss);
		if (!tmp_opt_rcvd.tstamp_ok)
			inet_rsk(req_sock)->ecn_ok = 0;
	}

	tcp_rsk(req_sock)->snt_isn = isn;
	tcp_rsk(req_sock)->txhash = net_tx_rndhash();
	tcp_rsk(req_sock)->syn_tos = TCP_SKB_CB(skb)->ip_dsfield;

	tcp_openreq_init_rwin(req_sock, sk, dst);
	sk_rx_queue_set(req_to_sk(req_sock), skb);
	if (!want_cookie) {
		mptcp_reqsk_record_syn(sk, req_sock, skb);
		mptcp_fo_sk = mptcp_try_fastopen(sk, skb, req_sock, &mptcp_foc, dst);
	}
	if (mptcp_fo_sk) {
		af_ops->send_synack(mptcp_fo_sk, dst, &fl, req_sock,
				    &mptcp_foc, TCP_SYNACK_FASTOPEN, skb);
		if (!inet_csk_reqsk_queue_add(sk, req_sock, mptcp_fo_sk)) {
			reqsk_fastopen_remove(mptcp_fo_sk, req_sock, false);
			bh_unlock_sock(mptcp_fo_sk);
			sock_put(mptcp_fo_sk);
			goto drop_and_free;
		}
		sk->sk_data_ready(sk);
		bh_unlock_sock(mptcp_fo_sk);
		sock_put(mptcp_fo_sk);


	} else {
		tcp_rsk(req_sock)->tfo_listener = false;
		if (!want_cookie) {
			req_sock->timeout = tcp_timeout_init((struct sock *)req_sock);
			inet_csk_reqsk_queue_hash_add(sk, req_sock, req_sock->timeout);
		}
		af_ops->send_synack(sk, dst, &fl, req_sock, &mptcp_foc,
				    !want_cookie ? TCP_SYNACK_NORMAL :
						   TCP_SYNACK_COOKIE,
				    skb);
		if (want_cookie) {
			reqsk_free(req_sock);
			return 0;
		}
	}
	reqsk_put(req_sock);
	return 0;

drop_and_release:
	dst_release(dst);
drop_and_free:
	__reqsk_free(req_sock);
drop:
	tcp_listendrop(sk);
	return 0;
}
