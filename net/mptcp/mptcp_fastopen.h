/* SPDX-License-Identifier: GPL-2.0
 * MPTCP Fast Open Mechanism. Copyright (c) 2021-2022, Dmytro SHYTYI.
 */

#ifndef __MPTCP_FASTOPEN_H
#define __MPTCP_FASTOPEN_H

#include <uapi/linux/mptcp.h>
#include <net/mptcp.h>
#include <net/sock.h>
#include "protocol.h"

int mptcp_sendmsg_fastopen(struct sock *sk, struct msghdr *msg,
			   size_t len, struct mptcp_sock *msk,
			   size_t *copied);

void mptcp_reqsk_record_syn(const struct sock *sk,
			    struct request_sock *req,
			    const struct sk_buff *skb);

void mptcp_ecn_create_request(struct request_sock *req,
			      const struct sk_buff *skb,
			      const struct sock *listen_sk,
			      const struct dst_entry *dst);

void mptcp_openreq_init(struct request_sock *req,
			const struct tcp_options_received *rx_opt,
			struct sk_buff *skb, const struct sock *sk);

void mptcp_fastopen_add_skb(struct sock *sk, struct sk_buff *skb);

struct sock *mptcp_fastopen_create_child(struct sock *sk,
					 struct sk_buff *skb,
					 struct request_sock *req);

bool mptcp_fastopen_queue_check(struct sock *sk);

bool mptcp_fastopen_cookie_gen_cipher(struct request_sock *req,
				      struct sk_buff *syn,
				      const siphash_key_t *key,
				      struct tcp_fastopen_cookie *foc);

void mptcp_fastopen_cookie_gen(struct sock *sk,
			       struct request_sock *req,
			       struct sk_buff *syn,
			       struct tcp_fastopen_cookie *foc);

int mptcp_fastopen_cookie_gen_check(struct sock *sk,
				    struct request_sock *req,
				    struct sk_buff *syn,
				    struct tcp_fastopen_cookie *orig,
				    struct tcp_fastopen_cookie *valid_foc);

bool mptcp_fastopen_no_cookie(const struct sock *sk,
			      const struct dst_entry *dst,
			      int flag);

struct sock *mptcp_try_fastopen(struct sock *sk, struct sk_buff *skb,
				struct request_sock *req,
				struct tcp_fastopen_cookie *foc,
				const struct dst_entry *dst);

int mptcp_conn_request(struct request_sock_ops *rsk_ops,
		       const struct tcp_request_sock_ops *af_ops,
		       struct sock *sk, struct sk_buff *skb);

#endif /* __MPTCP_FASTOPEN_H */
