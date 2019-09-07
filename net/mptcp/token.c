// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP token management
 * Copyright (c) 2017 - 2019, Intel Corporation.
 *
 * Note: This code is based on mptcp_ctrl.c from multipath-tcp.org,
 *       authored by:
 *
 *       Sébastien Barré <sebastien.barre@uclouvain.be>
 *       Christoph Paasch <christoph.paasch@uclouvain.be>
 *       Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *       Gregory Detal <gregory.detal@uclouvain.be>
 *       Fabien Duchêne <fabien.duchene@uclouvain.be>
 *       Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *       Lavkesh Lahngir <lavkesh51@gmail.com>
 *       Andreas Ripke <ripke@neclab.eu>
 *       Vlad Dogaru <vlad.dogaru@intel.com>
 *       Octavian Purdila <octavian.purdila@intel.com>
 *       John Ronan <jronan@tssg.org>
 *       Catalin Nicutar <catalin.nicutar@gmail.com>
 *       Brandon Heller <brandonh@stanford.edu>
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/radix-tree.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/protocol.h>
#include <net/mptcp.h>
#include "protocol.h"

static RADIX_TREE(token_tree, GFP_ATOMIC);
static RADIX_TREE(token_req_tree, GFP_ATOMIC);
static DEFINE_SPINLOCK(token_tree_lock);
static int token_used __read_mostly;

static bool find_req_token(u32 token)
{
	void *used;

	pr_debug("token=%u", token);
	used = radix_tree_lookup(&token_req_tree, token);
	return used;
}

static bool find_token(u32 token)
{
	void *used;

	pr_debug("token=%u", token);
	used = radix_tree_lookup(&token_tree, token);
	return used;
}

static struct sock *__token_lookup(u32 token)
{
	void *conn;

	pr_debug("token=%u", token);
	conn = radix_tree_lookup(&token_tree, token);
	return (struct sock *)conn;
}

static void new_req_token(struct request_sock *req,
			  const struct sk_buff *skb)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);

	crypto_key_gen_sha1(&subflow_req->local_key, &subflow_req->token,
			    &subflow_req->idsn);
	pr_debug("local_key=%llu, token=%u, idsn=%llu", subflow_req->local_key,
		 subflow_req->token, subflow_req->idsn);
}

static void new_req_join(struct request_sock *req, struct sock *sk,
			 const struct sk_buff *skb)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct mptcp_sock *msk = mptcp_sk(sk);
	u8 hmac[MPTCPOPT_HMAC_LEN];

	get_random_bytes(&subflow_req->local_nonce, sizeof(u32));
	crypto_hmac_sha1(msk->local_key, msk->remote_key,
			 subflow_req->local_nonce, subflow_req->remote_nonce,
			 (u32 *)hmac);

	subflow_req->thmac = get_unaligned_be64(hmac);
	pr_debug("local_nonce=%u, thmac=%llu", subflow_req->local_nonce,
		 subflow_req->thmac);
}

static int new_rsp_join(struct sock *sk)
{
	struct subflow_context *subflow = subflow_ctx(sk);
	u8 hmac[MPTCPOPT_HMAC_LEN];
	u64 thmac;

	crypto_hmac_sha1(subflow->remote_key, subflow->local_key,
			 subflow->remote_nonce, subflow->local_nonce,
			 (u32 *)hmac);

	thmac = get_unaligned_be64(hmac);
	pr_debug("thmac=%llu", thmac);
	if (thmac != subflow->thmac)
		return -1;

	crypto_hmac_sha1(subflow->local_key, subflow->remote_key,
			 subflow->local_nonce, subflow->remote_nonce,
			 (u32 *)subflow->hmac);

	return 0;
}

static int new_join_valid(struct request_sock *req, struct sock *sk,
			  struct tcp_options_received *rx_opt)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct mptcp_sock *msk = mptcp_sk(sk);
	u8 hmac[MPTCPOPT_HMAC_LEN];

	crypto_hmac_sha1(msk->remote_key, msk->local_key,
			 subflow_req->remote_nonce, subflow_req->local_nonce,
			 (u32 *)hmac);

	return memcmp(hmac, (char *)rx_opt->mptcp.hmac, MPTCPOPT_HMAC_LEN);
}

static void new_token(const struct sock *sk)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	crypto_key_gen_sha1(&subflow->local_key, &subflow->token,
			    &subflow->idsn);
	pr_debug("local_key=%llu, token=%u, idsn=%llu", subflow->local_key,
		 subflow->token, subflow->idsn);
}

static int insert_req_token(u32 token)
{
	void *used = &token_used;

	pr_debug("token=%u", token);
	return radix_tree_insert(&token_req_tree, token, used);
}

static int insert_token(u32 token, void *conn)
{
	void *used = &token_used;

	if (conn)
		used = conn;

	pr_debug("token=%u, conn=%p", token, used);
	return radix_tree_insert(&token_tree, token, used);
}

static void update_token(u32 token, void *conn)
{
	void **slot;

	pr_debug("token=%u, conn=%p", token, conn);
	slot = radix_tree_lookup_slot(&token_tree, token);
	if (slot) {
		if (*slot != &token_used)
			pr_err("slot ALREADY updated!");
		*slot = conn;
	} else {
		pr_warn("token NOT FOUND!");
	}
}

static void destroy_req_token(u32 token)
{
	void *cur;

	cur = radix_tree_delete(&token_req_tree, token);
	if (!cur)
		pr_warn("token NOT FOUND!");
}

static struct sock *destroy_token(u32 token)
{
	void *conn;

	pr_debug("token=%u", token);
	conn = radix_tree_delete(&token_tree, token);
	if (conn && conn != &token_used)
		return (struct sock *)conn;
	return NULL;
}

/* create new local key, idsn, and token for subflow_request */
void token_new_request(struct request_sock *req,
		       const struct sk_buff *skb)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);

	pr_debug("subflow_req=%p", req);
	while (1) {
		new_req_token(req, skb);
		spin_lock_bh(&token_tree_lock);
		if (!find_req_token(subflow_req->token) &&
		    !find_token(subflow_req->token))
			break;
		spin_unlock_bh(&token_tree_lock);
	}
	insert_req_token(subflow_req->token);
	spin_unlock_bh(&token_tree_lock);
}

/* validate received token and create truncated hmac and nonce for SYN-ACK */
int token_join_request(struct request_sock *req, const struct sk_buff *skb)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct sock *conn;

	pr_debug("subflow_req=%p, token=%u", subflow_req, subflow_req->token);
	spin_lock_bh(&token_tree_lock);
	conn = __token_lookup(subflow_req->token);
	if (conn)
		sock_hold(conn);
	spin_unlock_bh(&token_tree_lock);

	if (!conn)
		return -1;

	if (pm_get_local_id(req, conn, skb)) {
		sock_put(conn);
		return -1;
	}

	new_req_join(req, conn, skb);

	sock_put(conn);
	return 0;
}

/* validate received truncated hmac and create hmac for third ACK */
int token_join_response(struct sock *sk)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	pr_debug("subflow=%p, token=%u", subflow, subflow->token);
	return new_rsp_join(sk);
}

/* validate hmac received in third ACK */
int token_join_valid(struct request_sock *req,
		     struct tcp_options_received *rx_opt)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);
	struct sock *conn;
	int err;

	pr_debug("subflow_req=%p, token=%u", subflow_req, subflow_req->token);
	spin_lock_bh(&token_tree_lock);
	conn = __token_lookup(subflow_req->token);
	if (conn)
		sock_hold(conn);
	spin_unlock_bh(&token_tree_lock);
	if (!conn)
		return -1;

	err = new_join_valid(req, conn, rx_opt);
	sock_put(conn);
	return err;
}

/* create new local key, idsn, and token for subflow */
void token_new_connect(struct sock *sk)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	pr_debug("subflow=%p", sk);

	while (1) {
		new_token(sk);
		spin_lock_bh(&token_tree_lock);
		if (!find_req_token(subflow->token) &&
		    !find_token(subflow->token))
			break;
		spin_unlock_bh(&token_tree_lock);
	}
	insert_token(subflow->token, subflow->conn);
	sock_hold(subflow->conn);
	spin_unlock_bh(&token_tree_lock);
}

/* take reference to connection and create nonce for secondary subflow */
void token_new_subflow(struct sock *sk)
{
	struct subflow_context *subflow = subflow_ctx(sk);
	struct sock *conn;

	pr_debug("subflow=%p", subflow);

	spin_lock_bh(&token_tree_lock);
	conn = __token_lookup(subflow->token);
	if (conn)
		sock_hold(conn);
	spin_unlock_bh(&token_tree_lock);

	get_random_bytes(&subflow->local_nonce, sizeof(u32));
}

void token_new_accept(struct sock *sk)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	pr_debug("subflow=%p", sk);

	spin_lock_bh(&token_tree_lock);
	insert_token(subflow->token, NULL);
	spin_unlock_bh(&token_tree_lock);
}

void token_update_accept(struct sock *sk, struct sock *conn)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	pr_debug("subflow=%p, conn=%p", sk, conn);

	spin_lock_bh(&token_tree_lock);
	update_token(subflow->token, conn);
	sock_hold(conn);
	spin_unlock_bh(&token_tree_lock);
}

int token_new_join(struct sock *sk)
{
	struct subflow_context *subflow = subflow_ctx(sk);
	struct sock *conn;

	spin_lock_bh(&token_tree_lock);
	conn = __token_lookup(subflow->token);
	if (conn)
		sock_hold(conn);
	spin_unlock_bh(&token_tree_lock);

	if (!conn)
		return -1;

	subflow->conn = conn;

	return 0;
}

struct sock *token_lookup_get(u32 token)
{
	struct sock *conn;

	spin_lock_bh(&token_tree_lock);
	conn = __token_lookup(token);
	if (conn)
		sock_hold(conn);
	spin_unlock_bh(&token_tree_lock);

	return conn;
}

void token_destroy_request(u32 token)
{
	pr_debug("token=%u", token);

	spin_lock_bh(&token_tree_lock);
	destroy_req_token(token);
	spin_unlock_bh(&token_tree_lock);
}

void token_release(u32 token)
{
	struct sock *conn;

	pr_debug("token=%u", token);
	spin_lock_bh(&token_tree_lock);
	conn = __token_lookup(token);
	if (conn)
		sock_put(conn);
	spin_unlock_bh(&token_tree_lock);
}

void token_destroy(u32 token)
{
	struct sock *conn;

	pr_debug("token=%u", token);
	spin_lock_bh(&token_tree_lock);
	conn = destroy_token(token);
	if (conn)
		sock_put(conn);
	spin_unlock_bh(&token_tree_lock);
}
