/* SPDX-License-Identifier: GPL-2.0 */
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __MPTCP_PROTOCOL_H
#define __MPTCP_PROTOCOL_H

#include <linux/spinlock.h>

/* MPTCP option subtypes */
#define MPTCPOPT_MP_CAPABLE	0
#define MPTCPOPT_MP_JOIN	1
#define MPTCPOPT_DSS		2
#define MPTCPOPT_ADD_ADDR	3
#define MPTCPOPT_RM_ADDR	4
#define MPTCPOPT_MP_PRIO	5
#define MPTCPOPT_MP_FAIL	6
#define MPTCPOPT_MP_FASTCLOSE	7

/* MPTCP suboption lengths */
#define TCPOLEN_MPTCP_MPC_SYN		12
#define TCPOLEN_MPTCP_MPC_SYNACK	20
#define TCPOLEN_MPTCP_MPC_ACK		20
#define TCPOLEN_MPTCP_MPJ_SYN		12
#define TCPOLEN_MPTCP_MPJ_SYNACK	16
#define TCPOLEN_MPTCP_MPJ_ACK		24
#define TCPOLEN_MPTCP_DSS_BASE		4
#define TCPOLEN_MPTCP_DSS_ACK32		4
#define TCPOLEN_MPTCP_DSS_ACK64		8
#define TCPOLEN_MPTCP_DSS_MAP32		10
#define TCPOLEN_MPTCP_DSS_MAP64		14
#define TCPOLEN_MPTCP_DSS_CHECKSUM	2
#define TCPOLEN_MPTCP_ADD_ADDR		8
#define TCPOLEN_MPTCP_ADD_ADDR6		20
#define TCPOLEN_MPTCP_RM_ADDR		4

#define MPTCPOPT_BACKUP		BIT(0)
#define MPTCPOPT_HMAC_LEN	20

/* MPTCP MP_CAPABLE flags */
#define MPTCP_VERSION_MASK	(0x0F)
#define MPTCP_CAP_CHECKSUM_REQD	BIT(7)
#define MPTCP_CAP_EXTENSIBILITY	BIT(6)
#define MPTCP_CAP_HMAC_SHA1	BIT(0)
#define MPTCP_CAP_FLAG_MASK	(0x3F)

/* MPTCP DSS flags */
#define MPTCP_DSS_DATA_FIN	BIT(4)
#define MPTCP_DSS_DSN64		BIT(3)
#define MPTCP_DSS_HAS_MAP	BIT(2)
#define MPTCP_DSS_ACK64		BIT(1)
#define MPTCP_DSS_HAS_ACK	BIT(0)
#define MPTCP_DSS_FLAG_MASK	(0x1F)

/* MPTCP ADD_ADDR flags */
#define MPTCP_ADDR_FAMILY_MASK	(0x0F)
#define MPTCP_ADDR_IPVERSION_4	4
#define MPTCP_ADDR_IPVERSION_6	6

struct pm_data {
	u8 addr_id;
	sa_family_t family;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
};

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct inet_connection_sock sk;
	u64		local_key;
	u64		remote_key;
	u64		write_seq;
	u64		ack_seq;
	u32		token;
	struct list_head conn_list;
	struct socket	*subflow; /* outgoing connect/listener/!mp_capable */
	struct pm_data	pm;
	u8		addr_signal;
};

#define mptcp_for_each_subflow(__msk, __subflow)			\
	list_for_each_entry(__subflow, &((__msk)->conn_list), node)

static inline struct mptcp_sock *mptcp_sk(const struct sock *sk)
{
	return (struct mptcp_sock *)sk;
}

struct subflow_request_sock {
	struct	tcp_request_sock sk;
	u8	mp_capable : 1,
		mp_join : 1,
		checksum : 1,
		backup : 1,
		version : 4;
	u8	local_id;
	u8	remote_id;
	u64	local_key;
	u64	remote_key;
	u64	idsn;
	u32	token;
	u32	ssn_offset;
	u64	thmac;
	u32	local_nonce;
	u32	remote_nonce;
};

static inline
struct subflow_request_sock *subflow_rsk(const struct request_sock *rsk)
{
	return (struct subflow_request_sock *)rsk;
}

/* MPTCP subflow context */
struct subflow_context {
	struct	list_head node;/* conn_list of subflows */
	u64	local_key;
	u64	remote_key;
	u32	token;
	u32     rel_write_seq;
	u64     idsn;
	u64	map_seq;
	u32	map_subflow_seq;
	u32	ssn_offset;
	u16	map_data_len;
	u16	request_mptcp : 1,  /* send MP_CAPABLE */
		request_cksum : 1,
		mp_capable : 1,     /* remote is MPTCP capable */
		mp_join : 1,        /* remote is JOINing */
		fourth_ack : 1,     /* send initial DSS */
		version : 4,
		conn_finished : 1,
		use_checksum : 1,
		map_valid : 1,
		backup : 1;
	u32	remote_nonce;
	u64	thmac;
	u32	local_nonce;
	u8	local_id;
	u8	remote_id;

	struct  socket *tcp_sock;  /* underlying tcp_sock */
	struct  sock *conn;        /* parent mptcp_sock */

	void	(*tcp_sk_data_ready)(struct sock *sk);
};

static inline struct subflow_context *subflow_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return (struct subflow_context *)icsk->icsk_ulp_data;
}

static inline struct socket *
mptcp_subflow_tcp_socket(const struct subflow_context *subflow)
{
	return subflow->tcp_sock;
}

void subflow_init(void);

extern const struct inet_connection_sock_af_ops ipv4_specific;

void mptcp_get_options(const struct sk_buff *skb,
		       struct tcp_options_received *opt_rx);

void mptcp_finish_connect(struct sock *sk, int mp_capable);
void mptcp_finish_join(struct sock *conn, struct sock *sk);

void token_init(void);
void token_new_request(struct request_sock *req, const struct sk_buff *skb);
int token_join_request(struct request_sock *req, const struct sk_buff *skb);
int token_join_valid(struct request_sock *req,
		     struct tcp_options_received *rx_opt);
void token_destroy_request(u32 token);
void token_new_connect(struct sock *sk);
void token_new_accept(struct sock *sk);
int token_new_join(struct sock *sk);
void token_update_accept(struct sock *sk, struct sock *conn);
void token_release(u32 token);
void token_destroy(u32 token);

void crypto_init(void);
u32 crypto_v4_get_nonce(__be32 saddr, __be32 daddr,
			__be16 sport, __be16 dport);
u64 crypto_v4_get_key(__be32 saddr, __be32 daddr,
		      __be16 sport, __be16 dport);
u64 crypto_v6_get_key(const struct in6_addr *saddr,
		      const struct in6_addr *daddr,
		      __be16 sport, __be16 dport);
u32 crypto_v6_get_nonce(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__be16 sport, __be16 dport);
void crypto_key_sha1(u64 key, u32 *token, u64 *idsn);
void crypto_hmac_sha1(u64 key1, u64 key2, u32 *hash_out,
		      int arg_num, ...);

void pm_new_connection(struct mptcp_sock *msk);
void pm_fully_established(struct mptcp_sock *msk);
void pm_connection_closed(struct mptcp_sock *msk);
void pm_subflow_established(struct mptcp_sock *msk, u8 id);
void pm_subflow_closed(struct mptcp_sock *msk, u8 id);
void pm_add_addr(struct mptcp_sock *msk, const struct in_addr *addr, u8 id);
void pm_add_addr6(struct mptcp_sock *msk, const struct in6_addr *addr, u8 id);
void pm_rm_addr(struct mptcp_sock *msk, u8 id);
bool pm_addr_signal(struct mptcp_sock *msk, unsigned int *size,
		    unsigned int remaining, struct mptcp_out_options *opts);

static inline struct mptcp_ext *mptcp_get_ext(struct sk_buff *skb)
{
	return (struct mptcp_ext *)skb_ext_find(skb, SKB_EXT_MPTCP);
}

#endif /* __MPTCP_PROTOCOL_H */
