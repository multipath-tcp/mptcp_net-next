// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include "protocol.h"

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct tcp_options_received *opt_rx)
{
	struct mptcp_options_received *mp_opt = &opt_rx->mptcp;
	u8 subtype = *ptr >> 4;
	int expected_opsize;

	switch (subtype) {
	/* MPTCPOPT_MP_CAPABLE
	 * 0: 4MSB=subtype, 4LSB=version
	 * 1: Handshake flags
	 * 2-9: Sender key
	 * 10-17: Receiver key (optional)
	 */
	case MPTCPOPT_MP_CAPABLE:
		if (opsize != TCPOLEN_MPTCP_MPC_SYN &&
		    opsize != TCPOLEN_MPTCP_MPC_SYNACK)
			break;

		mp_opt->version = *ptr++ & MPTCP_VERSION_MASK;
		if (mp_opt->version != 0)
			break;

		mp_opt->flags = *ptr++;
		if (!((mp_opt->flags & MPTCP_CAP_FLAG_MASK) == MPTCP_CAP_HMAC_SHA1) ||
		    (mp_opt->flags & MPTCP_CAP_EXTENSIBILITY))
			break;

		/* RFC 6824, Section 3.1:
		 * "For the Checksum Required bit (labeled "A"), if either
		 * host requires the use of checksums, checksums MUST be used.
		 * In other words, the only way for checksums not to be used
		 * is if both hosts in their SYNs set A=0."
		 *
		 * Section 3.3.0:
		 * "If a checksum is not present when its use has been
		 * negotiated, the receiver MUST close the subflow with a RST as
		 * it is considered broken."
		 *
		 * We don't implement DSS checksum - fall back to TCP.
		 */
		if (mp_opt->flags & MPTCP_CAP_CHECKSUM_REQD)
			break;

		mp_opt->mp_capable = 1;
		mp_opt->sndr_key = get_unaligned_be64(ptr);
		ptr += 8;

		if (opsize == TCPOLEN_MPTCP_MPC_SYNACK) {
			mp_opt->rcvr_key = get_unaligned_be64(ptr);
			ptr += 8;
			pr_debug("MP_CAPABLE flags=%x, sndr=%llu, rcvr=%llu",
				 mp_opt->flags, mp_opt->sndr_key,
				 mp_opt->rcvr_key);
		} else {
			pr_debug("MP_CAPABLE flags=%x, sndr=%llu",
				 mp_opt->flags, mp_opt->sndr_key);
		}
		break;

	/* MPTCPOPT_MP_JOIN
	 * Initial SYN
	 * 0: 4MSB=subtype, 000, 1LSB=Backup
	 * 1: Address ID
	 * 2-5: Receiver token
	 * 6-9: Sender random number
	 * SYN/ACK response
	 * 0: 4MSB=subtype, 000, 1LSB=Backup
	 * 1: Address ID
	 * 2-9: Sender truncated HMAC
	 * 10-13: Sender random number
	 * Third ACK
	 * 0: 4MSB=subtype, 0000
	 * 1: 0 (Reserved)
	 * 2-21: Sender HMAC
	 */
	case MPTCPOPT_MP_JOIN:
		mp_opt->mp_join = 1;
		if (opsize == TCPOLEN_MPTCP_MPJ_SYN) {
			mp_opt->backup = *ptr++ & MPTCPOPT_BACKUP;
			mp_opt->join_id = *ptr++;
			mp_opt->token = get_unaligned_be32(ptr);
			ptr += 4;
			mp_opt->nonce = get_unaligned_be32(ptr);
			ptr += 4;
			pr_debug("MP_JOIN bkup=%u, id=%u, token=%u, nonce=%u",
				 mp_opt->backup, mp_opt->join_id,
				 mp_opt->token, mp_opt->nonce);
		} else if (opsize == TCPOLEN_MPTCP_MPJ_SYNACK) {
			mp_opt->backup = *ptr++ & MPTCPOPT_BACKUP;
			mp_opt->join_id = *ptr++;
			mp_opt->thmac = get_unaligned_be64(ptr);
			ptr += 8;
			mp_opt->nonce = get_unaligned_be32(ptr);
			ptr += 4;
			pr_debug("MP_JOIN bkup=%u, id=%u, thmac=%llu, nonce=%u",
				 mp_opt->backup, mp_opt->join_id,
				 mp_opt->thmac, mp_opt->nonce);
		} else if (opsize == TCPOLEN_MPTCP_MPJ_ACK) {
			ptr += 2;
			memcpy(mp_opt->hmac, ptr, MPTCPOPT_HMAC_LEN);
			pr_debug("MP_JOIN hmac");
		} else {
			pr_warn("MP_JOIN bad option size");
			mp_opt->mp_join = 0;
		}
		break;


	/* MPTCPOPT_DSS
	 * 0: 4MSB=subtype, 0000
	 * 1: 3MSB=0, F=Data FIN, m=DSN length, M=has DSN/SSN/DLL/checksum,
	 *    a=DACK length, A=has DACK
	 * 0, 4, or 8 bytes of DACK (depending on A/a)
	 * 0, 4, or 8 bytes of DSN (depending on M/m)
	 * 0 or 4 bytes of SSN (depending on M)
	 * 0 or 2 bytes of DLL (depending on M)
	 * 0 or 2 bytes of checksum (depending on M)
	 */
	case MPTCPOPT_DSS:
		pr_debug("DSS");
		ptr++;

		mp_opt->dss_flags = (*ptr++) & MPTCP_DSS_FLAG_MASK;
		mp_opt->data_fin = (mp_opt->dss_flags & MPTCP_DSS_DATA_FIN) != 0;
		mp_opt->dsn64 = (mp_opt->dss_flags & MPTCP_DSS_DSN64) != 0;
		mp_opt->use_map = (mp_opt->dss_flags & MPTCP_DSS_HAS_MAP) != 0;
		mp_opt->ack64 = (mp_opt->dss_flags & MPTCP_DSS_ACK64) != 0;
		mp_opt->use_ack = (mp_opt->dss_flags & MPTCP_DSS_HAS_ACK);

		pr_debug("data_fin=%d dsn64=%d use_map=%d ack64=%d use_ack=%d",
			 mp_opt->data_fin, mp_opt->dsn64,
			 mp_opt->use_map, mp_opt->ack64,
			 mp_opt->use_ack);

		expected_opsize = TCPOLEN_MPTCP_DSS_BASE;

		if (mp_opt->use_ack) {
			if (mp_opt->ack64)
				expected_opsize += TCPOLEN_MPTCP_DSS_ACK64;
			else
				expected_opsize += TCPOLEN_MPTCP_DSS_ACK32;
		}

		if (mp_opt->use_map) {
			if (mp_opt->dsn64)
				expected_opsize += TCPOLEN_MPTCP_DSS_MAP64;
			else
				expected_opsize += TCPOLEN_MPTCP_DSS_MAP32;
		}

		/* RFC 6824, Section 3.3:
		 * If a checksum is present, but its use had
		 * not been negotiated in the MP_CAPABLE handshake,
		 * the checksum field MUST be ignored.
		 */
		if (opsize != expected_opsize &&
		    opsize != expected_opsize + TCPOLEN_MPTCP_DSS_CHECKSUM)
			break;

		mp_opt->dss = 1;

		if (mp_opt->use_ack) {
			if (mp_opt->ack64) {
				mp_opt->data_ack = get_unaligned_be64(ptr);
				ptr += 8;
			} else {
				mp_opt->data_ack = get_unaligned_be32(ptr);
				ptr += 4;
			}

			pr_debug("data_ack=%llu", mp_opt->data_ack);
		}

		if (mp_opt->use_map) {
			if (mp_opt->dsn64) {
				mp_opt->data_seq = get_unaligned_be64(ptr);
				ptr += 8;
			} else {
				mp_opt->data_seq = get_unaligned_be32(ptr);
				ptr += 4;
			}

			mp_opt->subflow_seq = get_unaligned_be32(ptr);
			ptr += 4;

			mp_opt->data_len = get_unaligned_be16(ptr);
			ptr += 2;

			pr_debug("data_seq=%llu subflow_seq=%u data_len=%u",
				 mp_opt->data_seq, mp_opt->subflow_seq,
				 mp_opt->data_len);
		}

		break;

	/* MPTCPOPT_ADD_ADDR
	 * 0: 4MSB=subtype, 4LSB=IP version (4 or 6)
	 * 1: Address ID
	 * 4 or 16 bytes of address (depending on ip version)
	 * 0 or 2 bytes of port (depending on length)
	 */
	case MPTCPOPT_ADD_ADDR:
		if (opsize != TCPOLEN_MPTCP_ADD_ADDR &&
		    opsize != TCPOLEN_MPTCP_ADD_ADDR6)
			break;
		mp_opt->family = *ptr++ & MPTCP_ADDR_FAMILY_MASK;
		if (mp_opt->family != MPTCP_ADDR_IPVERSION_4 &&
		    mp_opt->family != MPTCP_ADDR_IPVERSION_6)
			break;

		if (mp_opt->family == MPTCP_ADDR_IPVERSION_4 &&
		    opsize != TCPOLEN_MPTCP_ADD_ADDR)
			break;
#if IS_ENABLED(CONFIG_IPV6)
		if (mp_opt->family == MPTCP_ADDR_IPVERSION_6 &&
		    opsize != TCPOLEN_MPTCP_ADD_ADDR6)
			break;
#endif
		mp_opt->addr_id = *ptr++;
		if (mp_opt->family == MPTCP_ADDR_IPVERSION_4) {
			mp_opt->add_addr = 1;
			memcpy((u8 *)&mp_opt->addr.s_addr, (u8 *)ptr, 4);
			pr_debug("ADD_ADDR: addr=%x, id=%d",
				 mp_opt->addr.s_addr, mp_opt->addr_id);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else {
			mp_opt->add_addr = 1;
			memcpy(mp_opt->addr6.s6_addr, (u8 *)ptr, 16);
			pr_debug("ADD_ADDR: addr6=, id=%d", mp_opt->addr_id);
		}
#endif
		break;

	/* MPTCPOPT_RM_ADDR
	 * 0: 4MSB=subtype, 0000
	 * 1: Address ID
	 * Additional bytes: More address IDs (depending on length)
	 */
	case MPTCPOPT_RM_ADDR:
		if (opsize != TCPOLEN_MPTCP_RM_ADDR)
			break;

		mp_opt->rm_addr = 1;
		mp_opt->addr_id = *ptr++;
		pr_debug("RM_ADDR: id=%d", mp_opt->addr_id);
		break;

	/* MPTCPOPT_MP_PRIO
	 * 0: 4MSB=subtype, 000, 1LSB=Backup
	 * 1: Address ID (optional, current addr implied if not present)
	 */

	/* MPTCPOPT_MP_FAIL
	 * 0: 4MSB=subtype, 0000
	 * 1: 0 (Reserved)
	 * 2-9: DSN
	 */

	/* MPTCPOPT_MP_FASTCLOSE
	 * 0: 4MSB=subtype, 0000
	 * 1: 0 (Reserved)
	 * 2-9: Receiver key
	 */
	default:
		break;
	}
}

void mptcp_get_options(const struct sk_buff *skb,
		       struct tcp_options_received *opt_rx)
{
	const unsigned char *ptr;
	const struct tcphdr *th = tcp_hdr(skb);
	int length = (th->doff * 4) - sizeof(struct tcphdr);

	ptr = (const unsigned char *)(th + 1);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			if (opcode == TCPOPT_MPTCP)
				mptcp_parse_option(ptr, opsize, opt_rx);
			ptr += opsize - 2;
			length -= opsize;
		}
	}
}

bool mptcp_syn_options(struct sock *sk, unsigned int *size,
		       struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

	if (subflow->request_mptcp) {
		pr_debug("local_key=%llu", subflow->local_key);
		opts->suboptions = OPTION_MPTCP_MPC_SYN;
		opts->sndr_key = subflow->local_key;
		*size = TCPOLEN_MPTCP_MPC_SYN;
		return true;
	} else if (subflow->request_join) {
		pr_debug("remote_token=%u, nonce=%u", subflow->remote_token,
			 subflow->local_nonce);
		opts->suboptions = OPTION_MPTCP_MPJ_SYN;
		opts->join_id = subflow->remote_id;
		opts->token = subflow->remote_token;
		opts->nonce = subflow->local_nonce;
		opts->backup = subflow->request_bkup;
		*size = TCPOLEN_MPTCP_MPJ_SYN;
		return true;
	}
	return false;
}

void mptcp_rcv_synsent(struct sock *sk)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (subflow->request_mptcp && tp->rx_opt.mptcp.mp_capable) {
		subflow->mp_capable = 1;
		subflow->remote_key = tp->rx_opt.mptcp.sndr_key;
		pr_debug("subflow=%p, remote_key=%llu", subflow,
			 subflow->remote_key);
	} else if (subflow->request_join && tp->rx_opt.mptcp.mp_join) {
		subflow->mp_join = 1;
		subflow->thmac = tp->rx_opt.mptcp.thmac;
		subflow->remote_nonce = tp->rx_opt.mptcp.nonce;
		pr_debug("subflow=%p, thmac=%llu, remote_nonce=%u", subflow,
			 subflow->thmac, subflow->remote_nonce);
	}
}

static bool mptcp_established_options_mp(struct sock *sk, unsigned int *size,
					 unsigned int remaining,
					 struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);

	if (subflow->mp_capable && !subflow->fourth_ack &&
	    remaining >= TCPOLEN_MPTCP_MPC_ACK) {
		opts->suboptions = OPTION_MPTCP_MPC_ACK;
		opts->sndr_key = subflow->local_key;
		opts->rcvr_key = subflow->remote_key;
		*size = TCPOLEN_MPTCP_MPC_ACK;
		subflow->fourth_ack = 1;
		pr_debug("subflow=%p, local_key=%llu, remote_key=%llu",
			 subflow, subflow->local_key, subflow->remote_key);
		return true;
	} else if (subflow->mp_join && !subflow->fourth_ack &&
		   remaining >= TCPOLEN_MPTCP_MPJ_ACK) {
		opts->suboptions = OPTION_MPTCP_MPJ_ACK;
		memcpy(opts->hmac, subflow->hmac, MPTCPOPT_HMAC_LEN);
		*size = TCPOLEN_MPTCP_MPJ_ACK;
		subflow->fourth_ack = 1;
		pr_debug("subflow=%p", subflow);
		return true;
	}
	return false;
}

static bool mptcp_established_options_dss(struct sock *sk, struct sk_buff *skb,
					  unsigned int *size,
					  unsigned int remaining,
					  struct mptcp_out_options *opts)
{
	unsigned int dss_size = 0;
	struct mptcp_ext *mpext;
	unsigned int ack_size;

	mpext = skb ? mptcp_get_ext(skb) : NULL;

	if (!skb || (mpext && mpext->use_map)) {
		unsigned int map_size;

		map_size = TCPOLEN_MPTCP_DSS_BASE + TCPOLEN_MPTCP_DSS_MAP64;

		if (map_size <= remaining) {
			remaining -= map_size;
			dss_size = map_size;
			if (mpext)
				opts->ext_copy = *mpext;
		} else {
			opts->ext_copy.use_map = 0;
			WARN_ONCE(1, "MPTCP: Map dropped");
		}
	}

	ack_size = TCPOLEN_MPTCP_DSS_ACK64;

	/* Add kind/length/subtype/flag overhead if mapping is not populated */
	if (dss_size == 0)
		ack_size += TCPOLEN_MPTCP_DSS_BASE;

	if (ack_size <= remaining) {
		struct mptcp_sock *msk;

		dss_size += ack_size;

		msk = mptcp_sk(mptcp_subflow_ctx(sk)->conn);
		if (msk) {
			opts->ext_copy.data_ack = msk->ack_seq;
		} else {
			mptcp_crypto_key_sha1(mptcp_subflow_ctx(sk)->remote_key,
					      NULL, &opts->ext_copy.data_ack);
			opts->ext_copy.data_ack++;
		}

		opts->ext_copy.ack64 = 1;
		opts->ext_copy.use_ack = 1;
	} else {
		opts->ext_copy.use_ack = 0;
		WARN(1, "MPTCP: Ack dropped");
	}

	if (!dss_size)
		return false;

	*size = ALIGN(dss_size, 4);
	return true;
}

static bool mptcp_established_options_addr(struct sock *sk,
					   unsigned int *size,
					   unsigned int remaining,
					   struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);
	struct sockaddr_storage saddr;
	u8 id;

	if (!msk)
		return false;

	if (!msk->pm.fully_established || !msk->addr_signal)
		return false;

	if (mptcp_pm_addr_signal(msk, &id, &saddr))
		return false;

	if (saddr.ss_family == AF_INET) {
		if (remaining < TCPOLEN_MPTCP_ADD_ADDR)
			return false;
		opts->suboptions |= OPTION_MPTCP_ADD_ADDR;
		opts->addr_id = id;
		opts->addr = ((struct sockaddr_in *)&saddr)->sin_addr;
		*size = TCPOLEN_MPTCP_ADD_ADDR;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (saddr.ss_family == AF_INET6) {
		if (remaining < TCPOLEN_MPTCP_ADD_ADDR6)
			return false;
		opts->suboptions |= OPTION_MPTCP_ADD_ADDR6;
		opts->addr_id = id;
		opts->addr6 = ((struct sockaddr_in6 *)&saddr)->sin6_addr;
		*size = TCPOLEN_MPTCP_ADD_ADDR6;
	}
#endif

	msk->addr_signal = 0;

	return true;
}

bool mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct mptcp_out_options *opts)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	unsigned int opt_size = 0;
	bool ret = false;

	if (!subflow->mp_capable && !subflow->mp_join)
		return false;

	opts->suboptions = 0;
	if (mptcp_established_options_mp(sk, &opt_size, remaining, opts)) {
		*size += opt_size;
		remaining -= opt_size;
		ret = true;
	} else if (mptcp_established_options_dss(sk, skb, &opt_size, remaining,
						 opts)) {
		*size += opt_size;
		remaining -= opt_size;
		ret = true;
	}
	if (mptcp_established_options_addr(sk, &opt_size, remaining, opts)) {
		*size += opt_size;
		remaining -= opt_size;
		ret = true;
	}
	return ret;
}

bool mptcp_synack_options(const struct request_sock *req, unsigned int *size,
			  struct mptcp_out_options *opts)
{
	struct mptcp_subflow_request_sock *subflow_req = mptcp_subflow_rsk(req);

	if (subflow_req->mp_capable) {
		opts->suboptions = OPTION_MPTCP_MPC_SYNACK;
		opts->sndr_key = subflow_req->local_key;
		opts->rcvr_key = subflow_req->remote_key;
		*size = TCPOLEN_MPTCP_MPC_SYNACK;
		pr_debug("req=%p, local_key=%llu, remote_key=%llu",
			 subflow_req, subflow_req->local_key,
			 subflow_req->remote_key);
		return true;
	} else if (subflow_req->mp_join) {
		opts->suboptions = OPTION_MPTCP_MPJ_SYNACK;
		opts->backup = subflow_req->backup;
		opts->join_id = subflow_req->local_id;
		opts->thmac = subflow_req->thmac;
		opts->nonce = subflow_req->local_nonce;
		pr_debug("req=%p, bkup=%u, id=%u, thmac=%llu, nonce=%u",
			 subflow_req, opts->backup, opts->join_id,
			 opts->thmac, opts->nonce);
		*size = TCPOLEN_MPTCP_MPJ_SYNACK;
		return true;
	}
	return false;
}

static u64 expand_ack(u64 old_ack, u64 cur_ack, bool use_64bit)
{
	u32 old_ack32, cur_ack32;

	if (use_64bit)
		return cur_ack;

	old_ack32 = (u32)old_ack;
	cur_ack32 = (u32)cur_ack;
	cur_ack = (old_ack & GENMASK_ULL(63, 32)) + cur_ack32;
	if (unlikely(before(cur_ack32, old_ack32)))
		return cur_ack + (1LL << 32);
	return cur_ack;
}

static void update_una(struct mptcp_sock *msk,
		       struct mptcp_options_received *mp_opt)
{
	u64 new_snd_una, snd_una, old_snd_una = atomic64_read(&msk->snd_una);
	u64 write_seq = READ_ONCE(msk->write_seq);

	/* avoid ack expansion on update conflict, to reduce the risk of
	 * wrongly expanding to a future ack sequence number, which is way
	 * more dangerous than missing an ack
	 */
	new_snd_una = expand_ack(old_snd_una, mp_opt->data_ack, mp_opt->ack64);

	/* ACK for data not even sent yet? Ignore. */
	if (after64(new_snd_una, write_seq))
		new_snd_una = old_snd_una;

	while (after64(new_snd_una, old_snd_una)) {
		snd_una = old_snd_una;
		old_snd_una = atomic64_cmpxchg(&msk->snd_una, snd_una,
					       new_snd_una);
		if (old_snd_una == snd_una) {
			mptcp_reset_timer((struct sock *)msk);
			break;
		}
	}
}

void mptcp_incoming_options(struct sock *sk, struct sk_buff *skb,
			    struct tcp_options_received *opt_rx)
{
	struct mptcp_subflow_context *subflow = mptcp_subflow_ctx(sk);
	struct mptcp_sock *msk = mptcp_sk(subflow->conn);
	struct mptcp_options_received *mp_opt;
	struct mptcp_ext *mpext;

	if (!subflow->mp_capable && !subflow->mp_join)
		return;

	mp_opt = &opt_rx->mptcp;

	if (msk && mp_opt->add_addr) {
		if (mp_opt->family == MPTCP_ADDR_IPVERSION_4)
			mptcp_pm_add_addr(msk, &mp_opt->addr, mp_opt->addr_id);
#if IS_ENABLED(CONFIG_IPV6)
		else if (mp_opt->family == MPTCP_ADDR_IPVERSION_6)
			mptcp_pm_add_addr6(msk, &mp_opt->addr6,
					   mp_opt->addr_id);
#endif
		mp_opt->add_addr = 0;
	}

	if (!mp_opt->dss)
		return;

	/* we can't wait for recvmsg() to update the ack_seq, otherwise
	 * monodirectional flows will stuck
	 */
	if (msk && mp_opt->use_ack)
		update_una(msk, mp_opt);

	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);
	if (!mpext)
		return;

	memset(mpext, 0, sizeof(*mpext));

	if (mp_opt->use_map) {
		mpext->data_seq = mp_opt->data_seq;
		mpext->subflow_seq = mp_opt->subflow_seq;
		mpext->data_len = mp_opt->data_len;
		mpext->use_map = 1;
		mpext->dsn64 = mp_opt->dsn64;
	}

	mpext->data_fin = mp_opt->data_fin;

	if (msk)
		mptcp_pm_fully_established(msk);
}

void mptcp_write_options(__be32 *ptr, struct mptcp_out_options *opts)
{
	if ((OPTION_MPTCP_MPC_SYN |
	     OPTION_MPTCP_MPC_SYNACK |
	     OPTION_MPTCP_MPC_ACK) & opts->suboptions) {
		u8 len;

		if (OPTION_MPTCP_MPC_SYN & opts->suboptions)
			len = TCPOLEN_MPTCP_MPC_SYN;
		else if (OPTION_MPTCP_MPC_SYNACK & opts->suboptions)
			len = TCPOLEN_MPTCP_MPC_SYNACK;
		else
			len = TCPOLEN_MPTCP_MPC_ACK;

		*ptr++ = mptcp_option(MPTCPOPT_MP_CAPABLE, len, 0,
				      MPTCP_CAP_HMAC_SHA1);
		put_unaligned_be64(opts->sndr_key, ptr);
		ptr += 2;
		if ((OPTION_MPTCP_MPC_SYNACK |
		     OPTION_MPTCP_MPC_ACK) & opts->suboptions) {
			put_unaligned_be64(opts->rcvr_key, ptr);
			ptr += 2;
		}
	}

	if (OPTION_MPTCP_ADD_ADDR & opts->suboptions) {
		*ptr++ = mptcp_option(MPTCPOPT_ADD_ADDR, TCPOLEN_MPTCP_ADD_ADDR,
				      MPTCP_ADDR_IPVERSION_4, opts->addr_id);
		memcpy((u8 *)ptr, (u8 *)&opts->addr.s_addr, 4);
		ptr += 1;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (OPTION_MPTCP_ADD_ADDR6 & opts->suboptions) {
		*ptr++ = mptcp_option(MPTCPOPT_ADD_ADDR,
				      TCPOLEN_MPTCP_ADD_ADDR6,
				      MPTCP_ADDR_IPVERSION_6, opts->addr_id);
		memcpy((u8 *)ptr, opts->addr6.s6_addr, 16);
		ptr += 4;
	}
#endif

	if (OPTION_MPTCP_RM_ADDR & opts->suboptions) {
		*ptr++ = mptcp_option(MPTCPOPT_RM_ADDR, TCPOLEN_MPTCP_RM_ADDR,
				      0, opts->addr_id);
	}

	if (OPTION_MPTCP_MPJ_SYN & opts->suboptions) {
		*ptr++ = mptcp_option(MPTCPOPT_MP_JOIN,
				      TCPOLEN_MPTCP_MPJ_SYN,
				      opts->backup, opts->join_id);
		put_unaligned_be32(opts->token, ptr);
		ptr += 1;
		put_unaligned_be32(opts->nonce, ptr);
		ptr += 1;
	}

	if (OPTION_MPTCP_MPJ_SYNACK & opts->suboptions) {
		*ptr++ = mptcp_option(MPTCPOPT_MP_JOIN,
				      TCPOLEN_MPTCP_MPJ_SYNACK,
				      opts->backup, opts->join_id);
		put_unaligned_be64(opts->thmac, ptr);
		ptr += 2;
		put_unaligned_be32(opts->nonce, ptr);
		ptr += 1;
	}

	if (OPTION_MPTCP_MPJ_ACK & opts->suboptions) {
		*ptr++ = mptcp_option(MPTCPOPT_MP_JOIN,
				      TCPOLEN_MPTCP_MPJ_ACK, 0, 0);
		memcpy(ptr, opts->hmac, MPTCPOPT_HMAC_LEN);
		ptr += 5;
	}

	if (opts->ext_copy.use_ack || opts->ext_copy.use_map) {
		struct mptcp_ext *mpext = &opts->ext_copy;
		u8 len = TCPOLEN_MPTCP_DSS_BASE;
		u8 flags = 0;

		if (mpext->use_ack) {
			len += TCPOLEN_MPTCP_DSS_ACK64;
			flags = MPTCP_DSS_HAS_ACK | MPTCP_DSS_ACK64;
		}

		if (mpext->use_map) {
			len += TCPOLEN_MPTCP_DSS_MAP64;

			/* Use only 64-bit mapping flags for now, add
			 * support for optional 32-bit mappings later.
			 */
			flags |= MPTCP_DSS_HAS_MAP | MPTCP_DSS_DSN64;
			if (mpext->data_fin)
				flags |= MPTCP_DSS_DATA_FIN;
		}

		*ptr++ = mptcp_option(MPTCPOPT_DSS, len, 0, flags);

		if (mpext->use_ack) {
			put_unaligned_be64(mpext->data_ack, ptr);
			ptr += 2;
		}

		if (mpext->use_map) {
			put_unaligned_be64(mpext->data_seq, ptr);
			ptr += 2;
			put_unaligned_be32(mpext->subflow_seq, ptr);
			ptr += 1;
			put_unaligned_be32(mpext->data_len << 16 |
					   TCPOPT_NOP << 8 | TCPOPT_NOP, ptr);
		}
	}
}
