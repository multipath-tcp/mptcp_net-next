// SPDX-License-Identifier: GPL-2.0
/*
 * Multipath TCP
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

		mp_opt->version = *ptr++ & MPTCPOPT_VERSION_MASK;
		if (mp_opt->version != 0)
			break;

		mp_opt->flags = *ptr++;
		if (!((mp_opt->flags & MPTCP_CAP_FLAG_MASK) == MPTCP_CAP_HMAC_SHA1) ||
		    (mp_opt->flags & MPTCP_CAP_EXTENSIBILITY))
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
	 *
	 * Initial SYN
	 * 0: 4MSB=subtype, 000, 1LSB=Backup
	 * 1: Address ID
	 * 2-5: Receiver token
	 * 6-9: Sender random number
	 *
	 * SYN/ACK response
	 * 0: 4MSB=subtype, 000, 1LSB=Backup
	 * 1: Address ID
	 * 2-9: Sender truncated HMAC
	 * 10-13: Sender random number
	 *
	 * Third ACK
	 * 0: 4MSB=subtype, 0000
	 * 1: 0 (Reserved)
	 * 2-21: Sender HMAC
	 */

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
		mp_opt->dss = 1;
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

			if (opsize < expected_opsize)
				break;

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
			if (mp_opt->dsn64)
				expected_opsize += TCPOLEN_MPTCP_DSS_MAP64;
			else
				expected_opsize += TCPOLEN_MPTCP_DSS_MAP32;

			if (opsize < expected_opsize)
				break;

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

			/* Checksum not currently supported */
			mp_opt->checksum = 0;

			pr_debug("data_seq=%llu subflow_seq=%u data_len=%u ck=%u",
				 mp_opt->data_seq, mp_opt->subflow_seq,
				 mp_opt->data_len, mp_opt->checksum);
		}
		break;

	/* MPTCPOPT_ADD_ADDR
	 * 0: 4MSB=subtype, 4LSB=IP version (4 or 6)
	 * 1: Address ID
	 * 4 or 16 bytes of address (depending on ip version)
	 * 0 or 2 bytes of port (depending on length)
	 */

	/* MPTCPOPT_REMOVE_ADDR
	 * 0: 4MSB=subtype, 0000
	 * 1: Address ID
	 * Additional bytes: More address IDs (depending on length)
	 */

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
		       struct mptcp_out_options* opts)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	if (subflow->request_mptcp) {
		pr_debug("local_key=%llu", subflow->local_key);
		opts->suboptions = OPTION_MPTCP_MPC_SYN;
		opts->sndr_key = subflow->local_key;
		*size = TCPOLEN_MPTCP_MPC_SYN;
		return true;
	}
	return false;
}

void mptcp_rcv_synsent(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct subflow_context *subflow = subflow_ctx(sk);

	pr_debug("subflow=%p", subflow);
	if (subflow->request_mptcp && tp->rx_opt.mptcp.mp_capable) {
		subflow->mp_capable = 1;
		subflow->remote_key = tp->rx_opt.mptcp.sndr_key;
	}
}

static bool mptcp_established_options_mp(struct sock *sk, unsigned int *size,
					 unsigned int remaining,
					 struct mptcp_out_options *opts)
{
	struct subflow_context *subflow = subflow_ctx(sk);

	if (!subflow->fourth_ack && remaining >= TCPOLEN_MPTCP_MPC_ACK) {
		opts->suboptions = OPTION_MPTCP_MPC_ACK;
		opts->sndr_key = subflow->local_key;
		opts->rcvr_key = subflow->remote_key;
		*size = TCPOLEN_MPTCP_MPC_ACK;
		subflow->fourth_ack = 1;
		pr_debug("subflow=%p, local_key=%llu, remote_key=%llu",
			 subflow, subflow->local_key, subflow->remote_key);
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
		bool use_csum;

		map_size = TCPOLEN_MPTCP_DSS_BASE + TCPOLEN_MPTCP_DSS_MAP64;
		use_csum = subflow_ctx(sk)->use_checksum;
		if (use_csum)
			map_size += TCPOLEN_MPTCP_DSS_CHECKSUM;

		if (map_size <= remaining) {
			remaining -= map_size;
			dss_size = map_size;
			if (mpext) {
				opts->ext_copy.data_seq = mpext->data_seq;
				opts->ext_copy.subflow_seq = mpext->subflow_seq;
				opts->ext_copy.data_len = mpext->data_len;
				opts->ext_copy.checksum = mpext->checksum;
				opts->ext_copy.use_map = 1;
				opts->ext_copy.dsn64 = mpext->dsn64;
				opts->ext_copy.use_checksum = use_csum;
			}
		} else {
			opts->ext_copy.use_map = 0;
			WARN_ONCE(1, "MPTCP: Map dropped");
		}
	}

	ack_size = TCPOLEN_MPTCP_DSS_ACK64;

	/* Add kind/length/subtype/flag overhead if mapping not populated */
	if (dss_size == 0)
		ack_size += TCPOLEN_MPTCP_DSS_BASE;

	if (ack_size <= remaining) {
		struct mptcp_sock *msk;

		dss_size += ack_size;

		msk = mptcp_sk(subflow_ctx(sk)->conn);
		if (msk) {
			opts->ext_copy.data_ack = atomic64_read(&msk->ack_seq);
		} else {
			crypto_key_sha1(subflow_ctx(sk)->remote_key, NULL,
					&opts->ext_copy.data_ack);
			opts->ext_copy.data_ack++;
		}

		opts->ext_copy.ack64 = 1;
		opts->ext_copy.use_ack = 1;
	} else {
		opts->ext_copy.use_ack = 0;
		WARN(1, "MPTCP: Ack dropped");
	}

	*size = ALIGN(dss_size, 4);
	return true;
}

bool mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct mptcp_out_options *opts)
{
	unsigned int opt_size = 0;

	if (!subflow_ctx(sk)->mp_capable)
		return false;

	if (mptcp_established_options_mp(sk, &opt_size, remaining, opts)) {
		*size += opt_size;
		remaining -= opt_size;
		return true;
	} else if (mptcp_established_options_dss(sk, skb, &opt_size, remaining,
					       opts)) {
		*size += opt_size;
		remaining -= opt_size;
		return true;
	}

	return false;
}

bool mptcp_synack_options(const struct request_sock *req, unsigned int *size,
			  struct mptcp_out_options *opts)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);

	if (subflow_req->mp_capable) {
		opts->suboptions = OPTION_MPTCP_MPC_SYNACK;
		opts->sndr_key = subflow_req->local_key;
		opts->rcvr_key = subflow_req->remote_key;
		*size = TCPOLEN_MPTCP_MPC_SYNACK;
		pr_debug("subflow_req=%p, local_key=%llu, remote_key=%llu",
			 subflow_req, subflow_req->local_key,
			 subflow_req->remote_key);
		return true;
	}
	return false;
}

void mptcp_attach_dss(struct sock *sk, struct sk_buff *skb,
		      struct tcp_options_received *opt_rx)
{
	struct mptcp_options_received *mp_opt;
	struct mptcp_ext *mpext;

	mp_opt = &opt_rx->mptcp;

	if (!mp_opt->dss)
		return;

	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);
	if (!mpext)
		return;

	memset(mpext, 0, sizeof(*mpext));

	if (mp_opt->use_map) {
		mpext->data_seq = mp_opt->data_seq;
		mpext->subflow_seq = mp_opt->subflow_seq;
		mpext->data_len = mp_opt->data_len;
		mpext->checksum = mp_opt->checksum;
		mpext->use_map = 1;
		mpext->dsn64 = mp_opt->dsn64;
		mpext->use_checksum = mp_opt->use_checksum;
	}

	if (mp_opt->use_ack) {
		mpext->data_ack = mp_opt->data_ack;
		mpext->use_ack = 1;
		mpext->ack64 = mp_opt->ack64;
	}

	mpext->data_fin = mp_opt->data_fin;
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

		*ptr++ = htonl((TCPOPT_MPTCP << 24) | (len << 16) |
			       (MPTCPOPT_MP_CAPABLE << 12) |
			       ((MPTCPOPT_VERSION_MASK & 0) << 8) |
			       MPTCP_CAP_HMAC_SHA1);
		put_unaligned_be64(opts->sndr_key, ptr);
		ptr += 2;
		if ((OPTION_MPTCP_MPC_SYNACK |
		     OPTION_MPTCP_MPC_ACK) & opts->suboptions) {
			put_unaligned_be64(opts->rcvr_key, ptr);
			ptr += 2;
		}
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
			pr_debug("Updating DSS length and flags for map");
			len += TCPOLEN_MPTCP_DSS_MAP64;

			if (mpext->use_checksum)
				len += TCPOLEN_MPTCP_DSS_CHECKSUM;

			/* Use only 64-bit mapping flags for now, add
			 * support for optional 32-bit mappings later.
			 */
			flags |= MPTCP_DSS_HAS_MAP | MPTCP_DSS_DSN64;
			if (mpext->data_fin)
				flags |= MPTCP_DSS_DATA_FIN;
		}

		*ptr++ = htonl((TCPOPT_MPTCP << 24) |
			       (len  << 16) |
			       (MPTCPOPT_DSS << 12) |
			       (flags));

		if (mpext->use_ack) {
			put_unaligned_be64(mpext->data_ack, ptr);
			ptr += 2;
		}

		if (mpext->use_map) {
			__sum16 checksum;

			pr_debug("Writing map values");
			put_unaligned_be64(mpext->data_seq, ptr);
			ptr += 2;
			*ptr++ = htonl(mpext->subflow_seq);

			if (mpext->use_checksum)
				checksum = mpext->checksum;
			else
				checksum = TCPOPT_NOP << 8 | TCPOPT_NOP;
			*ptr = htonl(mpext->data_len << 16 | checksum);
		}
	}
}
