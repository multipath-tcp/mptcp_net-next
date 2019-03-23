// SPDX-License-Identifier: GPL-2.0
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct mptcp_options_received *opt_rx)
{
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

		pr_debug("MP_CAPABLE");
		opt_rx->mp_capable = 1;
		opt_rx->version = *ptr++ & MPTCPOPT_VERSION_MASK;
		pr_debug("flags=%02x", *ptr);
		opt_rx->flags = *ptr++;
		opt_rx->sndr_key = get_unaligned_be64(ptr);
		pr_debug("sndr_key=%llu", opt_rx->sndr_key);
		ptr += 8;
		if (opsize == TCPOLEN_MPTCP_MPC_SYNACK) {
			opt_rx->rcvr_key = get_unaligned_be64(ptr);
			pr_debug("rcvr_key=%llu", opt_rx->rcvr_key);
			ptr += 8;
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
		opt_rx->dss = 1;
		ptr++;

		opt_rx->flags = (*ptr++) & MPTCP_DSS_FLAG_MASK;
		opt_rx->data_fin = (opt_rx->flags & MPTCP_DSS_DATA_FIN) != 0;
		opt_rx->dsn64 = (opt_rx->flags & MPTCP_DSS_DSN64) != 0;
		opt_rx->use_map = (opt_rx->flags & MPTCP_DSS_HAS_MAP) != 0;
		opt_rx->ack64 = (opt_rx->flags & MPTCP_DSS_ACK64) != 0;
		opt_rx->use_ack = (opt_rx->flags & MPTCP_DSS_HAS_ACK);

		pr_debug("data_fin=%d dsn64=%d use_map=%d ack64=%d use_ack=%d",
			 opt_rx->data_fin, opt_rx->dsn64,
			 opt_rx->use_map, opt_rx->ack64,
			 opt_rx->use_ack);

		expected_opsize = TCPOLEN_MPTCP_DSS_BASE;

		if (opt_rx->use_ack) {
			if (opt_rx->ack64)
				expected_opsize += TCPOLEN_MPTCP_DSS_ACK64;
			else
				expected_opsize += TCPOLEN_MPTCP_DSS_ACK32;

			if (opsize < expected_opsize)
				break;

			if (opt_rx->ack64) {
				opt_rx->data_ack = get_unaligned_be64(ptr);
				ptr += 8;
			} else {
				opt_rx->data_ack = get_unaligned_be32(ptr);
				ptr += 4;
			}

			pr_debug("data_ack=%llu", opt_rx->data_ack);
		}

		if (opt_rx->use_map) {
			if (opt_rx->dsn64)
				expected_opsize += TCPOLEN_MPTCP_DSS_MAP64;
			else
				expected_opsize += TCPOLEN_MPTCP_DSS_MAP32;

			if (opsize < expected_opsize)
				break;

			if (opt_rx->dsn64) {
				opt_rx->data_seq = get_unaligned_be64(ptr);
				ptr += 8;
			} else {
				opt_rx->data_seq = get_unaligned_be32(ptr);
				ptr += 4;
			}

			opt_rx->subflow_seq = get_unaligned_be32(ptr);
			ptr += 4;

			opt_rx->data_len = get_unaligned_be16(ptr);
			ptr += 2;

			/* Checksum not currently supported */
			opt_rx->checksum = 0;

			pr_debug("data_seq=%llu subflow_seq=%u data_len=%u ck=%u",
				 opt_rx->data_seq, opt_rx->subflow_seq,
				 opt_rx->data_len, opt_rx->checksum);
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
		       struct mptcp_options_received *opt_rx)
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

unsigned int mptcp_syn_options(struct sock *sk, u64 *local_key)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	if (subflow->request_mptcp) {
		pr_debug("local_key=%llu", subflow->local_key);
		*local_key = subflow->local_key;
	}
	return subflow->request_mptcp;
}

void mptcp_rcv_synsent(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct subflow_sock *subflow = subflow_sk(sk);

	pr_debug("subflow=%p", subflow);
	if (subflow->request_mptcp && tp->rx_opt.mptcp.mp_capable) {
		subflow->mp_capable = 1;
		subflow->remote_key = tp->rx_opt.mptcp.sndr_key;
	}
}

unsigned int mptcp_established_options(struct sock *sk, u64 *local_key,
				       u64 *remote_key)
{
	struct subflow_sock *subflow = subflow_sk(sk);

	pr_debug("subflow=%p", subflow);
	if (subflow->mp_capable && !subflow->fourth_ack) {
		subflow->fourth_ack = 1;
		*local_key = subflow->local_key;
		*remote_key = subflow->remote_key;
		pr_debug("local_key=%llu", *local_key);
		pr_debug("remote_key=%llu", *remote_key);
		return 1;
	}
	return 0;
}

unsigned int mptcp_synack_options(const struct request_sock *req,
				  u64 *local_key, u64 *remote_key)
{
	struct subflow_request_sock *subflow_req = subflow_rsk(req);

	pr_debug("subflow_req=%p", subflow_req);
	if (subflow_req->mp_capable) {
		*local_key = subflow_req->local_key;
		*remote_key = subflow_req->remote_key;
		pr_debug("local_key=%llu", *local_key);
		pr_debug("remote_key=%llu", *remote_key);
	}
	return subflow_req->mp_capable;
}

void mptcp_attach_dss(struct sock *sk, struct sk_buff *skb,
		      struct mptcp_options_received *opt_rx)
{
	struct mptcp_ext *mpext;

	if (!opt_rx->dss)
		return;

	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);
	if (!mpext)
		return;

	memset(mpext, 0, sizeof(*mpext));

	if (opt_rx->use_map) {
		mpext->data_seq = opt_rx->data_seq;
		mpext->subflow_seq = opt_rx->subflow_seq;
		mpext->data_len = opt_rx->data_len;
		mpext->checksum = opt_rx->checksum;
		mpext->use_map = 1;
		mpext->dsn64 = opt_rx->dsn64;
		mpext->use_checksum = opt_rx->use_checksum;
	}

	if (opt_rx->use_ack) {
		mpext->data_ack = opt_rx->data_ack;
		mpext->use_ack = 1;
		mpext->ack64 = opt_rx->ack64;
	}

	mpext->data_fin = opt_rx->data_fin;
}

void mptcp_options_write(__be32 *ptr, struct sk_buff *skb,
			 struct tcp_sock *tp,
			 struct mptcp_out_options *opts)
{
#if IS_ENABLED(CONFIG_MPTCP)
	struct mptcp_ext *mpext;

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
			       (MPTCPOPT_MP_CAPABLE << 20) |
			       ((MPTCPOPT_VERSION_MASK & 0) << 16) |
			       MPTCP_CAP_HMAC_SHA1);
		put_unaligned_be64(opts->sndr_key, ptr);
		ptr += 2;
		if ((OPTION_MPTCP_MPC_SYNACK |
		     OPTION_MPTCP_MPC_ACK) & opts->suboptions) {
			put_unaligned_be64(opts->rcvr_key, ptr);
			ptr += 2;
		}
	}

	mpext = mptcp_get_ext(skb);

	if ((OPTION_MPTCP_DSS_MAP | OPTION_MPTCP_DSS_ACK) &
	    opts->suboptions) {
		bool write_ack = !!(OPTION_MPTCP_DSS_ACK &
				    opts->suboptions);
		bool write_map = ((OPTION_MPTCP_DSS_MAP &
				   opts->suboptions) &&
				  mpext && mpext->use_map);
		u8 flags = 0;
		u8 len = TCPOLEN_MPTCP_DSS_BASE;

		if (write_ack) {
			len += TCPOLEN_MPTCP_DSS_ACK64;
			flags = MPTCP_DSS_HAS_ACK | MPTCP_DSS_ACK64;
		}

		if (write_map) {
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

		if (write_ack) {
			struct mptcp_sock *msk = mptcp_sk(subflow_tp(tp)->conn);
			u64 ack_seq;

			if (msk) {
				ack_seq = atomic64_read(&msk->ack_seq);
			} else {
				crypto_key_sha1(subflow_tp(tp)->remote_key,
						NULL, &ack_seq);
				ack_seq++;
			}

			pr_debug("ack=%llu", ack_seq);
			put_unaligned_be64(ack_seq, ptr);
			ptr += 2;
		}

		if (write_map) {
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
#endif
}
