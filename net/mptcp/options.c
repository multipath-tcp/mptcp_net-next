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
			struct tcp_options_received *opt_rx)
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
		opt_rx->mptcp.mp_capable = 1;
		opt_rx->mptcp.version = *ptr++ & 0x0F;
		pr_debug("flags=%02x", *ptr);
		opt_rx->mptcp.flags = *ptr++;
		opt_rx->mptcp.sndr_key = get_unaligned_be64(ptr);
		pr_debug("sndr_key=%llu", opt_rx->mptcp.sndr_key);
		ptr += 8;
		if (opsize == TCPOLEN_MPTCP_MPC_SYNACK) {
			opt_rx->mptcp.rcvr_key = get_unaligned_be64(ptr);
			pr_debug("rcvr_key=%llu", opt_rx->mptcp.rcvr_key);
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
		opt_rx->mptcp.dss = 1;
		ptr++;

		opt_rx->mptcp.flags = (*ptr++) & 0x1F;
		opt_rx->mptcp.data_fin = (opt_rx->mptcp.flags & 0x10) != 0;
		opt_rx->mptcp.dsn64 = (opt_rx->mptcp.flags & 0x08) != 0;
		opt_rx->mptcp.use_map = (opt_rx->mptcp.flags & 0x04) != 0;
		opt_rx->mptcp.ack64 = (opt_rx->mptcp.flags & 0x02) != 0;
		opt_rx->mptcp.use_ack = (opt_rx->mptcp.flags & 0x01);

		pr_debug("data_fin=%d dsn64=%d use_map=%d ack64=%d use_ack=%d",
			 opt_rx->mptcp.data_fin, opt_rx->mptcp.dsn64,
			 opt_rx->mptcp.use_map, opt_rx->mptcp.ack64,
			 opt_rx->mptcp.use_ack);

		expected_opsize = 0;

		if (opt_rx->mptcp.use_ack) {
			expected_opsize = 4;
			if (opt_rx->mptcp.ack64)
				expected_opsize += 4;

			if (opsize < expected_opsize)
				break;

			if (opt_rx->mptcp.ack64) {
				opt_rx->mptcp.ack = get_unaligned_be64(ptr);
				ptr += 8;
			} else {
				opt_rx->mptcp.ack = get_unaligned_be32(ptr);
				ptr += 4;
			}

			pr_debug("ack=%llu", opt_rx->mptcp.ack);
		}

		if (opt_rx->mptcp.use_map) {
			expected_opsize += 12;
			if (opt_rx->mptcp.dsn64)
				expected_opsize += 4;

			if (opsize < expected_opsize)
				break;

			if (opt_rx->mptcp.dsn64) {
				opt_rx->mptcp.seq = get_unaligned_be64(ptr);
				ptr += 8;
			} else {
				opt_rx->mptcp.seq = get_unaligned_be32(ptr);
				ptr += 4;
			}

			opt_rx->mptcp.subflow_seq = get_unaligned_be32(ptr);
			ptr += 4;

			opt_rx->mptcp.dll = get_unaligned_be16(ptr);
			ptr += 2;

			opt_rx->mptcp.checksum = get_unaligned_be16(ptr);

			pr_debug("seq=%llu subflow_seq=%u dll=%u ck=%u",
				 opt_rx->mptcp.seq, opt_rx->mptcp.subflow_seq,
				 opt_rx->mptcp.dll, opt_rx->mptcp.checksum);
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

unsigned int mptcp_synack_options(struct request_sock *req, u64 *local_key,
				  u64 *remote_key)
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
		      struct tcp_options_received *opt_rx)
{
	struct mptcp_ext *mpext;

	if (!opt_rx->mptcp.dss)
		return;

	mpext = skb_ext_add(skb, SKB_EXT_MPTCP);
	if (!mpext)
		return;

	memset(mpext, 0, sizeof(*mpext));

	if (opt_rx->mptcp.use_map) {
		mpext->data_seq = opt_rx->mptcp.seq;
		mpext->subflow_seq = opt_rx->mptcp.subflow_seq;
		mpext->dll = opt_rx->mptcp.dll;
		mpext->checksum = opt_rx->mptcp.checksum;
		mpext->use_map = 1;
		mpext->dsn64 = opt_rx->mptcp.dsn64;
		mpext->use_checksum = opt_rx->mptcp.use_checksum;
	}

	if (opt_rx->mptcp.use_ack) {
		mpext->data_ack = opt_rx->mptcp.ack;
		mpext->use_ack = 1;
		mpext->ack64 = opt_rx->mptcp.ack64;
	}

	mpext->data_fin = opt_rx->mptcp.data_fin;
}
