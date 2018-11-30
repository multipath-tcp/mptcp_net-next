/*
 * Multipath TCP
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/mptcp.h>

void mptcp_parse_option(const unsigned char *ptr, int opsize,
			struct tcp_options_received *opt_rx)
{
	u8 subtype;

	opsize -= 2;
	subtype = *ptr++;

	/* MPTCPOPT_MP_CAPABLE
	 * 0: 4MSB=subtype, 4LSB=version
	 * 1: Handshake flags
	 * 2-9: Sender key
	 * 10-17: Receiver key (optional)
	 */
	switch (subtype & 0xF0) {
	case 0x00:
		pr_debug("MP_CAPABLE");
		pr_debug("flags=%02x", *ptr);
		opt_rx->mptcp.mp_capable = 1;
		opt_rx->mptcp.version = subtype & 0x0F;
		opt_rx->mptcp.flags = *ptr++;
		opt_rx->mptcp.sndr_key = get_unaligned_be64(ptr);
		pr_debug("sndr_key=%llu", opt_rx->mptcp.sndr_key);
		ptr += 8;
		if (opsize > TCPOLEN_MPTCP_MPC_SYN) {
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
	case 0x20:
		pr_debug("DSS");
		opt_rx->mptcp.dss = 1;
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
