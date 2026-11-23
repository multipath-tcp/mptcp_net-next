// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/seg6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* On the tc ingress, skb->data points to the Ethernet header */
#define TC_IPV6_OFF		ETH_HLEN
/* Byte with the lowest 8 bits of the Flow Label */
#define TC_FLOW_LBL_OFF		(TC_IPV6_OFF + \
				 offsetof(struct ipv6hdr, flow_lbl) + 2)
/* Bit of the Flow Label changed in the control datagram */
#define CTRL_FLOW_LBL_BIT	0x01

/* In End.BPF, skb->data points to the IPv6 header, followed by the SRH */
#define SRH_TAG_OFF		(sizeof(struct ipv6hdr) + \
				 offsetof(struct ipv6_sr_hdr, tag))
/* Value written in the SRH Tag, test case (vi) */
#define SRH_TAG			0x1234

/* Test case (v) of srv6_csum_complete_test.sh. The program runs on the tc
 * ingress of rt, after the ct action, only for the control datagram. It
 * changes one bit of the Flow Label, without updating the receive checksum
 * (skb->csum). The Flow Label is not part of the UDP checksum, which stays
 * correct. UDP must drop the datagram because the receive checksum no longer
 * matches the packet.
 */
SEC("tc")
int ctrl_flow_label(struct __sk_buff *skb)
{
	__u8 lbl;

	/* Read the byte with the lowest 8 bits of the Flow Label */
	if (bpf_skb_load_bytes(skb, TC_FLOW_LBL_OFF, &lbl, sizeof(lbl)))
		return TC_ACT_SHOT;

	lbl ^= CTRL_FLOW_LBL_BIT;

	/* Write the byte back, flags 0 do not update the receive checksum */
	if (bpf_skb_store_bytes(skb, TC_FLOW_LBL_OFF, &lbl, sizeof(lbl), 0))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

/* Test case (vi), the End.BPF program writes the SRH Tag */
SEC("lwt_seg6local")
int end_bpf_tag(struct __sk_buff *skb)
{
	__u16 tag = bpf_htons(SRH_TAG);

	if (bpf_lwt_seg6_store_bytes(skb, SRH_TAG_OFF, &tag, sizeof(tag)))
		return BPF_DROP;

	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
