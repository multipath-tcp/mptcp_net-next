// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/dsa/lan9645x.h>

#include "tag.h"

#define LAN9645X_NAME "lan9645x"

/* The internal frame header (IFH) is 28 bytes, and the fields are documented
 * below. Some fields are only used on either injection or extraction.
 *
 * Injection header
 */
#define IFH_INJ_TIMESTAMP		192
#define IFH_BYPASS			191
#define IFH_MASQ			190
/* Extraction header */
#define IFH_TIMESTAMP_NS		194
#define IFH_TIMESTAMP_SUBNS		186
/* Injection header */
#define IFH_MASQ_PORT			186
#define IFH_RCT_INJ			185
/* Extraction header */
#define IFH_LEN				171
#define IFH_WRDMODE			169
/* Extraction/Injection header */
#define IFH_RTAGD			167
/* Extraction header */
#define IFH_CUTTHRU			166
/* Extraction/Injection header */
#define IFH_REW_CMD			156
#define IFH_REW_OAM			155
#define IFH_PDU_TYPE			151
#define IFH_FCS_UPD			150
#define IFH_DP				149
/* Reserved */
#define IFH_RTE_INB_UPDATE		148
/* Extraction/Injection header */
#define IFH_POP_CNT			146
#define IFH_ETYPE_OFS			144
/* Extraction header */
#define IFH_SRCPORT			140
/* Extraction/Injection header */
#define IFH_SEQ_NUM			120
#define IFH_TAG_TYPE			119
#define IFH_TCI				103
#define IFH_DSCP			97
#define IFH_QOS_CLASS			94
#define IFH_CPUQ			86
/* Extraction header */
#define IFH_LEARN_FLAGS			84
/* Extraction/Injection header */
#define IFH_SFLOW_ID			80
#define IFH_ACL_HIT			79
#define IFH_ACL_IDX			73
#define IFH_ISDX			65
#define IFH_DSTS			55
/* Extraction header */
#define IFH_FLOOD			53
/* Extraction/Injection header */
#define IFH_SEQ_OP			51
#define IFH_IPV				48
/* Injection header */
#define IFH_AFI				47
/* Reserved */
#define IFH_RTP_ID			37
#define IFH_RTP_SUBID			36
#define IFH_PN_DATA_STATUS		28
#define IFH_PN_TRANSF_STATUS_ZERO	27
#define IFH_PN_CC			11
/* Extraction/Injection header */
#define IFH_DUPL_DISC_ENA		10
/* Extraction header */
#define IFH_RCT_AVAIL			9

#define IFH_INJ_TIMESTAMP_SZ		32
#define IFH_BYPASS_SZ			1
#define IFH_MASQ_SZ			1
#define IFH_TIMESTAMP_NS_SZ		30
#define IFH_TIMESTAMP_SUBNS_SZ		8
#define IFH_MASQ_PORT_SZ		4
#define IFH_RCT_INJ_SZ			1
#define IFH_LEN_SZ			14
#define IFH_WRDMODE_SZ			2
#define IFH_RTAGD_SZ			2
#define IFH_CUTTHRU_SZ			1
#define IFH_REW_CMD_SZ			10
#define IFH_REW_OAM_SZ			1
#define IFH_PDU_TYPE_SZ			4
#define IFH_FCS_UPD_SZ			1
#define IFH_DP_SZ			1
#define IFH_RTE_INB_UPDATE_SZ		1
#define IFH_POP_CNT_SZ			2
#define IFH_ETYPE_OFS_SZ		2
#define IFH_SRCPORT_SZ			4
#define IFH_SEQ_NUM_SZ			16
#define IFH_TAG_TYPE_SZ			1
#define IFH_TCI_SZ			16
#define IFH_DSCP_SZ			6
#define IFH_QOS_CLASS_SZ		3
#define IFH_CPUQ_SZ			8
#define IFH_LEARN_FLAGS_SZ		2
#define IFH_SFLOW_ID_SZ			4
#define IFH_ACL_HIT_SZ			1
#define IFH_ACL_IDX_SZ			6
#define IFH_ISDX_SZ			8
#define IFH_DSTS_SZ			10
#define IFH_FLOOD_SZ			2
#define IFH_SEQ_OP_SZ			2
#define IFH_IPV_SZ			3
#define IFH_AFI_SZ			1
#define IFH_RTP_ID_SZ			10
#define IFH_RTP_SUBID_SZ		1
#define IFH_PN_DATA_STATUS_SZ		8
#define IFH_PN_TRANSF_STATUS_ZERO_SZ	1
#define IFH_PN_CC_SZ			16
#define IFH_DUPL_DISC_ENA_SZ		1
#define IFH_RCT_AVAIL_SZ		1

static __always_inline void lan9645x_ifh_merge_byte(u8 *dst, u8 src, u8 mask)
{
	*dst = *dst ^ ((*dst ^ src) & mask);
}

/* The internal frame header (IFH) is a big-endian 28 byte unpadded bit array.
 * Frames can be prepended with an IFH on injection and extraction. There
 * are two field layouts, one for extraction and one for injection.
 *
 *    IFH bits go from high to low, for instance
 *    ifh[0]  = [223:216]
 *    ifh[27] = [7:0]
 *
 * Here is an example of setting a value starting at bit 13 of bit length 17.
 *
 * val    = 0x1ff
 * pos    = 13
 * length = 17
 *
 *
 * IFH[]   0                         23       24       25        26      27
 *
 *                                           end_u8           start_u8
 *      +--------+----------------+--------+--------+--------+--------+--------+
 *      |        |                |        |        |        |        |        |
 * IFH  |        | ....           |        |  vvvvvvvvvvvvvvvvvvv     |        |
 *      |        |                |        |  |     |        |  |     |        |
 *      +--------+----------------+--------+--+-----+--------+--+-----+--------+
 * Bits  223                       39    32 31|   24 23    16 15|    8 7      0
 *                                            |                 |
 *                                            |                 |
 *                                            |                 |
 *                                            v                 v
 *                                        end       = 29       pos        = 13
 *                                        end_rem   = 5        pos_rem    = 5
 *                                        end_u8    = 3        start_u8   = 1
 *                                    GENMASK(5, 0) = 0x3f  GENMASK(7, 5) = 0xe0
 *
 *
 * In end_u8 and start_u8 we must merge the existing IFH byte with the new
 * value. In the 'middle' bytes of the value we can overwrite the corresponding
 * IFH byte.
 */
static __always_inline void lan9645x_ifh_set(u8 *ifh, u32 val, size_t pos,
					     size_t length)
{
	size_t end = (pos + length) - 1;
	size_t end_rem = end & 0x7;
	size_t pos_rem = pos & 0x7;
	size_t start_u8 = pos >> 3;
	size_t end_u8 = end >> 3;
	u8 end_mask, start_mask;
	size_t vshift;
	u8 *ptr;

	BUILD_BUG_ON_MSG(length > 32, "IFH field size wider than 32.");
	BUILD_BUG_ON_MSG(length == 0, "IFH field size of 0.");
	BUILD_BUG_ON_MSG(pos + length > LAN9645X_IFH_BITS,
			 "IFH field overflows IFH");

	end_mask = GENMASK(end_rem, 0);
	start_mask = GENMASK(7, pos_rem);

	ptr = &ifh[LAN9645X_IFH_LEN_BYTES - 1 - end_u8];

	if (end_u8 == start_u8)
		return lan9645x_ifh_merge_byte(ptr, val << pos_rem,
					       end_mask & start_mask);

	vshift = length - end_rem - 1;
	lan9645x_ifh_merge_byte(ptr++, val >> vshift, end_mask);

	for (size_t j = 1; j < end_u8 - start_u8; j++) {
		vshift -= 8;
		*ptr++ = val >> vshift;
	}

	lan9645x_ifh_merge_byte(ptr, val << pos_rem, start_mask);
}

static __always_inline u32 lan9645x_ifh_get(const u8 *ifh, size_t pos,
					    size_t length)
{
	size_t end = (pos + length) - 1;
	size_t end_rem = end & 0x7;
	size_t pos_rem = pos & 0x7;
	size_t start_u8 = pos >> 3;
	size_t end_u8 = end >> 3;
	u8 end_mask, start_mask;
	const u8 *ptr;
	u32 val;

	BUILD_BUG_ON_MSG(length > 32, "IFH field size wider than 32.");
	BUILD_BUG_ON_MSG(length == 0, "IFH field size of 0.");
	BUILD_BUG_ON_MSG(pos + length > LAN9645X_IFH_BITS,
			 "IFH field overflows IFH");

	end_mask = GENMASK(end_rem, 0);
	start_mask = GENMASK(7, pos_rem);

	ptr = &ifh[LAN9645X_IFH_LEN_BYTES - 1 - end_u8];

	if (end_u8 == start_u8)
		return (*ptr & end_mask & start_mask) >> pos_rem;

	val = *ptr++ & end_mask;

	for (size_t j = 1; j < end_u8 - start_u8; j++)
		val = val << 8 | *ptr++;

	return val << (8 - pos_rem) | (*ptr & start_mask) >> pos_rem;
}

static struct sk_buff *lan9645x_xmit_get_vlan_info(struct sk_buff *skb,
						   struct net_device *br,
						   u32 *vlan_tci,
						   u32 *tag_type)
{
	struct vlan_ethhdr *hdr;
	u16 proto, tci;

	/* If the VLAN tag is in the hwaccel area, move it to the payload so
	 * that both cases are handled uniformly below, and so that the conduit
	 * cannot insert it into the middle of the IFH we are about to prepend.
	 */
	if (unlikely(skb_vlan_tag_present(skb))) {
		skb = __vlan_hwaccel_push_inside(skb);
		if (!skb)
			return NULL;
	}

	if (!br || !br_vlan_enabled(br)) {
		*vlan_tci = 0;
		*tag_type = LAN9645X_IFH_TAG_TYPE_C;
		return skb;
	}

	br_vlan_get_proto(br, &proto);

	*vlan_tci = 0;
	if (skb->len >= VLAN_ETH_HLEN) {
		if (unlikely(!pskb_may_pull(skb, VLAN_ETH_HLEN))) {
			kfree_skb(skb);
			return NULL;
		}

		hdr = skb_vlan_eth_hdr(skb);
		if (ntohs(hdr->h_vlan_proto) == proto &&
		    ntohs(hdr->h_vlan_TCI) & VLAN_VID_MASK) {
			vlan_remove_tag(skb, &tci);
			*vlan_tci = tci;
		}
	}

	*tag_type = (proto != ETH_P_8021Q) ? LAN9645X_IFH_TAG_TYPE_S :
					     LAN9645X_IFH_TAG_TYPE_C;

	return skb;
}

static void lan9645x_offload_fwd_mark(struct sk_buff *skb, u32 cpuq)
{
	/* Trapped frames must be forwarded by the stack. */
	if (cpuq & BIT(LAN9645X_CPUQ_TRAP)) {
		skb->offload_fwd_mark = 0;
		return;
	}

	dsa_default_offload_fwd_mark(skb);
}

static struct sk_buff *lan9645x_xmit(struct sk_buff *skb,
				     struct net_device *ndev)
{
	struct dsa_port *dp = dsa_user_to_port(ndev);
	u32 vlan_tci, tag_type;
	u32 qos_class;
	void *ifh;

	skb = lan9645x_xmit_get_vlan_info(skb, dsa_port_bridge_dev_get(dp),
					  &vlan_tci, &tag_type);
	if (!skb)
		return NULL;

	/* We need to make sure frame has the proper size after IFH is stripped
	 * by hw.
	 */
	if (skb_put_padto(skb, ETH_ZLEN))
		return NULL;

	qos_class = netdev_get_num_tc(ndev) ?
		    netdev_get_prio_tc_map(ndev, skb->priority) :
		    skb->priority;
	qos_class = min_t(u32, qos_class, GENMASK(IFH_QOS_CLASS_SZ - 1, 0));

	/* Make room for IFH */
	ifh = skb_push(skb, LAN9645X_IFH_LEN_BYTES);
	memset(ifh, 0, LAN9645X_IFH_LEN_BYTES);

	lan9645x_ifh_set(ifh, 1, IFH_BYPASS, IFH_BYPASS_SZ);
	lan9645x_ifh_set(ifh, tag_type, IFH_TAG_TYPE, IFH_TAG_TYPE_SZ);
	lan9645x_ifh_set(ifh, vlan_tci, IFH_TCI, IFH_TCI_SZ);
	lan9645x_ifh_set(ifh, qos_class, IFH_QOS_CLASS, IFH_QOS_CLASS_SZ);
	lan9645x_ifh_set(ifh, qos_class, IFH_IPV, IFH_IPV_SZ);
	lan9645x_ifh_set(ifh, BIT(dp->index), IFH_DSTS, IFH_DSTS_SZ);

	return skb;
}

static int lan9645x_ifh_gap_len(const u8 *ifh)
{
	u32 popcnt = lan9645x_ifh_get(ifh, IFH_POP_CNT, IFH_POP_CNT_SZ);
	u32 etype_ofs = lan9645x_ifh_get(ifh, IFH_ETYPE_OFS, IFH_ETYPE_OFS_SZ);

	/* Tag pushing is disabled on the NPI port via REW_TAG_CFG, so if this
	 * fires REW_TAG_CFG is misconfigured.
	 */
	if (popcnt == 1 ||
	    (popcnt == 0 && etype_ofs > 0))
		return -EINVAL;

	/* Since REW_PORT_CFG_NO_REWRITE=0 is required on the NPI port, we need
	 * to account for any tags popped by the hardware, as that will leave a
	 * gap between the IFH and DMAC. Tag pushing is disabled.
	 *
	 * The IFH fields do not have intuitive values. This is how HW does the
	 * calculation:
	 *
	 * DMAC_DT = (ifh.pop_cnt == 0 && ifh.etype_ofs == 0) ? 4 : ifh.pop_cnt
	 * DMAC_OFFSET = TAG_SIZE + 4*(DMAC_DT - 2)
	 *
	 * With tag pushing disabled we have either
	 *
	 * popcnt=0 and etype_ofs=0     => 2x pop
	 * popcnt=3 and etype_ofs=*     => 1x pop
	 * popcnt=2 and etype_ofs=*     => no pop
	 *
	 * The remaining combinations indicate a push and will not occur.
	 */
	if (popcnt == 0 && etype_ofs == 0)
		return 2 * VLAN_HLEN;
	if (popcnt == 3)
		return VLAN_HLEN;

	return 0;
}

static struct sk_buff *lan9645x_rcv(struct sk_buff *skb,
				    struct net_device *ndev)
{
	u32 src_port, qos_class, vlan_tci, cpuq;
	int ifh_gap_len;
	u8 *ifh;

	/* Conduit already consumed DMAC,SMAC,ETYPE from long prefix. Go back
	 * to beginning of frame.
	 */
	skb_push(skb, ETH_HLEN);

	if (unlikely(!pskb_may_pull(skb, LAN9645X_TOTAL_TAG_LEN))) {
		kfree_skb(skb);
		return NULL;
	}

	/* IFH starts after our long prefix */
	ifh = skb_pull(skb, LAN9645X_LONG_PREFIX_LEN);

	src_port = lan9645x_ifh_get(ifh, IFH_SRCPORT, IFH_SRCPORT_SZ);
	vlan_tci = lan9645x_ifh_get(ifh, IFH_TCI, IFH_TCI_SZ);
	qos_class = lan9645x_ifh_get(ifh, IFH_QOS_CLASS, IFH_QOS_CLASS_SZ);
	cpuq = lan9645x_ifh_get(ifh, IFH_CPUQ, IFH_CPUQ_SZ);

	ifh_gap_len = lan9645x_ifh_gap_len(ifh);
	if (ifh_gap_len < 0) {
		kfree_skb(skb);
		return NULL;
	}

	/* Set skb->data at start of real header */
	skb_pull(skb, LAN9645X_IFH_LEN_BYTES);

	if (unlikely(!pskb_may_pull(skb, ifh_gap_len + ETH_HLEN))) {
		kfree_skb(skb);
		return NULL;
	}

	skb_pull(skb, ifh_gap_len);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_reset_mac_len(skb);

	/* Reset skb->data past the actual ethernet header. */
	skb_pull(skb, ETH_HLEN);

	/* We must deliver the skb so skb->csum only covers the data beyond the
	 * real ethernet header. The fake ethernet header in the prefix is
	 * not part of skb->csum already. We must subtract what remains of the
	 * prefix, the ifh, the gap and the real ethernet header, which
	 * dsa_switch_rcv() pushes back without updating skb->csum. The start
	 * is derived from the current skb->data rather than saved on entry,
	 * because the pskb_may_pull() calls above may have reallocated
	 * skb->head.
	 */
	skb_postpull_rcsum(skb,
			   skb->data - LAN9645X_TOTAL_TAG_LEN - ifh_gap_len,
			   LAN9645X_TOTAL_TAG_LEN + ifh_gap_len);

	skb->dev = dsa_conduit_find_user(ndev, 0, src_port);
	if (!skb->dev) {
		/* Reflection is disabled for frames from the tag driver itself,
		 * however it is possible that a frame sent directly on the
		 * conduit gets reflected, so we drop it here.
		 */
		kfree_skb(skb);
		return NULL;
	}

	lan9645x_offload_fwd_mark(skb, cpuq);

	skb->priority = qos_class;

	/* While we have REW_PORT_CFG_NO_REWRITE=0 on the NPI port, we still
	 * disable port VLAN tag pushing with REW_TAG_CFG. A frame ingressing
	 * on a vlan aware port, which is forwarded to the CPU, will not carry
	 * vlan info in the frame data, because the tag is popped. The
	 * classified VID is only communicated via the IFH, never in the
	 * payload. We therefore restore it via hwaccel and must not pop an
	 * in-band tag here.
	 */
	if (ifh_gap_len) {
		/* The tag is restored as a C-tag, not as the TAG_TYPE the IFH
		 * reports. The classifier recognizes both TPIDs as VLAN tags,
		 * so an S-tag has already been used for classification by the
		 * time we get here. Restoring it as 802.1AD would make the
		 * bridge push it back into the payload and reclassify the frame
		 * to the port pvid, on a different VID than the one the
		 * hardware forwarded it on.
		 */
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci);
	}

	return skb;
}

static void lan9645x_flow_dissect(const struct sk_buff *skb, __be16 *proto,
				  int *offset)
{
	u8 ifh_buf[LAN9645X_IFH_LEN_BYTES];
	const __be16 *encap_proto;
	__be16 proto_buf;
	const u8 *ifh;
	int tag_len;

	*proto = 0;
	*offset = 0;

	ifh = skb_header_pointer(skb, LAN9645X_LONG_PREFIX_LEN - ETH_HLEN,
				 LAN9645X_IFH_LEN_BYTES, ifh_buf);
	if (!ifh)
		return;

	tag_len = lan9645x_ifh_gap_len(ifh);
	if (tag_len < 0)
		return;

	tag_len += LAN9645X_TOTAL_TAG_LEN;

	encap_proto = skb_header_pointer(skb, tag_len - sizeof(proto_buf),
					 sizeof(proto_buf), &proto_buf);
	if (!encap_proto)
		return;

	*proto = *encap_proto;
	*offset = tag_len;
}

static const struct dsa_device_ops lan9645x_netdev_ops = {
	.name			= LAN9645X_NAME,
	.proto			= DSA_TAG_PROTO_LAN9645X,
	.xmit			= lan9645x_xmit,
	.rcv			= lan9645x_rcv,
	.flow_dissect		= lan9645x_flow_dissect,
	/* Covers the extraction prefix too, since dsa_tag_protocol_overhead()
	 * sizes the conduit MTU from this.
	 */
	.needed_headroom	= LAN9645X_TOTAL_TAG_LEN,
};

MODULE_DESCRIPTION("DSA tag driver for LAN9645x family of switches, using NPI port");
MODULE_LICENSE("GPL");
MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_LAN9645X, LAN9645X_NAME);

module_dsa_tag_driver(lan9645x_netdev_ops);
