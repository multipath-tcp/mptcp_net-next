// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2025-2026 NXP
 */

#include <linux/dsa/tag_netc.h>

#include "tag.h"

#define NETC_NAME			"nxp_netc"

/* Forward NXP switch tag */
#define NETC_TAG_FORWARD		0

/* To_Port NXP switch tag */
#define NETC_TAG_TO_PORT		1
/* SubType0: No request to perform timestamping */
#define NETC_TAG_TP_SUBTYPE0		0
/* SubType2: Request to perform two-step timestamping */
#define NETC_TAG_TP_SUBTYPE2		2
/* SubType3: Request to perform both one-step and two-step timestamping */
#define NETC_TAG_TP_SUBTYPE3		3

/* To_Host NXP switch tag */
#define NETC_TAG_TO_HOST		2
/* SubType0: frames redirected or copied to CPU port */
#define NETC_TAG_TH_SUBTYPE0		0
/* SubType1: frames redirected or copied to CPU port with timestamp */
#define NETC_TAG_TH_SUBTYPE1		1
/* SubType2: Transmit timestamp response (two-step timestamping) */
#define NETC_TAG_TH_SUBTYPE2		2

/* NETC switch tag lengths */
#define NETC_TAG_FORWARD_LEN		6
#define NETC_TAG_TP_SUBTYPE0_LEN	6
#define NETC_TAG_TP_SUBTYPE2_LEN	6
#define NETC_TAG_TP_SUBTYPE3_LEN	10
#define NETC_TAG_TH_SUBTYPE0_LEN	6
#define NETC_TAG_TH_SUBTYPE1_LEN	14
#define NETC_TAG_TH_SUBTYPE2_LEN	14
#define NETC_TAG_CMN_LEN		5

#define NETC_TAG_SUBTYPE		GENMASK(3, 0)
#define NETC_TAG_TYPE			GENMASK(7, 4)
#define NETC_TAG_QV			BIT(0)
#define NETC_TAG_IPV			GENMASK(4, 2)
#define NETC_TAG_SWITCH			GENMASK(2, 0)
#define NETC_TAG_PORT			GENMASK(7, 3)
#define NETC_TAG_TS_REQ_ID		GENMASK(3, 0)
#define NETC_TAG_TIMESTAMP		GENMASK(29, 0)

struct netc_tag_cmn {
	__be16 tpid;
	u8 type;
	u8 qos;
	u8 switch_port;
} __packed;

struct netc_tag_tp_subtype2 {
	struct netc_tag_cmn cmn;
	u8 ts_req_id;
} __packed;

struct netc_tag_tp_subtype3 {
	struct netc_tag_cmn cmn;
	u8 ts_req_id;
	__be32 timestamp;
} __packed;

struct netc_tag_th_subtype1 {
	struct netc_tag_cmn cmn;
	u8 host_reason;
	__be64 timestamp;
} __packed;

struct netc_tag_th_subtype2 {
	struct netc_tag_cmn cmn;
	u8 hr_tsreq_id;
	__be64 timestamp;
} __packed;

static void netc_fill_common_tag(struct netc_tag_cmn *tag, u8 type,
				 u8 subtype, u8 sw_id, u8 port, u8 ipv)
{
	tag->tpid = htons(ETH_P_NXP_NETC);
	tag->type = FIELD_PREP(NETC_TAG_TYPE, type) |
		    FIELD_PREP(NETC_TAG_SUBTYPE, subtype);
	tag->qos = NETC_TAG_QV | FIELD_PREP(NETC_TAG_IPV, ipv);
	tag->switch_port = FIELD_PREP(NETC_TAG_SWITCH, sw_id) |
			   FIELD_PREP(NETC_TAG_PORT, port);
}

static void *netc_fill_common_tp_tag(struct sk_buff *skb,
				     struct net_device *ndev,
				     u8 subtype, int tag_len)
{
	struct dsa_port *dp = dsa_user_to_port(ndev);
	u16 queue = skb_get_queue_mapping(skb);
	s8 ipv = netdev_txq_to_tc(ndev, queue);
	void *tag;

	if (unlikely(ipv < 0))
		ipv = 0;

	skb_push(skb, tag_len);
	dsa_alloc_etype_header(skb, tag_len);

	tag = dsa_etype_header_pos_tx(skb);
	memset(tag + NETC_TAG_CMN_LEN, 0, tag_len - NETC_TAG_CMN_LEN);
	/* As 'dsa,member' is a required property for NETC switch, the member
	 * is used to specify the switch ID (thus the hardware switch ID and
	 * the software switch ID are consistent), its range is 1 ~ 7. The
	 * NETC switch driver will check this value, and if it is invalid,
	 * the switch driver will fail the probe.
	 * In addition, according to the nxp,netc-switch.yaml doc, the port
	 * index will not be greater than 0xf.
	 */
	netc_fill_common_tag(tag, NETC_TAG_TO_PORT, subtype,
			     dp->ds->index, dp->index, ipv);

	return tag;
}

static void netc_fill_tp_tag_subtype0(struct sk_buff *skb,
				      struct net_device *ndev)
{
	netc_fill_common_tp_tag(skb, ndev, NETC_TAG_TP_SUBTYPE0,
				NETC_TAG_TP_SUBTYPE0_LEN);
}

static void netc_fill_tp_tag_subtype2(struct sk_buff *skb,
				      struct net_device *ndev)
{
	u8 ts_req_id = NETC_SKB_CB(skb)->ts_req_id;
	struct netc_tag_tp_subtype2 *tag;

	tag = netc_fill_common_tp_tag(skb, ndev, NETC_TAG_TP_SUBTYPE2,
				      NETC_TAG_TP_SUBTYPE2_LEN);
	tag->ts_req_id = FIELD_PREP(NETC_TAG_TS_REQ_ID, ts_req_id);
}

static void netc_fill_tp_tag_subtype3(struct sk_buff *skb,
				      struct net_device *ndev)
{
	u32 ts = FIELD_PREP(NETC_TAG_TIMESTAMP, NETC_SKB_CB(skb)->tstamp);
	u8 ts_req_id = NETC_SKB_CB(skb)->ts_req_id;
	struct netc_tag_tp_subtype3 *tag;

	tag = netc_fill_common_tp_tag(skb, ndev, NETC_TAG_TP_SUBTYPE3,
				      NETC_TAG_TP_SUBTYPE3_LEN);
	tag->ts_req_id = FIELD_PREP(NETC_TAG_TS_REQ_ID, ts_req_id);
	tag->timestamp = htonl(ts);
}

static void netc_onestep_sync_enqueue(struct sk_buff *skb,
				      struct net_device *ndev)
{
	struct dsa_port *dp = dsa_user_to_port(ndev);
	struct netc_tagger_data *tagger_data;

	tagger_data = dp->ds->tagger_data;
	if (unlikely(!tagger_data->onestep_sync_enqueue)) {
		kfree_skb(skb);
		return;
	}

	/* Hand the one-step Sync to the switch driver, which takes ownership
	 * and queues it for deferred transmission from its work. The tagger
	 * must not touch the skb after this point.
	 */
	tagger_data->onestep_sync_enqueue(dp->ds, dp->index, skb);
}

static netdev_tx_t netc_onestep_sync_xmit(struct sk_buff *skb,
					  struct net_device *dev)
{
	netc_fill_tp_tag_subtype3(skb, dev);

	return dsa_enqueue_skb(skb, dev);
}

static struct sk_buff *netc_xmit(struct sk_buff *skb,
				 struct net_device *ndev)
{
	u8 ptp_flag = NETC_SKB_CB(skb)->ptp_flag;

	/* Fast path: the overwhelming majority of frames are not PTP frames */
	if (likely(!ptp_flag)) {
		netc_fill_tp_tag_subtype0(skb, ndev);
	} else if (ptp_flag == NETC_PTP_FLAG_TWOSTEP) {
		netc_fill_tp_tag_subtype2(skb, ndev);
	} else if (ptp_flag == NETC_PTP_FLAG_ONESTEP) {
		/* The switch driver takes ownership of the one-step Sync and
		 * queues it for deferred TX; the deferred work tags it subtype
		 * 3 and transmits it directly to the conduit. Return NULL so
		 * dsa_user_xmit() stops processing this skb.
		 */
		netc_onestep_sync_enqueue(skb, ndev);
		skb = NULL;
	} else {
		/* NETC_PTP_FLAG_DROP */
		kfree_skb(skb);
		skb = NULL;
	}

	return skb;
}

static void netc_rx_tstamp_process(struct netc_tag_th_subtype1 *tag,
				   struct sk_buff *skb)
{
	u64 ts = get_unaligned_be64(&tag->timestamp);

	NETC_SKB_CB(skb)->rx_tstamp_valid = true;
	NETC_SKB_CB(skb)->tstamp = ts;
}

static void netc_twostep_tstamp_process(struct netc_tag_th_subtype2 *tag,
					struct sk_buff *skb)
{
	u8 ts_req_id = FIELD_GET(NETC_TAG_TS_REQ_ID, tag->hr_tsreq_id);
	struct dsa_port *dp = dsa_user_to_port(skb->dev);
	u64 ts = get_unaligned_be64(&tag->timestamp);
	struct netc_tagger_data *tagger_data;
	struct dsa_switch *ds = dp->ds;

	tagger_data = ds->tagger_data;
	if (unlikely(!tagger_data->txtstamp_handler))
		return;

	tagger_data->txtstamp_handler(ds, dp->index, ts_req_id, ts);
}

static int netc_get_rx_tag_len(int type, int subtype)
{
	/* Only NETC_TAG_TO_HOST and NETC_TAG_FORWARD are expected in RX,
	 * NETC_TAG_TO_PORT is a TX switch tag that does not exist in RX.
	 */
	if (type == NETC_TAG_TO_HOST) {
		if (subtype == NETC_TAG_TH_SUBTYPE1)
			return NETC_TAG_TH_SUBTYPE1_LEN;
		else if (subtype == NETC_TAG_TH_SUBTYPE2)
			return NETC_TAG_TH_SUBTYPE2_LEN;
		else
			return NETC_TAG_TH_SUBTYPE0_LEN;
	}

	return NETC_TAG_FORWARD_LEN;
}

static struct sk_buff *netc_rcv(struct sk_buff *skb,
				struct net_device *ndev)
{
	struct netc_tag_cmn *tag_cmn;
	int tag_len, sw_id, port;
	int type, subtype;
	void *tag;

	/* eth_type_trans() pulled ETH_HLEN bytes, so skb->data sits 2 bytes
	 * past the start of the switch tag (past the TPID) and skb->len is
	 * ETH_HLEN bytes shorter than the original frame length. The longest
	 * switch tag is NETC_TAG_MAX_LEN (14) bytes, but since 2 of those
	 * bytes are already behind skb->data, only NETC_TAG_MAX_LEN - 2 bytes
	 * need to be in the linear buffer. For the To_Host subtype 2 response
	 * frame, whose total length is only 26 bytes with no payload after the
	 * tag, this check is the only guard against a too-short frame.
	 */
	if (unlikely(!pskb_may_pull(skb, NETC_TAG_MAX_LEN - 2)))
		goto err_free_skb;

	tag = dsa_etype_header_pos_rx(skb);
	tag_cmn = tag;
	if (ntohs(tag_cmn->tpid) != ETH_P_NXP_NETC) {
		dev_warn_ratelimited(&ndev->dev, "Unknown TPID 0x%04x\n",
				     ntohs(tag_cmn->tpid));
		goto err_free_skb;
	}

	if (tag_cmn->qos & NETC_TAG_QV)
		skb->priority = FIELD_GET(NETC_TAG_IPV, tag_cmn->qos);

	sw_id = FIELD_GET(NETC_TAG_SWITCH, tag_cmn->switch_port);
	/* ENETC VEPA switch ID (0) is not supported yet */
	if (!sw_id) {
		dev_warn_ratelimited(&ndev->dev,
				     "VEPA switch ID is not supported yet\n");
		goto err_free_skb;
	}

	port = FIELD_GET(NETC_TAG_PORT, tag_cmn->switch_port);
	skb->dev = dsa_conduit_find_user(ndev, sw_id, port);
	if (!skb->dev)
		goto err_free_skb;

	/* skb->cb may be used to store hardware RX timestamp, so clear
	 * rx_tstamp_valid before processing to avoid data pollution from
	 * the previous layer.
	 */
	NETC_SKB_CB(skb)->rx_tstamp_valid = false;

	type = FIELD_GET(NETC_TAG_TYPE, tag_cmn->type);
	subtype = FIELD_GET(NETC_TAG_SUBTYPE, tag_cmn->type);
	if (type == NETC_TAG_FORWARD) {
		dsa_default_offload_fwd_mark(skb);
	} else if (type == NETC_TAG_TO_HOST) {
		switch (subtype) {
		case NETC_TAG_TH_SUBTYPE0:
			break;
		case NETC_TAG_TH_SUBTYPE1:
			/* To_Host Subtype 1 tag is 14 bytes, ensure it and the
			 * EtherType behind it are fully present in the linear
			 * area before netc_rcv() calls dsa_strip_etype_header()
			 * to strip the tag.
			 */
			if (unlikely(!pskb_may_pull(skb,
						    NETC_TAG_TH_SUBTYPE1_LEN)))
				goto err_free_skb;

			tag = dsa_etype_header_pos_rx(skb);
			netc_rx_tstamp_process(tag, skb);
			break;
		case NETC_TAG_TH_SUBTYPE2:
			/* This skb is a hardware-generated response to a
			 * two-step transmit timestamp request. The tag
			 * driver must free the skb after processing.
			 */
			netc_twostep_tstamp_process(tag, skb);
			consume_skb(skb);
			return NULL;
		default:
			dev_warn_ratelimited(&ndev->dev,
					     "Unsupported To_Host subtype: %d\n",
					     subtype);
			goto err_free_skb;
		}
	} else {
		dev_warn_ratelimited(&ndev->dev,
				     "Unexpected tag type %d\n", type);
		goto err_free_skb;
	}

	/* Remove Switch tag from the frame */
	tag_len = netc_get_rx_tag_len(type, subtype);
	skb_pull_rcsum(skb, tag_len);
	dsa_strip_etype_header(skb, tag_len);

	return skb;

err_free_skb:
	kfree_skb(skb);
	return NULL;
}

static void netc_flow_dissect(const struct sk_buff *skb, __be16 *proto,
			      int *offset)
{
	struct netc_tag_cmn *tag_cmn = (struct netc_tag_cmn *)(skb->data - 2);
	int subtype = FIELD_GET(NETC_TAG_SUBTYPE, tag_cmn->type);
	int type = FIELD_GET(NETC_TAG_TYPE, tag_cmn->type);
	int tag_len = netc_get_rx_tag_len(type, subtype);

	/* The CPU port of the switch is connected to the ENETC, so the frame
	 * is received by the ENETC driver. From the hardware perspective, the
	 * receive buffer of RX BD is at least 128 bytes, so the switch tag
	 * header is guaranteed to be in the linear region of the skb.
	 *
	 * When the subtype of the frame is NETC_TAG_TH_SUBTYPE2, it indicates
	 * the frame is a hardware generated timestamp response, which is only
	 * 26 bytes (DMAC + SMAC + tag), so the frame has no payload after the
	 * tag. Therefore, there is no need to parse the protocol and offset.
	 * For other types of the frames, they are all received from the switch
	 * ports, and the RX minimum frame length of the port is 64 bytes,
	 * frames shorter than 64 bytes will be discarded by the hardware and
	 * will not be received by the software.
	 */
	if (type == NETC_TAG_TO_HOST && subtype == NETC_TAG_TH_SUBTYPE2)
		return;

	*offset = tag_len;
	*proto = ((__be16 *)skb->data)[(tag_len / 2) - 1];
}

static int netc_connect(struct dsa_switch *ds)
{
	struct netc_tagger_data *tagger_data;

	tagger_data = kzalloc_obj(*tagger_data);
	if (!tagger_data)
		return -ENOMEM;

	tagger_data->onestep_sync_xmit = netc_onestep_sync_xmit;
	ds->tagger_data = tagger_data;

	return 0;
}

static void netc_disconnect(struct dsa_switch *ds)
{
	struct netc_tagger_data *tagger_data = ds->tagger_data;

	kfree(tagger_data);
	ds->tagger_data = NULL;
}

static const struct dsa_device_ops netc_netdev_ops = {
	.name			= NETC_NAME,
	.proto			= DSA_TAG_PROTO_NETC,
	.xmit			= netc_xmit,
	.rcv			= netc_rcv,
	.needed_headroom	= NETC_TAG_MAX_LEN,
	.flow_dissect		= netc_flow_dissect,
	.connect		= netc_connect,
	.disconnect		= netc_disconnect,
};

MODULE_DESCRIPTION("DSA tag driver for NXP NETC switch family");
MODULE_LICENSE("GPL");

MODULE_ALIAS_DSA_TAG_DRIVER(DSA_TAG_PROTO_NETC, NETC_NAME);
module_dsa_tag_driver(netc_netdev_ops);
