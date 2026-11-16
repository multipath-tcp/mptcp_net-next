// SPDX-License-Identifier: GPL-2.0
/* QoS and DCB register programming for the rtl8365mb switch family
 *
 * The rtl8365mb backend of the shared rtl83xx-qos.c layer. rtl8365mb_setup()
 * calls its init functions directly; the shared layer reaches the rest through
 * the realtek_ops qos_* callbacks.
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/build_bug.h>
#include <linux/dcbnl.h>
#include <linux/regmap.h>
#include <net/dsa.h>
#include <net/dscp.h>
#include <net/ieee8021q.h>

#include "realtek.h"
#include "rtl8365mb_qos.h"

/* The chip's eight internal priorities carry 802.1Q traffic types, one
 * internal priority per traffic type.
 */
static_assert(RTL8365MB_NUM_INTERNAL_PRIOS == IEEE8021Q_TT_MAX);

#define RTL8365MB_QOS_REG_BITS				16

/* QoS priority and queue selectors are 3-bit fields on 4-bit boundaries,
 * four per register.
 */
#define RTL8365MB_QOS_SEL_BITS				3
#define RTL8365MB_QOS_SEL_STRIDE			4
#define RTL8365MB_QOS_SELS_PER_REG			4
#define RTL8365MB_QOS_SEL_OFFSET(_i) \
	(((_i) % RTL8365MB_QOS_SELS_PER_REG) * RTL8365MB_QOS_SEL_STRIDE)

static_assert(RTL8365MB_QOS_SEL_BITS <= RTL8365MB_QOS_SEL_STRIDE);
static_assert(RTL8365MB_QOS_SEL_STRIDE * RTL8365MB_QOS_SELS_PER_REG <=
	      RTL8365MB_QOS_REG_BITS);

/* qmaps: the queue id of each internal priority, one table per qmap */
#define RTL8365MB_QOS_QMAP_TBL_REGS \
	(RTL8365MB_NUM_INTERNAL_PRIOS / RTL8365MB_QOS_SELS_PER_REG)
#define RTL8365MB_QOS_QMAP_TBL_REG(_m, _iprio) \
	(0x0904 + (_m) * RTL8365MB_QOS_QMAP_TBL_REGS + \
	 (_iprio) / RTL8365MB_QOS_SELS_PER_REG)

/* The qmap each port reads, one select per port */
#define RTL8365MB_QOS_PORT_QMAP_SEL_REG(_p) \
	(0x0900 + (_p) / RTL8365MB_QOS_SELS_PER_REG)

static_assert(BIT(RTL8365MB_QOS_SEL_BITS) == RTL8365MB_QOS_NUM_QMAPS);
/* Ports 0..7 fit in 0x0900..0x0901; 0x0902 does not read back */
static_assert(RTL8365MB_QOS_PORT_QMAP_SEL_REG(RTL8365MB_QOS_MAX_PORTS - 1) <=
	      0x0901);

/* qmap 7 is the table that select value 0 picks */
#define RTL8365MB_QOS_QMAP_DEFAULT			7

static_assert(RTL8365MB_QOS_QMAP_DEFAULT < RTL8365MB_QOS_NUM_QMAPS);

/* 802.1p (PCP) -> internal priority remap */
#define RTL8365MB_QOS_1Q_REMAP_REG(_pcp) \
	(0x0865 + (_pcp) / RTL8365MB_QOS_SELS_PER_REG)

/* PCP given to untagged frames, one 3-bit field per port */
#define RTL8365MB_QOS_PORT_UNTAG_PCP_REG(_p) \
	(0x0851 + (_p) / RTL8365MB_QOS_SELS_PER_REG)

/* Ports 0..7 fit in 0x0851..0x0852 */
static_assert(RTL8365MB_QOS_PORT_UNTAG_PCP_REG(RTL8365MB_QOS_MAX_PORTS - 1) <=
	      0x0852);

/* Port-based (default) priority, one select per port */
#define RTL8365MB_QOS_PORT_PRI_REG(_p) \
	(0x0877 + (_p) / RTL8365MB_QOS_SELS_PER_REG)

/* Ports 0..7 fit in 0x0877..0x0878; the next one is at 0x087a */
static_assert(RTL8365MB_QOS_PORT_PRI_REG(RTL8365MB_QOS_MAX_PORTS - 1) <=
	      0x0878);

/* DSCP -> internal priority, one table for the whole chip */
#define RTL8365MB_QOS_DSCP_PRI_REG(_d) \
	(0x0867 + (_d) / RTL8365MB_QOS_SELS_PER_REG)

static_assert(RTL8365MB_QOS_1Q_REMAP_REG(IEEE_8021Q_MAX_PRIORITIES - 1) <
	      RTL8365MB_QOS_DSCP_PRI_REG(0));
static_assert(RTL8365MB_QOS_DSCP_PRI_REG(DSCP_MAX - 1) <
	      RTL8365MB_QOS_PORT_PRI_REG(0));

/* Priority-decision weight tables. In the driver's model of the decision
 * hardware, a source ranks by its highest set weight bit (a one-hot rank), not
 * by numeric magnitude. A weight of zero disables the source.
 */
#define RTL8365MB_QOS_WEIGHT_BITS			8
#define RTL8365MB_QOS_WEIGHTS_PER_REG			2
#define RTL8365MB_QOS_PRIDEC_TBL0_BASE			0x087b
#define RTL8365MB_QOS_PRIDEC_TBL1_BASE			0x0885
#define RTL8365MB_QOS_PRIDEC_REG(_t, _s) \
	(((_t) == RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED ? \
	  RTL8365MB_QOS_PRIDEC_TBL1_BASE : RTL8365MB_QOS_PRIDEC_TBL0_BASE) + \
	 (_s) / RTL8365MB_QOS_WEIGHTS_PER_REG)
#define RTL8365MB_QOS_PRIDEC_OFFSET(_s) \
	(((_s) % RTL8365MB_QOS_WEIGHTS_PER_REG) * RTL8365MB_QOS_WEIGHT_BITS)

static_assert(RTL8365MB_QOS_WEIGHT_BITS * RTL8365MB_QOS_WEIGHTS_PER_REG <=
	      RTL8365MB_QOS_REG_BITS);

/* In the driver's model, each port selects one of the two decision tables;
 * one bit per port.
 */
#define RTL8365MB_QOS_PRIDEC_TBL_SEL_REG		0x0889
#define RTL8365MB_QOS_PRIDEC_TABLE_UNTRUSTED		0
#define RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED		1

/* Priority-decision sources, in the hardware's numbering */
enum rtl8365mb_qos_pridec_src {
	RTL8365MB_QOS_PRIDEC_PORT = 0,
	RTL8365MB_QOS_PRIDEC_ACL = 1,
	RTL8365MB_QOS_PRIDEC_DSCP = 2,
	RTL8365MB_QOS_PRIDEC_1Q = 3,
	RTL8365MB_QOS_PRIDEC_SVLAN = 4,
	RTL8365MB_QOS_PRIDEC_CVLAN = 5,
	RTL8365MB_QOS_PRIDEC_DA = 6,
	RTL8365MB_QOS_PRIDEC_SA = 7,
	RTL8365MB_QOS_PRIDEC_NUM_SRC,
};

static_assert(RTL8365MB_QOS_PRIDEC_REG(RTL8365MB_QOS_PRIDEC_TABLE_UNTRUSTED,
				       RTL8365MB_QOS_PRIDEC_NUM_SRC - 1) <
	      RTL8365MB_QOS_PRIDEC_TBL1_BASE);
static_assert(RTL8365MB_QOS_PRIDEC_REG(RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED,
				       RTL8365MB_QOS_PRIDEC_NUM_SRC - 1) <
	      RTL8365MB_QOS_PRIDEC_TBL_SEL_REG);

/* Priority-decision weights. The baseline trusts only the port-based priority;
 * every other source is disabled (weight 0). The port default holds the lowest
 * one-hot rank, BIT(0).
 */
#define RTL8365MB_QOS_WEIGHT_DISABLED			0
#define RTL8365MB_QOS_WEIGHT_PORT			BIT(0)

static u32 rtl8365mb_qos_sel_mask(unsigned int idx)
{
	unsigned int off = RTL8365MB_QOS_SEL_OFFSET(idx);

	return GENMASK(off + RTL8365MB_QOS_SEL_BITS - 1, off);
}

/* Mask of the weight of priority-decision source @src in its register */
static u32 rtl8365mb_qos_weight_mask(unsigned int src)
{
	unsigned int off = RTL8365MB_QOS_PRIDEC_OFFSET(src);

	return GENMASK(off + RTL8365MB_QOS_WEIGHT_BITS - 1, off);
}

static int rtl8365mb_qos_regmap_update_field(struct realtek_priv *priv,
					     u32 reg, u32 mask, u32 val)
{
	return regmap_update_bits(priv->map, reg, mask, field_prep(mask, val));
}

/* Return the field value, or a negative errno if the register read fails */
static int rtl8365mb_qos_regmap_read_field(struct realtek_priv *priv,
					   u32 reg, u32 mask)
{
	u32 data;
	int ret;

	ret = regmap_read(priv->map, reg, &data);
	if (ret)
		return ret;

	return field_get(mask, data);
}

/* Unused ports carry no traffic; no per-port QoS request is made for them */
static int rtl8365mb_qos_check_port(struct realtek_priv *priv, int port)
{
	if (WARN_ON_ONCE(dsa_is_unused_port(&priv->ds, port)))
		return -EINVAL;

	return 0;
}

int rtl8365mb_qos_get_port_prio(struct realtek_priv *priv, int port)
{
	return rtl8365mb_qos_regmap_read_field(priv,
					       RTL8365MB_QOS_PORT_PRI_REG(port),
					       rtl8365mb_qos_sel_mask(port));
}

int rtl8365mb_qos_set_port_prio(struct realtek_priv *priv, int port, u8 iprio,
				u8 untag_pcp)
{
	u32 untag_reg = RTL8365MB_QOS_PORT_UNTAG_PCP_REG(port);
	u32 reg = RTL8365MB_QOS_PORT_PRI_REG(port);
	u32 mask = rtl8365mb_qos_sel_mask(port);
	int ret;

	ret = rtl8365mb_qos_check_port(priv, port);
	if (ret)
		return ret;

	ret = rtl8365mb_qos_regmap_update_field(priv, untag_reg, mask,
						untag_pcp);
	if (ret)
		return ret;

	return rtl8365mb_qos_regmap_update_field(priv, reg, mask, iprio);
}

int rtl8365mb_qos_set_pcp_prio(struct realtek_priv *priv, u8 pcp, u8 iprio)
{
	u32 reg = RTL8365MB_QOS_1Q_REMAP_REG(pcp);
	u32 mask = rtl8365mb_qos_sel_mask(pcp);

	return rtl8365mb_qos_regmap_update_field(priv, reg, mask, iprio);
}

int rtl8365mb_qos_set_dscp_prio(struct realtek_priv *priv, u8 dscp, u8 iprio)
{
	u32 reg = RTL8365MB_QOS_DSCP_PRI_REG(dscp);
	u32 mask = rtl8365mb_qos_sel_mask(dscp);

	return rtl8365mb_qos_regmap_update_field(priv, reg, mask, iprio);
}

static int rtl8365mb_qos_set_port_qmap(struct realtek_priv *priv, int port,
				       int qmap)
{
	u32 reg = RTL8365MB_QOS_PORT_QMAP_SEL_REG(port);
	/* Field value v selects qmap v - 1; 0 selects qmap 7 */
	u32 val = (qmap + 1) % RTL8365MB_QOS_NUM_QMAPS;
	u32 mask = rtl8365mb_qos_sel_mask(port);

	return rtl8365mb_qos_regmap_update_field(priv, reg, mask, val);
}

static int rtl8365mb_qos_set_qmap_qid(struct realtek_priv *priv, int qmap,
				      u8 iprio, u8 qid)
{
	u32 reg = RTL8365MB_QOS_QMAP_TBL_REG(qmap, iprio);
	u32 mask = rtl8365mb_qos_sel_mask(iprio);

	return rtl8365mb_qos_regmap_update_field(priv, reg, mask, qid);
}

/* At reset, qmap 0 uses only queue 0, and qmap k (1..6) uses queues 0..k-1 and
 * queue 7. Follow that layout: with more than one queue in use, map the top
 * traffic class to queue 7.
 */
#define RTL8365MB_QOS_QID_TOP				7

static u8 rtl8365mb_qos_tc_to_qid(unsigned int num_queues, u8 tc)
{
	if (num_queues > 1 && tc == num_queues - 1)
		return RTL8365MB_QOS_QID_TOP;

	return tc;
}

int rtl8365mb_qos_qmap_init(struct realtek_priv *priv)
{
	unsigned int nq = priv->ds.num_tx_queues;
	struct dsa_port *dp;
	int iprio, ret;

	for (iprio = 0; iprio < RTL8365MB_NUM_INTERNAL_PRIOS; iprio++) {
		int tc = ieee8021q_tt_to_tc(iprio, nq);
		u8 qid;

		if (tc < 0)
			return tc;

		qid = rtl8365mb_qos_tc_to_qid(nq, tc);
		ret = rtl8365mb_qos_set_qmap_qid(priv,
						 RTL8365MB_QOS_QMAP_DEFAULT,
						 iprio, qid);
		if (ret)
			return ret;
	}

	/* Unused ports carry no traffic; their select is left alone */
	dsa_switch_for_each_available_port(dp, &priv->ds) {
		ret = rtl8365mb_qos_set_port_qmap(priv, dp->index,
						  RTL8365MB_QOS_QMAP_DEFAULT);
		if (ret)
			return ret;
	}

	return 0;
}

static int rtl8365mb_qos_set_pridec(struct realtek_priv *priv, int table,
				    int src, u8 weight)
{
	u32 reg = RTL8365MB_QOS_PRIDEC_REG(table, src);
	u32 mask = rtl8365mb_qos_weight_mask(src);

	return rtl8365mb_qos_regmap_update_field(priv, reg, mask, weight);
}

/* Program every source in both tables rather than relying on the reset state */
int rtl8365mb_qos_pridec_init(struct realtek_priv *priv)
{
	int table, ret;

	for (table = RTL8365MB_QOS_PRIDEC_TABLE_UNTRUSTED;
	     table <= RTL8365MB_QOS_PRIDEC_TABLE_TRUSTED; table++) {
		int src;

		for (src = 0; src < RTL8365MB_QOS_PRIDEC_NUM_SRC; src++) {
			u8 weight = src == RTL8365MB_QOS_PRIDEC_PORT ?
				    RTL8365MB_QOS_WEIGHT_PORT :
				    RTL8365MB_QOS_WEIGHT_DISABLED;

			ret = rtl8365mb_qos_set_pridec(priv, table, src,
						       weight);
			if (ret)
				return ret;
		}
	}

	/* In the driver's model, a clear bit selects the untrusted table */
	return regmap_write(priv->map, RTL8365MB_QOS_PRIDEC_TBL_SEL_REG, 0);
}
