// SPDX-License-Identifier: GPL-2.0
/* Shared QoS and DCB logic for the Realtek DSA switch family
 *
 * Every classifier (port default, PCP, DSCP) yields an internal priority that
 * is an 802.1Q traffic type. dcbnl uses 802.1p priorities. An 802.1p priority
 * equals the PCP value in the default PCP decoding (IEEE 802.1Q-2022 6.9.3).
 * This layer converts at its edges: every priority it hands a backend is an
 * internal priority, except the 802.1p PCP given to untagged frames.
 *
 * The backend maps internal priorities to its egress queues itself.
 */

#include <linux/build_bug.h>
#include <linux/dcbnl.h>
#include <linux/errno.h>
#include <net/dscp.h>
#include <net/dsa.h>
#include <net/ieee8021q.h>

#include "realtek.h"
#include "rtl83xx-qos.h"

/* dcbnl selector of each apptrust slot */
static const u8 rtl83xx_apptrust_sel[] = {
	[RTL83XX_APPTRUST_DSCP]	= IEEE_8021QAZ_APP_SEL_DSCP,
	[RTL83XX_APPTRUST_PCP]	= DCB_APP_SEL_PCP,
};

static_assert(ARRAY_SIZE(rtl83xx_apptrust_sel) == RTL83XX_APPTRUST_COUNT);

static int rtl83xx_apptrust_sel_to_slot(u8 sel)
{
	int slot;

	for (slot = 0; slot < ARRAY_SIZE(rtl83xx_apptrust_sel); slot++)
		if (rtl83xx_apptrust_sel[slot] == sel)
			return slot;

	return -EINVAL;
}

/* Seed the PCP and DSCP tables, although neither source is trusted yet */
int rtl83xx_qos_init(struct dsa_switch *ds)
{
	struct realtek_priv *priv = ds->priv;
	int i, ret;

	if (!priv->ops->qos_set_pcp_prio || !priv->ops->qos_set_dscp_prio)
		return -EOPNOTSUPP;

	/* Map ingress PCP to the internal priority via its 802.1Q traffic type,
	 * so Best Effort (PCP 0) outranks Background (PCP 1).
	 */
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		int tt = ieee8021q_pcp_to_tt(i);

		if (tt < 0)
			return tt;

		ret = priv->ops->qos_set_pcp_prio(priv, i, tt);
		if (ret)
			return ret;
	}

	for (i = 0; i < DSCP_MAX; i++) {
		int tt = ietf_dscp_to_ieee8021q_tt(i);

		if (tt < 0)
			return tt;

		ret = priv->ops->qos_set_dscp_prio(priv, i, tt);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_NS_GPL(rtl83xx_qos_init, "REALTEK_DSA");

int rtl83xx_qos_init_port(struct dsa_switch *ds, int port)
{
	struct realtek_priv *priv = ds->priv;
	int untag_pcp;

	if (!priv->ops->qos_set_port_prio)
		return -EOPNOTSUPP;

	/* An unused port's priority is left alone */
	if (dsa_is_unused_port(ds, port))
		return 0;

	untag_pcp = ieee8021q_tt_to_pcp(IEEE8021Q_TT_BE);
	if (untag_pcp < 0)
		return untag_pcp;

	/* iprio is Best Effort, not 0, which is Background */
	return priv->ops->qos_set_port_prio(priv, port, IEEE8021Q_TT_BE,
					    untag_pcp);
}
EXPORT_SYMBOL_NS_GPL(rtl83xx_qos_init_port, "REALTEK_DSA");

int rtl83xx_port_get_default_prio(struct dsa_switch *ds, int port)
{
	struct realtek_priv *priv = ds->priv;
	int tt;

	if (!priv->ops->qos_get_port_prio)
		return -EOPNOTSUPP;

	tt = priv->ops->qos_get_port_prio(priv, port);
	if (tt < 0)
		return tt;

	return ieee8021q_tt_to_pcp(tt);
}
EXPORT_SYMBOL_NS_GPL(rtl83xx_port_get_default_prio, "REALTEK_DSA");

int rtl83xx_port_set_default_prio(struct dsa_switch *ds, int port, u8 prio)
{
	struct realtek_priv *priv = ds->priv;
	int tt;

	if (!priv->ops->qos_set_port_prio)
		return -EOPNOTSUPP;

	if (prio >= IEEE_8021Q_MAX_PRIORITIES)
		return -ERANGE;

	tt = ieee8021q_pcp_to_tt(prio);
	if (tt < 0)
		return tt;

	return priv->ops->qos_set_port_prio(priv, port, tt, prio);
}
EXPORT_SYMBOL_NS_GPL(rtl83xx_port_set_default_prio, "REALTEK_DSA");

int rtl83xx_port_get_apptrust(struct dsa_switch *ds, int port, u8 *sel,
			      int *nsel)
{
	bool trust[ARRAY_SIZE(rtl83xx_apptrust_sel)];
	struct realtek_priv *priv = ds->priv;
	int i, ret;

	if (!priv->ops->qos_get_apptrust)
		return -EOPNOTSUPP;

	ret = priv->ops->qos_get_apptrust(priv, port, trust,
					  ARRAY_SIZE(trust));
	if (ret)
		return ret;

	*nsel = 0;

	for (i = 0; i < ARRAY_SIZE(rtl83xx_apptrust_sel); i++)
		if (trust[i])
			sel[(*nsel)++] = rtl83xx_apptrust_sel[i];

	return 0;
}
EXPORT_SYMBOL_NS_GPL(rtl83xx_port_get_apptrust, "REALTEK_DSA");

int rtl83xx_port_set_apptrust(struct dsa_switch *ds, int port, const u8 *sel,
			      int nsel)
{
	bool trust[ARRAY_SIZE(rtl83xx_apptrust_sel)] = { };
	struct realtek_priv *priv = ds->priv;
	int i, prev = -1;

	if (!priv->ops->qos_set_apptrust)
		return -EOPNOTSUPP;

	/* The backends use a fixed precedence, so the selector list
	 * must follow the slot order.
	 */
	for (i = 0; i < nsel; i++) {
		int slot = rtl83xx_apptrust_sel_to_slot(sel[i]);

		if (slot < 0 || slot <= prev) {
			dev_err(priv->dev,
				"unsupported apptrust order; supported: dscp, pcp, dscp pcp\n");
			return -EOPNOTSUPP;
		}

		prev = slot;
		trust[slot] = true;
	}

	return priv->ops->qos_set_apptrust(priv, port, trust,
					   ARRAY_SIZE(trust));
}
EXPORT_SYMBOL_NS_GPL(rtl83xx_port_set_apptrust, "REALTEK_DSA");
