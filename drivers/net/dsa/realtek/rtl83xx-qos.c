// SPDX-License-Identifier: GPL-2.0
/* Shared QoS and DCB logic for the Realtek DSA switch family
 *
 * Every classifier (port default, PCP, DSCP) yields an internal priority that
 * is an 802.1Q traffic type. dcbnl uses 802.1p priorities. An 802.1p priority
 * equals the PCP value in the default PCP decoding (IEEE 802.1Q-2022 6.9.3).
 * This layer converts at its edges: every priority it hands a backend is an
 * internal priority.
 *
 * The backend maps internal priorities to its egress queues itself.
 */

#include <linux/dcbnl.h>
#include <linux/errno.h>
#include <net/dscp.h>
#include <net/dsa.h>
#include <net/ieee8021q.h>

#include "realtek.h"
#include "rtl83xx-qos.h"

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

	if (!priv->ops->qos_set_port_prio)
		return -EOPNOTSUPP;

	/* An unused port's priority is left alone */
	if (dsa_is_unused_port(ds, port))
		return 0;

	/* Best Effort, not internal priority 0, which is Background */
	return priv->ops->qos_set_port_prio(priv, port, IEEE8021Q_TT_BE);
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

	return priv->ops->qos_set_port_prio(priv, port, tt);
}
EXPORT_SYMBOL_NS_GPL(rtl83xx_port_set_default_prio, "REALTEK_DSA");
