// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/of_net.h>

#include "lan9645x_main.h"

void lan9645x_port_cpu_init(struct lan9645x *lan9645x)
{
	u32 cpu_module_mask = BIT(lan9645x->num_phys_ports);

	/* Map the 8 CPU extraction queues to the CPU port module (datasheet is
	 * wrong)
	 */
	lan_wr(0, lan9645x, QSYS_CPU_GROUP_MAP);

	/* Configure first cpu port for manual extraction. */
	lan_rmw(QS_XTR_GRP_CFG_MODE_SET(1),
		QS_XTR_GRP_CFG_MODE,
		lan9645x, QS_XTR_GRP_CFG(0));

	/* The CPU will only use its reserved buffer in the shared queue system
	 * and none of the shared buffer space, therefore we disable resource
	 * sharing in egress direction. We must not disable resource sharing in
	 * the ingress direction, because some traffic test scenarios require
	 * loads of buffer memory for frames initiated by the CPU.
	 */
	lan_rmw(QSYS_EGR_NO_SHARING_EGR_NO_SHARING_SET(cpu_module_mask),
		QSYS_EGR_NO_SHARING_EGR_NO_SHARING_SET(cpu_module_mask),
		lan9645x, QSYS_EGR_NO_SHARING);

	/* The CPU should also discard frames forwarded to it if it has run
	 * out of the reserved buffer space. Otherwise they will be held back
	 * in the ingress queues with potential head-of-line blocking effects.
	 */
	lan_rmw(QSYS_EGR_DROP_MODE_EGRESS_DROP_MODE_SET(cpu_module_mask),
		QSYS_EGR_DROP_MODE_EGRESS_DROP_MODE_SET(cpu_module_mask),
		lan9645x, QSYS_EGR_DROP_MODE);

	lan_wr(cpu_module_mask, lan9645x, ANA_PGID(PGID_CPU));

	/* Enable switching to/from cpu port. Keep default aging-mode. */
	lan_rmw(QSYS_SW_PORT_MODE_PORT_ENA_SET(1) |
		QSYS_SW_PORT_MODE_SCH_NEXT_CFG_SET(1) |
		QSYS_SW_PORT_MODE_INGRESS_DROP_MODE_SET(1),
		QSYS_SW_PORT_MODE_PORT_ENA |
		QSYS_SW_PORT_MODE_SCH_NEXT_CFG |
		QSYS_SW_PORT_MODE_INGRESS_DROP_MODE,
		lan9645x, QSYS_SW_PORT_MODE(lan9645x->num_phys_ports));
}

/* VLAN tag overhead is handled by DEV_MAC_TAGS_CFG */
int lan9645x_port_set_maxlen(struct lan9645x *lan9645x, int port, size_t sdu)
{
	struct lan9645x_port *p = lan9645x_to_port(lan9645x, port);
	int maxlen = sdu + ETH_HLEN + ETH_FCS_LEN;

	if (port == lan9645x->npi) {
		maxlen += LAN9645X_IFH_LEN_BYTES;
		maxlen += LAN9645X_LONG_PREFIX_LEN;
	}

	lan_wr(DEV_MAC_MAXLEN_CFG_MAX_LEN_SET(maxlen), lan9645x,
	       DEV_MAC_MAXLEN_CFG(p->chip_port));

	/* Set Pause WM hysteresis */
	lan_rmw(SYS_PAUSE_CFG_PAUSE_STOP_SET(lan9645x_wm_enc(4 * maxlen)) |
		SYS_PAUSE_CFG_PAUSE_START_SET(lan9645x_wm_enc(6 * maxlen)),
		SYS_PAUSE_CFG_PAUSE_START |
		SYS_PAUSE_CFG_PAUSE_STOP,
		lan9645x,
		SYS_PAUSE_CFG(p->chip_port));

	return 0;
}

static void lan9645x_parse_mac_delay(struct lan9645x *lan9645x, int port,
				     struct device_node *dn, const char *name,
				     bool *out)
{
	u32 val;

	if (of_property_read_u32(dn, name, &val))
		return;

	if (val != 0 && val != 2000) {
		dev_warn(lan9645x->dev,
			 "port %d: %s only supports a 2ns delay (on/off), got %u ps\n",
			 port, name, val);
		return;
	}

	*out = val == 2000;
}

int lan9645x_port_setup(struct dsa_switch *ds, int port)
{
	struct dsa_port *dp = dsa_to_port(ds, port);
	struct lan9645x *lan9645x = ds->priv;
	struct lan9645x_port *p;

	p = lan9645x_to_port(lan9645x, port);

	if (dp->dn) {
		lan9645x_parse_mac_delay(lan9645x, port, dp->dn,
					 "rx-internal-delay-ps",
					 &p->rx_internal_delay);

		lan9645x_parse_mac_delay(lan9645x, port, dp->dn,
					 "tx-internal-delay-ps",
					 &p->tx_internal_delay);
	}

	/* Disable learning on port */
	lan_rmw(ANA_PORT_CFG_LEARN_ENA_SET(0),
		ANA_PORT_CFG_LEARN_ENA,
		lan9645x, ANA_PORT_CFG(p->chip_port));

	lan9645x_port_set_maxlen(lan9645x, port, ETH_DATA_LEN);

	/* Load HDX backoff seed (fixed per-port, one-shot strobe) */
	lan_rmw(DEV_MAC_HDX_CFG_SEED_SET(p->chip_port) |
		DEV_MAC_HDX_CFG_SEED_LOAD_SET(1),
		DEV_MAC_HDX_CFG_SEED |
		DEV_MAC_HDX_CFG_SEED_LOAD, lan9645x,
		DEV_MAC_HDX_CFG(p->chip_port));

	lan_rmw(DEV_MAC_HDX_CFG_SEED_LOAD_SET(0),
		DEV_MAC_HDX_CFG_SEED_LOAD, lan9645x,
		DEV_MAC_HDX_CFG(p->chip_port));

	/* Set SMAC of Pause frame (00:00:00:00:00:00) */
	lan_wr(0, lan9645x, DEV_FC_MAC_LOW_CFG(p->chip_port));
	lan_wr(0, lan9645x, DEV_FC_MAC_HIGH_CFG(p->chip_port));

	lan9645x_phylink_port_down(lan9645x, port);

	/* Drop frames with multicast source address */
	lan_rmw(ANA_DROP_CFG_DROP_MC_SMAC_ENA_SET(1),
		ANA_DROP_CFG_DROP_MC_SMAC_ENA, lan9645x,
		ANA_DROP_CFG(p->chip_port));

	lan_rmw(DEV_MAC_TAGS_CFG_VLAN_AWR_ENA_SET(1) |
		DEV_MAC_TAGS_CFG_PB_ENA_SET(1) |
		DEV_MAC_TAGS_CFG_VLAN_LEN_AWR_ENA_SET(1) |
		DEV_MAC_TAGS_CFG_TAG_ID_SET(ETH_P_8021AD),
		DEV_MAC_TAGS_CFG_VLAN_AWR_ENA |
		DEV_MAC_TAGS_CFG_PB_ENA |
		DEV_MAC_TAGS_CFG_VLAN_LEN_AWR_ENA |
		DEV_MAC_TAGS_CFG_TAG_ID,
		lan9645x, DEV_MAC_TAGS_CFG(p->chip_port));

	/* Enable receiving frames on the port, and activate auto-learning of
	 * MAC addresses. LEARNAUTO is ignored when LEARN_ENA=0.
	 */
	lan_rmw(ANA_PORT_CFG_LEARNAUTO_SET(1) |
		ANA_PORT_CFG_RECV_ENA_SET(1) |
		ANA_PORT_CFG_PORTID_VAL_SET(p->chip_port),
		ANA_PORT_CFG_LEARNAUTO |
		ANA_PORT_CFG_RECV_ENA |
		ANA_PORT_CFG_PORTID_VAL,
		lan9645x, ANA_PORT_CFG(p->chip_port));

	return 0;
}
