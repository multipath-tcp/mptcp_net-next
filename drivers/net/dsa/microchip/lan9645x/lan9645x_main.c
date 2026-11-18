// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/platform_device.h>

#include "lan9645x_main.h"

static const char *lan9645x_resource_names[NUM_TARGETS] = {
	[TARGET_GCB]          = "gcb",
	[TARGET_QS]           = "qs",
	[TARGET_CHIP_TOP]     = "chip_top",
	[TARGET_REW]          = "rew",
	[TARGET_SYS]          = "sys",
	[TARGET_HSIO]         = "hsio",
	[TARGET_DEV + 0]      = "dev0",
	[TARGET_DEV + 1]      = "dev1",
	[TARGET_DEV + 2]      = "dev2",
	[TARGET_DEV + 3]      = "dev3",
	[TARGET_DEV + 4]      = "dev4",
	[TARGET_DEV + 5]      = "dev5",
	[TARGET_DEV + 6]      = "dev6",
	[TARGET_DEV + 7]      = "dev7",
	[TARGET_DEV + 8]      = "dev8",
	[TARGET_QSYS]         = "qsys",
	[TARGET_ANA]          = "ana",
};

static int lan9645x_tag_npi_setup(struct dsa_switch *ds)
{
	struct lan9645x *lan9645x = ds->priv;
	struct dsa_port *dp, *cpu_dp = NULL;
	struct phylink_config c = {};

	dsa_switch_for_each_cpu_port(dp, ds) {
		if (cpu_dp) {
			dev_err(ds->dev, "Multiple NPI ports not supported\n");
			return -EINVAL;
		}

		cpu_dp = dp;
	}

	if (!cpu_dp) {
		dev_err(ds->dev,
			"NPI port on a remote switch is not supported\n");
		return -EINVAL;
	}

	lan9645x_phylink_get_caps(lan9645x, cpu_dp->index, &c);
	if (phy_interface_empty(c.supported_interfaces)) {
		dev_err(ds->dev,
			"Port %d has no usable interface mode, cannot be NPI port\n",
			cpu_dp->index);
		return -EINVAL;
	}

	lan9645x_npi_port_init(lan9645x, cpu_dp);

	return 0;
}

static enum dsa_tag_protocol lan9645x_get_tag_protocol(struct dsa_switch *ds,
						       int port,
						       enum dsa_tag_protocol tp)
{
	return DSA_TAG_PROTO_LAN9645X;
}

static void lan9645x_teardown(struct dsa_switch *ds)
{
	struct lan9645x *lan9645x = ds->priv;

	lan9645x_npi_port_deinit(lan9645x, lan9645x->npi);
}

static int lan9645x_change_mtu(struct dsa_switch *ds, int port, int new_mtu)
{
	return lan9645x_port_set_maxlen(ds->priv, port, new_mtu);
}

static int lan9645x_get_max_mtu(struct dsa_switch *ds, int port)
{
	/* Actual MAC max MTU is around 16KB. We set 10000 - overhead which
	 * should be sufficient for all jumbo frames. Larger frames can cause
	 * problems especially with flow control, since we only have 160K queue
	 * buffer.
	 *
	 * DSA only asks for the user port limit, and adds the tag overhead
	 * back when it sizes the conduit MTU, so the CPU port is not a case
	 * here.
	 */
	return 10000 - ETH_HLEN - ETH_FCS_LEN;
}

static int lan9645x_reset_switch(struct lan9645x *lan9645x)
{
	u32 rst_cfg, val = 0;
	int err;

	/* The parent must reset the whole chip before instantiating its
	 * children, so the switch core is disabled when we get here. The
	 * sequence below must not run more than once: initializing the
	 * memories on a running core corrupts pointers inside the queue
	 * system, which eventually fills up and stops passing traffic. If the
	 * core is already enabled the chip was not reset, so skip it.
	 */
	err = regmap_read(lan_rmap(lan9645x, SYS_RESET_CFG),
			  lan_rel_addr(SYS_RESET_CFG), &rst_cfg);
	if (err)
		return err;

	if (SYS_RESET_CFG_CORE_ENA_GET(rst_cfg))
		return 0;

	lan_wr(SYS_RESET_CFG_CORE_ENA_SET(0), lan9645x, SYS_RESET_CFG);
	lan_wr(SYS_RAM_INIT_RAM_INIT_SET(1), lan9645x, SYS_RAM_INIT);
	err = lan9645x_rd_poll_timeout(lan9645x, SYS_RAM_INIT, val,
				       SYS_RAM_INIT_RAM_INIT_GET(val) == 0);
	if (err) {
		dev_err(lan9645x->dev, "Failed to init chip RAM.\n");
		return err;
	}
	lan_wr(SYS_RESET_CFG_CORE_ENA_SET(1), lan9645x, SYS_RESET_CFG);

	return 0;
}

static int lan9645x_setup(struct dsa_switch *ds)
{
	struct lan9645x *lan9645x = ds->priv;
	struct device *dev = lan9645x->dev;
	u32 front_ports, res_wm;
	int supported, used = 0;
	struct dsa_port *dp;
	int err;

	lan9645x->num_phys_ports = ds->num_ports;
	front_ports = dsa_user_ports(ds);
	supported = lan9645x->num_phys_ports - lan9645x->num_port_dis;

	dsa_switch_for_each_available_port(dp, ds)
		used++;

	if (used > supported) {
		dev_err(ds->dev,
			"%d physical ports in use in DT, SKU supports at most %d\n",
			used, supported);
		return -EINVAL;
	}

	err = lan9645x_reset_switch(lan9645x);
	if (err)
		return err;

	err = lan9645x_tag_npi_setup(ds);
	if (err) {
		dev_err(dev, "Failed to setup NPI port.\n");
		return err;
	}

	/* Link Aggregation Mode: NETDEV_LAG_HASH_L2 */
	lan_wr(ANA_AGGR_CFG_AC_SMAC_ENA |
	       ANA_AGGR_CFG_AC_DMAC_ENA,
	       lan9645x, ANA_AGGR_CFG);

	/* Flush queues */
	lan_wr(GENMASK(1, 0), lan9645x, QS_XTR_FLUSH);

	/* Allow to drain */
	usleep_range(1000, 2000);

	/* All Queues normal */
	lan_wr(0x0, lan9645x, QS_XTR_FLUSH);

	/* Set MAC age time to default value, the entry is aged after
	 * 2 * AGE_PERIOD
	 */
	lan_wr(ANA_AUTOAGE_AGE_PERIOD_SET(BR_DEFAULT_AGEING_TIME / 2 / HZ),
	       lan9645x, ANA_AUTOAGE);

	/* Disable learning for frames discarded by VLAN ingress filtering */
	lan_rmw(ANA_ADVLEARN_VLAN_CHK_SET(1),
		ANA_ADVLEARN_VLAN_CHK,
		lan9645x, ANA_ADVLEARN);

	/* Queue system frame ageing. We target 2s ageing.
	 *
	 * Register unit is 1024 cycles.
	 *
	 * ASIC: 165.625 Mhz  ~ 6.0377 ns period
	 *
	 * 1024 * 6.0377 ns =~ 6182 ns
	 * val = 2000000000ns / 6182ns
	 */
	lan_wr(SYS_FRM_AGING_AGE_TX_ENA_SET(1) |
	       SYS_FRM_AGING_MAX_AGE_SET((2000000000 / 6182)),
	       lan9645x,  SYS_FRM_AGING);

	/* Setup flooding PGIDs for IPv4/IPv6 multicast. Control and dataplane
	 * use the same masks. Control frames are redirected to CPU, and
	 * the network stack is responsible for forwarding these.
	 * The dataplane is forwarding according to the offloaded MDB entries.
	 */
	lan_wr(ANA_FLOODING_IPMC_FLD_MC4_DATA_SET(PGID_MCIPV4) |
	       ANA_FLOODING_IPMC_FLD_MC4_CTRL_SET(PGID_MC) |
	       ANA_FLOODING_IPMC_FLD_MC6_DATA_SET(PGID_MCIPV6) |
	       ANA_FLOODING_IPMC_FLD_MC6_CTRL_SET(PGID_MC),
	       lan9645x, ANA_FLOODING_IPMC);

	for (int prio = 0; prio < NUM_PRIO_QUEUES; ++prio)
		lan_wr(ANA_FLOODING_FLD_MULTICAST_SET(PGID_MC) |
		       ANA_FLOODING_FLD_UNICAST_SET(PGID_UC) |
		       ANA_FLOODING_FLD_BROADCAST_SET(PGID_BC),
		       lan9645x, ANA_FLOODING(prio));

	/* Allow VLAN table to control whether cpu copy from the pgid table is
	 * enabled. Only the destination analysis resolves a CPU copy, so the
	 * aggregation and source regions are left at their reset value.
	 */
	for (int i = 0; i < PGID_AGGR; ++i)
		lan_wr(ANA_PGID_CFG_OBEY_VLAN_SET(1),
		       lan9645x, ANA_PGID_CFG(i));

	/* Disable bridging by default */
	for (int p = 0; p < lan9645x->num_phys_ports; p++) {
		lan_wr(0, lan9645x, ANA_PGID(PGID_SRC + p));

		/* Do not forward BPDU frames to the front ports and trap them
		 * to CPU
		 */
		lan_wr(ANA_CPU_FWD_BPDU_CFG_BPDU_REDIR_ENA,
		       lan9645x, ANA_CPU_FWD_BPDU_CFG(p));
	}

	for (int i = 0; i < 16; i++) {
		/* The register instance number corresponds to the
		 * address of the extracted frame. For instance:
		 * CPUQ_8021_CFG[4].CPUQ_BPDU_VAL
		 * is the cpu extraction queue used for BPDU frames
		 * with address 01-80-C2-00-00-04
		 */
		lan_rmw(ANA_CPUQ_8021_CFG_CPUQ_BPDU_VAL_SET(LAN9645X_CPUQ_TRAP),
			ANA_CPUQ_8021_CFG_CPUQ_BPDU_VAL,
			lan9645x, ANA_CPUQ_8021_CFG(i));
	}

	/* Reserve 1664 bytes, 26 buffer cells, per (port, prio) for source
	 * tracking (resource 0, indices 0..95) and destination tracking
	 * (resource 2, indices 512..607). These are access watermarks, not
	 * pre-allocations: a flow draws from its reservation first, then
	 * from the shared pool. Keeping the reservation above a max-size
	 * Ethernet frame prevents a single frame from spilling into the
	 * shared pool, and cause pause frames to be emitted without actual
	 * congestion.
	 */
	res_wm = QSYS_RES_CFG_WM_HIGH_SET(lan9645x_wm_enc(QS_SRC_BUF_RSV));
	for (int i = 0; i <= QSYS_Q_RSRV; ++i) {
		lan_wr(res_wm, lan9645x, QSYS_RES_CFG(i));
		lan_wr(res_wm, lan9645x, QSYS_RES_CFG(512 + i));
	}

	lan9645x_port_cpu_init(lan9645x);

	/* Multicast to cpu and all front ports */
	lan_wr(BIT(lan9645x->num_phys_ports) | front_ports, lan9645x,
	       ANA_PGID(PGID_MC));

	/* IP multicast to cpu and all front ports */
	lan_wr(BIT(lan9645x->num_phys_ports) | front_ports, lan9645x,
	       ANA_PGID(PGID_MCIPV4));
	lan_wr(BIT(lan9645x->num_phys_ports) | front_ports, lan9645x,
	       ANA_PGID(PGID_MCIPV6));

	/* Unicast to cpu and all front ports */
	lan_wr(BIT(lan9645x->num_phys_ports) | front_ports, lan9645x,
	       ANA_PGID(PGID_UC));

	/* Broadcast to cpu and all front ports */
	lan_wr(BIT(lan9645x->num_phys_ports) | front_ports, lan9645x,
	       ANA_PGID(PGID_BC));

	ds->mtu_enforcement_ingress = true;

	dev_info(lan9645x->dev,
		 "SKU features: max_ports=%d\n",
		 lan9645x->num_phys_ports - lan9645x->num_port_dis);

	return 0;
}

static void lan9645x_port_phylink_get_caps(struct dsa_switch *ds, int port,
					   struct phylink_config *config)
{
	lan9645x_phylink_get_caps(ds->priv, port, config);
}

static const struct dsa_switch_ops lan9645x_switch_ops = {
	.get_tag_protocol		= lan9645x_get_tag_protocol,

	.setup				= lan9645x_setup,
	.teardown			= lan9645x_teardown,
	.port_setup			= lan9645x_port_setup,

	/* Phylink integration */
	.phylink_get_caps		= lan9645x_port_phylink_get_caps,

	/* MTU  */
	.port_change_mtu		= lan9645x_change_mtu,
	.port_max_mtu			= lan9645x_get_max_mtu,
};

static int lan9645x_request_target_regmaps(struct lan9645x *lan9645x)
{
	const char *resource_name;
	struct regmap *tgt_map;

	for (int i = 0; i < NUM_TARGETS; i++) {
		resource_name = lan9645x_resource_names[i];
		if (!resource_name)
			continue;

		tgt_map = dev_get_regmap(lan9645x->dev->parent, resource_name);
		if (!tgt_map) {
			dev_err(lan9645x->dev, "Failed to get regmap=%s\n",
				resource_name);
			return -ENODEV;
		}

		lan9645x->rmap[i] = tgt_map;
	}

	return 0;
}

static int lan9645x_set_feat_dis(struct lan9645x *lan9645x)
{
	u32 feat_dis;
	int err;

	/* The features which can be physically disabled on some SKUs are:
	 * 1) Number of ports can be 5, 7 or 9. Any ports can be used, the chip
	 *    tracks how many are active.
	 * 2) HSR/PRP. The duplicate discard table can be disabled.
	 * 3) TAS, frame preemption and PSFP can be disabled.
	 */
	err = regmap_read(lan_rmap(lan9645x, GCB_FEAT_DISABLE),
			  lan_rel_addr(GCB_FEAT_DISABLE), &feat_dis);
	if (err)
		return err;

	lan9645x->num_port_dis =
		GCB_FEAT_DISABLE_FEAT_NUM_PORTS_DIS_GET(feat_dis);

	return 0;
}

static int lan9645x_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct lan9645x *lan9645x;
	struct dsa_switch *ds;
	int err = 0;

	lan9645x = devm_kzalloc(dev, sizeof(*lan9645x), GFP_KERNEL);
	if (!lan9645x)
		return -ENOMEM;

	dev_set_drvdata(dev, lan9645x);
	lan9645x->dev = dev;

	err = lan9645x_request_target_regmaps(lan9645x);
	if (err)
		return dev_err_probe(dev, err, "Failed to request regmaps\n");

	ds = devm_kzalloc(dev, sizeof(*ds), GFP_KERNEL);
	if (!ds)
		return -ENOMEM;

	lan9645x->ports = devm_kcalloc(lan9645x->dev, NUM_PHYS_PORTS,
				       sizeof(struct lan9645x_port *),
				       GFP_KERNEL);
	if (!lan9645x->ports)
		return -ENOMEM;

	for (int port = 0; port < NUM_PHYS_PORTS; port++) {
		struct lan9645x_port *p;

		p = devm_kzalloc(lan9645x->dev, sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;

		p->lan9645x = lan9645x;
		p->chip_port = port;
		lan9645x->ports[port] = p;
	}

	ds->dev = dev;
	ds->num_ports = NUM_PHYS_PORTS;
	ds->num_tx_queues = NUM_PRIO_QUEUES;

	ds->ops = &lan9645x_switch_ops;
	ds->phylink_mac_ops = &lan9645x_phylink_mac_ops;
	ds->priv = lan9645x;

	lan9645x->ds = ds;
	lan9645x->npi = -1;

	err = lan9645x_set_feat_dis(lan9645x);
	if (err)
		return dev_err_probe(dev, err, "Failed to read SKU features\n");

	err = dsa_register_switch(ds);
	if (err)
		return dev_err_probe(dev, err,
				     "Failed to register DSA switch\n");

	return 0;
}

static void lan9645x_remove(struct platform_device *pdev)
{
	struct lan9645x *lan9645x = dev_get_drvdata(&pdev->dev);

	if (!lan9645x)
		return;

	/* Calls lan9645x DSA .teardown */
	dsa_unregister_switch(lan9645x->ds);
	dev_set_drvdata(&pdev->dev, NULL);
}

static void lan9645x_shutdown(struct platform_device *pdev)
{
	struct lan9645x *lan9645x = dev_get_drvdata(&pdev->dev);

	if (!lan9645x)
		return;

	dsa_switch_shutdown(lan9645x->ds);

	dev_set_drvdata(&pdev->dev, NULL);
}

static const struct of_device_id lan9645x_switch_of_match[] = {
	{ .compatible = "microchip,lan96455s-switch" },
	{},
};
MODULE_DEVICE_TABLE(of, lan9645x_switch_of_match);

static struct platform_driver lan9645x_switch_driver = {
	.driver = {
		.name = "lan96455s-switch",
		.of_match_table = lan9645x_switch_of_match,
	},
	.probe = lan9645x_probe,
	.remove = lan9645x_remove,
	.shutdown = lan9645x_shutdown,
};
module_platform_driver(lan9645x_switch_driver);

MODULE_DESCRIPTION("LAN9645x Switch Driver");
MODULE_AUTHOR("Jens Emil Schulz Østergaard <jensemil.schulzostergaard@microchip.com>");
MODULE_LICENSE("GPL");
