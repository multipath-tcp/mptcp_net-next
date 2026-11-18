// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#include <linux/phy.h>

#include "lan9645x_main.h"

/* Port 7 is RGMII_0 and port 8 is RGMII_1 */
#define RGMII_IDX(port) ((port) == 8 ? 1 : 0)

void lan9645x_phylink_get_caps(struct lan9645x *lan9645x, int port,
			       struct phylink_config *c)
{
	c->mac_capabilities = MAC_ASYM_PAUSE | MAC_SYM_PAUSE | MAC_10 |
			      MAC_100 | MAC_1000FD;

	switch (port) {
	case 0 ... 4:
		__set_bit(PHY_INTERFACE_MODE_GMII, c->supported_interfaces);
		break;
	case 5 ... 6:
		/* SerDes ports: QSGMII/SGMII/1000BASEX/2500BASEX modes
		 * require PCS support which is not yet implemented. With an
		 * empty supported_interfaces, phylink_create() fails and
		 * dsa_tree_setup_ports() retries the port as unused, so a
		 * user port declared in DT is only disabled. A CPU port has
		 * no such fallback and fails the probe, which
		 * lan9645x_tag_npi_setup() rejects explicitly.
		 */
		break;
	case 7 ... 8:
		/* QSGMII mode on ports 7-8 requires SerDes PCS support,
		 * which is not yet implemented.
		 */
		phy_interface_set_rgmii(c->supported_interfaces);
		break;
	default:
		break;
	}
}

static void lan9645x_rgmii_set_speed(struct lan9645x *lan9645x, int port,
				     int speed)
{
	u8 tx_clk;

	tx_clk = speed == SPEED_1000 ? 1 :
		 speed == SPEED_100  ? 2 :
		 speed == SPEED_10   ? 3 : 0;

	lan_rmw(HSIO_RGMII_CFG_RGMII_RX_RST_SET(0) |
		HSIO_RGMII_CFG_RGMII_TX_RST_SET(0) |
		HSIO_RGMII_CFG_TX_CLK_CFG_SET(tx_clk),
		HSIO_RGMII_CFG_RGMII_RX_RST |
		HSIO_RGMII_CFG_RGMII_TX_RST |
		HSIO_RGMII_CFG_TX_CLK_CFG,
		lan9645x, HSIO_RGMII_CFG(RGMII_IDX(port)));
}

static void lan9645x_rgmii_dll_config(struct lan9645x_port *p)
{
	u32 rx_idx, tx_idx;

	/* DLL register layout:
	 * (N*2):   RGMII_N_RX
	 * (N*2)+1: RGMII_N_TX
	 */
	rx_idx = RGMII_IDX(p->chip_port) * 2;
	tx_idx = RGMII_IDX(p->chip_port) * 2 + 1;

	/* Enable DLL in RGMII clock paths, deassert DLL reset, and start the
	 * delay tune FSM.
	 */
	lan_rmw(HSIO_DLL_CFG_DLL_CLK_ENA_SET(1) |
		HSIO_DLL_CFG_DLL_RST_SET(0) |
		HSIO_DLL_CFG_DLL_ENA_SET(p->rx_internal_delay) |
		HSIO_DLL_CFG_DELAY_ENA_SET(p->rx_internal_delay),
		HSIO_DLL_CFG_DLL_CLK_ENA |
		HSIO_DLL_CFG_DLL_RST |
		HSIO_DLL_CFG_DLL_ENA |
		HSIO_DLL_CFG_DELAY_ENA,
		p->lan9645x, HSIO_DLL_CFG(rx_idx));

	lan_rmw(HSIO_DLL_CFG_DLL_CLK_ENA_SET(1) |
		HSIO_DLL_CFG_DLL_RST_SET(0) |
		HSIO_DLL_CFG_DLL_ENA_SET(p->tx_internal_delay) |
		HSIO_DLL_CFG_DELAY_ENA_SET(p->tx_internal_delay),
		HSIO_DLL_CFG_DLL_CLK_ENA |
		HSIO_DLL_CFG_DLL_RST |
		HSIO_DLL_CFG_DLL_ENA |
		HSIO_DLL_CFG_DELAY_ENA,
		p->lan9645x, HSIO_DLL_CFG(tx_idx));
}

static struct lan9645x_port *
lan9645x_phylink_config_to_port(struct phylink_config *config)
{
	struct dsa_port *dp = dsa_phylink_to_port(config);

	return lan9645x_to_port(dp->ds->priv, dp->index);
}

static int lan9645x_phylink_mac_prepare(struct phylink_config *config,
					unsigned int mode,
					phy_interface_t iface)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);
	struct lan9645x *lan9645x = p->lan9645x;
	int port = p->chip_port;

	lan_rmw(HSIO_HW_CFG_GMII_ENA_SET(BIT(port)),
		HSIO_HW_CFG_GMII_ENA_SET(BIT(port)), lan9645x, HSIO_HW_CFG);

	return 0;
}

static void lan9645x_phylink_mac_config(struct phylink_config *config,
					unsigned int mode,
					const struct phylink_link_state *state)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);

	if (phy_interface_mode_is_rgmii(state->interface))
		lan9645x_rgmii_dll_config(p);
}

static bool lan9645x_port_is_cuphy(int port, phy_interface_t interface)
{
	return port >= 0 && port <= 4 && interface == PHY_INTERFACE_MODE_GMII;
}

void lan9645x_phylink_port_down(struct lan9645x *lan9645x, int port)
{
	struct lan9645x_port *p = lan9645x_to_port(lan9645x, port);

	/* Disable traffic being sent to or from switch port */
	lan_rmw(QSYS_SW_PORT_MODE_PORT_ENA_SET(0),
		QSYS_SW_PORT_MODE_PORT_ENA,
		lan9645x, QSYS_SW_PORT_MODE(p->chip_port));

	/* With MAC_TX_RST and MAC_RX_RST asserted, the queue system treats
	 * the MAC as accepting every frame, so the frames queued to the port
	 * are discarded also when the MAC cannot transmit them, for example
	 * when the PHY is powered down or the MAC is held by a received pause
	 * frame. PORT_RST resets the FIFOs between the system and MAC clock
	 * domains, and asserting it while they still hold frames hangs the
	 * port, so it is kept deasserted.
	 */
	lan_rmw(DEV_CLOCK_CFG_MAC_TX_RST_SET(1) |
		DEV_CLOCK_CFG_MAC_RX_RST_SET(1) |
		DEV_CLOCK_CFG_PORT_RST_SET(0),
		DEV_CLOCK_CFG_MAC_TX_RST |
		DEV_CLOCK_CFG_MAC_RX_RST |
		DEV_CLOCK_CFG_PORT_RST,
		lan9645x, DEV_CLOCK_CFG(p->chip_port));
}

static void lan9645x_phylink_mac_link_down(struct phylink_config *config,
					   unsigned int link_an_mode,
					   phy_interface_t interface)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);
	struct lan9645x *lan9645x = p->lan9645x;

	/* Stop forwarding all CPU queues to the NPI port before the port is put
	 * in reset
	 */
	if (p->chip_port == lan9645x->npi)
		lan9645x_npi_cpuq_redirect(lan9645x, false);

	lan9645x_phylink_port_down(lan9645x, p->chip_port);
}

static void lan9645x_phylink_mac_link_up(struct phylink_config *config,
					 struct phy_device *phydev,
					 unsigned int link_an_mode,
					 phy_interface_t interface, int speed,
					 int duplex, bool tx_pause,
					 bool rx_pause)
{
	struct lan9645x_port *p = lan9645x_phylink_config_to_port(config);
	int rx_ifg1, rx_ifg2, tx_ifg, gtx_clk = 0;
	struct lan9645x *lan9645x = p->lan9645x;
	int gspeed = LAN9645X_SPEED_DISABLED;
	int port = p->chip_port;
	int mode = 0;
	int fc_spd;
	bool fdx;

	/* Configure RGMII TX clock for the negotiated speed */
	if (phy_interface_mode_is_rgmii(interface))
		lan9645x_rgmii_set_speed(lan9645x, port, speed);

	fdx = duplex == DUPLEX_FULL || speed == SPEED_1000;

	if (fdx)
		mode |= DEV_MAC_MODE_CFG_FDX_ENA_SET(1);

	tx_ifg = fdx ? 0x6 : 0x5;
	rx_ifg2 = 0x2;

	switch (speed) {
	case SPEED_10:
		rx_ifg1 = 0x2;
		gspeed = LAN9645X_SPEED_10;
		break;
	case SPEED_100:
		rx_ifg1 = 0x1;
		gspeed = LAN9645X_SPEED_100;
		break;
	case SPEED_1000:
		gspeed = LAN9645X_SPEED_1000;
		mode |= DEV_MAC_MODE_CFG_GIGA_MODE_ENA_SET(1);
		rx_ifg1 = 0x1;
		gtx_clk = 1;
		break;
	default:
		dev_err(lan9645x->dev, "Unsupported speed on port %d: %d\n",
			p->chip_port, speed);
		return;
	}

	fc_spd = lan9645x_speed_fc_enc(gspeed);

	lan_rmw(mode,
		DEV_MAC_MODE_CFG_FDX_ENA |
		DEV_MAC_MODE_CFG_GIGA_MODE_ENA,
		lan9645x, DEV_MAC_MODE_CFG(p->chip_port));

	lan_rmw(DEV_MAC_IFG_CFG_TX_IFG_SET(tx_ifg) |
		DEV_MAC_IFG_CFG_RX_IFG1_SET(rx_ifg1) |
		DEV_MAC_IFG_CFG_RX_IFG2_SET(rx_ifg2),
		DEV_MAC_IFG_CFG_TX_IFG |
		DEV_MAC_IFG_CFG_RX_IFG1 |
		DEV_MAC_IFG_CFG_RX_IFG2,
		lan9645x, DEV_MAC_IFG_CFG(p->chip_port));

	if (lan9645x_port_is_cuphy(port, interface)) {
		lan_rmw(CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA_SET(gtx_clk),
			CHIP_TOP_CUPHY_PORT_CFG_GTX_CLK_ENA, lan9645x,
			CHIP_TOP_CUPHY_PORT_CFG(p->chip_port));
	}

	lan_rmw(SYS_PAUSE_CFG_PAUSE_ENA_SET(1),
		SYS_PAUSE_CFG_PAUSE_ENA,
		lan9645x, SYS_PAUSE_CFG(p->chip_port));

	/* Flow control */
	lan_rmw(SYS_MAC_FC_CFG_FC_LINK_SPEED_SET(fc_spd) |
		SYS_MAC_FC_CFG_FC_LATENCY_CFG_SET(0x7) |
		SYS_MAC_FC_CFG_ZERO_PAUSE_ENA_SET(1) |
		SYS_MAC_FC_CFG_PAUSE_VAL_CFG_SET(0xffff) |
		SYS_MAC_FC_CFG_RX_FC_ENA_SET(rx_pause ? 1 : 0) |
		SYS_MAC_FC_CFG_TX_FC_ENA_SET(tx_pause ? 1 : 0),
		SYS_MAC_FC_CFG_FC_LINK_SPEED |
		SYS_MAC_FC_CFG_FC_LATENCY_CFG |
		SYS_MAC_FC_CFG_ZERO_PAUSE_ENA |
		SYS_MAC_FC_CFG_PAUSE_VAL_CFG |
		SYS_MAC_FC_CFG_RX_FC_ENA |
		SYS_MAC_FC_CFG_TX_FC_ENA,
		lan9645x, SYS_MAC_FC_CFG(p->chip_port));

	/* Enable MAC module */
	lan_wr(DEV_MAC_ENA_CFG_RX_ENA_SET(1) |
	       DEV_MAC_ENA_CFG_TX_ENA_SET(1),
	       lan9645x, DEV_MAC_ENA_CFG(p->chip_port));

	/* Take out the clock from reset. Note this write will set all these
	 * fields to zero:
	 *
	 * DEV_CLOCK_CFG[*].MAC_TX_RST
	 * DEV_CLOCK_CFG[*].MAC_RX_RST
	 * DEV_CLOCK_CFG[*].PCS_TX_RST
	 * DEV_CLOCK_CFG[*].PCS_RX_RST
	 * DEV_CLOCK_CFG[*].PORT_RST
	 * DEV_CLOCK_CFG[*].PHY_RST
	 *
	 * Note link_down will assert MAC_RX_RST and MAC_TX_RST, so
	 * we are effectively taking the mac tx/rx clocks out of reset.
	 *
	 * This linkspeed field has a slightly different encoding from others:
	 *
	 * - 0 is no-link
	 * - 1 is both 2500/1000
	 * - 2 is 100mbit
	 * - 3 is 10mbit
	 *
	 */
	lan_wr(DEV_CLOCK_CFG_LINK_SPEED_SET(fc_spd),
	       lan9645x,
	       DEV_CLOCK_CFG(p->chip_port));

	/* Core: Enable port for frame transfer */
	lan_rmw(QSYS_SW_PORT_MODE_PORT_ENA_SET(1) |
		QSYS_SW_PORT_MODE_SCH_NEXT_CFG_SET(1) |
		QSYS_SW_PORT_MODE_INGRESS_DROP_MODE_SET(1) |
		QSYS_SW_PORT_MODE_TX_PFC_ENA_SET(0),
		QSYS_SW_PORT_MODE_PORT_ENA |
		QSYS_SW_PORT_MODE_SCH_NEXT_CFG |
		QSYS_SW_PORT_MODE_INGRESS_DROP_MODE |
		QSYS_SW_PORT_MODE_TX_PFC_ENA,
		lan9645x, QSYS_SW_PORT_MODE(p->chip_port));

	/* Forward all CPU queues to the NPI port */
	if (port == lan9645x->npi)
		lan9645x_npi_cpuq_redirect(lan9645x, true);
}

const struct phylink_mac_ops lan9645x_phylink_mac_ops = {
	.mac_prepare			= lan9645x_phylink_mac_prepare,
	.mac_config			= lan9645x_phylink_mac_config,
	.mac_link_down			= lan9645x_phylink_mac_link_down,
	.mac_link_up			= lan9645x_phylink_mac_link_up,
};
