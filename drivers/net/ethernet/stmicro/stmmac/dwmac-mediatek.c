// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018 MediaTek Inc.
 */
#include <linux/bitfield.h>
#include <linux/io.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/stmmac.h>

#include "stmmac.h"
#include "stmmac_platform.h"

/* Peri Configuration register for mt2712 */
#define PERI_ETH_PHY_INTF_SEL	0x418
#define RMII_CLK_SRC_RXC	BIT(4)
#define RMII_CLK_SRC_INTERNAL	BIT(5)

#define PERI_ETH_DLY	0x428
#define ETH_DLY_GTXC_INV	BIT(6)
#define ETH_DLY_GTXC_ENABLE	BIT(5)
#define ETH_DLY_GTXC_STAGES	GENMASK(4, 0)
#define ETH_DLY_TXC_INV		BIT(20)
#define ETH_DLY_TXC_ENABLE	BIT(19)
#define ETH_DLY_TXC_STAGES	GENMASK(18, 14)
#define ETH_DLY_RXC_INV		BIT(13)
#define ETH_DLY_RXC_ENABLE	BIT(12)
#define ETH_DLY_RXC_STAGES	GENMASK(11, 7)

#define PERI_ETH_DLY_FINE	0x800
#define ETH_RMII_DLY_TX_INV	BIT(2)
#define ETH_FINE_DLY_GTXC	BIT(1)
#define ETH_FINE_DLY_RXC	BIT(0)

#define MT2712_MII_DLY_STAGE_DIV	550 /* 550ps per stage */
#define MT2712_MII_DELAY_MAX		17600 /* 32 x 550ps */
#define MT2712_RGMII_DLY_STAGE_DIV	170 /* 170ps per stage */
#define MT2712_RGMII_DELAY_MAX		5440 /* 32 x 170ps */

/* Peri Configuration register for mt8189 */
#define MT8189_PERI_ETH_CTRL_OFFSET	0x270

#define MT8189_CTRL0_TXC_OUT_OP_EN	BIT(20)

#define MT8189_MII_DLY_STAGE_DIV	180  /* 180ps per stage */
#define MT8189_MII_DELAY_MAX		5760 /* 32 x 180ps */
#define MT8189_RGMII_DLY_STAGE_DIV	180  /* 180ps per stage */
#define MT8189_RGMII_DELAY_MAX		5760 /* 32 x 180ps */

/* Peri Configuration register for mt8195 */
#define MT8195_PERI_ETH_CTRL_OFFSET	0xFD0

#define MT8195_PERI_ETH_CTRL0		0x0
#define MT8195_RMII_CLK_SRC_INTERNAL	BIT(28)
#define MT8195_RMII_CLK_SRC_RXC		BIT(27)
#define MT8195_ETH_INTF_SEL		GENMASK(26, 24)
#define MT8195_RGMII_TXC_PHASE_CTRL	BIT(22)
#define MT8195_EXT_PHY_MODE		BIT(21)
#define MT8195_DLY_GTXC_INV		BIT(12)
#define MT8195_DLY_GTXC_ENABLE		BIT(5)
#define MT8195_DLY_GTXC_STAGES		GENMASK(4, 0)

#define MT8195_PERI_ETH_CTRL1		0x4
#define MT8195_DLY_RXC_INV		BIT(25)
#define MT8195_DLY_RXC_ENABLE		BIT(18)
#define MT8195_DLY_RXC_STAGES		GENMASK(17, 13)
#define MT8195_DLY_TXC_INV		BIT(12)
#define MT8195_DLY_TXC_ENABLE		BIT(5)
#define MT8195_DLY_TXC_STAGES		GENMASK(4, 0)

#define MT8195_PERI_ETH_CTRL2		0x8
#define MT8195_DLY_RMII_RXC_INV		BIT(25)
#define MT8195_DLY_RMII_RXC_ENABLE	BIT(18)
#define MT8195_DLY_RMII_RXC_STAGES	GENMASK(17, 13)
#define MT8195_DLY_RMII_TXC_INV		BIT(12)
#define MT8195_DLY_RMII_TXC_ENABLE	BIT(5)
#define MT8195_DLY_RMII_TXC_STAGES	GENMASK(4, 0)

#define MT8195_MII_DLY_STAGE_DIV	290 /* 290ps per stage */
#define MT8195_MII_DELAY_MAX		9280 /* 32 x 290ps */
#define MT8195_RGMII_DLY_STAGE_DIV	290 /* 290ps per stage */
#define MT8195_RGMII_DELAY_MAX		9280 /* 32 x 290ps */

struct mac_delay_struct {
	u32 tx_delay;
	u32 rx_delay;
	u32 rgmii_tx_delay;
	u32 rgmii_rx_delay;
	bool tx_inv;
	bool rx_inv;
};

struct mediatek_dwmac_plat_data {
	const struct mediatek_dwmac_variant *variant;
	struct mac_delay_struct mac_delay;
	struct clk *rmii_internal_clk;
	struct clk_bulk_data *clks;
	struct regmap *peri_regmap;
	struct device_node *np;
	struct device *dev;
	phy_interface_t phy_mode;
	bool rmii_clk_from_mac;
	bool rmii_rxc;
	bool mac_wol;
};

struct mediatek_dwmac_variant {
	int (*dwmac_set_phy_interface)(struct mediatek_dwmac_plat_data *plat,
				       u8 phy_intf_sel);
	int (*dwmac_set_delay)(struct mediatek_dwmac_plat_data *plat);

	/* clock ids to be requested */
	const char * const *clk_list;
	int num_clks;

	u32 mii_delay_max;
	u32 rgmii_delay_max;
	u16 mii_delay_stage_div;
	u16 rgmii_delay_stage_div;
	u32 peri_eth_ctrl_offset;
	u8 dma_bit_mask;
	bool mac_txclk_out_en;
};

/* list of clocks required for mac */
static const char * const mt2712_dwmac_clk_l[] = {
	"axi", "apb", "mac_main", "ptp_ref"
};

static const char * const mt8189_dwmac_clk_l[] = {
	"axi", "apb", "mac_main", "ptp_ref"
};

static const char * const mt8195_dwmac_clk_l[] = {
	"axi", "apb", "mac_cg", "mac_main", "ptp_ref"
};

static int get_delay_stage(struct mediatek_dwmac_plat_data *plat,
			   u32 *rx_val, u32 *tx_val)
{
	struct mac_delay_struct *mac_delay = &plat->mac_delay;
	u32 rx_delay_conf_val, tx_delay_conf_val;
	u16 delay_stage_div;

	if (phy_interface_mode_is_rgmii(plat->phy_mode)) {
		/* RGMII case */
		delay_stage_div = plat->variant->rgmii_delay_stage_div;
		rx_delay_conf_val = mac_delay->rgmii_rx_delay;
		tx_delay_conf_val = mac_delay->rgmii_tx_delay;
	} else {
		/* MII/RMII case */
		delay_stage_div = plat->variant->mii_delay_stage_div;
		rx_delay_conf_val = mac_delay->rx_delay;
		tx_delay_conf_val = mac_delay->tx_delay;
	}

	if (!delay_stage_div) {
		dev_err(plat->dev, "Invalid internal delay stage divider\n");
		return -EINVAL;
	}

	*rx_val = rx_delay_conf_val / delay_stage_div;
	*tx_val = tx_delay_conf_val / delay_stage_div;

	return 0;
}

static int mt2712_set_interface(struct mediatek_dwmac_plat_data *plat,
				u8 phy_intf_sel)
{
	u32 intf_val = phy_intf_sel;

	if (phy_intf_sel == PHY_INTF_SEL_RMII) {
		if (plat->rmii_clk_from_mac)
			intf_val |= RMII_CLK_SRC_INTERNAL;
		if (plat->rmii_rxc)
			intf_val |= RMII_CLK_SRC_RXC;
	}

	regmap_write(plat->peri_regmap, PERI_ETH_PHY_INTF_SEL, intf_val);

	return 0;
}

static int mt2712_set_delay(struct mediatek_dwmac_plat_data *plat)
{
	struct mac_delay_struct *mac_delay = &plat->mac_delay;
	u32 rx_delay_stage_val, tx_delay_stage_val;
	u32 delay_val = 0;
	u32 fine_val = 0;
	int ret;

	ret = get_delay_stage(plat, &rx_delay_stage_val, &tx_delay_stage_val);
	if (ret)
		return ret;

	switch (plat->phy_mode) {
	case PHY_INTERFACE_MODE_MII:
		delay_val |= FIELD_PREP(ETH_DLY_TXC_ENABLE,
					!!tx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_TXC_STAGES,
					tx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_TXC_INV, mac_delay->tx_inv);

		delay_val |= FIELD_PREP(ETH_DLY_RXC_ENABLE,
					!!rx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_RXC_STAGES,
					rx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_RXC_INV, mac_delay->rx_inv);
		break;
	case PHY_INTERFACE_MODE_RMII:
		if (plat->rmii_clk_from_mac) {
			/* case 1: mac provides the rmii reference clock,
			 * and the clock output to TXC pin.
			 * The egress timing can be adjusted by GTXC delay macro circuit.
			 * The ingress timing can be adjusted by TXC delay macro circuit.
			 */
			delay_val |= FIELD_PREP(ETH_DLY_TXC_ENABLE,
						!!rx_delay_stage_val);
			delay_val |= FIELD_PREP(ETH_DLY_TXC_STAGES,
						rx_delay_stage_val);
			delay_val |= FIELD_PREP(ETH_DLY_TXC_INV, mac_delay->rx_inv);

			delay_val |= FIELD_PREP(ETH_DLY_GTXC_ENABLE,
						!!tx_delay_stage_val);
			delay_val |= FIELD_PREP(ETH_DLY_GTXC_STAGES,
						tx_delay_stage_val);
			delay_val |= FIELD_PREP(ETH_DLY_GTXC_INV, mac_delay->tx_inv);
		} else {
			/* case 2: the rmii reference clock is from external phy,
			 * and the property "rmii_rxc" indicates which pin(TXC/RXC)
			 * the reference clk is connected to. The reference clock is a
			 * received signal, so rx_delay/rx_inv are used to indicate
			 * the reference clock timing adjustment
			 */
			if (plat->rmii_rxc) {
				/* the rmii reference clock from outside is connected
				 * to RXC pin, the reference clock will be adjusted
				 * by RXC delay macro circuit.
				 */
				delay_val |= FIELD_PREP(ETH_DLY_RXC_ENABLE,
							!!rx_delay_stage_val);
				delay_val |= FIELD_PREP(ETH_DLY_RXC_STAGES,
							rx_delay_stage_val);
				delay_val |= FIELD_PREP(ETH_DLY_RXC_INV, mac_delay->rx_inv);
			} else {
				/* the rmii reference clock from outside is connected
				 * to TXC pin, the reference clock will be adjusted
				 * by TXC delay macro circuit.
				 */
				delay_val |= FIELD_PREP(ETH_DLY_TXC_ENABLE,
							!!rx_delay_stage_val);
				delay_val |= FIELD_PREP(ETH_DLY_TXC_STAGES,
							rx_delay_stage_val);
				delay_val |= FIELD_PREP(ETH_DLY_TXC_INV, mac_delay->rx_inv);
			}
			/* tx_inv will inverse the tx clock inside mac relateive to
			 * reference clock from external phy,
			 * and this bit is located in the same register with fine-tune
			 */
			if (mac_delay->tx_inv)
				fine_val = ETH_RMII_DLY_TX_INV;
		}
		break;
	case PHY_INTERFACE_MODE_RGMII:
	case PHY_INTERFACE_MODE_RGMII_TXID:
	case PHY_INTERFACE_MODE_RGMII_RXID:
	case PHY_INTERFACE_MODE_RGMII_ID:
		fine_val = ETH_FINE_DLY_GTXC | ETH_FINE_DLY_RXC;

		delay_val |= FIELD_PREP(ETH_DLY_GTXC_ENABLE,
					!!tx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_GTXC_STAGES,
					tx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_GTXC_INV, mac_delay->tx_inv);

		delay_val |= FIELD_PREP(ETH_DLY_RXC_ENABLE,
					!!rx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_RXC_STAGES,
					rx_delay_stage_val);
		delay_val |= FIELD_PREP(ETH_DLY_RXC_INV, mac_delay->rx_inv);
		break;
	default:
		dev_err(plat->dev, "phy interface not supported\n");
		return -EINVAL;
	}
	regmap_write(plat->peri_regmap, PERI_ETH_DLY, delay_val);
	regmap_write(plat->peri_regmap, PERI_ETH_DLY_FINE, fine_val);

	return 0;
}

static const struct mediatek_dwmac_variant mt2712_gmac_variant = {
	.dwmac_set_phy_interface = mt2712_set_interface,
	.dwmac_set_delay = mt2712_set_delay,
	.clk_list = mt2712_dwmac_clk_l,
	.num_clks = ARRAY_SIZE(mt2712_dwmac_clk_l),
	.mii_delay_max = MT2712_MII_DELAY_MAX,
	.rgmii_delay_max = MT2712_RGMII_DELAY_MAX,
	.mii_delay_stage_div = MT2712_MII_DLY_STAGE_DIV,
	.rgmii_delay_stage_div = MT2712_RGMII_DLY_STAGE_DIV,
	.dma_bit_mask = 33,
};

static int mt8195_set_interface(struct mediatek_dwmac_plat_data *plat,
				u8 phy_intf_sel)
{
	u32 intf_val = FIELD_PREP(MT8195_ETH_INTF_SEL, phy_intf_sel);
	u32 reg_offset = plat->variant->peri_eth_ctrl_offset;

	if (phy_intf_sel == PHY_INTF_SEL_RMII) {
		if (plat->rmii_clk_from_mac)
			intf_val |= MT8195_RMII_CLK_SRC_INTERNAL;
		if (plat->rmii_rxc)
			intf_val |= MT8195_RMII_CLK_SRC_RXC;
	}

	/* MT8195 only support external PHY */
	intf_val |= MT8195_EXT_PHY_MODE;

	if (plat->variant->mac_txclk_out_en)
		intf_val |= MT8189_CTRL0_TXC_OUT_OP_EN;

	regmap_write(plat->peri_regmap,
		     reg_offset + MT8195_PERI_ETH_CTRL0,
		     intf_val);

	return 0;
}

static int mt8195_set_delay(struct mediatek_dwmac_plat_data *plat)
{
	struct mac_delay_struct *mac_delay = &plat->mac_delay;
	u32 reg_offset = plat->variant->peri_eth_ctrl_offset;
	u32 rx_delay_stage_val, tx_delay_stage_val;
	u32 gtxc_delay_val = 0;
	u32 rmii_delay_val = 0;
	u32 delay_val = 0;
	int ret;

	ret = get_delay_stage(plat, &rx_delay_stage_val, &tx_delay_stage_val);
	if (ret)
		return ret;

	switch (plat->phy_mode) {
	case PHY_INTERFACE_MODE_MII:
		delay_val |= FIELD_PREP(MT8195_DLY_TXC_ENABLE,
					!!tx_delay_stage_val);
		delay_val |= FIELD_PREP(MT8195_DLY_TXC_STAGES,
					tx_delay_stage_val);
		delay_val |= FIELD_PREP(MT8195_DLY_TXC_INV, mac_delay->tx_inv);

		delay_val |= FIELD_PREP(MT8195_DLY_RXC_ENABLE,
					!!rx_delay_stage_val);
		delay_val |= FIELD_PREP(MT8195_DLY_RXC_STAGES,
					rx_delay_stage_val);
		delay_val |= FIELD_PREP(MT8195_DLY_RXC_INV, mac_delay->rx_inv);
		break;
	case PHY_INTERFACE_MODE_RMII:
		if (plat->rmii_clk_from_mac) {
			/* case 1: mac provides the rmii reference clock,
			 * and the clock output to TXC pin.
			 * The egress timing can be adjusted by RMII_TXC delay macro circuit.
			 * The ingress timing can be adjusted by RMII_RXC delay macro circuit.
			 */
			rmii_delay_val |= FIELD_PREP(MT8195_DLY_RMII_TXC_ENABLE,
						     !!tx_delay_stage_val);
			rmii_delay_val |= FIELD_PREP(MT8195_DLY_RMII_TXC_STAGES,
						     tx_delay_stage_val);
			rmii_delay_val |= FIELD_PREP(MT8195_DLY_RMII_TXC_INV,
						     mac_delay->tx_inv);

			rmii_delay_val |= FIELD_PREP(MT8195_DLY_RMII_RXC_ENABLE,
						     !!rx_delay_stage_val);
			rmii_delay_val |= FIELD_PREP(MT8195_DLY_RMII_RXC_STAGES,
						     rx_delay_stage_val);
			rmii_delay_val |= FIELD_PREP(MT8195_DLY_RMII_RXC_INV,
						     mac_delay->rx_inv);
		} else {
			/* case 2: the rmii reference clock is from external phy,
			 * and the property "rmii_rxc" indicates which pin(TXC/RXC)
			 * the reference clk is connected to. The reference clock is a
			 * received signal, so rx_delay/rx_inv are used to indicate
			 * the reference clock timing adjustment
			 */
			if (plat->rmii_rxc) {
				/* the rmii reference clock from outside is connected
				 * to RXC pin, the reference clock will be adjusted
				 * by RXC delay macro circuit.
				 */
				delay_val |= FIELD_PREP(MT8195_DLY_RXC_ENABLE,
							!!rx_delay_stage_val);
				delay_val |= FIELD_PREP(MT8195_DLY_RXC_STAGES,
							rx_delay_stage_val);
				delay_val |= FIELD_PREP(MT8195_DLY_RXC_INV,
							mac_delay->rx_inv);
			} else {
				/* the rmii reference clock from outside is connected
				 * to TXC pin, the reference clock will be adjusted
				 * by TXC delay macro circuit.
				 */
				delay_val |= FIELD_PREP(MT8195_DLY_TXC_ENABLE,
							!!rx_delay_stage_val);
				delay_val |= FIELD_PREP(MT8195_DLY_TXC_STAGES,
							rx_delay_stage_val);
				delay_val |= FIELD_PREP(MT8195_DLY_TXC_INV,
							mac_delay->rx_inv);
			}
		}
		break;
	case PHY_INTERFACE_MODE_RGMII:
	case PHY_INTERFACE_MODE_RGMII_TXID:
	case PHY_INTERFACE_MODE_RGMII_RXID:
	case PHY_INTERFACE_MODE_RGMII_ID:
		gtxc_delay_val |= FIELD_PREP(MT8195_DLY_GTXC_ENABLE,
					     !!tx_delay_stage_val);
		gtxc_delay_val |= FIELD_PREP(MT8195_DLY_GTXC_STAGES,
					     tx_delay_stage_val);
		gtxc_delay_val |= FIELD_PREP(MT8195_DLY_GTXC_INV, mac_delay->tx_inv);

		delay_val |= FIELD_PREP(MT8195_DLY_RXC_ENABLE,
					!!rx_delay_stage_val);
		delay_val |= FIELD_PREP(MT8195_DLY_RXC_STAGES,
					rx_delay_stage_val);
		delay_val |= FIELD_PREP(MT8195_DLY_RXC_INV, mac_delay->rx_inv);

		break;
	default:
		dev_err(plat->dev, "phy interface not supported\n");
		return -EINVAL;
	}

	regmap_update_bits(plat->peri_regmap,
			   reg_offset + MT8195_PERI_ETH_CTRL0,
			   MT8195_RGMII_TXC_PHASE_CTRL |
			   MT8195_DLY_GTXC_INV |
			   MT8195_DLY_GTXC_ENABLE |
			   MT8195_DLY_GTXC_STAGES,
			   gtxc_delay_val);
	regmap_write(plat->peri_regmap,
		     reg_offset + MT8195_PERI_ETH_CTRL1,
		     delay_val);
	regmap_write(plat->peri_regmap,
		     reg_offset + MT8195_PERI_ETH_CTRL2,
		     rmii_delay_val);

	return 0;
}

static const struct mediatek_dwmac_variant mt8189_gmac_variant = {
	.dwmac_set_phy_interface = mt8195_set_interface,
	.dwmac_set_delay = mt8195_set_delay,
	.clk_list = mt8189_dwmac_clk_l,
	.num_clks = ARRAY_SIZE(mt8189_dwmac_clk_l),
	.dma_bit_mask = 35,
	.mii_delay_max = MT8189_MII_DELAY_MAX,
	.rgmii_delay_max = MT8189_RGMII_DELAY_MAX,
	.mii_delay_stage_div = MT8189_MII_DLY_STAGE_DIV,
	.rgmii_delay_stage_div = MT8189_RGMII_DLY_STAGE_DIV,
	.peri_eth_ctrl_offset = MT8189_PERI_ETH_CTRL_OFFSET,
	.mac_txclk_out_en = true,
};

static const struct mediatek_dwmac_variant mt8195_gmac_variant = {
	.dwmac_set_phy_interface = mt8195_set_interface,
	.dwmac_set_delay = mt8195_set_delay,
	.clk_list = mt8195_dwmac_clk_l,
	.num_clks = ARRAY_SIZE(mt8195_dwmac_clk_l),
	.mii_delay_max = MT8195_MII_DELAY_MAX,
	.rgmii_delay_max = MT8195_RGMII_DELAY_MAX,
	.mii_delay_stage_div = MT8195_MII_DLY_STAGE_DIV,
	.rgmii_delay_stage_div = MT8195_RGMII_DLY_STAGE_DIV,
	.dma_bit_mask = 35,
	.peri_eth_ctrl_offset = MT8195_PERI_ETH_CTRL_OFFSET,
};

static int mediatek_dwmac_config_dt(struct mediatek_dwmac_plat_data *plat)
{
	struct mac_delay_struct *mac_delay = &plat->mac_delay;
	u32 rgmii_tx_delay_ps = 0;
	u32 rgmii_rx_delay_ps = 0;
	u32 tx_delay_ps = 0;
	u32 rx_delay_ps = 0;

	plat->peri_regmap = syscon_regmap_lookup_by_phandle(plat->np, "mediatek,pericfg");
	if (IS_ERR(plat->peri_regmap)) {
		dev_err(plat->dev, "Failed to get pericfg syscon\n");
		return PTR_ERR(plat->peri_regmap);
	}

	of_property_read_u32(plat->np, "mediatek,tx-delay-ps", &tx_delay_ps);
	if (tx_delay_ps >= plat->variant->mii_delay_max) {
		dev_err(plat->dev, "Invalid TX clock delay: %dps\n",
			tx_delay_ps);
		return -EINVAL;
	}

	/* Read RGMII TX internal delay standard property */
	if (!of_property_read_u32(plat->np, "tx-internal-delay-ps",
				  &rgmii_tx_delay_ps)) {
		if (rgmii_tx_delay_ps >= plat->variant->rgmii_delay_max) {
			dev_err(plat->dev, "Invalid RGMII TX clock delay: %dps\n",
				rgmii_tx_delay_ps);
			return -EINVAL;
		}
	} else {
		/*
		 * standard property value not available, fallback on vendor
		 * value instead and cap it to max RGMII delay value
		 */
		rgmii_tx_delay_ps = min(tx_delay_ps,
					plat->variant->rgmii_delay_max);
	}

	of_property_read_u32(plat->np, "mediatek,rx-delay-ps", &rx_delay_ps);
	if (rx_delay_ps >= plat->variant->mii_delay_max) {
		dev_err(plat->dev, "Invalid RX clock delay: %dps\n",
			rx_delay_ps);
		return -EINVAL;
	}

	/* Read RGMII RX internal delay standard property */
	if (!of_property_read_u32(plat->np, "rx-internal-delay-ps",
				  &rgmii_rx_delay_ps)) {
		if (rgmii_rx_delay_ps >= plat->variant->rgmii_delay_max) {
			dev_err(plat->dev, "Invalid RGMII RX clock delay: %dps\n",
				rgmii_rx_delay_ps);
			return -EINVAL;
		}
	} else {
		/*
		 * standard property value not available, fallback on vendor
		 * value instead and cap it to max RGMII delay value
		 */
		rgmii_rx_delay_ps = min(rx_delay_ps,
					plat->variant->rgmii_delay_max);
	}

	mac_delay->rx_delay = rx_delay_ps;
	mac_delay->tx_delay = tx_delay_ps;
	mac_delay->rgmii_rx_delay = rgmii_rx_delay_ps;
	mac_delay->rgmii_tx_delay = rgmii_tx_delay_ps;
	mac_delay->tx_inv = of_property_read_bool(plat->np, "mediatek,txc-inverse");
	mac_delay->rx_inv = of_property_read_bool(plat->np, "mediatek,rxc-inverse");
	plat->rmii_rxc = of_property_read_bool(plat->np, "mediatek,rmii-rxc");
	plat->rmii_clk_from_mac = of_property_read_bool(plat->np, "mediatek,rmii-clk-from-mac");
	plat->mac_wol = of_property_read_bool(plat->np, "mediatek,mac-wol");

	return 0;
}

static int mediatek_dwmac_clk_init(struct mediatek_dwmac_plat_data *plat)
{
	const struct mediatek_dwmac_variant *variant = plat->variant;
	int i, ret;

	plat->clks = devm_kzalloc_objs(plat->dev, *plat->clks,
				       variant->num_clks);
	if (!plat->clks)
		return -ENOMEM;

	for (i = 0; i < variant->num_clks; i++)
		plat->clks[i].id = variant->clk_list[i];

	ret = devm_clk_bulk_get(plat->dev, variant->num_clks, plat->clks);
	if (ret)
		return ret;

	/* The clock labeled as "rmii_internal" is needed only in RMII(when
	 * MAC provides the reference clock), and useless for RGMII/MII or
	 * RMII(when PHY provides the reference clock).
	 * So, "rmii_internal" clock is got and configured only when
	 * reference clock of RMII is from MAC.
	 */
	if (plat->rmii_clk_from_mac) {
		plat->rmii_internal_clk = devm_clk_get(plat->dev, "rmii_internal");
		if (IS_ERR(plat->rmii_internal_clk))
			ret = PTR_ERR(plat->rmii_internal_clk);
	} else {
		plat->rmii_internal_clk = NULL;
	}

	return ret;
}

static int mediatek_dwmac_init(struct device *dev, void *priv)
{
	struct mediatek_dwmac_plat_data *plat = priv;
	const struct mediatek_dwmac_variant *variant = plat->variant;
	int phy_intf_sel, ret;

	if (variant->dwmac_set_phy_interface) {
		phy_intf_sel = stmmac_get_phy_intf_sel(plat->phy_mode);
		if (phy_intf_sel != PHY_INTF_SEL_GMII_MII &&
		    phy_intf_sel != PHY_INTF_SEL_RGMII &&
		    phy_intf_sel != PHY_INTF_SEL_RMII) {
			dev_err(plat->dev, "phy interface not supported\n");
			return phy_intf_sel < 0 ? phy_intf_sel : -EINVAL;
		}

		ret = variant->dwmac_set_phy_interface(plat, phy_intf_sel);
		if (ret) {
			dev_err(dev, "failed to set phy interface, err = %d\n", ret);
			return ret;
		}
	}

	if (variant->dwmac_set_delay) {
		ret = variant->dwmac_set_delay(plat);
		if (ret) {
			dev_err(dev, "failed to set delay value, err = %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static int mediatek_dwmac_clks_config(void *priv, bool enabled)
{
	struct mediatek_dwmac_plat_data *plat = priv;
	const struct mediatek_dwmac_variant *variant = plat->variant;
	int ret = 0;

	if (enabled) {
		ret = clk_bulk_prepare_enable(variant->num_clks, plat->clks);
		if (ret) {
			dev_err(plat->dev, "failed to enable clks, err = %d\n", ret);
			return ret;
		}

		ret = clk_prepare_enable(plat->rmii_internal_clk);
		if (ret) {
			dev_err(plat->dev, "failed to enable rmii internal clk, err = %d\n", ret);
			return ret;
		}
	} else {
		clk_disable_unprepare(plat->rmii_internal_clk);
		clk_bulk_disable_unprepare(variant->num_clks, plat->clks);
	}

	return ret;
}

static int mediatek_dwmac_common_data(struct platform_device *pdev,
				      struct plat_stmmacenet_data *plat,
				      struct mediatek_dwmac_plat_data *priv_plat)
{
	int i;

	priv_plat->phy_mode = plat->phy_interface;
	if (priv_plat->mac_wol)
		plat->flags &= ~STMMAC_FLAG_USE_PHY_WOL;
	else
		plat->flags |= STMMAC_FLAG_USE_PHY_WOL;
	plat->riwt_off = true;
	plat->maxmtu = ETH_DATA_LEN;
	plat->host_dma_width = priv_plat->variant->dma_bit_mask;
	plat->bsp_priv = priv_plat;
	plat->resume = mediatek_dwmac_init;
	plat->clks_config = mediatek_dwmac_clks_config;

	plat->safety_feat_cfg = devm_kzalloc_obj(&pdev->dev,
						 *plat->safety_feat_cfg);
	if (!plat->safety_feat_cfg)
		return -ENOMEM;

	plat->safety_feat_cfg->tsoee = 1;
	plat->safety_feat_cfg->mrxpee = 0;
	plat->safety_feat_cfg->mestee = 1;
	plat->safety_feat_cfg->mrxee = 1;
	plat->safety_feat_cfg->mtxee = 1;
	plat->safety_feat_cfg->epsi = 0;
	plat->safety_feat_cfg->edpp = 1;
	plat->safety_feat_cfg->prtyen = 1;
	plat->safety_feat_cfg->tmouten = 1;

	for (i = 0; i < plat->tx_queues_to_use; i++) {
		/* Default TX Q0 to use TSO and rest TXQ for TBS */
		if (i > 0)
			plat->tx_queues_cfg[i].tbs_en = 1;
	}

	return 0;
}

static int mediatek_dwmac_probe(struct platform_device *pdev)
{
	struct mediatek_dwmac_plat_data *priv_plat;
	struct plat_stmmacenet_data *plat_dat;
	struct stmmac_resources stmmac_res;
	int ret;

	priv_plat = devm_kzalloc_obj(&pdev->dev, *priv_plat);
	if (!priv_plat)
		return -ENOMEM;

	priv_plat->variant = of_device_get_match_data(&pdev->dev);
	if (!priv_plat->variant) {
		dev_err(&pdev->dev, "Missing dwmac-mediatek variant\n");
		return -EINVAL;
	}

	priv_plat->dev = &pdev->dev;
	priv_plat->np = pdev->dev.of_node;

	ret = mediatek_dwmac_config_dt(priv_plat);
	if (ret)
		return ret;

	ret = mediatek_dwmac_clk_init(priv_plat);
	if (ret)
		return ret;

	ret = stmmac_get_platform_resources(pdev, &stmmac_res);
	if (ret)
		return ret;

	plat_dat = devm_stmmac_probe_config_dt(pdev, stmmac_res.mac);
	if (IS_ERR(plat_dat))
		return PTR_ERR(plat_dat);

	mediatek_dwmac_common_data(pdev, plat_dat, priv_plat);
	mediatek_dwmac_init(&pdev->dev, priv_plat);

	ret = mediatek_dwmac_clks_config(priv_plat, true);
	if (ret)
		return ret;

	ret = stmmac_dvr_probe(&pdev->dev, plat_dat, &stmmac_res);
	if (ret)
		goto err_drv_probe;

	return 0;

err_drv_probe:
	mediatek_dwmac_clks_config(priv_plat, false);

	return ret;
}

static void mediatek_dwmac_remove(struct platform_device *pdev)
{
	struct mediatek_dwmac_plat_data *priv_plat = get_stmmac_bsp_priv(&pdev->dev);

	stmmac_pltfr_remove(pdev);
	mediatek_dwmac_clks_config(priv_plat, false);
}

static const struct of_device_id mediatek_dwmac_match[] = {
	{ .compatible = "mediatek,mt2712-gmac",
	  .data = &mt2712_gmac_variant },
	{ .compatible = "mediatek,mt8189-gmac",
	  .data = &mt8189_gmac_variant },
	{ .compatible = "mediatek,mt8195-gmac",
	  .data = &mt8195_gmac_variant },
	{ }
};

MODULE_DEVICE_TABLE(of, mediatek_dwmac_match);

static struct platform_driver mediatek_dwmac_driver = {
	.probe  = mediatek_dwmac_probe,
	.remove = mediatek_dwmac_remove,
	.driver = {
		.name           = "dwmac-mediatek",
		.pm		= &stmmac_pltfr_pm_ops,
		.of_match_table = mediatek_dwmac_match,
	},
};
module_platform_driver(mediatek_dwmac_driver);

MODULE_AUTHOR("Biao Huang <biao.huang@mediatek.com>");
MODULE_DESCRIPTION("MediaTek DWMAC specific glue layer");
MODULE_LICENSE("GPL v2");
