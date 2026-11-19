// SPDX-License-Identifier: GPL-2.0+
/* Driver for Asix PHYs
 *
 * Author: Michael Schmitz <schmitzmic@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mii.h>
#include <linux/phy.h>

#define PHY_ID_ASIX_AX88772A		0x003b1861
#define PHY_ID_ASIX_AX88772C		0x003b1881
#define PHY_ID_ASIX_AX88796B		0x003b1841
#define PHY_ID_ASIX_AX88772D		0x003b772d
#define PHY_ID_ASIX_AX88179A		0x003b179a
#define PHY_ID_ASIX_AX88279		0x003b2790

#define AX_ADVERTISE_2500		0x1000

/* MII Vendor registers */
#define AX_CTRL_STATUS			0x1d
#define AX_CTRL_STATUS_SPEED_MASK	0x0c
#define   AX_CTRL_STATUS_SPEED_10	0x0
#define   AX_CTRL_STATUS_SPEED_100	0x4
#define   AX_CTRL_STATUS_SPEED_1000	0x8
#define   AX_CTRL_STATUS_SPEED_2500	0xc

MODULE_DESCRIPTION("Asix PHY driver");
MODULE_AUTHOR("Michael Schmitz <schmitzmic@gmail.com>");
MODULE_LICENSE("GPL");

/**
 * asix_soft_reset - software reset the PHY via BMCR_RESET bit
 * @phydev: target phy_device struct
 *
 * Description: Perform a software PHY reset using the standard
 * BMCR_RESET bit and poll for the reset bit to be cleared.
 * Toggle BMCR_RESET bit off to accommodate broken AX8796B PHY implementation
 * such as used on the Individual Computers' X-Surf 100 Zorro card.
 *
 * Returns: 0 on success, < 0 on failure
 */
static int asix_soft_reset(struct phy_device *phydev)
{
	int ret;

	/* Asix PHY won't reset unless reset bit toggles */
	ret = phy_write(phydev, MII_BMCR, 0);
	if (ret < 0)
		return ret;

	return genphy_soft_reset(phydev);
}

/* AX88772A is not working properly with some old switches (NETGEAR EN 108TP):
 * after autoneg is done and the link status is reported as active, the MII_LPA
 * register is 0. This issue is not reproducible on AX88772C.
 */
static int asix_ax88772a_read_status(struct phy_device *phydev)
{
	int ret, val;

	ret = genphy_update_link(phydev);
	if (ret)
		return ret;

	if (!phydev->link)
		return 0;

	/* If MII_LPA is 0, phy_resolve_aneg_linkmode() will fail to resolve
	 * linkmode so use MII_BMCR as default values.
	 */
	val = phy_read(phydev, MII_BMCR);
	if (val < 0)
		return val;

	if (val & BMCR_SPEED100)
		phydev->speed = SPEED_100;
	else
		phydev->speed = SPEED_10;

	if (val & BMCR_FULLDPLX)
		phydev->duplex = DUPLEX_FULL;
	else
		phydev->duplex = DUPLEX_HALF;

	ret = genphy_read_lpa(phydev);
	if (ret < 0)
		return ret;

	if (phydev->autoneg == AUTONEG_ENABLE && phydev->autoneg_complete)
		phy_resolve_aneg_linkmode(phydev);

	return 0;
}

static int asix_ax88279_read_status(struct phy_device *phydev)
{
	int ret, val;

	ret = genphy_read_status(phydev);
	if (ret)
		return ret;

	if (!phydev->link)
		return 0;

	/* Read actual speed from vendor register */
	val = phy_read(phydev, AX_CTRL_STATUS);
	if (val < 0)
		return val;

	switch (val & AX_CTRL_STATUS_SPEED_MASK) {
	case AX_CTRL_STATUS_SPEED_2500:
		phydev->speed = SPEED_2500;
		break;
	case AX_CTRL_STATUS_SPEED_1000:
		phydev->speed = SPEED_1000;
		break;
	case AX_CTRL_STATUS_SPEED_100:
		phydev->speed = SPEED_100;
		break;
	case AX_CTRL_STATUS_SPEED_10:
		phydev->speed = SPEED_10;
	}

	/* MDIO_AN_10GBT_STAT_LP2_5G is broken, but we can deduce that
	 * the link-partner advertised 2500M if remotely AN succceded
	 * for link speed > 1000M and we locally have a link speed of
	 * 2500M
	 */
	linkmode_clear_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT, phydev->lp_advertising);
	val = phy_read_mmd(phydev, MDIO_MMD_AN, MDIO_AN_10GBT_STAT);
	if (val >= 0 && val & MDIO_AN_10GBT_STAT_REMOK) {
		linkmode_mod_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT,
				 phydev->lp_advertising,
				 phydev->speed == SPEED_2500);
	}
	/* Only supports full duplex */
	phydev->duplex = DUPLEX_FULL;

	/* PHY switches interface between 2.5GBit and slower modes */
	if (phydev->speed == SPEED_2500)
		phydev->interface = PHY_INTERFACE_MODE_2500BASEX;
	else
		phydev->interface = PHY_INTERFACE_MODE_SGMII;

	return 0;
}

static int asix_ax88279_config_aneg(struct phy_device *phydev)
{
	bool adv_2500;
	int ret;

	if (phydev->autoneg == AUTONEG_DISABLE) {
		phydev_warn(phydev, "Disabling autoneg is not supported\n");
		return -EOPNOTSUPP;
	}

	adv_2500 = linkmode_test_bit(ETHTOOL_LINK_MODE_2500baseT_Full_BIT, phydev->advertising);
	ret = phy_modify_changed(phydev, MII_ADVERTISE, AX_ADVERTISE_2500,
				 adv_2500 ? AX_ADVERTISE_2500 : 0);
	if (ret < 0)
		return ret;

	return __genphy_config_aneg(phydev, (ret == 1));
}

static int asix_ax88279_get_features(struct phy_device *phydev)
{
	int ret;

	/* MDIO_DEVS1/2 empty, so set mmds_present bits to allow reading abilities */
	phydev->c45_ids.mmds_present |= MDIO_DEVS_PMAPMD | MDIO_DEVS_AN;

	linkmode_set_bit_array(phy_basic_ports_array, ARRAY_SIZE(phy_basic_ports_array),
			       phydev->supported);

	ret = genphy_c45_pma_read_abilities(phydev);
	if (ret < 0)
		return ret;

	/* AX88279 does not support reported 100baseT-half duplex mode */
	linkmode_clear_bit(ETHTOOL_LINK_MODE_100baseT_Half_BIT, phydev->supported);

	return 0;
}

static int asix_ax88279_config_init(struct phy_device *phydev)
{
	__set_bit(PHY_INTERFACE_MODE_2500BASEX, phydev->possible_interfaces);
	__set_bit(PHY_INTERFACE_MODE_SGMII, phydev->possible_interfaces);

	return 0;
}

static void asix_ax88772a_link_change_notify(struct phy_device *phydev)
{
	/* Reset PHY, otherwise MII_LPA will provide outdated information.
	 * This issue is reproducible only with some link partner PHYs
	 */
	if (phydev->state == PHY_NOLINK) {
		phy_init_hw(phydev);
		_phy_start_aneg(phydev);
	}
}

static int asix_ax88772D_get_features(struct phy_device *phydev)
{
	int ret;

	/* MDIO_DEVS1/2 empty, so set mmds_present bits to allow reading abilities */
	phydev->c45_ids.mmds_present |= MDIO_DEVS_PMAPMD | MDIO_DEVS_AN;

	ret = genphy_read_abilities(phydev);
	if (ret < 0)
		return ret;

	/* AX88772D does not support (possibly) reported 1000baseT modes */
	linkmode_clear_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, phydev->supported);
	linkmode_clear_bit(ETHTOOL_LINK_MODE_1000baseT_Half_BIT, phydev->supported);
	linkmode_clear_bit(ETHTOOL_LINK_MODE_1000baseX_Full_BIT, phydev->supported);

	return 0;
}

static struct phy_driver asix_driver[] = {
{
	PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88772A),
	.name		= "Asix Electronics AX88772A",
	.flags		= PHY_IS_INTERNAL,
	.read_status	= asix_ax88772a_read_status,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
	.soft_reset	= asix_soft_reset,
	.link_change_notify	= asix_ax88772a_link_change_notify,
}, {
	PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88772C),
	.name		= "Asix Electronics AX88772C",
	.flags		= PHY_IS_INTERNAL,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
	.soft_reset	= asix_soft_reset,
}, {
	PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88772D),
	.name		= "Asix Electronics AX88772D",
	.flags		= PHY_IS_INTERNAL,
	.get_features	= asix_ax88772D_get_features,
	.read_mmd	= genphy_read_mmd_c45,
	.write_mmd	= genphy_write_mmd_c45,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
}, {
	PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88179A),
	.name		= "Asix Electronics AX88179A",
	.flags		= PHY_IS_INTERNAL,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
	.read_mmd	= genphy_read_mmd_c45,
	.write_mmd	= genphy_write_mmd_c45,
}, {
	PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88279),
	.name		= "Asix Electronics AX88279",
	.flags		= PHY_IS_INTERNAL | PHY_BROKEN_FORCED,
	.get_features	= asix_ax88279_get_features,
	.read_status	= asix_ax88279_read_status,
	.config_aneg	= asix_ax88279_config_aneg,
	.config_init	= asix_ax88279_config_init,
	.read_mmd	= genphy_read_mmd_c45,
	.write_mmd	= genphy_write_mmd_c45,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
}, {
	PHY_ID_MATCH_MODEL(PHY_ID_ASIX_AX88796B),
	.name		= "Asix Electronics AX88796B",
	/* PHY_BASIC_FEATURES */
	.soft_reset	= asix_soft_reset,
} };

module_phy_driver(asix_driver);

static const struct mdio_device_id __maybe_unused asix_tbl[] = {
	{ PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88772A) },
	{ PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88772C) },
	{ PHY_ID_MATCH_MODEL(PHY_ID_ASIX_AX88796B) },
	{ PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88772D) },
	{ PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88179A) },
	{ PHY_ID_MATCH_EXACT(PHY_ID_ASIX_AX88279) },
	{ }
};

MODULE_DEVICE_TABLE(mdio, asix_tbl);
