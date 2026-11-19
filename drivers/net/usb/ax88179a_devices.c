// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/phylink.h>
#include <linux/if_vlan.h>
#include "ax88179_lib.h"

static int ax88179a_reset(struct usbnet *dev);

#define AX88279_EEPROM_LEN			0x4000
#define AX88179A_EEPROM_LEN			(32 * 20)

enum ax_bulk_in_speeds {
	BULK_IN_SPEED_2G5 = 0,
	BULK_IN_SPEED_1G_SS = 1,
	BULK_IN_SPEED_1G_HS   = 2,
	BULK_IN_SPEED_100_FULL_SS = 3,
	BULK_IN_SPEED_100_HALF_SS = 4,
	BULK_IN_SPEED_100_FULL_HS = 5,
	BULK_IN_SPEED_100_HALF_HS = 6,
	BULK_IN_SPEED_FS = 7,
};

static const struct ax_bulkin_settings AX88179A_BULKIN_SIZE[] = {
	[BULK_IN_SPEED_1G_SS]		= {5, 0x7B, 0x00, 0x17, 0x0F},
	[BULK_IN_SPEED_1G_HS]		= {5, 0xC0, 0x02, 0x06, 0x0F},
	[BULK_IN_SPEED_100_FULL_SS]	= {7, 0xF0, 0x00, 0x0C, 0x0F},
	[BULK_IN_SPEED_100_HALF_SS]	= {6, 0x00, 0x00, 0x06, 0x0F},
	[BULK_IN_SPEED_100_FULL_HS]	= {5, 0xC0, 0x04, 0x06, 0x0F},
	[BULK_IN_SPEED_100_HALF_HS]	= {7, 0xC0, 0x04, 0x06, 0x0F},
	[BULK_IN_SPEED_FS]		= {7, 0x00, 0x00, 0x03, 0x3F},
};

static const struct ax_bulkin_settings AX88772D_BULKIN_SIZE[] = {
	[BULK_IN_SPEED_100_FULL_HS]	= {5, 0xC0, 0x04, 0x06, 0x0F},
	[BULK_IN_SPEED_100_HALF_HS]	= {7, 0xC0, 0x04, 0x06, 0x0F},
	[BULK_IN_SPEED_FS]		= {7, 0x00, 0x00, 0x03, 0x3F},
};

static const struct ax_bulkin_settings AX88279_BULKIN_SIZE[] = {
	[BULK_IN_SPEED_2G5]		= {5, 0x10, 0x01, 0x11, 0x0F},
	[BULK_IN_SPEED_1G_SS]		= {7, 0xB3, 0x01, 0x11, 0x0F},
	[BULK_IN_SPEED_1G_HS]		= {7, 0xC0, 0x02, 0x06, 0x0F},
	[BULK_IN_SPEED_100_FULL_SS]	= {7, 0x80, 0x01, 0x03, 0x0F},
	[BULK_IN_SPEED_100_HALF_SS]	= {7, 0x80, 0x01, 0x03, 0x0F},
	[BULK_IN_SPEED_100_FULL_HS]	= {7, 0x80, 0x01, 0x03, 0x0F},
	[BULK_IN_SPEED_100_HALF_HS]	= {7, 0x80, 0x01, 0x03, 0x0F},
	[BULK_IN_SPEED_FS]		= {7, 0x00, 0x00, 0x03, 0x3F},
};

static int ax88179_mdiobus_read(struct mii_bus *bus, int phy_id, int regnum)
{
	struct usbnet *dev = bus->priv;
	struct ax88179_data *priv;
	u16 res;
	int ret;

	priv = dev->driver_priv;
	/* When reading PHYSID, return unused PHY-IDs from the ASIX vendor range */
	if (phy_id == AX88179_PHY_ID && regnum == MII_PHYSID1)
		return 0x003b;
	if (phy_id == AX88179_PHY_ID && regnum == MII_PHYSID2) {
		if (priv->chip_version == AX_VERSION_AX88179A && priv->is_ax88772d)
			return 0x772d;
		else if (priv->chip_version == AX_VERSION_AX88179A)
			return 0x179a;
		else if (priv->chip_version == AX_VERSION_AX88279)
			return 0x2790;
	}

	ret = ax88179_read_cmd(dev, AX_ACCESS_PHY, phy_id, (__u16)regnum, 2, &res);
	if (ret < 0)
		return ret;
	return res;
}

static int ax88179_mdiobus_write(struct mii_bus *bus, int phy_id, int regnum, u16 val)
{
	struct usbnet *dev = bus->priv;

	return ax88179_write_u16(dev, AX_ACCESS_PHY, phy_id, (__u16)regnum, val);
}

static int ax179a_read_mmd(struct usbnet *dev, u16 dev_addr, u16 reg)
{
	u16 res;
	int ret;

	ret = ax88179_read_cmd(dev, AX88179A_PHY_CLAUSE45, dev_addr, reg, 2, &res);
	if (ret < 0)
		return ret;
	return res;
}

static int ax179a_write_mmd(struct usbnet *dev, u16 dev_addr, u16 reg, u16 data)
{
	return ax88179_write_cmd(dev, AX88179A_PHY_CLAUSE45, dev_addr, reg, 2, &data);
}

static int ax88179_mdiobus_read_c45(struct mii_bus *bus, int addr, int devnum, int regnum)
{
	struct usbnet *dev = bus->priv;

	if (addr != AX88179_PHY_ID)
		return -EINVAL;

	return ax179a_read_mmd(dev, devnum, regnum);
}

static int ax88179_mdiobus_write_c45(struct mii_bus *bus, int addr, int devnum,
				     int regnum, u16 val)
{
	struct usbnet *dev = bus->priv;

	if (addr != AX88179_PHY_ID)
		return -EINVAL;

	return ax179a_write_mmd(dev, devnum, regnum, val);
}

static void ax88179a_status(struct usbnet *dev, struct urb *urb)
{
	struct ax88179_data *data = dev->driver_priv;

	if (urb->actual_length < 8)
		return;

	phylink_mac_interrupt(data->phylink);
}

static int ax88179a_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct ax88179_data *priv;
	u8 tmp8 = 0;
	u16 tmp16;
	int ret;

	priv = dev->driver_priv;
	ax88179_set_pm_mode(dev, true);

	if (netif_running(dev->net)) {
		rtnl_lock();
		phylink_suspend(priv->phylink, !!priv->wolopts);
		rtnl_unlock();
	}

	ret = usbnet_suspend(intf, message);
	if (ret && netif_running(dev->net)) {
		rtnl_lock();
		phylink_resume(priv->phylink);
		rtnl_unlock();
		ax88179_set_pm_mode(dev, false);
		return ret;
	}

	/* Enable WoL */
	if (priv->wolopts) {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD, 1, 1, &tmp8);
		tmp8 &= ~(AX_MONITOR_MODE_RWLC | AX_MONITOR_MODE_RWMP);
		if (priv->wolopts & WAKE_PHY)
			tmp8 |= AX_MONITOR_MODE_RWLC;
		if (priv->wolopts & WAKE_MAGIC)
			tmp8 |= AX_MONITOR_MODE_RWMP;

		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD, 1, 1, &tmp8);

		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, 2, &tmp16);
		tmp16 |= AX_MEDIUM_RECEIVE_EN;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, 2, &tmp16);

		if (priv->chip_version == AX_VERSION_AX88279)
			ax88179_write_cmd(dev, AX88179A_WAKEUP_SETTING, 8,
					  EPHY_LOW_POWER_EN | S5_WOL_EN
					  | S5_WOL_LOW_POWER | 0x8000, 0, NULL);
		else
			ax88179_write_cmd(dev, AX88179A_WAKEUP_SETTING, 0,
					  EPHY_LOW_POWER_EN, 0, NULL);

	} else if (priv->chip_version == AX_VERSION_AX88279) {
		ax88179_write_cmd(dev, AX88179A_WAKEUP_SETTING, 8, 0x8000, 0, NULL);
	}

	ax88179_set_pm_mode(dev, false);
	return 0;
}

static int ax88179a_auto_detach(struct usbnet *dev)
{
	u16 tmp16;

	tmp16 = AX88179A_AUTODETACH_DELAY;
	ax88179_write_cmd(dev, AX88179A_AUTODETACH, tmp16, 0, 0, NULL);
	return 0;
}

static int ax88179a_resume(struct usb_interface *intf)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct ax88179_data *ax179_data;
	u8 reg8 = 0;
	int ret;

	ax179_data = dev->driver_priv;
	ax88179_set_pm_mode(dev, true);

	ret = ax88179_read_cmd(dev, AX88179A_PHY_POWER, 0, 0, 1, &reg8);
	if (ret < 0)
		goto err_out;

	if (!(reg8 & AX_PHY_POWER)) {
		reg8 = AX_PHY_POWER;
		ax88179_write_cmd(dev, AX88179A_PHY_POWER, 0, 0, 1, &reg8);
		msleep(250);
	}
	ax88179_write_cmd(dev, AX_FW_MODE, AX_FW_MODE_179A, 0, 0, NULL);

	/* Now, that AX_FW_MODE_179A is enabled, the PHY needs a power-cycle.
	 * PHY-power is re-enabled in ax88179a_reset()
	 */
	ax88179_write_u8(dev, AX88179A_PHY_POWER, 0, 0, 0);
	msleep(250);

	ax88179a_reset(dev);

err_out:
	if (netif_running(dev->net)) {
		rtnl_lock();
		phylink_resume(ax179_data->phylink);
		rtnl_unlock();
	}

	ax88179_set_pm_mode(dev, false);

	return usbnet_resume(intf);
}

static void ax88179a_get_drvinfo(struct net_device *net, struct ethtool_drvinfo *info)
{
	struct ax88179_data *priv = netdev2data(net);

	/* Inherit standard device info */
	usbnet_get_drvinfo(net, info);
	if (priv->chip_version < AX_VERSION_AX88179A)
		return;

	snprintf(info->fw_version, sizeof(info->fw_version), "%d.%d.%d.%d",
		 priv->fw_version[0], priv->fw_version[1],
		 priv->fw_version[2], priv->fw_version[3]);
}

static void ax88179a_bulkin_config(struct usbnet *dev, u8 link_sts, u8 speed, bool full_duplex)
{
	struct ax88179_data *ax179_data = dev->driver_priv;
	const struct ax_bulkin_settings *bulkin_data;
	int index = 0;

	switch (speed) {
	case ETHER_LINK_2500:	/* AX88279 only */
		index = BULK_IN_SPEED_2G5;
		break;

	case ETHER_LINK_1000:	/* AX88279 & AX88178A */
		if (link_sts & AX_USB_SS)
			index = BULK_IN_SPEED_1G_SS;
		else if (link_sts & AX_USB_HS)
			index = BULK_IN_SPEED_1G_HS;
		break;

	case ETHER_LINK_100:
		if (link_sts & AX_USB_SS)
			index = BULK_IN_SPEED_100_FULL_SS;
		else if (link_sts & AX_USB_HS)
			index = BULK_IN_SPEED_100_FULL_HS;
		if (!full_duplex)
			index++;
		break;

	case ETHER_LINK_10:
		index = BULK_IN_SPEED_FS;
		break;

	default:	/* No link */
		index = BULK_IN_SPEED_FS;
	}

	if (link_sts & AX_USB_FS)
		index = BULK_IN_SPEED_FS;

	if (ax179_data->chip_version == AX_VERSION_AX88279) {
		bulkin_data = AX88279_BULKIN_SIZE;
	} else {
		if (ax179_data->is_ax88772d)
			bulkin_data = AX88772D_BULKIN_SIZE;
		else
			bulkin_data = AX88179A_BULKIN_SIZE;
	}

	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, 5, &bulkin_data[index]);
}

static void ax88179a_get_pauseparam(struct net_device *net, struct ethtool_pauseparam *pause)
{
	struct ax88179_data *data = netdev2data(net);

	phylink_ethtool_get_pauseparam(data->phylink, pause);
}

static int ax88179a_set_pauseparam(struct net_device *net, struct ethtool_pauseparam *pause)
{
	struct ax88179_data *data = netdev2data(net);

	return phylink_ethtool_set_pauseparam(data->phylink, pause);
}

static int ax88179a_get_link_ksettings(struct net_device *net,
				       struct ethtool_link_ksettings *cmd)
{
	struct ax88179_data *data = netdev2data(net);

	return phylink_ethtool_ksettings_get(data->phylink, cmd);
}

static int ax88179a_set_link_ksettings(struct net_device *net,
				       const struct ethtool_link_ksettings *cmd)
{
	struct ax88179_data *data = netdev2data(net);

	return phylink_ethtool_ksettings_set(data->phylink, cmd);
}

static int ax88179a_get_eeprom_len(struct net_device *net)
{
	struct ax88179_data *ax179_data = netdev2data(net);

	if (ax179_data->chip_version >= AX_VERSION_AX88279)
		return AX88279_EEPROM_LEN;
	else
		return AX88179A_EEPROM_LEN;
}

static int ax88179a_get_eee(struct net_device *net, struct ethtool_keee *edata)
{
	struct ax88179_data *ax179_data = netdev2data(net);

	return phylink_ethtool_get_eee(ax179_data->phylink, edata);
}

static int ax88179a_set_eee(struct net_device *net, struct ethtool_keee *edata)
{
	struct ax88179_data *ax179_data = netdev2data(net);

	return phylink_ethtool_set_eee(ax179_data->phylink, edata);
}

static const struct ethtool_ops ax88179a_ethtool_ops = {
	.get_drvinfo            = ax88179a_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_msglevel		= usbnet_get_msglevel,
	.set_msglevel		= usbnet_set_msglevel,
	.get_wol		= ax88179_get_wol,
	.set_wol		= ax88179_set_wol,
	.get_eeprom_len		= ax88179a_get_eeprom_len,
	.get_eeprom		= ax88179_get_eeprom,
	.set_eeprom		= ax88179_set_eeprom,
	.get_eee		= ax88179a_get_eee,
	.set_eee		= ax88179a_set_eee,
	.nway_reset		= phy_ethtool_nway_reset,
	.get_link_ksettings	= ax88179a_get_link_ksettings,
	.set_link_ksettings	= ax88179a_set_link_ksettings,
	.get_pauseparam		= ax88179a_get_pauseparam,
	.set_pauseparam		= ax88179a_set_pauseparam,
	.get_ts_info		= ethtool_op_get_ts_info,
};

static int ax88179a_vlan_rx_kill_vid(struct net_device *net, __be16 proto, u16 vid)
{
	struct usbnet *dev = netdev_priv(net);
	u16 reg16 = 0;
	u8 vlan_ctrl;
	int ret = 0;
	u8 reg8 = 0;

	ret = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL, 1, 1, &reg8);
	if (ret < 0)
		return ret;
	vlan_ctrl = reg8;

	/* Address */
	reg8 = (vid / 16);
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_ADDRESS, 1, 1, &reg8);
	if (ret < 0)
		return ret;

	/* Data */
	reg8 = vlan_ctrl | AX_VLAN_CONTROL_RD;
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL, 1, 1, &reg8);
	if (ret < 0)
		return ret;

	ret = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_DATA0, 2, 2, &reg16);
	if (ret < 0)
		return ret;
	reg16 &= ~(1 << (vid % 16));
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_DATA0, 2, 2, &reg16);
	if (ret < 0)
		return ret;

	reg8 = vlan_ctrl | AX_VLAN_CONTROL_WE;
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL, 1, 1, &reg8);
	if (ret < 0)
		return ret;

	return 0;
}

static int ax88179a_vlan_rx_add_vid(struct net_device *net, __be16 proto, u16 vid)
{
	struct usbnet *dev = netdev_priv(net);
	u8 vlan_ctrl;
	int ret = 0;
	u16 reg16;
	u8 reg8;

	ret = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL, 1, 1, &reg8);
	if (ret < 0)
		return ret;
	vlan_ctrl = reg8;

	/* Address */
	reg8 = (vid / 16);
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_ADDRESS, 1, 1, &reg8);
	if (ret < 0)
		return ret;

	/* Data */
	reg8 = vlan_ctrl | AX_VLAN_CONTROL_RD;
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL, 1, 1, &reg8);
	if (ret < 0)
		return ret;

	ret = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_DATA0, 2, 2, &reg16);
	if (ret < 0)
		return ret;
	reg16 |= (1 << (vid % 16));
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_DATA0, 2, 2, &reg16);
	if (ret < 0)
		return ret;

	reg8 = vlan_ctrl | AX_VLAN_CONTROL_WE;
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL, 1, 1, &reg8);
	if (ret < 0)
		return ret;

	return 0;
}

static void ax88179a_mdio_unregister(struct ax88179_data *data)
{
	mdiobus_unregister(data->mdio);
	mdiobus_free(data->mdio);
}

static int ax88179a_init_phy(struct usbnet *dev)
{
	struct ax88179_data *data = dev->driver_priv;
	int ret;

	data->phydev = mdiobus_get_phy(data->mdio, AX88179_PHY_ID);
	if (!data->phydev) {
		netdev_err(dev->net, "Could not find PHY\n");
		return -ENODEV;
	}

	data->phydev->irq = PHY_MAC_INTERRUPT;
	ret = phylink_connect_phy(data->phylink, data->phydev);
	if (ret) {
		netdev_err(dev->net, "Could not connect PHY\n");
		return ret;
	}

	phy_suspend(data->phydev);
	data->phydev->mac_managed_pm = true;

	phy_attached_info(data->phydev);

	return 0;
}

static void ax88179a_mac_config(struct phylink_config *config, unsigned int mode,
				const struct phylink_link_state *state)
{
	/* Nothing to do */
}

static void ax88179a_mac_link_down(struct phylink_config *config,
				   unsigned int mode, phy_interface_t interface)
{
	/* Nothing to do */
}

static void ax88179a_mac_link_up(struct phylink_config *config,
				 struct phy_device *phy,
				 unsigned int phy_mode, phy_interface_t interface,
				 int speed, int duplex,
				 bool tx_pause, bool rx_pause)
{
	struct usbnet *dev = netdev_priv(to_net_dev(config->dev));
	struct ax88179_data *ax179_data = dev->driver_priv;
	u8 link_sts = 0, reg8[3];
	u8 bulk_config_speed = 0;
	u16 mode;

	/* Stop RX/TX for link configuration */
	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, AX_RX_CTL_STOP);
	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_PATH, 1, 0);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_CDC_DELAY_TX, 1, 0xa5);

	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_LOW, 2, 0x0410);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_ETH_TX_GAP, 1, 0);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_EP5_EHR, 1, 0x07);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_NEW_PAUSE_CTRL, 1,
			 0x28 | AX_NEW_PAUSE_EN);

	mode = AX_MEDIUM_RECEIVE_EN;
	if (tx_pause)
		mode |= AX_MEDIUM_TXFLOW_CTRLEN;
	if (rx_pause)
		mode |= AX_MEDIUM_RXFLOW_CTRLEN;

	switch (speed) {
	case SPEED_2500:
		reg8[0] = 0x00;
		reg8[1] = 0xF8;
		reg8[2] = 0x07;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_MAC_TX_PAUSE, 3, 3, reg8);

		reg8[0] = 0x78;
		reg8[1] = (AX_LSOFC_WCNT_7_ACCESS << 5);
		reg8[2] = 0;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_MAC_RX_STATUS_CDC, 3, 3, reg8);

		ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_RX_DATA_CDC_CNT, 1, 0x40);
		ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_RX_DATA_CDC_CNT + 1, 1,
				 AX_MAC_MIQFFCTRL_FORMAT | AX_MAC_MIQFFCTRL_DROP_CRC |
				 AX_MAC_LSO_ERR_EN);

		ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_BFM_DATA, 1, AX_XGMII_EN);

		ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_LSO_ENHANCE_CTRL, 1,
				 0x1C | AX_LSO_ENHANCE_EN);

		mode |= AX_MEDIUM_GIGAMODE | AX_MEDIUM_FULL_DUPLEX;
		bulk_config_speed = ETHER_LINK_2500;

		break;

	case SPEED_1000:
		mode |= AX_MEDIUM_GIGAMODE;
		bulk_config_speed = ETHER_LINK_1000;
		fallthrough;

	case SPEED_100:
		reg8[0] = 0x78;
		reg8[1] = (AX_LSOFC_WCNT_7_ACCESS << 5) | AX_GMII_CRC_APPEND;
		reg8[2] = 0;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_MAC_RX_STATUS_CDC, 3, 3, reg8);

		ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_RX_DATA_CDC_CNT, 1, 0x40);
		if (!bulk_config_speed)
			bulk_config_speed = ETHER_LINK_100;
		break;

	case SPEED_10:
		reg8[0] = 0xFA;
		reg8[1] = (AX_LSOFC_WCNT_7_ACCESS << 5) | AX_GMII_CRC_APPEND;
		reg8[2] = 0xFF;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_MAC_RX_STATUS_CDC, 3, 3, reg8);

		ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_RX_DATA_CDC_CNT, 1, 0xFA);

		bulk_config_speed = ETHER_LINK_10;
		break;
	}

	ax88179_read_cmd(dev, AX_ACCESS_MAC, PHYSICAL_LINK_STATUS, 1, 1, &link_sts);
	ax88179a_bulkin_config(dev, link_sts, bulk_config_speed, !!duplex);

	if (speed != SPEED_2500)
		ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_BFM_DATA, 1, 0);

	if (duplex)
		mode |= AX_MEDIUM_FULL_DUPLEX;

	mutex_lock(&ax179_data->medium_status_mutex);
	if (dev->net->mtu > 1500)
		mode |= AX_MEDIUM_JUMBO_EN;
	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, mode);

	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, READ_ONCE(ax179_data->rxctl));
	mutex_unlock(&ax179_data->medium_status_mutex);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_PATH, 1,
			 AX_MAC_RX_PATH_READY | AX_MAC_TX_PATH_READY);
}

static void ax88179a_mac_disable_tx_lpi(struct phylink_config *config)
{
	struct usbnet *dev = netdev_priv(to_net_dev(config->dev));

	ax88179_write_cmd(dev, AX_GPHY_CTL, AX_GPHY_EEE_CTRL, false, 0, NULL);
}

static int ax88179a_mac_enable_tx_lpi(struct phylink_config *config, u32 timer, bool tx_clk_stop)
{
	struct usbnet *dev = netdev_priv(to_net_dev(config->dev));

	/* AX88179A does not provide LPI timer registers */
	return ax88179_write_cmd(dev, AX_GPHY_CTL, AX_GPHY_EEE_CTRL, true, 0, NULL);
}

static const struct phylink_mac_ops ax88179a_phylink_mac_ops = {
	.mac_config = ax88179a_mac_config,
	.mac_link_down = ax88179a_mac_link_down,
	.mac_link_up = ax88179a_mac_link_up,
	.mac_disable_tx_lpi = ax88179a_mac_disable_tx_lpi,
	.mac_enable_tx_lpi = ax88179a_mac_enable_tx_lpi,
};

static int ax88179a_phylink_setup(struct usbnet *dev)
{
	struct ax88179_data *data = dev->driver_priv;
	phy_interface_t phy_if_mode;
	struct phylink *phylink;

	data->phylink_config.dev = &dev->net->dev;
	data->phylink_config.type = PHYLINK_NETDEV;
	data->phylink_config.mac_capabilities = MAC_SYM_PAUSE | MAC_ASYM_PAUSE | MAC_100;
	if (data->is_ax88772d)
		data->phylink_config.mac_capabilities |= MAC_10;
	else if (data->chip_version < AX_VERSION_AX88279)
		data->phylink_config.mac_capabilities |= MAC_10 | MAC_1000;
	else
		data->phylink_config.mac_capabilities |= MAC_1000 | MAC_2500FD;

	if (!data->is_ax88772d) {
		data->phylink_config.lpi_capabilities = MAC_100FD | MAC_1000FD;
		data->phylink_config.eee_enabled_default = false;
	}

	if (data->chip_version == AX_VERSION_AX88279) {
		__set_bit(PHY_INTERFACE_MODE_2500BASEX,
			  data->phylink_config.supported_interfaces);
		__set_bit(PHY_INTERFACE_MODE_SGMII,
			  data->phylink_config.supported_interfaces);
		phy_if_mode = PHY_INTERFACE_MODE_2500BASEX;
	} else {
		__set_bit(PHY_INTERFACE_MODE_SGMII,
			  data->phylink_config.supported_interfaces);
		phy_if_mode = PHY_INTERFACE_MODE_SGMII;
	}

	memcpy(data->phylink_config.lpi_interfaces,
	       data->phylink_config.supported_interfaces,
	       sizeof(data->phylink_config.lpi_interfaces));

	phylink = phylink_create(&data->phylink_config, dev->net->dev.fwnode,
				 phy_if_mode, &ax88179a_phylink_mac_ops);
	if (IS_ERR(phylink))
		return PTR_ERR(phylink);

	data->phylink = phylink;
	return 0;
}

static int ax88179a_init_mdio(struct usbnet *dev)
{
	struct ax88179_data *data = dev->driver_priv;
	int ret;

	data->mdio = mdiobus_alloc();
	if (!data->mdio)
		return -ENOMEM;

	data->mdio->priv = dev;
	data->mdio->read = ax88179_mdiobus_read;
	data->mdio->write = ax88179_mdiobus_write;
	data->mdio->read_c45 = ax88179_mdiobus_read_c45;
	data->mdio->write_c45 = ax88179_mdiobus_write_c45;
	data->mdio->name = "AX88179A MDIO Bus";
	data->mdio->phy_mask = ~(1 << AX88179_PHY_ID);
	/* mii bus name is usb-<usb bus number>-<usb device number> */
	snprintf(data->mdio->id, MII_BUS_ID_SIZE, "usb-%03d:%03d",
		 dev->udev->bus->busnum, dev->udev->devnum);

	ret = mdiobus_register(data->mdio);
	if (ret) {
		netdev_err(dev->net, "Could not register MDIO bus (err %d)\n", ret);
		mdiobus_free(data->mdio);
		data->mdio = NULL;
	}

	return ret;
}

static int ax88179a_mii_ioctl(struct net_device *net, struct ifreq *rq, int cmd)
{
	struct ax88179_data *data = netdev2data(net);

	return phylink_mii_ioctl(data->phylink, rq, cmd);
}

static int ax88179a_set_features(struct net_device *net, netdev_features_t features)
{
	struct usbnet *dev = netdev_priv(net);
	netdev_features_t changed;
	int ret;
	u8 tmp;

	changed = net->features ^ features;

	ret = ax88179_set_features(net, features);
	if (ret)
		return ret;

	if (changed & NETIF_F_HW_VLAN_CTAG_FILTER) {
		if (features & NETIF_F_HW_VLAN_CTAG_FILTER) {
			u8 vlan_state = 0;

			ret = ax88179_read_cmd(dev, AX_ACCESS_MAC,
					       AX88179A_VLAN_ID_CONTROL, 1, 1, &vlan_state);
			if (ret < 0)
				return ret;

			for (int i = 0; i < 256; i++) {
				/* Address */
				tmp = i;
				ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_ADDRESS,
						  1, 1, &tmp);
				/* Data */
				ax88179_write_u16(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_DATA0,
						  2, 0);
				/* Write-Execute */
				ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL,
						 1, vlan_state | AX_VLAN_CONTROL_WE);
			}
			vlan_state |= AX_VLAN_CONTROL_VFE;
			ret = ax88179_write_cmd(dev, AX_ACCESS_MAC,
						AX88179A_VLAN_ID_CONTROL, 1, 1, &vlan_state);
			if (ret < 0)
				return ret;
		} else {
			ret = ax88179_read_cmd(dev, AX_ACCESS_MAC,
					       AX88179A_VLAN_ID_CONTROL, 1, 1, &tmp);
			if (ret < 0)
				return ret;
			tmp &= ~AX_VLAN_CONTROL_VFE;
			ret = ax88179_write_cmd(dev, AX_ACCESS_MAC,
						AX88179A_VLAN_ID_CONTROL, 1, 1, &tmp);
			if (ret < 0)
				return ret;
		}
	}

	if (changed & NETIF_F_HW_VLAN_CTAG_RX) {
		ret = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL,
				       1, 1, &tmp);
		if (ret < 0)
			return ret;
		if (features & NETIF_F_HW_VLAN_CTAG_RX)
			tmp |= AX_VLAN_CONTROL_VSO;
		else
			tmp &= ~AX_VLAN_CONTROL_VSO;
		ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL,
					1, 1, &tmp);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static const struct net_device_ops ax88179a_netdev_ops = {
	.ndo_open		= usbnet_open,
	.ndo_stop		= usbnet_stop,
	.ndo_start_xmit		= usbnet_start_xmit,
	.ndo_tx_timeout		= usbnet_tx_timeout,
	.ndo_get_stats64	= dev_get_tstats64,
	.ndo_change_mtu		= ax88179_change_mtu,
	.ndo_set_mac_address	= ax88179_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_eth_ioctl		= ax88179a_mii_ioctl,
	.ndo_set_rx_mode	= ax88179_set_multicast,
	.ndo_set_features	= ax88179a_set_features,
	.ndo_vlan_rx_add_vid	= ax88179a_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= ax88179a_vlan_rx_kill_vid,
};

static int ax88179a_bind(struct usbnet *dev, struct usb_interface *intf)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct ax88179_data *ax179_data;
	int ret;

	/* Check if vendor configuration */
	if (udev->actconfig->desc.bConfigurationValue != 1) {
		netdev_info(dev->net, "Switching to vendor mode\n");
		usb_driver_set_configuration(udev, 1);
		return -ENODEV;
	}

	ret = usbnet_get_endpoints(dev, intf);
	if (ret < 0)
		return ret;

	ax179_data = kzalloc_obj(*ax179_data);
	if (!ax179_data)
		return -ENOMEM;

	dev->driver_priv = ax179_data;
	mutex_init(&ax179_data->medium_status_mutex);

	ret = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_CHIP_STATUS,
			       1, 1, &ax179_data->chip_version);
	if (ret < 0)
		goto err_nodev;

	ax179_data->chip_version = (ax179_data->chip_version & 0xf0) >> 4;
	ax179_data->is_ax88772d = 0;
	if (ax179_data->chip_version == AX_VERSION_AX88179A) {
		if (le16_to_cpu(udev->descriptor.bcdDevice) == 0x300)
			ax179_data->is_ax88772d = 1;
	}

	for (int i = 0; i < 3; i++) {
		ret = ax88179_read_cmd(dev, AX88179A_ACCESS_BL, AX88179A_SW_VERSION + i,
				       1, 1, &ax179_data->fw_version[i]);
		if (ret < 0)
			ax179_data->fw_version[i] = 0xff;
	}
	ret = ax88179_read_cmd(dev, AX88179A_ACCESS_BL, AX88179A_SW_REVISION,
			       1, 1, &ax179_data->fw_version[3]);
	if (ret < 0)
		ax179_data->fw_version[3] = 0xff;

	netdev_info(dev->net, "AX88179A/279/772D Chip Version: %x, FW: %d.%d.%d.%d\n",
		    ax179_data->chip_version,
		    ax179_data->fw_version[0], ax179_data->fw_version[1],
		    ax179_data->fw_version[2], ax179_data->fw_version[3]);

	/* The AX88279 requires both the AX_RX_CTL_IPE and AX_RX_CTL_DROPCRCERR
	 * bits set in AX_RX_CTL for creating correct RX-URBs. AX_RX_CTL_DROPCRCERR
	 * is anyway set for all chips, make sure AX_RX_CTL_IPE is set via ip_align.
	 * Also configure eeprom access parameters.
	 */
	if (ax179_data->chip_version == AX_VERSION_AX88279) {
		ax179_data->ip_align = 1;
		ax179_data->eeprom_read_cmd = AX88179A_FLASH_READ;
		ax179_data->eeprom_write_cmd = AX88179A_FLASH_WRITE;
		ax179_data->eeprom_block = 256;
		ax179_data->eeprom_wen = 1;
	} else {
		ax179_data->ip_align = 0;
		ax179_data->eeprom_read_cmd = AX_ACCESS_EFUS;
		ax179_data->eeprom_write_cmd = AX_ACCESS_EFUS;
		ax179_data->eeprom_block = 20;
		ax179_data->eeprom_wen = 0;
	}

	ax179_data->resume = ax88179a_resume;
	ax179_data->suspend = ax88179a_suspend;

	dev->net->netdev_ops = &ax88179a_netdev_ops;
	dev->net->ethtool_ops = &ax88179a_ethtool_ops;
	dev->net->needed_headroom = 8;
	dev->net->needed_tailroom = 8;
	dev->net->min_mtu = ETH_MIN_MTU;
	dev->hard_mtu = 9 * 1024;
	dev->net->max_mtu = dev->hard_mtu - dev->net->hard_header_len;

	if (!ax179_data->is_ax88772d)
		dev->mii.supports_gmii = 1;

	dev->net->features |= NETIF_F_SG | NETIF_F_IP_CSUM |
			      NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM | NETIF_F_TSO |
			      NETIF_F_HW_VLAN_CTAG_TX;

	dev->net->hw_features |= dev->net->features;
	dev->net->hw_features |= NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_FILTER;

	dev->net->vlan_features = NETIF_F_SG | NETIF_F_IP_CSUM |
				  NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM | NETIF_F_TSO;

	netif_set_tso_max_size(dev->net, 16384);

	/* Enable Transmission of Link Speed byte in interrupt URB */
	ax88179_write_cmd(dev, AX_FW_MODE, AX_FW_MODE_179A, 0, 0, NULL);
	ax88179_write_cmd(dev, AX_RELOAD_EEPROM_EFUSE, 0, 0, 0, NULL);

	/* Read MAC address from DTB or ASIX chip */
	ax88179_get_mac_addr(dev);
	memcpy(dev->net->perm_addr, dev->net->dev_addr, ETH_ALEN);

	/* Power PHY for probing */
	ax88179_write_u8(dev, AX88179A_PHY_POWER, 0, 0, AX_PHY_POWER);
	msleep(250);

	ret = ax88179a_init_mdio(dev);
	if (ret)
		goto err_nodev;

	ret = ax88179a_phylink_setup(dev);
	if (ret)
		goto phylink_err;

	ret = ax88179a_init_phy(dev);
	if (ret)
		goto initphy_err;

	/* Keep this interface runtime-PM active by taking a usage ref.
	 * Prevents runtime suspend while bound and avoids resume paths
	 * that could deadlock (autoresume under RTNL while USB PM lock
	 * is held, phylink/MDIO wants RTNL).
	 */
	pm_runtime_get_noresume(&intf->dev);

	return 0;

initphy_err:
	phylink_destroy(ax179_data->phylink);
phylink_err:
	ax88179a_mdio_unregister(ax179_data);
err_nodev:
	kfree(ax179_data);
	ax179_data = NULL;

	return ret;
}

static void ax88179a_unbind(struct usbnet *dev, struct usb_interface *intf)
{
	struct ax88179_data *ax179_data = dev->driver_priv;

	/* Configure RX control register => stop operation */
	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, AX_RX_CTL_STOP);

	rtnl_lock();
	phylink_disconnect_phy(ax179_data->phylink);
	rtnl_unlock();
	phylink_destroy(ax179_data->phylink);
	ax88179a_mdio_unregister(ax179_data);

	ax88179_write_u8(dev, AX88179A_PHY_POWER, 0, 0, 0);
	/* Drop the PM usage ref taken in bind() */
	pm_runtime_put_noidle(&intf->dev);
	kfree(ax179_data);
}

static void ax88179a_rx_checksum(struct sk_buff *skb, u64 pkt_desc)
{
	u32 pkt_type;

	skb->ip_summed = CHECKSUM_NONE;
	/* checksum error bit is set */
	if (pkt_desc & AX179A_RX_PD_L4_ERR || pkt_desc & AX179A_RX_PD_L3_ERR)
		return;

	pkt_type = pkt_desc & AX179A_RX_PD_L4_TYPE_MASK;
	/* It must be a TCP or UDP packet with a valid checksum */
	if (pkt_type == AX179A_RX_PD_L4_TCP || pkt_type == AX179A_RX_PD_L4_UDP)
		skb->ip_summed = CHECKSUM_UNNECESSARY;
}

static int ax88179a_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	struct ax88179_data *ax179_data = dev->driver_priv;
	struct sk_buff *ax_skb;
	u32 hdr_off, pkt_end;
	__le64 *pkt_desc_ptr;
	u16 vlan_tag;
	u16 pkt_cnt;
	u64 rx_hdr;

	/* SKB contents for AX179A-based chips:
	 *   <packet 1>
	 *   ...
	 *   <packet N>
	 *   <per-packet metadata entry 1>
	 *   ...
	 *   <per-packet metadata entry N>
	 *   <rx_hdr>
	 *
	 * where:
	 *   <packet N> contains pkt_len data bytes and padding:
	 *		2 bytes of IP alignment (optional, depends on AX_RX_CTL_IPE flag)
	 *		packet data received
	 *		optional padding to 8-bytes boundary
	 *   <per-packet metadata entry N> contains 8 bytes:
	 *		pkt_len and fields AX_RXHDR_*
	 *   <rx-hdr>	contains 8 bytes:
	 *		pkt_cnt and hdr_off (offset of <per-packet metadata entry 1>)
	 *
	 * pkt_cnt is number of entries in the per-packet metadata array.
	 */

	if (!skb || skb->len < sizeof(rx_hdr))
		goto err;

	/* RX Descriptor Header */
	skb_trim(skb, skb->len - sizeof(rx_hdr));
	rx_hdr = get_unaligned_le64((__le64 *)skb_tail_pointer(skb));

	/* Check these packets */
	hdr_off = FIELD_GET(AX179A_RX_DH_DESC_OFFSET, rx_hdr);
	pkt_cnt = rx_hdr & AX179A_RX_DH_PKT_CNT_MASK;

	/* Consistency check header position */
	if (hdr_off != skb->len - (pkt_cnt * sizeof(rx_hdr)))
		goto err;

	/* Make sure that the bounds of the metadata array are inside the SKB
	 * (and in front of the counter at the end).
	 */
	if (pkt_cnt * 8 + hdr_off > skb->len)
		goto err;

	/* Packets must not overlap the metadata array */
	skb_trim(skb, hdr_off);

	if (!pkt_cnt)
		goto err;

	/* Get the first RX packet descriptor */
	pkt_desc_ptr = (__le64 *)(skb->data + hdr_off);

	pkt_end = 0;
	while (pkt_cnt--) {
		u64 pkt_desc = get_unaligned_le64(pkt_desc_ptr);
		u32 pkt_len_plus_padd;
		u32 pkt_len;

		pkt_len = FIELD_GET(AX179A_RX_PD_LEN, pkt_desc);
		pkt_len -= (ax179_data->ip_align ? 2 : 0);
		pkt_len_plus_padd = ((pkt_len + 7 + (ax179_data->ip_align ? 2 : 0)) & 0x7FFF8);

		pkt_end += pkt_len_plus_padd;
		if (pkt_end > hdr_off || (pkt_cnt == 0 && pkt_end != hdr_off))
			goto err;

		if (pkt_desc & AX179A_RX_PD_DROP || !(pkt_desc & AX179A_RX_PD_RX_OK) ||
		    pkt_len > (dev->hard_mtu + AX179A_RX_HW_PAD) || pkt_len < 2 + ETH_HLEN) {
			skb_pull(skb, pkt_len_plus_padd);

			/* Next RX Packet Descriptor */
			pkt_desc_ptr++;
			continue;
		}

		ax_skb = netdev_alloc_skb_ip_align(dev->net, pkt_len);
		if (!ax_skb)
			goto err;

		skb_put(ax_skb, pkt_len);
		memcpy(ax_skb->data, skb->data + (ax179_data->ip_align ? AX179A_RX_HW_PAD : 0),
		       pkt_len);

		if (ax179_data->rx_checksum)
			ax88179a_rx_checksum(ax_skb, pkt_desc);

		if (pkt_desc & AX179A_RX_PD_VLAN) {
			vlan_tag = pkt_desc >> AX179A_RX_PD_VLAN_SHIFT;
			__vlan_hwaccel_put_tag(ax_skb, htons(ETH_P_8021Q), vlan_tag);
		}

		usbnet_skb_return(dev, ax_skb);
		skb_pull(skb, pkt_len_plus_padd);

		/* Next RX Packet Header */
		pkt_desc_ptr++;
	}

	return 1;

err:
	return 0;
}

static struct sk_buff *ax88179a_tx_fixup(struct usbnet *dev, struct sk_buff *skb, gfp_t flags)
{
	u64 tx_desc = skb->len & AX179A_TX_DESC_LEN_MASK;
	int frame_size = dev->maxpacket;
	struct sk_buff *ax_skb;
	u64 *tx_desc_ptr;
	int padding_size;
	int headroom;
	int tailroom;
	u16 tci = 0;

	/* TSO MSS */
	tx_desc |= FIELD_PREP(AX179A_TX_DESC_MSS, (u64)skb_shinfo(skb)->gso_size);

	headroom = (skb->len + sizeof(tx_desc)) % 8;
	padding_size = headroom ? 8 - headroom : 0;

	if (((skb->len + sizeof(tx_desc) + padding_size) % frame_size) == 0) {
		padding_size += 8;
		tx_desc |= AX179A_TX_DESC_DROP_PADD;
	}

	if ((dev->net->features & NETIF_F_HW_VLAN_CTAG_TX) && (vlan_get_tag(skb, &tci) >= 0)) {
		tx_desc |= AX179A_TX_DESC_VLAN;
		tx_desc |= FIELD_PREP(AX179A_TX_DESC_VLAN_ID, (u64)tci);
	}

	if (!dev->can_dma_sg && (dev->net->features & NETIF_F_SG) && skb_linearize(skb)) {
		dev_kfree_skb_any(skb);
		return NULL;
	}

	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);

	if (skb_cloned(skb) || !(headroom >= sizeof(tx_desc) && tailroom >= padding_size)) {
		ax_skb = skb_copy_expand(skb, sizeof(tx_desc), padding_size, flags);
		dev_kfree_skb_any(skb);
		skb = ax_skb;
		if (!skb)
			return NULL;
	}
	if (padding_size != 0)
		skb_put_zero(skb, padding_size);
	/* Copy TX header */
	tx_desc_ptr = skb_push(skb, sizeof(tx_desc));
	put_unaligned_le64(tx_desc, tx_desc_ptr);

	usbnet_set_skb_tx_stats(skb, 1, 0);

	return skb;
}

static int ax88179a_reset(struct usbnet *dev)
{
	struct ax88179_data *ax179_data = dev->driver_priv;
	u16 *tmp16;
	u8 buf[5];
	u16 rxctl;
	u8 *tmp;

	tmp16 = (u16 *)buf;
	tmp = (u8 *)buf;

	/* Power up ethernet PHY */
	ax88179_write_u8(dev, AX88179A_PHY_POWER, 0, 0, AX_PHY_POWER);
	msleep(250);

	/* Ethernet PHY Auto Detach*/
	ax88179a_auto_detach(dev);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_BULK_OUT_CTRL, 1, AX_MAC_EFF_EN);

	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 0);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_LOW, 1, 0x04);
	ax88179_write_u8(dev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_HIGH, 1, 0x10);

	*tmp = 0;
	if (dev->net->features & NETIF_F_HW_VLAN_CTAG_FILTER)
		*tmp |= AX_VLAN_CONTROL_VFE;
	if (dev->net->features & NETIF_F_HW_VLAN_CTAG_RX)
		*tmp |= AX_VLAN_CONTROL_VSO;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX88179A_VLAN_ID_CONTROL, 1, 1, tmp);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_BM_INT_MASK, 1, 0xff);

	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_BM_RX_DMA_CTL, 1, 0);
	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_BM_TX_DMA_CTL, 1, 0);
	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_ARC_CTRL, 1, 0);
	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_SWP_CTRL, 1, 0);
	ax88179_write_u8(dev, AX_ACCESS_MAC, AX88179A_MAC_TX_HDR_CKSUM, 1, 0);

	/* Read MAC address from DTB or asix chip, except when called
	 * from resume context.
	 */
	if (!ax179_data->in_pm) {
		ax88179_get_mac_addr(dev);
		memcpy(dev->net->perm_addr, dev->net->dev_addr, ETH_ALEN);
	}

	/* The Bulk-Register configuration for the AX88179A is done in
	 * ax88179a_mac_link_up(), once the link is up for a given link and USB-speed.
	 */
	if (ax179_data->is_ax88772d)
		dev->rx_urb_size = 1024 * 24;
	else
		dev->rx_urb_size = 1024 * 48;

	/* Enable checksum offload */
	if (dev->net->features & NETIF_F_RXCSUM) {
		ax88179_write_u8(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1,
				 AX_RXCOE_IP | AX_RXCOE_TCP | AX_RXCOE_UDP |
				 AX_RXCOE_TCPV6 | AX_RXCOE_UDPV6);
		ax179_data->rx_checksum = 1;
	} else {
		ax179_data->rx_checksum = 0;
		ax88179_write_u8(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 0);
	}

	*tmp = 0;
	if (dev->net->features & NETIF_F_IP_CSUM)
		*tmp = AX_TXCOE_IP | AX_TXCOE_TCP | AX_TXCOE_UDP;
	if (dev->net->features & NETIF_F_IPV6_CSUM)
		*tmp |= AX_TXCOE_IP | AX_TXCOE_TCPV6 | AX_TXCOE_UDPV6;
	ax88179_write_u8(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, *tmp);

	/* Configure RX control register => start operation */
	rxctl = AX_RX_CTL_DROPCRCERR | AX_RX_CTL_START | AX_RX_CTL_AP |
		AX_RX_CTL_AMALL | AX_RX_CTL_AB;
	if (ax179_data->ip_align)
		rxctl |= AX_RX_CTL_IPE;
	if (dev->net->flags & IFF_PROMISC)
		rxctl |= AX_RX_CTL_PRO;
	WRITE_ONCE(ax179_data->rxctl, rxctl);
	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, rxctl);

	if (ax179_data->chip_version < AX_VERSION_AX88179A)
		*tmp = AX_MONITOR_MODE_PMETYPE | AX_MONITOR_MODE_PMEPOL | AX_MONITOR_MODE_RWMP;
	else
		*tmp = AX_MONITOR_MODE_RWMP;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD, 1, 1, tmp);

	/* Configure default medium type => giga */
	*tmp16 = AX_MEDIUM_RECEIVE_EN | AX_MEDIUM_TXFLOW_CTRLEN |
		 AX_MEDIUM_RXFLOW_CTRLEN | AX_MEDIUM_FULL_DUPLEX;
	if (!ax179_data->is_ax88772d)
		*tmp16 |= AX_MEDIUM_GIGAMODE;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, 2, tmp16);

	/* Check if WoL is supported */
	ax179_data->wol_supported = 0;
	if (ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD,
			     1, 1, tmp) > 0)
		ax179_data->wol_supported = WAKE_MAGIC | WAKE_PHY;

	/* Ensure EEE state is off, consistent with phylink setup */
	ax88179_write_cmd(dev, AX_GPHY_CTL, AX_GPHY_EEE_CTRL, false, 0, NULL);

	/* ax88179a_reset() may also be called from resume context,
	 * phylink_resume() will start phylink, then.
	 */
	if (!ax179_data->in_pm)
		phylink_start(ax179_data->phylink);

	return 0;
}

static int ax88179a_stop(struct usbnet *dev)
{
	struct ax88179_data *ax179_data = dev->driver_priv;
	u16 reg16 = 0;

	phylink_stop(ax179_data->phylink);

	ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, 2, &reg16);
	reg16 &= ~AX_MEDIUM_RECEIVE_EN;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, 2, &reg16);

	ax88179_write_u16(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 0);

	ax88179_write_u8(dev, AX88179A_PHY_POWER, 0, 0, 0);

	return 0;
}

const struct driver_info ax88179a_info = {
	.description = "ASIX AX88179A USB 3.2 Gigabit Ethernet",
	.bind = ax88179a_bind,
	.unbind = ax88179a_unbind,
	.status = ax88179a_status,
	.reset = ax88179a_reset,
	.stop = ax88179a_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX | FLAG_MULTI_PACKET | FLAG_AVOID_UNLINK_URBS,
	.rx_fixup = ax88179a_rx_fixup,
	.tx_fixup = ax88179a_tx_fixup,
};

const struct driver_info ax88772d_info = {
	.description = "ASIX AX88772D/E USB 2.0 Fast Ethernet",
	.bind = ax88179a_bind,
	.unbind = ax88179a_unbind,
	.status = ax88179a_status,
	.reset = ax88179a_reset,
	.stop = ax88179a_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX | FLAG_MULTI_PACKET | FLAG_AVOID_UNLINK_URBS,
	.rx_fixup = ax88179a_rx_fixup,
	.tx_fixup = ax88179a_tx_fixup,
};

const struct driver_info ax88279_info = {
	.description = "ASIX AX88279 USB 3.2 2.5Gigabit Ethernet",
	.bind = ax88179a_bind,
	.unbind = ax88179a_unbind,
	.status = ax88179a_status,
	.reset = ax88179a_reset,
	.stop = ax88179a_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX | FLAG_MULTI_PACKET | FLAG_AVOID_UNLINK_URBS,
	.rx_fixup = ax88179a_rx_fixup,
	.tx_fixup = ax88179a_tx_fixup,
};
