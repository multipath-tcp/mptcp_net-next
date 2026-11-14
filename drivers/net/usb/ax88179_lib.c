// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ASIX AX88179/178A USB 3.0/2.0 to Gigabit Ethernet Devices
 *
 * Copyright (C) 2011-2013 ASIX
 */

#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include "ax88179_lib.h"

void ax88179_set_pm_mode(struct usbnet *dev, bool pm_mode)
{
	struct ax88179_data *ax179_data = dev->driver_priv;

	ax179_data->in_pm = pm_mode;
}

static int ax88179_in_pm(struct usbnet *dev)
{
	struct ax88179_data *ax179_data = dev->driver_priv;

	return ax179_data->in_pm;
}

int __ax88179_read_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
		       u16 size, void *data)
{
	int (*fn)(struct usbnet *dev, u8 cmd, u8 rtype, u16 val, u16 i, void *d, u16 size);
	struct ax88179_data *ax179_data = dev->driver_priv;
	int ret;

	if (!ax88179_in_pm(dev))
		fn = usbnet_read_cmd;
	else
		fn = usbnet_read_cmd_nopm;

	ret = fn(dev, cmd, USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
		 value, index, data, size);

	if (unlikely(ret < 0 && !(ret == -ENODEV && ax179_data->disconnecting)))
		netdev_warn(dev->net, "Failed to read reg index 0x%04x: %d\n",
			    index, ret);

	return ret;
}

static int __ax88179_write_cmd(struct usbnet *dev, u8 cmd, u16 value,
			       u16 index, u16 size, const void *data)
{
	int (*fn)(struct usbnet *dev, u8 cmd, u8 rtype, u16 val, u16 i, const void *d, u16 size);
	struct ax88179_data *ax179_data = dev->driver_priv;
	int ret;

	if (!ax88179_in_pm(dev))
		fn = usbnet_write_cmd;
	else
		fn = usbnet_write_cmd_nopm;

	ret = fn(dev, cmd, USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
		 value, index, data, size);

	if (unlikely(ret < 0 && !(ret == -ENODEV && ax179_data->disconnecting)))
		netdev_warn(dev->net, "Failed to write reg index 0x%04x: %d\n",
			    index, ret);

	return ret;
}

void ax88179_write_cmd_async(struct usbnet *dev, u8 cmd, u16 value,
			     u16 index, u16 size, void *data)
{
	u16 buf;

	if (size == 2) {
		buf = *((u16 *)data);
		cpu_to_le16s(&buf);
		usbnet_write_cmd_async(dev, cmd, USB_DIR_OUT | USB_TYPE_VENDOR |
				       USB_RECIP_DEVICE, value, index, &buf,
				       size);
	} else {
		usbnet_write_cmd_async(dev, cmd, USB_DIR_OUT | USB_TYPE_VENDOR |
				       USB_RECIP_DEVICE, value, index, data,
				       size);
	}
}

int ax88179_read_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
		     u16 size, void *data)
{
	int ret;

	if (size == 2) {
		u16 buf = 0;

		ret = __ax88179_read_cmd(dev, cmd, value, index, size, &buf);
		le16_to_cpus(&buf);
		*((u16 *)data) = buf;
	} else if (size == 4) {
		u32 buf = 0;

		ret = __ax88179_read_cmd(dev, cmd, value, index, size, &buf);
		le32_to_cpus(&buf);
		*((u32 *)data) = buf;
	} else {
		ret = __ax88179_read_cmd(dev, cmd, value, index, size, data);
	}

	return ret;
}

int ax88179_write_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
		      u16 size, const void *data)
{
	int ret;

	if (size == 2) {
		u16 buf;

		buf = *((u16 *)data);
		cpu_to_le16s(&buf);
		ret = __ax88179_write_cmd(dev, cmd, value, index,
					  size, &buf);
	} else {
		ret = __ax88179_write_cmd(dev, cmd, value, index,
					  size, data);
	}

	return ret;
}

int ax88179_write_u16(struct usbnet *dev, u8 cmd, u16 value, u16 index, u16 data)
{
	u16 buf = data;

	cpu_to_le16s(&buf);
	return __ax88179_write_cmd(dev, cmd, value, index, 2, &buf);
}

int ax88179_write_u8(struct usbnet *dev, u8 cmd, u16 value, u16 index, u8 data)
{
	u8 buf = data;

	return __ax88179_write_cmd(dev, cmd, value, index, 1, &buf);
}

struct ax88179_data *netdev2data(struct net_device *net)
{
	struct usbnet *dev = netdev_priv(net);

	return dev->driver_priv;
}

void ax88179_status(struct usbnet *dev, struct urb *urb)
{
	struct ax88179_int_data *event;
	u32 link;

	if (urb->actual_length < 8)
		return;

	event = urb->transfer_buffer;
	le32_to_cpus((void *)&event->intdata1);

	link = (((__force u32)event->intdata1) & AX_INT_PPLS_LINK) >> 16;

	if (netif_carrier_ok(dev->net) != link) {
		usbnet_link_change(dev, link, 1);
		if (!link)
			netdev_info(dev->net, "ax88179 - Link status is: 0\n");
	}
}

int ax88179_mdio_read(struct net_device *netdev, int phy_id, int loc)
{
	struct usbnet *dev = netdev_priv(netdev);
	u16 res;

	ax88179_read_cmd(dev, AX_ACCESS_PHY, phy_id, (__u16)loc, 2, &res);
	return res;
}

void ax88179_mdio_write(struct net_device *netdev, int phy_id, int loc, int val)
{
	struct usbnet *dev = netdev_priv(netdev);
	u16 res = (u16)val;

	ax88179_write_cmd(dev, AX_ACCESS_PHY, phy_id, (__u16)loc, 2, &res);
}

void ax88179_get_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax88179_data *priv = dev->driver_priv;

	wolinfo->supported = priv->wol_supported;
	wolinfo->wolopts = priv->wolopts;
}

int ax88179_set_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax88179_data *priv = dev->driver_priv;

	if (wolinfo->wolopts & ~(priv->wol_supported))
		return -EINVAL;

	priv->wolopts = wolinfo->wolopts;

	return 0;
}

int ax88179_get_eeprom(struct net_device *net, struct ethtool_eeprom *eeprom, u8 *data)
{
	struct usbnet *dev = netdev_priv(net);
	u16 *eeprom_buff;
	int first_word, last_word;
	int i, ret;

	if (eeprom->len == 0)
		return -EINVAL;

	eeprom->magic = AX88179_EEPROM_MAGIC;

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;
	eeprom_buff = kmalloc_objs(u16, last_word - first_word + 1);
	if (!eeprom_buff)
		return -ENOMEM;

	/* ax88179/178A returns 2 bytes from eeprom on read */
	for (i = first_word; i <= last_word; i++) {
		ret = __ax88179_read_cmd(dev, AX_ACCESS_EEPROM, i, 1, 2,
					 &eeprom_buff[i - first_word]);
		if (ret < 0) {
			kfree(eeprom_buff);
			return -EIO;
		}
	}

	memcpy(data, (u8 *)eeprom_buff + (eeprom->offset & 1), eeprom->len);
	kfree(eeprom_buff);
	return 0;
}

int ax88179_set_eeprom(struct net_device *net, struct ethtool_eeprom *eeprom, u8 *data)
{
	struct usbnet *dev = netdev_priv(net);
	u16 *eeprom_buff;
	int first_word;
	int last_word;
	int ret;
	int i;

	netdev_dbg(net, "write EEPROM len %d, offset %d, magic 0x%x\n",
		   eeprom->len, eeprom->offset, eeprom->magic);

	if (eeprom->len == 0)
		return -EINVAL;

	if (eeprom->magic != AX88179_EEPROM_MAGIC)
		return -EINVAL;

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;

	eeprom_buff = kmalloc_objs(u16, last_word - first_word + 1);
	if (!eeprom_buff)
		return -ENOMEM;

	/* align data to 16 bit boundaries, read the missing data from
	 * the EEPROM
	 */
	if (eeprom->offset & 1) {
		ret = ax88179_read_cmd(dev, AX_ACCESS_EEPROM, first_word, 1, 2,
				       &eeprom_buff[0]);
		if (ret < 0) {
			netdev_err(net, "Failed to read EEPROM at offset 0x%02x.\n", first_word);
			goto free;
		}
	}

	if ((eeprom->offset + eeprom->len) & 1) {
		ret = ax88179_read_cmd(dev, AX_ACCESS_EEPROM, last_word, 1, 2,
				       &eeprom_buff[last_word - first_word]);
		if (ret < 0) {
			netdev_err(net, "Failed to read EEPROM at offset 0x%02x.\n", last_word);
			goto free;
		}
	}

	memcpy((u8 *)eeprom_buff + (eeprom->offset & 1), data, eeprom->len);

	for (i = first_word; i <= last_word; i++) {
		netdev_dbg(net, "write to EEPROM at offset 0x%02x, data 0x%04x\n",
			   i, eeprom_buff[i - first_word]);
		ret = ax88179_write_cmd(dev, AX_ACCESS_EEPROM, i, 1, 2,
					&eeprom_buff[i - first_word]);
		if (ret < 0) {
			netdev_err(net, "Failed to write EEPROM at offset 0x%02x.\n", i);
			goto free;
		}
		msleep(20);
	}

	/* reload EEPROM data */
	ret = ax88179_write_cmd(dev, AX_RELOAD_EEPROM_EFUSE, 0x0000, 0, 0, NULL);
	if (ret < 0) {
		netdev_err(net, "Failed to reload EEPROM data\n");
		goto free;
	}

	ret = 0;
free:
	kfree(eeprom_buff);
	return ret;
}

void ax88179_set_multicast(struct net_device *net)
{
	struct usbnet *dev = netdev_priv(net);
	u8 *m_filter = ((u8 *)dev->data);
	struct ax88179_data *data;
	u16 rxctl = 0;

	data = dev->driver_priv;

	rxctl = (AX_RX_CTL_START | AX_RX_CTL_AB | AX_RX_CTL_DROPCRCERR);
	if (data->ip_align)
		rxctl |= AX_RX_CTL_IPE;

	if (net->flags & IFF_PROMISC) {
		rxctl |= AX_RX_CTL_PRO;
	} else if (net->flags & IFF_ALLMULTI ||
		   netdev_mc_count(net) > AX_MAX_MCAST) {
		rxctl |= AX_RX_CTL_AMALL;
	} else if (netdev_mc_empty(net)) {
		/* just broadcast and directed */
	} else {
		/* We use dev->data for our 8 byte filter buffer
		 * to avoid allocating memory that is tricky to free later
		 */
		u32 crc_bits;
		struct netdev_hw_addr *ha;

		memset(m_filter, 0, AX_MCAST_FLTSIZE);

		netdev_for_each_mc_addr(ha, net) {
			crc_bits = ether_crc(ETH_ALEN, ha->addr) >> 26;
			*(m_filter + (crc_bits >> 3)) |= (1 << (crc_bits & 7));
		}

		ax88179_write_cmd_async(dev, AX_ACCESS_MAC, AX_MULFLTARY,
					AX_MCAST_FLTSIZE, AX_MCAST_FLTSIZE,
					m_filter);

		rxctl |= AX_RX_CTL_AM;
	}

	WRITE_ONCE(data->rxctl, rxctl);
	ax88179_write_cmd_async(dev, AX_ACCESS_MAC, AX_RX_CTL,
				2, 2, &data->rxctl);
}

int ax88179_set_features(struct net_device *net, netdev_features_t features)
{
	u8 tmp;
	struct usbnet *dev = netdev_priv(net);
	struct ax88179_data *data = dev->driver_priv;
	netdev_features_t changed = net->features ^ features;

	if (changed & NETIF_F_IP_CSUM) {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
		tmp ^= AX_TXCOE_TCP | AX_TXCOE_UDP;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
	}

	if (changed & NETIF_F_IPV6_CSUM) {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
		tmp ^= AX_TXCOE_TCPV6 | AX_TXCOE_UDPV6;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
	}

	if (changed & NETIF_F_RXCSUM) {
		/* When we disable rx-checksumming, we need to clear the rx_checksum
		 * flag before disabling the engine
		 */
		if (!(features & NETIF_F_RXCSUM))
			data->rx_checksum = 0;

		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 1, &tmp);
		tmp ^= AX_RXCOE_IP | AX_RXCOE_TCP | AX_RXCOE_UDP |
		       AX_RXCOE_TCPV6 | AX_RXCOE_UDPV6;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 1, &tmp);
		data->rx_checksum = !!(features & NETIF_F_RXCSUM);
	}

	return 0;
}

void ax88179_get_mac_addr(struct usbnet *dev)
{
	u8 mac[ETH_ALEN];

	memset(mac, 0, sizeof(mac));

	/* Maybe the boot loader passed the MAC address via device tree */
	if (!eth_platform_get_mac_address(&dev->udev->dev, mac)) {
		netif_dbg(dev, ifup, dev->net,
			  "MAC address read from device tree");
	} else {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_NODE_ID, ETH_ALEN,
				 ETH_ALEN, mac);
		netif_dbg(dev, ifup, dev->net,
			  "MAC address read from ASIX chip");
	}

	if (is_valid_ether_addr(mac)) {
		eth_hw_addr_set(dev->net, mac);
		if (!is_local_ether_addr(mac))
			dev->net->addr_assign_type = NET_ADDR_PERM;
	} else {
		netdev_info(dev->net, "invalid MAC address, using random\n");
	}

	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_NODE_ID, ETH_ALEN, ETH_ALEN,
			  dev->net->dev_addr);
}

int ax88179_change_mtu(struct net_device *net, int new_mtu)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax88179_data *data;
	u16 tmp16;
	int err;

	data = dev->driver_priv;
	mutex_lock(&data->medium_status_mutex);
	WRITE_ONCE(net->mtu, new_mtu);
	dev->hard_mtu = net->mtu + net->hard_header_len;
	if (net->mtu > 1500) {
		err = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
				       2, 2, &tmp16);
		if (err < 0)
			goto err_out;
		tmp16 |= AX_MEDIUM_JUMBO_EN;
		err = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
					2, 2, &tmp16);
		if (err < 0)
			goto err_out;
	} else {
		err = ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
				       2, 2, &tmp16);
		if (err < 0)
			goto err_out;
		tmp16 &= ~AX_MEDIUM_JUMBO_EN;
		err = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
					2, 2, &tmp16);
		if (err < 0)
			goto err_out;
	}
	mutex_unlock(&data->medium_status_mutex);

	/* max qlen depend on hard_mtu and rx_urb_size */
	usbnet_update_max_qlen(dev);

	return 0;

err_out:
	mutex_unlock(&data->medium_status_mutex);
	return err;
}

int ax88179_set_mac_addr(struct net_device *net, void *p)
{
	struct usbnet *dev = netdev_priv(net);
	struct sockaddr *addr = p;
	int ret;

	if (netif_running(net))
		return -EBUSY;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	eth_hw_addr_set(net, addr->sa_data);

	/* Set the MAC address */
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_NODE_ID, ETH_ALEN,
				ETH_ALEN, net->dev_addr);
	if (ret < 0)
		return ret;

	return 0;
}

