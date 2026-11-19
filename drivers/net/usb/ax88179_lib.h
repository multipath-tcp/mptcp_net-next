/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <linux/usb.h>
#include <linux/crc32.h>
#include <linux/phylink.h>
#include <linux/usb/usbnet.h>

#ifndef __LINUX_USBNET_AX88179_H
#define __LINUX_USBNET_AX88179_H

#define AX88179_PHY_ID				0x03
#define AX_EEPROM_LEN				0x100
#define AX88179_EEPROM_MAGIC			0x17900b95
#define AX_MCAST_FLTSIZE			8
#define AX_MAX_MCAST				64
#define AX_INT_PPLS_LINK			((u32)BIT(16))
#define AX_RXHDR_L4_TYPE_MASK			0x1c
#define AX_RXHDR_L4_TYPE_UDP			4
#define AX_RXHDR_L4_TYPE_TCP			16
#define AX_RXHDR_L3CSUM_ERR			2
#define AX_RXHDR_L4CSUM_ERR			1
#define AX_RXHDR_CRC_ERR			((u32)BIT(29))
#define AX_RXHDR_DROP_ERR			((u32)BIT(31))
#define AX_ACCESS_MAC				0x01
#define AX_ACCESS_PHY				0x02
#define AX_ACCESS_EEPROM			0x04
#define AX_ACCESS_EFUS				0x05
#define AX_RELOAD_EEPROM_EFUSE			0x06
#define AX88179A_WAKEUP_SETTING			0x07
#define AX_FW_MODE				0x08
#define AX_GPHY_CTL				0x0F
#define AX88179A_FLASH_READ			0x21
#define AX88179A_FLASH_WEN			0x22
#define AX88179A_FLASH_WDIS			0x23
#define AX88179A_FLASH_WRITE			0x24
#define AX88179A_PHY_CLAUSE45			0x27
#define AX88179A_FLASH_ERASE_SECTION		0x28
#define AX88179A_ACCESS_BL			0x2A
#define AX88179A_PHY_POWER			0x31
#define AX88179A_AUTODETACH			0xC0

#define AX_PAUSE_WATERLVL_LOW			0x54
#define AX_PAUSE_WATERLVL_HIGH			0x55

#define AX_FW_MODE_179A				0x01
#define PHYSICAL_LINK_STATUS			0x02
	#define	AX_USB_SS		0x04
	#define	AX_USB_HS		0x02
	#define AX_USB_FS		0x01

#define GENERAL_STATUS				0x03
/* Check AX88179 version. UA1:Bit2 = 0,  UA2:Bit2 = 1 */
	#define	AX_SECLD		0x04

#define AX_CHIP_STATUS				0x05

#define AX_SROM_ADDR				0x07
#define AX_SROM_CMD				0x0a
	#define EEP_RD			0x04
	#define EEP_BUSY		0x10

#define AX_SROM_DATA_LOW			0x08
#define AX_SROM_DATA_HIGH			0x09

#define AX_RX_CTL				0x0b
	#define AX_RX_CTL_DROPCRCERR	0x0100
	#define AX_RX_CTL_IPE		0x0200
	#define AX_RX_CTL_START		0x0080
	#define AX_RX_CTL_AP		0x0020
	#define AX_RX_CTL_AM		0x0010
	#define AX_RX_CTL_AB		0x0008
	#define AX_RX_CTL_AMALL		0x0002
	#define AX_RX_CTL_PRO		0x0001
	#define AX_RX_CTL_STOP		0x0000

#define AX88179A_ETH_TX_GAP			0x0D

#define AX88179A_BFM_DATA			0x0E
	#define AX_TX_QUEUE_CFG		0x02
	#define AX_TX_QUEUE_SET		0x08
	#define AX_TX_Q1_AHB_FC_EN	0x10
	#define AX_TX_Q2_AHB_FC_EN	0x20
	#define AX_XGMII_EN		0x80

#define AX_NODE_ID				0x10
#define AX_MULFLTARY				0x16

#define AX_MEDIUM_STATUS_MODE			0x22
	#define AX_MEDIUM_GIGAMODE	0x01
	#define AX_MEDIUM_FULL_DUPLEX	0x02
	#define AX_MEDIUM_EN_125MHZ	0x08
	#define AX_MEDIUM_RXFLOW_CTRLEN	0x10
	#define AX_MEDIUM_TXFLOW_CTRLEN	0x20
	#define AX_MEDIUM_RECEIVE_EN	0x100
	#define AX_MEDIUM_PS		0x200
	#define AX_MEDIUM_JUMBO_EN	0x8040

#define AX_MONITOR_MOD				0x24
	#define AX_MONITOR_MODE_RWLC	0x02
	#define AX_MONITOR_MODE_RWMP	0x04
	#define AX_MONITOR_MODE_PMEPOL	0x20
	#define AX_MONITOR_MODE_PMETYPE	0x40

#define AX_GPIO_CTRL				0x25
	#define AX_GPIO_CTRL_GPIO3EN	0x80
	#define AX_GPIO_CTRL_GPIO2EN	0x40
	#define AX_GPIO_CTRL_GPIO1EN	0x20

#define AX_PHYPWR_RSTCTL			0x26
	#define AX_PHYPWR_RSTCTL_BZ	0x0010
	#define AX_PHYPWR_RSTCTL_IPRL	0x0020
	#define AX_PHYPWR_RSTCTL_AT	0x1000

#define AX88179A_VLAN_ID_ADDRESS		0x2A

#define AX88179A_VLAN_ID_CONTROL		0x2B
	#define AX_VLAN_CONTROL_WE	0x0001
	#define AX_VLAN_CONTROL_RD	0x0002
	#define AX_VLAN_CONTROL_VSO	0x0010
	#define AX_VLAN_CONTROL_VFE	0x0020

#define AX88179A_VLAN_ID_DATA0			0x2C
#define AX88179A_VLAN_ID_DATA1			0x2D

#define AX_RX_BULKIN_QCTRL			0x2e
#define AX_GPHY_EEE_CTRL			0x01

#define AX_CLK_SELECT				0x33
	#define AX_CLK_SELECT_BCS	0x01
	#define AX_CLK_SELECT_ACS	0x02
	#define AX_CLK_SELECT_ULR	0x08

#define AX_RXCOE_CTL				0x34
	#define AX_RXCOE_IP		0x01
	#define AX_RXCOE_TCP		0x02
	#define AX_RXCOE_UDP		0x04
	#define AX_RXCOE_TCPV6		0x20
	#define AX_RXCOE_UDPV6		0x40

#define AX_TXCOE_CTL				0x35
	#define AX_TXCOE_IP		0x01
	#define AX_TXCOE_TCP		0x02
	#define AX_TXCOE_UDP		0x04
	#define AX_TXCOE_TCPV6		0x20
	#define AX_TXCOE_UDPV6		0x40

#define AX88179A_MAC_BM_INT_MASK		0x41
#define AX88179A_MAC_BM_RX_DMA_CTL		0x43
#define AX88179A_MAC_BM_TX_DMA_CTL		0x46

#define AX88179A_MAC_RX_STATUS_CDC		0x6D
	#define AX_LSOFC_WCNT_7_ACCESS	0x03
	#define AX_GMII_CRC_APPEND	0x10

#define AX_LEDCTRL				0x73
#define AX88179A_MAC_ARC_CTRL			0x9E
#define AX88179A_MAC_SWP_CTRL			0xB1

#define AX88179A_MAC_TX_PAUSE			0xB2

#define AX88179A_MAC_CDC_DELAY_TX		0xB5

#define AX88179A_MAC_PATH			0xB7
	#define AX_MAC_RX_PATH_READY	0x01
	#define AX_MAC_TX_PATH_READY	0x02

#define AX88179A_NEW_PAUSE_CTRL			0xB8
	#define AX_NEW_PAUSE_EN		0x01

#define AX88179A_MAC_BULK_OUT_CTRL		0xB9
	#define AX_MAC_EFF_EN		0x02

#define AX88179A_MAC_RX_DATA_CDC_CNT		0xC0
	#define AX_MAC_LSO_ERR_EN	0x04
	#define AX_MAC_MIQFFCTRL_FORMAT	0x10
	#define AX_MAC_MIQFFCTRL_DROP_CRC 0x20

#define AX88179A_AUTODETACH_DELAY	(5UL << 8)
#define AX88179A_AUTODETACH_EN		1

#define AX88179A_MAC_LSO_ENHANCE_CTRL		0xC3
	#define AX_LSO_ENHANCE_EN	0x01

#define AX88179A_MAC_TX_HDR_CKSUM		0xCC
#define AX88179A_EP5_EHR			0xF9

#define AX_PHY_POWER				0x02

#define EPHY_LOW_POWER_EN			0x01
#define S5_WOL_EN				0x04
#define S5_WOL_LOW_POWER			0x20

#define GMII_PHY_PHYSR				0x11
	#define GMII_PHY_PHYSR_SMASK	0xc000
	#define GMII_PHY_PHYSR_GIGA	0x8000
	#define GMII_PHY_PHYSR_100	0x4000
	#define GMII_PHY_PHYSR_FULL	0x2000
	#define GMII_PHY_PHYSR_LINK	0x400

#define GMII_LED_ACT				0x1a
	#define	GMII_LED_ACTIVE_MASK	0xff8f
	#define	GMII_LED0_ACTIVE	BIT(4)
	#define	GMII_LED1_ACTIVE	BIT(5)
	#define	GMII_LED2_ACTIVE	BIT(6)

#define GMII_LED_LINK				0x1c
	#define	GMII_LED_LINK_MASK	0xf888
	#define	GMII_LED0_LINK_10	BIT(0)
	#define	GMII_LED0_LINK_100	BIT(1)
	#define	GMII_LED0_LINK_1000	BIT(2)
	#define	GMII_LED1_LINK_10	BIT(4)
	#define	GMII_LED1_LINK_100	BIT(5)
	#define	GMII_LED1_LINK_1000	BIT(6)
	#define	GMII_LED2_LINK_10	BIT(8)
	#define	GMII_LED2_LINK_100	BIT(9)
	#define	GMII_LED2_LINK_1000	BIT(10)
	#define	LED0_ACTIVE		BIT(0)
	#define	LED0_LINK_10		BIT(1)
	#define	LED0_LINK_100		BIT(2)
	#define	LED0_LINK_1000		BIT(3)
	#define	LED0_FD			BIT(4)
	#define	LED0_USB3_MASK		0x001f
	#define	LED1_ACTIVE		BIT(5)
	#define	LED1_LINK_10		BIT(6)
	#define	LED1_LINK_100		BIT(7)
	#define	LED1_LINK_1000		BIT(8)
	#define	LED1_FD			BIT(9)
	#define	LED1_USB3_MASK		0x03e0
	#define	LED2_ACTIVE		BIT(10)
	#define	LED2_LINK_1000		BIT(13)
	#define	LED2_LINK_100		BIT(12)
	#define	LED2_LINK_10		BIT(11)
	#define	LED2_FD			BIT(14)
	#define	LED_VALID		BIT(15)
	#define	LED2_USB3_MASK		0x7c00

#define GMII_PHYPAGE				0x1e
#define GMII_PHY_PAGE_SELECT			0x1f
	#define GMII_PHY_PGSEL_EXT	0x0007
	#define GMII_PHY_PGSEL_PAGE0	0x0000
	#define GMII_PHY_PGSEL_PAGE3	0x0003
	#define GMII_PHY_PGSEL_PAGE5	0x0005

#define AX88179A_SW_REVISION		0xFC
#define AX88179A_SW_VERSION		0xFD

/* TX Descriptor */
#define AX179A_TX_DESC_LEN_MASK		0x1FFFFF
#define AX179A_TX_DESC_DROP_PADD	BIT(28)
#define AX179A_TX_DESC_VLAN		BIT(29)
#define AX179A_TX_DESC_MSS		GENMASK_U64(46, 32)
#define AX179A_TX_DESC_VLAN_ID		GENMASK_U64(63, 48)

/* RX Packet Descriptor */
#define AX179A_RX_PD_L4_ERR		BIT(0)
#define AX179A_RX_PD_L3_ERR		BIT(1)
#define AX179A_RX_PD_L4_TYPE_MASK	0x1C
#define AX179A_RX_PD_L4_UDP		0x04
#define AX179A_RX_PD_L4_TCP		0x10
#define AX179A_RX_PD_L3_TYPE_MASK	0x60
#define AX179A_RX_PD_L3_IP		0x20
#define AX179A_RX_PD_L3_IP6		0x40

#define AX179A_RX_PD_VLAN		BIT(10)
#define AX179A_RX_PD_RX_OK		BIT(11)
#define AX179A_RX_PD_DROP		BIT(31)
#define AX179A_RX_PD_LEN		GENMASK(30, 16)
#define AX179A_RX_PD_VLAN_SHIFT		0x20

/* RX Descriptor header */
#define AX179A_RX_DH_PKT_CNT_MASK	0x1FFF
#define AX179A_RX_DH_DESC_OFFSET	GENMASK(31, 13)

#define AX179A_RX_HW_PAD		0x02

#define AX_ADVERTISE_2500		0x1000

enum ax_ether_link_speed {
	ETHER_LINK_NONE = 0,
	ETHER_LINK_10   = 1,
	ETHER_LINK_100  = 2,
	ETHER_LINK_1000 = 3,
	ETHER_LINK_2500 = 4,
};

enum ax_chip_version {
	AX_VERSION_INVALID		= 0x0,
	AX_VERSION_AX88179		= 0x4,
	AX_VERSION_AX88179A		= 0x6,	/* Also AX88772D */
	AX_VERSION_AX88279		= 0x7,
};

struct ax88179_data {
	struct mutex medium_status_mutex;  /* protect AX_MEDIUM_STATUS_MODE */
	u8  eee_enabled;
	u8  eee_active;
	u16 rxctl;
	u8 in_pm;
	u32 wol_supported;
	u32 wolopts;
	u8 disconnecting;
	u8 chip_version;
	u8 fw_version[4];
	u8 is_ax88772d;
	u8 ip_align;
	u8 link;
	u8 speed;
	u8 full_duplex;
	u8 rx_checksum;
	u8 eeprom_read_cmd;
	u8 eeprom_write_cmd;
	u8 eeprom_wen;
	u16 eeprom_block;
	struct mii_bus *mdio;
	struct phy_device *phydev;
	struct phylink *phylink;
	struct phylink_config phylink_config;
	int (*resume)(struct usb_interface *intf);
	int (*suspend)(struct usb_interface *intf, pm_message_t message);
};

struct ax88179_int_data {
	__le32 intdata1;
	__le32 intdata2;
};

struct ax_bulkin_settings {
	unsigned char ctrl, timer_l, timer_h, size, ifg;
};

void ax88179_set_pm_mode(struct usbnet *dev, bool pm_mode);
int __ax88179_read_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index, u16 size, void *data);
int ax88179_read_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index, u16 size, void *data);
int ax88179_write_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index, u16 size,
		      const void *data);
void ax88179_write_cmd_async(struct usbnet *dev, u8 cmd, u16 value, u16 index,
			     u16 size, void *data);
int ax88179_write_u16(struct usbnet *dev, u8 cmd, u16 value, u16 index, u16 data);
int ax88179_write_u8(struct usbnet *dev, u8 cmd, u16 value, u16 index, u8 data);
int ax88179_mdio_read(struct net_device *netdev, int phy_id, int loc);
void ax88179_mdio_write(struct net_device *netdev, int phy_id, int loc, int val);
struct ax88179_data *netdev2data(struct net_device *net);
void ax88179_status(struct usbnet *dev, struct urb *urb);
void ax88179_get_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo);
int ax88179_set_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo);
int ax88179_get_eeprom(struct net_device *net, struct ethtool_eeprom *eeprom, u8 *data);
int ax88179_set_eeprom(struct net_device *net, struct ethtool_eeprom *eeprom, u8 *data);
void ax88179_set_multicast(struct net_device *net);
int ax88179_set_features(struct net_device *net, netdev_features_t features);
void ax88179_get_mac_addr(struct usbnet *dev);
int ax88179_change_mtu(struct net_device *net, int new_mtu);
int ax88179_set_mac_addr(struct net_device *net, void *p);
int ax88179_suspend_wrapper(struct usb_interface *intf, pm_message_t message);
int ax88179_resume_wrapper(struct usb_interface *intf);

extern const struct driver_info ax88179a_info;
extern const struct driver_info ax88772d_info;
extern const struct driver_info ax88279_info;

#endif /*__LINUX_USBNET_AX88179_H */
