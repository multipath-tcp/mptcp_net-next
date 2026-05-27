// SPDX-License-Identifier: GPL-2.0-only
/*
 * Realtek switches of the Otto series (RTL838x, RTL839x, RTL930x and RTL931x SoCs) have multiple
 * integrated MDIO controllers. This driver targets the ethernet MDIO controller. It serves only
 * 1G/2.5G/10G ethernet PHYs attached to up to 4 individual buses.
 *
 * The controller is programmed through MMIO. The MDIO communication is abstracted by the hardware
 * and uses the switch port number for its addressing. For this to work, mapping registers need to
 * be setup in advance. With that the controller translates each port based I/O operation into the
 * physical bus and address. This gives the following end-to-end communication
 *
 *     +----------+       +----------+           +----------+       +----------+
 *     |  phydev  |  ...  |  phydev  |           |  phydev  |  ...  |  phydev  |
 *     +----------+       +----------+           +----------+       +----------+
 *              |                  |               |                  |
 *   mii_bus 0  +------------------+               +------------------+  mii_bus 1
 *                                 |               |
 *           +-----------------------------------------------------+
 *           |  MDIO driver                                        |
 *           |                      translate bus/address -> port  |
 *           +-----------------------------------------------------+
 *                                        |                             Software
 *                             - - - - - - - - - - - - - - - - - - - - - - - - -
 *                                        |                             Hardware
 *           +-----------------------------------------------------+
 *           | MDIO controller                                     |
 *           |                      translate port -> bus/address  |
 *           +-----------------------------------------------------+
 *                                 |               |
 *       bus 0  +------------------+               +------------------+  bus 1
 *              |                  |               |                  |
 *     +----------+       +----------+           +----------+       +----------+
 *     | PHY 0/1  |  ...  | PHY 0/31 |           | PHY 1/1  |  ...  | PHY 1/31 |
 *     +----------+       +----------+           +----------+       +----------+
 *
 * The driver works out the mapping based on the MDIO bus described in device tree and phandles on
 * the ethernet-ports property.
 */

#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/bits.h>
#include <linux/find.h>
#include <linux/mdio.h>
#include <linux/mfd/syscon.h>
#include <linux/mod_devicetable.h>
#include <linux/mutex.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/regmap.h>

#define RTL9300_NUM_BUSES		4
#define RTL9300_NUM_PAGES		4096
#define RTL9300_NUM_PORTS		28
#define SMI_GLB_CTRL			0xca00
#define   GLB_CTRL_INTF_SEL(intf)	BIT(16 + (intf))
#define SMI_PORT0_15_POLLING_SEL	0xca08
#define RTL9300_SMI_ACCESS_PHY_CTRL_0	0xcb70
#define RTL9300_SMI_ACCESS_PHY_CTRL_1	0xcb74
#define   PHY_CTRL_REG_ADDR		GENMASK(24, 20)
#define   PHY_CTRL_PARK_PAGE		GENMASK(19, 15)
#define   PHY_CTRL_MAIN_PAGE		GENMASK(14, 3)
#define   PHY_CTRL_WRITE		BIT(2)
#define   PHY_CTRL_READ			0
#define   PHY_CTRL_TYPE_C45		BIT(1)
#define   PHY_CTRL_TYPE_C22		0
#define   PHY_CTRL_CMD			BIT(0)
#define   PHY_CTRL_FAIL			BIT(25)
#define RTL9300_SMI_ACCESS_PHY_CTRL_2	0xcb78
#define   PHY_CTRL_INDATA		GENMASK(31, 16)
#define   PHY_CTRL_DATA			GENMASK(15, 0)
#define RTL9300_SMI_ACCESS_PHY_CTRL_3	0xcb7c
#define   PHY_CTRL_MMD_DEVAD		GENMASK(20, 16)
#define   PHY_CTRL_MMD_REG		GENMASK(15, 0)
#define SMI_PORT0_5_ADDR_CTRL		0xcb80

#define MAX_PORTS       28
#define MAX_SMI_BUSSES  4
#define MAX_SMI_ADDR	0x1f
#define RAW_PAGE(priv)	((priv)->info->num_pages - 1)


struct otto_emdio_cmd_regs {
	u32 c22_data;
	u32 c45_data;
	u32 io_data;
	u32 port_mask_low;
};

struct otto_emdio_info {
	struct otto_emdio_cmd_regs cmd_regs;
	u8 num_buses;
	u8 num_ports;
	u16 num_pages;
	int (*read_c22)(struct mii_bus *bus, int phy_id, int regnum);
	int (*read_c45)(struct mii_bus *bus, int phy_id, int dev_addr, int regnum);
	int (*write_c22)(struct mii_bus *bus, int phy_id, int regnum, u16 value);
	int (*write_c45)(struct mii_bus *bus, int phy_id, int dev_addr, int regnum, u16 value);
};

struct otto_emdio_priv {
	const struct otto_emdio_info *info;
	struct regmap *regmap;
	struct mutex lock; /* protect HW access */
	DECLARE_BITMAP(valid_ports, MAX_PORTS);
	u8 smi_bus[MAX_PORTS];
	u8 smi_addr[MAX_PORTS];
	bool smi_bus_is_c45[MAX_SMI_BUSSES];
	struct mii_bus *bus[MAX_SMI_BUSSES];
};

struct otto_emdio_chan {
	struct otto_emdio_priv *priv;
	u8 mdio_bus;
};

static int otto_emdio_phy_to_port(struct mii_bus *bus, int phy_id)
{
	struct otto_emdio_chan *chan = bus->priv;
	struct otto_emdio_priv *priv;
	int i;

	priv = chan->priv;

	for_each_set_bit(i, priv->valid_ports, priv->info->num_ports)
		if (priv->smi_bus[i] == chan->mdio_bus &&
		    priv->smi_addr[i] == phy_id)
			return i;

	return -ENOENT;
}

static int otto_emdio_wait_ready(struct otto_emdio_priv *priv)
{
	struct regmap *regmap = priv->regmap;
	u32 cmd_reg, val;

	lockdep_assert_held(&priv->lock);
	cmd_reg = priv->info->cmd_regs.c22_data; /* shared command/C22 register */

	return regmap_read_poll_timeout(regmap, cmd_reg, val, !(val & PHY_CTRL_CMD), 10, 1000);
}

static int otto_emdio_9300_read_c22(struct mii_bus *bus, int phy_id, int regnum)
{
	struct otto_emdio_chan *chan = bus->priv;
	struct otto_emdio_priv *priv;
	u32 io_reg, cmd_reg, val;
	struct regmap *regmap;
	int port;
	int err;

	priv = chan->priv;
	regmap = priv->regmap;
	io_reg = priv->info->cmd_regs.io_data;
	cmd_reg = priv->info->cmd_regs.c22_data; /* shared command/C22 register */

	port = otto_emdio_phy_to_port(bus, phy_id);
	if (port < 0)
		return port;

	mutex_lock(&priv->lock);
	err = otto_emdio_wait_ready(priv);
	if (err)
		goto out_err;

	err = regmap_write(regmap, io_reg, FIELD_PREP(PHY_CTRL_INDATA, port));
	if (err)
		goto out_err;

	val = FIELD_PREP(PHY_CTRL_REG_ADDR, regnum) |
	      FIELD_PREP(PHY_CTRL_PARK_PAGE, 0x1f) |
	      FIELD_PREP(PHY_CTRL_MAIN_PAGE, RAW_PAGE(priv)) |
	      PHY_CTRL_READ | PHY_CTRL_TYPE_C22 | PHY_CTRL_CMD;
	err = regmap_write(regmap, cmd_reg, val);
	if (err)
		goto out_err;

	err = otto_emdio_wait_ready(priv);
	if (err)
		goto out_err;

	err = regmap_read(regmap, io_reg, &val);
	if (err)
		goto out_err;

	mutex_unlock(&priv->lock);
	return FIELD_GET(PHY_CTRL_DATA, val);

out_err:
	mutex_unlock(&priv->lock);
	return err;
}

static int otto_emdio_9300_write_c22(struct mii_bus *bus, int phy_id, int regnum, u16 value)
{
	struct otto_emdio_chan *chan = bus->priv;
	struct otto_emdio_priv *priv;
	u32 io_reg, cmd_reg, val;
	struct regmap *regmap;
	int port;
	int err;

	priv = chan->priv;
	regmap = priv->regmap;
	io_reg = priv->info->cmd_regs.io_data;
	cmd_reg = priv->info->cmd_regs.c22_data; /* shared command/C22 register */

	port = otto_emdio_phy_to_port(bus, phy_id);
	if (port < 0)
		return port;

	mutex_lock(&priv->lock);
	err = otto_emdio_wait_ready(priv);
	if (err)
		goto out_err;

	err = regmap_write(regmap, priv->info->cmd_regs.port_mask_low, BIT(port));
	if (err)
		goto out_err;

	err = regmap_write(regmap, io_reg, FIELD_PREP(PHY_CTRL_INDATA, value));
	if (err)
		goto out_err;

	val = FIELD_PREP(PHY_CTRL_REG_ADDR, regnum) |
	      FIELD_PREP(PHY_CTRL_PARK_PAGE, 0x1f) |
	      FIELD_PREP(PHY_CTRL_MAIN_PAGE, RAW_PAGE(priv)) |
	      PHY_CTRL_WRITE | PHY_CTRL_TYPE_C22 | PHY_CTRL_CMD;
	err = regmap_write(regmap, cmd_reg, val);
	if (err)
		goto out_err;

	err = regmap_read_poll_timeout(regmap, cmd_reg, val, !(val & PHY_CTRL_CMD), 10, 100);
	if (err)
		goto out_err;

	if (val & PHY_CTRL_FAIL) {
		err = -ENXIO;
		goto out_err;
	}

	mutex_unlock(&priv->lock);
	return 0;

out_err:
	mutex_unlock(&priv->lock);
	return err;
}

static int otto_emdio_9300_read_c45(struct mii_bus *bus, int phy_id, int dev_addr, int regnum)
{
	struct otto_emdio_chan *chan = bus->priv;
	struct otto_emdio_priv *priv;
	u32 io_reg, cmd_reg, val;
	struct regmap *regmap;
	int port;
	int err;

	priv = chan->priv;
	regmap = priv->regmap;
	io_reg = priv->info->cmd_regs.io_data;
	cmd_reg = priv->info->cmd_regs.c22_data; /* shared command/C22 register */

	port = otto_emdio_phy_to_port(bus, phy_id);
	if (port < 0)
		return port;

	mutex_lock(&priv->lock);
	err = otto_emdio_wait_ready(priv);
	if (err)
		goto out_err;

	val = FIELD_PREP(PHY_CTRL_INDATA, port);
	err = regmap_write(regmap, io_reg, val);
	if (err)
		goto out_err;

	val = FIELD_PREP(PHY_CTRL_MMD_DEVAD, dev_addr) |
	      FIELD_PREP(PHY_CTRL_MMD_REG, regnum);
	err = regmap_write(regmap, priv->info->cmd_regs.c45_data, val);
	if (err)
		goto out_err;

	err = regmap_write(regmap, cmd_reg, PHY_CTRL_READ | PHY_CTRL_TYPE_C45 | PHY_CTRL_CMD);
	if (err)
		goto out_err;

	err = otto_emdio_wait_ready(priv);
	if (err)
		goto out_err;

	err = regmap_read(regmap, io_reg, &val);
	if (err)
		goto out_err;

	mutex_unlock(&priv->lock);
	return FIELD_GET(PHY_CTRL_DATA, val);

out_err:
	mutex_unlock(&priv->lock);
	return err;
}

static int otto_emdio_9300_write_c45(struct mii_bus *bus, int phy_id, int dev_addr,
				  int regnum, u16 value)
{
	struct otto_emdio_chan *chan = bus->priv;
	struct otto_emdio_priv *priv;
	u32 io_reg, cmd_reg, val;
	struct regmap *regmap;
	int port;
	int err;

	priv = chan->priv;
	regmap = priv->regmap;
	io_reg = priv->info->cmd_regs.io_data;
	cmd_reg = priv->info->cmd_regs.c22_data; /* shared command/C22 register */

	port = otto_emdio_phy_to_port(bus, phy_id);
	if (port < 0)
		return port;

	mutex_lock(&priv->lock);
	err = otto_emdio_wait_ready(priv);
	if (err)
		goto out_err;

	err = regmap_write(regmap, priv->info->cmd_regs.port_mask_low, BIT(port));
	if (err)
		goto out_err;

	val = FIELD_PREP(PHY_CTRL_INDATA, value);
	err = regmap_write(regmap, io_reg, val);
	if (err)
		goto out_err;

	val = FIELD_PREP(PHY_CTRL_MMD_DEVAD, dev_addr) |
	      FIELD_PREP(PHY_CTRL_MMD_REG, regnum);
	err = regmap_write(regmap, priv->info->cmd_regs.c45_data, val);
	if (err)
		goto out_err;

	err = regmap_write(regmap, cmd_reg, PHY_CTRL_TYPE_C45 | PHY_CTRL_WRITE | PHY_CTRL_CMD);
	if (err)
		goto out_err;

	err = regmap_read_poll_timeout(regmap, cmd_reg, val, !(val & PHY_CTRL_CMD), 10, 100);
	if (err)
		goto out_err;

	if (val & PHY_CTRL_FAIL) {
		err = -ENXIO;
		goto out_err;
	}

	mutex_unlock(&priv->lock);
	return 0;

out_err:
	mutex_unlock(&priv->lock);
	return err;
}

static int otto_emdio_9300_mdiobus_init(struct otto_emdio_priv *priv)
{
	u32 glb_ctrl_mask = 0, glb_ctrl_val = 0;
	struct regmap *regmap = priv->regmap;
	u32 port_addr[5] = { 0 };
	u32 poll_sel[2] = { 0 };
	int i, err;

	/* Associate the port with the SMI interface and PHY */
	for_each_set_bit(i, priv->valid_ports, priv->info->num_ports) {
		int pos;

		pos = (i % 6) * 5;
		port_addr[i / 6] |= (priv->smi_addr[i] & 0x1f) << pos;

		pos = (i % 16) * 2;
		poll_sel[i / 16] |= (priv->smi_bus[i] & 0x3) << pos;
	}

	/* Put the interfaces into C45 mode if required */
	glb_ctrl_mask = GENMASK(19, 16);
	for (i = 0; i < priv->info->num_buses; i++)
		if (priv->smi_bus_is_c45[i])
			glb_ctrl_val |= GLB_CTRL_INTF_SEL(i);

	err = regmap_bulk_write(regmap, SMI_PORT0_5_ADDR_CTRL,
				port_addr, 5);
	if (err)
		return err;

	err = regmap_bulk_write(regmap, SMI_PORT0_15_POLLING_SEL,
				poll_sel, 2);
	if (err)
		return err;

	err = regmap_update_bits(regmap, SMI_GLB_CTRL,
				 glb_ctrl_mask, glb_ctrl_val);
	if (err)
		return err;

	return 0;
}

static int otto_emdio_probe_one(struct device *dev, struct otto_emdio_priv *priv,
				 struct fwnode_handle *node)
{
	struct otto_emdio_chan *chan;
	struct mii_bus *bus;
	u32 mdio_bus;
	int err;

	err = fwnode_property_read_u32(node, "reg", &mdio_bus);
	if (err)
		return err;

	/* The MDIO accesses from the kernel work with the PHY polling unit in
	 * the switch. We need to tell the PPU to operate either in GPHY (i.e.
	 * clause 22) or 10GPHY mode (i.e. clause 45).
	 *
	 * We select 10GPHY mode if there is at least one PHY that declares
	 * compatible = "ethernet-phy-ieee802.3-c45". This does mean we can't
	 * support both c45 and c22 on the same MDIO bus.
	 */
	fwnode_for_each_child_node_scoped(node, child)
		if (fwnode_device_is_compatible(child, "ethernet-phy-ieee802.3-c45"))
			priv->smi_bus_is_c45[mdio_bus] = true;

	bus = devm_mdiobus_alloc_size(dev, sizeof(*chan));
	if (!bus)
		return -ENOMEM;

	bus->name = "Realtek Switch MDIO Bus";
	if (priv->smi_bus_is_c45[mdio_bus]) {
		bus->read_c45 = priv->info->read_c45;
		bus->write_c45 = priv->info->write_c45;
	} else {
		bus->read = priv->info->read_c22;
		bus->write = priv->info->write_c22;
	}
	bus->parent = dev;
	chan = bus->priv;
	chan->mdio_bus = mdio_bus;
	chan->priv = priv;

	snprintf(bus->id, MII_BUS_ID_SIZE, "%s-%d", dev_name(dev), mdio_bus);

	err = devm_of_mdiobus_register(dev, bus, to_of_node(node));
	if (err)
		return dev_err_probe(dev, err, "cannot register MDIO bus\n");

	return 0;
}

/* The mdio-controller is part of a switch block so we parse the sibling
 * ethernet-ports node and build a mapping of the switch port to MDIO bus/addr
 * based on the phy-handle.
 */
static int otto_emdio_map_ports(struct device *dev)
{
	struct otto_emdio_priv *priv = dev_get_drvdata(dev);
	struct device *parent = dev->parent;
	int err;

	struct fwnode_handle *ports __free(fwnode_handle) =
		device_get_named_child_node(parent, "ethernet-ports");
	if (!ports)
		return dev_err_probe(dev, -EINVAL, "%pfwP missing ethernet-ports\n",
				     dev_fwnode(parent));

	fwnode_for_each_child_node_scoped(ports, port) {
		struct device_node *mdio_dn;
		u32 addr;
		u32 bus;
		u32 pn;

		struct device_node *phy_dn __free(device_node) =
			of_parse_phandle(to_of_node(port), "phy-handle", 0);
		/* skip ports without phys */
		if (!phy_dn)
			continue;

		mdio_dn = phy_dn->parent;
		/* only map ports that are connected to this mdio-controller */
		if (mdio_dn->parent != dev->of_node)
			continue;

		err = fwnode_property_read_u32(port, "reg", &pn);
		if (err)
			return err;

		if (pn >= priv->info->num_ports)
			return dev_err_probe(dev, -EINVAL, "illegal port number %d\n", pn);

		if (test_bit(pn, priv->valid_ports))
			return dev_err_probe(dev, -EINVAL, "duplicated port number %d\n", pn);

		err = of_property_read_u32(mdio_dn, "reg", &bus);
		if (err)
			return err;

		if (bus >= priv->info->num_buses)
			return dev_err_probe(dev, -EINVAL, "illegal smi bus number %d\n", bus);

		err = of_property_read_u32(phy_dn, "reg", &addr);
		if (err)
			return err;

		__set_bit(pn, priv->valid_ports);
		priv->smi_bus[pn] = bus;
		priv->smi_addr[pn] = addr;
	}

	return 0;
}

static int otto_emdio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct otto_emdio_priv *priv;
	int err;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	err = devm_mutex_init(dev, &priv->lock);
	if (err)
		return err;

	priv->info = device_get_match_data(dev);
	priv->regmap = syscon_node_to_regmap(dev->parent->of_node);
	if (IS_ERR(priv->regmap))
		return PTR_ERR(priv->regmap);

	platform_set_drvdata(pdev, priv);

	err = otto_emdio_map_ports(dev);
	if (err)
		return err;

	device_for_each_child_node_scoped(dev, child) {
		err = otto_emdio_probe_one(dev, priv, child);
		if (err)
			return err;
	}

	err = otto_emdio_9300_mdiobus_init(priv);
	if (err)
		return dev_err_probe(dev, err, "failed to initialise MDIO bus controller\n");

	return 0;
}

static const struct otto_emdio_info otto_emdio_9300_info = {
	.cmd_regs = {
		.c22_data = RTL9300_SMI_ACCESS_PHY_CTRL_1,
		.c45_data = RTL9300_SMI_ACCESS_PHY_CTRL_3,
		.io_data = RTL9300_SMI_ACCESS_PHY_CTRL_2,
		.port_mask_low = RTL9300_SMI_ACCESS_PHY_CTRL_0,
	},
	.num_buses = RTL9300_NUM_BUSES,
	.num_ports = RTL9300_NUM_PORTS,
	.num_pages = RTL9300_NUM_PAGES,
	.read_c22 = otto_emdio_9300_read_c22,
	.read_c45 = otto_emdio_9300_read_c45,
	.write_c22 = otto_emdio_9300_write_c22,
	.write_c45 = otto_emdio_9300_write_c45,
};

static const struct of_device_id otto_emdio_ids[] = {
	{ .compatible = "realtek,rtl9301-mdio", .data = &otto_emdio_9300_info },
	{}
};
MODULE_DEVICE_TABLE(of, otto_emdio_ids);

static struct platform_driver otto_emdio_driver = {
	.probe = otto_emdio_probe,
	.driver = {
		.name = "mdio-rtl9300",
		.of_match_table = otto_emdio_ids,
	},
};

module_platform_driver(otto_emdio_driver);

MODULE_DESCRIPTION("RTL9300 MDIO driver");
MODULE_LICENSE("GPL");
