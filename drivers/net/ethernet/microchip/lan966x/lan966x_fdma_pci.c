// SPDX-License-Identifier: GPL-2.0+

#include <linux/ip.h>
#include <net/addrconf.h>

#include "fdma_api.h"
#include "lan966x_main.h"

static int lan966x_fdma_pci_dataptr_cb(struct fdma *fdma, int dcb, int db,
				       u64 *dataptr)
{
	u64 addr;

	addr = fdma_dataptr_dma_addr_contiguous(fdma, dcb, db);

	*dataptr = fdma_pci_atu_translate_addr(fdma->atu_region, addr);

	return 0;
}

static int lan966x_fdma_pci_nextptr_cb(struct fdma *fdma, int dcb, u64 *nextptr)
{
	u64 addr;

	fdma_nextptr_cb(fdma, dcb, &addr);

	*nextptr = fdma_pci_atu_translate_addr(fdma->atu_region, addr);

	return 0;
}

/* Stop the TX queues on every port, so nothing feeds the injection channel
 * while it is torn down or resized.
 */
static void lan966x_fdma_tx_disable_netdev(struct lan966x *lan966x)
{
	struct lan966x_port *port;
	int i;

	for (i = 0; i < lan966x->num_phys_ports; ++i) {
		port = lan966x->ports[i];
		if (!port)
			continue;

		netif_tx_disable(port->dev);
	}
}

static int lan966x_fdma_pci_rx_alloc(struct lan966x_rx *rx)
{
	struct lan966x *lan966x = rx->lan966x;
	struct fdma *fdma = &rx->fdma;
	int err;

	err = fdma_alloc_coherent_and_map(lan966x->dma_dev, fdma,
					  &lan966x->atu);
	if (err)
		return err;

	err = fdma_dcbs_init(fdma,
			     FDMA_DCB_INFO_DATAL(fdma->db_size - XDP_PACKET_HEADROOM),
			     FDMA_DCB_STATUS_INTR);
	if (err) {
		fdma_free_coherent_and_unmap(lan966x->dma_dev, fdma);
		return err;
	}

	lan966x_fdma_llp_configure(lan966x,
				   fdma->atu_region->base_addr,
				   fdma->channel_id);

	return 0;
}

static int lan966x_fdma_pci_tx_alloc(struct lan966x_tx *tx)
{
	struct lan966x *lan966x = tx->lan966x;
	struct fdma *fdma = &tx->fdma;
	int err;

	err = fdma_alloc_coherent_and_map(lan966x->dma_dev, fdma,
					  &lan966x->atu);
	if (err)
		return err;

	err = fdma_dcbs_init(fdma,
			     FDMA_DCB_INFO_DATAL(fdma->db_size),
			     FDMA_DCB_STATUS_DONE);
	if (err) {
		fdma_free_coherent_and_unmap(lan966x->dma_dev, fdma);
		return err;
	}

	lan966x_fdma_llp_configure(lan966x,
				   fdma->atu_region->base_addr,
				   fdma->channel_id);

	return 0;
}

static int lan966x_fdma_pci_get_next_dcb(struct fdma *fdma)
{
	struct fdma_db *db;

	for (int i = 0; i < fdma->n_dcbs; i++) {
		db = fdma_db_get(fdma, i, 0);

		if (!fdma_db_is_done(db))
			continue;
		if (fdma_is_last(fdma, &fdma->dcbs[i]))
			continue;

		return i;
	}

	return -ENOSPC;
}

/* TX slot layout (sizes in bytes):
 *
 *  +---------------------+-----+---------+-----+
 *  | XDP_PACKET_HEADROOM | IFH | payload | FCS |
 *  |         256         |  28 |   len   |   4 |
 *  +---------------------+-----+---------+-----+
 *  |<---------------- db_size ----------------->|
 *
 * Return true if the frame plus required overhead fits.
 */
static bool lan966x_fdma_pci_tx_size_fits(struct fdma *fdma, u32 len)
{
	return XDP_PACKET_HEADROOM + IFH_LEN_BYTES + len + ETH_FCS_LEN <=
	       fdma->db_size;
}

/* Return true if blockl is a valid RX frame size. */
static bool lan966x_fdma_pci_rx_size_fits(struct fdma *fdma, u32 blockl)
{
	return blockl >= IFH_LEN_BYTES + ETH_HLEN + ETH_FCS_LEN &&
	       blockl <= fdma->db_size - XDP_PACKET_HEADROOM;
}

static int lan966x_fdma_pci_rx_check_frame(struct lan966x_rx *rx, u64 *src_port)
{
	struct lan966x *lan966x = rx->lan966x;
	struct fdma *fdma = &rx->fdma;
	struct lan966x_port *port;
	struct fdma_db *db;
	void *virt_addr;
	u32 blockl;

	/* virt_addr points to the IFH. */
	virt_addr = fdma_dataptr_virt_addr_contiguous(fdma,
						      fdma->dcb_index,
						      fdma->db_index);

	lan966x_ifh_get_src_port(virt_addr, src_port);

	if (*src_port >= lan966x->num_phys_ports)
		return FDMA_ERROR;

	port = lan966x->ports[*src_port];
	if (!port)
		return FDMA_ERROR;

	db = fdma_db_next_get(fdma);

	/* BLOCKL is a 16-bit HW-populated field; reject obviously-bad
	 * values before they feed memcpy/XDP sizes.
	 */
	blockl = fdma_db_len_get(db);
	if (!lan966x_fdma_pci_rx_size_fits(fdma, blockl))
		return FDMA_ERROR;

	return FDMA_PASS;
}

static bool lan966x_fdma_pci_hw_offload(struct lan966x *lan966x, u32 port,
					struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	u32 val;

	val = lan_rd(lan966x, ANA_CPU_FWD_CFG(port));
	if (!(val & (ANA_CPU_FWD_CFG_IGMP_REDIR_ENA |
		     ANA_CPU_FWD_CFG_MLD_REDIR_ENA)))
		return true;

	if (eth_type_vlan(skb->protocol)) {
		skb = skb_vlan_untag(skb);
		*pskb = skb;
		if (unlikely(!skb))
			return false;
	}

	if (skb->protocol == htons(ETH_P_IP) &&
	    ip_hdr(skb)->protocol == IPPROTO_IGMP)
		return false;

	if (IS_ENABLED(CONFIG_IPV6) &&
	    skb->protocol == htons(ETH_P_IPV6) &&
	    ipv6_addr_is_multicast(&ipv6_hdr(skb)->daddr) &&
	    !ipv6_mc_check_mld(skb))
		return false;

	return true;
}

static struct sk_buff *lan966x_fdma_pci_rx_get_frame(struct lan966x_rx *rx,
						     u64 src_port)
{
	struct lan966x *lan966x = rx->lan966x;
	struct fdma *fdma = &rx->fdma;
	struct sk_buff *skb;
	struct fdma_db *db;
	u32 data_len;

	/* Get the received frame and create an SKB for it. */
	db = fdma_db_next_get(fdma);
	data_len = fdma_db_len_get(db);

	skb = napi_alloc_skb(&lan966x->napi, data_len);
	if (unlikely(!skb))
		return NULL;

	memcpy(skb->data,
	       fdma_dataptr_virt_addr_contiguous(fdma,
						 fdma->dcb_index,
						 fdma->db_index),
						 data_len);

	skb_put(skb, data_len);

	skb->dev = lan966x->ports[src_port]->dev;
	skb_pull(skb, IFH_LEN_BYTES);

	skb_trim(skb, skb->len - ETH_FCS_LEN);

	skb->protocol = eth_type_trans(skb, skb->dev);

	if (lan966x->bridge_mask & BIT(src_port)) {
		skb->offload_fwd_mark = 1;

		skb_reset_network_header(skb);
		if (!lan966x_fdma_pci_hw_offload(lan966x, src_port, &skb)) {
			if (unlikely(!skb))
				return NULL;
			skb->offload_fwd_mark = 0;
		}
	}

	skb->dev->stats.rx_bytes += skb->len;
	skb->dev->stats.rx_packets++;

	return skb;
}

static int lan966x_fdma_pci_xmit(struct sk_buff *skb, __be32 *ifh,
				 struct net_device *dev)
{
	struct lan966x_port *port = netdev_priv(dev);
	struct lan966x *lan966x = port->lan966x;
	struct lan966x_tx *tx = &lan966x->tx;
	struct fdma *fdma = &tx->fdma;
	int next_to_use;
	void *virt_addr;

	next_to_use = lan966x_fdma_pci_get_next_dcb(fdma);

	if (next_to_use < 0) {
		netif_stop_queue(dev);
		return NETDEV_TX_BUSY;
	}

	if (skb_put_padto(skb, ETH_ZLEN)) {
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (!lan966x_fdma_pci_tx_size_fits(fdma, skb->len)) {
		dev_kfree_skb_any(skb);
		dev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}

	skb_tx_timestamp(skb);

	/* virt_addr points to the IFH. */
	virt_addr = fdma_dataptr_virt_addr_contiguous(fdma, next_to_use, 0);
	memcpy(virt_addr, ifh, IFH_LEN_BYTES);
	memcpy(virt_addr + IFH_LEN_BYTES, skb->data, skb->len);

	/* Order frame write before DCB status write below. */
	dma_wmb();

	fdma_dcb_add(fdma,
		     next_to_use,
		     0,
		     FDMA_DCB_STATUS_INTR |
		     FDMA_DCB_STATUS_SOF |
		     FDMA_DCB_STATUS_EOF |
		     FDMA_DCB_STATUS_BLOCKO(0) |
		     FDMA_DCB_STATUS_BLOCKL(IFH_LEN_BYTES + skb->len + ETH_FCS_LEN));

	/* Start the transmission. */
	lan966x_fdma_tx_start(tx);

	dev->stats.tx_bytes += skb->len;
	dev->stats.tx_packets++;

	/* Safe to free: PTP is not supported on the PCIe path yet,
	 * so lan966x->ptp is always 0 here.
	 */
	dev_consume_skb_any(skb);

	return NETDEV_TX_OK;
}

static int lan966x_fdma_pci_napi_poll(struct napi_struct *napi, int weight)
{
	struct lan966x *lan966x = container_of(napi, struct lan966x, napi);
	struct lan966x_rx *rx = &lan966x->rx;
	struct fdma *fdma = &rx->fdma;
	int dcb_reload, old_dcb;
	struct sk_buff *skb;
	int counter = 0;
	u64 src_port;

	/* Wake any stopped TX queues if a TX DCB is available. */
	spin_lock(&lan966x->tx_lock);
	if (lan966x_fdma_pci_get_next_dcb(&lan966x->tx.fdma) >= 0)
		lan966x_fdma_wakeup_netdev(lan966x);
	spin_unlock(&lan966x->tx_lock);

	dcb_reload = fdma->dcb_index;

	/* Get all received skbs. */
	while (counter < weight) {
		if (!fdma_has_frames(fdma))
			break;
		/* Order DONE read before DCB/frame reads below. */
		dma_rmb();
		counter++;
		switch (lan966x_fdma_pci_rx_check_frame(rx, &src_port)) {
		case FDMA_PASS:
			break;
		case FDMA_ERROR:
			/* No rx_dropped increment here because src_port is
			 * invalid.
			 */
			fdma_dcb_advance(fdma);
			continue;
		}
		skb = lan966x_fdma_pci_rx_get_frame(rx, src_port);
		fdma_dcb_advance(fdma);
		if (!skb) {
			lan966x->ports[src_port]->dev->stats.rx_dropped++;
			continue;
		}

		napi_gro_receive(&lan966x->napi, skb);
	}
	while (dcb_reload != fdma->dcb_index) {
		old_dcb = dcb_reload;
		dcb_reload++;
		dcb_reload &= fdma->n_dcbs - 1;

		fdma_dcb_add(fdma,
			     old_dcb,
			     FDMA_DCB_INFO_DATAL(fdma->db_size - XDP_PACKET_HEADROOM),
			     FDMA_DCB_STATUS_INTR);

		lan966x_fdma_rx_reload(rx);
	}

	if (counter < weight && napi_complete_done(napi, counter))
		lan_wr(0xff, lan966x, FDMA_INTR_DB_ENA);

	return counter;
}

static int lan966x_fdma_pci_init(struct lan966x *lan966x)
{
	struct fdma *rx_fdma = &lan966x->rx.fdma;
	struct fdma *tx_fdma = &lan966x->tx.fdma;
	int err;

	if (!lan966x->fdma)
		return 0;

	lan_wr(FDMA_CTRL_NRESET_SET(0), lan966x, FDMA_CTRL);
	lan_wr(FDMA_CTRL_NRESET_SET(1), lan966x, FDMA_CTRL);

	fdma_pci_atu_init(&lan966x->atu, lan966x->regs[TARGET_PCIE_DBI]);

	lan966x->rx.lan966x = lan966x;
	lan966x->rx.max_mtu = lan966x_fdma_get_max_frame(lan966x);
	rx_fdma->channel_id = FDMA_XTR_CHANNEL;
	rx_fdma->n_dcbs = FDMA_DCB_MAX;
	rx_fdma->n_dbs = FDMA_RX_DCB_MAX_DBS;
	rx_fdma->priv = lan966x;
	rx_fdma->db_size = FDMA_PCI_DB_SIZE(lan966x->rx.max_mtu);
	rx_fdma->size = fdma_get_size_contiguous(rx_fdma);
	rx_fdma->ops.nextptr_cb = &lan966x_fdma_pci_nextptr_cb;
	rx_fdma->ops.dataptr_cb = &lan966x_fdma_pci_dataptr_cb;

	lan966x->tx.lan966x = lan966x;
	tx_fdma->channel_id = FDMA_INJ_CHANNEL;
	tx_fdma->n_dcbs = FDMA_DCB_MAX;
	tx_fdma->n_dbs = FDMA_TX_DCB_MAX_DBS;
	tx_fdma->priv = lan966x;
	tx_fdma->db_size = FDMA_PCI_DB_SIZE(lan966x->rx.max_mtu);
	tx_fdma->size = fdma_get_size_contiguous(tx_fdma);
	tx_fdma->ops.nextptr_cb = &lan966x_fdma_pci_nextptr_cb;
	tx_fdma->ops.dataptr_cb = &lan966x_fdma_pci_dataptr_cb;

	err = lan966x_fdma_pci_rx_alloc(&lan966x->rx);
	if (err)
		return err;

	err = lan966x_fdma_pci_tx_alloc(&lan966x->tx);
	if (err) {
		fdma_free_coherent_and_unmap(lan966x->dma_dev, rx_fdma);
		return err;
	}

	lan966x_fdma_rx_start(&lan966x->rx);

	return 0;
}

static int lan966x_fdma_pci_resize(struct lan966x *lan966x)
{
	return -EOPNOTSUPP;
}

static void lan966x_fdma_pci_deinit(struct lan966x *lan966x)
{
	if (!lan966x->fdma)
		return;

	if (lan966x->fdma_ndev)
		napi_disable(&lan966x->napi);

	lan966x_fdma_tx_disable_netdev(lan966x);
	lan966x_fdma_rx_disable(&lan966x->rx);
	lan966x_fdma_tx_disable(&lan966x->tx);

	fdma_free_coherent_and_unmap(lan966x->dma_dev, &lan966x->rx.fdma);
	fdma_free_coherent_and_unmap(lan966x->dma_dev, &lan966x->tx.fdma);
}

const struct lan966x_fdma_ops lan966x_fdma_pci_ops = {
	.fdma_init = &lan966x_fdma_pci_init,
	.fdma_deinit = &lan966x_fdma_pci_deinit,
	.fdma_xmit = &lan966x_fdma_pci_xmit,
	.fdma_poll = &lan966x_fdma_pci_napi_poll,
	.fdma_resize = &lan966x_fdma_pci_resize,
};
