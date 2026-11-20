// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: Copyright Red Hat

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>

#include "ice_adapter.h"
#include "ice.h"

#define ICE_ADAPTER_FIXED_INDEX	BIT_ULL(63)

#define ICE_ADAPTER_INDEX_E825C	\
	(ICE_DEV_ID_E825C_BACKPLANE | ICE_ADAPTER_FIXED_INDEX)

static u64 ice_adapter_index(struct pci_dev *pdev)
{
	switch (pdev->device) {
	case ICE_DEV_ID_E825C_BACKPLANE:
	case ICE_DEV_ID_E825C_QSFP:
	case ICE_DEV_ID_E825C_SFP:
	case ICE_DEV_ID_E825C_SGMII:
		/* E825C devices have multiple NACs which are connected to the
		 * same clock source, and which must share the same
		 * ice_adapter structure. We can't use the serial number since
		 * each NAC has its own NVM generated with its own unique
		 * Device Serial Number. Instead, rely on the embedded nature
		 * of the E825C devices, and use a fixed index. This relies on
		 * the fact that all E825C physical functions in a given
		 * system are part of the same overall device.
		 */
		return ICE_ADAPTER_INDEX_E825C;
	default:
		return pci_get_dsn(pdev) & ~ICE_ADAPTER_FIXED_INDEX;
	}
}

static int ice_adapter_init(void *priv, void *init_param)
{
	struct ice_adapter *adapter = priv;
	struct devlink *devlink;

	devlink = shd_priv_to_devlink(adapter);
	adapter->devlink = devlink;

	spin_lock_init(&adapter->ptp_gltsyn_time_lock);
	spin_lock_init(&adapter->txq_ctx_lock);
	for (int i = 0; i < ARRAY_SIZE(adapter->cpi_phy_lock); i++)
		mutex_init(&adapter->cpi_phy_lock[i]);
	mutex_init(&adapter->cgu_synce_lock);

	spin_lock_init(&adapter->ports.lock);
	INIT_LIST_HEAD(&adapter->ports.list);

	return init_srcu_struct(&adapter->ports.srcu);
}

static void ice_adapter_fini(void *priv)
{
	struct ice_adapter *adapter = priv;

	WARN_ON(!list_empty(&adapter->ports.list));
	for (int i = 0; i < ARRAY_SIZE(adapter->cpi_phy_lock); i++)
		mutex_destroy(&adapter->cpi_phy_lock[i]);
	mutex_destroy(&adapter->cgu_synce_lock);

	cleanup_srcu_struct(&adapter->ports.srcu);
}

static const struct devlink_ops ice_adapter_devlink_ops = {
	.shd_init = ice_adapter_init,
	.shd_fini = ice_adapter_fini,
};

/**
 * ice_adapter_get - Get a shared ice_adapter structure.
 * @pdev: Pointer to the pci_dev whose driver is getting the ice_adapter.
 *
 * Gets a pointer to a shared ice_adapter structure. Physical functions (PFs)
 * of the same multi-function PCI device share one ice_adapter structure.
 * The ice_adapter is reference-counted. The PF driver must use ice_adapter_put
 * to release its reference.
 *
 * Context: Process, may sleep.
 * Return:  Pointer to ice_adapter on success.
 *          ERR_PTR() on error.
 */
struct ice_adapter *ice_adapter_get(struct pci_dev *pdev)
{
	struct ice_adapter *adapter;
	struct devlink *devlink;
	char devlink_id[32];
	u64 index;

	index = ice_adapter_index(pdev);
	snprintf(devlink_id, sizeof(devlink_id), "ice:%llx", index);
	devlink = devlink_shd_get(devlink_id, &ice_adapter_devlink_ops,
				  sizeof(*adapter), NULL, pdev->dev.driver);
	if (IS_ERR(devlink))
		return ERR_CAST(devlink);

	adapter = devlink_shd_get_priv(devlink);

	return adapter;
}

/**
 * ice_adapter_put - Release a reference to the shared ice_adapter structure.
 * @adapter: the ice_adapter to release reference to
 *
 * Releases the reference to ice_adapter previously obtained with
 * ice_adapter_get.
 *
 * Context: Process, may sleep.
 */
void ice_adapter_put(struct ice_adapter *adapter)
{
	devlink_shd_put(adapter->devlink);
}
