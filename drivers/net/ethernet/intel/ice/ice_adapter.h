/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Red Hat */

#ifndef _ICE_ADAPTER_H_
#define _ICE_ADAPTER_H_

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/srcu.h>
#include <linux/spinlock_types.h>

#include <net/devlink.h>

#include "ice_type.h"

struct pci_dev;
struct ice_pf;

/**
 * struct ice_port_list - data used to store the list of adapter ports
 *
 * This structure contains data used to maintain a list of adapter ports.
 * Writers modifying the list *must* acquire the lock, and use SRCU safe list
 * operations. Readers should use srcu_read_lock() on the provided domain.
 *
 * @list: list of ports
 * @lock: protect write access to the list
 * @srcu: Sleepable RCU domain for this adapter
 */
struct ice_port_list {
	struct list_head list;
	/* To synchronize write operations on the port list */
	spinlock_t lock;
	struct srcu_struct srcu;
};

/**
 * struct ice_adapter - PCI adapter resources shared across PFs
 * @devlink: ice adapter's devlink (whole dev devlink)
 * @ptp_gltsyn_time_lock: Spinlock protecting access to the GLTSYN_TIME
 *                        register of the PTP clock.
 * @txq_ctx_lock: Spinlock protecting access to the GLCOMM_QTX_CNTX_CTL register
 * @cpi_phy_lock: Per-PHY mutex serializing CPI REQ/ACK transactions.
 *               Index 0 = PHY0, index 1 = PHY1. Used on E825C devices.
 * @cgu_synce_lock: Mutex serializing changes of the CGU registers R10 and R11,
 *                  which all PFs reach. Used on E825C devices.
 * @ctrl_pf: Control PF of the adapter
 * @ports: Ports list
 */
struct ice_adapter {
	struct devlink *devlink;

	/* For access to the GLTSYN_TIME register */
	spinlock_t ptp_gltsyn_time_lock;
	/* For access to GLCOMM_QTX_CNTX_CTL register */
	spinlock_t txq_ctx_lock;
	/* Serialize CPI REQ/ACK transactions per PHY (E825C only) */
	struct mutex cpi_phy_lock[ICE_E825_MAX_PHYS];
	/* Serialize changes of the SyncE CGU registers (E825C only) */
	struct mutex cgu_synce_lock;

	struct ice_pf *ctrl_pf;
	struct ice_port_list ports;
};

struct ice_adapter *ice_adapter_get(struct pci_dev *pdev);
void ice_adapter_put(struct ice_adapter *adapter);

#endif /* _ICE_ADAPTER_H */
