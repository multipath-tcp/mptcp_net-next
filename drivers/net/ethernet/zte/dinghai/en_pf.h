/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ZTE DingHai Ethernet driver - PF header
 * Copyright (c) 2022-2026, ZTE Corporation.
 */

#ifndef __ZXDH_EN_PF_H__
#define __ZXDH_EN_PF_H__

#include <linux/types.h>

#define ZXDH_PF_VENDOR_ID	0x1cf2
#define ZXDH_PF_DEVICE_ID	0x8040
#define ZXDH_VF_DEVICE_ID	0x8041

/* Common configuration */
#define ZXDH_PCI_CAP_COMMON_CFG	1
/* Notifications */
#define ZXDH_PCI_CAP_NOTIFY_CFG	2
/* ISR access */
#define ZXDH_PCI_CAP_ISR_CFG		3
/* Device specific configuration */
#define ZXDH_PCI_CAP_DEVICE_CFG	4
/* PCI configuration access */
#define ZXDH_PCI_CAP_PCI_CFG		5

#define ZXDH_PF_MAX_BAR_VAL		0x5
#define ZXDH_PF_ALIGN4			4
#define ZXDH_PF_ALIGN2			2
#define ZXDH_PF_MAP_MINLEN2		2

/* Fixed offsets of the firmware interface regions within BAR 0. */
#define ZXDH_RISCV_HB_OFFSET	0x5300
#define ZXDH_FW_COMPAT_OFFSET	0x5400

/* Driver/firmware version contract. The firmware publishes its side of
 * the contract in the region at ZXDH_FW_COMPAT_OFFSET.
 */
#define ZXDH_MODULE_ID		1
#define ZXDH_MAJOR		1
#define ZXDH_FW_MINOR		0
#define ZXDH_DRV_MINOR		0
/* Firmware patch level that introduced hot-plug IRQ support. */
#define ZXDH_HPIRQ_PATCH	4

#define ZXDH_FW_COMPAT_TIMEOUT_SEC	20
#define ZXDH_RISCV_READY_TIMEOUT_SEC	40

/* Firmware version compatibility block at ZXDH_FW_COMPAT_OFFSET.
 * Fields are read through ioread*(), which converts from little-endian.
 */
struct zxdh_fw_compat {
	u8 module_id;
	u8 major;
	u8 fw_minor;
	u8 drv_minor;
	u16 patch;
	u16 rsv;
};

/* Health buffer at ZXDH_RISCV_HB_OFFSET, maintained by the RISC-V
 * management core of the firmware. Fields are read through ioread*().
 */
struct zxdh_health_buffer {
	u32 synd;		/* Bitmask of active syndrome flags. */
	u32 health_counter;	/* Incremented heartbeat counter. */
	u8 status;
	u8 rfr;
	u8 fw_exception;
	u8 riscv_power_on;	/* Set to 1 once the core finished booting. */
	u8 fw_version[32];
	u8 pf_status[5];
	u8 health_version;	/* 1 when the firmware supports self-healing. */
	u8 rsv1[30];
};

struct zxdh_core_dev {
	struct device *device;
	struct pci_dev *pdev;
	struct devlink *devlink;
	void *priv;
};

struct zxdh_pf_dev {
	struct zxdh_pf_pci_common_cfg __iomem *common;
	/* Device-specific data (non-legacy mode)  */
	/* Base of vq notifications (non-legacy mode). */
	void __iomem *device;
	void __iomem *notify_base;
	/* Physical base of vq notifications */
	resource_size_t notify_pa;
	/* So we can sanity-check accesses. */
	size_t notify_len;
	size_t device_len;
	/* Capability for when we need to map notifications per-vq. */
	s32 notify_map_cap;
	u32 notify_offset_multiplier;
	/* Multiply queue_notify_off by this value. (non-legacy mode). */
	s32 modern_bars;
	void __iomem *pci_ioremap_addr[6];
	u32 dev_cfg_bar_off;
	struct zxdh_fw_compat fw_compat;
};

void *zxdh_core_alloc_priv(struct zxdh_core_dev *zxdh_dev, size_t size);
void zxdh_core_free_priv(struct zxdh_core_dev *zxdh_dev);
void zxdh_pf_pci_close(struct zxdh_core_dev *zxdh_dev);
int zxdh_pf_pci_find_capability(struct pci_dev *pdev, u8 cfg_type,
				u32 ioresource_types, int *bars);
void __iomem *zxdh_pf_map_capability(struct zxdh_core_dev *zxdh_dev, int off,
				     size_t minlen, u32 align,
				     u32 start, u32 size,
				     size_t *len, resource_size_t *pa,
				     u32 *bar_off);
int zxdh_pf_common_cfg_init(struct zxdh_core_dev *zxdh_dev);
int zxdh_pf_notify_cfg_init(struct zxdh_core_dev *zxdh_dev);
int zxdh_pf_device_cfg_init(struct zxdh_core_dev *zxdh_dev);
void zxdh_pf_modern_cfg_uninit(struct zxdh_core_dev *zxdh_dev);
int zxdh_pf_modern_cfg_init(struct zxdh_core_dev *zxdh_dev);

#endif /* __ZXDH_EN_PF_H__ */
