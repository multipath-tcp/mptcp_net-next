/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef _MLX5_IB_DATA_DIRECT_H
#define _MLX5_IB_DATA_DIRECT_H

#include <linux/notifier.h>
#include <linux/mlx5/data_direct.h>

struct mlx5_core_dev;
struct mlx5_ib_dev;

enum mlx5_data_direct_event {
	MLX5_DATA_DIRECT_UNBIND,
};

struct mlx5_data_direct_dev {
	struct device *device;
	struct pci_dev *pdev;
	char *vuid;
	struct list_head list;
};

int mlx5_data_direct_driver_register(void);
void mlx5_data_direct_driver_unregister(void);

#endif
