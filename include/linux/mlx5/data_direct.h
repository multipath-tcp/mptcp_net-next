/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef _MLX5_DATA_DIRECT_H
#define _MLX5_DATA_DIRECT_H

struct mlx5_core_dev;

int mlx5_data_direct_query_vuid(struct mlx5_core_dev *dev, char *out_vuid);

#endif
