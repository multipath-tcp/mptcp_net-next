/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 David Yang
 */

#ifndef _YT_DEVLINK_H
#define _YT_DEVLINK_H

#include <net/dsa.h>

struct yt921x_priv;

int
yt921x_dsa_devlink_info_get(struct dsa_switch *ds, struct devlink_info_req *req,
			    struct netlink_ext_ack *extack);
int yt921x_devlink_setup(struct yt921x_priv *priv);

#endif
