/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifndef _MPNIC_RPC_H_
#define _MPNIC_RPC_H_

#include <linux/if_ether.h>
#include <linux/types.h>

#include "mpnic_csr.h"

struct mpnic_dev;

/*  The TCAM state definitions follow an expected ordering.
 *  They start out disabled, then move through the following states:
 *  Disabled  0	-> Add	      2
 *  Add	      2	-> Valid      1
 *
 *  Valid     1	-> Add	      2
 *  Add	      2	-> Valid      1
 *
 *  Valid     1	-> Delete     3
 *  Delete    3	-> Disabled   0
 */
enum {
	MPNIC_TCAM_S_DISABLED	= 0,
	MPNIC_TCAM_S_VALID	= 1,
	MPNIC_TCAM_S_ADD	= 2,
	MPNIC_TCAM_S_DELETE	= 3,
};

#define MPNIC_TCAM_MACDA_BROADCAST_IDX	0
#define MPNIC_TCAM_MACDA_HOST_ADDR_IDX	(MPNIC_RXB_DMAC_TCAM_CNT - 2)
#define MPNIC_TCAM_MACDA_PROMISC_IDX	(MPNIC_RXB_DMAC_TCAM_CNT - 1)

struct mpnic_mac_addr {
	u8 mask[ETH_ALEN];
	u8 value[ETH_ALEN];
	u8 state;
} __aligned(2);

void mpnic_promisc_sync(struct mpnic_dev *mpd, bool uc_promisc,
			bool mc_promisc);
void mpnic_write_macda(struct mpnic_dev *mpd);

#endif /* _MPNIC_RPC_H_ */
