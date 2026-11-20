// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/bitfield.h>
#include <linux/etherdevice.h>

#include "mpnic.h"
#include "mpnic_rpc.h"

static bool mpnic_macda_free(struct mpnic_mac_addr *mac_addr)
{
	return mac_addr->state == MPNIC_TCAM_S_DISABLED ||
	       mac_addr->state == MPNIC_TCAM_S_DELETE;
}

int mpnic_macda_sync(struct mpnic_dev *mpd, const u8 *addr)
{
	struct mpnic_mac_addr *avail_addr = NULL;
	unsigned int i;

	for (i = MPNIC_TCAM_MACDA_BROADCAST_IDX + 1;
	     i < MPNIC_TCAM_MACDA_HOST_ADDR_IDX; i++) {
		struct mpnic_mac_addr *mac_addr = &mpd->mac_addr[i];

		if (mac_addr->state != MPNIC_TCAM_S_DISABLED &&
		    ether_addr_equal(mac_addr->value, addr)) {
			avail_addr = mac_addr;
			break;
		}

		if (!avail_addr && mpnic_macda_free(mac_addr))
			avail_addr = mac_addr;
	}

	if (!avail_addr)
		return -ENOSPC;

	if (mpnic_macda_free(avail_addr)) {
		ether_addr_copy(avail_addr->value, addr);
		eth_broadcast_addr(avail_addr->mask);
		avail_addr->state = MPNIC_TCAM_S_ADD;
	}

	avail_addr->users++;

	return 0;
}

int mpnic_macda_unsync(struct mpnic_dev *mpd, const u8 *addr)
{
	unsigned int i;

	for (i = MPNIC_TCAM_MACDA_BROADCAST_IDX + 1;
	     i < MPNIC_TCAM_MACDA_HOST_ADDR_IDX; i++) {
		struct mpnic_mac_addr *mac_addr = &mpd->mac_addr[i];

		if (mpnic_macda_free(mac_addr) ||
		    !ether_addr_equal(mac_addr->value, addr))
			continue;

		if (!--mac_addr->users)
			mac_addr->state = MPNIC_TCAM_S_DELETE;

		return 0;
	}

	return -ENOENT;
}

void mpnic_promisc_sync(struct mpnic_dev *mpd, bool uc_promisc,
			bool mc_promisc)
{
	struct mpnic_mac_addr *mac_addr;

	mac_addr = &mpd->mac_addr[MPNIC_TCAM_MACDA_PROMISC_IDX];
	if (uc_promisc) {
		if (!is_zero_ether_addr(mac_addr->value) ||
		    mac_addr->state != MPNIC_TCAM_S_VALID) {
			eth_zero_addr(mac_addr->value);
			eth_zero_addr(mac_addr->mask);
			mac_addr->state = MPNIC_TCAM_S_ADD;
		}
	} else if (mc_promisc) {
		if (!is_multicast_ether_addr(mac_addr->value) ||
		    mac_addr->state != MPNIC_TCAM_S_VALID) {
			eth_zero_addr(mac_addr->value);
			eth_zero_addr(mac_addr->mask);
			mac_addr->value[0] ^= 1;
			mac_addr->mask[0] ^= 1;
			mac_addr->state = MPNIC_TCAM_S_ADD;
		}
	} else if (mac_addr->state == MPNIC_TCAM_S_VALID) {
		mac_addr->state = MPNIC_TCAM_S_DELETE;
	}
}

static void mpnic_write_macda_entry(struct mpnic_dev *mpd, unsigned int idx,
				    struct mpnic_mac_addr *mac_addr)
{
	mpnic_wr64(mpd, MPNIC_RXB_DMAC_TCAM(idx),
		   FIELD_PREP(MPNIC_RXB_DMAC_TCAM_DMAC,
			      ether_addr_to_u64(mac_addr->value)));
	mpnic_wr64(mpd, MPNIC_RXB_DMAC_TCAM_MASK(idx),
		   FIELD_PREP(MPNIC_RXB_DMAC_TCAM_DMAC,
			      ether_addr_to_u64(mac_addr->mask)));
}

void mpnic_write_macda(struct mpnic_dev *mpd)
{
	for (int i = 0; i < ARRAY_SIZE(mpd->mac_addr); i++) {
		u64 tcam_op = FIELD_PREP(MPNIC_RXB_DMAC_TCAM_OP_TCAM_ENTRY, i);
		struct mpnic_mac_addr *mac_addr = &mpd->mac_addr[i];

		if (mac_addr->state != MPNIC_TCAM_S_ADD &&
		    mac_addr->state != MPNIC_TCAM_S_DELETE)
			continue;

		if (mac_addr->state == MPNIC_TCAM_S_DELETE) {
			memset(mac_addr, 0, sizeof(*mac_addr));
			tcam_op |= MPNIC_RXB_DMAC_TCAM_OP_UNLOAD_TRIG;
		} else {
			mpnic_write_macda_entry(mpd, i, mac_addr);
			mac_addr->state = MPNIC_TCAM_S_VALID;
			tcam_op |= MPNIC_RXB_DMAC_TCAM_OP_RELOAD_TRIG;
		}

		mpnic_wr64(mpd, MPNIC_RXB_DMAC_TCAM_OP, tcam_op);
	}
}
