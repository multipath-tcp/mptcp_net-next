/* SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2026 Microchip Technology Inc.
 */

#ifndef _NET_DSA_TAG_LAN9645X_H_
#define _NET_DSA_TAG_LAN9645X_H_

#include <linux/bits.h>
#include <linux/types.h>

/* LAN9645x supports 3 different formats on an NPI port, long prefix, short
 * prefix and no prefix. The format can be configured asymmetrically on RX and
 * TX. We use long prefix on extraction (RX), and no prefix on injection.
 * The long prefix on extraction helps get through the conduit port on host
 * side, since it will see a broadcast MAC.
 *
 * The internal frame header (IFH) is 28 bytes.
 *
 * Long prefix, 16 bytes + IFH:
 * - DMAC    = 0xFFFFFFFFFFFF on extraction.
 * - SMAC    = 0xFEFFFFFFFFFF on extraction.
 * - ETYPE   = 0x8880
 * - payload = 0x0011
 * - IFH
 *
 * Short prefix, 4 bytes + IFH:
 * - 0x8880
 * - 0x0011
 * - IFH
 *
 * No prefix:
 * - IFH
 *
 */
#define LAN9645X_IFH_TAG_TYPE_C		0
#define LAN9645X_IFH_TAG_TYPE_S		1
#define LAN9645X_IFH_LEN_U32		7
#define LAN9645X_IFH_LEN_BYTES		(LAN9645X_IFH_LEN_U32 * sizeof(u32))
#define LAN9645X_IFH_BITS		(LAN9645X_IFH_LEN_BYTES * BITS_PER_BYTE)
#define LAN9645X_LONG_PREFIX_LEN	16
#define LAN9645X_TOTAL_TAG_LEN \
	(LAN9645X_LONG_PREFIX_LEN + LAN9645X_IFH_LEN_BYTES)

/* Chip has 8 cpu queues. The cpu queues used by a frame are passed as a mask in
 * the IFH on extraction. We use this to avoid classifying BPDU, IGMP and MLD
 * frames in the tag driver.
 */
enum {
	LAN9645X_CPUQ_DEF = 0,
	LAN9645X_CPUQ_TRAP = 1,
	LAN9645X_CPUQ_COPY = 2,
};

#endif /* _NET_DSA_TAG_LAN9645X_H_ */
