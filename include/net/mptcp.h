/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __NET_MPTCP_H
#define __NET_MPTCP_H

#ifdef CONFIG_MPTCP

void mptcp_init(void);

#else

static inline void mptcp_init(void)
{
}

#endif /* CONFIG_MPTCP */
#endif /* __NET_MPTCP_H */
