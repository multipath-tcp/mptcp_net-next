/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024 Pengutronix, Oleksij Rempel <kernel@pengutronix.de> */

#ifndef _NET_IEEE8021Q_H
#define _NET_IEEE8021Q_H

#include <linux/errno.h>

/**
 * enum ieee8021q_traffic_type - 802.1Q traffic types (802.1Q-2022)
 *
 * @IEEE8021Q_TT_BK: Background
 * @IEEE8021Q_TT_BE: Best Effort (default). The enum value is not the 802.1Q
 * priority. IEEE 802.1Q-2022 (Annex I.4, Table I-2) gives Best Effort priority
 * 0 and Background priority 1, and says that priority 1 is lower than priority
 * 0. The enum orders the traffic types lowest first, so Background is 0 and
 * Best Effort is 1.
 * @IEEE8021Q_TT_EE: Excellent Effort
 * @IEEE8021Q_TT_CA: Critical Applications
 * @IEEE8021Q_TT_VI: Video, < 100 ms latency and jitter
 * @IEEE8021Q_TT_VO: Voice, < 10 ms latency and jitter
 * @IEEE8021Q_TT_IC: Internetwork Control
 * @IEEE8021Q_TT_NC: Network Control
 */
enum ieee8021q_traffic_type {
	IEEE8021Q_TT_BK = 0,
	IEEE8021Q_TT_BE = 1,
	IEEE8021Q_TT_EE = 2,
	IEEE8021Q_TT_CA = 3,
	IEEE8021Q_TT_VI = 4,
	IEEE8021Q_TT_VO = 5,
	IEEE8021Q_TT_IC = 6,
	IEEE8021Q_TT_NC = 7,

	/* private: */
	IEEE8021Q_TT_MAX,
};

#define SIMPLE_IETF_DSCP_TO_IEEE8021Q_TT(dscp)		((dscp >> 3) & 0x7)

#if IS_ENABLED(CONFIG_NET_IEEE8021Q_HELPERS)

int ietf_dscp_to_ieee8021q_tt(u8 dscp);
int ieee8021q_pcp_to_tt(u8 pcp);
int ieee8021q_tt_to_tc(enum ieee8021q_traffic_type tt, unsigned int num_queues);

#else

static inline int ietf_dscp_to_ieee8021q_tt(u8 dscp)
{
	return -EOPNOTSUPP;
}

static inline int ieee8021q_pcp_to_tt(u8 pcp)
{
	return -EOPNOTSUPP;
}

static inline int ieee8021q_tt_to_tc(enum ieee8021q_traffic_type tt,
				     unsigned int num_queues)
{
	return -EOPNOTSUPP;
}

#endif
#endif /* _NET_IEEE8021Q_H */
