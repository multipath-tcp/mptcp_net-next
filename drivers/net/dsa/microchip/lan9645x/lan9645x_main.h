/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (C) 2026 Microchip Technology Inc.
 */

#ifndef __LAN9645X_MAIN_H__
#define __LAN9645X_MAIN_H__

#include <linux/dsa/lan9645x.h>
#include <linux/if_bridge.h>
#include <linux/regmap.h>
#include <net/dsa.h>

#include "lan9645x_regs.h"

/* Port modules 0-8 are front (user) ports. The chip additionally has two
 * logical CPU port modules at indices 9 and 10. These are not the DSA CPU port.
 * The CPU port modules are logical ports in the chip intended for management.
 *
 * The frame delivery mechanism can vary: direct register injection/extraction,
 * or a front port can be used as the management port, called a Node Processor
 * Interface (NPI) in the datasheet.
 *
 * LAN9645X uses the NPI approach, so the DSA CPU port is a front port
 * (see lan9645x->npi) configured as NPI port.
 *
 * Therefore the CPU datapath has two port module indices of interest,
 * lan9645x->npi and the cpu port module at index 9.
 */
#define NUM_PHYS_PORTS		9

#define NUM_PRIO_QUEUES		8

#define QS_SRC_BUF_RSV		1664

/* Reserved amount for (SRC, PRIO) at index 8*SRC + PRIO
 * See QSYS:RES_CTRL[*]:RES_CFG description
 */
#define QSYS_Q_RSRV			95

/* Port Group Identifiers (PGID) are port-masks applied to all frames.
 *
 * The forwarding engine outputs two masks for the forwarding decision, DEST and
 * CPUQ. DEST determines which front ports will receive a frame, and CPUQ
 * whether the frame is forwarded to the CPU.
 *
 * The replicated registers are organized like so in HW:
 *
 * 0-63:         Destination analysis.
 * 64-79:        Aggregation analysis
 * 80-(80+10-1): Source port analysis
 *
 * Destination: Destination PGIDs are the result of mac table lookups or
 * flooding decisions. The resolved destination PGID will feed into DEST and set
 * the bit for ANA_PGID_CFG.CPUQ_DST_PGID in CPUQ, if the CPU port module bit is
 * set in the PGID. This is how PGID_CPU and host flooding work.
 *
 * The first NUM_PHYS_PORTS destination PGIDs can not be used freely, because
 * dynamic learning writes mac table entries with DEST_IDX taken from the
 * ingress ports ANA_PORT_CFG.PORTID_VAL. They come out of reset as BIT(i)
 * for that reason.
 *
 * PGID NUM_PHYS_PORTS..63 come out of reset as zero and have no reserved
 * role. We use them for L2 Multicast and flooding (see FLOODING and
 * FLOODING_IPMC) and reserve a few at the end of the range. The CPU port module
 * has no reserved destination PGID. It does have a reserved source PGID at
 * PGID_SRC + NUM_PHYS_PORTS.
 *
 * Aggregation: Each frame receives a link aggregation code from the analyzer,
 * based on a configurable algorithm. This code picks out one of the 16
 * aggregation PGIDs to mask out ports in DEST. If no aggregation is configured,
 * these are all-ones. The CPU port module bit is inert here.
 *
 * Source: Control which ports a given source port can forward to. A frame that
 * is received on port n, uses entry PGID_SRC + n to mask out DEST.
 * The default values are all bits set except for the index itself
 * (no loopback). The CPU port module bit is inert here.
 */

#define PGID_AGGR			64
#define PGID_SRC			80

/* Reserved PGIDs. */
#define PGID_CPU			(PGID_AGGR - 6)
#define PGID_UC				(PGID_AGGR - 5)
#define PGID_BC				(PGID_AGGR - 4)
#define PGID_MC				(PGID_AGGR - 3)
#define PGID_MCIPV4			(PGID_AGGR - 2)
#define PGID_MCIPV6			(PGID_AGGR - 1)

/* Flooding PGIDS:
 * PGID_UC
 * PGID_MC*
 * PGID_BC
 */

#define GWM_MULTIPLIER_BIT		BIT(8)
#define LAN9645X_BUFFER_CELL_SZ		64

#define RD_SLEEP_US			3
#define RD_SLEEPTIMEOUT_US		100000
#define SLOW_RD_SLEEP_US		1000
#define SLOW_RD_SLEEPTIMEOUT_US		4000000

/* regmap_read_poll_timeout() re-evaluates its map and address arguments on
 * every iteration, so resolve both once up front.
 */
#define lan9645x_rd_poll_timeout(_lan9645x, _reg_macro, _val, _cond)	\
({									\
	struct regmap *__map = lan_rmap((_lan9645x), _reg_macro);	\
	u32 __addr = lan_rel_addr(_reg_macro);				\
									\
	regmap_read_poll_timeout(__map, __addr, (_val), (_cond),		\
				 RD_SLEEP_US, RD_SLEEPTIMEOUT_US);	\
})

#define lan9645x_rd_poll_slow(_lan9645x, _reg_macro, _val, _cond)	\
({									\
	struct regmap *__map = lan_rmap((_lan9645x), _reg_macro);	\
	u32 __addr = lan_rel_addr(_reg_macro);				\
									\
	regmap_read_poll_timeout(__map, __addr, (_val), (_cond),		\
				 SLOW_RD_SLEEP_US,			\
				 SLOW_RD_SLEEPTIMEOUT_US);		\
})

/* NPI port prefix config encoding
 *
 * 0: No CPU extraction header (normal frames)
 * 1: CPU extraction header without prefix
 * 2: CPU extraction header with short prefix
 * 3: CPU extraction header with long prefix
 */
enum lan9645x_tag_prefix {
	LAN9645X_TAG_PREFIX_DISABLED = 0,
	LAN9645X_TAG_PREFIX_NONE = 1,
	LAN9645X_TAG_PREFIX_SHORT = 2,
	LAN9645X_TAG_PREFIX_LONG = 3,
};

enum {
	LAN9645X_SPEED_DISABLED = 0,
	LAN9645X_SPEED_10 = 1,
	LAN9645X_SPEED_100 = 2,
	LAN9645X_SPEED_1000 = 3,
	LAN9645X_SPEED_2500 = 4,
};

/* Rewriter VLAN port tagging encoding for REW:PORT[0-10]:TAG_CFG.TAG_CFG
 *
 * 0: Port tagging disabled.
 * 1: Tag all frames, except when VID=PORT_VLAN_CFG.PORT_VID or VID=0.
 * 2: Tag all frames, except when VID=0.
 * 3: Tag all frames.
 */
enum lan9645x_vlan_port_tag {
	LAN9645X_TAG_DISABLED = 0,
	LAN9645X_TAG_NO_PVID_NO_UNAWARE = 1,
	LAN9645X_TAG_NO_UNAWARE = 2,
	LAN9645X_TAG_ALL = 3,
};

struct lan9645x {
	struct device *dev;
	struct dsa_switch *ds;
	struct regmap *rmap[NUM_TARGETS];

	/* NPI chip_port */
	int npi;

	u8 num_phys_ports;
	struct lan9645x_port **ports;

	int num_port_dis;
};

struct lan9645x_port {
	struct lan9645x *lan9645x;

	u8 chip_port;

	bool rx_internal_delay;
	bool tx_internal_delay;
};

extern const struct phylink_mac_ops lan9645x_phylink_mac_ops;

/* PFC_CFG.FC_LINK_SPEED encoding */
static inline int lan9645x_speed_fc_enc(int speed)
{
	switch (speed) {
	case LAN9645X_SPEED_10:
		return 3;
	case LAN9645X_SPEED_100:
		return 2;
	case LAN9645X_SPEED_1000:
		return 1;
	case LAN9645X_SPEED_2500:
		return 0;
	default:
		WARN_ON_ONCE(1);
		return 1;
	}
}

/* Watermark encode. See QSYS:RES_CTRL[*]:RES_CFG.WM_HIGH for details.
 * Returns lowest encoded number which will fit request/ is larger than request.
 * Or the maximum representable value, if request is too large.
 */
static inline u32 lan9645x_wm_enc(u32 value)
{
	value = DIV_ROUND_UP(value, LAN9645X_BUFFER_CELL_SZ);

	if (value >= GWM_MULTIPLIER_BIT) {
		value = DIV_ROUND_UP(value, 16);
		if (value >= GWM_MULTIPLIER_BIT)
			value = (GWM_MULTIPLIER_BIT - 1);
		value |= GWM_MULTIPLIER_BIT;
	}

	return value;
}

static inline struct lan9645x_port *lan9645x_to_port(struct lan9645x *lan9645x,
						     int port)
{
	return lan9645x->ports[port];
}

static inline struct regmap *lan_tgt2rmap(struct lan9645x *lan9645x,
					  enum lan9645x_target t, int tinst)
{
	return lan9645x->rmap[t + tinst];
}

static inline u32 __lan_rel_addr(int gbase, int ginst, int gcnt,
				 int gwidth, int raddr, int rinst,
				 int rcnt, int rwidth)
{
	WARN_ON(ginst >= gcnt);
	WARN_ON(rinst >= rcnt);
	return gbase + ginst * gwidth + raddr + rinst * rwidth;
}

/* Get register address relative to target instance */
static inline u32 lan_rel_addr(enum lan9645x_target t, int tinst, int tcnt,
			       int gbase, int ginst, int gcnt, int gwidth,
			       int raddr, int rinst, int rcnt, int rwidth)
{
	WARN_ON(tinst >= tcnt);
	return __lan_rel_addr(gbase, ginst, gcnt, gwidth, raddr, rinst,
			      rcnt, rwidth);
}

static inline struct regmap *lan_rmap(struct lan9645x *lan9645x,
				      enum lan9645x_target t, int tinst,
				      int tcnt, int gbase, int ginst,
				      int gcnt, int gwidth, int raddr,
				      int rinst, int rcnt, int rwidth)
{
	return lan_tgt2rmap(lan9645x, t, tinst);
}

static inline void lan_wr(u32 val, struct lan9645x *lan9645x,
			  enum lan9645x_target t, int tinst, int tcnt,
			  int gbase, int ginst, int gcnt, int gwidth,
			  int raddr, int rinst, int rcnt, int rwidth)
{
	u32 addr;

	addr = lan_rel_addr(t, tinst, tcnt, gbase, ginst, gcnt, gwidth,
			    raddr, rinst, rcnt, rwidth);

	WARN_ON_ONCE(regmap_write(lan_tgt2rmap(lan9645x, t, tinst), addr, val));
}

static inline void lan_rmw(u32 val, u32 mask, struct lan9645x *lan9645x,
			   enum lan9645x_target t, int tinst, int tcnt,
			   int gbase, int ginst, int gcnt, int gwidth,
			   int raddr, int rinst, int rcnt, int rwidth)
{
	u32 addr;

	addr = lan_rel_addr(t, tinst, tcnt, gbase, ginst, gcnt, gwidth,
			    raddr, rinst, rcnt, rwidth);

	WARN_ON_ONCE(regmap_update_bits(lan_tgt2rmap(lan9645x, t, tinst),
					addr, mask, val));
}

/* lan9645x_npi.c */
void lan9645x_npi_port_init(struct lan9645x *lan9645x,
			    struct dsa_port *cpu_port);
void lan9645x_npi_port_deinit(struct lan9645x *lan9645x, int port);
void lan9645x_npi_cpuq_redirect(struct lan9645x *lan9645x, bool enable);

/* lan9645x_port.c */
int lan9645x_port_setup(struct dsa_switch *ds, int port);
int lan9645x_port_set_maxlen(struct lan9645x *lan9645x, int port, size_t sdu);
void lan9645x_port_cpu_init(struct lan9645x *lan9645x);

/* lan9645x_phylink.c */
void lan9645x_phylink_get_caps(struct lan9645x *lan9645x, int port,
			       struct phylink_config *c);
void lan9645x_phylink_port_down(struct lan9645x *lan9645x, int port);

#endif /* __LAN9645X_MAIN_H__ */
