/* SPDX-License-Identifier: GPL-2.0 */
/* Shared QoS and DCB logic for the Realtek DSA switch family */

#ifndef _RTL83XX_QOS_H
#define _RTL83XX_QOS_H

#include <linux/types.h>
#include <net/dsa.h>

int rtl83xx_qos_init(struct dsa_switch *ds);
int rtl83xx_qos_init_port(struct dsa_switch *ds, int port);
int rtl83xx_port_get_default_prio(struct dsa_switch *ds, int port);
int rtl83xx_port_set_default_prio(struct dsa_switch *ds, int port, u8 prio);
int rtl83xx_port_get_apptrust(struct dsa_switch *ds, int port, u8 *sel,
			      int *nsel);
int rtl83xx_port_set_apptrust(struct dsa_switch *ds, int port, const u8 *sel,
			      int nsel);
int rtl83xx_port_get_dscp_prio(struct dsa_switch *ds, int port, u8 dscp);

#endif /* _RTL83XX_QOS_H */
