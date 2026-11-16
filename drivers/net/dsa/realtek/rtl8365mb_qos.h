/* SPDX-License-Identifier: GPL-2.0 */
/* QoS and DCB register programming for the rtl8365mb switch family */

#ifndef _REALTEK_RTL8365MB_QOS_H
#define _REALTEK_RTL8365MB_QOS_H

#include <linux/types.h>

struct realtek_priv;

/* The switch has eight internal priorities (0..7) */
#define RTL8365MB_NUM_INTERNAL_PRIOS	8

/* Ports the QoS code handles */
#define RTL8365MB_QOS_MAX_PORTS		8

/* Internal priority -> queue id tables (qmaps) */
#define RTL8365MB_QOS_NUM_QMAPS		8

int rtl8365mb_qos_pridec_init(struct realtek_priv *priv);
int rtl8365mb_qos_qmap_init(struct realtek_priv *priv);
int rtl8365mb_qos_get_port_prio(struct realtek_priv *priv, int port);
int rtl8365mb_qos_set_port_prio(struct realtek_priv *priv, int port, u8 iprio,
				u8 untag_pcp);
int rtl8365mb_qos_set_pcp_prio(struct realtek_priv *priv, u8 pcp, u8 iprio);
int rtl8365mb_qos_set_dscp_prio(struct realtek_priv *priv, u8 dscp, u8 iprio);
int rtl8365mb_qos_set_apptrust(struct realtek_priv *priv, int port,
			       const bool *trust, unsigned int n);
int rtl8365mb_qos_get_apptrust(struct realtek_priv *priv, int port, bool *trust,
			       unsigned int n);

#endif /* _REALTEK_RTL8365MB_QOS_H */
