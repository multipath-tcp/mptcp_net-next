// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/mptcp.yaml */
/* YNL-GEN kernel source */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "pm_nl.h"

#include <linux/mptcp_pm.h>

/* Common nested types */
const struct nla_policy mptcp_pm_addr_nl_policy[MPTCP_PM_ADDR_ATTR_IF_IDX + 1] = {
	[MPTCP_PM_ADDR_ATTR_FAMILY] = { .type = NLA_U16, },
	[MPTCP_PM_ADDR_ATTR_ID] = { .type = NLA_U8, },
	[MPTCP_PM_ADDR_ATTR_ADDR4] = { .type = NLA_U32, },
	[MPTCP_PM_ADDR_ATTR_ADDR6] = { .len = 16, },
	[MPTCP_PM_ADDR_ATTR_PORT] = { .type = NLA_U16, },
	[MPTCP_PM_ADDR_ATTR_FLAGS] = { .type = NLA_U32, },
	[MPTCP_PM_ADDR_ATTR_IF_IDX] = { .type = NLA_S32, },
};

/* Global operation policy for mptcp_pm */
const struct nla_policy mptcp_pm_attr_nl_policy[MPTCP_PM_ATTR_ADDR_REMOTE + 1] = {
	[MPTCP_PM_ATTR_ADDR] = NLA_POLICY_NESTED(mptcp_pm_addr_nl_policy),
	[MPTCP_PM_ATTR_RCV_ADD_ADDRS] = { .type = NLA_U32, },
	[MPTCP_PM_ATTR_SUBFLOWS] = { .type = NLA_U32, },
	[MPTCP_PM_ATTR_TOKEN] = { .type = NLA_U32, },
	[MPTCP_PM_ATTR_LOC_ID] = { .type = NLA_U8, },
	[MPTCP_PM_ATTR_ADDR_REMOTE] = NLA_POLICY_NESTED(mptcp_pm_addr_nl_policy),
};

/* Ops table for mptcp_pm */
const struct genl_small_ops mptcp_pm_nl_ops[11] = {
	{
		.cmd	= MPTCP_PM_CMD_ADD_ADDR,
		.doit	= mptcp_pm_nl_add_addr_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_DEL_ADDR,
		.doit	= mptcp_pm_nl_del_addr_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_GET_ADDR,
		.doit	= mptcp_pm_nl_get_addr_doit,
		.dumpit	= mptcp_pm_nl_get_addr_dumpit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_FLUSH_ADDRS,
		.doit	= mptcp_pm_nl_flush_addrs_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_SET_LIMITS,
		.doit	= mptcp_pm_nl_set_limits_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_GET_LIMITS,
		.doit	= mptcp_pm_nl_get_limits_doit,
	},
	{
		.cmd	= MPTCP_PM_CMD_SET_FLAGS,
		.doit	= mptcp_pm_nl_set_flags_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_ANNOUNCE,
		.doit	= mptcp_pm_nl_announce_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_REMOVE,
		.doit	= mptcp_pm_nl_remove_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_SUBFLOW_CREATE,
		.doit	= mptcp_pm_nl_subflow_create_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd	= MPTCP_PM_CMD_SUBFLOW_DESTROY,
		.doit	= mptcp_pm_nl_subflow_destroy_doit,
		.flags	= GENL_UNS_ADMIN_PERM,
	},
};
