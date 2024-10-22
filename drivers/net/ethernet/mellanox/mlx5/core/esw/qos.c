// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include "eswitch.h"
#include "lib/mlx5.h"
#include "esw/qos.h"
#include "en/port.h"
#define CREATE_TRACE_POINTS
#include "diag/qos_tracepoint.h"

/* Minimum supported BW share value by the HW is 1 Mbit/sec */
#define MLX5_MIN_BW_SHARE 1

/* Holds rate nodes associated with an E-Switch. */
struct mlx5_qos_domain {
	/* Serializes access to all qos changes in the qos domain. */
	struct mutex lock;
	/* List of all mlx5_esw_sched_nodes. */
	struct list_head nodes;
};

static void esw_qos_lock(struct mlx5_eswitch *esw)
{
	mutex_lock(&esw->qos.domain->lock);
}

static void esw_qos_unlock(struct mlx5_eswitch *esw)
{
	mutex_unlock(&esw->qos.domain->lock);
}

static void esw_assert_qos_lock_held(struct mlx5_eswitch *esw)
{
	lockdep_assert_held(&esw->qos.domain->lock);
}

static struct mlx5_qos_domain *esw_qos_domain_alloc(void)
{
	struct mlx5_qos_domain *qos_domain;

	qos_domain = kzalloc(sizeof(*qos_domain), GFP_KERNEL);
	if (!qos_domain)
		return NULL;

	mutex_init(&qos_domain->lock);
	INIT_LIST_HEAD(&qos_domain->nodes);

	return qos_domain;
}

static int esw_qos_domain_init(struct mlx5_eswitch *esw)
{
	esw->qos.domain = esw_qos_domain_alloc();

	return esw->qos.domain ? 0 : -ENOMEM;
}

static void esw_qos_domain_release(struct mlx5_eswitch *esw)
{
	kfree(esw->qos.domain);
	esw->qos.domain = NULL;
}

enum sched_node_type {
	SCHED_NODE_TYPE_VPORTS_TSAR,
	SCHED_NODE_TYPE_VPORT,
};

static const char * const sched_node_type_str[] = {
	[SCHED_NODE_TYPE_VPORTS_TSAR] = "vports TSAR",
	[SCHED_NODE_TYPE_VPORT] = "vport",
};

struct mlx5_esw_sched_node {
	u32 ix;
	/* Bandwidth parameters. */
	u32 max_rate;
	u32 min_rate;
	/* A computed value indicating relative min_rate between node's children. */
	u32 bw_share;
	/* The parent node in the rate hierarchy. */
	struct mlx5_esw_sched_node *parent;
	/* Entry in the parent node's children list. */
	struct list_head entry;
	/* The type of this node in the rate hierarchy. */
	enum sched_node_type type;
	/* The eswitch this node belongs to. */
	struct mlx5_eswitch *esw;
	/* The children nodes of this node, empty list for leaf nodes. */
	struct list_head children;
	/* Valid only if this node is associated with a vport. */
	struct mlx5_vport *vport;
};

static void
esw_qos_node_set_parent(struct mlx5_esw_sched_node *node, struct mlx5_esw_sched_node *parent)
{
	list_del_init(&node->entry);
	node->parent = parent;
	list_add_tail(&node->entry, &parent->children);
	node->esw = parent->esw;
}

u32 mlx5_esw_qos_vport_get_sched_elem_ix(const struct mlx5_vport *vport)
{
	if (!vport->qos.sched_node)
		return 0;

	return vport->qos.sched_node->ix;
}

struct mlx5_esw_sched_node *
mlx5_esw_qos_vport_get_parent(const struct mlx5_vport *vport)
{
	if (!vport->qos.sched_node)
		return NULL;

	return vport->qos.sched_node->parent;
}

static void esw_qos_sched_elem_config_warn(struct mlx5_esw_sched_node *node, int err)
{
	if (node->vport) {
		esw_warn(node->esw->dev,
			 "E-Switch modify %s scheduling element failed (vport=%d,err=%d)\n",
			 sched_node_type_str[node->type], node->vport->vport, err);
		return;
	}

	esw_warn(node->esw->dev,
		 "E-Switch modify %s scheduling element failed (err=%d)\n",
		 sched_node_type_str[node->type], err);
}

static int esw_qos_sched_elem_config(struct mlx5_esw_sched_node *node, u32 max_rate, u32 bw_share,
				     struct netlink_ext_ack *extack)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = node->esw->dev;
	u32 bitmask = 0;
	int err;

	if (!MLX5_CAP_GEN(dev, qos) || !MLX5_CAP_QOS(dev, esw_scheduling))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, sched_ctx, bw_share, bw_share);
	bitmask |= MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_MAX_AVERAGE_BW;
	bitmask |= MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_BW_SHARE;

	err = mlx5_modify_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 sched_ctx,
						 node->ix,
						 bitmask);
	if (err) {
		esw_qos_sched_elem_config_warn(node, err);
		NL_SET_ERR_MSG_MOD(extack, "E-Switch modify scheduling element failed");

		return err;
	}

	if (node->type == SCHED_NODE_TYPE_VPORTS_TSAR)
		trace_mlx5_esw_node_qos_config(dev, node, node->ix, bw_share, max_rate);
	else if (node->type == SCHED_NODE_TYPE_VPORT)
		trace_mlx5_esw_vport_qos_config(dev, node->vport, bw_share, max_rate);

	return 0;
}

static u32 esw_qos_calculate_min_rate_divider(struct mlx5_eswitch *esw,
					      struct mlx5_esw_sched_node *parent)
{
	struct list_head *nodes = parent ? &parent->children : &esw->qos.domain->nodes;
	u32 fw_max_bw_share = MLX5_CAP_QOS(esw->dev, max_tsar_bw_share);
	struct mlx5_esw_sched_node *node;
	u32 max_guarantee = 0;

	/* Find max min_rate across all nodes.
	 * This will correspond to fw_max_bw_share in the final bw_share calculation.
	 */
	list_for_each_entry(node, nodes, entry) {
		if (node->esw == esw && node->ix != esw->qos.root_tsar_ix &&
		    node->min_rate > max_guarantee)
			max_guarantee = node->min_rate;
	}

	if (max_guarantee)
		return max_t(u32, max_guarantee / fw_max_bw_share, 1);

	/* If nodes max min_rate divider is 0 but their parent has bw_share
	 * configured, then set bw_share for nodes to minimal value.
	 */

	if (parent && parent->bw_share)
		return 1;

	/* If the node nodes has min_rate configured, a divider of 0 sets all
	 * nodes' bw_share to 0, effectively disabling min guarantees.
	 */
	return 0;
}

static u32 esw_qos_calc_bw_share(u32 min_rate, u32 divider, u32 fw_max)
{
	if (!divider)
		return 0;
	return min_t(u32, max_t(u32, DIV_ROUND_UP(min_rate, divider), MLX5_MIN_BW_SHARE), fw_max);
}

static int esw_qos_update_sched_node_bw_share(struct mlx5_esw_sched_node *node,
					      u32 divider,
					      struct netlink_ext_ack *extack)
{
	u32 fw_max_bw_share = MLX5_CAP_QOS(node->esw->dev, max_tsar_bw_share);
	u32 bw_share;
	int err;

	bw_share = esw_qos_calc_bw_share(node->min_rate, divider, fw_max_bw_share);

	if (bw_share == node->bw_share)
		return 0;

	err = esw_qos_sched_elem_config(node, node->max_rate, bw_share, extack);
	if (err)
		return err;

	node->bw_share = bw_share;

	return err;
}

static int esw_qos_normalize_min_rate(struct mlx5_eswitch *esw,
				      struct mlx5_esw_sched_node *parent,
				      struct netlink_ext_ack *extack)
{
	struct list_head *nodes = parent ? &parent->children : &esw->qos.domain->nodes;
	u32 divider = esw_qos_calculate_min_rate_divider(esw, parent);
	struct mlx5_esw_sched_node *node;

	list_for_each_entry(node, nodes, entry) {
		int err;

		if (node->esw != esw || node->ix == esw->qos.root_tsar_ix)
			continue;

		err = esw_qos_update_sched_node_bw_share(node, divider, extack);
		if (err)
			return err;

		if (list_empty(&node->children))
			continue;

		err = esw_qos_normalize_min_rate(node->esw, node, extack);
		if (err)
			return err;
	}

	return 0;
}

static int esw_qos_set_vport_min_rate(struct mlx5_vport *vport,
				      u32 min_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	u32 fw_max_bw_share, previous_min_rate;
	bool min_rate_supported;
	int err;

	esw_assert_qos_lock_held(vport_node->esw);
	fw_max_bw_share = MLX5_CAP_QOS(vport->dev, max_tsar_bw_share);
	min_rate_supported = MLX5_CAP_QOS(vport->dev, esw_bw_share) &&
				fw_max_bw_share >= MLX5_MIN_BW_SHARE;
	if (min_rate && !min_rate_supported)
		return -EOPNOTSUPP;
	if (min_rate == vport_node->min_rate)
		return 0;

	previous_min_rate = vport_node->min_rate;
	vport_node->min_rate = min_rate;
	err = esw_qos_normalize_min_rate(vport_node->parent->esw, vport_node->parent, extack);
	if (err)
		vport_node->min_rate = previous_min_rate;

	return err;
}

static int esw_qos_set_vport_max_rate(struct mlx5_vport *vport,
				      u32 max_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	u32 act_max_rate = max_rate;
	bool max_rate_supported;
	int err;

	esw_assert_qos_lock_held(vport_node->esw);
	max_rate_supported = MLX5_CAP_QOS(vport->dev, esw_rate_limit);

	if (max_rate && !max_rate_supported)
		return -EOPNOTSUPP;
	if (max_rate == vport_node->max_rate)
		return 0;

	/* Use parent node limit if new max rate is 0. */
	if (!max_rate)
		act_max_rate = vport_node->parent->max_rate;

	err = esw_qos_sched_elem_config(vport_node, act_max_rate, vport_node->bw_share, extack);
	if (!err)
		vport_node->max_rate = max_rate;

	return err;
}

static int esw_qos_set_node_min_rate(struct mlx5_esw_sched_node *node,
				     u32 min_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;
	u32 previous_min_rate;
	int err;

	if (!MLX5_CAP_QOS(esw->dev, esw_bw_share) ||
	    MLX5_CAP_QOS(esw->dev, max_tsar_bw_share) < MLX5_MIN_BW_SHARE)
		return -EOPNOTSUPP;

	if (min_rate == node->min_rate)
		return 0;

	previous_min_rate = node->min_rate;
	node->min_rate = min_rate;
	err = esw_qos_normalize_min_rate(esw, NULL, extack);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch node min rate setting failed");

		/* Attempt restoring previous configuration */
		node->min_rate = previous_min_rate;
		if (esw_qos_normalize_min_rate(esw, NULL, extack))
			NL_SET_ERR_MSG_MOD(extack, "E-Switch BW share restore failed");
	}

	return err;
}

static int esw_qos_set_node_max_rate(struct mlx5_esw_sched_node *node,
				     u32 max_rate, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node;
	int err;

	if (node->max_rate == max_rate)
		return 0;

	err = esw_qos_sched_elem_config(node, max_rate, node->bw_share, extack);
	if (err)
		return err;

	node->max_rate = max_rate;

	/* Any unlimited vports in the node should be set with the value of the node. */
	list_for_each_entry(vport_node, &node->children, entry) {
		if (vport_node->max_rate)
			continue;

		err = esw_qos_sched_elem_config(vport_node, max_rate, vport_node->bw_share, extack);
		if (err)
			NL_SET_ERR_MSG_MOD(extack,
					   "E-Switch vport implicit rate limit setting failed");
	}

	return err;
}

static int esw_qos_create_node_sched_elem(struct mlx5_core_dev *dev, u32 parent_element_id,
					  u32 *tsar_ix)
{
	u32 tsar_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	void *attr;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR,
					     SCHEDULING_HIERARCHY_E_SWITCH) ||
	    !mlx5_qos_tsar_type_supported(dev,
					  TSAR_ELEMENT_TSAR_TYPE_DWRR,
					  SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, tsar_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_TSAR);
	MLX5_SET(scheduling_context, tsar_ctx, parent_element_id,
		 parent_element_id);
	attr = MLX5_ADDR_OF(scheduling_context, tsar_ctx, element_attributes);
	MLX5_SET(tsar_element, attr, tsar_type, TSAR_ELEMENT_TSAR_TYPE_DWRR);

	return mlx5_create_scheduling_element_cmd(dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  tsar_ctx,
						  tsar_ix);
}

static int
esw_qos_vport_create_sched_element(struct mlx5_vport *vport, struct mlx5_esw_sched_node *parent,
				   u32 max_rate, u32 bw_share, u32 *sched_elem_ix)
{
	u32 sched_ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_core_dev *dev = parent->esw->dev;
	void *attr;
	int err;

	if (!mlx5_qos_element_type_supported(dev,
					     SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT,
					     SCHEDULING_HIERARCHY_E_SWITCH))
		return -EOPNOTSUPP;

	MLX5_SET(scheduling_context, sched_ctx, element_type,
		 SCHEDULING_CONTEXT_ELEMENT_TYPE_VPORT);
	attr = MLX5_ADDR_OF(scheduling_context, sched_ctx, element_attributes);
	MLX5_SET(vport_element, attr, vport_number, vport->vport);
	MLX5_SET(scheduling_context, sched_ctx, parent_element_id, parent->ix);
	MLX5_SET(scheduling_context, sched_ctx, max_average_bw, max_rate);
	MLX5_SET(scheduling_context, sched_ctx, bw_share, bw_share);

	err = mlx5_create_scheduling_element_cmd(dev,
						 SCHEDULING_HIERARCHY_E_SWITCH,
						 sched_ctx,
						 sched_elem_ix);
	if (err) {
		esw_warn(dev,
			 "E-Switch create vport scheduling element failed (vport=%d,err=%d)\n",
			 vport->vport, err);
		return err;
	}

	return 0;
}

static int esw_qos_update_node_scheduling_element(struct mlx5_vport *vport,
						  struct mlx5_esw_sched_node *curr_node,
						  struct mlx5_esw_sched_node *new_node,
						  struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	u32 max_rate;
	int err;

	err = mlx5_destroy_scheduling_element_cmd(curr_node->esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  vport_node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch destroy vport scheduling element failed");
		return err;
	}

	/* Use new node max rate if vport max rate is unlimited. */
	max_rate = vport_node->max_rate ? vport_node->max_rate : new_node->max_rate;
	err = esw_qos_vport_create_sched_element(vport, new_node, max_rate,
						 vport_node->bw_share,
						 &vport_node->ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch vport node set failed.");
		goto err_sched;
	}

	esw_qos_node_set_parent(vport->qos.sched_node, new_node);

	return 0;

err_sched:
	max_rate = vport_node->max_rate ? vport_node->max_rate : curr_node->max_rate;
	if (esw_qos_vport_create_sched_element(vport, curr_node, max_rate,
					       vport_node->bw_share,
					       &vport_node->ix))
		esw_warn(curr_node->esw->dev, "E-Switch vport node restore failed (vport=%d)\n",
			 vport->vport);

	return err;
}

static int esw_qos_vport_update_node(struct mlx5_vport *vport,
				     struct mlx5_esw_sched_node *node,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *vport_node = vport->qos.sched_node;
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *new_node, *curr_node;
	int err;

	esw_assert_qos_lock_held(esw);
	curr_node = vport_node->parent;
	new_node = node ?: esw->qos.node0;
	if (curr_node == new_node)
		return 0;

	err = esw_qos_update_node_scheduling_element(vport, curr_node, new_node, extack);
	if (err)
		return err;

	/* Recalculate bw share weights of old and new nodes */
	if (vport_node->bw_share || new_node->bw_share) {
		esw_qos_normalize_min_rate(curr_node->esw, curr_node, extack);
		esw_qos_normalize_min_rate(new_node->esw, new_node, extack);
	}

	return 0;
}

static struct mlx5_esw_sched_node *
__esw_qos_alloc_node(struct mlx5_eswitch *esw, u32 tsar_ix, enum sched_node_type type,
		     struct mlx5_esw_sched_node *parent)
{
	struct list_head *parent_children;
	struct mlx5_esw_sched_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	node->esw = esw;
	node->ix = tsar_ix;
	node->type = type;
	node->parent = parent;
	INIT_LIST_HEAD(&node->children);
	parent_children = parent ? &parent->children : &esw->qos.domain->nodes;
	list_add_tail(&node->entry, parent_children);

	return node;
}

static void __esw_qos_free_node(struct mlx5_esw_sched_node *node)
{
	list_del(&node->entry);
	kfree(node);
}

static struct mlx5_esw_sched_node *
__esw_qos_create_vports_sched_node(struct mlx5_eswitch *esw, struct mlx5_esw_sched_node *parent,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	u32 tsar_ix;
	int err;

	err = esw_qos_create_node_sched_elem(esw->dev, esw->qos.root_tsar_ix, &tsar_ix);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch create TSAR for node failed");
		return ERR_PTR(err);
	}

	node = __esw_qos_alloc_node(esw, tsar_ix, SCHED_NODE_TYPE_VPORTS_TSAR, parent);
	if (!node) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch alloc node failed");
		err = -ENOMEM;
		goto err_alloc_node;
	}

	err = esw_qos_normalize_min_rate(esw, NULL, extack);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "E-Switch nodes normalization failed");
		goto err_min_rate;
	}
	trace_mlx5_esw_node_qos_create(esw->dev, node, node->ix);

	return node;

err_min_rate:
	__esw_qos_free_node(node);
err_alloc_node:
	if (mlx5_destroy_scheduling_element_cmd(esw->dev,
						SCHEDULING_HIERARCHY_E_SWITCH,
						tsar_ix))
		NL_SET_ERR_MSG_MOD(extack, "E-Switch destroy TSAR for node failed");
	return ERR_PTR(err);
}

static int esw_qos_get(struct mlx5_eswitch *esw, struct netlink_ext_ack *extack);
static void esw_qos_put(struct mlx5_eswitch *esw);

static struct mlx5_esw_sched_node *
esw_qos_create_vports_sched_node(struct mlx5_eswitch *esw, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	int err;

	esw_assert_qos_lock_held(esw);
	if (!MLX5_CAP_QOS(esw->dev, log_esw_max_sched_depth))
		return ERR_PTR(-EOPNOTSUPP);

	err = esw_qos_get(esw, extack);
	if (err)
		return ERR_PTR(err);

	node = __esw_qos_create_vports_sched_node(esw, NULL, extack);
	if (IS_ERR(node))
		esw_qos_put(esw);

	return node;
}

static int __esw_qos_destroy_node(struct mlx5_esw_sched_node *node, struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = node->esw;
	int err;

	trace_mlx5_esw_node_qos_destroy(esw->dev, node, node->ix);

	err = mlx5_destroy_scheduling_element_cmd(esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  node->ix);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "E-Switch destroy TSAR_ID failed");
	__esw_qos_free_node(node);

	err = esw_qos_normalize_min_rate(esw, NULL, extack);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "E-Switch nodes normalization failed");


	return err;
}

static int esw_qos_create(struct mlx5_eswitch *esw, struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = esw->dev;
	int err;

	if (!MLX5_CAP_GEN(dev, qos) || !MLX5_CAP_QOS(dev, esw_scheduling))
		return -EOPNOTSUPP;

	err = esw_qos_create_node_sched_elem(esw->dev, 0, &esw->qos.root_tsar_ix);
	if (err) {
		esw_warn(dev, "E-Switch create root TSAR failed (%d)\n", err);
		return err;
	}

	if (MLX5_CAP_QOS(dev, log_esw_max_sched_depth)) {
		esw->qos.node0 = __esw_qos_create_vports_sched_node(esw, NULL, extack);
	} else {
		/* The eswitch doesn't support scheduling nodes.
		 * Create a software-only node0 using the root TSAR to attach vport QoS to.
		 */
		if (!__esw_qos_alloc_node(esw,
					  esw->qos.root_tsar_ix,
					  SCHED_NODE_TYPE_VPORTS_TSAR,
					  NULL))
			esw->qos.node0 = ERR_PTR(-ENOMEM);
	}
	if (IS_ERR(esw->qos.node0)) {
		err = PTR_ERR(esw->qos.node0);
		esw_warn(dev, "E-Switch create rate node 0 failed (%d)\n", err);
		goto err_node0;
	}
	refcount_set(&esw->qos.refcnt, 1);

	return 0;

err_node0:
	if (mlx5_destroy_scheduling_element_cmd(esw->dev, SCHEDULING_HIERARCHY_E_SWITCH,
						esw->qos.root_tsar_ix))
		esw_warn(esw->dev, "E-Switch destroy root TSAR failed.\n");

	return err;
}

static void esw_qos_destroy(struct mlx5_eswitch *esw)
{
	int err;

	if (esw->qos.node0->ix != esw->qos.root_tsar_ix)
		__esw_qos_destroy_node(esw->qos.node0, NULL);
	else
		__esw_qos_free_node(esw->qos.node0);
	esw->qos.node0 = NULL;

	err = mlx5_destroy_scheduling_element_cmd(esw->dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  esw->qos.root_tsar_ix);
	if (err)
		esw_warn(esw->dev, "E-Switch destroy root TSAR failed (%d)\n", err);
}

static int esw_qos_get(struct mlx5_eswitch *esw, struct netlink_ext_ack *extack)
{
	int err = 0;

	esw_assert_qos_lock_held(esw);
	if (!refcount_inc_not_zero(&esw->qos.refcnt)) {
		/* esw_qos_create() set refcount to 1 only on success.
		 * No need to decrement on failure.
		 */
		err = esw_qos_create(esw, extack);
	}

	return err;
}

static void esw_qos_put(struct mlx5_eswitch *esw)
{
	esw_assert_qos_lock_held(esw);
	if (refcount_dec_and_test(&esw->qos.refcnt))
		esw_qos_destroy(esw);
}

static int esw_qos_vport_enable(struct mlx5_vport *vport,
				u32 max_rate, u32 bw_share, struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	u32 sched_elem_ix;
	int err;

	esw_assert_qos_lock_held(esw);
	if (vport->qos.sched_node)
		return 0;

	err = esw_qos_get(esw, extack);
	if (err)
		return err;

	err = esw_qos_vport_create_sched_element(vport, esw->qos.node0, max_rate, bw_share,
						 &sched_elem_ix);
	if (err)
		goto err_out;

	vport->qos.sched_node = __esw_qos_alloc_node(esw, sched_elem_ix, SCHED_NODE_TYPE_VPORT,
						     esw->qos.node0);
	if (!vport->qos.sched_node) {
		err = -ENOMEM;
		goto err_alloc;
	}

	vport->qos.sched_node->vport = vport;

	trace_mlx5_esw_vport_qos_create(vport->dev, vport, bw_share, max_rate);

	return 0;

err_alloc:
	if (mlx5_destroy_scheduling_element_cmd(esw->dev,
						SCHEDULING_HIERARCHY_E_SWITCH, sched_elem_ix))
		esw_warn(esw->dev, "E-Switch destroy vport scheduling element failed.\n");
err_out:
	esw_qos_put(esw);

	return err;
}

void mlx5_esw_qos_vport_disable(struct mlx5_vport *vport)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	struct mlx5_esw_sched_node *vport_node;
	struct mlx5_core_dev *dev;
	int err;

	lockdep_assert_held(&esw->state_lock);
	esw_qos_lock(esw);
	vport_node = vport->qos.sched_node;
	if (!vport_node)
		goto unlock;
	WARN(vport_node->parent != esw->qos.node0,
	     "Disabling QoS on port before detaching it from node");

	dev = vport_node->esw->dev;
	trace_mlx5_esw_vport_qos_destroy(dev, vport);

	err = mlx5_destroy_scheduling_element_cmd(dev,
						  SCHEDULING_HIERARCHY_E_SWITCH,
						  vport_node->ix);
	if (err)
		esw_warn(dev,
			 "E-Switch destroy vport scheduling element failed (vport=%d,err=%d)\n",
			 vport->vport, err);

	__esw_qos_free_node(vport_node);
	memset(&vport->qos, 0, sizeof(vport->qos));

	esw_qos_put(esw);
unlock:
	esw_qos_unlock(esw);
}

int mlx5_esw_qos_set_vport_rate(struct mlx5_vport *vport, u32 max_rate, u32 min_rate)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	int err;

	esw_qos_lock(esw);
	err = esw_qos_vport_enable(vport, 0, 0, NULL);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_min_rate(vport, min_rate, NULL);
	if (!err)
		err = esw_qos_set_vport_max_rate(vport, max_rate, NULL);
unlock:
	esw_qos_unlock(esw);
	return err;
}

bool mlx5_esw_qos_get_vport_rate(struct mlx5_vport *vport, u32 *max_rate, u32 *min_rate)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	bool enabled;

	esw_qos_lock(esw);
	enabled = !!vport->qos.sched_node;
	if (enabled) {
		*max_rate = vport->qos.sched_node->max_rate;
		*min_rate = vport->qos.sched_node->min_rate;
	}
	esw_qos_unlock(esw);
	return enabled;
}

static u32 mlx5_esw_qos_lag_link_speed_get_locked(struct mlx5_core_dev *mdev)
{
	struct ethtool_link_ksettings lksettings;
	struct net_device *slave, *master;
	u32 speed = SPEED_UNKNOWN;

	/* Lock ensures a stable reference to master and slave netdevice
	 * while port speed of master is queried.
	 */
	ASSERT_RTNL();

	slave = mlx5_uplink_netdev_get(mdev);
	if (!slave)
		goto out;

	master = netdev_master_upper_dev_get(slave);
	if (master && !__ethtool_get_link_ksettings(master, &lksettings))
		speed = lksettings.base.speed;

out:
	return speed;
}

static int mlx5_esw_qos_max_link_speed_get(struct mlx5_core_dev *mdev, u32 *link_speed_max,
					   bool hold_rtnl_lock, struct netlink_ext_ack *extack)
{
	int err;

	if (!mlx5_lag_is_active(mdev))
		goto skip_lag;

	if (hold_rtnl_lock)
		rtnl_lock();

	*link_speed_max = mlx5_esw_qos_lag_link_speed_get_locked(mdev);

	if (hold_rtnl_lock)
		rtnl_unlock();

	if (*link_speed_max != (u32)SPEED_UNKNOWN)
		return 0;

skip_lag:
	err = mlx5_port_max_linkspeed(mdev, link_speed_max);
	if (err)
		NL_SET_ERR_MSG_MOD(extack, "Failed to get link maximum speed");

	return err;
}

static int mlx5_esw_qos_link_speed_verify(struct mlx5_core_dev *mdev,
					  const char *name, u32 link_speed_max,
					  u64 value, struct netlink_ext_ack *extack)
{
	if (value > link_speed_max) {
		pr_err("%s rate value %lluMbps exceed link maximum speed %u.\n",
		       name, value, link_speed_max);
		NL_SET_ERR_MSG_MOD(extack, "TX rate value exceed link maximum speed");
		return -EINVAL;
	}

	return 0;
}

int mlx5_esw_qos_modify_vport_rate(struct mlx5_eswitch *esw, u16 vport_num, u32 rate_mbps)
{
	u32 ctx[MLX5_ST_SZ_DW(scheduling_context)] = {};
	struct mlx5_vport *vport;
	u32 link_speed_max;
	u32 bitmask;
	int err;

	vport = mlx5_eswitch_get_vport(esw, vport_num);
	if (IS_ERR(vport))
		return PTR_ERR(vport);

	if (rate_mbps) {
		err = mlx5_esw_qos_max_link_speed_get(esw->dev, &link_speed_max, false, NULL);
		if (err)
			return err;

		err = mlx5_esw_qos_link_speed_verify(esw->dev, "Police",
						     link_speed_max, rate_mbps, NULL);
		if (err)
			return err;
	}

	esw_qos_lock(esw);
	if (!vport->qos.sched_node) {
		/* Eswitch QoS wasn't enabled yet. Enable it and vport QoS. */
		err = esw_qos_vport_enable(vport, rate_mbps, 0, NULL);
	} else {
		struct mlx5_core_dev *dev = vport->qos.sched_node->parent->esw->dev;

		MLX5_SET(scheduling_context, ctx, max_average_bw, rate_mbps);
		bitmask = MODIFY_SCHEDULING_ELEMENT_IN_MODIFY_BITMASK_MAX_AVERAGE_BW;
		err = mlx5_modify_scheduling_element_cmd(dev,
							 SCHEDULING_HIERARCHY_E_SWITCH,
							 ctx,
							 vport->qos.sched_node->ix,
							 bitmask);
	}
	esw_qos_unlock(esw);

	return err;
}

#define MLX5_LINKSPEED_UNIT 125000 /* 1Mbps in Bps */

/* Converts bytes per second value passed in a pointer into megabits per
 * second, rewriting last. If converted rate exceed link speed or is not a
 * fraction of Mbps - returns error.
 */
static int esw_qos_devlink_rate_to_mbps(struct mlx5_core_dev *mdev, const char *name,
					u64 *rate, struct netlink_ext_ack *extack)
{
	u32 link_speed_max, remainder;
	u64 value;
	int err;

	value = div_u64_rem(*rate, MLX5_LINKSPEED_UNIT, &remainder);
	if (remainder) {
		pr_err("%s rate value %lluBps not in link speed units of 1Mbps.\n",
		       name, *rate);
		NL_SET_ERR_MSG_MOD(extack, "TX rate value not in link speed units of 1Mbps");
		return -EINVAL;
	}

	err = mlx5_esw_qos_max_link_speed_get(mdev, &link_speed_max, true, extack);
	if (err)
		return err;

	err = mlx5_esw_qos_link_speed_verify(mdev, name, link_speed_max, value, extack);
	if (err)
		return err;

	*rate = value;
	return 0;
}

int mlx5_esw_qos_init(struct mlx5_eswitch *esw)
{
	return esw_qos_domain_init(esw);
}

void mlx5_esw_qos_cleanup(struct mlx5_eswitch *esw)
{
	if (esw->qos.domain)
		esw_qos_domain_release(esw);
}

/* Eswitch devlink rate API */

int mlx5_esw_devlink_rate_leaf_tx_share_set(struct devlink_rate *rate_leaf, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport = priv;
	struct mlx5_eswitch *esw;
	int err;

	esw = vport->dev->priv.eswitch;
	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	err = esw_qos_devlink_rate_to_mbps(vport->dev, "tx_share", &tx_share, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_min_rate(vport, tx_share, extack);
unlock:
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_leaf_tx_max_set(struct devlink_rate *rate_leaf, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
	struct mlx5_vport *vport = priv;
	struct mlx5_eswitch *esw;
	int err;

	esw = vport->dev->priv.eswitch;
	if (!mlx5_esw_allowed(esw))
		return -EPERM;

	err = esw_qos_devlink_rate_to_mbps(vport->dev, "tx_max", &tx_max, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (err)
		goto unlock;

	err = esw_qos_set_vport_max_rate(vport, tx_max, extack);
unlock:
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_node_tx_share_set(struct devlink_rate *rate_node, void *priv,
					    u64 tx_share, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv;
	struct mlx5_eswitch *esw = node->esw;
	int err;

	err = esw_qos_devlink_rate_to_mbps(esw->dev, "tx_share", &tx_share, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = esw_qos_set_node_min_rate(node, tx_share, extack);
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_node_tx_max_set(struct devlink_rate *rate_node, void *priv,
					  u64 tx_max, struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv;
	struct mlx5_eswitch *esw = node->esw;
	int err;

	err = esw_qos_devlink_rate_to_mbps(esw->dev, "tx_max", &tx_max, extack);
	if (err)
		return err;

	esw_qos_lock(esw);
	err = esw_qos_set_node_max_rate(node, tx_max, extack);
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_node_new(struct devlink_rate *rate_node, void **priv,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	struct mlx5_eswitch *esw;
	int err = 0;

	esw = mlx5_devlink_eswitch_get(rate_node->devlink);
	if (IS_ERR(esw))
		return PTR_ERR(esw);

	esw_qos_lock(esw);
	if (esw->mode != MLX5_ESWITCH_OFFLOADS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Rate node creation supported only in switchdev mode");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	node = esw_qos_create_vports_sched_node(esw, extack);
	if (IS_ERR(node)) {
		err = PTR_ERR(node);
		goto unlock;
	}

	*priv = node;
unlock:
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_node_del(struct devlink_rate *rate_node, void *priv,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node = priv;
	struct mlx5_eswitch *esw = node->esw;
	int err;

	esw_qos_lock(esw);
	err = __esw_qos_destroy_node(node, extack);
	esw_qos_put(esw);
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_qos_vport_update_node(struct mlx5_vport *vport,
				   struct mlx5_esw_sched_node *node,
				   struct netlink_ext_ack *extack)
{
	struct mlx5_eswitch *esw = vport->dev->priv.eswitch;
	int err = 0;

	if (node && node->esw != esw) {
		NL_SET_ERR_MSG_MOD(extack, "Cross E-Switch scheduling is not supported");
		return -EOPNOTSUPP;
	}

	esw_qos_lock(esw);
	if (!vport->qos.sched_node && !node)
		goto unlock;

	err = esw_qos_vport_enable(vport, 0, 0, extack);
	if (!err)
		err = esw_qos_vport_update_node(vport, node, extack);
unlock:
	esw_qos_unlock(esw);
	return err;
}

int mlx5_esw_devlink_rate_parent_set(struct devlink_rate *devlink_rate,
				     struct devlink_rate *parent,
				     void *priv, void *parent_priv,
				     struct netlink_ext_ack *extack)
{
	struct mlx5_esw_sched_node *node;
	struct mlx5_vport *vport = priv;

	if (!parent)
		return mlx5_esw_qos_vport_update_node(vport, NULL, extack);

	node = parent_priv;
	return mlx5_esw_qos_vport_update_node(vport, node, extack);
}
