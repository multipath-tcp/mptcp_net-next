// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <net/devlink.h>

#include "devl_internal.h"

static LIST_HEAD(shd_list);
static DEFINE_MUTEX(shd_mutex); /* Protects shd_list and shd->list */

/* This structure represents a shared devlink instance,
 * there is one created per identifier (e.g., serial number).
 */
struct devlink_shd {
	struct list_head list; /* Node in shd list */
	const char *id; /* Identifier string (e.g., serial number) */
	refcount_t refcount; /* Reference count */
	size_t priv_size; /* Size of driver private data */
	char priv[] __aligned(NETDEV_ALIGN) __counted_by(priv_size);
};

static struct devlink_shd *devlink_shd_lookup(const char *id)
{
	struct devlink_shd *shd;

	list_for_each_entry(shd, &shd_list, list) {
		if (!strcmp(shd->id, id))
			return shd;
	}

	return NULL;
}

static struct devlink_shd *devlink_shd_create(const char *id,
					      const struct devlink_ops *ops,
					      size_t priv_size,
					      void *init_param,
					      const struct device_driver *driver)
{
	struct devlink_shd *shd;
	struct devlink *devlink;
	int err;

	devlink = __devlink_alloc(ops, sizeof(struct devlink_shd) + priv_size,
				  &init_net, NULL, driver);
	if (!devlink)
		return ERR_PTR(-ENOMEM);
	shd = devlink_priv(devlink);

	shd->id = kstrdup(id, GFP_KERNEL);
	if (!shd->id) {
		err = -ENOMEM;
		goto err_devlink_free;
	}
	shd->priv_size = priv_size;

	devl_lock(devlink);

	if (ops->shd_init) {
		err = ops->shd_init(shd->priv, init_param);
		if (err)
			goto err_unlock;
	}
	devl_register(devlink);
	devl_unlock(devlink);

	refcount_set(&shd->refcount, 1);
	list_add_tail(&shd->list, &shd_list);

	return shd;

err_unlock:
	devl_unlock(devlink);
	kfree(shd->id);

err_devlink_free:
	devlink_free(devlink);
	return ERR_PTR(err);
}

static void devlink_shd_destroy(struct devlink_shd *shd)
{
	struct devlink *devlink = priv_to_devlink(shd);

	list_del(&shd->list);
	devl_lock(devlink);
	devl_unregister(devlink);

	if (devlink->ops->shd_fini)
		devlink->ops->shd_fini(shd->priv);

	devl_unlock(devlink);
	kfree(shd->id);
	devlink_free(devlink);
}

/**
 * devlink_shd_get - Get or create a shared devlink instance
 * @id: Identifier string (e.g., serial number) for the shared instance
 * @ops: Devlink operations structure
 * @priv_size: Size of private data structure
 * @init_param: Passed to .shd_init() callback alongside driver's priv;
 *              this value need not match across all users of the shared
 *              instance
 * @driver: Driver associated with the shared devlink instance
 *
 * Get an existing shared devlink instance identified by @id, or create
 * a new one if it doesn't exist. Return the devlink instance with a
 * reference held. The caller must call devlink_shd_put() when done.
 *
 * On creation, @ops->shd_init() is called (if set), see its description
 * for the calling context. Its error is returned to the caller.
 *
 * All callers sharing the same @id must pass identical @ops, @priv_size
 * and @driver. A mismatch triggers a warning and returns ERR_PTR(-EINVAL).
 *
 * Return: Pointer to the shared devlink instance on success,
 *         ERR_PTR() on failure
 */
struct devlink *devlink_shd_get(const char *id,
				const struct devlink_ops *ops,
				size_t priv_size,
				void *init_param,
				const struct device_driver *driver)
{
	struct devlink *devlink;
	struct devlink_shd *shd;

	mutex_lock(&shd_mutex);

	shd = devlink_shd_lookup(id);
	if (!shd) {
		shd = devlink_shd_create(id, ops, priv_size, init_param, driver);
		goto unlock;
	}

	devlink = priv_to_devlink(shd);
	if (WARN_ON_ONCE(devlink->ops != ops ||
			 shd->priv_size != priv_size ||
			 devlink->dev_driver != driver)) {
		shd = ERR_PTR(-EINVAL);
		goto unlock;
	}
	refcount_inc(&shd->refcount);

unlock:
	mutex_unlock(&shd_mutex);
	return IS_ERR(shd) ? ERR_CAST(shd) : priv_to_devlink(shd);
}
EXPORT_SYMBOL_GPL(devlink_shd_get);

/**
 * devlink_shd_put - Release a reference on a shared devlink instance
 * @devlink: Shared devlink instance
 *
 * Release a reference on a shared devlink instance obtained via
 * devlink_shd_get().
 */
void devlink_shd_put(struct devlink *devlink)
{
	struct devlink_shd *shd;

	mutex_lock(&shd_mutex);
	shd = devlink_priv(devlink);
	if (refcount_dec_and_test(&shd->refcount))
		devlink_shd_destroy(shd);
	mutex_unlock(&shd_mutex);
}
EXPORT_SYMBOL_GPL(devlink_shd_put);

/**
 * devlink_shd_get_priv - Get private data from shared devlink instance
 * @devlink: Devlink instance
 *
 * Returns a pointer to the driver's private data structure within
 * the shared devlink instance.
 *
 * Return: Pointer to private data
 */
void *devlink_shd_get_priv(struct devlink *devlink)
{
	struct devlink_shd *shd = devlink_priv(devlink);

	return shd->priv;
}
EXPORT_SYMBOL_GPL(devlink_shd_get_priv);

/**
 * shd_priv_to_devlink - Get shared devlink instance from its priv data
 * @priv: Driver's priv data, as returned by devlink_shd_get_priv()
 *
 * Return: pointer to shared devlink instance the @priv belongs to.
 */
struct devlink *shd_priv_to_devlink(void *priv)
{
	struct devlink_shd *shd = container_of(priv, struct devlink_shd, priv);

	return priv_to_devlink(shd);
}
EXPORT_SYMBOL_GPL(shd_priv_to_devlink);
