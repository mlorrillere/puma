/*
 *	policy.c
 *
 *	Copyright (C) 2014
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

/*
 * Inspired by dm-cache-policy
 */

#include <linux/spinlock.h>
#include <linux/module.h>

#include "policy.h"

static DEFINE_SPINLOCK(register_lock);
static LIST_HEAD(register_list);

static struct remotecache_policy_type *__find_policy(const char *name)
{
	struct remotecache_policy_type *t;

	list_for_each_entry(t, &register_list, list)
		if (!strcmp(t->name, name))
			return t;

	return NULL;
}

static struct remotecache_policy_type *__get_policy_once(const char *name)
{
	struct remotecache_policy_type *t = __find_policy(name);

	if (t && !try_module_get(t->owner)) {
		pr_warn("couldn't get module %s", name);
		t = ERR_PTR(-EINVAL);
	}

	return t;
}

static struct remotecache_policy_type *get_policy_once(const char *name)
{
	struct remotecache_policy_type *t;

	spin_lock(&register_lock);
	t = __get_policy_once(name);
	spin_unlock(&register_lock);

	return t;
}

static struct remotecache_policy_type *get_policy(const char *name)
{
	struct remotecache_policy_type *t;

	t = get_policy_once(name);
	if (IS_ERR(t))
		return NULL;

	if (t)
		return t;

	/*
	 * If policy not found, try to load corresponding module
	 */
	request_module("remotecache-policy-%s", name);

	t = get_policy_once(name);
	if (IS_ERR(t))
		return NULL;

	return t;
}

static void put_policy(struct remotecache_policy_type *t)
{
	module_put(t->owner);
}

int remotecache_policy_register(struct remotecache_policy_type *type)
{
	int r;

	spin_lock(&register_lock);
	if (__find_policy(type->name)) {
		pr_warn("attempt to register policy under duplicate name %s", type->name);
		r = -EINVAL;
	} else {
		list_add(&type->list, &register_list);
		r = 0;
	}
	spin_unlock(&register_lock);

	return r;
}
EXPORT_SYMBOL_GPL(remotecache_policy_register);

void remotecache_policy_unregister(struct remotecache_policy_type *type)
{
	spin_lock(&register_lock);
	list_del_init(&type->list);
	spin_unlock(&register_lock);
}
EXPORT_SYMBOL_GPL(remotecache_policy_unregister);

struct remotecache_policy *remotecache_policy_create(const char *name)
{
	struct remotecache_policy *p = NULL;
	struct remotecache_policy_type *type;

	type = get_policy(name);
	if (!type) {
		pr_warn("unknown policy type");
		return NULL;
	}

	p = type->create();
	if (!p) {
		put_policy(type);
		return NULL;
	}
	p->private = type;

	return p;
}
EXPORT_SYMBOL_GPL(remotecache_policy_create);

void remotecache_policy_destroy(struct remotecache_policy *p)
{
	struct remotecache_policy_type *t = p->private;

	p->destroy(p);
	put_policy(t);
}
EXPORT_SYMBOL_GPL(remotecache_policy_destroy);

const char *remotecache_policy_get_name(struct remotecache_policy *p)
{
	struct remotecache_policy_type *t = p->private;

	return t->name;
}
EXPORT_SYMBOL_GPL(remotecache_policy_get_name);
