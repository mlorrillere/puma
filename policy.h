/*
 *	policy.h
 *
 *	Copyright (C) 2014
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef REMOTECACHE_POLICY_H
#define REMOTECACHE_POLICY_H

#include <linux/list.h>

struct remotecache;
struct remotecache_page;

/*
 * Cache replacement policy
 */
struct remotecache_policy {
	/*
	 * Mark a page as referenced
	 */
	void (*referenced) (struct remotecache *cache,
			struct remotecache_page *page);

	/*
	 * Remove a single page from the page replacement algorithm. This is
	 * called for exemple when a page is removed from the cache after
	 * being invalidated.
	 */
	void (*remove) (struct remotecache *cache,
			struct remotecache_page	*page);

	/*
	 * Reclaim a batch of pages.
	 */
	int (*reclaim) (struct remotecache *cache, struct list_head *dst,
			int nr_to_scan);

	/*
	 * Destroy this object
	 */
	void (*destroy) (struct remotecache_policy *policy);

	/*
	 * Private pointer to be used by the policy
	 */
	void *private;
};

#define REMOTECACHE_POLICY_NAME_SIZE 16
struct remotecache_policy_type {
	struct list_head list;

	/*
	 * Policy name to be used when choosing a cache replacement policy
	 */
	char name[REMOTECACHE_POLICY_NAME_SIZE];

	struct module *owner;

	struct remotecache_policy *(*create)(void);
};

struct remotecache_policy *remotecache_policy_create(const char *name);
void remotecache_policy_destroy(struct remotecache_policy *p);
const char *remotecache_policy_get_name(struct remotecache_policy *p);
int remotecache_policy_register(struct remotecache_policy_type *type);
void remotecache_policy_unregister(struct remotecache_policy_type *type);
#endif
