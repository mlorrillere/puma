/*
 *	policy.c
 *
 *	Copyright (C) 2014
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */
/*
 * Default policy: simple LRU
 */

#include <linux/module.h>
#include <linux/slab.h>

#include "metadata.h"
#include "policy.h"

struct lru_policy {
	struct remotecache_policy policy;
	struct list_head lru;
};

static struct lru_policy *to_lru_policy(struct remotecache_policy *p)
{
	return container_of(p, struct lru_policy, policy);
}

static void lru_policy_referenced(struct remotecache_metadata *cache,
		struct remotecache_page_metadata *page) {
	struct lru_policy *policy = to_lru_policy(cache->policy);
	if (list_empty(&page->lru)) {
		BUG_ON(test_and_set_bit(RC_PAGE_LRU, &page->flags));
		remotecache_page_metadata_get(page);
		list_add(&page->lru, &policy->lru);
	} else {
		BUG_ON(!test_bit(RC_PAGE_LRU, &page->flags));
		list_move(&page->lru, &policy->lru);
	}
}

static void lru_policy_remove(struct remotecache_metadata *cache,
		struct remotecache_page_metadata *page)
{
	list_del_init(&page->lru);
	remotecache_page_metadata_put(page);
}


static int lru_policy_reclaim(struct remotecache_metadata *cache,
		struct list_head *dst, int nr_to_scan) {
	struct lru_policy *policy = to_lru_policy(cache->policy);
	int nr_taken = 0, scan;

	for (scan = 0; scan < nr_to_scan && !list_empty(&policy->lru); scan++) {
		struct remotecache_page_metadata *page = list_entry(policy->lru.prev,
				struct remotecache_page_metadata, lru);

		/*
		 * xxx: testing bit is not enough, we have to lock the page
		 * (but we don't have the code to do that yet...)
		 */
		if (!test_bit(RC_PAGE_LOCKED, &page->flags)) {
			BUG_ON(!test_and_clear_bit(RC_PAGE_LRU,	&page->flags));
			list_move(&page->lru, dst);

			/*
			 * drop lru ref
			 */
			remotecache_page_metadata_put(page);
			nr_taken++;
		}
	}

	return nr_taken;
}

static void lru_policy_destroy(struct remotecache_policy *p) {
	struct lru_policy *lru_policy = to_lru_policy(p);

	WARN_ON(!list_empty(&lru_policy->lru));
}

static struct remotecache_policy *lru_create(void)
{
	struct lru_policy *lru = kzalloc(sizeof(*lru), GFP_KERNEL);

	if (!lru)
		return NULL;

	lru->policy.referenced = lru_policy_referenced;
	lru->policy.remove = lru_policy_remove;
	lru->policy.reclaim = lru_policy_reclaim;
	lru->policy.destroy = lru_policy_destroy;
	INIT_LIST_HEAD(&lru->lru);

	return &lru->policy;
}
static struct remotecache_policy_type lru_policy_type = {
	.name = "lru",
	.owner = THIS_MODULE,
	.create = lru_create
};

static int __init lru_init(void)
{
	int r;

	r = remotecache_policy_register(&lru_policy_type);
	if (!r) {
		return 0;
	}

	pr_err("register failed %d", r);
	return -ENOMEM;
}

static void __exit lru_exit(void)
{
	remotecache_policy_unregister(&lru_policy_type);
}

module_init(lru_init);
module_exit(lru_exit);

MODULE_AUTHOR("Maxime Lorrillere <maxime.lorrillere@lip6.fr>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lru cache policy for remotecache_metadata");
