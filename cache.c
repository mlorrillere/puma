/*
 *	cache.c
 *
 *	Copyright (C) 2013
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#include <linux/export.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/bug.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "cache.h"
#include "remotecache.h"

static mempool_t *remotecache_page_pool = NULL;
static struct kmem_cache *remotecache_page_cachep = NULL;

static inline int remotecache_page_cmp(ino_t lhs_ino, pgoff_t lhs_index,
		ino_t rhs_ino, pgoff_t rhs_index)
{
	int r = lhs_ino - rhs_ino;
	if (r)
		return r;
	return lhs_index - rhs_index;
}

static inline int remotecache_inode_cmp(ino_t lhs_ino, pgoff_t lhs_index,
		ino_t rhs_ino, pgoff_t rhs_index)
{
	return lhs_ino - rhs_ino;
}

static struct remotecache_page *do_remotecache_lookup(struct remotecache *cache,
		ino_t ino, pgoff_t index,
		int (*cmp_fn)(ino_t, pgoff_t, ino_t, pgoff_t))
{
	struct rb_node *n = cache->pages_tree.rb_node;
	struct remotecache_page *rcp = NULL;

	while (n) {
		int cmp;
		rcp = rb_entry(n, struct remotecache_page, rb_node);

		cmp = cmp_fn(ino, index, rcp->ino, rcp->index);

		if (cmp < 0) {
			n = n->rb_left;
		} else if (cmp > 0) {
			n = n->rb_right;
		} else {
			remotecache_page_get(rcp);
			return rcp;
		}
	}
	return NULL;
}

struct remotecache_page *__remotecache_lookup(struct remotecache *cache,
		ino_t ino, pgoff_t index)
{
	rc_debug("%s: lookup for remotecache page ino=%lu, index=%lu "
			"in cache %p \n", __func__, ino, index, cache);
	return do_remotecache_lookup(cache, ino, index, remotecache_page_cmp);
}
EXPORT_SYMBOL(__remotecache_lookup);

struct remotecache_page *__remotecache_lookup_inode(struct remotecache *cache,
		ino_t ino)
{
	return do_remotecache_lookup(cache, ino, 0, remotecache_inode_cmp);
}
EXPORT_SYMBOL(__remotecache_lookup_inode);

void __remotecache_remove_page_list(struct remotecache *cache,
		struct list_head *free_pages)
{
	struct remotecache_page *page, *next;

	rc_debug("%s: removing remotecache pages", __func__);

	list_for_each_entry_safe(page, next, free_pages, lru) {
		rb_erase(&page->rb_node, &cache->pages_tree);
		RB_CLEAR_NODE(&page->rb_node);

		/*
		 * Pages where removed from the LRU by
		 * policy->reclaim
		 */
		INIT_LIST_HEAD(&page->lru);

		remotecache_page_put(page);
	}
}
EXPORT_SYMBOL(__remotecache_remove_page_list);

static unsigned long shrinker_count_objects(struct shrinker *shrinker,
		struct shrink_control *sc) {
	struct remotecache *cache =
		container_of(shrinker, struct remotecache, shrinker);

	if (!cache->evict)
		return 0;

	return (unsigned long) atomic_read(&cache->size);
}

static unsigned long shrinker_scan_objects(struct shrinker *shrinker, struct shrink_control *sc)
{
	int nr_removed = 0;
	struct remotecache *cache =
		container_of(shrinker, struct remotecache, shrinker);

	if (!cache->evict)
		return SHRINK_STOP;

	if (sc->nr_to_scan) {
		unsigned long flags;
		LIST_HEAD(free_pages);

		spin_lock_irqsave(&cache->lock, flags);
		cache->policy->reclaim(cache, &free_pages, sc->nr_to_scan);

		nr_removed = cache->evict(cache, &free_pages);
		__remotecache_remove_page_list(cache, &free_pages);
		atomic_sub(nr_removed, &cache->size);
		spin_unlock_irqrestore(&cache->lock, flags);
	}

	return nr_removed;
}

static struct remotecache_page *do_remotecache_insert(struct remotecache *cache,
		struct remotecache_page *new)
{
	struct remotecache_page *rcp;
	struct rb_node **p = &cache->pages_tree.rb_node;
	struct rb_node *parent = NULL;

	while (*p) {
		int keycmp;
		parent = *p;
		rcp = rb_entry(parent, struct remotecache_page, rb_node);

		keycmp = remotecache_page_cmp(new->ino, new->index,
				rcp->ino, rcp->index);
		if (keycmp < 0)
			p = &(*p)->rb_left;
		else if (keycmp > 0)
			p = &(*p)->rb_right;
		else
			return rcp;
	}

	rb_link_node(&new->rb_node, parent, p);
	return NULL;
}

struct remotecache_page *__remotecache_insert(struct remotecache *cache,
		struct remotecache_page *new)
{
	struct remotecache_page *rcp;

	rc_debug("%s: insert page %p (ino=%lu, index=%lu) into cache %p",
			__func__, new, new->ino, new->index, cache);

	BUG_ON(!RB_EMPTY_NODE(&new->rb_node));
	BUG_ON(!list_empty(&new->lru));

	rcp = do_remotecache_insert(cache, new);

	if (!rcp) {
		rb_insert_color(&new->rb_node, &cache->pages_tree);
		atomic_inc(&cache->size);
		remotecache_page_get(new);
		new->cache = cache;

		cache->policy->referenced(cache, new);
	} else {
		remotecache_page_get(rcp);
	}
	return rcp;
}
EXPORT_SYMBOL(__remotecache_insert);

void __remotecache_remove(struct remotecache *cache,
		struct remotecache_page *page)
{
	if (RB_EMPTY_NODE(&page->rb_node))
		return;

	rc_debug("%s: page %p ino %lu index %lu cache %pUl\n",
			__func__, page, page->ino, page->index, &cache->uuid);

	rb_erase(&page->rb_node, &cache->pages_tree);
	RB_CLEAR_NODE(&page->rb_node);

	if (test_and_clear_bit(RC_PAGE_LRU, &page->flags))
		cache->policy->remove(cache, page);

	BUG_ON(atomic_sub_return(1, &cache->size) < 0);
	remotecache_page_put(page);
}
EXPORT_SYMBOL(__remotecache_remove);

bool remotecache_erase(struct remotecache *cache, ino_t ino, pgoff_t index)
{
	bool erased;
	spin_lock(&cache->lock);
	erased = __remotecache_erase(cache, ino, index);
	spin_unlock(&cache->lock);
	return erased;
}
EXPORT_SYMBOL(remotecache_erase);

bool __remotecache_erase(struct remotecache *cache, ino_t ino, pgoff_t index)
{
	struct remotecache_page *p = NULL;

	rc_debug("%s: erase remotecache page ino=%lu, index=%lu from cache %p\n",
			__func__, ino, index, cache);

	p = __remotecache_lookup(cache, ino, index);
	if (p) {
		__remotecache_remove(cache, p);
		remotecache_page_put(p);
		return true;
	}
	return false;
}
EXPORT_SYMBOL(__remotecache_erase);

bool __remotecache_erase_inode(struct remotecache *cache, ino_t ino)
{
	struct remotecache_page *p = NULL;

	rc_debug("%s: erase remotecache ino=%lu from cache %p\n",
			__func__, ino, cache);

	p = __remotecache_lookup_inode(cache, ino);
	if (p) {
		__remotecache_remove_inode(cache, p);
		remotecache_page_put(p);
		return true;
	}
	return false;
}
EXPORT_SYMBOL(__remotecache_erase_inode);

void __remotecache_remove_inode(struct remotecache *cache, struct remotecache_page *inode)
{
	struct rb_node *node = rb_next(&inode->rb_node);

	rc_debug("%s: remove inode %lu from remotecache page %p)",
			__func__, inode->ino, inode);

	if (node) {
		do {
			struct remotecache_page *rcp =
				rb_entry(node, struct remotecache_page, rb_node);

			if (rcp->ino != inode->ino)
				break;
			node = rb_next(node);
			__remotecache_remove(cache, rcp);
		} while (node);
	}

	node = rb_prev(&inode->rb_node);
	if (node) {
		do {
			struct remotecache_page *rcp=
				rb_entry(node, struct remotecache_page, rb_node);

			if (rcp->ino != inode->ino)
				break;
			node = rb_prev(node);
			__remotecache_remove(cache, rcp);
		} while (node);
	}
	__remotecache_remove(cache, inode);
}
EXPORT_SYMBOL(__remotecache_remove_inode);

static void remotecache_page_init(struct remotecache_page *page)
{
	kref_init(&page->kref);
	INIT_LIST_HEAD(&page->lru);
	RB_CLEAR_NODE(&page->rb_node);

	page->cache = NULL;
	page->flags = 0;
	page->ino = 0;
	page->index = 0;
	page->private = NULL;
#ifdef CONFIG_REMOTECACHE_DEBUG
	page->crc = 0;
#endif
}

void remotecache_page_free(struct kref *ref)
{
	struct remotecache_page *page = container_of(ref, struct remotecache_page, kref);

	rc_debug("%s %p %p", __func__, page, page->private);

	BUG_ON(!RB_EMPTY_NODE(&page->rb_node));
	BUG_ON(!list_empty(&page->lru));

	remotecache_set_page(page, 0);

	mempool_free(page, remotecache_page_pool);
}
EXPORT_SYMBOL(remotecache_page_free);

void __remotecache_clear(struct remotecache *cache)
{
	while (!RB_EMPTY_ROOT(&cache->pages_tree)) {
		struct remotecache_page *p =
			rb_entry(cache->pages_tree.rb_node,
					struct remotecache_page, rb_node);
		__remotecache_remove_inode(cache, p);
	}

	BUG_ON(atomic_read(&cache->size) != 0);
}
EXPORT_SYMBOL(__remotecache_clear);

void remotecache_release(struct kref *ref)
{
	unsigned long flags;
	struct remotecache *cache = container_of(ref, struct remotecache, kref);

	rc_debug("%s: remotecache release %p", __func__, cache);

	unregister_shrinker(&cache->shrinker);

	BUG_ON(!list_empty(&cache->list));

	spin_lock_irqsave(&cache->lock, flags);
	__remotecache_clear(cache);
	spin_unlock_irqrestore(&cache->lock, flags);

	remotecache_policy_destroy(cache->policy);
}
EXPORT_SYMBOL(remotecache_release);

struct remotecache_page *remotecache_page_alloc(gfp_t gfp_mask)
{
	struct remotecache_page *p =
		mempool_alloc(remotecache_page_pool, gfp_mask);

	if (p)
		remotecache_page_init(p);
	return p;
}
EXPORT_SYMBOL(remotecache_page_alloc);

static void *rc_page_pool_alloc(gfp_t gfp_mask, void *pool_data) {
	return kmem_cache_zalloc(remotecache_page_cachep, gfp_mask);
}

static void rc_page_pool_free(void *element, void *pool_data)
{
	kmem_cache_free(remotecache_page_cachep, element);
}

void remotecache_init(struct remotecache *cache)
{
	/* TODO: destroy kmem_cache on module unload */
	if (!remotecache_page_pool) {
		remotecache_page_cachep = kmem_cache_create("remotecache_page",
				sizeof(struct remotecache_page), 0,
				SLAB_MEM_SPREAD|SLAB_PANIC, NULL);

		remotecache_page_pool =
			mempool_create(REMOTECACHE_PAGE_POOL_SIZE,
					rc_page_pool_alloc,
					rc_page_pool_free, NULL);
		BUG_ON(!remotecache_page_pool);
	}

	kref_init(&cache->kref);
	INIT_LIST_HEAD(&cache->list);

	memset(&cache->uuid, 0, sizeof(cache->uuid));
	cache->pool_id = 0;
	atomic_set(&cache->size, 0);

	spin_lock_init(&cache->lock);
	cache->pages_tree = RB_ROOT;

	cache->policy = remotecache_policy_create("lru");
	cache->session = NULL;

	/* Shrinker initialization */
	cache->evict = NULL;
	cache->shrinker.count_objects = shrinker_count_objects;
	cache->shrinker.scan_objects = shrinker_scan_objects;
	/* TODO: make experiments to test other values */
	cache->shrinker.seeks = 1;
	/*
	 * TODO: 1024 should be a good value for remotecache page nodes
	 * used to store a real page (server side), but may be too small
	 * for 'empty' nodes
	 */
	cache->shrinker.batch = 1024;
	INIT_LIST_HEAD(&cache->shrinker.list);
	register_shrinker(&cache->shrinker);
}
EXPORT_SYMBOL(remotecache_init);


static int sleep_on_remotecache_page(void *word)
{
	schedule();
	return 0;
}

bool trylock_remotecache_page(struct remotecache_page *page)
{
	return !test_and_set_bit_lock(RC_PAGE_LOCKED, &page->flags);
}
EXPORT_SYMBOL(trylock_remotecache_page);

void lock_remotecache_page(struct remotecache_page *page)
{
	might_sleep();
	wait_on_bit_lock(&page->flags, RC_PAGE_LOCKED,
			sleep_on_remotecache_page, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(lock_remotecache_page);

void unlock_remotecache_page(struct remotecache_page *page)
{
	clear_bit_unlock(RC_PAGE_LOCKED, &page->flags);
	smp_mb__after_clear_bit();
	wake_up_remotecache_page(page, RC_PAGE_LOCKED);
}
EXPORT_SYMBOL(unlock_remotecache_page);

void wake_up_remotecache_page(struct remotecache_page *page, int bit)
{
	wake_up_bit(&page->flags, bit);
}
EXPORT_SYMBOL(wake_up_remotecache_page);

void wait_on_remotecache_page_bit(struct remotecache_page *page, int bit)
{
	wait_on_bit(&page->flags, bit, sleep_on_remotecache_page,
			TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_remotecache_page_bit);
