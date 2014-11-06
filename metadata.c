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

#include "metadata.h"

static mempool_t *remotecache_metadata_pool = NULL;
static struct kmem_cache *remotecache_metadata_cachep = NULL;

static inline int remotecache_page_metadata_cmp(ino_t lhs_ino, pgoff_t lhs_index,
		ino_t rhs_ino, pgoff_t rhs_index)
{
	int r = lhs_ino - rhs_ino;
	if (r)
		return r;
	return lhs_index - rhs_index;
}

static inline int remotecache_metadata_inode_cmp(ino_t lhs_ino, pgoff_t lhs_index,
		ino_t rhs_ino, pgoff_t rhs_index)
{
	return lhs_ino - rhs_ino;
}

static struct remotecache_page_metadata *do_remotecache_metadata_lookup(
		struct remotecache_metadata *metadata,
		ino_t ino, pgoff_t index,
		int (*cmp_fn)(ino_t, pgoff_t, ino_t, pgoff_t))
{
	struct rb_node *n = metadata->pages_tree.rb_node;
	struct remotecache_page_metadata *pmd = NULL;

	while (n) {
		int cmp;
		pmd = rb_entry(n, struct remotecache_page_metadata, rb_node);

		cmp = cmp_fn(ino, index, pmd->ino, pmd->index);

		if (cmp < 0) {
			n = n->rb_left;
		} else if (cmp > 0) {
			n = n->rb_right;
		} else {
			remotecache_page_metadata_get(pmd);
			return pmd;
		}
	}
	return NULL;
}

struct remotecache_page_metadata *__remotecache_metadata_lookup(struct remotecache_metadata *metadata,
		ino_t ino, pgoff_t index)
{
	rc_debug("%s: lookup for remotecache_metadata_page ino=%lu, index=%lu "
			"in cache %p \n", __func__, ino, index, metadata);
	return do_remotecache_metadata_lookup(metadata, ino, index, remotecache_page_metadata_cmp);
}
EXPORT_SYMBOL(__remotecache_metadata_lookup);

struct remotecache_page_metadata *__remotecache_metadata_lookup_inode(struct remotecache_metadata *metadata,
		ino_t ino)
{
	return do_remotecache_metadata_lookup(metadata, ino, 0, remotecache_metadata_inode_cmp);
}
EXPORT_SYMBOL(__remotecache_metadata_lookup_inode);

void __remotecache_metadata_remove_page_list(struct remotecache_metadata *metadata,
		struct list_head *free_pages)
{
	struct remotecache_page_metadata *page, *next;

	rc_debug("%s: removing remotecache_metadata_pages", __func__);

	list_for_each_entry_safe(page, next, free_pages, lru) {
		rb_erase(&page->rb_node, &metadata->pages_tree);
		RB_CLEAR_NODE(&page->rb_node);

		/*
		 * Pages where removed from the LRU by
		 * policy->reclaim
		 */
		INIT_LIST_HEAD(&page->lru);

		remotecache_page_metadata_put(page);
	}
}
EXPORT_SYMBOL(__remotecache_metadata_remove_page_list);

static unsigned long shrinker_count_objects(struct shrinker *shrinker,
		struct shrink_control *sc) {
	struct remotecache_metadata *metadata =
		container_of(shrinker, struct remotecache_metadata, shrinker);

	if (!metadata->evict)
		return 0;

	return (unsigned long) atomic_read(&metadata->size);
}

static unsigned long shrinker_scan_objects(struct shrinker *shrinker, struct shrink_control *sc)
{
	int nr_removed = 0;
	struct remotecache_metadata *metadata =
		container_of(shrinker, struct remotecache_metadata, shrinker);

	if (!metadata->evict)
		return SHRINK_STOP;

	if (sc->nr_to_scan) {
		unsigned long flags;
		LIST_HEAD(free_pages);

		spin_lock_irqsave(&metadata->lock, flags);
		metadata->policy->reclaim(metadata, &free_pages, sc->nr_to_scan);

		nr_removed = metadata->evict(metadata, &free_pages);
		__remotecache_metadata_remove_page_list(metadata, &free_pages);
		atomic_sub(nr_removed, &metadata->size);
		spin_unlock_irqrestore(&metadata->lock, flags);
	}

	return nr_removed;
}

static struct remotecache_page_metadata *do_remotecache_metadata_insert(struct remotecache_metadata *metadata,
		struct remotecache_page_metadata *new)
{
	struct remotecache_page_metadata *pmd;
	struct rb_node **p = &metadata->pages_tree.rb_node;
	struct rb_node *parent = NULL;

	while (*p) {
		int keycmp;
		parent = *p;
		pmd = rb_entry(parent, struct remotecache_page_metadata, rb_node);

		keycmp = remotecache_page_metadata_cmp(new->ino, new->index,
				pmd->ino, pmd->index);
		if (keycmp < 0)
			p = &(*p)->rb_left;
		else if (keycmp > 0)
			p = &(*p)->rb_right;
		else
			return pmd;
	}

	rb_link_node(&new->rb_node, parent, p);
	return NULL;
}

struct remotecache_page_metadata *__remotecache_metadata_insert(struct remotecache_metadata *metadata,
		struct remotecache_page_metadata *new)
{
	struct remotecache_page_metadata *pmd;

	rc_debug("%s: insert page %p (ino=%lu, index=%lu) into metadata %p",
			__func__, new, new->ino, new->index, metadata);

	BUG_ON(!RB_EMPTY_NODE(&new->rb_node));
	BUG_ON(!list_empty(&new->lru));

	pmd = do_remotecache_metadata_insert(metadata, new);

	if (!pmd) {
		rb_insert_color(&new->rb_node, &metadata->pages_tree);
		atomic_inc(&metadata->size);
		remotecache_page_metadata_get(new);

		metadata->policy->referenced(metadata, new);
	} else {
		remotecache_page_metadata_get(pmd);
	}
	return pmd;
}
EXPORT_SYMBOL(__remotecache_metadata_insert);

void __remotecache_metadata_remove(struct remotecache_metadata *metadata,
		struct remotecache_page_metadata *page)
{
	if (RB_EMPTY_NODE(&page->rb_node))
		return;

	rc_debug("%s: page %p ino %lu index %lu cache %pUl\n",
			__func__, page, page->ino, page->index, &metadata->uuid);

	rb_erase(&page->rb_node, &metadata->pages_tree);
	RB_CLEAR_NODE(&page->rb_node);

	if (test_and_clear_bit(RC_PAGE_LRU, &page->flags))
		metadata->policy->remove(metadata, page);

	BUG_ON(atomic_sub_return(1, &metadata->size) < 0);
	remotecache_page_metadata_put(page);
}
EXPORT_SYMBOL(__remotecache_metadata_remove);

bool remotecache_metadata_erase(struct remotecache_metadata *metadata, ino_t ino, pgoff_t index)
{
	bool erased;
	spin_lock(&metadata->lock);
	erased = __remotecache_metadata_erase(metadata, ino, index);
	spin_unlock(&metadata->lock);
	return erased;
}
EXPORT_SYMBOL(remotecache_metadata_erase);

bool __remotecache_metadata_erase(struct remotecache_metadata *metadata, ino_t ino, pgoff_t index)
{
	struct remotecache_page_metadata *p = NULL;

	rc_debug("%s: erase remotecache_metadata_page ino=%lu, index=%lu from cache %p\n",
			__func__, ino, index, metadata);

	p = __remotecache_metadata_lookup(metadata, ino, index);
	if (p) {
		__remotecache_metadata_remove(metadata, p);
		remotecache_page_metadata_put(p);
		return true;
	}
	return false;
}
EXPORT_SYMBOL(__remotecache_metadata_erase);

bool __remotecache_metadata_erase_inode(struct remotecache_metadata *metadata, ino_t ino)
{
	struct remotecache_page_metadata *p = NULL;

	rc_debug("%s: erase remotecache_metadata_ino=%lu from cache %p\n",
			__func__, ino, metadata);

	p = __remotecache_metadata_lookup_inode(metadata, ino);
	if (p) {
		__remotecache_metadata_remove_inode(metadata, p);
		remotecache_page_metadata_put(p);
		return true;
	}
	return false;
}
EXPORT_SYMBOL(__remotecache_metadata_erase_inode);

void __remotecache_metadata_remove_inode(struct remotecache_metadata *metadata, struct remotecache_page_metadata *inode)
{
	struct rb_node *node = rb_next(&inode->rb_node);

	rc_debug("%s: remove inode %lu from remotecache_metadatapage %p)",
			__func__, inode->ino, inode);

	if (node) {
		do {
			struct remotecache_page_metadata *pmd =
				rb_entry(node, struct remotecache_page_metadata, rb_node);

			if (pmd->ino != inode->ino)
				break;
			node = rb_next(node);
			__remotecache_metadata_remove(metadata, pmd);
		} while (node);
	}

	node = rb_prev(&inode->rb_node);
	if (node) {
		do {
			struct remotecache_page_metadata *pmd=
				rb_entry(node, struct remotecache_page_metadata, rb_node);

			if (pmd->ino != inode->ino)
				break;
			node = rb_prev(node);
			__remotecache_metadata_remove(metadata, pmd);
		} while (node);
	}
	__remotecache_metadata_remove(metadata, inode);
}
EXPORT_SYMBOL(__remotecache_metadata_remove_inode);

static void remotecache_page_metadata_init(struct remotecache_page_metadata *pmd)
{
	kref_init(&pmd->kref);
	INIT_LIST_HEAD(&pmd->lru);
	RB_CLEAR_NODE(&pmd->rb_node);

	pmd->flags = 0;
	pmd->ino = 0;
	pmd->index = 0;
	pmd->private = NULL;
#ifdef CONFIG_REMOTECACHE_DEBUG
	pmd->crc = 0;
#endif
}

void remotecache_page_metadata_free(struct kref *ref)
{
	struct remotecache_page_metadata *pmd = container_of(ref, struct remotecache_page_metadata, kref);

	rc_debug("%s %p %p", __func__, pmd, pmd->private);

	BUG_ON(!RB_EMPTY_NODE(&pmd->rb_node));
	BUG_ON(!list_empty(&pmd->lru));

	remotecache_metadata_set_page(pmd, 0);

	mempool_free(pmd, remotecache_metadata_pool);
}
EXPORT_SYMBOL(remotecache_page_metadata_free);

void __remotecache_metadata_clear(struct remotecache_metadata *metadata)
{
	while (!RB_EMPTY_ROOT(&metadata->pages_tree)) {
		struct remotecache_page_metadata *p =
			rb_entry(metadata->pages_tree.rb_node,
					struct remotecache_page_metadata, rb_node);
		__remotecache_metadata_remove_inode(metadata, p);
	}

	BUG_ON(atomic_read(&metadata->size) != 0);
}
EXPORT_SYMBOL(__remotecache_metadata_clear);

void remotecache_metadata_release(struct kref *ref)
{
	unsigned long flags;
	struct remotecache_metadata *metadata = container_of(ref, struct remotecache_metadata, kref);

	rc_debug("%s: remotecache_metadata_release %p", __func__, metadata);

	unregister_shrinker(&metadata->shrinker);

	BUG_ON(!list_empty(&metadata->list));

	spin_lock_irqsave(&metadata->lock, flags);
	__remotecache_metadata_clear(metadata);
	spin_unlock_irqrestore(&metadata->lock, flags);

	remotecache_policy_destroy(metadata->policy);
}
EXPORT_SYMBOL(remotecache_metadata_release);

struct remotecache_page_metadata *remotecache_page_metadata_alloc(gfp_t gfp_mask)
{
	struct remotecache_page_metadata *p =
		mempool_alloc(remotecache_metadata_pool, gfp_mask);

	if (p)
		remotecache_page_metadata_init(p);
	return p;
}
EXPORT_SYMBOL(remotecache_page_metadata_alloc);

static void *rc_page_metadata_pool_alloc(gfp_t gfp_mask, void *pool_data) {
	return kmem_cache_zalloc(remotecache_metadata_cachep, gfp_mask);
}

static void rc_page_metadata_pool_free(void *element, void *pool_data)
{
	kmem_cache_free(remotecache_metadata_cachep, element);
}

void remotecache_metadata_init(struct remotecache_metadata *metadata)
{
	/* TODO: destroy kmem_cache on module unload */
	if (!remotecache_metadata_pool) {
		remotecache_metadata_cachep = kmem_cache_create("remotecache_page_metadata",
				sizeof(struct remotecache_page_metadata), 0,
				SLAB_MEM_SPREAD|SLAB_PANIC, NULL);

		remotecache_metadata_pool =
			mempool_create(REMOTECACHE_PAGE_POOL_SIZE,
					rc_page_metadata_pool_alloc,
					rc_page_metadata_pool_free, NULL);
		BUG_ON(!remotecache_metadata_pool);
	}

	kref_init(&metadata->kref);
	INIT_LIST_HEAD(&metadata->list);

	memset(&metadata->uuid, 0, sizeof(metadata->uuid));
	metadata->pool_id = 0;
	atomic_set(&metadata->size, 0);

	spin_lock_init(&metadata->lock);
	metadata->pages_tree = RB_ROOT;

	metadata->policy = remotecache_policy_create("lru");

	/* Shrinker initialization */
	metadata->evict = NULL;
	metadata->shrinker.count_objects = shrinker_count_objects;
	metadata->shrinker.scan_objects = shrinker_scan_objects;
	/* TODO: make experiments to test other values */
	metadata->shrinker.seeks = 1;
	/*
	 * TODO: 1024 should be a good value for remotecache_metadatapage nodes
	 * used to store a real page (server side), but may be too small
	 * for 'empty' nodes
	 */
	metadata->shrinker.batch = 1024;
	INIT_LIST_HEAD(&metadata->shrinker.list);
	register_shrinker(&metadata->shrinker);
}
EXPORT_SYMBOL(remotecache_metadata_init);


static int sleep_on_remotecache_page_metadata(void *word)
{
	schedule();
	return 0;
}

bool trylock_remotecache_page_metadata(struct remotecache_page_metadata *page)
{
	return !test_and_set_bit_lock(RC_PAGE_LOCKED, &page->flags);
}
EXPORT_SYMBOL(trylock_remotecache_page_metadata);

void lock_remotecache_page_metadata(struct remotecache_page_metadata *page)
{
	might_sleep();
	wait_on_bit_lock(&page->flags, RC_PAGE_LOCKED,
			sleep_on_remotecache_page_metadata, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(lock_remotecache_page_metadata);

void unlock_remotecache_page_metadata(struct remotecache_page_metadata *page)
{
	clear_bit_unlock(RC_PAGE_LOCKED, &page->flags);
	smp_mb__after_clear_bit();
	wake_up_remotecache_page_metadata(page, RC_PAGE_LOCKED);
}
EXPORT_SYMBOL(unlock_remotecache_page_metadata);

void wake_up_remotecache_page_metadata(struct remotecache_page_metadata *page, int bit)
{
	wake_up_bit(&page->flags, bit);
}
EXPORT_SYMBOL(wake_up_remotecache_page_metadata);

void wait_on_remotecache_page_metadata_bit(struct remotecache_page_metadata *page, int bit)
{
	wait_on_bit(&page->flags, bit, sleep_on_remotecache_page_metadata,
			TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_remotecache_page_metadata_bit);
