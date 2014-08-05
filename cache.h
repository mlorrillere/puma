/*
 *	cache.h
 *
 *	Copyright (C) 2013
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef REMOTECACHE_STORE_H
#define REMOTECACHE_STORE_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/uuid.h>
#include <linux/shrinker.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include "remotecache.h"
#include "policy.h"
#include "metadata.h"

struct page;
struct remotecache;
struct remotecache_policy;

/* A remote cache page
 *
 * Each page of the remote cache is stored in a rbtree
 */
struct remotecache_page {
	struct kref kref;
	struct list_head lru;
	struct remotecache *cache;

	unsigned long flags;
	struct rb_node rb_node;

#ifdef CONFIG_REMOTECACHE_DEBUG
	u32 crc;
#endif
	ino_t ino;
	pgoff_t index;
	void *private;
};

struct remotecache {
	struct kref kref;
	struct list_head list;
	struct shrinker shrinker;
	struct remotecache_policy *policy;
	struct remotecache_session *session;

	int (*evict) (struct remotecache *cache, struct list_head *pages);

	uuid_le uuid;
	int pool_id;		/* Compat with cleancache */
	atomic_t size;

	struct rb_root pages_tree;
	spinlock_t lock; 	/* lock to protect pages_tree, lru */
};

void remotecache_init(struct remotecache *cache);
void remotecache_release(struct kref *ref);
struct remotecache_page *remotecache_page_alloc(gfp_t gfp_mask);

static inline void remotecache_get(struct remotecache *cache)
{
	kref_get(&cache->kref);
}

static inline void remotecache_put(struct remotecache *cache)
{
	kref_put(&cache->kref, remotecache_release);
}

void remotecache_page_free(struct kref *ref);

static inline void remotecache_page_get(struct remotecache_page *page)
{
	kref_get(&page->kref);
}

static inline void remotecache_page_put(struct remotecache_page *page)
{
	kref_put(&page->kref, remotecache_page_free);
}

static inline void remotecache_set_page(struct remotecache_page *rcp,
		struct page *page)
{
	if (page) {
		if (test_and_set_bit(RC_PAGE_HAS_PAGE, &rcp->flags)) {
			struct page *old;
			BUG_ON(rcp->private == NULL);

			old = rcp->private;
			if (PagePrivate(old)) {
				ClearPagePrivate(old);
				ClearPageRemote(old);
				set_page_private(old, 0);
				__dec_zone_page_state(old, NR_FILE_PAGES);
				release_pages(&old, 1, 0);
			} else {
				put_page(old);
			}
		} else {
			BUG_ON(rcp->private != NULL);
		}
		rcp->private = page;
		get_page(page);
	} else {
		if (test_and_clear_bit(RC_PAGE_HAS_PAGE, &rcp->flags)) {
			struct page *old;
			BUG_ON(!rcp->private);

			old = rcp->private;
			if (PagePrivate(old)) {
				ClearPagePrivate(old);
				ClearPageRemote(old);
				set_page_private(old, 0);
				__dec_zone_page_state(old, NR_FILE_PAGES);
				release_pages(&old, 1, 0);
			} else {
				put_page(old);
			}

			rcp->private = NULL;
		}
	}
}

extern struct remotecache_page *__remotecache_lookup(
		struct remotecache *cache, ino_t ino, pgoff_t index);

static inline struct remotecache_page *remotecache_lookup(
		struct remotecache *cache, ino_t ino, pgoff_t index)
{
	struct remotecache_page *ret = NULL;

	spin_lock(&cache->lock);
	ret = __remotecache_lookup(cache, ino, index);
	spin_unlock(&cache->lock);

	return ret;
}

static inline bool remotecache_contains(struct remotecache *cache,
		ino_t ino, pgoff_t index)
{
	struct remotecache_page *p =
		remotecache_lookup(cache, ino, index);
	if (p) {
		remotecache_page_put(p);
		return true;
	}
	return false;
}

static inline bool __remotecache_contains(struct remotecache *cache,
		ino_t ino, pgoff_t index)
{
	struct remotecache_page *p =
		__remotecache_lookup(cache, ino, index);
	if (p) {
		remotecache_page_put(p);
		return true;
	}
	return false;
}

extern struct remotecache_page *__remotecache_lookup_inode(
		struct remotecache *cache, ino_t ino);

static inline struct remotecache_page *remotecache_lookup_inode(
		struct remotecache *cache, ino_t ino)
{
	struct remotecache_page *ret = NULL;

	spin_lock(&cache->lock);
	ret = __remotecache_lookup_inode(cache, ino);
	spin_unlock(&cache->lock);

	return ret;
}

/*
 * Returns a pointer to a page with key rcp->key if it is already in the
 * store.
 */
extern struct remotecache_page *__remotecache_insert(
		struct remotecache *cache, struct remotecache_page *new);

static inline struct remotecache_page *remotecache_insert(
		struct remotecache *cache, struct remotecache_page *new)
{
	struct remotecache_page *ret = NULL;

	spin_lock(&cache->lock);
	ret = __remotecache_insert(cache, new);
	spin_unlock(&cache->lock);

	return ret;
}

extern void __remotecache_remove(struct remotecache *cache,
		struct remotecache_page *page);

static inline void remotecache_remove(struct remotecache *cache,
		struct remotecache_page *page)
{
	spin_lock(&cache->lock);
	__remotecache_remove(cache, page);
	spin_unlock(&cache->lock);
}


extern bool __remotecache_erase_inode(struct remotecache *cache, ino_t ino);
extern void __remotecache_remove_inode(struct remotecache *cache,
		struct remotecache_page *inode);

void __remotecache_clear(struct remotecache *cache);
bool remotecache_erase(struct remotecache *cache, ino_t ino, pgoff_t index);
bool __remotecache_erase(struct remotecache *cache, ino_t ino, pgoff_t index);

void __remotecache_remove_page_list(struct remotecache *, struct list_head *);

bool trylock_remotecache_page(struct remotecache_page *page);
void lock_remotecache_page(struct remotecache_page *page);
void unlock_remotecache_page(struct remotecache_page *page);
void wake_up_remotecache_page(struct remotecache_page *page, int bit);
void wait_on_remotecache_page_bit(struct remotecache_page *page, int bit);
#endif /* REMOTECACHE_STORE_H */
