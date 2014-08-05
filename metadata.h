/*
 *	cache.h
 *
 *	Copyright (C) 2013
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef REMOTECACHE_METADATA_H
#define REMOTECACHE_METADATA_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/uuid.h>
#include <linux/shrinker.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include "remotecache.h"
#include "policy.h"

/*
 * A remotecache page pool is created to speed up memory allocations and
 * to allow new nodes to be added to rbtree in case of high memory
 * pressure
 */
#define REMOTECACHE_PAGE_POOL_SIZE (1 << 16)

struct page;
struct remotecache_metadata;
struct remotecache_policy;

enum remotecache_page_flags {
	RC_PAGE_LOCKED,		/* Remote cache page is locked */
	RC_PAGE_HAS_PAGE,	/* ->private points to a struct page */
	RC_PAGE_LRU,		/* page is in the LRU */
	RC_PAGE_BUSY,		/* page is busy (ex. during a PUT) */
};

/* A remote cache page
 *
 * Each page of the remote cache is stored in a rbtree
 */
struct remotecache_page_metadata {
	struct kref kref;
	struct list_head lru;
	struct remotecache_metadata *metadata;

	unsigned long flags;
	struct rb_node rb_node;

#ifdef CONFIG_REMOTECACHE_DEBUG
	u32 crc;
#endif
	ino_t ino;
	pgoff_t index;
	void *private;
};

struct remotecache_metadata {
	struct kref kref;
	struct list_head list;
	struct shrinker shrinker;
	struct remotecache_policy *policy;
	struct remotecache_session *session;

	int (*evict) (struct remotecache_metadata *metadata, struct list_head *pages);

	uuid_le uuid;
	int pool_id;		/* Compat with cleancache */
	atomic_t size;

	struct rb_root pages_tree;
	spinlock_t lock; 	/* lock to protect pages_tree, lru */
};

void remotecache_metadata_init(struct remotecache_metadata *metadata);
void remotecache_metadata_release(struct kref *ref);
struct remotecache_page_metadata *remotecache_page_metadata_alloc(gfp_t gfp_mask);

static inline void remotecache_metadata_get(struct remotecache_metadata *metadata)
{
	kref_get(&metadata->kref);
}

static inline void remotecache_metadata_put(struct remotecache_metadata *metadata)
{
	kref_put(&metadata->kref, remotecache_metadata_release);
}

void remotecache_page_metadata_free(struct kref *ref);

static inline void remotecache_page_metadata_get(struct remotecache_page_metadata *pmd)
{
	kref_get(&pmd->kref);
}

static inline void remotecache_page_metadata_put(struct remotecache_page_metadata *pmd)
{
	kref_put(&pmd->kref, remotecache_page_metadata_free);
}

static inline void remotecache_metadata_set_page(struct remotecache_page_metadata *pmd,
		struct page *page)
{
	if (page) {
		if (test_and_set_bit(RC_PAGE_HAS_PAGE, &pmd->flags)) {
			struct page *old;
			BUG_ON(pmd->private == NULL);

			old = pmd->private;
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
			BUG_ON(pmd->private != NULL);
		}
		pmd->private = page;
		get_page(page);
	} else {
		if (test_and_clear_bit(RC_PAGE_HAS_PAGE, &pmd->flags)) {
			struct page *old;
			BUG_ON(!pmd->private);

			old = pmd->private;
			if (PagePrivate(old)) {
				ClearPagePrivate(old);
				ClearPageRemote(old);
				set_page_private(old, 0);
				__dec_zone_page_state(old, NR_FILE_PAGES);
				release_pages(&old, 1, 0);
			} else {
				put_page(old);
			}

			pmd->private = NULL;
		}
	}
}

extern struct remotecache_page_metadata *__remotecache_metadata_lookup(
		struct remotecache_metadata *metadata, ino_t ino, pgoff_t index);

static inline struct remotecache_page_metadata *remotecache_metadata_lookup(
		struct remotecache_metadata *metadata, ino_t ino, pgoff_t index)
{
	struct remotecache_page_metadata *ret = NULL;

	spin_lock(&metadata->lock);
	ret = __remotecache_metadata_lookup(metadata, ino, index);
	spin_unlock(&metadata->lock);

	return ret;
}

static inline bool remotecache_metadata_contains(struct remotecache_metadata *metadata,
		ino_t ino, pgoff_t index)
{
	struct remotecache_page_metadata *p =
		remotecache_metadata_lookup(metadata, ino, index);
	if (p) {
		remotecache_page_metadata_put(p);
		return true;
	}
	return false;
}

static inline bool __remotecache_metadata_contains(struct remotecache_metadata *metadata,
		ino_t ino, pgoff_t index)
{
	struct remotecache_page_metadata *p =
		__remotecache_metadata_lookup(metadata, ino, index);
	if (p) {
		remotecache_page_metadata_put(p);
		return true;
	}
	return false;
}

extern struct remotecache_page_metadata *__remotecache_metadata_lookup_inode(
		struct remotecache_metadata *metadata, ino_t ino);

static inline struct remotecache_page_metadata *remotecache_metadata_lookup_inode(
		struct remotecache_metadata *metadata, ino_t ino)
{
	struct remotecache_page_metadata *ret = NULL;

	spin_lock(&metadata->lock);
	ret = __remotecache_metadata_lookup_inode(metadata, ino);
	spin_unlock(&metadata->lock);

	return ret;
}

/*
 * Returns a pointer to a page with key pmd->key if it is already in the
 * store.
 */
extern struct remotecache_page_metadata *__remotecache_metadata_insert(
		struct remotecache_metadata *metadata, struct remotecache_page_metadata *new);

static inline struct remotecache_page_metadata *remotecache_metadata_insert(
		struct remotecache_metadata *metadata, struct remotecache_page_metadata *new)
{
	struct remotecache_page_metadata *ret = NULL;

	spin_lock(&metadata->lock);
	ret = __remotecache_metadata_insert(metadata, new);
	spin_unlock(&metadata->lock);

	return ret;
}

extern void __remotecache_metadata_remove(struct remotecache_metadata *metadata,
		struct remotecache_page_metadata *pmd);

static inline void remotecache_metadata_remove(struct remotecache_metadata *metadata,
		struct remotecache_page_metadata *pmd)
{
	spin_lock(&metadata->lock);
	__remotecache_metadata_remove(metadata, pmd);
	spin_unlock(&metadata->lock);
}


extern bool __remotecache_metadata_erase_inode(struct remotecache_metadata *metadata, ino_t ino);
extern void __remotecache_metadata_remove_inode(struct remotecache_metadata *metadata,
		struct remotecache_page_metadata *inode);

void __remotecache_metadata_clear(struct remotecache_metadata *metadata);
bool remotecache_metadata_erase(struct remotecache_metadata *metadata, ino_t ino, pgoff_t index);
bool __remotecache_metadata_erase(struct remotecache_metadata *metadata, ino_t ino, pgoff_t index);

void __remotecache_metadata_remove_page_list(struct remotecache_metadata *, struct list_head *);

bool trylock_remotecache_page_metadata(struct remotecache_page_metadata *pmd);
void lock_remotecache_page_metadata(struct remotecache_page_metadata *pmd);
void unlock_remotecache_page_metadata(struct remotecache_page_metadata *pmd);
void wake_up_remotecache_page_metadata(struct remotecache_page_metadata *pmd, int bit);
void wait_on_remotecache_page_metadata_bit(struct remotecache_page_metadata *pmd, int bit);
#endif /* REMOTECACHE_METADATA_H */