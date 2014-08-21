/*
 *	cache.h
 *
 *	Copyright (C) 2013
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef REMOTECACHE_CACHE_H
#define REMOTECACHE_CACHE_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/uuid.h>
#include <linux/shrinker.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/radix-tree.h>
#include <linux/hashtable.h>

#include "remotecache.h"
#include "policy.h"

struct page;
struct remotecache;
struct remotecache_policy;

struct remotecache_inode {
	struct kref kref;
	struct hlist_node hash;
	struct list_head list; /* reclaim list */
	struct remotecache *cache;
	ino_t ino;
	struct radix_tree_root pages_tree;
	spinlock_t lock;
};

#define REMOTECACHE_INODES_HASH_ORDER 10

struct remotecache {
	struct kref kref;
	struct list_head list;	/* links for cache lists */
	struct remotecache_session *session;	/* parent session */

	uuid_le uuid;		/* cache UUID (currently not used) */
	int pool_id;		/* Compat with cleancache */

	DECLARE_HASHTABLE(inodes_hash, REMOTECACHE_INODES_HASH_ORDER);
	spinlock_t lock; 	/* lock to protect inodes_hash */

	atomic_t size;		/* cache size */
};

void remotecache_init(struct remotecache *cache);
void remotecache_release(struct kref *ref);

static inline void remotecache_get(struct remotecache *cache)
{
	kref_get(&cache->kref);
}

static inline void remotecache_put(struct remotecache *cache)
{
	kref_put(&cache->kref, remotecache_release);
}

static inline void remotecache_inode_get(struct remotecache_inode *i)
{
	kref_get(&i->kref);
}

void remotecache_inode_release(struct kref *ref);
static inline void remotecache_inode_put(struct remotecache_inode *i)
{
	kref_put(&i->kref, remotecache_inode_release);
}

struct remotecache_inode *remotecache_inode_alloc(gfp_t gfp_mask);

void __remotecache_insert_inode(struct remotecache *cache,
		struct remotecache_inode *i);

void __remotecache_remove_inode(struct remotecache_inode *i);

struct remotecache_inode *__remotecache_lookup_inode(
		struct remotecache *, ino_t);
#endif /* REMOTECACHE_CACHE_H */
