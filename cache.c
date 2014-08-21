/*
 *	cache.c
 *
 *	Copyright (C) 2013
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/bug.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/lockdep.h>

#include "cache.h"

static struct kmem_cache *remotecache_inode_cachep = NULL;

static void remotecache_inode_init(struct remotecache_inode *inode)
{
	kref_init(&inode->kref);
	INIT_HLIST_NODE(&inode->hash);
	INIT_LIST_HEAD(&inode->list);
	INIT_RADIX_TREE(&inode->pages_tree, GFP_ATOMIC);
	spin_lock_init(&inode->lock);

	inode->ino = 0;
}


struct remotecache_inode *__remotecache_lookup_inode(struct remotecache *cache,
		ino_t ino)
{
	struct remotecache_inode *i;

	if (!rcu_read_lock_held())
		lockdep_assert_held(&cache->lock);

	rc_debug("%s: cache %d inode %lu\n", __func__, cache->pool_id, ino);

	hash_for_each_possible_rcu(cache->inodes_hash, i, hash, ino)
		if (ino == i->ino) {
			rc_debug("%s: found inode %p ino %lu == %lu\n",
					__func__, i, i->ino, ino);
			remotecache_inode_get(i);
			return i;
		}
	return NULL;
}

void __remotecache_insert_inode(struct remotecache *cache,
		struct remotecache_inode *i)
{
	lockdep_assert_held(&cache->lock);

	rc_debug("%s: cache %d inode %p %lu\n", __func__, cache->pool_id,
			i, i->ino);

	remotecache_inode_get(i);
	hash_add_rcu(cache->inodes_hash, &i->hash, i->ino);

	i->cache = cache;
}

void __remotecache_remove_inode(struct remotecache_inode *i)
{
	lockdep_assert_held(&i->cache->lock);

	rc_debug("%s: cache %d inode %p %lu\n", __func__, i->cache->pool_id,
			i, i->ino);

	hash_del_rcu(&i->hash);
	remotecache_inode_put(i);
}


void remotecache_inode_release(struct kref *ref)
{
	struct remotecache_inode *inode =
		container_of(ref, struct remotecache_inode, kref);
	unsigned long pos = 0;
	struct page *pages[16];
	int n;

	rc_debug("%s %p %lu", __func__, inode, inode->ino);

	do {
		int i;

		spin_lock(&inode->lock);
		n = radix_tree_gang_lookup(&inode->pages_tree, (void **)pages,
				pos, ARRAY_SIZE(pages));

		for (i = 0; i < n; ++i) {
			struct page *p = pages[i];
			void *ret;

			BUG_ON(!get_page_unless_zero(p));
			pos = p->index;
			ret = radix_tree_delete(&inode->pages_tree, p->index);
			BUG_ON(!ret || ret != p);
		}

		pos++;

		spin_unlock(&inode->lock);

		/*
		 * synchronize_rcu as radix_tree_*_lookup does not returns
		 * pages with refcount increased
		 */
		synchronize_rcu();

		for (i = 0; i < n; ++i) {
			struct page *p = pages[i];

			WARN_ON(!TestClearPageRemote(p));
			ClearPagePrivate(p);
			set_page_private(p, 0);
			__dec_zone_page_state(p, NR_FILE_PAGES);

			/*
			 * Release page cache ref
			 */
			page_cache_release(p);

			/*
			 * Drop last ref
			 */
			put_page(p);
		}
		atomic_sub(n, &inode->cache->size);
	} while (n > 0);

	kmem_cache_free(remotecache_inode_cachep, inode);
}

void remotecache_clear(struct remotecache *cache)
{
	int bucket;
	struct remotecache_inode *ino, *next;
	struct hlist_node *tmp;
	LIST_HEAD(inodes_list);

	spin_lock(&cache->lock);
	hash_for_each_safe(cache->inodes_hash, bucket, tmp, ino, hash) {
		hash_del_rcu(&ino->hash);
		list_add(&ino->list, &inodes_list);
	}
	spin_unlock(&cache->lock);

	synchronize_rcu();

	list_for_each_entry_safe(ino, next, &inodes_list, list) {
		remotecache_inode_put(ino);
	}

	WARN_ON(atomic_read(&cache->size) != 0);
}

void remotecache_release(struct kref *ref)
{
	struct remotecache *cache = container_of(ref, struct remotecache, kref);

	rc_debug("%s: remotecache release %p", __func__, cache);

	BUG_ON(!list_empty(&cache->list));

	remotecache_clear(cache);
}

struct remotecache_inode *remotecache_inode_alloc(gfp_t gfp_mask)
{
	struct remotecache_inode *i =
		kmem_cache_zalloc(remotecache_inode_cachep, gfp_mask);

	if (i)
		remotecache_inode_init(i);
	return i;
}

void remotecache_init(struct remotecache *cache)
{
	/* TODO: destroy kmem_cache on module unload */
	if (!remotecache_inode_cachep) {
		remotecache_inode_cachep = kmem_cache_create("remotecache_inode",
				sizeof(struct remotecache_inode), 0,
				SLAB_MEM_SPREAD|SLAB_PANIC, NULL);
	}

	kref_init(&cache->kref);
	INIT_LIST_HEAD(&cache->list);
	cache->session = NULL;

	memset(&cache->uuid, 0, sizeof(cache->uuid));
	cache->pool_id = 0;

	hash_init(cache->inodes_hash);
	spin_lock_init(&cache->lock);
	atomic_set(&cache->size, 0);
}
