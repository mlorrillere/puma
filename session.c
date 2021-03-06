/*
 *	session.h
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/bsearch.h>
#include <linux/sort.h>
#include <linux/remotecache.h>
#include <linux/cleancache.h>
#include <linux/wait.h>

#include "session.h"
#include "node.h"
#include "remotecache.h"
#include "cache.h"
#include "metadata.h"
#include "msgpool.h"
#include "heartbeat.h"

/*
 * Module parameters
 */
bool remotecache_suspend_disable_get = false;
bool remotecache_slow_put = false;
int remotecache_timeout_usec = 1000;
int remotecache_eviction_base_penalty = 0;

module_param_named(suspend_disable_get, remotecache_suspend_disable_get,
		bool, 0666);
module_param_named(enable_slow_put, remotecache_slow_put, bool, 0666);
module_param_named(timeout_usec, remotecache_timeout_usec, int, 0666);
module_param_named(eviction_base_penalty, remotecache_eviction_base_penalty,
		int, 0666);

static void submit_request_pages(struct remotecache_request *request);
static void remotecache_request_put(struct remotecache_request *r);
static void mark_remotecache_page_evicted(struct remotecache_inode *, pgoff_t);
static int remotecache_page_score(struct remotecache_inode *, pgoff_t,
		unsigned long *score, unsigned long *evict);
static void remotecache_unpack_shadow(void *, unsigned long *, unsigned long *);
static void *remotecache_pack_shadow(unsigned long, unsigned long);

struct remotecache_session *remotecache_session_create(
		struct remotecache_node *node)
{
	struct remotecache_session *session = kzalloc(sizeof(*session),
			GFP_KERNEL);

	if (!session)
		return ERR_PTR(-ENOMEM);

	kref_init(&session->kref);
	INIT_LIST_HEAD(&session->list);
	INIT_LIST_HEAD(&session->requests);
	INIT_LIST_HEAD(&session->caches);
	mutex_init(&session->c_lock);
	mutex_init(&session->r_lock);
	session->available = ULONG_MAX;
	session->flags = 0;
	session->latency = 0;
	session->latency_15 = 0;

	session->node = node;

	remotecache_node_get(node);

	pr_err("%s created session %p node %p\n", __func__, session, node);

	return session;
}

void remotecache_session_cancel_requests(struct remotecache_session *session)
{
	struct remotecache_request *r, *next;
	LIST_HEAD(requests);

	mutex_lock(&session->r_lock);
	list_splice_init(&session->requests, &requests);
	mutex_unlock(&session->r_lock);

	list_for_each_entry_safe(r, next, &requests, list) {
		pr_err("%s waiting for pending request %lu\n", __func__, r->id);
		hrtimer_cancel(&r->timer);

		if (!test_bit(REMOTECACHE_REQUEST_CANCELED, &r->flags))
			submit_request_pages(r);
		atomic_set(&r->nr_received, r->nr_pages);
		remotecache_request_put(r);
	}
}

void remotecache_session_close(struct remotecache_session *session)
{
	struct remotecache_request *r, *next;
	LIST_HEAD(requests);
	pr_err("%s close session %p\n", __func__, session);

	rc_con_close(&session->con);

	mutex_lock(&session->r_lock);
	list_splice_init(&session->requests, &requests);
	mutex_unlock(&session->r_lock);

	list_for_each_entry_safe(r, next, &requests, list) {
		pr_err("%s waiting for pending request %lu\n", __func__, r->id);
		hrtimer_cancel(&r->timer);

		if (!test_bit(REMOTECACHE_REQUEST_CANCELED, &r->flags))
			submit_request_pages(r);
		atomic_set(&r->nr_received, r->nr_pages);
		remotecache_request_put(r);
	}
}

void remotecache_session_last_put(struct kref *ref)
{
	struct remotecache *cache, *next;
	struct remotecache_session *session = container_of(ref,
			struct remotecache_session, kref);

	pr_err("%s destroy session %p\n", __func__, session);

	/*
	 * close connection
	 * TODO: ensure messages are ACK'ed before closing the connection
	 */
	remotecache_session_close(session);

	mutex_lock(&session->node->s_lock);
	list_del_rcu(&session->list);
	synchronize_rcu();
	INIT_LIST_HEAD(&session->list);
	mutex_unlock(&session->node->s_lock);

	mutex_lock(&session->c_lock);
	list_for_each_entry_safe(cache, next, &session->caches, list) {
		list_del_rcu(&cache->list);
		remotecache_put(cache);
	}
	mutex_unlock(&session->c_lock);

	synchronize_rcu();

	remotecache_node_put(session->node);

	kfree(session);
}

/*
 * remote->cache functions
 */
static struct remotecache *__session_create_cache(
		struct remotecache_session *session,
		int pool_id, uuid_le uuid) {
	struct remotecache *cache;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	BUG_ON(!cache);

	remotecache_init(cache);
	cache->pool_id = pool_id;
	cache->uuid = uuid;

	/*
	 * We enable automatic reclaiming only if store_size (i.e.: static
	 * reclaiming) is disabled
	 */
//	if (!store_size)
//		cache->evict = remotecache_shrinker_evict;

	return cache;
}

static struct remotecache *__session_get_cache(
		struct remotecache_session *session,
		int pool_id, uuid_le uuid)
{
	struct remotecache *cache = NULL;

	/* TODO: do the work with UUID */
	list_for_each_entry_rcu(cache, &session->caches, list) {
		if (cache->pool_id == pool_id)
			goto found;
	}

	return NULL;

found:
	remotecache_get(cache);
	return cache;
}

static struct remotecache *session_get_cache(
		struct remotecache_session *session,
		int pool_id, uuid_le uuid)
{
	struct remotecache *cache;

	/* TODO: do the work with UUID */
	rcu_read_lock();
	cache = __session_get_cache(session, pool_id, uuid);
	rcu_read_unlock();

	if (cache)
		return cache;

	mutex_lock(&session->c_lock);
	cache = __session_get_cache(session, pool_id, uuid);
	if (!cache) {
		struct remotecache *new =
			__session_create_cache(session, pool_id, uuid);

		list_add_tail_rcu(&new->list, &session->caches);
		remotecache_get(new);
		cache = new;
		cache->session = session;
	}
	mutex_unlock(&session->c_lock);

	return cache;
}

/*
 * match function against pool_id for do_invalidate_page
 */
bool match_pool_id(struct rc_msg *m, void *arg)
{
	int pool_id = *(int *)arg;
	struct rc_invalidate_page_request *front;

	if (le16_to_cpu(m->header.type) != RC_MSG_TYPE_INVALIDATE_PAGE)
		return false;

	front = m->front.iov_base;

	if (le32_to_cpu(front->pool_id) == pool_id)
		return true;

	return false;
}

/*
 * Taken from fs/proc/meminfo.c
 */
static unsigned long get_available_pages_count(void)
{
	struct sysinfo i;
	long available;
	unsigned long pagecache;
	unsigned long wmark_low = 0;
	struct zone *zone;

	si_meminfo(&i);

	for_each_zone(zone)
		wmark_low += zone->watermark[WMARK_LOW];

	/*
	 * Estimate the amount of memory available for userspace allocations,
	 * without causing swapping.
	 *
	 * Free memory cannot be taken below the low watermark, before the
	 * system starts swapping.
	 */
	available = i.freeram - wmark_low;

	/*
	 * Not all the page cache can be freed, otherwise the system will
	 * start swapping. Assume at least half of the page cache, or the
	 * low watermark worth of cache, needs to stay.
	 */
	pagecache = global_page_state(NR_INACTIVE_FILE);
	pagecache += global_page_state(NR_ACTIVE_FILE);
	pagecache -= min(pagecache / 2, wmark_low);
	available += pagecache;

	/*
	 * Part of the reclaimable slab consists of items that are in use,
	 * and cannot be freed. Cap this estimate at the low watermark.
	 */
	available += global_page_state(NR_SLAB_RECLAIMABLE) -
		     min(global_page_state(NR_SLAB_RECLAIMABLE) / 2, wmark_low);

	if (available < 0)
		available = 0;

	return available;
}

/*
 * Dispatch functions
 *
 * If metadata is true, then we want to invalidate peer's metadata? Otherwise
 * we want to invalidate the page stored remotely.
 */
bool do_invalidate_page(struct remotecache_session *session,
		int pool_id, ino_t ino, pgoff_t index, bool metadata)
{
	struct rc_msg *request = NULL;
	struct rc_invalidate_page_request *front;
	struct rc_invalidate_page_request_middle *middle;

	rc_debug("%s: invalidating page (%d,%lu,%lu)\n",
			__func__, pool_id, ino, index);

	request = rc_con_plug_find(match_pool_id, &pool_id);
	if (!request)
		goto new_request;

	if (metadata && !rc_msg_test_flag(request, RC_MSG_FLAG_INVALIDATE_PMD))
		goto new_request;

	/* We try to merge invalidate request with the previous entry of
	 * the last message */
	middle = request->middle.iov_base+request->middle.iov_len-sizeof(*middle);

	if (le64_to_cpu(middle->ino) == ino &&
			le64_to_cpu(middle->index) == index + 1 &&
			middle->nr_pages < 255) {
		middle->index = cpu_to_le64(index);
		middle->nr_pages++;
	} else if (le64_to_cpu(middle->ino) == ino &&
			le64_to_cpu(middle->index) + middle->nr_pages == index &&
			middle->nr_pages < 255) {
		middle->nr_pages++;
	} else if (request->middle.iov_len / sizeof(*middle) < 64) {
		/* Otherwise we create a new entry in the previous
		 * message */
		middle = request->middle.iov_base+request->middle.iov_len;
		middle->ino = cpu_to_le64(ino);
		middle->index = cpu_to_le64(index);
		middle->nr_pages = 1;

		request->middle.iov_len += sizeof(*middle);
		request->header.middle_len = cpu_to_le32(request->middle.iov_len);
	} else {
new_request:
		request = rc_msgpool_get(&remotecache_inv_cachep, GFP_NOWAIT,
				sizeof(*front), sizeof(*middle)*64, 0);
		if (!request)
			return false;

		front = request->front.iov_base;
		front->pool_id	= cpu_to_le32(pool_id);
		front->available = cpu_to_le64(get_available_pages_count());
		request->middle.iov_len = sizeof(*middle);
		request->header.middle_len = cpu_to_le32(request->middle.iov_len);
		middle = request->middle.iov_base;
		middle->ino	= cpu_to_le64(ino);
		middle->index	= cpu_to_le64(index);
		middle->nr_pages = 1;

		if (metadata)
			rc_msg_set_flag(request, RC_MSG_FLAG_INVALIDATE_PMD);

		rc_con_send(&session->con, request);
	}

	return true;
}

/*static void shrink_cache(struct remotecache *cache,
		struct remotecache_session *session, int nr_to_scan)
{
	struct remotecache_page *page, *next;
	struct remotecache_plug rm_plug;
	int nr_removed = 0;
	LIST_HEAD(free_pages);

	cache->policy->reclaim(cache, &free_pages, nr_to_scan);

	rc_con_start_plug(&rm_plug);
	list_for_each_entry_safe(page, next, &free_pages, lru) {
		if (__invalidate_page(session, cache->pool_id, page->ino, page->index)) {
			nr_removed++;
		} else {
			pr_warn("%s: cannot invalidate page %p (%d,%lu,%lu)",
					__func__, page, cache->pool_id,
					page->ino, page->index);
			list_del_init(&page->lru);
			cache->policy->referenced(cache, page);
		}
	}
	rc_con_finish_plug(&session->con, &rm_plug);

	__remotecache_remove_page_list(cache, &free_pages);
	atomic_sub(nr_removed, &cache->size);
}*/

static void __handle_put(struct remotecache_session *session, struct rc_msg *msg)
{
	struct rc_put_request *request;
	struct remotecache *cache;
	struct rc_put_request_middle *middle, *endp;
	int pageidx = 0;

	request = msg->front.iov_base;
	cache = session_get_cache(session, le32_to_cpu(request->pool_id), NULL_UUID_LE);
	middle = msg->middle.iov_base;
	endp = msg->middle.iov_base+le32_to_cpu(msg->header.middle_len);

	BUG_ON(msg->front.iov_len != sizeof(*request));

	for ( ; middle < endp; middle++, pageidx++) {
		struct remotecache_inode *inode;
		int error;

		ino_t ino = le64_to_cpu(middle->ino);
		pgoff_t index = le64_to_cpu(middle->index);

		rc_debug("%s: received page (%d,%lu,%lu)\n", __func__,
				le32_to_cpu(request->pool_id), ino, index);

		/*
		 * Fetch the corresponding remotecache inode
		 */
		rcu_read_lock();
		inode = __remotecache_lookup_inode(cache, ino);
		rcu_read_unlock();

		if (!inode) {
			unsigned long flags;

			if (test_bit(REMOTECACHE_NODE_SUSPENDED,
						&session->node->flags))
				continue;

			rc_debug("%s: create inode %d %lu\n", __func__,
					le32_to_cpu(request->pool_id), ino);

			inode = remotecache_inode_alloc(GFP_KERNEL);
			if (!inode) {
				pr_err("%s: could not allocate remotecache inode\n",
						__func__);
				continue;
			}

			inode->ino = ino;

			spin_lock_irqsave(&cache->lock, flags);
			__remotecache_insert_inode(cache, inode);
			spin_unlock_irqrestore(&cache->lock, flags);
		} else {
			rc_debug("%s: use inode %p %lu\n", __func__, inode,
					inode->ino);
		}

		/*
		 * If the node is suspended, we remove the page to avoid
		 * inconsistencies because client metadata might be out of
		 * date.
		 */
		if (test_bit(REMOTECACHE_NODE_SUSPENDED, &session->node->flags)) {
			struct page *p;

			spin_lock(&inode->lock);
			p = radix_tree_delete(&inode->pages_tree, index);
			if (p) {
				BUG_ON(!get_page_unless_zero(p));
				remotecache_page_release(p);
				put_page(p);
			}
			spin_unlock(&inode->lock);
			remotecache_inode_put(inode);
			continue;
		}
		/*
		 * Insert/replace the old page with the new one
		 */
		error = radix_tree_preload(GFP_KERNEL);
		if (!error) {
			void **slot;
			struct page *old, *new;

			/*
			 * Add the new page to the system LRU
			 */
			new = msg->pages[pageidx];
			new->index = index;
			get_page(new);	// radix tree ref
			SetPagePrivate(new);
			SetPageRemote(new);
			set_page_private(new, (unsigned long)inode);

			__inc_zone_page_state(new, NR_FILE_PAGES);
			__inc_zone_page_state(new, NR_REMOTE);
			lru_cache_add_file(new);
			atomic_inc(&cache->size);

			/*
			 * Lookup for the old page. If found, replace it.
			 */
			spin_lock(&inode->lock);
			slot = radix_tree_lookup_slot(&inode->pages_tree, index);
			if (!slot) {
				rc_debug("%s insert new page %p index %lu\n",
						__func__, new, index);
				error = radix_tree_insert(&inode->pages_tree, index, new);
				BUG_ON(error);
			} else {
				old = radix_tree_deref_slot_protected(slot,
						&inode->lock);
				radix_tree_replace_slot(slot, new);

				/*
				 * Old page found, remove it from the remote
				 * cache and from the system LRU
				 */
				if (old) {
					BUG_ON(!get_page_unless_zero(old));
					remotecache_page_release(old);
					put_page(old);
				}
			}
			spin_unlock(&inode->lock);

			rc_debug("%s insert page %p pool %d ino %lu index %lu\n",
					__func__, new, cache->pool_id, ino,
					index);
		} else {
			pr_err("%s: radix_tree_preload returns errno %d\n",
					__func__, error);
		}

		radix_tree_preload_end();
		remotecache_inode_put(inode);
	}

	if (remotecache_max_size && atomic_read(&cache->size) > remotecache_max_size) {
		/*
		 * TODO
		 */
		//shrink_cache(cache, session, msg->nr_pages*8);
	}

	remotecache_put(cache);
	rc_msg_put(msg);
}

static void __handle_get(struct remotecache_session *session, struct rc_msg *msg)
{
	struct rc_msg *res;
	struct rc_get_request *request = msg->front.iov_base;
	struct rc_get_request_middle *middle = msg->middle.iov_base,
				     *endp;
	struct rc_get_response *front;
	struct rc_get_response_middle *rmid;
	struct remotecache *cache;
	struct remotecache_inode *inode;

	int pool_id = le32_to_cpu(request->pool_id);
	ino_t ino = (ino_t)le64_to_cpu(request->ino);

	BUG_ON(msg->front.iov_len != sizeof(*request));

	cache = session_get_cache(session, le32_to_cpu(request->pool_id),
			NULL_UUID_LE);

	res = rc_msg_new(RC_MSG_TYPE_GET_RESPONSE,
			sizeof(struct rc_get_response),
			sizeof(struct rc_get_response_middle)*PAGES_PER_GET,
			PAGES_PER_GET, GFP_NOFS, 0);
	if (!res) {
		pr_err("__handle_get: cannot allocate message");
		BUG();
	}
	front = res->front.iov_base;
	front->available = cpu_to_le64(get_available_pages_count());
	front->req_id = request->req_id;
	front->pool_id = request->pool_id;
	front->ino = request->ino;
	front->nr_miss = 0;
	res->middle.iov_len = 0;
	rmid = res->middle.iov_base;

	rcu_read_lock();
	inode = __remotecache_lookup_inode(cache, ino);
	rcu_read_unlock();

	endp = middle + msg->middle.iov_len/sizeof(*middle);
	for (; middle < endp; ++middle) {
		pgoff_t index = le64_to_cpu(middle->index);
		unsigned int n = 0, i;
		void **slot;
		struct radix_tree_iter iter;
		struct page *pages[PAGES_PER_GET];

		rc_debug("%s: middle index %lu nr_pages %hhu\n", __func__,
				index, middle->nr_pages);

		front->nr_miss += middle->nr_pages;
		if (!inode)
			continue;

		rcu_read_lock();
		radix_tree_for_each_contig(slot, &inode->pages_tree, &iter, index) {
			struct page *p = NULL;

repeat:
			p = radix_tree_deref_slot(slot);
			if (unlikely(!p))
				continue;
			if (radix_tree_deref_retry(p))
				goto repeat;
			if (unlikely(!get_page_unless_zero(p)))
				goto repeat;

			/* Has the page moved? */
			if (unlikely(p != *slot)) {
				page_cache_release(p);
				goto repeat;
			}

			pages[n] = p;
			if (++n == middle->nr_pages)
				break;
		}
		rcu_read_unlock();

		/*
		 * Add pages to response message
		 */
		for (i = 0; i < n; ++i) {
			struct page *p = pages[i];

			rmid->index = cpu_to_le64(p->index);
			rc_msg_add_page(res, p);

			rc_debug("%s page %p pool %d ino %lu index %lu " \
					"res %p middle %p\n",
					__func__, p, pool_id, ino,
					p->index, res, rmid);
			front->nr_miss--;
			rmid++;

			if (remotecache_strategy != RC_STRATEGY_EXCLUSIVE) {
				mark_page_accessed(p);
				put_page(p);
			}
		}

		/*
		 * Remove page from the cache if we are in exclusive caching
		 * mode.
		 */
		if (remotecache_strategy == RC_STRATEGY_EXCLUSIVE) {
			spin_lock(&inode->lock);
			for (i = 0; i < n; ++i) {
				struct page *p = pages[i];
				radix_tree_delete_item(&inode->pages_tree,
						p->index, p);
			}
			spin_unlock(&inode->lock);

			for (i = 0; i < n; ++i) {
				struct page *p = pages[i];
				remotecache_page_release(p);
				put_page(p);
			}
		}
	}

	rc_debug("%s: found %d miss %d pages\n", __func__,
			res->nr_pages, front->nr_miss);

	res->middle.iov_len =
		sizeof(struct rc_get_response_middle)*res->nr_pages;
	res->header.middle_len = cpu_to_le32(res->middle.iov_len);
	rc_con_send(&session->con, res);

	if (inode)
		remotecache_inode_put(inode);
	remotecache_put(cache);
	rc_msg_put(msg);
}

static void __handle_invalidate_fs(struct remotecache_session *session,
		struct rc_msg *msg)
{
	struct remotecache *cache;
	struct rc_invalidate_fs_request *inv_fs = msg->front.iov_base;
	int pool_id;

	BUG_ON(le16_to_cpu(msg->header.type) != RC_MSG_TYPE_INVALIDATE_FS);
	BUG_ON(msg->front.iov_len != sizeof(*inv_fs));

	pool_id = le32_to_cpu(inv_fs->pool_id);

	rc_debug("Handling INVALIDATE_FS (pool_id=%d) request", pool_id);

	mutex_lock(&session->c_lock);
	cache = __session_get_cache(session, pool_id, NULL_UUID_LE);
	list_del_rcu(&cache->list);
	remotecache_put(cache); /* list reference */
	mutex_unlock(&session->c_lock);

	remotecache_put(cache);

	rc_msg_put(msg);
}

static void __handle_invalidate_ino(struct remotecache_session *session,
		struct rc_msg *msg)
{
	struct rc_invalidate_ino_request *inv_ino = msg->front.iov_base;
	struct remotecache_inode *inode;
	struct remotecache *cache;
	int pool_id;
	ino_t ino;

	BUG_ON(le16_to_cpu(msg->header.type) != RC_MSG_TYPE_INVALIDATE_INO);
	BUG_ON(msg->front.iov_len != sizeof(*inv_ino));

	pool_id = le32_to_cpu(inv_ino->pool_id);
	ino = le64_to_cpu(inv_ino->ino);

	rc_debug("%s: pool=%d,ino=%lu\n", __func__, pool_id, ino);

	cache = session_get_cache(session, pool_id, NULL_UUID_LE);

	rcu_read_lock();
	inode = __remotecache_lookup_inode(cache, ino);
	rcu_read_unlock();

	if (inode) {
		unsigned long flags;
		spin_lock_irqsave(&cache->lock, flags);
		__remotecache_remove_inode(inode);
		spin_unlock_irqrestore(&cache->lock, flags);

		remotecache_inode_put(inode);
	}

	remotecache_put(cache);
	rc_msg_put(msg);
}

static void __invalidate_page(struct remotecache_session *session,
		struct rc_msg *msg)
{
	struct rc_invalidate_page_request *inv_page = msg->front.iov_base;
	struct rc_invalidate_page_request_middle *middle, *endp;
	struct remotecache *cache;
	int pool_id;

	BUG_ON(le16_to_cpu(msg->header.type) != RC_MSG_TYPE_INVALIDATE_PAGE);
	BUG_ON(msg->front.iov_len != sizeof(*inv_page));

	pool_id = le32_to_cpu(inv_page->pool_id);
	rc_debug("%s invalidate page request on pool %d\n", __func__, pool_id);

	middle = msg->middle.iov_base;
	endp = msg->middle.iov_base + msg->middle.iov_len;

	cache = session_get_cache(session, pool_id, NULL_UUID_LE);
	while (middle < endp) {
		struct remotecache_inode *inode;
		ino_t ino = le64_to_cpu(middle->ino);
		pgoff_t index= le64_to_cpu(middle->index);
		int n = middle->nr_pages;

		rcu_read_lock();
		inode = __remotecache_lookup_inode(cache, ino);
		rcu_read_unlock();

		do {
			struct page *pages[16];
			int i, batch = min_t(int, n, ARRAY_SIZE(pages));

			spin_lock(&inode->lock);
			for (i = 0; i < batch; i++) {
				pages[i] = radix_tree_delete(&inode->pages_tree, index++);
				if (pages[i])
					get_page(pages[i]);
			}
			spin_unlock(&inode->lock);

			for (i = 0; i < batch; i++) {
				struct page *p = pages[i];
				if (!p)
					break;
				remotecache_page_release(p);
				put_page(p);
			}

			n -= batch;
			cond_resched();
		} while (n > 0);

		remotecache_inode_put(inode);
		middle++;
	}
	remotecache_put(cache);
}

static void __invalidate_page_metadata(struct remotecache_session *session,
		struct rc_msg *msg)
{
	struct rc_invalidate_page_request *inv_page = msg->front.iov_base;
	struct rc_invalidate_page_request_middle *middle, *endp;
	struct remotecache *metadata;
	unsigned long flags;
	unsigned count = 0;
	int pool_id;

	BUG_ON(le16_to_cpu(msg->header.type) != RC_MSG_TYPE_INVALIDATE_PAGE);
	BUG_ON(msg->front.iov_len != sizeof(*inv_page));

	pool_id = le32_to_cpu(inv_page->pool_id);
	rc_debug("%s invalidate page request on pool %d\n", __func__, pool_id);

	middle = msg->middle.iov_base;
	endp = msg->middle.iov_base + msg->middle.iov_len;

	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);
	while (middle < endp) {
		ino_t ino = le64_to_cpu(middle->ino);
		pgoff_t first = le64_to_cpu(middle->index),
			last = first + middle->nr_pages;
		struct remotecache_inode *inode;

		rcu_read_lock();
		inode = __remotecache_lookup_inode(metadata, ino);
		rcu_read_unlock();

		count += middle->nr_pages;

		if (!inode) {
			pr_err("%s inode %lu not found\n", __func__, ino);
			middle++;
			continue;
		}

		/*
		 * Lookup for the first page of the [first, last] interval
		 */
		spin_lock_irqsave(&inode->lock, flags);
		while (first < last) {
			if (!radix_tree_tag_clear(&inode->pages_tree, first,
						REMOTECACHE_TAG_PRESENT)) {
				pr_warn("%s remotecache page (%d,%lu,%lu) not found\n",
					__func__, pool_id, ino, first);
			}
			if (remotecache_eviction_base_penalty > 0)
				mark_remotecache_page_evicted(inode, first);
			first++;
		}
		spin_unlock_irqrestore(&inode->lock, flags);

		middle++;
	}

	this_node->stats.n_remote_invalidate += count;
	session->available = le64_to_cpu(inv_page->available);

	remotecache_put(metadata);
}

/*
 * INVALIDATE_PAGE message is sent both client side when the VFS invalidate a
 * page, and server side when a victim page is evicted from the remote page
 * cache. For the first case, the RC_MSG_FLAG_INVALIDATE_PMD flag has been set
 * by the server case so we know that we have to lookup for metadata.
 */
static void __handle_invalidate_page(struct remotecache_session *session,
		struct rc_msg *msg)
{
	BUG_ON(le16_to_cpu(msg->header.type) != RC_MSG_TYPE_INVALIDATE_PAGE);
	BUG_ON(msg->front.iov_len != sizeof(struct rc_invalidate_page_request));

	if (rc_msg_test_flag(msg, RC_MSG_FLAG_INVALIDATE_PMD))
		__invalidate_page_metadata(session, msg);
	else
		__invalidate_page(session, msg);

	rc_msg_put(msg);
}

/*
 * Network/connection related functions
 */
static struct rc_connection *remotecache_session_con_get(struct rc_connection *con)
{
	struct remotecache_session *session =
		container_of(con, struct remotecache_session, con);

	rc_debug("%s %p\n", __func__, con);
	if (kref_get_unless_zero(&session->kref))
		return con;
	return NULL;
}

static void remotecache_session_con_put(struct rc_connection *con)
{
	struct remotecache_session *session =
		container_of(con, struct remotecache_session, con);

	rc_debug("%s %p\n", __func__, con);
	remotecache_session_put(session);
}

struct rc_msg * remotecache_session_alloc_msg(struct rc_connection *con,
		struct rc_msg_header *header, int *skip)
{
	int front_len = le32_to_cpu(header->front_len);
	int middle_len = le32_to_cpu(header->middle_len);
	int nr_pages = le32_to_cpu(header->data_len)/PAGE_SIZE;
	struct rc_msg *msg = NULL;

	switch (le16_to_cpu(header->type)) {
	case RC_MSG_TYPE_GET_RESPONSE:
		msg = rc_msgpool_get(&remotecache_get_response_cachep,
				GFP_NOWAIT, front_len, middle_len, nr_pages);
		break;
	case RC_MSG_TYPE_INVALIDATE_PAGE:
		msg = rc_msgpool_get(&remotecache_inv_cachep, GFP_NOWAIT,
				front_len, middle_len, 0);
		break;
	case RC_MSG_TYPE_PUT:
		msg = rc_msgpool_get(&remotecache_put_cachep, GFP_NOFS,
				front_len, middle_len, nr_pages);
		break;
	case RC_MSG_TYPE_GET:
		msg = rc_msgpool_get(&remotecache_get_cachep, GFP_NOFS,
				front_len, middle_len, nr_pages);
		break;
	case RC_MSG_TYPE_INVALIDATE_FS:
	case RC_MSG_TYPE_INVALIDATE_INO:
		msg = rc_msg_new(le16_to_cpu(header->type), front_len,
				middle_len, nr_pages, GFP_NOFS, 1);
		break;
	case RC_MSG_TYPE_SUSPEND:
	case RC_MSG_TYPE_RESUME:
		msg = rc_msg_new(le16_to_cpu(header->type), 0, 0, 0, GFP_ATOMIC, 0);
		break;
	case RC_MSG_TYPE_PING:
	case RC_MSG_TYPE_PONG:
		msg = rc_msg_new(le16_to_cpu(header->type), front_len, 0, 0, GFP_ATOMIC, 0);
		break;
	default:
		break;
	}

	return msg;
}

static void remotecache_session_fault(struct rc_connection *con)
{
	struct remotecache_session *session = container_of(con,
			struct remotecache_session, con);

	pr_err("%s received fault %s", __func__, con->error_msg);

	/* close and free session */
	mutex_lock(&session->node->s_lock);
	list_del_rcu(&session->list);
	synchronize_rcu();
	INIT_LIST_HEAD(&session->list);
	mutex_unlock(&session->node->s_lock);

	remotecache_session_put(session);
}

/*
 * VFS/Page cache hooks
 */

/* rc_init_fs: implementation of the cleancache init_fs call */
static int __remotecache_init_fs(size_t page_size)
{
	static int pool_ids = 0;
	struct remotecache *metadata;

	metadata = kzalloc(sizeof(*metadata), GFP_KERNEL);
	BUG_ON(!metadata);

	remotecache_init(metadata);
	metadata->pool_id = pool_ids++;

	mutex_lock(&this_node->m_lock);
	list_add_tail(&metadata->list, &this_node->metadata);
	mutex_unlock(&this_node->m_lock);

	return metadata->pool_id;
}

/* rc_init_shared_fs: implementation of the cleancache init_shared_fs call */
static int __remotecache_init_shared_fs(char *uuid, size_t page_size)
{
	return -1;
}

static int __remotecache_get_page(int pool_id, struct cleancache_filekey key,
		pgoff_t index, struct page *page)
{
	return -1;
}

/* PUT management */
static inline struct rc_msg *alloc_put_msg(int pool_id) {
	struct rc_put_request *p;
	struct rc_msg *msg =
		rc_msgpool_get(&remotecache_put_cachep, GFP_NOWAIT, sizeof(*p),
			PAGES_PER_PUT*sizeof(struct rc_put_request_middle),
			PAGES_PER_PUT);
	if (!msg) {
		pr_err("%s: cannot allocate struct rc_msg: "
				"out of memory", __func__);
		dump_stack();
		return NULL;
	}

	p = msg->front.iov_base;
	p->pool_id = cpu_to_le32(pool_id);

	msg->middle.iov_len = 0;

	rc_msg_set_flag(msg, RC_MSG_FLAG_URG);

	return msg;
}

/* rc_put_page: implementation of the cleancache put_page call */
static void __remotecache_put_page(int pool_id, struct cleancache_filekey key,
		pgoff_t index, struct page *page)
{
	struct rc_msg *msg;
	struct rc_put_request *p;
	struct rc_put_request_middle *middle;
	struct page *dst_page = NULL;
	short type;
	struct remotecache *cache, *metadata;
	struct remotecache_inode *inode;
	struct remotecache_session *session;
	unsigned long flags;
	int present = 0;
	unsigned long score, evict;
	bool keep_local = TestClearPageKeepLocal(page);
	BUG_ON(PageRemote(page));

	/* not coming from shrink_page_list */
	if (page_count(page) != 0 || !PageLocked(page) ||
			page->mapping->host->i_ino < 2)
		return;

	/*
	 * TODO: with multiple sessions, return only a useful session or NULL,
	 * instead of a possibly suspended session.
	 */
	session = remotecache_node_session(this_node);
	if (!session) {
		rc_debug("%s: not connected to a remote node\n", __func__);
		return;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(cache, &session->caches, list) {
		if (atomic_read(&cache->size)) {
			rcu_read_unlock();
			rc_debug("%s node busy\n", __func__);
			return;
		}
	}
	rcu_read_unlock();

	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);

	rcu_read_lock();
	inode = __remotecache_lookup_inode(metadata, key.u.ino);
	rcu_read_unlock();

	/*
	 * If the inode does not exists, create a new one and insert it into
	 * the metadata.
	 */
	if (!inode) {
		rc_debug("%s: create inode %d %lu\n", __func__, pool_id, key.u.ino);

		inode = remotecache_inode_alloc(GFP_ATOMIC);
		if (!inode) {
			pr_err("%s: could not allocate remotecache inode\n",
					__func__);
			goto out;
		}

		inode->ino = key.u.ino;

		spin_lock_irqsave(&metadata->lock, flags);
		__remotecache_insert_inode(metadata, inode);
		spin_unlock_irqrestore(&metadata->lock, flags);
	}

	rcu_read_lock();
	present = radix_tree_tag_get(&inode->pages_tree, index,
			REMOTECACHE_TAG_PRESENT);
	remotecache_page_score(inode, index, &score, &evict);
	rcu_read_unlock();

	/*
	 * If the node is suspended, remove page metadata
	 */
	if (test_bit(REMOTECACHE_SESSION_SUSPENDED, &session->flags)) {
		goto out_clear_present;
	}

	/*
	 * In case of an inclusive strategy, we can avoid to send a page if it
	 * is consistent with the version stored into the remote cache.
	 */
	if (present && remotecache_strategy == RC_STRATEGY_INCLUSIVE) {
		rcu_read_lock();
		/*
		 * mapping->tree_lock is already locked in
		 * __delete_from_page_cache
		 */
		if (!radix_tree_tag_get(&page->mapping->page_tree,
				index, PAGECACHE_TAG_DIRTIED)) {
			rc_debug("%s: avoid page put on non-dirtied page\n",
					__func__);
			this_node->stats.n_non_dirtied_put++;
			rcu_read_unlock();
			goto out;
		}
		rcu_read_unlock();
	}

	if (keep_local && (remotecache_eviction_base_penalty == -1 ||
				(remotecache_eviction_base_penalty > 0 && evict >= score))) {
		rc_debug("%s ino %lu page %lu score %lu evict %lu\n", __func__,
			inode->ino, index, score, evict);
		this_node->stats.n_refault_put++;
		goto out_clear_present;
	}

	dst_page = mempool_alloc(remotecache_page_pool, GFP_NOWAIT);
	if (dst_page) {
		get_page(dst_page);
	} else if (!remotecache_slow_put) {
		this_node->stats.n_aborted_put++;
		goto out_clear_present;
	}

	msg = rc_con_plug_last();
	if (!msg) {
		msg = alloc_put_msg(pool_id);
		if (!msg) {
			pr_err("%s: cannot allocate put message\n",
					__func__);
			goto out_clear_present;
		}
		middle = msg->middle.iov_base;
	}

	type = le16_to_cpu(msg->header.type);
	p = msg->front.iov_base;
	if (type != RC_MSG_TYPE_PUT || p->pool_id != pool_id ||
			msg->nr_pages >= PAGES_PER_PUT) {
		rc_con_flush_plug(&session->con, current);

		msg = alloc_put_msg(pool_id);
		if (!msg) {
			pr_err("%s: cannot allocate put message\n",
					__func__);
			goto out_clear_present;
		}
		middle = msg->middle.iov_base;
	} else {
		middle = msg->middle.iov_base+msg->middle.iov_len;
	}

	/*
	 * page may have been read without entering into the
	 * readpage/readpages path, ie. with ll_rw_block, leading to a put
	 * while the same ino/index is being transfered to the server. In this
	 * case, we locally invalidate the remote cache page and replace it
	 * with a new one. It should be safe since there is no sharing on the
	 * server side.
	 */
	spin_lock_irqsave(&inode->lock, flags);
	if (!present) {
		int error;
		void *shadow = remotecache_pack_shadow(0, 0);
		error = radix_tree_insert(&inode->pages_tree, index, shadow);
		if (error && error != -EEXIST) {
			pr_err("%s radix_tree_insert returned error %d\n",
					__func__, error);
			spin_unlock_irqrestore(&inode->lock, flags);
			if (middle == msg->middle.iov_base)
				rc_msg_put(msg);
			goto out;
		}

		radix_tree_tag_set(&inode->pages_tree, index,
				REMOTECACHE_TAG_PRESENT);
		present = 1;
	}
	__remotecache_metadata_set_busy(inode, index);
	spin_unlock_irqrestore(&inode->lock, flags);

	rc_debug("%s: page %p ino %lu index %lu msg %p\n",
			__func__, page, key.u.ino, index, msg);

	/*
	 * We try to copy the page content to an aother pre-allocated
	 * page to avoid page frame reclaiming algorithm to wait for the
	 * ack. If it is not possible to get pre-allocated page from the
	 * pool, we set the PG_remote flag to the page which will be
	 * used by the page frame reclaiming algorithm to wait for the
	 * ack.
	 */
	if (dst_page) {
		char *src, *dst;

		rc_debug("%s: try copy page %p to page %p in mempool\n",
				__func__, page, dst_page);

		src = kmap_atomic(page);
		if (!src) {
			mempool_free(dst_page, remotecache_page_pool);
			goto kmap_failure;
		}

		dst = kmap_atomic(dst_page);
		if (!dst) {
			__kunmap_atomic(src);
			mempool_free(dst_page, remotecache_page_pool);
			goto kmap_failure;
		}
		copy_page(dst, src);
		__kunmap_atomic(dst);
		__kunmap_atomic(src);

		rc_msg_add_page(msg, dst_page);

		this_node->stats.n_fast_put++;
	} else {
kmap_failure:
		/*
		 * cleanup everything if we do not allow to force a put
		 */
		if (!remotecache_slow_put) {
			if (middle == msg->middle.iov_base)
				rc_msg_put(msg);
			this_node->stats.n_aborted_put++;
			goto out_clear_present;
		}
		rc_debug("%s: put page %p msg %p\n", __func__, page, msg);

		/*
		 * It is important to set PG_remote first and then unfreeze
		 * refs to avoid a race condition with
		 * page_cache_get_speculative which might be spinning on
		 * page_count
		 */
		SetPageRemote(page);
		page_unfreeze_refs(page, 2);

		rc_msg_add_page(msg, page);
		this_node->stats.n_slow_put++;
	}

	/* Now we can update middle len size and initialize next middle */
	msg->middle.iov_len += sizeof(*middle);
	middle->ino = cpu_to_le64(key.u.ino);
	middle->index = cpu_to_le64(index);

	msg->header.middle_len = cpu_to_le32(msg->middle.iov_len);

	this_node->stats.nput++;
	if (msg->nr_pages == PAGES_PER_PUT) {
		rc_con_flush_plug(&session->con, current);
	} else if (msg->nr_pages == 1) {
		rc_con_send(&session->con, msg);
		this_node->stats.nput_msg++;
	}

out:
	if (inode)
		remotecache_inode_put(inode);
	if (dst_page)
		put_page(dst_page);
	remotecache_put(metadata);

	return;

out_clear_present:
	if (present) {
		spin_lock_irqsave(&inode->lock, flags);
		radix_tree_tag_clear(&inode->pages_tree, index,
				REMOTECACHE_TAG_PRESENT);
		spin_unlock_irqrestore(&inode->lock, flags);
	}
	goto out;
}

/* rc_invalidate_page: implementation of the cleancache invalidate_page call */
static void __remotecache_invalidate_page(int pool_id, struct cleancache_filekey key,
		pgoff_t index)
{
	unsigned long flags;
	struct remotecache *metadata;
	struct remotecache_session *session;
	struct remotecache_inode *inode;
	bool present = false;

	session = remotecache_node_session(this_node);
	if (!session) {
		rc_debug("%s: not connected to a remote node\n", __func__);
		return;
	}

	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);

	rc_debug("%s: ino %lu index %lu\n", __func__, key.u.ino, index);

	rcu_read_lock();
	inode = __remotecache_lookup_inode(metadata, key.u.ino);
	if (!inode) {
		rcu_read_unlock();
		goto out;
	}
	present = radix_tree_tag_get(&inode->pages_tree, index,
			REMOTECACHE_TAG_PRESENT);
	rcu_read_unlock();

	if (present) {
		spin_lock_irqsave(&inode->lock, flags);
		radix_tree_tag_clear(&inode->pages_tree, index,
				REMOTECACHE_TAG_PRESENT);
		spin_unlock_irqrestore(&inode->lock, flags);
	}

	/*
	 * See comment for __handle_invalidate_page
	 */
	if (present) {
		if (!do_invalidate_page(session, pool_id, key.u.ino, index, false))
			pr_warn("%s: cannot invalidate page: out of memory\n", __func__);

		this_node->stats.n_invalidate_pages++;
	}

out:
	if (inode)
		remotecache_inode_put(inode);
	remotecache_put(metadata);
}

/* rc_invalidate_inode: implementation of the cleancache invalidate_inode call */
static void __remotecache_invalidate_inode(int pool_id, struct cleancache_filekey key)
{
	unsigned long flags;
	struct rc_msg *request;
	struct rc_invalidate_ino_request *inv;
	struct remotecache *metadata;
	struct remotecache_inode *inode;
	struct remotecache_session *session;
	bool erased;

	session = remotecache_node_session(this_node);
	if (!session) {
		rc_debug("%s: not connected to a remote node\n", __func__);
		return;
	}

	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);

	rc_debug("%s: ino %lu\n", __func__, key.u.ino);

	rcu_read_lock();
	inode = __remotecache_lookup_inode(metadata, key.u.ino);
	rcu_read_unlock();

	if (inode) {
		void **slot;
		struct radix_tree_iter iter;
		spin_lock_irqsave(&inode->lock, flags);
		radix_tree_for_each_tagged(slot, &inode->pages_tree, &iter,
				0, REMOTECACHE_TAG_PRESENT) {
			radix_tree_tag_clear(&inode->pages_tree, iter.index,
					REMOTECACHE_TAG_PRESENT);
		}
		spin_unlock_irqrestore(&inode->lock, flags);
		erased = true;
	}

	if (!erased)
		goto out;

	request = rc_msg_new(RC_MSG_TYPE_INVALIDATE_INO, sizeof(*inv), 0, 0,
			GFP_KERNEL, 1);
	if (!request) {
		printk(KERN_ERR "rc_invalidate_ino: cannot allocate struct rc_msg: out of memory");
		dump_stack();
		goto out;
	}
	inv = request->front.iov_base;
	inv->pool_id	= cpu_to_le32(pool_id);
	inv->ino	= cpu_to_le64(key.u.ino);

	this_node->stats.n_invalidate_inodes++;
	rc_con_send(&session->con, request);

out:
	remotecache_put(metadata);
}

/* rc_invalidate_fs: implementation of the cleancache invalidate_fs call */
static void __remotecache_invalidate_fs(int pool_id)
{
	unsigned long flags;
	struct rc_msg *request;
	struct rc_invalidate_fs_request *inv;
	struct remotecache *metadata;
	struct remotecache_session *session;
	int bkt;
	struct remotecache_inode *inode;

	session = remotecache_node_session(this_node);
	if (!session) {
		rc_debug("%s: not connected to a remote node\n", __func__);
		return;
	}

	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);
	if (!metadata) {
		pr_err("%s: no cache found for file system pool id %d\n",
				__func__, pool_id);
		return;
	}

	rc_debug("%s: invalidating filesystem (%d)", __func__, pool_id);

	request = rc_msg_new(RC_MSG_TYPE_INVALIDATE_FS, sizeof(*inv), 0, 0,
			GFP_KERNEL, 1);
	if (!request) {
		pr_err("%s: cannot allocate struct rc_msg: out of memory",
				__func__);
		dump_stack();
		goto out;
	}
	inv = request->front.iov_base;
	inv->pool_id = cpu_to_le32(pool_id);

	rc_con_send(&session->con, request);

	spin_lock_irqsave(&metadata->lock, flags);
	hash_for_each(metadata->inodes_hash, bkt, inode, hash) {
		void *slot;
		struct radix_tree_iter iter;
		unsigned long i_flags;
		spin_lock_irqsave(&inode->lock, i_flags);
		radix_tree_for_each_tagged(slot, &inode->pages_tree, &iter,
				0, REMOTECACHE_TAG_PRESENT) {
			radix_tree_tag_clear(&inode->pages_tree, iter.index,
					REMOTECACHE_TAG_PRESENT);
		}
		spin_unlock_irqrestore(&inode->lock, i_flags);
	}
	spin_unlock_irqrestore(&metadata->lock, flags);

out:
	remotecache_put(metadata);
}

/*
 * remotecache request handling
 */
enum hrtimer_restart request_timeout(struct hrtimer *timer);
static struct remotecache_request *remotecache_request_create(
		struct remotecache_session *session, int nr_pages)
{
	static atomic_long_t idgen = ATOMIC_LONG_INIT(1);
	struct remotecache_request *request;

	request = kmalloc(sizeof(*request), GFP_KERNEL);
	if (!request) {
		return NULL;
	}

	if (nr_pages) {
		request->pages = kzalloc(sizeof(struct page*)*nr_pages,
				GFP_KERNEL);
		if (!request->pages) {
			kfree(request);
			return NULL;
		}
	} else {
		request->page = NULL;
	}

	kref_init(&request->kref);
	spin_lock_init(&request->lock);
	getnstimeofday(&request->stamp);
	hrtimer_init(&request->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	request->timer.function = request_timeout;
	atomic_set(&request->nr_received, 0);
	INIT_LIST_HEAD(&request->list);

	request->id = atomic_long_inc_return(&idgen);
	request->flags = 0;
	if (nr_pages > 0)
		__set_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags);
	request->nr_pages = 0;
	request->session = session;
	request->bh = NULL;

	return request;
}

static int __request_page_cmp_bsearch(const void *key, const void *elt)
{
	const pgoff_t *index = key;
	const struct page *page = *((struct page **)elt);

	if (*index> page->index)
		return 1;
	else if (*index < page->index)
		return -1;
	return 0;
}

static int __request_page_cmp_sort(const void *a, const void *b)
{
	const struct page *pa= *((struct page **)a);
	const struct page *pb= *((struct page **)b);

	if (pa->index > pb->index)
		return 1;
	else if (pa->index < pb->index)
		return -1;
	return 0;
}

static void __request_page_swap(void *a, void *b, int size)
{
	struct page *t = *(struct page **)a;
	*(struct page **)a = *(struct page **)b;
	*(struct page **)b = t;
}

static struct page *remotecache_request_page_lookup(
		struct remotecache_request *request, pgoff_t index)
{
	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags)) {
		struct page **p = bsearch(&index, request->pages,
				request->nr_pages, sizeof(struct page*),
				__request_page_cmp_bsearch);
		if (p) return *p;
	} else {
		BUG_ON(!request->page);
		if (request->page->index == index)
			return request->page;
	}

	return NULL;
}

static struct remotecache_request *__remotecache_request_lookup(
		struct remotecache_session *session, unsigned long id)
{
	struct remotecache_request *r;

	list_for_each_entry(r, &session->requests, list) {
		if (r->id == id)
			return r;
	}

	return NULL;
}

static void __remotecache_request_last_put(struct kref *ref)
{
	struct remotecache_request *r =
		container_of(ref, struct remotecache_request, kref);

	mutex_lock(&r->session->r_lock);
	list_del_init(&r->list);
	mutex_unlock(&r->session->r_lock);

	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &r->flags))
		kfree(r->pages);
	kfree(r);
}

static void remotecache_request_get(struct remotecache_request *r)
{
	kref_get(&r->kref);
}

static void remotecache_request_put(struct remotecache_request *r)
{
	kref_put(&r->kref, __remotecache_request_last_put);
}

DECLARE_WAIT_QUEUE_HEAD(wait_readpage_sync);

static void submit_request_pages(struct remotecache_request *request) {
	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags)) {
		int i;
		for (i = 0; i < request->nr_pages; ++i)
			unlock_page(request->pages[i]);
	} else if (request->bh) {
		rc_debug("%s calling b_end_io(%p, %d)\n", __func__,
			request->bh, PageUptodate(request->page));
		request->bh->b_end_io(request->bh, PageUptodate(request->page));
	} else if (test_bit(REMOTECACHE_REQUEST_SYNC, &request->flags)) {
		wake_up(&wait_readpage_sync);
	} else {
		unlock_page(request->page);
	}
}

enum hrtimer_restart request_timeout(struct hrtimer *timer)
{
	unsigned long i_flags, r_flags;
	struct remotecache *metadata;
	struct remotecache_request *request = container_of(timer,
			struct remotecache_request, timer);
	int pool;
	struct remotecache_inode *inode;
	ino_t ino;

	/* we already received the response */
	set_bit(REMOTECACHE_REQUEST_CANCELED, &request->flags);

	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags))
		pool = get_poolid_from_fake(request->pages[0]->mapping->host->i_sb->cleancache_poolid);
	else
		pool = get_poolid_from_fake(request->page->mapping->host->i_sb->cleancache_poolid);

	rc_debug("%s timeout for request %p id %lu pool %d\n", __func__,
			request, request->id, pool);
	metadata = remotecache_node_metadata(this_node, pool, NULL_UUID_LE);

	spin_lock_irqsave(&request->lock, r_flags);
	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags)) {
		ino = request->pages[0]->mapping->host->i_ino;
	} else {
		ino = request->page->mapping->host->i_ino;
	}
	rcu_read_lock();
	inode = __remotecache_lookup_inode(metadata, ino);
	rcu_read_unlock();

	spin_lock_irqsave(&inode->lock, i_flags);
	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags)) {
		int i;
		for (i = 0; i < request->nr_pages; ++i) {
			struct page *p = request->pages[i];
			if (!PageUptodate(p))
				radix_tree_tag_clear(&inode->pages_tree,
						p->index,
						REMOTECACHE_TAG_PRESENT);
		}
	} else {
		struct page *p = request->page;
		if (!PageUptodate(p))
			radix_tree_tag_clear(&inode->pages_tree, p->index,
					REMOTECACHE_TAG_PRESENT);
	}
	spin_unlock_irqrestore(&inode->lock, i_flags);
	spin_unlock_irqrestore(&request->lock, r_flags);

	this_node->stats.n_get_expired += request->nr_pages;

	submit_request_pages(request);
	remotecache_inode_put(inode);
	remotecache_put(metadata);

	return HRTIMER_NORESTART;
}

static void __handle_get_response(struct remotecache_session *session,
		struct rc_msg *msg)
{
	unsigned long flags;
	struct remotecache_request *request = NULL;
	struct rc_get_response *res = msg->front.iov_base;
	struct rc_get_response_middle *middle = msg->middle.iov_base;
	int nr_middle = msg->middle.iov_len / sizeof(*middle);
	pgoff_t index;
	int pool_id = le32_to_cpu(res->pool_id);
	ino_t ino = le64_to_cpu(res->ino);
	int i;
	struct remotecache *metadata;
	struct remotecache_inode *inode;

	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);

	BUG_ON(msg->front.iov_len != sizeof(*res));
	BUG_ON(!msg->middle.iov_base);

	/* looking for corresponding pending request */
	mutex_lock(&session->r_lock);
	request = __remotecache_request_lookup(session, le64_to_cpu(res->req_id));
	mutex_unlock(&session->r_lock);
	BUG_ON(!request);
	BUG_ON(request->nr_pages < nr_middle);

	rc_debug("%s session %p msg %p request %p rid %lu (%lu) " \
			"nr_middle = %u nr_pages = %u nr_miss= %hhu\n",
			__func__, session, msg, request, request->id,
			(unsigned long) le64_to_cpu(res->req_id),
			nr_middle, msg->nr_pages, res->nr_miss);

	spin_lock_irqsave(&request->lock, flags);
	if (test_bit(REMOTECACHE_REQUEST_CANCELED, &request->flags)) {
		spin_unlock_irqrestore(&request->lock, flags);
		if (atomic_add_return(msg->nr_pages+res->nr_miss, &request->nr_received) == request->nr_pages) {
			hrtimer_cancel(&request->timer);
			remotecache_request_put(request);
		}
		goto out;
	}

	rcu_read_lock();
	inode = __remotecache_lookup_inode(metadata, ino);
	rcu_read_unlock();

	for (i = 0; i < msg->nr_pages; ++i) {
		unsigned long flags;
		struct page *page = msg->pages[i];
		middle = msg->middle.iov_base+sizeof(*middle)*i;
		index = le64_to_cpu(middle->index);
		BUG_ON(page->index != index);

		if (remotecache_strategy == RC_STRATEGY_EXCLUSIVE) {
			spin_lock_irqsave(&inode->lock, flags);
			radix_tree_tag_clear(&inode->pages_tree, index,
					REMOTECACHE_TAG_PRESENT);
			spin_unlock_irqrestore(&inode->lock, flags);
		}
		SetPageUptodate(page);
	}
	this_node->stats.n_rc_hit += nr_middle;
	this_node->stats.n_rc_miss += res->nr_miss;
	session->available = le64_to_cpu(res->available);

	/*
	 * update metadata to remove missing pages
	 */
	if (res->nr_miss) {
		unsigned long flags;
		spin_lock_irqsave(&inode->lock, flags);
		if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags)) {
			int i;
			for (i = 0; i < request->nr_pages; ++i) {
				struct page *p = request->pages[i];
				if (!PageUptodate(p))
					radix_tree_tag_clear(&inode->pages_tree,
							p->index,
							REMOTECACHE_TAG_PRESENT);
			}
		} else {
			if (!PageUptodate(request->page))
				radix_tree_tag_clear(&inode->pages_tree,
						request->page->index,
						REMOTECACHE_TAG_PRESENT);
		}
		spin_unlock_irqrestore(&inode->lock, flags);
	}
	remotecache_inode_put(inode);
	remotecache_put(metadata);
	spin_unlock_irqrestore(&request->lock, flags);
	/*
	 * Free request and update stats if we received enough responses
	 */
	if (atomic_add_return(msg->nr_pages+res->nr_miss, &request->nr_received) == request->nr_pages) {
		struct timespec delay;
		getnstimeofday(&delay);

		hrtimer_cancel(&request->timer);

		if (!test_bit(REMOTECACHE_REQUEST_CANCELED, &request->flags))
			submit_request_pages(request);

		/* Updating client statistics */
		delay = timespec_sub(delay, request->stamp);

		rc_stats_update_avg(&this_node->stats.get_avg_time, &delay);
		rc_stats_update_min(&this_node->stats.get_min_time, &delay);
		rc_stats_update_max(&this_node->stats.get_max_time, &delay);
		remotecache_request_put(request);
	}
out:
	msg->nr_pages = 0;
	rc_msg_put(msg);
}

static void __handle_put_ack(struct remotecache_session *session, struct rc_msg *msg)
{
	int i, pool_id;
	struct rc_put_request *req;
	struct timespec delay;
	struct remotecache *metadata;

	req = (struct rc_put_request *)msg->front.iov_base;
	pool_id = le32_to_cpu(req->pool_id);
	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);

	for (i = 0; i < msg->nr_pages; ++i) {
		struct page *page;
		struct rc_put_request_middle *middle;
		struct remotecache_inode *inode;
		unsigned long flags;
		ino_t ino;
		pgoff_t index;

		middle = msg->middle.iov_base+sizeof(*middle)*i;
		ino = le64_to_cpu(middle->ino);
		index = le64_to_cpu(middle->index);

		page = msg->pages[i];

		rcu_read_lock();
		inode = __remotecache_lookup_inode(metadata, ino);
		rcu_read_unlock();

		BUG_ON(!inode);

		rc_debug("%s: pool %d page %p ino %lu index %lu\n",
			__func__, pool_id, page, ino, index);

		/*
		 * Processes might be waiting on RC_PAGE_BUSY bit to be
		 * cleared (see rc_pending_get_add). We clear the bit and
		 * wakup those processes, then we lock the page to clear
		 * pmd->private. Locking is important since a process might be
		 * trying to copy page content in rc_pending_get_add.
		 */
		spin_lock_irqsave(&inode->lock, flags);
		__remotecache_metadata_clear_busy(inode, index);
		spin_unlock_irqrestore(&inode->lock, flags);

		remotecache_inode_put(inode);

		put_page(page);
		if (PageRemote(page)) {
			unlock_page(page);
		} else {
			mempool_free(page, remotecache_page_pool);
		}
	}

	/* Updating client statistics */
	getnstimeofday(&delay);
	delay = timespec_sub(delay, msg->stamp);

	this_node->stats.nput_acked++;
	rc_stats_update_avg(&this_node->stats.put_avg_time, &delay);
	rc_stats_update_min(&this_node->stats.put_min_time, &delay);
	rc_stats_update_max(&this_node->stats.put_max_time, &delay);

	msg->nr_pages = 0;

	remotecache_put(metadata);
}

static void remotecache_session_acked(struct rc_connection *con, struct rc_msg *msg)
{
	struct remotecache_session *session = container_of(con,
			struct remotecache_session, con);

	switch (le16_to_cpu(msg->header.type)) {
	case RC_MSG_TYPE_PUT:
		__handle_put_ack(session, msg);
		break;
	}
}

static void __handle_suspend(struct remotecache_session *session,
		struct rc_msg *msg)
{
       rc_debug("%s: suspending activity\n", __func__);

       WARN_ON(test_and_set_bit(REMOTECACHE_SESSION_SUSPENDED, &session->flags));

       rc_msg_put(msg);
}

static void __handle_resume(struct remotecache_session *session,
		struct rc_msg *msg)
{
       rc_debug("%s: resume activity\n", __func__);

       WARN_ON(!test_and_clear_bit(REMOTECACHE_SESSION_SUSPENDED, &session->flags));

       rc_msg_put(msg);
}


static void remotecache_session_dispatch(struct rc_connection *con, struct rc_msg *msg)
{
	struct remotecache_session *session = container_of(con,
			struct remotecache_session, con);

	switch (le16_to_cpu(msg->header.type)) {
	case RC_MSG_TYPE_PUT:
		__handle_put(session, msg);
		break;
	case RC_MSG_TYPE_GET:
		__handle_get(session, msg);
		break;
	case RC_MSG_TYPE_INVALIDATE_FS:
		__handle_invalidate_fs(session, msg);
		break;
	case RC_MSG_TYPE_INVALIDATE_INO:
		__handle_invalidate_ino(session, msg);
		break;
	case RC_MSG_TYPE_INVALIDATE_PAGE:
		__handle_invalidate_page(session, msg);
		break;
	case RC_MSG_TYPE_GET_RESPONSE:
		__handle_get_response(session, msg);
		break;
	case RC_MSG_TYPE_SUSPEND:
		__handle_suspend(session, msg);
		break;
	case RC_MSG_TYPE_RESUME:
		__handle_resume(session, msg);
		break;
	case RC_MSG_TYPE_PING:
		heartbeat_handle_ping(session, msg);
		break;
	case RC_MSG_TYPE_PONG:
		heartbeat_handle_pong(session, msg);
		break;
	default:
		pr_err("unhandled message type %d",
				le16_to_cpu(msg->header.type));
	}
}

static void remotecache_session_alloc_data(struct rc_connection *con, struct rc_msg *msg)
{
	struct remotecache_session *session = container_of(con,
			struct remotecache_session, con);

	if (le16_to_cpu(msg->header.type) == RC_MSG_TYPE_GET_RESPONSE) {
		unsigned long flags;
		struct remotecache_request *request;
		struct rc_get_response *response = msg->front.iov_base;
		struct rc_get_response_middle *middle;
		unsigned n, nr_middle = msg->middle.iov_len / sizeof(*middle),
			 nr_pages = le32_to_cpu(msg->header.data_len)/PAGE_SIZE;

		mutex_lock(&session->r_lock);
		request = __remotecache_request_lookup(session,
				le64_to_cpu(response->req_id));
		mutex_unlock(&session->r_lock);
		BUG_ON(!request);

		BUG_ON(nr_pages > request->nr_pages);

		/* request has expired */
		spin_lock_irqsave(&request->lock, flags);
		if (test_bit(REMOTECACHE_REQUEST_CANCELED, &request->flags)) {
			spin_unlock_irqrestore(&request->lock, flags);
			return;
		}

		for (n = 0; n < nr_middle; ++n) {
			pgoff_t index;
			struct page *page;
			middle = msg->middle.iov_base+sizeof(*middle)*n;
			index = le64_to_cpu(middle->index);
			page = remotecache_request_page_lookup(request, index);
			rc_debug("%s lookup page %lu for request req %lu",
					__func__, index, request->id);

			if (!page) {
				pr_err("%s: cannot find page index %lu in request %p",
						__func__, index,
						request);
				BUG();
			}

			msg->pages[n] = page;
		}
		spin_unlock_irqrestore(&request->lock, flags);

	} else if (le16_to_cpu(msg->header.type == RC_MSG_TYPE_PUT)) {
		int nr_pages = le32_to_cpu(msg->header.data_len)/PAGE_SIZE;
		int i;
		for (i = 0; i < nr_pages; ++i) {
			msg->pages[i] =	alloc_page(GFP_KERNEL);
			if (!msg->pages[i]) {
				for (; i > 0; --i)
					__free_page(msg->pages[i]);
				return;
			}
		}
	}
}

static void remotecache_unpack_shadow(void *shadow, unsigned long *score,
		unsigned long *evict)
{
	unsigned long entry = (unsigned long) shadow;
	entry >>= RADIX_TREE_EXCEPTIONAL_SHIFT;
	*score = entry & ((1UL << 16) - 1);
	entry >>= 16;
	*evict = entry & ((1UL << 16) - 1);
}

static void *remotecache_pack_shadow(unsigned long score, unsigned long evict)
{
	unsigned long entry;

	entry = evict;
	entry = (entry << 16) | score;
	entry = (entry << RADIX_TREE_EXCEPTIONAL_SHIFT);

	return (void *)(entry | RADIX_TREE_EXCEPTIONAL_ENTRY);
}

static void mark_remotecache_page_accessed(struct remotecache_inode *inode,
		struct page *page, bool present)
{
	unsigned long flags;
	unsigned long score, evict;
	void **slot, *shadow;
	pgoff_t index = page->index;

	spin_lock_irqsave(&inode->lock, flags);
	slot = radix_tree_lookup_slot(&inode->pages_tree, index);
	if (!slot) {
		int error;
		shadow = remotecache_pack_shadow(PageKeepLocal(page) ? 1 : 0, 0);
		error = radix_tree_insert(&inode->pages_tree, index, shadow);
		if (error && error != -EEXIST) {
			pr_err("%s radix_tree_insert returned error %d\n",
					__func__, error);
		}
		goto out;
	}

	shadow = radix_tree_deref_slot_protected(slot, &inode->lock);
	remotecache_unpack_shadow(shadow, &score, &evict);

	if (present) {
		if (score)
			score = min_t(unsigned long, score + 1, USHRT_MAX);
	} else if (PageKeepLocal(page)) {
		score = min_t(unsigned long, score + 1, USHRT_MAX);
	} else {
		evict = max((int) (evict - score), 0);
		score = 0;
	}

	shadow = remotecache_pack_shadow(score, evict);
	radix_tree_replace_slot(slot, shadow);

	rc_debug("%s ino %lu page %lu keep %d new value (%lu %lu)\n", __func__,
		inode->ino, index, PageKeepLocal(page), score, evict);

out:
	spin_unlock_irqrestore(&inode->lock, flags);
}

static void mark_remotecache_page_evicted(struct remotecache_inode *inode,
		pgoff_t index)
{
	unsigned long score;
	unsigned long evict;
	void **slot, *shadow;

	slot = radix_tree_lookup_slot(&inode->pages_tree, index);
	BUG_ON(!slot);

	shadow = radix_tree_deref_slot_protected(slot, &inode->lock);
	remotecache_unpack_shadow(shadow, &score, &evict);

	if (!evict)
		evict = remotecache_eviction_base_penalty;
	else
		evict = min_t(unsigned long, max(evict * evict, 2UL), USHRT_MAX);
	score = 0;

	shadow = remotecache_pack_shadow(score, evict);
	radix_tree_replace_slot(slot, shadow);

	rc_debug("%s ino %lu page %lu new value (%lu %lu)\n", __func__,
			inode->ino, index, score, evict);
}

static int remotecache_page_score(struct remotecache_inode *inode,
		pgoff_t index, unsigned long *score, unsigned long *evict)
{
	void **slot, *shadow;
	*score = 0;
	*evict = 0;

	slot = radix_tree_lookup_slot(&inode->pages_tree, index);
	if (!slot) {
		rc_debug("%s ino %lu page %lu slot not found\n", __func__,
				inode->ino, index);
		return 0;
	}

	shadow = radix_tree_deref_slot(slot);
	remotecache_unpack_shadow(shadow, score, evict);
	return *score - *evict;
}

static int __request_add_page(struct page *page,
		struct address_space *mapping,
		struct remotecache_request *request)
{
	unsigned long flags;
	int r = 0;
	int pool_id = get_poolid_from_fake(mapping->host->i_sb->cleancache_poolid);
	ino_t ino = mapping->host->i_ino;
	struct remotecache *metadata = NULL;
	struct remotecache_inode *inode = NULL;
	bool present = false;

	if (ino == -1)
		goto out;

	metadata = remotecache_node_metadata(this_node, pool_id, NULL_UUID_LE);

	WARN_ON(PageUptodate(page));

	/* We check if the page is in the remote page cache */
	rcu_read_lock();
	inode = __remotecache_lookup_inode(metadata, ino);
	if (inode)
		present = radix_tree_tag_get(&inode->pages_tree, page->index,
				REMOTECACHE_TAG_PRESENT);
	rcu_read_unlock();

	if (test_bit(REMOTECACHE_SESSION_SUSPENDED, &request->session->flags) &&
			(remotecache_suspend_disable_get ||
			 test_bit(REMOTECACHE_SESSION_HEARTBEAT,
				 &request->session->flags))) {
		rc_debug("%s: node suspended\n", __func__);
		if (present)
			goto out_clear_present;
		goto out;
	}

	if (inode && remotecache_eviction_base_penalty > 0)
		mark_remotecache_page_accessed(inode, page, present);

	if (!inode || !present) {
		rc_debug("%s: avoided miss on page %p\n", __func__, page);
		this_node->stats.n_rc_miss_avoided++;
		goto out;
	}


	/*
	 * Check if the page is being transferred. Since PUT messages are
	 * buffered in current->plug, an other process might have a this (ino,
	 * index) waiting to be sent, and thus if we don't synchronize à this
	 * point our GET message might be sent before the PUT, leading to
	 * inconsistency if the page were modified.
	 *
	 * We wait for RC_PAGE_BUSY bit to be clear, meaning that the server
	 * received the corresponding message.
	 */
	remotecache_metadata_wait_busy(inode, page->index);

	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags)) {
		int status;
		list_del_init(&page->lru);

		status = add_to_page_cache_lru(page, mapping,
					page->index, GFP_KERNEL);
		if (likely(!status)) {
			rc_debug("%s adding page %lu to req %lu",
					__func__, page->index, request->id);
			if (!PageUptodate(page))
				request->pages[request->nr_pages++] = page;
			r = 1;
			page_cache_release(page);
			goto out;
		} else {
			if (status == -EEXIST) {
				rc_debug("%s: page index %lu exists\n",
						__func__, page->index);
			} else {
				rc_debug("%s: failed to add page %p ino %lu " \
					"index %lu to page cache lru\n",
				__func__, page, mapping->host->i_ino,
				page->index);
			}
			r = 1;
			goto abort;
		}
	} else {
		rc_debug("%s adding page %lu to req %lu",
				__func__, page->index, request->id);
		if (!PageUptodate(page)) {
			request->page = page;
			request->nr_pages++;
			BUG_ON(request->nr_pages != 1);
		}
		r = 1;
		goto out;
	}

abort:
	ClearPageKeepLocal(page);
	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags))
		page_cache_release(page);

	rc_debug("%s: abort on page %p ino %lu index %lu\n", __func__, page,
			mapping->host->i_ino, page->index);
out_clear_present:
	spin_lock_irqsave(&inode->lock, flags);
	radix_tree_tag_clear(&inode->pages_tree, page->index,
			REMOTECACHE_TAG_PRESENT);
	spin_unlock_irqrestore(&inode->lock, flags);
	page = NULL;

out:
	/*
	 * Unlock the page if we succeed to copy content from busy page
	 */
	if (page && PageUptodate(page))
		unlock_page(page);
	if (inode)
		remotecache_inode_put(inode);
	if (metadata)
		remotecache_put(metadata);
	return r;
}

static void __send_request(struct remotecache_session *session,
		struct remotecache_request *request,
		struct address_space *mapping)
{
	struct rc_msg *msg;
	struct rc_get_request *req;
	struct rc_get_request_middle *middle;
	unsigned sent = 0, nr_to_send;

	remotecache_request_get(request);
	if (remotecache_timeout_usec > 0) {
		hrtimer_start(&request->timer, ktime_set(0,
				remotecache_timeout_usec * USEC_PER_MSEC),
			HRTIMER_MODE_REL);
	}
	if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags))
		sort(request->pages, request->nr_pages, sizeof(struct page *),
				__request_page_cmp_sort, __request_page_swap);
	do {
		int i;
		nr_to_send = request->nr_pages - sent;
		if (nr_to_send > PAGES_PER_GET)
			nr_to_send = PAGES_PER_GET;

		rc_debug("%s: request %p req %lu sending %u/%u pages",
				__func__, request, request->id,
				nr_to_send+sent, request->nr_pages);

		msg = rc_msgpool_get(&remotecache_get_cachep, GFP_KERNEL, sizeof(*req),
			sizeof(struct rc_get_request_middle)*nr_to_send, 0);
		/* TODO: handle allocation failure */
		BUG_ON(!msg);

		msg->private = request;
		msg->middle.iov_len = sizeof(struct rc_get_request_middle);
		msg->header.middle_len = cpu_to_le32(msg->middle.iov_len);

		req = msg->front.iov_base;
		req->req_id = cpu_to_le64(request->id);
		req->pool_id = cpu_to_le32(get_poolid_from_fake(
					mapping->host->i_sb->cleancache_poolid));
		req->ino = cpu_to_le64(mapping->host->i_ino);

		middle = msg->middle.iov_base;
		/*
		 * Add first page to the middle
		 */
		if (test_bit(REMOTECACHE_REQUEST_HAS_PAGES, &request->flags))
			middle->index =	cpu_to_le64(request->pages[sent]->index);
		else
			middle->index = cpu_to_le64(request->page->index);
		middle->nr_pages = 1;

		/*
		 * Increment middle->nr_pages until a hole is found
		 */
		for (i = 1; i < nr_to_send; ++i) {
			struct page *page = request->pages[i + sent];
			if (page->index == (le64_to_cpu(middle->index) + middle->nr_pages)) {
				middle->nr_pages++;
			} else {
				middle = msg->middle.iov_base +
					msg->middle.iov_len;
				msg->middle.iov_len += sizeof(struct rc_get_request_middle);
				middle->index = cpu_to_le64(page->index);
				middle->nr_pages = 1;
			}
		}

		msg->header.middle_len = cpu_to_le32(msg->middle.iov_len);
		rc_msg_set_flag(msg, RC_MSG_FLAG_URG);
		rc_con_send(&session->con, msg);

		this_node->stats.nget_msg++;
		sent += nr_to_send;
	} while (sent != request->nr_pages);
	this_node->stats.nget += sent;
}

void remotecache_node_readpage_sync(struct file *file, struct page *page)
{
	struct remotecache_request *request;
	struct remotecache_session *session;

	rc_debug("%s file %s index %lu", __func__,
			file ? file->f_dentry->d_name.name : NULL,
			page->index);

	if (!cleancache_fs_enabled(page)) {
		rc_debug("%s: cleancache disabled", __func__);
		return;
	}

	session = remotecache_node_session(this_node);
	if (!session) {
		rc_debug("%s: not connected to a remote node\n", __func__);
		return;
	}

	request = remotecache_request_create(session, 0);
	if (!request) {
		pr_err("Can't allocate request");
		return;
	}

	__set_bit(REMOTECACHE_REQUEST_SYNC, &request->flags);

	if (__request_add_page(page, page->mapping, request)) {
		mutex_lock(&session->r_lock);
		list_add_tail(&request->list, &session->requests);
		mutex_unlock(&session->r_lock);

		if (request->page) {
			__send_request(session, request, page->mapping);

			while (!atomic_read(&request->nr_received) &&
					!test_bit(REMOTECACHE_REQUEST_CANCELED,
						&request->flags)) {
				DEFINE_WAIT(wait);

				prepare_to_wait(&wait_readpage_sync, &wait,
						TASK_UNINTERRUPTIBLE);
				if (!atomic_read(&request->nr_received))
					schedule();
				finish_wait(&wait_readpage_sync, &wait);
			}
		}
	}
	remotecache_request_put(request);
}

int remotecache_node_readpage(struct file *file, struct page *page)
{
	struct remotecache_request *request;
	struct remotecache_session *session;

	rc_debug("%s file %s index %lu", __func__,
			file ? file->f_dentry->d_name.name : NULL,
			page->index);

	if (!cleancache_fs_enabled(page)) {
		rc_debug("%s: cleancache disabled", __func__);
		goto readpage;
	}

	session = remotecache_node_session(this_node);
	if (!session) {
		rc_debug("%s: not connected to a remote node\n", __func__);
		goto readpage;
	}

	request = remotecache_request_create(session, 0);
	if (!request) {
		pr_err("Can't allocate request");
		goto readpage;
	}

	if (__request_add_page(page, page->mapping, request)) {
		mutex_lock(&session->r_lock);
		list_add_tail(&request->list, &session->requests);
		mutex_unlock(&session->r_lock);

		if (request->page)
			__send_request(session, request, page->mapping);
		remotecache_request_put(request);
	} else {
		remotecache_request_put(request);
		goto readpage;
	}

	return 0;

readpage:
	return page->mapping->a_ops->readpage(file, page);
}

void remotecache_node_ll_rw_block(int rw, struct buffer_head *bh)
{
	struct address_space *mapping = bh->b_page->mapping;

	rc_debug("%s bh %p page %p ino %lu index %lu\n", __func__,
			bh, bh->b_page, mapping->host->i_ino,
			bh->b_page->index);

	if (cleancache_fs_enabled(bh->b_page)) {
		cleancache_invalidate_page(mapping, bh->b_page);
	}

	submit_bh(rw, bh);
}

/*
 * Count contiguously cached pages from @offset-1 to @offset-@max,
 * this count is a conservative estimation of
 * 	- length of the sequential read sequence, or
 * 	- thrashing threshold in memory tight systems
 */
static pgoff_t count_history_pages(struct address_space *mapping,
				   pgoff_t offset, unsigned long max)
{
	pgoff_t head;

	rcu_read_lock();
	head = page_cache_prev_hole(mapping, offset - 1, max);
	rcu_read_unlock();

	return offset - 1 - head;
}

int remotecache_node_readpages(struct file *file,
		struct address_space *mapping, struct list_head *pages,
		unsigned nr_pages)
{
	struct page *page, *next;
	struct remotecache_request *request;
	struct remotecache_session *session;
	unsigned nr_to_read = nr_pages;
	pgoff_t history_size, prev_offset = -1;
	static ino_t prev_ino = 0;

	rc_debug("%s %s nr_pages %u\n", __func__,
			file->f_dentry->d_name.name, nr_pages);

	if (!cleancache_fs_enabled_mapping(mapping)) {
		rc_debug("%s cleancache disabled", __func__);
		goto readpages;
	}

	session = remotecache_node_session(this_node);
	if (!session) {
		rc_debug("%s: not connected to a remote node\n", __func__);
		goto readpages;
	}

	request = remotecache_request_create(session, nr_pages);
	if (!request) {
		rc_debug("Can't allocate pending");
		goto readpages;
	}

	mutex_lock(&session->r_lock);
	list_add_tail(&request->list, &session->requests);
	mutex_unlock(&session->r_lock);

	history_size = count_history_pages(mapping, file->f_ra.start, 128);
	if (file->f_ra.prev_pos != -1)
		prev_offset = (unsigned long long)file->f_ra.prev_pos >> PAGE_CACHE_SHIFT;

	list_for_each_entry_safe_reverse(page, next, pages, lru) {
		if (file->f_ra.size >= file->f_ra.ra_pages && history_size >= 128) {
			SetPageKeepLocal(page);
		}
		if (__request_add_page(page, mapping, request)) {
			nr_to_read--;
		}
	}

	prev_ino = mapping->host->i_ino;

	if (request->nr_pages)
		__send_request(session, request, mapping);

	if (!list_empty(pages)) {
		/*
		 * Some pages cannot be read from remote cache, read them from
		 * disk
		 */
		remotecache_request_put(request);
		goto readpages;
	}

	remotecache_request_put(request);

	return 0;

readpages:
	return mapping->a_ops->readpages(file, mapping, pages, nr_to_read);
}

struct cleancache_ops session_cleancache_ops = {
	.init_fs = __remotecache_init_fs,
	.init_shared_fs = __remotecache_init_shared_fs,
	.get_page = __remotecache_get_page,
	.put_page = __remotecache_put_page,
	.invalidate_page = __remotecache_invalidate_page,
	.invalidate_inode = __remotecache_invalidate_inode,
	.invalidate_fs = __remotecache_invalidate_fs
};

struct rc_connection_operations session_ops = {
	.get = remotecache_session_con_get,
	.put = remotecache_session_con_put,
	.dispatch = remotecache_session_dispatch,
	.acked = remotecache_session_acked,
	.alloc_msg = remotecache_session_alloc_msg,
	.alloc_data = remotecache_session_alloc_data,
	.fault = remotecache_session_fault,
};
