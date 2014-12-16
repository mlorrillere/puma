/*
 * node.h
 *
 * Copyright (C) 2014
 * Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 * LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef NODE_H
#define NODE_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/uuid.h>
#include <linux/timer.h>

#include "messenger.h"
#include "stats.h"

extern unsigned short remotecache_port;
extern ulong remotecache_max_size;
extern bool remotecache_strategy;

struct remotecache_node {
	struct kref kref;

	struct rc_stats stats;		/* sysfs statistics */

	/* local metadata */
	struct list_head metadata;
	struct mutex m_lock;		/* lock to protect ->metadata */

	/* Remote connections */
	struct rc_connection con; 	/* Listen connection */
	struct list_head sessions;
	struct mutex s_lock; 		/* lock to protect ->sessions */

	struct timer_list suspend_timer;

	unsigned long flags;
};

enum remotecache_node_flags {
	REMOTECACHE_NODE_SUSPENDED,
	REMOTECACHE_NODE_CLOSED
};

extern struct remotecache_node *this_node;

extern mempool_t *remotecache_page_pool;
extern struct rc_msgpool remotecache_get_cachep;
extern struct rc_msgpool remotecache_get_response_cachep;
extern struct rc_msgpool remotecache_put_cachep;
extern struct rc_msgpool remotecache_inv_cachep;

void remotecache_node_last_put(struct kref *ref);

static inline void remotecache_node_get(struct remotecache_node *node)
{
	kref_get(&node->kref);
}

static inline void remotecache_node_put(struct remotecache_node *node)
{
	kref_put(&node->kref, remotecache_node_last_put);
}

struct remotecache *remotecache_node_metadata(struct remotecache_node *node,
		int pool_id, uuid_le uuid);

/* Returns a session to be used.
 *
 * This is transitionnal code, we have to choose the best suited session
 */
struct remotecache_session *remotecache_node_session(
		struct remotecache_node *node);

int remotecache_node_readpages(struct file *file,
		struct address_space *mapping, struct list_head *pages,
		unsigned nr_pages);
int remotecache_node_readpage(struct file *file, struct page *page);
void remotecache_node_readpage_sync(struct file *file, struct page *page);
void remotecache_node_ll_rw_block(int rw, struct buffer_head *bh);
#endif //NODE_H
