/*
 * session.h
 *
 * Copyright (C) 2014
 * Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 * LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef SESSION_H
#define SESSION_H

#include <linux/time.h>
#include <linux/hrtimer.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/cleancache.h>

#include "messenger.h"

struct remotecache_node;

struct remotecache_session {
	struct kref kref;

	struct rc_connection con; /* connection to the remote host */

	struct list_head list;

	struct list_head requests;	/* pending requests */

	struct remotecache_node *node;

	struct list_head caches; /* Caches for this host */

	struct mutex c_lock;	 /* lock to protect ->caches */

	struct mutex r_lock;	 /* lock to protect ->requests */

	unsigned long available;	/* remote cache size (estimation) */

	unsigned long flags;

	/* TODO: remote statistics (memory, latency, bandwidth, cpu usage) */
	u64 latency;
	u64 latency_15;
};

enum remotecache_session_flags {
	REMOTECACHE_SESSION_SUSPENDED,
	REMOTECACHE_SESSION_HEARTBEAT,
	REMOTECACHE_SESSION_HEARTBEAT_PENDING,
};

enum remotecache_request_flags {
	REMOTECACHE_REQUEST_HAS_PAGES,
	REMOTECACHE_REQUEST_SYNC,
	REMOTECACHE_REQUEST_CANCELED
};

/* Tracking of remotecache requests */
struct remotecache_request {
	struct kref kref;
	spinlock_t lock;
	unsigned long id;	/* request-id */
	unsigned long flags;
	struct timespec stamp;	/* timestamp used for response time
				   calculation */
	struct hrtimer timer;

	struct remotecache_session *session;

	struct list_head list;

	union {
		struct page **pages;
		struct page *page;
	};

	struct buffer_head *bh;

	unsigned nr_pages;	/* Number of pages */
	atomic_t nr_received;	/* Number of pages already handled */
};

extern struct rc_connection_operations session_ops;
extern struct cleancache_ops session_cleancache_ops;

void remotecache_session_last_put(struct kref *ref);

static inline void remotecache_session_get(struct remotecache_session *session)
{
	kref_get(&session->kref);
}

static inline void remotecache_session_put(struct remotecache_session *session)
{
	kref_put(&session->kref, remotecache_session_last_put);
}

static inline void remotecache_session_suspend(struct remotecache_session *session)
{
       set_bit(REMOTECACHE_SESSION_SUSPENDED, &session->flags);
}

static inline void remotecache_session_resume(struct remotecache_session *session)
{
       clear_bit(REMOTECACHE_SESSION_SUSPENDED, &session->flags);
}

static inline bool remotecache_session_is_suspended(struct remotecache_session *session)
{
       return test_bit(REMOTECACHE_SESSION_SUSPENDED, &session->flags);
}

void remotecache_session_close(struct remotecache_session *session);
struct remotecache_session *remotecache_session_create(struct remotecache_node *);

bool do_invalidate_page(struct remotecache_session *session,
		int pool_id, ino_t ino, pgoff_t index, bool metadata);
#endif //SESSION_H
