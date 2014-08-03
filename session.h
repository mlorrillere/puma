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
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
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

	spinlock_t c_lock;	 /* lock to protect ->caches */

	spinlock_t r_lock;	 /* lock to protect ->requests */

	unsigned long flags;

	/* TODO: remote statistics (memory, latency, bandwidth, cpu usage) */
};

enum remotecache_session_flags {
	REMOTECACHE_SESSION_SUSPENDED
};

/* Tracking of remotecache requests */
struct remotecache_request {
	struct kref kref;
	unsigned long id;	/* request-id */
	struct timespec stamp;	/* timestamp used for response time
				   calculation */

	struct remotecache_session *session;

	struct list_head list;

	union {
		struct page **pages;
		struct page *page;
	};

	unsigned nr_pages;	/* Number of pages */
	atomic_t nr_received;	/* Number of pages already handled */
	bool has_pages;		/* use of ->page or ->pages ? */
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

void remotecache_session_close(struct remotecache_session *session);
struct remotecache_session *remotecache_session_create(struct remotecache_node *);

bool __invalidate_page(struct remotecache_session *session,
		int pool_id, ino_t ino, pgoff_t index);
#endif //SESSION_H
