/*
 *	node.h
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/remotecache.h>

#include "node.h"
#include "session.h"
#include "remotecache.h"
#include "cache.h"
#include "metadata.h"
#include "msgpool.h"

struct remotecache_node *this_node;
static struct cleancache_ops *cleancache_old_ops = NULL;

/*
 * Forward declarations
 */
static void remotecache_node_destroy(struct remotecache_node *node);
static struct rc_connection *remotecache_node_con_get(struct rc_connection *con);
static void remotecache_node_con_put(struct rc_connection *con);
static void remotecache_node_fault(struct rc_connection *con);
static struct rc_connection *remotecache_node_accept(
		struct rc_connection *con);
static ssize_t node_show_stats(struct rc_stats *stats, char *buf);
static int remotecache_node_connect(struct remotecache_node *node,
		const char *ip, short port);
static void remotecache_node_start_plug(struct remotecache_plug *plug);
static void remotecache_node_finish_plug(struct remotecache_plug *plug);
static void remotecache_node_flush_plug(struct task_struct *tsk);
static void remotecache_node_releasepage(struct page *page);

/*
 * Module parameters
 */
unsigned short remotecache_port = REMOTECACHE_PORT;
ulong remotecache_max_size __read_mostly = 1<<19;
bool remotecache_strategy __read_mostly = true;

module_param_named(port, remotecache_port, ushort, 0444);
module_param_named(store_size, remotecache_max_size, ulong, 0444);
module_param_named(inclusive_strategy, remotecache_strategy, bool, 0444);

/*
 * caches/pools
 */
mempool_t *remotecache_page_pool __read_mostly;
extern struct kmem_cache *remotecache_request_cachep;
struct rc_msgpool remotecache_get_cachep __read_mostly;
struct rc_msgpool remotecache_get_response_cachep __read_mostly;
struct rc_msgpool remotecache_put_cachep __read_mostly;
struct rc_msgpool remotecache_inv_cachep __read_mostly;

static void *__page_pool_alloc(gfp_t gfp_mask, void *data)
{
	/*
	 * When GFP_NOWAIT is used on this pool, we actually expect to get a
	 * page from the pool or nothing. This is to avoid to pick too many
	 * free pages and then run into an OOM kill.
	 */
	if (!(gfp_mask & __GFP_WAIT))
		return NULL;

	return alloc_pages(gfp_mask, 0);
}

static void __page_pool_free(void *element, void *data)
{
	__free_pages(element, 0);
}

static int __init init_caches(void)
{
	int err;

	err = rc_msgpool_init(&remotecache_get_cachep, RC_MSG_TYPE_GET,
			sizeof(struct rc_get_request),
			sizeof(struct rc_get_request_middle)*128,
			0, PAGES_PER_GET, "GET message pool");
	if (err != 0) {
		pr_err("%s: failed to initialize GET message pool", __func__);
		return -ENOMEM;
	}

	err = rc_msgpool_init(&remotecache_get_response_cachep,
			RC_MSG_TYPE_GET_RESPONSE,
			sizeof(struct rc_get_response),
			sizeof(struct rc_get_response_middle)*128,
			PAGES_PER_GET, PAGES_PER_GET,
			"GET_RESPONSE message pool");
	if (err != 0) {
		pr_err("%s: failed to initialize GET_RESPONSE message pool",
				__func__);
		goto bad_get_response;
	}

	err = rc_msgpool_init(&remotecache_put_cachep, RC_MSG_TYPE_PUT,
			sizeof(struct rc_put_request),
			sizeof(struct rc_put_request_middle)*PAGES_PER_PUT,
			PAGES_PER_PUT, (1 << 10), "PUT message pool");
	if (err != 0) {
		pr_err("%s: failed to initialize PUT message pool", __func__);
		goto bad_put;
	}

	err = rc_msgpool_init(&remotecache_inv_cachep,
			RC_MSG_TYPE_INVALIDATE_PAGE,
			sizeof(struct rc_invalidate_page_request),
			sizeof(struct rc_invalidate_page_request_middle)*64,
			0, 64, "INVALIDATE_PAGE message pool");
	if (err != 0) {
		pr_err("%s: failed to initialize INVALIDATE_PAGE message pool",
				__func__);
		goto bad_inv;
	}

	/*
	 * Allow up to 32 messages sent without blocking the PFRA into
	 * wait_for_remote_pages
	 * Note that we cannot mempool_create_page_pool as explained in
	 * comment of __page_pool_alloc.
	 */
	remotecache_page_pool = mempool_create(PAGES_PER_PUT*32,
			__page_pool_alloc, __page_pool_free, NULL);
	if (!remotecache_page_pool) {
		pr_err("%s: failed to initialize pages pool", __func__);
		goto bad_page_pool;
	}

	return 0;

bad_page_pool:
	rc_msgpool_destroy(&remotecache_inv_cachep);
bad_inv:
	rc_msgpool_destroy(&remotecache_put_cachep);
bad_put:
	rc_msgpool_destroy(&remotecache_get_response_cachep);
bad_get_response:
	rc_msgpool_destroy(&remotecache_get_cachep);
	return -ENOMEM;
}

static void destroy_caches(void)
{
	rc_msgpool_destroy(&remotecache_get_cachep);
	rc_msgpool_destroy(&remotecache_get_response_cachep);
	rc_msgpool_destroy(&remotecache_put_cachep);
	rc_msgpool_destroy(&remotecache_inv_cachep);
	mempool_destroy(remotecache_page_pool);
}



void remotecache_node_last_put(struct kref *ref)
{
	struct remotecache_node *node = container_of(ref,
			struct remotecache_node, kref);

	/*
	 * We are not supposed to go to this point since currently we do not
	 * release the last reference (this_node) but we manually destroy the
	 * node.
	 */
	BUG();
}

static void remotecache_node_close(struct remotecache_node *node)
{
	LIST_HEAD(sessions);
	LIST_HEAD(metadata);
	struct remotecache_session *session;
	struct remotecache_metadata *m;
	unsigned long flags;

	pr_err("%s close node %p\n", __func__, node);

	/* stop accepting new connections */
	rc_con_close(&node->con);

	/* close and free remote nodes */
	spin_lock_irqsave(&node->s_lock, flags);
	list_splice_init(&node->sessions, &sessions);
	spin_unlock_irqrestore(&node->s_lock, flags);

	while (!list_empty(&sessions)) {
		session = list_first_entry(&sessions,
				struct remotecache_session, list);
		remotecache_session_put(session);
	}

	/* clear local metadata */
	spin_lock_irqsave(&node->m_lock, flags);
	list_splice_init(&node->metadata, &metadata);
	spin_unlock_irqrestore(&node->m_lock, flags);

	while (!list_empty(&metadata)) {
		m = list_first_entry(&metadata, struct remotecache_metadata, list);
		list_del_init(&m->list);
		remotecache_metadata_put(m);
	}

	/* wait for messenger work queue to finish */
	rc_messenger_flush();
}

static void remotecache_node_destroy(struct remotecache_node *node)
{
	rc_debug("%s destroy node %p\n", __func__, node);

	rc_stats_destroy(&node->stats);

	WARN_ON(atomic_read(&node->kref.refcount) != 1);
	BUG_ON(atomic_read(&node->kref.refcount) != 1);

	kfree(node);
}

/*
 * Network/connection related functions
 */

static struct rc_connection *remotecache_node_con_get(struct rc_connection *con)
{
	struct remotecache_node *node =
		container_of(con, struct remotecache_node, con);

	rc_debug("%s %p\n", __func__, con);
	if (kref_get_unless_zero(&node->kref))
		return con;
	return NULL;
}

static void remotecache_node_con_put(struct rc_connection *con)
{
	struct remotecache_node *node =
		container_of(con, struct remotecache_node, con);

	rc_debug("%s %p\n", __func__, con);
	remotecache_node_put(node);
}

static void remotecache_node_fault(struct rc_connection *con)
{
	struct remotecache_node *node = container_of(con,
			struct remotecache_node, con);

	pr_err("%s received fault %s", __func__, con->error_msg);
}

/*
 * Suspend/resume logic
 */
static void remotecache_node_suspend(struct remotecache_node *node)
{
	unsigned long flags;
	struct remotecache_session *session;
	struct rc_msg *msg;

	if (!test_and_set_bit(REMOTECACHE_NODE_SUSPENDED, &node->flags)) {
		rc_debug("%s: suspend remote cache node\n", __func__);

		spin_lock_irqsave(&node->s_lock, flags);
		list_for_each_entry(session, &node->sessions, list) {
			rc_debug("%s suspend session %s\n", __func__,
					rc_pr_addr(&session->con.peer_addr));
			msg = rc_msg_new(RC_MSG_TYPE_SUSPEND, 0, 0, 0,
					GFP_NOWAIT, 0);
			if (msg) {
				 rc_con_send(&session->con, msg);
			} else {
				 pr_err("%s: failed to alloc suspend message\n",
					__func__);
			}
		}
		spin_unlock_irqrestore(&node->s_lock, flags);
	} else {
		pr_warn("%s: server already suspended\n", __func__);
	}
}

static void remotecache_node_resume(struct remotecache_node *node)
{
	unsigned long flags;
	struct remotecache_session *session;
	struct rc_msg *msg;

	if (test_and_clear_bit(REMOTECACHE_NODE_SUSPENDED, &node->flags)) {
		rc_debug("%s: resume remote cache node\n", __func__);

		spin_lock_irqsave(&node->s_lock, flags);
		list_for_each_entry(session, &node->sessions, list) {
			rc_debug("%s resume session %s\n", __func__,
					rc_pr_addr(&session->con.peer_addr));
			msg = rc_msg_new(RC_MSG_TYPE_RESUME, 0, 0, 0,
					GFP_NOWAIT, 0);
			if (msg) {
				 rc_con_send(&session->con, msg);
			} else {
				 pr_err("%s: failed to alloc resume message\n",
						 __func__);
			}
		}
		spin_unlock_irqrestore(&node->s_lock, flags);
	} else {
		pr_warn("%s: server already running\n", __func__);
	}
}

static void remotecache_node_suspend_op(void)
{
	if (this_node)
		remotecache_node_suspend(this_node);
}

static void remotecache_node_resume_op(void)
{
	if (this_node)
		remotecache_node_resume(this_node);
}

static int remotecache_node_suspend_param_set(const char *val, const struct kernel_param *kp)
{
	bool b;
	int err = 0;

	if (!val || !this_node)
		 return -EINVAL;

	if ((err = strtobool(val, &b)) != 0)
		 return err;

	if (b)
		 remotecache_node_suspend(this_node);
	else
		 remotecache_node_resume(this_node);

	return err;
}

static int remotecache_node_suspend_param_get(char *buffer, const struct kernel_param *kp)
{
	if (!this_node)
		return -EINVAL;

	return sprintf(buffer, "%c",  test_bit(REMOTECACHE_NODE_SUSPENDED,
				&this_node->flags) ? 'Y' : 'N');
}

struct kernel_param_ops remotecache_node_suspend_param_ops = {
	.set = remotecache_node_suspend_param_set,
	.get = remotecache_node_suspend_param_get
};

module_param_cb(suspend, &remotecache_node_suspend_param_ops , NULL, 0644);

static struct remotecache_ops remotecache_node_ops = {
	.start_plug = remotecache_node_start_plug,
	.finish_plug = remotecache_node_finish_plug,
	.flush_plug = remotecache_node_flush_plug,
	.releasepage = remotecache_node_releasepage,
	.readpage = remotecache_node_readpage,
	.readpages = remotecache_node_readpages,
	.suspend = remotecache_node_suspend_op,
	.resume = remotecache_node_resume_op
};

/*
 * Local node initialization
 */
static struct rc_connection *remotecache_node_accept(struct rc_connection *con)
{
	unsigned long flags;
	struct remotecache_node *node;
	struct remotecache_session *session;

	node = container_of(con, struct remotecache_node, con);
	session = remotecache_session_create(node);

	if (!session)
		return NULL;

	rc_con_init(&session->con, con->private, &session_ops, &node->stats);

	spin_lock_irqsave(&node->s_lock, flags);
	list_add_tail(&session->list, &node->sessions);
	spin_unlock_irqrestore(&node->s_lock, flags);

	return &session->con;
}

struct remotecache_session *remotecache_node_session(
		struct remotecache_node *node)
{
	struct remotecache_session *session = NULL;
	unsigned long flags;

	spin_lock_irqsave(&node->s_lock, flags);
	if (!list_empty(&node->sessions))
		session = list_first_entry(&node->sessions,
				struct remotecache_session, list);
	spin_unlock_irqrestore(&node->s_lock, flags);

	return session;
}

static void remotecache_node_start_plug(struct remotecache_plug *plug)
{
	rc_con_start_plug(plug);
}

static void remotecache_node_finish_plug(struct remotecache_plug *plug)
{
	struct remotecache_session *session;
	session = remotecache_node_session(this_node);

	/*
	 * XXX: The connection might close while some message are. We have to
	 * handle cancellation at some point...
	 */
	BUG_ON(!list_empty(&plug->list) && !session);

	if (!session)
		rc_con_finish_plug(NULL, plug);
	else
		rc_con_finish_plug(&session->con, plug);
}

static void remotecache_node_flush_plug(struct task_struct *tsk)
{
	struct remotecache_session *session;

	if (remotecache_needs_flush_plug(tsk)) {
		session = remotecache_node_session(this_node);
		BUG_ON(!session);

		rc_con_flush_plug(&session->con, tsk);
	}
}

static void remotecache_node_releasepage(struct page *page) {
	struct remotecache_page *rcp = (void*)page->private;
	struct remotecache *cache = rcp->cache;
	struct remotecache_session *session = cache->session;
	unsigned long flags;

	BUG_ON(!test_and_clear_bit(RC_PAGE_HAS_PAGE, &rcp->flags));

	ClearPagePrivate(page);
	ClearPageRemote(page);
	set_page_private(page, 0);
	__dec_zone_page_state(page, NR_FILE_PAGES);
	put_page(page);
	rcp->private = NULL;

	if (!__invalidate_page(session, cache->pool_id, rcp->ino, rcp->index)) {
		pr_warn("%s: cannot invalidate rcp %p (%d,%lu,%lu)", __func__,
				rcp, cache->pool_id, rcp->ino, rcp->index);
	}
	spin_lock_irqsave(&cache->lock, flags);
	__remotecache_remove(cache, rcp);
	spin_unlock_irqrestore(&cache->lock, flags);
}

struct remotecache_metadata *remotecache_node_metadata(struct remotecache_node *node,
		int pool_id, uuid_le uuid)
{
	unsigned long flags;
	struct remotecache_metadata *metadata;

	/* TODO: do the work with UUID */
	spin_lock_irqsave(&node->m_lock, flags);
	list_for_each_entry(metadata, &node->metadata, list) {
		if (metadata->pool_id == pool_id) {
			remotecache_metadata_get(metadata);
			spin_unlock_irqrestore(&node->m_lock, flags);
			return metadata;
		}
	}
	spin_unlock_irqrestore(&node->m_lock, flags);

	return NULL;
}

static struct rc_connection_operations node_ops = {
	.get = remotecache_node_con_get,
	.put = remotecache_node_con_put,
	.accept = remotecache_node_accept,
	.fault = remotecache_node_fault,
	//.acked = server_acked
};

static int init_node_network(struct remotecache_node *node)
{
	int err;
	struct sockaddr_storage addr;

	if (!rc_set_addr(&addr, "0.0.0.0", remotecache_port)) {
		pr_err("Cannot set address %s:%hu", "0.0.0.0", remotecache_port);
		return -EINVAL;
	}

	rc_con_init(&node->con, node, &node_ops, &node->stats);

	/*
	 * Lock the mutex to block incomming connections until we are ready.
	 */
	mutex_lock(&node->con.mutex);

	if ((err = rc_con_listen(&node->con, (struct sockaddr*)&addr)) != 0) {
		mutex_unlock(&node->con.mutex);
		printk(KERN_ERR "rc_con_listen error %d", err);
		return err;
	}

	return 0;
}

static int remotes_param_set(const char *val, const struct kernel_param *kp)
{
	struct remotecache_session *s;
	unsigned long flags;

	char *ip = (char *)val;
	char *str_port = strrchr(val, ':');
	u16 port;
	int err;

	if (!this_node)
		return -EINVAL;

	if (str_port && *str_port)
		str_port++;

	if (!str_port) {
		port = REMOTECACHE_PORT;
	} else if ((err = kstrtou16(str_port, 10, &port)) != 0) {
		pr_err("not a valid port number: %s\n", str_port);
		return err;
	}

	*str_port = '\0';

	/*
	 * We check if we are not already connected to this remote host.
	 * TODO: check only against IP address, not IP:PORT
	 */
	spin_lock_irqsave(&this_node->s_lock, flags);
	list_for_each_entry(s, &this_node->sessions, list) {
		if (strstr(rc_pr_addr(&s->con.peer_addr), ip)) {
			spin_unlock_irqrestore(&this_node->s_lock, flags);
			pr_err("node already connected to host %s\n", val);
			return -EISCONN;
		}
	}
	spin_unlock_irqrestore(&this_node->s_lock, flags);

	/*
	 * Connect to the remote host
	 */
	if ((err = remotecache_node_connect(this_node, ip, port)) != 0)
	{
		pr_err("%s: unable to connect to remote host %s\n",
				__func__, val);
		return err;
	}

	return 0;
}

static int remotes_param_get(char *buf, const struct kernel_param *kp)
{
	struct remotecache_session *s;
	unsigned long flags;
	int count = 0;

	if (!this_node)
		return -EINVAL;

	spin_lock_irqsave(&this_node->s_lock, flags);
	list_for_each_entry(s, &this_node->sessions, list) {
		count += scnprintf(buf+count, PAGE_SIZE-count,
			"%s\n", rc_pr_addr(&s->con.peer_addr));
	}
	spin_unlock_irqrestore(&this_node->s_lock, flags);

	return count;
}

struct kernel_param_ops remotes_param_ops = {
	.set = remotes_param_set,
	.get = remotes_param_get
};

module_param_cb(remotes, &remotes_param_ops, NULL, 0644);

static struct remotecache_node *create_node(void)
{
	int err;
	struct remotecache_node *node = kzalloc(sizeof(*node), GFP_KERNEL);

	if (!node)
		return ERR_PTR(-ENOMEM);

	kref_init(&node->kref);

	if ((err = rc_stats_init(&__this_module.mkobj.kobj, &node->stats)) != 0)
		goto bad_stats;

	node->stats.show = node_show_stats;

	INIT_LIST_HEAD(&node->metadata);
	INIT_LIST_HEAD(&node->sessions);
	spin_lock_init(&node->s_lock);
	spin_lock_init(&node->m_lock);
	node->flags = 0;

	if ((err = init_node_network(node)) != 0)
		goto bad_network;

	pr_err("%s: node %p created\n", __func__, node);

	/*
	 * TODO: register rc_server_ops
	 */
	return node;

bad_network:
	rc_stats_destroy(&node->stats);
bad_stats:
	kfree(node);
	return ERR_PTR(err);
}

static int enable_param_set(const char *val, const struct kernel_param *kp)
{
	int err;

	if (!*val)
		return -EINVAL;

	if (*val == '1' && !this_node) {
		this_node = create_node();

		if (IS_ERR(this_node)) {
			err = PTR_ERR(this_node);
			pr_err("%s: unable to create node\n", __func__);
			return err;
		}

		cleancache_old_ops = cleancache_register_ops(&session_cleancache_ops);
		remotecache_register_ops(&remotecache_node_ops);

		/*
		 * Node created and ops registered, we are ready to process incomming
		 * connections
		 */
		mutex_unlock(&this_node->con.mutex);
	} else if (*val == '0' && this_node) {
		struct remotecache_node *n = this_node;

		cleancache_register_ops(cleancache_old_ops);
		remotecache_node_close(this_node);
		remotecache_register_ops(NULL);
		barrier();
		this_node = NULL;
		remotecache_node_destroy(n);
	} else {
		return -EINVAL;
	}

	return 0;
}

struct kernel_param_ops enable_param_ops = {
	.set = enable_param_set
};

module_param_cb(enable, &enable_param_ops, NULL, 0200);

static int remotecache_node_init(void)
{
	int err = 0;

	err = rc_messenger_init();
	if (err)
		return err;

	err = init_caches();
	if (err)
		goto bad_messenger;

	return 0;

bad_messenger:
	rc_messenger_exit();

	return err;
}

static void remotecache_node_exit(void)
{
	pr_err("%s\n", __func__);
	/*
	 * TODO: block until node is disabled
	 */
	destroy_caches();
	rc_messenger_exit();
}

static int remotecache_node_connect(struct remotecache_node *node,
		const char *ip, short port)
{
	unsigned long flags;
	struct remotecache_session *session;
	struct sockaddr_storage addr;

	session = remotecache_session_create(node);

	if (!session)
		return -ENOMEM;

	rc_con_init(&session->con, session, &session_ops, &node->stats);

	if (!rc_set_addr(&addr, ip, port)) {
		pr_err("Cannot set address %s:%hu", ip, port);
		goto bad_address;
	}

	spin_lock_irqsave(&node->s_lock, flags);
	list_add_tail(&session->list, &node->sessions);
	spin_unlock_irqrestore(&node->s_lock, flags);

	pr_info("%s: connecting to %pISpc\n", __func__, &addr);

	rc_con_open(&session->con, (struct sockaddr*)&addr);

	return 0;

bad_address:
	remotecache_session_put(session);
	return -EINVAL;

}

static ssize_t node_show_stats(struct rc_stats *stats, char *buf)
{
	ssize_t count = 0;
	unsigned long flags;
	struct remotecache *m, *c;
	struct remotecache_session *s;
	struct remotecache_node *n = container_of(stats,
			struct remotecache_node, stats);
	struct timespec get_avg, get_msg_avg, put_avg, put_msg_avg;

	get_avg = timespec_avg(&n->stats.get_avg_time, n->stats.nget);
	get_msg_avg = timespec_avg(&n->stats.get_avg_time,
			n->stats.nget_msg);
	put_avg = timespec_avg(&n->stats.put_avg_time, n->stats.nput);
	put_msg_avg = timespec_avg(&n->stats.put_avg_time,
			n->stats.nput_msg);

	/* Summary version, better for parsing */
	count += scnprintf(buf, PAGE_SIZE,
			"%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu "
			"%lu.%09lu %lu.%09lu %lu.%09lu %lu.%09lu "
			"%lu.%09lu %lu.%09lu %lu.%09lu %lu.%09lu",
			n->stats.nget, n->stats.nget_msg,
			n->stats.n_rc_hit + n->stats.n_rc_miss,
			n->stats.nput, n->stats.nput_msg,
			n->stats.nput_acked,
		      n->stats.n_non_dirtied_put,
		      n->stats.n_invalidate_pages,
		      n->stats.n_invalidate_inodes,
		      n->stats.n_remote_invalidate,
		      n->stats.n_rc_hit, n->stats.n_rc_miss,
		      n->stats.n_rc_miss_avoided,
		      get_avg.tv_sec, get_avg.tv_nsec,
		      get_msg_avg.tv_sec, get_msg_avg.tv_nsec,
		      n->stats.get_min_time.tv_sec,
		      n->stats.get_min_time.tv_nsec,
		      n->stats.get_max_time.tv_sec,
			n->stats.get_max_time.tv_nsec,
			put_avg.tv_sec, put_avg.tv_nsec,
			put_msg_avg.tv_sec, put_msg_avg.tv_nsec,
			n->stats.put_min_time.tv_sec,
			n->stats.put_min_time.tv_nsec,
			n->stats.put_max_time.tv_sec,
			n->stats.put_max_time.tv_nsec);

	count += scnprintf(buf+count, PAGE_SIZE-count, "\n\nmetadata:\n");

	spin_lock_irqsave(&n->s_lock, flags);
	list_for_each_entry(m, &n->metadata, list) {
		count += scnprintf(buf+count, PAGE_SIZE-count,
				"\t%pUl %d %d\n", &m->uuid, m->pool_id,
				atomic_read(&m->size));
	}
	spin_unlock_irqrestore(&n->s_lock, flags);

	count += scnprintf(buf+count, PAGE_SIZE-count, "\n\nsessions:\n");

	spin_lock_irqsave(&n->m_lock, flags);
	list_for_each_entry(s, &n->sessions, list) {
		count += scnprintf(buf+count, PAGE_SIZE-count,
			"\thost: %s\n", rc_pr_addr(&s->con.peer_addr));
		list_for_each_entry(c, &s->caches, list) {
			count += scnprintf(buf+count, PAGE_SIZE-count,
				"\t\t%pUl %d %d\n", &c->uuid, c->pool_id,
				atomic_read(&c->size));
		}
	}
	spin_unlock_irqrestore(&n->m_lock, flags);

	count += scnprintf(buf+count, PAGE_SIZE-count, "statistics:\n");
	count += scnprintf(buf+count, PAGE_SIZE-count,
			"\tget (pages, messages): %lu %lu\n"
			"\tget response (hit+miss): %lu\n"
			"\tput (pages, messages): %lu %lu\n"
			"\tput acked: %lu\n"
			"\tnon dirtied put: %lu\n"
			"\tinvalidate pages: %lu\n"
			"\tinvalidate inodes: %lu\n"
			"\tremote invalidate pages: %lu\n"
			"\trc hit: %lu\n"
			"\trc miss: %lu\n"
			"\trc miss avoided: %lu\n"
			"\tget delay: %lu.%09lu %lu.%09lu %lu.%09lu %lu.%09lu\n"
			"\tput delay: %lu.%09lu %lu.%09lu %lu.%09lu %lu.%09lu\n",
			n->stats.nget, n->stats.nget_msg,
			n->stats.n_rc_hit + n->stats.n_rc_miss,
			n->stats.nput, n->stats.nput_msg,
			n->stats.nput_acked,
			n->stats.n_non_dirtied_put,
			n->stats.n_invalidate_pages,
			n->stats.n_invalidate_inodes,
			n->stats.n_remote_invalidate,
			n->stats.n_rc_hit, n->stats.n_rc_miss,
			n->stats.n_rc_miss_avoided,
			get_avg.tv_sec, get_avg.tv_nsec,
			get_msg_avg.tv_sec, get_msg_avg.tv_nsec,
			n->stats.get_min_time.tv_sec,
			n->stats.get_min_time.tv_nsec,
			n->stats.get_max_time.tv_sec,
			n->stats.get_max_time.tv_nsec,
			put_avg.tv_sec, put_avg.tv_nsec,
			put_msg_avg.tv_sec, put_msg_avg.tv_nsec,
			n->stats.put_min_time.tv_sec,
			n->stats.put_min_time.tv_nsec,
			n->stats.put_max_time.tv_sec,
			n->stats.put_max_time.tv_nsec);

	return count;
}

module_init(remotecache_node_init);
module_exit(remotecache_node_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maxime Lorrillere <maxime.lorrillere@lip6.fr>");
