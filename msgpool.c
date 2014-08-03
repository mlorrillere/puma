#include <linux/err.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/export.h>

#include "msgpool.h"
#include "remotecache.h"

static void *msgpool_alloc(gfp_t gfp_mask, void *arg)
{
	struct rc_msgpool *pool = arg;
	struct rc_msg *msg;

	msg = rc_msg_new(pool->type, pool->front_len, pool->middle_len,
			pool->pages_len, gfp_mask, true);

	if (msg) {
		rc_debug("%s %s %p\n", __func__, pool->name, msg);
		msg->pool = pool;
	} else {
		rc_debug("%s %s failed\n", __func__, pool->name);
	}
	return msg;
}

static void msgpool_free(void *element, void *arg)
{
	struct rc_msgpool *pool = arg;
	struct rc_msg *msg = element;

	rc_debug("msgpool_release %s %p\n", pool->name, msg);
	msg->pool = NULL;
	rc_msg_put(msg);
}

extern int rc_msgpool_init(struct rc_msgpool *pool, int type,
			     unsigned front_len, unsigned middle_len,
			     unsigned pages_len, int size, const char *name)
{
	rc_debug("msgpool %s init\n", name);
	pool->type = type;
	pool->front_len = front_len;
	pool->middle_len = middle_len;
	pool->pages_len = pages_len;
	pool->pool = mempool_create(size, msgpool_alloc, msgpool_free, pool);
	if (!pool->pool)
		return -ENOMEM;
	pool->name = name;
	return 0;
}
EXPORT_SYMBOL(rc_msgpool_init);

void rc_msgpool_destroy(struct rc_msgpool *pool)
{
	rc_debug("msgpool %s destroy\n", pool->name);
	mempool_destroy(pool->pool);
}
EXPORT_SYMBOL(rc_msgpool_destroy);

extern struct rc_msg *rc_msgpool_get(struct rc_msgpool *pool, gfp_t gfp_flags,
		unsigned front_len, unsigned middle_len, unsigned pages_len)
{
	struct rc_msg *msg;

	if (front_len > pool->front_len ||
			middle_len > pool->middle_len ||
			pages_len > pool->pages_len) {
		rc_debug("msgpool_get %s need (front,middle,pages_len) "
				"(%u,%u,%u), pool size is (%u,%u,%u)\n",
		       pool->name, front_len, middle_len, pages_len,
		       pool->front_len, pool->middle_len, pool->pages_len);
		WARN_ON(1);

		/* try to alloc a fresh message */
		return rc_msg_new(pool->type, front_len, middle_len,
				pages_len, gfp_flags, false);
	}

	msg = mempool_alloc(pool->pool, gfp_flags);
	rc_debug("msgpool_get %s %p\n", pool->name, msg);
	return msg;
}
EXPORT_SYMBOL(rc_msgpool_get);

void rc_msgpool_put(struct rc_msgpool *pool, struct rc_msg *msg)
{
	rc_debug("msgpool_put %s %p\n", pool->name, msg);

	/* reset msg front_len; user may have changed it */
	msg->front.iov_len = pool->front_len;
	msg->header.front_len = cpu_to_le32(pool->front_len);

	msg->middle.iov_len = pool->middle_len;
	msg->header.middle_len = cpu_to_le32(pool->middle_len);
	msg->header.data_len = 0;
	msg->private = NULL;

	if (pool->pages_len) {
		memset(msg->pages, 0, sizeof(*msg->pages)*pool->pages_len);
	} else {
		BUG_ON(msg->pages != NULL);
	}

	kref_init(&msg->kref);  /* retake single ref */
	mempool_free(msg, pool->pool);
}
