/*
 *	metadata.c
 *
 *	Copyright (C) 2014
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/lockdep.h>

#include "metadata.h"

/*
 * As we can't do atomic wait/wakeup with radix tree tags, we use a hash table
 * to store busy pages state. On a racy state, the waiter atomically adds a
 * busy_page struct into the hash table and wait on a bit to be cleared.
 *
 * On the other side, when an ack is received, the bit is cleared and all
 * threads wating for a busy page are woken.
 */
DECLARE_WAIT_QUEUE_HEAD(wait_busy_page);
DEFINE_HASHTABLE(busy_pages_hash, 6);
DEFINE_SPINLOCK(busy_pages_lock);

struct busy_page {
	struct hlist_node hash;
	ino_t ino;
	pgoff_t index;
	atomic_t state;
};

static int sleep_on_remotecache_page_metadata(void *word)
{
	schedule();
	return 0;
}

void wake_up_remotecache_page_metadata(void *word, int bit)
{
	wake_up_bit(word, bit);
}

void wait_on_remotecache_page_metadata(void *word, int bit)
{
	wait_on_bit(word, bit, sleep_on_remotecache_page_metadata,
			TASK_UNINTERRUPTIBLE);
}

void __remotecache_metadata_clear_busy(struct remotecache_inode *inode, pgoff_t index)
{
	unsigned long *entry;
	struct busy_page *bp;

	lockdep_assert_held(&inode->lock);

	entry = radix_tree_tag_clear(&inode->pages_tree, index,
			REMOTECACHE_TAG_BUSY);
	BUG_ON(!entry);

	smp_mb__after_clear_bit();

	rc_debug("%s inode %lu index %lu value %lx\n", __func__, inode->ino,
			index, *entry);

	rcu_read_lock();
	hash_for_each_possible_rcu(busy_pages_hash, bp, hash, inode->ino^index) {
		if (bp->ino == inode->ino && bp->index == index) {
			rc_debug("%s inode %lu index %lu bp %p\n", __func__, inode->ino, index, bp);
			atomic_set(&bp->state, 0);
		}
	}
	rcu_read_unlock();

	wake_up(&wait_busy_page);
}

void __remotecache_metadata_set_busy(struct remotecache_inode *inode, pgoff_t index)
{
	unsigned long *entry;

	lockdep_assert_held(&inode->lock);

	entry = radix_tree_tag_set(&inode->pages_tree, index, REMOTECACHE_TAG_BUSY);

	rc_debug("%s inode %lu index %lu value %lx\n", __func__, inode->ino,
			index, *entry);
}

void remotecache_metadata_wait_busy(struct remotecache_inode *inode, pgoff_t index)
{
	unsigned long flags;
	struct busy_page bp = {.ino = inode->ino,
			       .index = index,
			       .state = ATOMIC_INIT(1)};

	INIT_HLIST_NODE(&bp.hash);

	rcu_read_lock();
	if (!radix_tree_tag_get(&inode->pages_tree, index,
			REMOTECACHE_TAG_BUSY)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	spin_lock_irqsave(&busy_pages_lock, flags);
	hash_add_rcu(busy_pages_hash, &bp.hash, bp.ino^bp.index);
	spin_unlock_irqrestore(&busy_pages_lock, flags);

	/*
	 * Concurrent wait busy/clear busy: BUSY tag may have been cleared and
	 * waiters woken up before we add bp to the hash table.
	 */
	synchronize_rcu();
	rcu_read_lock();
	if (!radix_tree_tag_get(&inode->pages_tree, index,
			REMOTECACHE_TAG_BUSY)) {
		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();

	rc_debug("%s wait on inode %lu index %lu bp %p\n", __func__, inode->ino, index, &bp);

	while (atomic_read(&bp.state) != 0) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&wait_busy_page, &wait, TASK_UNINTERRUPTIBLE);
		if (atomic_read(&bp.state) != 0 && schedule_timeout(15*HZ)) {
			WARN_ON(true);
			finish_wait(&wait_busy_page, &wait);
			goto out;
		}
		finish_wait(&wait_busy_page, &wait);
	}

out:
	spin_lock_irqsave(&busy_pages_lock, flags);
	hash_del_rcu(&bp.hash);
	spin_unlock_irqrestore(&busy_pages_lock, flags);

	synchronize_rcu();

	rc_debug("%s done on inode %lu index %lu bp %p\n", __func__, inode->ino, index, &bp);
}
