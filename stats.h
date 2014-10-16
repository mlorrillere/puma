/*
 *	stats.h
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef STATS_H
#define STATS_H
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/time.h>

/* The rc_stats structure is used to store usefull measurements on the usage
 * of the remotecache. Statistics are exported through sysfs when initialized
 * with rc_stats_init() and can then be accessed from userspace through the
 * kobject passed as parameter.
 */
struct rc_stats {
	/* Total GET requests. Does not take into account GET requests
	 * avoided using the bitmap */
	unsigned long nget;
	/* Total PUT messages sent */
	unsigned long nput;
	/* Total PUT messages acked */
	unsigned long nput_acked;
	/* Total avoided non-dirtied PUT */
	unsigned long n_non_dirtied_put;

	/* Total INVALIDATE_PAGE messages sent */
	unsigned long n_invalidate_pages;

	/* Total INVALIDATE_INO messages sent */
	unsigned long n_invalidate_inodes;

	/* Total INVALIDATE_PAGE requests received */
	unsigned long n_remote_invalidate;

	/* Total GET messages sent */
	unsigned long nget_msg;
	/* Total PUT messages sent */
	unsigned long nput_msg;

	unsigned long nsend;

	/* Number of remote cache hit */
	unsigned long n_rc_hit;

	/* Number of remote cache miss. Does not take into account GET
	 * requests avoided using the bitmap */
	unsigned long n_rc_miss;
	/* Miss avoided using the remote_bitmap bitmap */
	unsigned long n_rc_miss_avoided;

	/* Number of put using memory pool */
	unsigned long n_fast_put;

	/* Number of slow put (without the use of the memory pool) */
	unsigned long n_slow_put;

	/* Number of aborted put due to empty memory pool */
	unsigned long n_aborted_put;

	/* Time needed for a RC_MSG_GET to complete */
	struct timespec send_max_time;
	struct timespec send_min_time;
	struct timespec send_avg_time;


	/* Time needed for a RC_MSG_GET to complete */
	struct timespec get_max_time;
	struct timespec get_min_time;
	struct timespec get_avg_time;

	/* Time needed for a RC_MSG_PUT to complete */
	struct timespec put_max_time;
	struct timespec put_min_time;
	struct timespec put_avg_time;

	/* Handler to handle a read on the stats file */
	ssize_t (*show) (struct rc_stats *stats, char *buf);

	/* Handler to handle a write on the stats file */
	ssize_t (*store) (struct rc_stats *stats, const char *buf, size_t size);

	struct kobject kobj;
};

struct rc_stats_attribute {
	struct attribute attr;
	ssize_t (*show)(struct rc_stats *, struct rc_stats_attribute *, char *buf);
	ssize_t (*store)(struct rc_stats *, struct rc_stats_attribute *, const char *buf, size_t count);
};

int rc_stats_init(struct kobject *parent, struct rc_stats *stats);
void rc_stats_destroy(struct rc_stats *stats);
void rc_stats_reset(struct rc_stats *stats);

static inline struct timespec timespec_avg(const struct timespec *sum, unsigned long count)
{
	s64 nstime = timespec_to_ns(sum);
	if (count)
		nstime /= count;

	return ns_to_timespec(nstime);
}

static inline void rc_stats_update_min(struct timespec *old,
		const struct timespec *new)
{
	if ((old->tv_sec == 0 && old->tv_nsec == 0) || timespec_compare(old, new) > 0)
		*old = *new;
}

static inline void rc_stats_update_max(struct timespec *old,
		const struct timespec *new)
{
	if (timespec_compare(old, new) < 0)
		*old = *new;
}

static inline void rc_stats_update_avg(struct timespec *old, const struct timespec *new)
{
	*old = timespec_add(*old, *new);
}
#endif /* STATS_H */
