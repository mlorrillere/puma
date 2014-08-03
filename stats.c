/*
 *	stats.c
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */
#include <linux/kallsyms.h>
#include <linux/export.h>
#include "stats.h"

#define def_show_ulong(_name) \
	static ssize_t show_##_name(struct rc_stats *stats, struct rc_stats_attribute *attr, char *buf) \
	{\
		return scnprintf(buf, PAGE_SIZE, "%lu\n", stats->_name);\
	}

#define def_show_timespec(_name) \
	static ssize_t show_##_name(struct rc_stats *stats, struct rc_stats_attribute *attr, char *buf) \
	{\
		return scnprintf(buf, PAGE_SIZE, "%ld.%09ld\n", stats->_name.tv_sec, stats->_name.tv_nsec);\
	}

#define RC_STATS_ATTR(_name, _mode)\
	struct rc_stats_attribute rc_stats_##_name = __ATTR(_name, _mode, show_##_name, NULL);

#define RC_STATS_ATTR_TYPE(_name, _mode, _type) \
	def_show_##_type(_name);\
	struct rc_stats_attribute rc_stats_##_name = __ATTR(_name, _mode, show_##_name, NULL);

#define to_rc_stats(obj) container_of(obj, struct rc_stats, kobj)
#define to_rc_stats_attr(_attr) container_of(_attr, struct rc_stats_attribute, attr)

static ssize_t show_send_avg_time(struct rc_stats *stats,
		struct	rc_stats_attribute *attr, char *buf)
{
	struct timespec avg = timespec_avg(&stats->send_avg_time, stats->nsend);
	return scnprintf(buf, PAGE_SIZE, "%ld.%09ld\n", avg.tv_sec, avg.tv_nsec);
}

static ssize_t show_get_avg_time(struct rc_stats *stats,
		struct	rc_stats_attribute *attr, char *buf)
{
	struct timespec avg = timespec_avg(&stats->get_avg_time, stats->nget);
	return scnprintf(buf, PAGE_SIZE, "%ld.%09ld\n", avg.tv_sec, avg.tv_nsec);
}

static ssize_t show_put_avg_time(struct rc_stats *stats,
		struct	rc_stats_attribute *attr, char *buf)
{
	struct timespec avg = timespec_avg(&stats->put_avg_time, stats->nput_acked);
	return scnprintf(buf, PAGE_SIZE, "%ld.%09ld\n", avg.tv_sec, avg.tv_nsec);
}

/* rc_stats_reset - reinitialize statistics
 *
 * @stats: the rc_stats structure to be (re)initialized
 *
 * It is possible to reinitialize statistics through userspace by writing 1
 * into thr "reset" attribute.
 */
void rc_stats_reset(struct rc_stats *stats)
{
	stats->nget = 0;
	stats->nput= 0;
	stats->nput_acked = 0;
	stats->n_non_dirtied_put = 0;
	stats->n_invalidate_pages = 0;
	stats->n_invalidate_inodes = 0;
	stats->n_remote_invalidate = 0;
	stats->nget_msg = 0;
	stats->nput_msg = 0;
	stats->nsend = 0;
	stats->n_rc_hit = 0;
	stats->n_rc_miss = 0;
	stats->n_rc_miss_avoided = 0;

	stats->send_max_time.tv_sec = 0;
	stats->send_max_time.tv_nsec = 0;
	stats->send_min_time.tv_sec = 0;
	stats->send_min_time.tv_nsec = 0;
	stats->send_avg_time.tv_sec = 0;
	stats->send_avg_time.tv_nsec = 0;

	stats->get_max_time.tv_sec = 0;
	stats->get_max_time.tv_nsec = 0;
	stats->get_min_time.tv_sec = 0;
	stats->get_min_time.tv_nsec = 0;
	stats->get_avg_time.tv_sec = 0;
	stats->get_avg_time.tv_nsec = 0;

	stats->put_max_time.tv_sec = 0;
	stats->put_max_time.tv_nsec = 0;
	stats->put_min_time.tv_sec = 0;
	stats->put_min_time.tv_nsec = 0;
	stats->put_avg_time.tv_sec = 0;
	stats->put_avg_time.tv_nsec = 0;
}

static ssize_t store_reset(struct rc_stats *stats, struct rc_stats_attribute *attr,
		const char *buf, size_t count)
{
	int ret, reset = 0;

	ret = sscanf(buf, "%u", &reset);
	if (ret != 1)
		return -EINVAL;

	if (reset)
		rc_stats_reset(stats);

	return count;
}

static ssize_t show_stats(struct rc_stats *stats,
		struct rc_stats_attribute *attr, char *buf)
{
	if (stats->show)
		return stats->show(stats, buf);

	return -EINVAL;
}

static ssize_t store_stats(struct rc_stats *stats,
		struct rc_stats_attribute *attr,
		const char *buf, size_t count)
{
	if (stats->store)
		return stats->store(stats, buf, count);

	return -EINVAL;
}

RC_STATS_ATTR_TYPE(nget, 0444, ulong);
RC_STATS_ATTR_TYPE(nput, 0444, ulong);
RC_STATS_ATTR_TYPE(nput_acked, 0444, ulong);
RC_STATS_ATTR_TYPE(n_non_dirtied_put, 0444, ulong);
RC_STATS_ATTR_TYPE(n_invalidate_pages, 0444, ulong);
RC_STATS_ATTR_TYPE(n_invalidate_inodes, 0444, ulong);
RC_STATS_ATTR_TYPE(n_remote_invalidate, 0444, ulong);
RC_STATS_ATTR_TYPE(nget_msg, 0444, ulong);
RC_STATS_ATTR_TYPE(nput_msg, 0444, ulong);
RC_STATS_ATTR_TYPE(nsend, 0444, ulong);
RC_STATS_ATTR_TYPE(n_rc_hit, 0444, ulong);
RC_STATS_ATTR_TYPE(n_rc_miss, 0444, ulong);
RC_STATS_ATTR_TYPE(n_rc_miss_avoided, 0444, ulong);
RC_STATS_ATTR_TYPE(send_max_time, 0444, timespec);
RC_STATS_ATTR_TYPE(send_min_time, 0444, timespec);
RC_STATS_ATTR(send_avg_time, 0444);
RC_STATS_ATTR_TYPE(get_max_time, 0444, timespec);
RC_STATS_ATTR_TYPE(get_min_time, 0444, timespec);
RC_STATS_ATTR(get_avg_time, 0444);
RC_STATS_ATTR_TYPE(put_max_time, 0444, timespec);
RC_STATS_ATTR_TYPE(put_min_time, 0444, timespec);
RC_STATS_ATTR(put_avg_time, 0444);

struct rc_stats_attribute rc_stats_reset_attr = __ATTR(reset, 0222, NULL, store_reset);
struct rc_stats_attribute rc_stats_stats_attr = __ATTR(stats, 0666, show_stats, store_stats);

static const struct attribute *attributes[] = {
	&rc_stats_nget.attr,
	&rc_stats_nput.attr,
	&rc_stats_nput_acked.attr,
	&rc_stats_n_non_dirtied_put.attr,
	&rc_stats_n_invalidate_pages.attr,
	&rc_stats_n_invalidate_inodes.attr,
	&rc_stats_n_remote_invalidate.attr,
	&rc_stats_nget_msg.attr,
	&rc_stats_nput_msg.attr,
	&rc_stats_nsend.attr,
	&rc_stats_n_rc_hit.attr,
	&rc_stats_n_rc_miss.attr,
	&rc_stats_n_rc_miss_avoided.attr,
	&rc_stats_send_max_time.attr,
	&rc_stats_send_min_time.attr,
	&rc_stats_send_avg_time.attr,
	&rc_stats_get_max_time.attr,
	&rc_stats_get_min_time.attr,
	&rc_stats_get_avg_time.attr,
	&rc_stats_put_max_time.attr,
	&rc_stats_put_min_time.attr,
	&rc_stats_put_avg_time.attr,
	&rc_stats_reset_attr.attr,
	&rc_stats_stats_attr.attr,
	NULL
};

static ssize_t rc_stats_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct rc_stats_attribute *stats_attr = to_rc_stats_attr(attr);
	struct rc_stats *stats = to_rc_stats(kobj);
	ssize_t ret = -EIO;

	if (stats_attr->show)
		ret = stats_attr->show(stats, stats_attr, buf);
	if (ret >= (ssize_t)PAGE_SIZE) {
		print_symbol("rc_stats_attr_show: %s returned bad count\n",
				(unsigned long)stats_attr->show);
	}
	return ret;
}

static ssize_t rc_stats_attr_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count)
{
	struct rc_stats_attribute *stats_attr = to_rc_stats_attr(attr);
	struct rc_stats *stats = to_rc_stats(kobj);
	ssize_t ret = -EIO;

	if (stats_attr->store)
		ret = stats_attr->store(stats, stats_attr, buf, count);
	if (ret >= (ssize_t)PAGE_SIZE) {
		print_symbol("rc_stats_attr_store: %s returned bad count\n",
				(unsigned long)stats_attr->store);
	}
	return ret;
}

static struct sysfs_ops rc_stats_sysfs_ops = {
	.show = rc_stats_attr_show,
	.store = rc_stats_attr_store,
};

static void rc_stats_kobject_release(struct kobject *kobj)
{
	kobject_del(kobj);
}

static struct kobj_type rc_stats_ktype = {
	.release = rc_stats_kobject_release,
	.sysfs_ops = &rc_stats_sysfs_ops,
};

/* rc_stats_init - initializes sysfs to export statistics to userspace
 *
 * @parent: parent kobject, usually the module kobject
 * @stats: the statistics struct to use, usually the static one (rc_stats)
 *
 * Returns 0 if the sysfs was correctly initialized
 */
int rc_stats_init(struct kobject *parent, struct rc_stats *stats)
{
	int retval;

	memset(&stats->kobj, 0, sizeof(stats->kobj));
	retval = kobject_init_and_add(&stats->kobj, &rc_stats_ktype,
			parent, "statistics");

	if (!retval) {
		retval = sysfs_create_files(&stats->kobj, attributes);
	}

	stats->show = NULL;
	stats->store = NULL;

	rc_stats_reset(stats);

	return retval;
}
EXPORT_SYMBOL(rc_stats_init);

void rc_stats_destroy(struct rc_stats *stats)
{
	sysfs_remove_files(&stats->kobj, attributes);
	kobject_put(&stats->kobj);
}
EXPORT_SYMBOL(rc_stats_destroy);
