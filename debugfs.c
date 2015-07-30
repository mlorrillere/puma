#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "debugfs.h"

static struct dentry *remotecache_debugfs = NULL;


struct suspend_state {
	struct list_head list;
	struct timespec stamp;
	bool enabled;
};

static LIST_HEAD(suspend_history);
static DEFINE_MUTEX(suspend_lock);
static bool debugfs_suspend_monitor = false;

module_param_named(suspend_monitor,
		debugfs_suspend_monitor, bool, 0666);

void remotecache_debugfs_suspend(bool enabled)
{
	struct suspend_state *state;

	if (!debugfs_suspend_monitor)
		return;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	getnstimeofday(&state->stamp);
	state->enabled = enabled;

	mutex_lock(&suspend_lock);
	list_add_tail(&state->list, &suspend_history);
	mutex_unlock(&suspend_lock);
}

static void __suspend_clear(void)
{
	struct suspend_state *state, *n;

	list_for_each_entry_safe(state, n, &suspend_history, list) {
		list_del(&state->list);
		kfree(state);
	}

	INIT_LIST_HEAD(&suspend_history);
}

/* File write operation to configure suspend history at run-time. The
 * following commands can be written to the
 * /sys/kernel/debug/remotecache/suspend file:
 *   off	- stop the suspend monitoring
 *   on		- start the suspend monitoring
 *   clear	- clear current suspend monitoring logs
 */
static ssize_t suspend_write(struct file *file, const char __user *user_buf,
		size_t size, loff_t *ppos)
{
	char buf[64];
	int buf_size;
	int ret;

	buf_size = min(size, (sizeof(buf) - 1));
	if (strncpy_from_user(buf, user_buf, buf_size) < 0)
		return -EFAULT;
	buf[buf_size] = 0;

	ret = mutex_lock_interruptible(&suspend_lock);
	if (ret < 0)
		return ret;

	if (strncmp(buf, "clear", 5) == 0) {
		if (debugfs_suspend_monitor)
			__suspend_clear();
		goto out;
	}

	if (strncmp(buf, "off", 3) == 0) {
		debugfs_suspend_monitor = false;
		__suspend_clear();
	} else if (strncmp(buf, "on", 2) == 0) {
		debugfs_suspend_monitor = true;
	}
	else {
		ret = -EINVAL;
	}

out:
	mutex_unlock(&suspend_lock);
	if (ret < 0)
		return ret;

	/* ignore the rest of the buffer, only one command at a time */
	*ppos += size;
	return size;
}

/*
 * Iterate over the suspend_history and return the first valid object at or after
 * the required position with its use_count incremented.
 */
static void *suspend_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct suspend_state *state;
	loff_t n = *pos;
	int err;

	err = mutex_lock_interruptible(&suspend_lock);
	if (err < 0)
		return ERR_PTR(err);

	list_for_each_entry(state, &suspend_history, list) {
		if (n-- > 0)
			continue;
		goto out;
	}
	state = NULL;
out:
	return state;
}

/*
 * Return the next state in the history_list.
 */
static void *suspend_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct suspend_state *state = v;
	struct suspend_state *next = list_next_entry(state, list);
	++(*pos);

	if (&next->list == &suspend_history)
		next = NULL;
	return next;
}

/*
 * Decrement the use_count of the last object required, if any.
 */
static void suspend_seq_stop(struct seq_file *seq, void *v)
{
	if (!IS_ERR(v)) {
		/*
		 * suspend_seq_start may return ERR_PTR if the suspend_lock
		 * waiting was interrupted, so only release it if !IS_ERR.
		 */
		mutex_unlock(&suspend_lock);
	}
}

/*
 * Print the information for an unreferenced object to the seq file.
 */
static int suspend_seq_show(struct seq_file *seq, void *v)
{
	struct suspend_state *state = v;

	seq_printf(seq, "%ld.%09ld %s\n",
			state->stamp.tv_sec,
			state->stamp.tv_nsec,
			state->enabled ? "active" : "inactive");
	return 0;
}

static const struct seq_operations suspend_seq_ops = {
	.start = suspend_seq_start,
	.next  = suspend_seq_next,
	.stop  = suspend_seq_stop,
	.show  = suspend_seq_show,
};

static int suspend_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &suspend_seq_ops);
}

static const struct file_operations suspend_fops = {
	.owner		= THIS_MODULE,
	.open		= suspend_open,
	.read		= seq_read,
	.write		= suspend_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

int remotecache_debugfs_init(void)
{
	struct dentry *suspend_file;
	int err = -EFAULT;

	remotecache_debugfs = debugfs_create_dir("remotecache", NULL);
	if (!remotecache_debugfs) {
		pr_err("error when creating debugfs directory\n");
		goto abort;
	} else if (IS_ERR(remotecache_debugfs)) {
		pr_err("debugfs not mounted\n");
		err = -ENODEV;
		goto abort;
	}

	suspend_file = debugfs_create_file("suspend", 0666,
			remotecache_debugfs, NULL, &suspend_fops);
	if (!suspend_file) {
		pr_err("debugfs: error when creating suspend file\n");
		goto suspend_file_failure;
	} else if (IS_ERR(suspend_file)) {
		pr_err("debugfs not mounted\n");
		err = -ENODEV;
		goto suspend_file_failure;
	}

	return 0;

suspend_file_failure:
	debugfs_remove_recursive(remotecache_debugfs);
abort:
	return err;
}

void remotecache_debugfs_exit(void)
{
	debugfs_remove_recursive(remotecache_debugfs);

	mutex_lock(&suspend_lock);
	__suspend_clear();
	mutex_unlock(&suspend_lock);
}
