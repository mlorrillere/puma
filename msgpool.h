#ifndef RC_MSGPOOL_H
#define RC_MSGPOOL_H
/* Taken from include/linux/ceph/msgpool.h */

#include <linux/mempool.h>
#include "messenger.h"

/*
 * we use memory pools for preallocating messages we may receive, to
 * avoid unexpected OOM conditions.
 */
struct rc_msgpool {
	const char *name;
	mempool_t *pool;
	int type;               /* preallocated message type */
	unsigned front_len;     /* preallocated payload size */
	unsigned middle_len;	/* preallocated middle size */
	unsigned pages_len;	/* preallocated pages array size */
};

extern int rc_msgpool_init(struct rc_msgpool *pool, int type,
			     unsigned front_len, unsigned middle_len,
			     unsigned pages_len, int size, const char *name);
extern void rc_msgpool_destroy(struct rc_msgpool *pool);
extern struct rc_msg *rc_msgpool_get(struct rc_msgpool *, gfp_t gfp_flags,
		unsigned front_len, unsigned middle_len, unsigned pages_len);
extern void rc_msgpool_put(struct rc_msgpool *, struct rc_msg *);

#endif
