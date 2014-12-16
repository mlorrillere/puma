/*
 *	remotecache.h
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef REMOTECACHE_H
#define REMOTECACHE_H
#include <linux/bitmap.h>
#include <asm/bitops.h>

#if defined(CONFIG_REMOTECACHE_DEBUG)
#   define rc_debug(fmt, ...)						\
	pr_debug(fmt, ##__VA_ARGS__)
# else
#  define rc_debug(fmt, ...)					\
	do {							\
		if (0)						\
			pr_debug(fmt, ##__VA_ARGS__);	\
	} while (0)
#endif

enum {
	RC_STRATEGY_EXCLUSIVE = 0,
	RC_STRATEGY_INCLUSIVE = 1
};

#define PAGES_PER_PUT	32
#define PAGES_PER_GET	32

#define	RC_MSG_TYPE_PUT			1 /* PUT a page to the remote cache */
#define	RC_MSG_TYPE_GET			2 /* GET a page from the remote cache */
#define	RC_MSG_TYPE_GET_RESPONSE	3 /* response to a GET request */
#define	RC_MSG_TYPE_INVALIDATE_FS	4 /* INVALIDATE a filesystem */
#define	RC_MSG_TYPE_INVALIDATE_INO	5 /* INVALIDATE an inode */
#define	RC_MSG_TYPE_INVALIDATE_PAGE	6 /* INVALIDATE a page */
#define RC_MSG_TYPE_SUSPEND		7 /* Suspend server side activity */
#define RC_MSG_TYPE_RESUME		8 /* Resume server side activity */

struct rc_put_request {
	__le32 pool_id;	/* identifier of the source filesystem */
} __packed;

struct rc_get_request {
	__le64 req_id;
	__le32 pool_id;		/* identifier of the source filesystem */
	__le64 ino;		/* inode number from where the page comes from */
} __packed;

struct rc_get_response {
	__le64 available;
	__le64 req_id;
	__le32 pool_id;	/* identifier of the source filesystem */
	__le64 ino;	/* inode number from where the pages comes from */
	u8 nr_miss;
} __packed;

struct rc_put_request_middle {
	__le64 ino;	/* inode number from where the pages comes from */
	__le64 index;	/* logical offset of the page within the inode */
};

struct rc_get_response_middle {
	__le64 index;	/* logical offset of the page within the inode */
} __packed;

struct rc_get_request_middle {
	__le64 index;	/* logical offset of the page within the inode */
	u8 nr_pages;	/* number of consecutive pages starting from index */
} __packed;

struct rc_invalidate_fs_request {
	__le32 pool_id;	/* identifier of the source filesystem */
} __packed;

struct rc_invalidate_ino_request {
	__le32 pool_id;	/* identifier of the source filesystem */
	__le64 ino;	/* inode number from where the page comes from */
} __packed;

struct rc_invalidate_page_request {
	__le64 available;
	__le32 pool_id;	/* identifier of the source filesystem */
} __packed;

#define RC_MSG_FLAG_INVALIDATE_PMD	(1 << RC_MSG_FLAGS_SHIFT)

struct rc_invalidate_page_request_middle {
	__le64 ino;	/* inode number from where the page comes from */
	__le64 index;	/* logical offset of the page within the inode */
	u8 nr_pages;	/* number of pages starting from index to be
			 * invalidated (should be > 0)
			 */
} __packed;

#endif /* REMOTECACHE_H */
