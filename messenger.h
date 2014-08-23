/*
 *	messenger.h
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef MESSENGER_H
#define MESSENGER_H
#include <linux/uio.h>
#include <linux/kref.h>
#include <linux/mempool.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

#if 0
#include <linux/timer.h>
#endif

/*
 * Network stack for the remote cache.
 *
 * This stack is highly based on Ceph's messenger (net/ceph/messenger.c),
 * thanks to Sage Weil and to the other maintainers of Ceph.
 */

struct rc_connection;
struct rc_msg;
struct remotecache_plug;


/* Port number used by servers to listen for incoming connections */
#define REMOTECACHE_PORT 4444

/* used by message exchange protocol */
#define RC_MSG_TAG_READY         1  /* server->client: ready for messages */
#define RC_MSG_TAG_MSG           2  /* message */
#define RC_MSG_TAG_ACK           3  /* message ack */

/* limits */
#define RC_MSG_MAX_FRONT_LEN	(4096)
#define RC_MSG_MAX_MIDDLE_LEN	(4096)
#define RC_MSG_MAX_DATA_LEN	(16*1024*1024)

#define RC_MSG_FLAG_URG		1   /* Urgent message: should be sent and
				       acked quickly */
#define RC_MSG_FLAGS_SHIFT	(8) /* Shift to be used for message flags */

#define rc_msg_set_flag(msg, flag) \
	do {\
		msg->header.flags = cpu_to_le16(le16_to_cpu(msg->header.flags)|flag);\
	} while (0)
#define rc_msg_test_flag(msg, flag) (le16_to_cpu(msg->header.flags) & flag)

/*
 * Message header
 */
struct rc_msg_header {
	__le64 seq;		/* message seq# for this session */
	__le16 type;		/* message type */
	__le16 flags;		/* additional flags
				 * - first 8bits are reserved for messenger
				 * - last 8bits can be used for messages
				 */

	__le32 front_len;	/* bytes in front part */
	__le32 middle_len;	/* bytes in middle part */
	__le32 data_len;	/* bytes in data payload */

	__le32 front_crc;	/* front crc32c */
	__le32 middle_crc;	/* middle crc32c */
	__le32 data_crc;	/* data crc32c */
	__le32 crc;		/* header crc32c */
} __packed;

/*
 * A single message. It contains a header (message type, crc values, etc.), a "front"
 * message body and possibly a data payload (stored in some number of pages).
 */
struct rc_msg {
	struct rc_msg_header header;	/* header */
	struct kvec front;		/* main message */
	struct kvec middle;		/* middle message */
	struct page **pages;		/* data payload. The message owns a
					   ref on each page. */
	struct page *page;
	struct list_head pagelist;	/* list of pages instead of pages */
	unsigned nr_pages;		/* number of pages in pages or
					   page_list */
	struct list_head list_head;
	struct kref kref;
	bool more;			/* another message will soon follow */
	struct timespec stamp;		/* when we were queued */

	struct rc_connection *con;

	struct rc_msgpool *pool;	/* if not null, message pool where the
					   message comes from */
	void *private;
};

struct rc_msg_pos {
	int page, page_pos;  /* which page; offset in page */
	int data_pos;        /* offset in data payload */
};

/*
 * Callbacks for handling connection events
 */
struct rc_connection_operations {
	struct rc_connection *(*get)(struct rc_connection *);
	void (*put)(struct rc_connection *);

	struct rc_connection *(*accept) (struct rc_connection *listening);

	/* handle an incoming message */
	void (*dispatch) (struct rc_connection *, struct rc_msg *);

	/* handle a message when acked */
	void (*acked) (struct rc_connection *, struct rc_msg *);

	/* error handling */
	void (*fault) (struct rc_connection *);

	struct rc_msg * (*alloc_msg) (struct rc_connection *con,
					struct rc_msg_header *hdr,
					int *skip);

	/* Alloc message data pages */
	void (*alloc_data) (struct rc_connection *con, struct rc_msg *msg);
};

struct rc_connection {
	const struct rc_connection_operations *ops;

	atomic_t sock_state;	/* socket state */
	struct socket *sock;

	unsigned long flags;	/* connection flags */
	unsigned long state;	/* connection state */
	const char *error_msg;	/* error message, if any */
	int error;

	struct sockaddr_storage peer_addr;	/* peer address */

	struct mutex mutex;
	spinlock_t lock;	/* lock to protect out_queue */

	struct list_head list;	/* Might be used to link connections together,
				   mainly when used as a listening connection */

	/* out queue */
	struct list_head out_queue;
	struct list_head out_sent;
	u64 out_seq;		/* last message sent */

	u64 in_seq, 		/* last message successfully received */
	    in_seq_acked;	/* last message acked */

	/* message out temps */
	struct rc_msg *out_msg;	/* sending message (== tail of out_sent) */

	bool out_msg_done;	/* if out_msg processing is done */
	struct rc_msg_pos out_msg_pos;	/* position of next byte to send */

	struct kvec out_kvec[8],	/* kvec to send header/footer data */
		*out_kvec_cur;
	int out_kvec_left;	/* kvec's left in out_kvec */
	int out_kvec_bytes;	/* total bytes left */
	int out_more;		/* there is more data after the kvecs */
	__le64 out_temp_ack;	/* for writing an ack */

	/* message in temps */
	struct rc_msg_header in_header;	/* for received header */
	struct rc_msg *in_msg;		/* incoming message */
	struct rc_msg_pos in_msg_pos;	/* position for next bytes do receive */
	u32 in_front_crc, in_middle_crc, in_data_crc;  /* calculated crc */

	char in_tag;         /* protocol control byte */
	int in_base_pos;     /* bytes read */
	__le64 in_temp_ack;  /* for reading an ack */

	struct delayed_work work;	    /* send|recv work */
	unsigned long backoff;

	struct rc_stats *stats;

	void *private;
};

const char *rc_pr_addr(const struct sockaddr_storage *ss);
extern void rc_con_init(struct rc_connection *con, void *private,
		const struct rc_connection_operations *, struct rc_stats *);

int rc_set_addr(struct sockaddr_storage *addr, const char *ip,
		unsigned short port);
extern void rc_con_open(struct rc_connection *con, struct sockaddr *addr);
extern int rc_con_listen(struct rc_connection *con, struct sockaddr *addr);
extern void rc_con_close(struct rc_connection *);
extern void rc_con_send(struct rc_connection *con, struct rc_msg *msg);
extern void rc_con_flush(struct rc_connection *con);

extern struct rc_msg *rc_con_plug_last(void);
extern void rc_con_finish_plug(struct rc_connection *con,
		struct remotecache_plug *plug);
extern void rc_con_start_plug(struct remotecache_plug *plug);
extern void rc_con_flush_plug(struct rc_connection *con,
		struct task_struct *tsk);

extern struct rc_msg *rc_msg_new(int type, int front_len, int middle_len,
		int pages_len, gfp_t flags, bool can_fail);
/*
 * Pages must be added to pages array or pagelist thourgh corresponding
 * helpers
 */
extern void rc_msg_add_page(struct rc_msg *, struct page *);
extern void rc_msg_add_page_list(struct rc_msg *, struct page *);

/* Might be used when processing an acked message */
extern void rc_msg_del_page_list(struct rc_msg *, struct page *);

static inline void rc_msg_get(struct rc_msg *msg)
{
	kref_get(&msg->kref);
}

extern void rc_msg_last_put(struct kref *kref);
static inline void rc_msg_put(struct rc_msg *msg)
{
	kref_put(&msg->kref, rc_msg_last_put);
}


int rc_messenger_init(void);
void rc_messenger_exit(void);
void rc_messenger_flush(void);
#endif /* MESSENGER_H */
