/*
 *	messenger.c
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <linux/crc32c.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <net/tcp.h>
#include <linux/module.h>

#include <linux/remotecache.h>
#include "messenger.h"
#include "msgpool.h"
#include "remotecache.h"
#include "stats.h"

/*
 * We track the state of the socket on a given connection using
 * values defined below.  The transition to a new socket state is
 * handled by a function which verifies we aren't coming from an
 * unexpected state.
 *
 *      --------
 *      | NEW* |  transient initial state
 *      --------
 *          | con_sock_state_init()
 *          v
 *      ----------
 *      | CLOSED |  initialized, but no socket (and no
 *      ----------  TCP connection)
 *       ^      \
 *       |       \ con_sock_state_connecting()
 *       |        ----------------------
 *       |                              \
 *       + con_sock_state_closed()       \
 *       |+---------------------------    \
 *       | \                          \    \
 *       |  -----------                \    \
 *       |  | CLOSING |  socket event;  \    \
 *       |  -----------  await close     \    \
 *       |       ^                        \   |
 *       |       |                         \  |
 *       |       + con_sock_state_closing() \ |
 *       |      / \                         | |
 *       |     /   ---------------          | |
 *       |    /                   \         v v
 *       |   /                    --------------
 *       |  /    -----------------| CONNECTING |  socket created, TCP
 *       |  |   /                 --------------  connect initiated
 *       |  |   | con_sock_state_connected()
 *       |  |   v
 *      -------------
 *      | CONNECTED |  TCP connection established
 *      -------------
 *
 * State values for rc_connection->sock_state; NEW is assumed to be 0.
 */

#define CON_SOCK_STATE_NEW		0	/* -> CLOSED */
#define CON_SOCK_STATE_CLOSED		1	/* -> CONNECTING or LISTENING */
#define CON_SOCK_STATE_CONNECTING	2	/* -> CONNECTED or -> CLOSING */
#define CON_SOCK_STATE_CONNECTED	3	/* -> CLOSING or -> CLOSED */
#define CON_SOCK_STATE_LISTENING	4	/* -> CLOSING or -> CLOSED */
#define CON_SOCK_STATE_CLOSING		5	/* -> CLOSED */

/*
 * connection states
 */
#define CON_STATE_CLOSED        1  /* -> PREOPEN, LISTENING */
#define CON_STATE_PREOPEN       2  /* -> CONNECTING, CLOSED */
#define CON_STATE_CONNECTING    3  /* -> OPEN, CLOSED */
#define CON_STATE_LISTENING	4  /* -> CLOSED */
#define CON_STATE_OPEN          5  /* -> CLOSED */

/*
 * rc_connection flag bits
 */
#define CON_FLAG_WRITE_PENDING	   1  /* we have data ready to send */
#define CON_FLAG_SOCK_CLOSED	   2  /* socket state changed to closed */
#define CON_FLAG_URG	   3          /* we received or sent an urgent message */


/* static tag bytes (protocol control messages) */
static char tag_msg = RC_MSG_TAG_MSG;
static char tag_ack = RC_MSG_TAG_ACK;

static struct kmem_cache *remotecache_msg_cachep = NULL;

static void queue_con(struct rc_connection *con);
static void con_work(struct work_struct *);
static void rc_fault(struct rc_connection *con);

/*
 * Nicely render a sockaddr as a string.  An array of formatted
 * strings is used, to approximate reentrancy.
 */
#define ADDR_STR_COUNT_LOG	5	/* log2(# address strings in array) */
#define ADDR_STR_COUNT		(1 << ADDR_STR_COUNT_LOG)
#define ADDR_STR_COUNT_MASK	(ADDR_STR_COUNT - 1)
#define MAX_ADDR_STR_LEN	64	/* 54 is enough */

static char addr_str[ADDR_STR_COUNT][MAX_ADDR_STR_LEN];
static atomic_t addr_str_seq = ATOMIC_INIT(0);

const char *rc_pr_addr(const struct sockaddr_storage *ss)
{
	int i;
	char *s;
	struct sockaddr_in *in4 = (struct sockaddr_in *) ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ss;

	i = atomic_inc_return(&addr_str_seq) & ADDR_STR_COUNT_MASK;
	s = addr_str[i];

	switch (ss->ss_family) {
	case AF_INET:
		snprintf(s, MAX_ADDR_STR_LEN, "%pI4:%hu", &in4->sin_addr,
			 ntohs(in4->sin_port));
		break;

	case AF_INET6:
		snprintf(s, MAX_ADDR_STR_LEN, "[%pI6c]:%hu", &in6->sin6_addr,
			 ntohs(in6->sin6_port));
		break;

	default:
		snprintf(s, MAX_ADDR_STR_LEN, "(unknown sockaddr family %hu)",
			 ss->ss_family);
	}

	return s;
}

/*
 * work queue for all reading and writing to/from the socket.
 */
static struct workqueue_struct *rc_msgr_wq;

static void _rc_msgr_exit(void)
{
	if (rc_msgr_wq) {
		destroy_workqueue(rc_msgr_wq);
		rc_msgr_wq = NULL;
	}

	if (remotecache_msg_cachep) {
		kmem_cache_destroy(remotecache_msg_cachep);
		remotecache_msg_cachep = NULL;
	}
}

int rc_messenger_init(void)
{
	remotecache_msg_cachep = kmem_cache_create("remotecache_msg",
			sizeof(struct rc_msg), 0,
			SLAB_MEM_SPREAD|SLAB_PANIC, NULL);
	if (!remotecache_msg_cachep) {
		pr_err("%s: failed to create msg slab\n", __func__);
		_rc_msgr_exit();
	}

	rc_msgr_wq = alloc_workqueue("remotecache-msgr",
			WQ_MEM_RECLAIM|WQ_HIGHPRI|WQ_UNBOUND, 0);
	if (rc_msgr_wq)
		return 0;

	pr_err("msgr_init failed to create workqueue\n");
	_rc_msgr_exit();

	return -ENOMEM;
}

void rc_messenger_exit(void)
{
	BUG_ON(rc_msgr_wq == NULL);

	_rc_msgr_exit();
}

void rc_messenger_flush(void)
{
	flush_workqueue(rc_msgr_wq);
}
EXPORT_SYMBOL(rc_messenger_flush);

/* Connection socket state transition functions */

static void con_sock_state_init(struct rc_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSED);
	if (WARN_ON(old_state != CON_SOCK_STATE_NEW))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	rc_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,
	     CON_SOCK_STATE_CLOSED);
}

static void con_sock_state_connecting(struct rc_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CONNECTING);
	if (WARN_ON(old_state != CON_SOCK_STATE_CLOSED))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	rc_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,
	     CON_SOCK_STATE_CONNECTING);
}

static void con_sock_state_connected(struct rc_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CONNECTED);
	if (WARN_ON(old_state != CON_SOCK_STATE_CONNECTING))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	rc_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,
	     CON_SOCK_STATE_CONNECTED);
}

static void con_sock_state_listening(struct rc_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_LISTENING);
	if (WARN_ON(old_state != CON_SOCK_STATE_CLOSED))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	rc_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,
	     CON_SOCK_STATE_LISTENING);
}

static void con_sock_state_closing(struct rc_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSING);
	if (WARN_ON(old_state != CON_SOCK_STATE_CONNECTING &&
			old_state != CON_SOCK_STATE_CONNECTED &&
			old_state != CON_SOCK_STATE_LISTENING &&
			old_state != CON_SOCK_STATE_CLOSING))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	rc_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,
	     CON_SOCK_STATE_CLOSING);
}

static void con_sock_state_closed(struct rc_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSED);
	if (WARN_ON(old_state != CON_SOCK_STATE_CONNECTED &&
		    old_state != CON_SOCK_STATE_CLOSING &&
		    old_state != CON_SOCK_STATE_CONNECTING &&
		    old_state != CON_SOCK_STATE_LISTENING &&
		    old_state != CON_SOCK_STATE_CLOSED))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	rc_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,
	     CON_SOCK_STATE_CLOSED);
}

void rc_con_init(struct rc_connection *con, void* private,
		const struct rc_connection_operations *ops,
		struct rc_stats *stats)
{
	rc_debug("con_init %p\n", con);
	memset(con, 0, sizeof(*con));
	con->private = private;
	con->ops = ops;

	con_sock_state_init(con);

	mutex_init(&con->mutex);
	spin_lock_init(&con->lock);
	INIT_LIST_HEAD(&con->list);
	INIT_LIST_HEAD(&con->out_queue);
	INIT_LIST_HEAD(&con->out_sent);
	INIT_DELAYED_WORK(&con->work, con_work);
	con->backoff = 1;
	con->stats = stats;

	con->state = CON_STATE_CLOSED;
}
EXPORT_SYMBOL(rc_con_init);

static void con_out_kvec_reset(struct rc_connection *con)
{
	con->out_kvec_left = 0;
	con->out_kvec_bytes = 0;
	con->out_kvec_cur = &con->out_kvec[0];
}

static void con_out_kvec_add(struct rc_connection *con,
				size_t size, void *data)
{
	int index;

	index = con->out_kvec_left;
	BUG_ON(index >= ARRAY_SIZE(con->out_kvec));

	con->out_kvec[index].iov_len = size;
	con->out_kvec[index].iov_base = data;
	con->out_kvec_left++;
	con->out_kvec_bytes += size;
}

/*
 * socket callback functions
 */

/* data available on socket, or listen socket received a connect */
static void rc_sock_data_ready(struct sock *sk, int count_unused)
{
	struct rc_connection *con = sk->sk_user_data;
	if (!con) {
		/* A newly created socked might not be fully initialized */
		rc_debug("%s socked %p not fully initialized", __func__, sk);
		return;
	}

	if (sk->sk_state != TCP_CLOSE_WAIT) {
		rc_debug("%s on %p con->sock->sk = %p, sk = %p, state = %lu, queueing work\n", __func__,
		     con, (con->sock ? con->sock->sk : NULL), sk, con->state);
		queue_con(con);
	}
}

/* socket has buffer space for writing */
static void rc_sock_write_space(struct sock *sk)
{
	struct rc_connection *con = sk->sk_user_data;
	if (!con) {
		/* A newly created socked might not be fully initialized */
		rc_debug("%s socked %p not fully initialized", __func__, sk);
		return;
	}

	/* only queue to workqueue if there is data we want to write,
	 * and there is sufficient space in the socket buffer to accept
	 * more data.  clear SOCK_NOSPACE so that rc_sock_write_space()
	 * doesn't get called again until try_write() fills the socket
	 * buffer. See net/ipv4/tcp_input.c:tcp_check_space()
	 * and net/core/stream.c:sk_stream_write_space().
	 */
	if (test_bit(CON_FLAG_WRITE_PENDING, &con->flags)) {
		if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
			rc_debug("%s %p queueing write work\n", __func__, con);
			clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			queue_con(con);
		}
	} else {
		rc_debug("%s %p nothing to write\n", __func__, con);
	}
}

/* socket's state has changed */
static void rc_sock_state_change(struct sock *sk)
{
	struct rc_connection *con = sk->sk_user_data;
	if (!con) {
		/* A newly created socked might not be fully initialized */
		rc_debug("%s socked %p not fully initialized", __func__, sk);
		return;
	}

	rc_debug("%s %p con->sock->sk = %p, sk = %p, state = %lu sk_state = %u\n", __func__,
	     con, (con->sock ? con->sock->sk : NULL), sk, con->state, sk->sk_state);

	switch (sk->sk_state) {
	case TCP_CLOSE:
		rc_debug("%s TCP_CLOSE\n", __func__);
	case TCP_CLOSE_WAIT:
		rc_debug("%s TCP_CLOSE_WAIT\n", __func__);
		con_sock_state_closing(con);
		set_bit(CON_FLAG_SOCK_CLOSED, &con->flags);
		queue_con(con);
		break;
	case TCP_ESTABLISHED:
		rc_debug("%s TCP_ESTABLISHED\n", __func__);
		if (con->state == CON_STATE_LISTENING) {
			rc_debug("%s listening socked", __func__);
			/* con is a listening connection accepting a new peer:
			 * in this case we reset sock callbacks because they
			 * will be initialized in rc_tcp_accept */
			sk->sk_user_data = NULL;
		} else {
			con_sock_state_connected(con);
			queue_con(con);
		}
		break;
	default:	/* Everything else is uninteresting */
		break;
	}
}

/*
 * set up socket callbacks
 */
static void set_sock_callbacks(struct socket *sock,
			       struct rc_connection *con)
{
	struct sock *sk = sock->sk;
	sk->sk_user_data = con;
	sk->sk_data_ready = rc_sock_data_ready;
	sk->sk_write_space = rc_sock_write_space;
	sk->sk_state_change = rc_sock_state_change;
}


/*
 * socket helpers
 */

/*
 * initiate connection to a remote socket.
 */
static int rc_tcp_connect(struct rc_connection *con)
{
	struct sockaddr_storage *paddr = &con->peer_addr;
	struct socket *sock;
	int ret;

	BUG_ON(con->sock);
	ret = sock_create_kern(paddr->ss_family, SOCK_STREAM,
			       IPPROTO_TCP, &sock);
	if (ret)
		return ret;
	sock->sk->sk_allocation = GFP_ATOMIC;

	set_sock_callbacks(sock, con);

	rc_debug("connect %s\n", rc_pr_addr(paddr));

	con_sock_state_connecting(con);
	ret = sock->ops->connect(sock, (struct sockaddr *)paddr, sizeof(*paddr),
				 O_NONBLOCK);
	if (ret == -EINPROGRESS) {
		rc_debug("connect %s EINPROGRESS sk_state = %u\n",
		     rc_pr_addr(paddr),
		     sock->sk->sk_state);
	} else if (ret < 0) {
		con->error_msg = "connect error";
		con->error = ret;

		pr_err("connect %s error %d\n",
		       rc_pr_addr(paddr), ret);
		sock_release(sock);
		return ret;
	}

	con->sock = sock;
	return 0;
}

static int rc_tcp_accept(struct rc_connection *con)
{
	struct socket *sock;
	struct rc_connection *new;
	int err, addrlen = sizeof(new->peer_addr);

	BUG_ON(!con->ops->accept);
	err = kernel_accept(con->sock, &sock, O_NONBLOCK);
	if (err) {
		goto out;
	}

	rc_debug("%s new sock %p, sk_state=%d", __func__, sock,
			sock->sk->sk_state);

	new = con->ops->accept(con);
	if (!new) {
		sock_release(sock);
		err = -ENOMEM;
	}

	err = kernel_getpeername(sock, (struct sockaddr *)&new->peer_addr, &addrlen);
	if (err) {
		pr_err("%s: cannot get peer name (%d)\n", __func__, err);
		err = 0;
	}

	pr_info("%s: accepting connection from %pISpc\n", __func__,
			&new->peer_addr);

	new->sock = sock;
	set_sock_callbacks(sock, new);
	con_out_kvec_reset(new);
	atomic_set(&new->sock_state, CON_SOCK_STATE_CONNECTED);
	new->state = CON_STATE_OPEN;
	new->in_tag = RC_MSG_TAG_READY;

	queue_con(new);
out:
	if (err == -EAGAIN)
		err = 0;
	else if (err != 0)
		pr_err("rc_tcp_accept: kernel_accept returned %d", err);
	return err;
}

struct rc_tcp_desc {
	void *buf;
	size_t len;
};

static int rc_tcp_recv_actor(read_descriptor_t *desc, struct sk_buff *skb,
		unsigned int offset, size_t len)
{
	struct rc_tcp_desc *arg = desc->arg.data;
	size_t to_copy = min(len, arg->len);

	rc_debug("%s: offset %u len %lu buf %p buf len %lu\n", __func__, offset,
			len, arg->buf, arg->len);

	skb_copy_bits(skb, offset, arg->buf, to_copy);

	arg->len -= to_copy;
	arg->buf += to_copy;

	return to_copy;
}

static int __rc_tcp_recvmsg(struct socket *sock, void *buf, size_t len)
{
	/*struct kvec iov = {buf, len};
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int r;

	r = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
	if (r == -EAGAIN)
		r = 0;

	return r;*/

	int r;
	struct rc_tcp_desc arg = {.buf = buf, .len = len};
	read_descriptor_t desc = {
		.count = 1,
		.error = 0,
		.arg.data = &arg};

	r = tcp_read_sock(sock->sk, &desc, rc_tcp_recv_actor);

	rc_debug("%s: buf %p len %lu arg.buf %p arg.len %lu r %d\n",
			__func__, buf, len, arg.buf, arg.len, r);

	return r;
}

static int rc_tcp_recvmsg(struct socket *sock, void *buf, size_t len)
{
	/*struct kvec iov = {buf, len};
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int r;

	r = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
	if (r == -EAGAIN)
		r = 0;

	return r;*/

	int r;
	bool fast;

	fast = lock_sock_fast(sock->sk);
	r = __rc_tcp_recvmsg(sock, buf, len);
	unlock_sock_fast(sock->sk, fast);

	return r;
}

/*
 * write something.  @more is true if caller will be sending more data
 * shortly.
 */
static int rc_tcp_sendmsg(struct socket *sock, struct kvec *iov,
		     size_t kvlen, size_t len, int more)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int r;

	if (more)
		msg.msg_flags |= MSG_MORE;
	else
		msg.msg_flags |= MSG_EOR;  /* superfluous, but what the hell */

	r = kernel_sendmsg(sock, &msg, iov, kvlen, len);
	if (r == -EAGAIN)
		r = 0;
	return r;
}

static int rc_tcp_sendpage(struct socket *sock, struct page *page,
		     int offset, size_t size, int more)
{
	int flags = MSG_DONTWAIT | MSG_NOSIGNAL | (more ? MSG_MORE : MSG_EOR);
	int ret;

	ret = kernel_sendpage(sock, page, offset, size, flags);
	if (ret == -EAGAIN)
		ret = 0;
	return ret;
}

/*
 * Shutdown/close the socket for the given connection.
 */
static int con_close_socket(struct rc_connection *con)
{
	int rc = 0;

	rc_debug("con_close_socket on %p sock %p\n", con, con->sock);

	if (con->sock) {
		rc = con->sock->ops->shutdown(con->sock, SHUT_RDWR);
		sock_release(con->sock);
		con->sock = NULL;
	}

	/*
	 * Forcibly clear the SOCK_CLOSED flag.  It gets set
	 * independent of the connection mutex, and we could have
	 * received a socket close event before we had the chance to
	 * shut the socket down.
	 */
	clear_bit(CON_FLAG_SOCK_CLOSED, &con->flags);

	con_sock_state_closed(con);
	return rc;
}

/*
 * Reset a connection.  Discard all incoming and outgoing messages
 * and clear *_seq state.
 */
static void rc_msg_remove(struct rc_msg *msg)
{
	list_del_init(&msg->list_head);
	BUG_ON(msg->con == NULL);
	msg->con->ops->put(msg->con);
	msg->con = NULL;

	rc_msg_put(msg);
}
static void rc_msg_remove_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct rc_msg *msg = list_first_entry(head, struct rc_msg,
							list_head);
		rc_msg_remove(msg);
	}
}

static void reset_connection(struct rc_connection *con)
{
	/* reset connection, out_queue, msg_ and connect_seq */
	/* discard existing out_queue and msg_seq */
	rc_debug("reset_connection %p\n", con);
	rc_msg_remove_list(&con->out_queue);
	rc_msg_remove_list(&con->out_sent);

	if (con->in_msg) {
		BUG_ON(con->in_msg->con != con);
		con->in_msg->con = NULL;
		rc_msg_put(con->in_msg);
		con->in_msg = NULL;
		con->ops->put(con);
	}

	con->out_seq = 0;
	if (con->out_msg) {
		rc_msg_put(con->out_msg);
		con->out_msg = NULL;
	}
	con->in_seq = 0;
	con->in_seq_acked = 0;
}

/*
 * mark a peer down.  drop any open connections.
 */
void rc_con_close(struct rc_connection *con)
{
	unsigned long flags;

	mutex_lock(&con->mutex);
	rc_debug("con_close %p\n", con);
	con->state = CON_STATE_CLOSED;

	clear_bit(CON_FLAG_WRITE_PENDING, &con->flags);

	spin_lock_irqsave(&con->lock, flags);
	reset_connection(con);
	spin_unlock_irqrestore(&con->lock, flags);

	cancel_delayed_work(&con->work);
	con_close_socket(con);
	mutex_unlock(&con->mutex);
}
EXPORT_SYMBOL(rc_con_close);

static int rc_inet_pton(int af, const char *src, size_t srclen, void *dst)
{
	int r = 0;
	if (af == AF_INET)
		r = in4_pton(src, srclen, dst, '\0', NULL);
	else if (af == AF_INET6)
		r = in6_pton(src, srclen, dst, '\0', NULL);

	if (r == 0)
		printk(KERN_DEBUG "Failed to convert %s to binary form", src);
	return r != 0;
}

int rc_set_addr(struct sockaddr_storage *addr, const char *ip,
		unsigned short port)
{
	int r = 0;
	size_t len = ip ? strlen(ip) : 0;
	struct sockaddr_in *s_in = (struct sockaddr_in *)addr;
	struct sockaddr_in6 *s_in6 = (struct sockaddr_in6 *)addr;

	addr->ss_family = AF_UNSPEC;
	if (!ip) {
		r = 1;
	} else if (rc_inet_pton(AF_INET, ip, len, &s_in->sin_addr.s_addr)) {
		s_in->sin_family = AF_INET;
		r = 1;
	} else if (rc_inet_pton(AF_INET6, ip, len, &s_in6->sin6_addr.s6_addr)) {
		s_in6->sin6_family = AF_INET6;
		r = 1;
	}

	switch (addr->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)addr)->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
		break;
	}

	return r;
}
EXPORT_SYMBOL(rc_set_addr);

/*
 * Reopen a closed connection, with a new peer address.
 */
void rc_con_open(struct rc_connection *con, struct sockaddr *addr)
{
	mutex_lock(&con->mutex);
	rc_debug("con_open %p %s\n", con,
			rc_pr_addr((struct sockaddr_storage *)addr));

	BUG_ON(con->state != CON_STATE_CLOSED);
	con->state = CON_STATE_PREOPEN;

	memcpy(&con->peer_addr, addr, sizeof(*addr));

	mutex_unlock(&con->mutex);
	queue_con(con);
}
EXPORT_SYMBOL(rc_con_open);

int rc_con_listen(struct rc_connection *con, struct sockaddr *addr)
{
	struct sockaddr_storage *paddr = &con->peer_addr;
	struct socket *sock;
	int ret, reuseaddr = 1;

	rc_debug("con_listen %p %s\n", con,
			rc_pr_addr((struct sockaddr_storage *)addr));

	BUG_ON(con->state != CON_STATE_CLOSED);
	BUG_ON(con->sock);

	memcpy(&con->peer_addr, addr, sizeof(*addr));

	ret = sock_create_kern(paddr->ss_family, SOCK_STREAM,
			       IPPROTO_TCP, &sock);
	if (ret)
		return ret;
	sock->sk->sk_allocation = GFP_NOWAIT;

	ret = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			(char*)&reuseaddr, sizeof(reuseaddr));
	if (ret) {
		pr_err("rc_con_listen: setsockopt error %d", ret);
		sock_release(sock);
		return ret;
	}

	set_sock_callbacks(sock, con);

	rc_debug("listen %s\n", rc_pr_addr(paddr));

	ret = kernel_bind(sock, (struct sockaddr *)paddr,
			paddr->ss_family == AF_INET ?
			sizeof(struct sockaddr_in) :
			sizeof(struct sockaddr_in6));
	if (ret) {
		pr_err("rc_tcp_listen: bind error %d", ret);
		sock_release(sock);
		return ret;
	}

	ret = kernel_listen(sock, 10);
	if (ret) {
		pr_err("rc_tcp_listen: listen error %d", ret);
		sock_release(sock);
		return ret;
	}

	con->sock = sock;

	rc_debug("%s TCP_LISTEN\n", __func__);
	con_sock_state_listening(con);
	con->state = CON_STATE_LISTENING;
	return 0;
}
EXPORT_SYMBOL(rc_con_listen);

static void prepare_write_message_data(struct rc_connection *con)
{
	struct rc_msg *msg = con->out_msg;
	struct page *page = NULL;
	void *kaddr;
	u32 crc = 0;

	BUG_ON(!msg);
	BUG_ON(!msg->header.data_len);

	/* initialize page iterator */
	con->out_msg_pos.page = 0;
	con->out_msg_pos.page_pos = 0;

	/* calculate data crc32c */
	if (con->out_msg->pages) {
		int i;
		for (i = 0; i < con->out_msg->nr_pages; ++i) {
			page = con->out_msg->pages[i];
			kaddr = kmap(page);
			BUG_ON(kaddr == NULL);
			crc = crc32c(crc, kaddr, PAGE_SIZE);
			kunmap(page);
		}
	} else {
		list_for_each_entry(page, &con->out_msg->pagelist, lru) {
			kaddr = kmap(page);
			BUG_ON(kaddr == NULL);
			crc = crc32c(crc, kaddr, PAGE_SIZE);
			kunmap(page);
		}
	}

	con->out_msg->header.data_crc = cpu_to_le32(crc);
	con->out_msg_pos.data_pos = 0;
	con->out_more = 1;  /* data + footer will follow */
}

/*
 * Prepare headers for the next outgoing message.
 */
static void prepare_write_message(struct rc_connection *con)
{
	struct rc_msg *m;
	u32 crc;

	con_out_kvec_reset(con);
	con->out_msg_done = false;

	/* Sneak an ack in there first?  If we can get it into the same
	 * TCP packet that's a good thing. */
	if (con->in_seq > con->in_seq_acked) {
		con->in_seq_acked = con->in_seq;
		con_out_kvec_add(con, sizeof (tag_ack), &tag_ack);
		con->out_temp_ack = cpu_to_le64(con->in_seq_acked);
		con_out_kvec_add(con, sizeof (con->out_temp_ack),
			&con->out_temp_ack);
	}

	BUG_ON(!con->out_msg);
	m = con->out_msg;

	m->header.seq = cpu_to_le64(++con->out_seq);

	rc_debug("prepare_write_message %p seq %lld type %d len %d+%d+%d %d pgs\n",
	     m, con->out_seq, le16_to_cpu(m->header.type),
	     le32_to_cpu(m->header.front_len),
	     le32_to_cpu(m->header.middle_len),
	     le32_to_cpu(m->header.data_len),
	     m->nr_pages);
	BUG_ON(le32_to_cpu(m->header.front_len) != m->front.iov_len);
	BUG_ON(le32_to_cpu(m->header.middle_len) != m->middle.iov_len);

	/* tag + hdr + front + middle */
	con_out_kvec_add(con, sizeof (tag_msg), &tag_msg);
	con_out_kvec_add(con, sizeof (m->header), &m->header);
	con_out_kvec_add(con, m->front.iov_len, m->front.iov_base);
	if (m->middle.iov_base)
		con_out_kvec_add(con, m->middle.iov_len, m->middle.iov_base);

	/* is there a data payload? */
	con->out_msg->header.data_crc = 0;
	if (m->header.data_len) {
		prepare_write_message_data(con);
	} else {
		con->out_msg_done = true;
		con->out_more = con->out_msg->more;
	}

	/* fill in front crc */
	crc = crc32c(0, m->front.iov_base, m->front.iov_len);
	con->out_msg->header.front_crc = cpu_to_le32(crc);

	/* fill in middle crc */
	if (m->middle.iov_base) {
		crc = crc32c(0, m->middle.iov_base, m->middle.iov_len);
		con->out_msg->header.middle_crc = cpu_to_le32(crc);
	} else {
		con->out_msg->header.middle_crc = 0;
	}

	/* fill in header crc */
	crc = crc32c(0, &m->header, offsetof(struct rc_msg_header, crc));
	con->out_msg->header.crc = cpu_to_le32(crc);

	set_bit(CON_FLAG_WRITE_PENDING, &con->flags);
}

/*
 * Prepare an ack.
 */
static void prepare_write_ack(struct rc_connection *con)
{
	rc_debug("prepare_write_ack %p %llu -> %llu\n", con,
	     con->in_seq_acked, con->in_seq);
	con->in_seq_acked = con->in_seq;

	con_out_kvec_reset(con);

	con_out_kvec_add(con, sizeof (tag_ack), &tag_ack);

	con->out_temp_ack = cpu_to_le64(con->in_seq_acked);
	con_out_kvec_add(con, sizeof (con->out_temp_ack),
				&con->out_temp_ack);

	con->out_more = 1;  /* more will follow.. eventually.. */
	set_bit(CON_FLAG_WRITE_PENDING, &con->flags);
}

/*
 * write as much of pending kvecs to the socket as we can.
 *  1 -> done
 *  0 -> socket full, but more to do
 * <0 -> error
 */
static int write_partial_kvec(struct rc_connection *con)
{
	int ret;

	rc_debug("write_partial_kvec %p %d left\n", con, con->out_kvec_bytes);
	while (con->out_kvec_bytes > 0) {
		ret = rc_tcp_sendmsg(con->sock, con->out_kvec_cur,
				       con->out_kvec_left, con->out_kvec_bytes,
				       con->out_more);
		if (ret <= 0) {
			if (ret < 0) {
				pr_err("%s returned %d", __func__, ret);
				dump_stack();
				BUG();
			}
			goto out;
		}
		con->out_kvec_bytes -= ret;
		if (con->out_kvec_bytes == 0)
			break;            /* done */

		/* account for full iov entries consumed */
		while (ret >= con->out_kvec_cur->iov_len) {
			BUG_ON(!con->out_kvec_left);
			ret -= con->out_kvec_cur->iov_len;
			con->out_kvec_cur++;
			con->out_kvec_left--;
		}
		/* and for a partially-consumed entry */
		if (ret) {
			con->out_kvec_cur->iov_len -= ret;
			con->out_kvec_cur->iov_base += ret;
		}
	}
	con->out_kvec_left = 0;
	ret = 1;
out:
	rc_debug("write_partial_kvec %p %d left in %d kvecs ret = %d\n", con,
	     con->out_kvec_bytes, con->out_kvec_left, ret);
	return ret;  /* done! */
}

static void out_msg_pos_next(struct rc_connection *con, struct page *page,
			size_t len, size_t sent)
{
	struct rc_msg *msg = con->out_msg;

	BUG_ON(!msg);
	BUG_ON(!sent);

	con->out_msg_pos.data_pos += sent;
	con->out_msg_pos.page_pos += sent;
	if (sent < len)
		return;

	BUG_ON(sent != len);
	con->out_msg_pos.page_pos = 0;
	con->out_msg_pos.page++;
	if (!list_empty(&msg->pagelist))
		list_move_tail(&page->lru,
			       &msg->pagelist);
}

/*
 * Write as much message data payload as we can.  If we finish, queue
 * up the footer.
 *  1 -> done, footer is now queued in out_kvec[].
 *  0 -> socket full, but more to do
 * <0 -> error
 */
static int write_partial_msg_pages(struct rc_connection *con)
{
	struct rc_msg *msg = con->out_msg;
	unsigned int data_len = le32_to_cpu(msg->header.data_len);
	size_t len;
	int ret;
	int total_max_write;

	rc_debug("write_partial_msg_pages %p msg %p page %d/%d offset %d\n",
	     con, msg, con->out_msg_pos.page, msg->nr_pages,
	     con->out_msg_pos.page_pos);

	/*
	 * Iterate through each page that contains data to be
	 * written, and send as much as possible for each.
	 */
	while (data_len > con->out_msg_pos.data_pos) {
		struct page *page = NULL;
		int max_write = PAGE_SIZE;

		BUG_ON(!msg->pages && !list_empty(&msg->pagelist));
		total_max_write = data_len - con->out_msg_pos.data_pos;
		if (msg->pages) {
			page = msg->pages[con->out_msg_pos.page];
		} else if (!list_empty(&msg->pagelist)) {
			page = list_first_entry(&msg->pagelist,
						struct page, lru);
		}
		len = min_t(int, max_write - con->out_msg_pos.page_pos,
			    total_max_write);

		ret = rc_tcp_sendpage(con->sock, page,
				      con->out_msg_pos.page_pos, len, 1);
		if (ret <= 0) {
			if (ret < 0) {
				pr_err("%s returned %d", __func__, ret);
				dump_stack();
				BUG();
			}
			goto out;
		}

		out_msg_pos_next(con, page, len, (size_t) ret);
	}

	rc_debug("write_partial_msg_pages %p msg %p done\n", con, msg);

	con_out_kvec_reset(con);
	con->out_msg_done = true;
	con->out_more = con->out_msg->more;
	ret = 1;
out:
	return ret;
}

/*
 * Prepare to read a tag
 */
static void prepare_read_tag(struct rc_connection *con)
{
	rc_debug("prepare_read_tag %p\n", con);
	con->in_base_pos = 0;
	con->in_tag = RC_MSG_TAG_READY;
}

/*
 * Prepare to read an ack
 */
static void prepare_read_ack(struct rc_connection *con)
{
	rc_debug("prepare_read_ack %p\n", con);
	con->in_base_pos = 0;
}

/*
 * Prepare to read a message.
 */
static int prepare_read_message(struct rc_connection *con)
{
	rc_debug("prepare_read_message %p\n", con);
	BUG_ON(con->in_msg != NULL);
	con->in_base_pos = 0;
	con->in_front_crc = con->in_middle_crc = con->in_data_crc = 0;
	return 0;
}

static int read_partial(struct rc_connection *con,
			int end, int size, void *object)
{
	while (con->in_base_pos < end) {
		int left = end - con->in_base_pos;
		int have = size - left;
		int ret = rc_tcp_recvmsg(con->sock, object + have, left);
		if (ret <= 0)
			return ret;
		con->in_base_pos += ret;
	}
	return 1;
}

/*
 * read (part of) an ack
 */
static int read_partial_ack(struct rc_connection *con)
{
	int size = sizeof (con->in_temp_ack);
	int end = size;

	return read_partial(con, end, size, &con->in_temp_ack);
}


/*
 * We can finally discard anything that's been acked.
 */
static void process_ack(struct rc_connection *con)
{
	struct rc_msg *m;
	u64 ack = le64_to_cpu(con->in_temp_ack);
	u64 seq;

	/*
	 * We dont need to lock con->lock since we already lock con->mutex and
	 * out_sent is never used without con->mutex
	 */
	while (!list_empty(&con->out_sent)) {
		m = list_first_entry(&con->out_sent, struct rc_msg,
				     list_head);
		seq = le64_to_cpu(m->header.seq);
		if (seq > ack)
			break;
		rc_debug("got ack for seq %llu type %d at %p\n", seq,
		     le16_to_cpu(m->header.type), m);

		/* removing message */
		list_del_init(&m->list_head);
		BUG_ON(m->con == NULL);
		if (m->con->ops->acked)
			m->con->ops->acked(con, m);
		m->con->ops->put(m->con);
		m->con = NULL;

		rc_msg_put(m);
	}
	prepare_read_tag(con);
}

static int read_partial_message_section(struct rc_connection *con,
					struct kvec *section,
					unsigned int sec_len, u32 *crc)
{
	int ret, left;

	BUG_ON(!section);

	while (section->iov_len < sec_len) {
		BUG_ON(section->iov_base == NULL);
		left = sec_len - section->iov_len;
		ret = __rc_tcp_recvmsg(con->sock, (char *)section->iov_base +
				       section->iov_len, left);
		if (ret <= 0) {
			if (ret < 0) {
				pr_err("%s returned %d", __func__, ret);
				dump_stack();
				BUG();
			}
			return ret;
		}
		section->iov_len += ret;
	}
	if (section->iov_len == sec_len)
		*crc = crc32c(0, section->iov_base, section->iov_len);

	return 1;
}

static int read_partial_message_pages(struct rc_connection *con,
				      struct page **pages, unsigned int data_len)
{
	void *p;
	int ret;
	int left;

	left = min((int)(data_len - con->in_msg_pos.data_pos),
		   (int)(PAGE_SIZE - con->in_msg_pos.page_pos));
	/* (page) data */
	BUG_ON(pages == NULL);
	p = kmap_atomic(pages[con->in_msg_pos.page]);
	ret = __rc_tcp_recvmsg(con->sock, p + con->in_msg_pos.page_pos,
			       left);
	if (ret > 0)
		con->in_data_crc =
			crc32c(con->in_data_crc,
				  p + con->in_msg_pos.page_pos, ret);
	kunmap_atomic(p);
	if (ret <= 0) {
		if (ret < 0) {
			pr_err("%s returned %d", __func__, ret);
			dump_stack();
			BUG();
		}
		return ret;
	}
	con->in_msg_pos.data_pos += ret;
	con->in_msg_pos.page_pos += ret;
	if (con->in_msg_pos.page_pos == PAGE_SIZE) {
		con->in_msg_pos.page_pos = 0;
		con->in_msg_pos.page++;
		con->in_msg->nr_pages++;
	}

	return ret;
}

static int rc_con_in_msg_alloc(struct rc_connection *con, int *skip);

/*
 * read (part of) a message.
 */
static int read_partial_message(struct rc_connection *con)
{
	struct rc_msg *m = con->in_msg;
	int size;
	int end;
	int ret;
	unsigned int front_len, middle_len, data_len;
	u64 seq;
	u32 crc;
	bool fast;

	rc_debug("read_partial_message con %p msg %p\n", con, m);

	/* header */
	size = sizeof (con->in_header);
	end = size;
	ret = read_partial(con, end, size, &con->in_header);
	if (ret <= 0)
		goto out;

	crc = crc32c(0, &con->in_header, offsetof(struct rc_msg_header, crc));
	if (cpu_to_le32(crc) != con->in_header.crc) {
		pr_err("read_partial_message bad hdr "
		       " crc %u != expected %u\n",
		       crc, con->in_header.crc);
		return -EBADMSG;
	}

	front_len = le32_to_cpu(con->in_header.front_len);
	if (front_len > RC_MSG_MAX_FRONT_LEN)
		return -EIO;
	middle_len = le32_to_cpu(con->in_header.middle_len);
	if (middle_len > RC_MSG_MAX_MIDDLE_LEN)
		return -EIO;
	data_len = le32_to_cpu(con->in_header.data_len);
	if (data_len > RC_MSG_MAX_DATA_LEN)
		return -EIO;

	/* verify seq# */
	seq = le64_to_cpu(con->in_header.seq);
	if ((s64)seq - (s64)con->in_seq < 1) {
		pr_err("skipping %s seq %lld expected %lld\n",
			rc_pr_addr(&con->peer_addr),
			seq, con->in_seq + 1);
		con->in_base_pos = -front_len - middle_len - data_len;
		con->in_tag = RC_MSG_TAG_READY;

		/* This should never happened in remotecache since we don't
		 * handle message loss and retransmission */
		BUG();
		return 0;
	} else if ((s64)seq - (s64)con->in_seq > 1) {
		pr_err("read_partial_message bad seq %lld expected %lld\n",
		       seq, con->in_seq + 1);
		con->error_msg = "bad message sequence # for incoming message";
		con->error = -EBADMSG;
		return -EBADMSG;
	}

	/* allocate message? */
	if (!con->in_msg) {
		int skip = 0;

		rc_debug("got hdr type %d front %d middle %d data %d\n", con->in_header.type,
		     con->in_header.front_len, con->in_header.middle_len,
		     con->in_header.data_len);
		ret = rc_con_in_msg_alloc(con, &skip);
		if (ret < 0)
			return ret;
		if (skip) {
			/* skip this message */
			rc_debug("alloc_msg said skip message\n");
			BUG_ON(con->in_msg);
			con->in_base_pos = -front_len - middle_len - data_len;
			con->in_tag = RC_MSG_TAG_READY;
			con->in_seq++;
			return 0;
		}

		BUG_ON(!con->in_msg);
		BUG_ON(con->in_msg->con != con);
		m = con->in_msg;
		m->front.iov_len = 0;    /* haven't read it yet */
		m->middle.iov_len = 0;

		con->in_msg_pos.page = 0;
		con->in_msg_pos.data_pos = 0;
	}

	/* front */
	fast = lock_sock_fast(con->sock->sk);
	ret = read_partial_message_section(con, &m->front, front_len,
					   &con->in_front_crc);
	if (ret <= 0) {
		unlock_sock_fast(con->sock->sk, fast);
		goto out;
	}

	/* middle */
	if (middle_len > 0) {
		ret = read_partial_message_section(con, &m->middle,
				middle_len, &con->in_middle_crc);
		if (ret <= 0) {
			unlock_sock_fast(con->sock->sk, fast);
			goto out;
		}
	}

	if (data_len && (!m->pages || !m->pages[0]) && con->ops->alloc_data)
		con->ops->alloc_data(con, m);

	/* (page) data */
	while (con->in_msg_pos.data_pos < data_len) {
		if (m->pages) {
			ret = read_partial_message_pages(con, m->pages, data_len);
			if (ret <= 0) {
				unlock_sock_fast(con->sock->sk, fast);
				goto out;
			}
		} else {
			BUG_ON(1);
		}
	}
	unlock_sock_fast(con->sock->sk, fast);

	rc_debug("read_partial_message got msg %p %d (%u) + %d (%u) + %d (%u)\n",
	     m, front_len, m->header.front_crc, middle_len,
	     m->header.middle_crc, data_len, m->header.data_crc);

	/* crc ok? */
	if (con->in_front_crc != le32_to_cpu(m->header.front_crc)) {
		pr_err("read_partial_message %p front crc %u != exp. %u\n",
		       m, con->in_front_crc, m->header.front_crc);
		return -EBADMSG;
	}
	if (con->in_middle_crc != le32_to_cpu(m->header.middle_crc)) {
		pr_err("read_partial_message %p middle crc %u != exp. %u\n",
		       m, con->in_middle_crc, m->header.middle_crc);
		return -EBADMSG;
	}
	if (con->in_data_crc != le32_to_cpu(m->header.data_crc)) {
		pr_err("read_partial_message %p data crc %u != exp. %u\n", m,
		       con->in_data_crc, le32_to_cpu(m->header.data_crc));
		return -EBADMSG;
	}

	ret = 1;

out:
	return ret; /* done! */
}

/*
 * Process message.  This happens in the worker thread.  The callback should
 * be careful not to do anything that waits on other incoming messages or it
 * may deadlock.
 */
static void process_message(struct rc_connection *con)
{
	struct rc_msg *msg;

	BUG_ON(con->in_msg->con != con);
	con->in_msg->con = NULL;
	msg = con->in_msg;
	con->in_msg = NULL;
	con->ops->put(con);

	mutex_unlock(&con->mutex);

	rc_debug("===== %p %llu type=%d len %d+%d+%d (%u %u) =====\n",
	     msg, le64_to_cpu(msg->header.seq),
	     le16_to_cpu(msg->header.type),
	     le32_to_cpu(msg->header.front_len),
	     le32_to_cpu(msg->header.middle_len),
	     le32_to_cpu(msg->header.data_len),
	     con->in_front_crc, con->in_data_crc);
	con->ops->dispatch(con, msg);

	mutex_lock(&con->mutex);
}

/*
 * Write something to the socket.  Called in a worker thread when the
 * socket appears to be writeable and we have something ready to send.
 */
static int try_write(struct rc_connection *con)
{
	int ret = 0;

	rc_debug("try_write start %p state %lu\n", con, con->state);

more:
	rc_debug("try_write out_kvec_bytes %d\n", con->out_kvec_bytes);

	/* open the socket first? */
	if (con->state == CON_STATE_PREOPEN) {
		BUG_ON(con->sock);
		con->state = CON_STATE_CONNECTING;

		con_out_kvec_reset(con);

		BUG_ON(con->in_msg);
		con->in_tag = RC_MSG_TAG_READY;
		rc_debug("try_write initiating connect on %p new state %lu\n",
		     con, con->state);
		ret = rc_tcp_connect(con);
		if (ret < 0) {
			con->error_msg = "connect error";
			con->error = ret;
			goto out;
		}
	} else if (con->state == CON_STATE_LISTENING) {
		rc_debug("%s listening socket, nothing to write", __func__);
		ret = 0;
		goto out;
	}

more_kvec:
	if (con->out_kvec_left) {
		ret = write_partial_kvec(con);
		if (ret <= 0)
			goto out;
	}

	/* msg pages? */
	if (con->out_msg) {
		if (con->out_msg_done) {
			struct timespec delay;

			if (rc_msg_test_flag(con->out_msg, RC_MSG_FLAG_URG)) {
				set_bit(CON_FLAG_URG, &con->flags);
				rc_debug("%s found urgent flag on %p",
						__func__, con->out_msg);
			}

			/* Updating statistics */
			getnstimeofday(&delay);
			delay = timespec_sub(delay, con->out_msg->stamp);

			rc_stats_update_avg(&con->stats->send_avg_time, &delay);
			rc_stats_update_min(&con->stats->send_min_time, &delay);
			rc_stats_update_max(&con->stats->send_max_time, &delay);
			con->stats->nsend++;

			rc_msg_put(con->out_msg);
			con->out_msg = NULL;   /* we're done with this one */

			/*
			 * Stop receiving messages to avoid read starvation if
			 * there is a lot of messages to send
			 */
			ret = 1;
			goto out;
		}

		ret = write_partial_msg_pages(con);
		if (ret == 1)
			goto more_kvec;  /* we need to send the footer, too! */
		if (ret == 0)
			goto out;
		if (ret < 0) {
			rc_debug("try_write write_partial_msg_pages err %d\n",
			     ret);
			goto out;
		}
	}

	if (con->state == CON_STATE_OPEN) {

		if (con->in_seq > con->in_seq_acked) {
			prepare_write_ack(con);
			goto more;
		}

		/* is anything else pending? */
		if (!list_empty(&con->out_queue)) {
			unsigned long flags;
			struct rc_msg *m = list_first_entry(&con->out_queue,
					struct rc_msg, list_head);

			con->out_msg = m;
			BUG_ON(m->con != con);

			/* put message on sent list */
			rc_msg_get(m);

			spin_lock_irqsave(&con->lock, flags);
			list_move_tail(&m->list_head, &con->out_sent);
			spin_unlock_irqrestore(&con->lock, flags);

			prepare_write_message(con);
			goto more;
		}
	}

	/* Nothing to do! */
	clear_bit(CON_FLAG_WRITE_PENDING, &con->flags);
	rc_debug("try_write nothing else to write.\n");
	ret = 0;
out:
	/* There is a path in TCP where there is not enough space to allocate
	 * memory __and__ it cannot recover memory from its already allocated
	 * objects (sk_buf, ...) __and__ we never get notified through
	 * sock_write_space: the only way I found is to requeue the connection
	 * to the workqueue whenever we see SOCK_ASYNC_NOSPACE bit set into
	 * the socket.
	 */
	if (test_bit(CON_FLAG_WRITE_PENDING, &con->flags) &&
			test_bit(SOCK_ASYNC_NOSPACE, &con->sock->flags)) {
		rc_debug("%s SOCK_ASYNC_NOSPACE set, requeuing with "
				"backoff=%lu\n", __func__, con->backoff);
		con->ops->get(con);
		if (mod_delayed_work(rc_msgr_wq, &con->work, con->backoff))
			con->ops->put(con);
		con->backoff = min_t(unsigned long, con->backoff*2, HZ);
	} else {
		con->backoff = 1;
	}

	if (test_and_clear_bit(CON_FLAG_URG, &con->flags)) {
		int nodelay = 1;
		rc_debug("%s urgent flag set, force push", __func__);
		kernel_setsockopt(con->sock, IPPROTO_TCP, TCP_NODELAY,
				(void*)&nodelay, sizeof(nodelay));
	}

	rc_debug("try_write done on %p ret %d\n", con, ret);
	return ret;
}

/*
 * Read what we can from the socket.
 */
static int try_read(struct rc_connection *con)
{
	int ret = -1;

more:
	rc_debug("try_read start on %p state %lu\n", con, con->state);
	if (con->state != CON_STATE_CONNECTING &&
	    con->state != CON_STATE_OPEN &&
	    con->state != CON_STATE_LISTENING)
		return 0;

	BUG_ON(!con->sock);

	if (con->state == CON_STATE_LISTENING) {
		rc_debug("try_read: accept");
		ret = rc_tcp_accept(con);
		if (ret <= 0)
			goto out;
		goto more;
	}

	rc_debug("try_read tag %d in_base_pos %d\n", (int)con->in_tag,
	     con->in_base_pos);

	if (con->state == CON_STATE_CONNECTING) {
		rc_debug("try_read connecting\n");
		con->state = CON_STATE_OPEN;
		goto more;
	}

	BUG_ON(con->state != CON_STATE_OPEN);

	if (con->in_tag == RC_MSG_TAG_READY) {
		/*
		 * process previously read message
		 */
		if (con->in_msg)
			process_message(con);

		/*
		 * what's next?
		 */
		ret = rc_tcp_recvmsg(con->sock, &con->in_tag, 1);
		if (ret <= 0)
			goto out;
		rc_debug("try_read got tag %d\n", (int)con->in_tag);
		switch (con->in_tag) {
		case RC_MSG_TAG_MSG:
			prepare_read_message(con);
			break;
		case RC_MSG_TAG_ACK:
			prepare_read_ack(con);
			break;
		default:
			goto bad_tag;
		}
	}
	if (con->in_tag == RC_MSG_TAG_MSG) {
		ret = read_partial_message(con);
		if (ret <= 0) {
			con->error =  ret;
			switch (ret) {
			case -EBADMSG:
				con->error_msg = "bad crc";
				ret = -EIO;
				break;
			case -EIO:
				con->error_msg = "io error";
				break;
			}
			goto out;
		}
		if (con->in_tag == RC_MSG_TAG_READY)
			goto more;
		if (con->state == CON_STATE_OPEN)
			prepare_read_tag(con);

		/*
		 * Stop try_read loop if we read 1 complete message to
		 * avoid write starvation
		 */
		con->in_seq++;
		if (rc_msg_test_flag(con->in_msg, RC_MSG_FLAG_URG)) {
			set_bit(CON_FLAG_URG, &con->flags);
			rc_debug("%s found urgent flag on %p", __func__, con->in_msg);
		}

		ret = 1;
		goto out;
	}
	if (con->in_tag == RC_MSG_TAG_ACK) {
		ret = read_partial_ack(con);
		if (ret <= 0)
			goto out;
		process_ack(con);
		goto more;
	}

out:
	rc_debug("try_read done on %p ret %d\n", con, ret);
	return ret;

bad_tag:
	pr_err("try_read bad con->in_tag = %d\n", (int)con->in_tag);
	con->error_msg = "protocol error, garbage tag";
	ret = -1;
	goto out;
}

/*
 * Atomically queue work on a connection.  Bump @con reference to
 * avoid races with connection teardown.
 */
static void queue_con(struct rc_connection *con)
{
	if (!con->ops->get(con)) {
		rc_debug("queue_con %p ref count 0\n", con);
		return;
	}

	if (!queue_delayed_work(rc_msgr_wq, &con->work, 0)) {
		rc_debug("queue_con %p - already queued\n", con);
		con->ops->put(con);
	} else {
		rc_debug("queue_con %p\n", con);
	}
}

/*
 * Do some work on a connection.  Drop a connection ref when we're done.
 */
static void con_work(struct work_struct *work)
{
	struct rc_connection *con = container_of(work, struct rc_connection,
						   work.work);
	int read_ret, write_ret;

	mutex_lock(&con->mutex);
restart:
	if (test_and_clear_bit(CON_FLAG_SOCK_CLOSED, &con->flags)) {
		switch (con->state) {
		case CON_STATE_CONNECTING:
			con->error_msg = "connection failed";
			break;
		case CON_STATE_OPEN:
			con->error_msg = "socket closed";
			break;
		default:
			rc_debug("unrecognized con state %d\n", (int)con->state);
			con->error_msg = "unrecognized con state";
			BUG();
		}
		goto fault;
	}

	if (con->state == CON_STATE_CLOSED) {
		rc_debug("con_work %p CLOSED\n", con);
		BUG_ON(con->sock);
		goto done;
	}
	if (con->state == CON_STATE_PREOPEN) {
		rc_debug("con_work OPENING\n");
		BUG_ON(con->sock);
	}

	do {
		read_ret = try_read(con);
		if (read_ret == -EAGAIN)
			goto restart;
		if (read_ret < 0) {
			con->error_msg = "socket error on read";
			con->error = read_ret;
			goto fault;
		}

		write_ret = try_write(con);
		if (write_ret == -EAGAIN)
			goto restart;
		if (write_ret < 0) {
			con->error_msg = "socket error on write";
			con->error = write_ret;
			goto fault;
		}
	} while (read_ret == 1 || write_ret == 1);

done:
	mutex_unlock(&con->mutex);
done_unlocked:
	con->ops->put(con);
	return;

fault:
	rc_fault(con);     /* error/fault path */
	goto done_unlocked;
}

static void rc_fault(struct rc_connection *con)
	__releases(con->mutex)
{
	unsigned long flags;
	rc_debug("fault %p state %lu\n", con, con->state);

	BUG_ON(con->state != CON_STATE_CONNECTING &&
	       con->state != CON_STATE_OPEN);

	spin_lock_irqsave(&con->lock, flags);
	reset_connection(con);
	spin_unlock_irqrestore(&con->lock, flags);

	con_close_socket(con);
	con->state = CON_STATE_CLOSED;

	mutex_unlock(&con->mutex);

	if (con->ops->fault)
		con->ops->fault(con);
}

/*
 * Queue up an outgoing message on the given connection.
 */
void rc_con_send(struct rc_connection *con, struct rc_msg *msg)
{
	/* set src+dst */
	BUG_ON(msg->front.iov_len != le32_to_cpu(msg->header.front_len));

	if (con->state == CON_STATE_CLOSED) {
		rc_debug("con_send %p closed, dropping %p\n", con, msg);
		rc_msg_put(msg);
		return;
	}

	BUG_ON(msg->con != NULL);
	msg->con = con->ops->get(con);
	BUG_ON(msg->con == NULL);

	BUG_ON(!list_empty(&msg->list_head));

	rc_debug("rc_con_send: %p type %d len %d+%d+%d -----\n", msg,
	     le16_to_cpu(msg->header.type),
	     le32_to_cpu(msg->header.front_len),
	     le32_to_cpu(msg->header.middle_len),
	     le32_to_cpu(msg->header.data_len));

	getnstimeofday(&msg->stamp);
	if (current->remotecache_plug) {
		list_add_tail(&msg->list_head,
				&current->remotecache_plug->list);
	} else {
		unsigned long flags;

		spin_lock_irqsave(&con->lock, flags);
		list_add_tail(&msg->list_head, &con->out_queue);

		/* if there wasn't anything waiting to send before, queue
		 * new work */
		if (test_and_set_bit(CON_FLAG_WRITE_PENDING, &con->flags) == 0)
			queue_con(con);
		spin_unlock_irqrestore(&con->lock, flags);
	}
}
EXPORT_SYMBOL(rc_con_send);

void rc_con_flush_plug(struct rc_connection *con, struct task_struct *tsk)
{
	struct remotecache_plug *plug = tsk->remotecache_plug;

	if (!plug)
		return;

	rc_debug("%s %p", __func__, con);

	if (!list_empty(&plug->list)) {
		unsigned long flags;

		spin_lock_irqsave(&con->lock, flags);
		list_splice_tail_init(&plug->list, &con->out_queue);

		if (test_and_set_bit(CON_FLAG_WRITE_PENDING, &con->flags) == 0)
			queue_con(con);
		spin_unlock_irqrestore(&con->lock, flags);
	}
}
EXPORT_SYMBOL(rc_con_flush_plug);

void rc_con_flush(struct rc_connection *con)
{
	flush_delayed_work(&con->work);
}
EXPORT_SYMBOL(rc_con_flush);

/*
 * Start buffering messages
 * This is similar to blk_start_plug/blk_finish_plug: each process has its own
 * plug so there is no need for synchronisation
 */
void rc_con_start_plug(struct remotecache_plug *plug)
{
	INIT_LIST_HEAD(&plug->list);

	if (!current->remotecache_plug)
		current->remotecache_plug = plug;
}
EXPORT_SYMBOL(rc_con_start_plug);

/*
 * Flush buffered messages
 */
void rc_con_finish_plug(struct rc_connection *con, struct remotecache_plug *plug)
{
	unsigned long flags;

	BUG_ON(!current->remotecache_plug);

	if (list_empty(&plug->list))
		goto out;

	spin_lock_irqsave(&con->lock, flags);
	list_splice_tail_init(&plug->list, &con->out_queue);

	if (test_and_set_bit(CON_FLAG_WRITE_PENDING, &con->flags) == 0)
		queue_con(con);
	spin_unlock_irqrestore(&con->lock, flags);

out:
	if (plug == current->remotecache_plug)
		current->remotecache_plug = NULL;
}
EXPORT_SYMBOL(rc_con_finish_plug);

/*
 * Returns the last buffered message if any. The caller might use the returned
 * message to iterate over the buffered messages
 */
struct rc_msg *rc_con_plug_last(void)
{
	struct rc_msg *msg = NULL;

	if(!current->remotecache_plug)
		goto out;

	if (!list_empty(&current->remotecache_plug->list)) {
		msg = list_entry(current->remotecache_plug->list.prev,
				struct rc_msg, list_head);
	}

out:
	return msg;
}
EXPORT_SYMBOL(rc_con_plug_last);

void rc_msg_add_page(struct rc_msg *msg, struct page *page)
{
	unsigned data_len = le32_to_cpu(msg->header.data_len);
	BUG_ON(!list_empty(&msg->pagelist));
	BUG_ON(msg->pages == NULL);

	get_page(page);
	msg->pages[msg->nr_pages++] = page;
	msg->header.data_len = cpu_to_le32(data_len+PAGE_SIZE);
}
EXPORT_SYMBOL(rc_msg_add_page);

void rc_msg_add_page_list(struct rc_msg *msg, struct page *page)
{
	unsigned data_len = le32_to_cpu(msg->header.data_len);
	BUG_ON(msg->pages != NULL);
	BUG_ON(!list_empty(&page->lru));

	get_page(page);
	list_add_tail(&page->lru, &msg->pagelist);
	msg->nr_pages++;
	msg->header.data_len = cpu_to_le32(data_len+PAGE_SIZE);
}
EXPORT_SYMBOL(rc_msg_add_page_list);

void rc_msg_del_page_list(struct rc_msg *msg, struct page *page)
{
	unsigned data_len = le32_to_cpu(msg->header.data_len);
	BUG_ON(msg->pages != NULL);
	BUG_ON(msg->nr_pages == 0);
	BUG_ON(list_empty(&page->lru));
	BUG_ON(list_empty(&msg->pagelist));


	list_del_init(&page->lru);
	msg->nr_pages--;
	msg->header.data_len = cpu_to_le32(data_len-PAGE_SIZE);
	put_page(page);
}
EXPORT_SYMBOL(rc_msg_del_page_list);

/*
 * construct a new message with given type, size
 * the new msg has a ref count of 1.
 */
struct rc_msg *rc_msg_new(int type, int front_len, int middle_len,
		int pages_len, gfp_t flags, bool can_fail)
{
	struct rc_msg *m;

	m = kmem_cache_alloc(remotecache_msg_cachep, flags);
	if (m == NULL)
		goto out;
	kref_init(&m->kref);

	m->con = NULL;
	INIT_LIST_HEAD(&m->list_head);

	m->header.seq = 0;
	m->header.type = cpu_to_le16(type);
	m->header.flags = 0;
	m->header.front_len = cpu_to_le32(front_len);
	m->header.middle_len = 0;
	m->header.data_len = 0;
	m->header.front_crc = 0;
	m->header.middle_crc = 0;
	m->header.data_crc = 0;
	m->header.crc = 0;
	m->more = false;
	m->pool = NULL;
	m->private = NULL;
	m->pages = NULL;
	m->nr_pages = 0;
	m->page = NULL;
	INIT_LIST_HEAD(&m->pagelist);
	m->front.iov_base = m->middle.iov_base = NULL;

	/* middle */
	if (middle_len) {
		m->middle.iov_base = kmalloc(middle_len, flags);
		if (m->middle.iov_base == NULL) {
			rc_debug("rc_msg_new can't allocate %d bytes\n",
			     middle_len);
			goto out2;
		}
	} else {
		m->middle.iov_base = NULL;
	}
	m->middle.iov_len = middle_len;

	/* data */
	if (pages_len) {
		m->pages = kzalloc(sizeof(*m->pages)*pages_len, flags);
		if (!m->pages) {
			rc_debug("rc_msg_new can't allocate %lu bytes\n",
					sizeof(*m->pages)*pages_len);
			goto out2;
		}
	} else {
		m->pages = NULL;
	}

	/* front */
	if (front_len) {
		m->front.iov_base = kmalloc(front_len, flags);
		if (m->front.iov_base == NULL) {
			rc_debug("rc_msg_new can't allocate %d bytes\n",
			     front_len);
			goto out2;
		}
	} else {
		m->front.iov_base = NULL;
	}
	m->front.iov_len = front_len;

	rc_debug("rc_msg_new %p front %d middle %d pages %d\n", m, front_len,
			middle_len, pages_len);
	return m;

out2:
	rc_msg_put(m);
out:
	if (!can_fail) {
		pr_err("msg_new can't create type %d front %d "
				"middle %d pages %d\n", type, front_len,
				middle_len, pages_len);
		WARN_ON(1);
	} else {
		rc_debug("msg_new can't create type %d front %d "
				"middle %d pages %d\n", type, front_len,
				middle_len, pages_len);
	}
	return NULL;
}
EXPORT_SYMBOL(rc_msg_new);

/*
 * Allocate a message for receiving an incoming message on a
 * connection, and save the result in con->in_msg.  Uses the
 * connection's private alloc_msg op if available.
 *
 * Returns 0 on success, or a negative error code.
 *
 * On success, if we set *skip = 1:
 *  - the next message should be skipped and ignored.
 *  - con->in_msg == NULL
 * or if we set *skip = 0:
 *  - con->in_msg is non-null.
 * On error (ENOMEM, EAGAIN, ...),
 *  - con->in_msg == NULL
 */
static int rc_con_in_msg_alloc(struct rc_connection *con, int *skip)
{
	struct rc_msg_header *header = &con->in_header;
	int type = le16_to_cpu(header->type);
	int front_len = le32_to_cpu(header->front_len);
	int middle_len = le32_to_cpu(header->middle_len);
	int nr_pages = le32_to_cpu(header->data_len)/PAGE_SIZE;
	size_t pages_len = sizeof(struct pages*)*nr_pages;
	int ret = 0;

	BUG_ON(con->in_msg != NULL);

	if (con->ops->alloc_msg) {
		struct rc_msg *msg;

		mutex_unlock(&con->mutex);
		msg = con->ops->alloc_msg(con, header, skip);
		mutex_lock(&con->mutex);
		if (con->state != CON_STATE_OPEN) {
			rc_msg_put(msg);
			return -EAGAIN;
		}
		con->in_msg = msg;
		if (con->in_msg) {
			con->in_msg->con = con->ops->get(con);
			BUG_ON(con->in_msg->con == NULL);
		}
		if (*skip) {
			con->in_msg = NULL;
			return 0;
		}
		if (!con->in_msg) {
			con->error_msg =
				"error allocating memory for incoming message";
			con->error = -ENOMEM;
			return -ENOMEM;
		}
	}
	if (!con->in_msg) {
		con->in_msg = rc_msg_new(type, front_len, middle_len,
				nr_pages, GFP_NOFS, false);
		if (!con->in_msg) {
			pr_err("unable to allocate msg type %d len %d+%d+%lu\n",
			       type, front_len, middle_len, pages_len);
			return -ENOMEM;
		}
		con->in_msg->con = con->ops->get(con);
		BUG_ON(con->in_msg->con == NULL);
	}
	memcpy(&con->in_msg->header, &con->in_header, sizeof(con->in_header));

	/*if (middle_len && !con->in_msg->middle.iov_base) {
		con->in_msg->middle.iov_base = kmalloc(middle_len, GFP_NOFS);
		if (!con->in_msg->middle.iov_base) {
			pr_err("unable to allocate middle msg len %d\n",
					middle_len);
			rc_msg_put(con->in_msg);
			con->in_msg = NULL;
			return -ENOMEM;
		}
		con->in_msg->middle.iov_len = middle_len;
	}*/

	return ret;
}

/*
 * Free a generically kmalloc'd message.
 */
void rc_msg_kfree(struct rc_msg *m)
{
	rc_debug("msg_kfree %p\n", m);

	/* drop middle, data, if any */
	kfree(m->middle.iov_base);
	kfree(m->front.iov_base);
	kfree(m->pages);
	kmem_cache_free(remotecache_msg_cachep, m);
}

/*
 * Drop a msg ref.  Destroy as needed.
 */
void rc_msg_last_put(struct kref *kref)
{
	struct rc_msg *m = container_of(kref, struct rc_msg, kref);

	rc_debug("rc_msg_put last one on %p\n", m);
	BUG_ON(!list_empty(&m->list_head));

	if (m->pages) {
		int i;
		for (i = 0; i < m->nr_pages; ++i) {
			put_page(m->pages[i]);
		}
	}
	m->nr_pages = 0;

	while (!list_empty(&m->pagelist)) {
		struct page *page = list_first_entry(&m->pagelist, struct page,
						     lru);
		list_del(&page->lru);
		put_page(page);
	}

	if (m->pool)
		rc_msgpool_put(m->pool, m);
	else
		rc_msg_kfree(m);
}
EXPORT_SYMBOL(rc_msg_last_put);
