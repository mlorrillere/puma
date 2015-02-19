/*
 *	heartbeat.c
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/slab.h>

#include "remotecache.h"
#include "node.h"
#include "session.h"
#include "messenger.h"

struct timer_list heartbeat_timer;
static unsigned int latency_high_threshold_us = 40000;
static unsigned int latency_low_threshold_us = 3000;
static unsigned int latency_avg_high_threshold_us = 2500;
static unsigned int latency_avg_low_threshold_us = 2000;
static unsigned int latency_smoothing_factor = 8;
static unsigned long heartbeat_frequency_ms = 500;
static bool heartbeat_enabled = false;

module_param(latency_high_threshold_us, uint, 0600);
module_param(latency_low_threshold_us, uint, 0600);
module_param(latency_avg_high_threshold_us, uint, 0600);
module_param(latency_avg_low_threshold_us, uint, 0600);
module_param(latency_smoothing_factor, uint, 0600);
module_param(heartbeat_frequency_ms, ulong, 0600);
module_param_named(enable_heartbeat, heartbeat_enabled, bool, 0400);

void heartbeat_suspend_session(struct remotecache_session *session)
{
	set_bit(REMOTECACHE_SESSION_HEARTBEAT, &session->flags);
	remotecache_session_suspend(session);
}

void heartbeat_resume_session(struct remotecache_session *session)
{
	clear_bit(REMOTECACHE_SESSION_HEARTBEAT, &session->flags);
	remotecache_session_resume(session);
}

bool heartbeat_session_is_suspended(struct remotecache_session *session)
{
	return remotecache_session_is_suspended(session) &&
		test_bit(REMOTECACHE_SESSION_HEARTBEAT, &session->flags);
}

void heartbeat_send_ping(struct remotecache_session *session)
{
	struct rc_ping_request *ping;
	struct rc_msg *msg;
	struct timespec now = {.tv_sec = 0, .tv_nsec = 0};

	if (test_and_set_bit(REMOTECACHE_SESSION_HEARTBEAT_PENDING, &session->flags)) {
		pr_err("%s heartbeat already sent, disabling session", __func__);
		heartbeat_suspend_session(session);
		return;
	}

	msg = rc_msg_new(RC_MSG_TYPE_PING, sizeof(*ping), 0, 0, GFP_NOWAIT, 1);
	if (!msg) {
		pr_err("%s: failed to alloc ping msg", __func__);
		return;
	}

	getnstimeofday(&now);
	ping = msg->front.iov_base;
	ping->stamp = timespec_to_ns(&now);

	rc_con_send(&session->con, msg);
}

void heartbeat_handle_ping(struct remotecache_session *session, struct rc_msg *msg)
{
	struct rc_ping_request *ping = msg->front.iov_base;
	struct rc_pong_response *pong;
	struct rc_msg *response;

	rc_debug("%s session %p", __func__, session);

	response = rc_msg_new(RC_MSG_TYPE_PONG, sizeof(*pong), 0, 0, GFP_NOWAIT, 1);
	if (!msg) {
		pr_err("%s: failed to alloc pong msg", __func__);
		return;
	}

	pong = response->front.iov_base;
	pong->stamp = ping->stamp;

	rc_con_send(&session->con, response);

	rc_msg_put(msg);
}

void heartbeat_check(struct remotecache_session *session)
{
	unsigned long latency_avg_high_threshold_ns = latency_avg_high_threshold_us * 1000;
	unsigned long latency_avg_low_threshold_ns = latency_avg_low_threshold_us * 1000;
	unsigned long latency_high_threshold_ns = latency_high_threshold_us * 1000;
	unsigned long latency_low_threshold_ns = latency_low_threshold_us * 1000;

	if (session->latency_15 > latency_avg_high_threshold_ns) {
		rc_debug("%s: average latency too high (%lldus, %lldus)\n",
				__func__, session->latency / 1000, session->latency_15 / 1000);
		heartbeat_suspend_session(session);
	} else if (session->latency > latency_high_threshold_ns) {
		rc_debug("%s: latency peak detected (%lldus, %lldus)\n",
				__func__, session->latency / 1000, session->latency_15 / 1000);
		heartbeat_suspend_session(session);
	} else if (session->latency < latency_low_threshold_ns) {
		if (heartbeat_session_is_suspended(session)) {
			rc_debug("%s: latency is getting better (%lldus, %lldus)\n",
					__func__, session->latency / 1000, session->latency_15 / 1000);
			heartbeat_resume_session(session);
		} else {
			rc_debug("%s: latency is good (%lldus, %lldus)\n",
					__func__, session->latency / 1000, session->latency_15 / 1000);
		}
	} else if (session->latency_15 < latency_avg_low_threshold_ns) {
		if (heartbeat_session_is_suspended(session)) {
			rc_debug("%s: average latency is getting better (%lldus, %lldus)\n",
					__func__, session->latency / 1000, session->latency_15 / 1000);
			heartbeat_resume_session(session);
		} else {
			rc_debug("%s: average latency is good (%lldus, %lldus)\n",
					__func__, session->latency / 1000, session->latency_15 / 1000);
		}
	} else {
		if (heartbeat_session_is_suspended(session)) {
			rc_debug("%s: latency is still high (%lldus, %lldus)\n",
					__func__, session->latency / 1000, session->latency_15 / 1000);
		}
		rc_debug("%s: latency is high (%lldus, %lldus)\n",
				__func__, session->latency / 1000, session->latency_15 / 1000);
	}
}

static inline u64 smooth(u64 old, u64 new, u64 factor)
{
	return (old * (factor - 1) + new) / factor;
}

void heartbeat_handle_pong(struct remotecache_session *session, struct rc_msg *msg)
{
	struct rc_pong_response *pong = msg->front.iov_base;
	struct timespec end = {.tv_sec = 0, .tv_nsec = 0};
	s64 latency;

	getnstimeofday(&end);

	clear_bit(REMOTECACHE_SESSION_HEARTBEAT_PENDING, &session->flags);

	latency = timespec_to_ns(&end) - pong->stamp;
	session->latency = smooth(latency, session->latency, latency_smoothing_factor);
	session->latency_15 = smooth(session->latency, latency, 15000 / heartbeat_frequency_ms);

	heartbeat_check(session);
	rc_debug("%s session %p\n", __func__, session);
	rc_msg_put(msg);
}


void heartbeat_timeout(unsigned long data)
{
	struct remotecache_node *node = (struct remotecache_node *)data;
	struct remotecache_session *session;

	rc_debug("%s node %p\n", __func__, node);

	rcu_read_lock();
	list_for_each_entry_rcu(session, &node->sessions, list) {
		heartbeat_send_ping(session);
	}
	rcu_read_unlock();

	mod_timer(&heartbeat_timer, jiffies + HZ * heartbeat_frequency_ms / 1000);
}

void heartbeat_start(struct remotecache_node *node)
{
	if (!heartbeat_enabled)
		return;

	init_timer(&heartbeat_timer);
	heartbeat_timer.data = (unsigned long) node;
	heartbeat_timer.function = heartbeat_timeout;

	mod_timer(&heartbeat_timer, jiffies + HZ * heartbeat_frequency_ms / 1000);
}

void heartbeat_stop(struct remotecache_node *node)
{
	if (!heartbeat_enabled)
		return;

	del_timer_sync(&heartbeat_timer);
}
