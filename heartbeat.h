/*
 *	heartbeat.c
 *
 *	Copyright (C) 2012
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

struct remotecache_node;
struct remotecache_session;
struct rc_msg;

void heartbeat_start(struct remotecache_node *node);
void heartbeat_stop(struct remotecache_node *node);
void heartbeat_handle_ping(struct remotecache_session *, struct rc_msg *);
void heartbeat_handle_pong(struct remotecache_session *, struct rc_msg *);
