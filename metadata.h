/*
 *	metadata.h
 *
 *	Copyright (C) 2014
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef REMOTECACHE_METADATA_H
#define REMOTECACHE_METADATA_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/uuid.h>
#include <linux/shrinker.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include "remotecache.h"
#include "cache.h"

/*
 * Metadata tags, for tagging present and busy pages
 */
#define REMOTECACHE_TAG_BUSY 0
#define REMOTECACHE_TAG_PRESENT 1

void __remotecache_metadata_clear_busy(struct remotecache_inode *inode, pgoff_t index);
void __remotecache_metadata_set_busy(struct remotecache_inode *inode, pgoff_t index);
void remotecache_metadata_wait_busy(struct remotecache_inode *inode, pgoff_t index);
#endif /* REMOTECACHE_METADATA_H */
