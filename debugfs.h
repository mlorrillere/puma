/*
 * debugfs.h
 *
 * Copyright (C) 2015
 * Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 * LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef DEBUGFS_H
#define DEBUGFS_H

int remotecache_debugfs_init(void);
void remotecache_debugfs_exit(void);

void remotecache_debugfs_suspend(bool);

#endif /* DEBUGFS_H */
