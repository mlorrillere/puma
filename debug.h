/*
 *	debug.h
 *
 *	Copyright (C) 2013
 *	Maxime Lorrillere <maxime.lorrillere@lip6.fr>
 *	LIP6 - Laboratoire d'Informatique de Paris 6
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <linux/time.h>

#if 1
#define timer_debug_start() \
	do { \
		char _log[16][128]; \
		int _n = 0; \
		struct timespec _start, _start2, _end, _delay; \
		const char *_func = __func__; \
		int _line = __LINE__, _i; \
		getnstimeofday(&_start); \
		_start2 = _start;

#define __timer_debug_stop() \
	getnstimeofday(&_end); \
	_delay = timespec_sub(_end, _start); \
	if (_delay.tv_sec > 0 || _delay.tv_nsec > 50000000) { \
		for (_i = 0; _i < _n; _i++) { \
			pr_info("%s", _log[_i]);\
		} \
		pr_info("[%s:%d -> %s:%d] %ld.%09ld\n", \
				_func, _line, __func__, __LINE__, \
				_delay.tv_sec, _delay.tv_nsec); \
	} \

#define timer_debug_stop() \
		__timer_debug_stop() \
	} while (0);

#define timer_debug_stop_cb(cb, cb_arg) \
		getnstimeofday(&_end); \
		_delay = timespec_sub(_end, _start); \
		if (_delay.tv_sec > 0 || _delay.tv_nsec > 750000) { \
			for (_i = 0; _i < _n; _i++) { \
				pr_info("%s", _log[_i]);\
			} \
			pr_info("[%s:%d -> %s:%d] %ld.%09ld\n", \
					_func, _line, __func__, __LINE__, \
					_delay.tv_sec, _delay.tv_nsec); \
			cb(_func, _line, __func__, __LINE__, cb_arg); \
		} \
	} while (0);

#define timer_debug_break() \
		do {\
			struct timespec _delay2;\
			getnstimeofday(&_end); \
			_delay = timespec_sub(_end, _start2); \
			_delay2 = timespec_sub(_end, _start); \
			_start2 = _end; \
			if (_n == 16) { \
				for (_i = 0; _i < _n; _i++) { \
					pr_info("%s", _log[_i]);\
				} \
				_n = 0;\
			} \
			sprintf(_log[_n++], "[%s:%d -> \t%s:%d] %ld.%09ld (%ld.%09ld)\n", \
				_func, _line, __func__, __LINE__, \
				_delay.tv_sec, _delay.tv_nsec, \
				_delay2.tv_sec, _delay2.tv_nsec); \
		} while (0);
#else
#define timer_debug_start()
#define timer_debug_stop()
#define timer_debug_break()
#endif

#endif /* DEBUG_H */
