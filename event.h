/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2018, Mitsumete Ishikawa
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TIFA_EVENT_H
#define __TIFA_EVENT_H

#include <sys/types.h>
#include <netinet/in.h>

#include "config.h"

typedef enum {
	EVENT_NONE		= 0,
	EVENT_READ		= (1LL << 0),
	EVENT_WRITE		= (1LL << 1),
	EVENT_TIMEOUT		= (1LL << 16),
	EVENT_FREE_PAYLOAD	= (1LL << 17),
	EVENT_TIMER		= (1LL << 32),
} event_flags_t;

struct __event_info;
typedef struct __event_info event_info_t;
typedef void (*event_callback_t)(event_info_t *info, event_flags_t eventflags);

struct __event_info {
	uint64_t ident;
	flags_t flags;
	time64_t time;
	event_callback_t callback;
	event_callback_t on_close;
	void *payload;
};

extern void event_handler_init(void);
extern event_info_t *event_add(int fd, event_flags_t eventflags,
	event_callback_t callback, void *payload, size_t payload_size);
extern void event_update(event_info_t *event, event_flags_t to_remove,
	event_flags_t to_add);
extern void event_remove(event_info_t *event);

extern event_info_t *timer_set(uint64_t msec_delay, event_callback_t callback,
	void *payload);
extern void timer_cancel(event_info_t *event);
extern void timer_remove(event_info_t *event);

extern void event_loop_start(void);

#endif /* __TIFA_EVENT_H */
