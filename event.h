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

typedef useconds_t mseconds_t;

typedef enum {
	EVENT_NONE		= 0,
	EVENT_READ		= (1LL << 0),
	EVENT_WRITE		= (1LL << 1)
} event_direction_t;

typedef void (*event_callback_t)(void *info, void *payload);

typedef struct __event_callback_info {
	event_callback_t call;
	void *payload;
} event_callback_info_t;

typedef struct __event_fd {
	event_callback_info_t callback;
	struct timeval timeout;
	mseconds_t interval;
	int fd;
	event_direction_t direction;
} event_fd_t;

typedef struct __event_timer {
	event_callback_info_t callback;
	struct timeval timeout;
	mseconds_t interval;
	int repeats;
} event_timer_t;

extern void event_handler_init(void);
extern event_fd_t *event_fd_add(int fd, event_direction_t direction,
	event_callback_t callback, void *payload, size_t payload_size);
extern void event_fd_update(event_fd_t *event,
	event_direction_t new_direction);
extern void event_fd_remove(event_fd_t *event);
extern int event_fd_get(event_fd_t *event);
extern void event_fd_timeout_set(event_fd_t *event, mseconds_t msec_delay);

extern void *event_payload_get(event_fd_t *event);
extern void event_callback_set(event_fd_t *event, event_callback_t callback);

extern event_timer_t *event_timer_add(uint64_t msec_delay, int repeats,
	event_callback_t callback, void *payload);
extern void event_timer_remove(event_timer_t *event);

extern void event_loop_start(void);

extern void event_loop_poll(void);

#endif /* __TIFA_EVENT_H */
