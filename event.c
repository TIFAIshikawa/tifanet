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

#include <poll.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sysexits.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "config.h"
#include "event.h"
#include "vlist.h"
#include "log.h"

#define NUM_EVENTS 128

#ifdef __OpenBSD__
typedef __uintptr_t uintptr_t;
#endif

static struct pollfd *__pollfds = NULL;
static size_t __nfds = 0;

static vlist_t *__event_fds = NULL;
static vlist_t *__event_timers = NULL;

static void event_free(void *info);

void
event_handler_init()
{
	if (__pollfds)
		return;

	__nfds = 10;
	__pollfds = calloc(1, sizeof(struct pollfd) * __nfds);
	for (size_t i = 0; i < __nfds; i++)
		__pollfds[i].fd = -1;

	__event_fds = vlist_init(10);
	__event_timers = vlist_init(10);
}

static void *
event_base_alloc(size_t size, event_callback_t callback, void *payload,
	size_t payload_size)
{
	event_callback_info_t *res;

	res = calloc(1, size + payload_size);
#ifdef DEBUG_ALLOC
	lprintf("+EVENT %p", res);
#endif

	res->call = callback;

	if (payload) {
		if (payload_size) {
			res->payload = (char *)res + size;
			bcopy(payload, res->payload, payload_size);
		} else {
			res->payload = payload;
		}
	}

	return (res);
}

event_fd_t *
event_fd_add(int fd, event_direction_t direction,
        event_callback_t callback, void *payload, size_t payload_size)
{
	size_t i, o;
	event_fd_t *res;

	res = (event_fd_t *)event_base_alloc(sizeof(event_fd_t), callback,
				payload, payload_size);
	res->fd = fd;
	res->direction = direction;

	for (i = 0; i < __nfds; i++) {
		if (__pollfds[i].fd == -1) {
			__pollfds[i].fd = res->fd;
			__pollfds[i].events = 0;
			//if (direction & EVENT_READ)
				__pollfds[i].events |= POLLIN;
			if (direction & EVENT_WRITE)
				__pollfds[i].events |= POLLOUT;
			break;
		}
	} 
	if (i == __nfds) {
		o = __nfds;
		__nfds += 10;
		__pollfds = realloc(__pollfds, sizeof(struct pollfd) * __nfds);
		for (; o < __nfds; o++) {
			__pollfds[o].fd = -1;
			__pollfds[o].events = 0;
		}
	}

	vlist_item_add(__event_fds, res);

	return (res);
}

void
event_fd_update(event_fd_t *info, event_direction_t direction)
{
	for (size_t i = 0; i < __nfds; i++) {
		if (__pollfds[i].fd == info->fd) {
			__pollfds[i].events = 0;
			//if (direction & EVENT_READ)
				__pollfds[i].events |= POLLIN;
			if (direction & EVENT_WRITE)
				__pollfds[i].events |= POLLOUT;
			return;
		}
	} 
}

void
event_fd_remove(event_fd_t *info)
{
	event_fd_t *fde;

	vlist_item_remove(__event_fds, info);

	fde = (event_fd_t *)info;
	for (size_t i = 0; i < __nfds; i++) {
		if (__pollfds[i].fd == fde->fd) {
			__pollfds[i].fd = -1;
			__pollfds[i].events = 0;
			break;
		}
	}

	event_free(info);
}

void
event_fd_timeout_set(event_fd_t *event, mseconds_t msec_delay)
{
	struct timeval now, tv;

	gettimeofday(&now, NULL);
	msec_delay *= 1000;
	tv.tv_sec = msec_delay / 1000000;
	tv.tv_usec = msec_delay - (tv.tv_sec * 1000000);
	timeradd(&now, &tv, &event->timeout);
}

int
event_fd_get(event_fd_t *event)
{
	return (event->fd);
}

void *
event_payload_get(event_fd_t *event)
{
	return (event->callback.payload);
}

void
event_callback_set(event_fd_t *event, event_callback_t callback)
{
	((event_fd_t *)event)->callback.call = callback;
}

static void
event_free(void *info)
{
#ifdef DEBUG_ALLOC
	lprintf("-EVENT %p", info);
#endif
	free(info);
}

event_timer_t *
event_timer_add(uint64_t msec_delay, int repeats,
        event_callback_t callback, void *payload)
{
	struct timeval now, tv;
	event_timer_t *res;

	res = (event_timer_t *)event_base_alloc(sizeof(event_timer_t), callback,
				payload, 0);

	res->repeats = repeats;
	res->interval = msec_delay;

	gettimeofday(&now, NULL);
	tv.tv_sec = 0;
	tv.tv_usec = msec_delay * 1000;
	timeradd(&now, &tv, &res->timeout);

	vlist_item_add(__event_timers, res);

	return (res);
}

void
event_timer_remove(event_timer_t *info)
{
	vlist_item_remove(__event_timers, info);

	event_free(info);
}

static void
__event_fire_for_fd(char *item, void *payload)
{
	size_t *i;
	event_fd_t *event;

	event = (event_fd_t *)item;
	i = (size_t *)payload;

	if (event->fd == __pollfds[*i].fd) {
char revents[1024];
revents[0] = 0;
if (__pollfds[*i].revents & POLLIN) strcat(revents, "POLLIN ");
if (__pollfds[*i].revents & POLLOUT) strcat(revents, "POLLOUT ");
if (__pollfds[*i].revents & POLLHUP) strcat(revents, "POLLHUP ");
if (__pollfds[*i].revents & POLLERR) strcat(revents, "POLLERR ");
if (__pollfds[*i].revents & POLLNVAL) strcat(revents, "POLLNVAL ");
lprintf("%d: %s", event->fd, revents);
		if (__pollfds[*i].revents & POLLHUP)
			errno = ECONNRESET;
		else
			errno = 0;
		event->callback.call(event, event->callback.payload);
	}
}

static void
__events_check_poll_results(void)
{
	errno = 0;

	for (size_t i = 0; i < __nfds; i++) {	
		if (!__pollfds[i].revents)
			continue;

		vlist_loop(__event_fds, __event_fire_for_fd, &i);
	}
}

static void
__event_fds_check_timeout(char *item, void *payload)
{
	event_fd_t *event;
	struct timeval *now;

	event = (event_fd_t *)item;
	now = (struct timeval *)payload;

	if (!event->timeout.tv_sec && !event->timeout.tv_usec)
		return;

	if (timercmp(&event->timeout, now, > ))
		return;

	// close() will cause read/write errors, so upstream will act
	// accordingly
lprintf("TIMEOUT %d %p", event->fd, event);
	close(event->fd);
	errno = ETIMEDOUT;
	event->callback.call(event, event->callback.payload);
}

static void
__event_timers_check_timeout(char *item, void *payload)
{
	event_timer_t *timer;
	struct timeval *now;

	timer = (event_timer_t *)item;
	now = (struct timeval *)payload;

	if (timercmp(&timer->timeout, now, > ))
		return;

	timer->callback.call(timer, timer->callback.payload);

	if (!timer->repeats) {
		event_timer_remove((event_timer_t *)item);
		return;
	}

	bcopy(now, &timer->timeout, sizeof(struct timeval));
}

static void
__event_loop_poll(int timeout)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	for (size_t i = 0; i < __nfds; i++)
		__pollfds[i].revents = 0;
	if (poll(__pollfds, __nfds, timeout) > 0)
		__events_check_poll_results();

	vlist_loop(__event_fds, __event_fds_check_timeout, &now);
	vlist_loop(__event_timers, __event_timers_check_timeout, &now);
}

void
event_loop_start(void)
{
	for (;;)
		__event_loop_poll(1);
}

void
event_loop_poll(void)
{
	__event_loop_poll(0);
}
