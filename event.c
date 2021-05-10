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

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sysexits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef __linux__
#  include <sys/epoll.h>
#  include <sys/timerfd.h>
#else
#  include <sys/event.h>
#endif
#include "config.h"
#include "event.h"
#include "log.h"

static int __eventfd;

#define NUM_EVENTS 128
static event_info_t *__events_to_remove[NUM_EVENTS];

static void add_info_to_remove(event_info_t *info);

void
event_handler_init()
{
#ifdef __linux__
	if ((__eventfd = epoll_create1(0)) == -1)
#else
	if ((__eventfd = kqueue()) == -1)
#endif
		FAIL(EX_TEMPFAIL, "init_event_handler: kqueue: ",
				  strerror(errno));
}

static event_info_t *
event_info_alloc(int ident, event_callback_t callback, void *payload,
	size_t payload_size)
{
	event_info_t *res;

	res = calloc(1, sizeof(event_info_t) + payload_size);
#ifdef DEBUG_ALLOC
	lprintf("+EVENT %p %d", res, ident);
#endif

	res->ident = ident;
	res->time = time(NULL);
	res->callback = callback;

	if (payload) {
		if (payload_size) {
			res->payload = (uint8_t *)res + sizeof(event_info_t);
			bcopy(payload, res->payload, payload_size);
		} else {
			res->payload = payload;
		}
	}

	return (res);
}

event_info_t *
event_add(int fd, event_flags_t eventflags, event_callback_t callback,
	void *payload, size_t payload_size)
{
	event_info_t *res;

	res = event_info_alloc(fd, callback, payload, payload_size);
	res->flags = eventflags;

#ifdef __linux__
	struct epoll_event event;

	bzero(&event, sizeof(struct epoll_event));
	event.events = 0;
	if (eventflags & EVENT_READ)
		event.events |= EPOLLIN;
	if (eventflags & EVENT_WRITE)
		event.events |= EPOLLOUT;
	event.data.fd = fd;
	event.data.ptr = res;

	if (epoll_ctl(__eventfd, EPOLL_CTL_ADD, fd, &event) == -1)
		FAIL(EX_TEMPFAIL, "event_add: %s\n", strerror(errno));
#else
	struct kevent event;

	if (eventflags & EVENT_READ) {
		EV_SET(&event, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, res);
		if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
			FAIL(EX_TEMPFAIL, "event_add: %s\n", strerror(errno));
	}
	if (eventflags & EVENT_WRITE) {
		EV_SET(&event, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, res);
		if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
			FAIL(EX_TEMPFAIL, "event_add: %s\n", strerror(errno));
	}
#endif

	return (res);
}

event_info_t *
timer_set(uint64_t msec_delay, event_callback_t callback, void *payload)
{
	event_info_t *res;

	res = event_info_alloc(0, callback, payload, 0);
	res->flags = EVENT_TIMER;

#ifdef __linux__
	int first = FALSE;
	struct itimerspec ts;
	struct epoll_event event;

	res->ident = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);

	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	ts.it_value.tv_sec = msec_delay / 1000 + 1;
	ts.it_value.tv_nsec = msec_delay % 1000 * 1000;
	timerfd_settime(res->ident, 0, &ts, NULL);

	bzero(&event, sizeof(struct epoll_event));
	event.events = EVENT_READ;
	event.data.fd = res->ident;
	event.data.ptr = res;

	if (epoll_ctl(__eventfd, EPOLL_CTL_ADD, res->ident, &event) == -1)
		FAIL(EX_TEMPFAIL, "event_add: %s\n", strerror(errno));
#else
	struct kevent event;

	res->ident = (uintptr_t)res;

	EV_SET(&event, res->ident, EVFILT_TIMER,
		EV_ADD | EV_ENABLE | EV_ONESHOT, 0, msec_delay, res);

	if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
		FAIL(EX_TEMPFAIL, "timer_set: %s\n", strerror(errno));
#endif

	return (res);
}

void
timer_cancel(event_info_t *info)
{
#ifdef __linux__
#else
	struct kevent event;
#endif

	if (!(info->flags & EVENT_TIMER))
		FAIL(EX_SOFTWARE, "timer_cancel: info %p is not a timer", info);

#ifndef __linux__
	EV_SET(&event, info->ident, EVFILT_TIMER, EV_DELETE, 0, 0, info);

	if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
		lprintf("timer_cancel: %s\n", strerror(errno));
	else
		lprintf("timer_cancel: OKOKOK!!\n");
#endif

	timer_remove(info);
}

void
event_update(event_info_t *info, event_flags_t to_remove, event_flags_t to_add)
{
	if (info->flags & EVENT_TIMER)
		FAIL(EX_SOFTWARE, "event_update: info %p is a timer", info);

#ifdef __linux__
	struct epoll_event event;

	info->flags &= ~to_remove;
	info->flags |= to_add;
	bzero(&event, sizeof(struct epoll_event));
	event.events = 0;
	if (info->flags & EVENT_READ)
		event.events |= EPOLLIN;
	if (info->flags & EVENT_WRITE)
		event.events |= EPOLLOUT;
	event.data.fd = info->ident;
	event.data.ptr = info;

	if (epoll_ctl(__eventfd, EPOLL_CTL_MOD, info->ident, &event) == -1)
		FAIL(EX_TEMPFAIL, "event_update: %s\n", strerror(errno));
#else
	struct kevent event;

	if (to_remove & EVENT_READ && info->flags & EVENT_READ) {
		EV_SET(&event, info->ident, EVFILT_READ, EV_DELETE, 0, 0, info);
		if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
			lprintf("event_update: remove READ: %s",
				strerror(errno));
	}
	if (to_add & EVENT_READ && !(info->flags & EVENT_READ)) {
		EV_SET(&event, info->ident, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, info);
		if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
			lprintf("event_update: add READ: %s", strerror(errno));
	}
	if (to_remove & EVENT_WRITE && info->flags & EVENT_WRITE) {
		EV_SET(&event, info->ident, EVFILT_WRITE, EV_DELETE, 0, 0, info);
		if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
			lprintf("event_update: remove WRITE: %s",
				strerror(errno));
	}
	if (to_add & EVENT_WRITE && !(info->flags & EVENT_WRITE)) {
		EV_SET(&event, info->ident, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, info);
		if (kevent(__eventfd, &event, 1, NULL, 0, NULL) == -1)
			lprintf("event_update: add WRITE: %s", strerror(errno));
	}

	info->flags &= ~to_remove;
	info->flags |= to_add;
#endif
}

void
event_remove(event_info_t *info)
{
	if (info->flags & EVENT_TIMER)
		FAIL(EX_SOFTWARE, "event_remove: info %p is a timer", info);

	if (info->on_close)
		info->on_close(info, 0);
	close(info->ident);
	add_info_to_remove(info);
}

static void
event_free(event_info_t *info)
{
	size_t sz;

	sz = (uint8_t *)info->payload - (uint8_t *)info;
	if (info->payload && sz != sizeof(event_info_t) &&
		info->flags & EVENT_FREE_PAYLOAD)
		free(info->payload);

#ifdef DEBUG_ALLOC
	lprintf("-EVENT %p %d", info, info->ident);
#endif
	free(info);
}

void
timer_remove(event_info_t *info)
{
	if (!(info->flags & EVENT_TIMER))
		FAIL(EX_SOFTWARE, "timer_remove: info %p is not a timer", info);

#ifdef __linux__
	struct epoll_event event;
	char buf[1];

	read(info->ident, buf, 1); // disarm timer

	bzero(&event, sizeof(struct epoll_event));
	event.events = EVENT_READ;
	event.data.fd = info->ident;
	event.data.ptr = info;

	if (epoll_ctl(__eventfd, EPOLL_CTL_DEL, info->ident, &event) == -1)
		FAIL(EX_TEMPFAIL, "timer_remove: %s\n", strerror(errno));

	close(info->ident);
#endif

	event_free(info);
}

static void
add_info_to_remove(event_info_t *info)
{
	for (size_t i = 0; i < NUM_EVENTS; i++) {
		if (!__events_to_remove[i]) {
			__events_to_remove[i] = info;
			return;
		}
	}

	lprintf("add_info_to_remove: internal error: __events_to_remove full!");
}

static int
event_valid(event_info_t *info)
{
	for (size_t i = 0; i < NUM_EVENTS; i++)
		if (__events_to_remove[i] == info)
			return (FALSE);

	return (TRUE);
}

static void
#ifdef __linux__
event_process(time_t t, struct epoll_event event)
#else
event_process(time_t t, struct kevent event)
#endif
{
	event_flags_t eventflags = 0;
	event_info_t *info;
	int pending;
	int fd;

#ifdef __linux__
	if (event.events & EPOLLIN)
		eventflags = EVENT_READ;
	else if (event.events & EPOLLOUT)
		eventflags = EVENT_WRITE;

	info = event.data.ptr;
	fd = info->ident;
#else
	if (event.filter == EVFILT_READ)
		eventflags = EVENT_READ;
	if (event.filter == EVFILT_WRITE)
		eventflags = EVENT_WRITE;

	info = event.udata;
	fd = event.ident;
#endif

	if (!event_valid(info))
		return;

	if (info->flags & EVENT_TIMER) {
		info->callback(info, eventflags);
		timer_remove(info);
	} else {
		pending = -1;
		ioctl(fd, FIONREAD, &pending, sizeof(int));
#ifdef __linux__
		if (eventflags & EVENT_READ && !pending) {
#else
		if (event.flags & EV_EOF && !pending) {
#endif
			event_remove(info);
			return;
		}

		if (info->flags & EVENT_TIMEOUT) {
			if (t - info->time < 30) {
				info->callback(info, eventflags);
			} else
				event_remove(info);
		} else {
			info->callback(info, eventflags);
		}
	}
}

void
event_loop_start()
{
	time_t t;
	int n;

#ifdef __linux__
	struct epoll_event events[NUM_EVENTS];
#else
#define MAX_EVENTS 128
	struct kevent events[NUM_EVENTS];
#endif

	for(;;) {
		bzero(__events_to_remove, sizeof(__events_to_remove));
#ifdef __linux__
		switch((n = epoll_wait(__eventfd, events, NUM_EVENTS, -1))) {
#else
		switch((n = kevent(__eventfd, NULL, 0, events, NUM_EVENTS,
			NULL))) {
#endif
		case -1:
			if (errno != EINTR)
				FAIL(EX_TEMPFAIL, "event_loop: %s\n",
					strerror(errno));
		case 0:
			break;
		default:
			t = time(NULL);
			for (size_t i = 0; i < n; i++)
				event_process(t, events[i]);

			for (size_t i = 0; i < NUM_EVENTS; i++) {
				if (__events_to_remove[i])
					event_free(__events_to_remove[i]);
				else
					break;
			}
			break;
		}
	}
}
