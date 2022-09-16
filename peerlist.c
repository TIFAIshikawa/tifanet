/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2021, Mitsumete Ishikawa
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
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sodium.h>
#include <sys/param.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "opcode_callback.h"
#include "peerlist.h"
#include "network.h"
#include "endian.h"
#include "config.h"
#include "event.h"
#include "log.h"

#define PEERLIST_SAVE_DELAY_USECONDS (60 * 10 * 1000)

typedef struct {
	time64_t time;
	struct in_addr addr;
} ban_ipv4_t;

typedef struct {
	time64_t time;
	struct in6_addr addr;
} ban_ipv6_t;

typedef struct {
	size_t list4_size;
	size_t list6_size;
	ban_ipv4_t *list4;
	ban_ipv6_t *list6;
} ignorelist_t;

peerlist_t peerlist = {
	.list4_size = 0,
	.list6_size = 0,
	.list4 = NULL,
	.list6 = NULL
};

ignorelist_t ignorelist = {
	.list4_size = 0,
	.list6_size = 0,
	.list4 = NULL,
	.list6 = NULL
};

static const char *__bootstrap_server = "bootstrap.%s.tifa.network";

static event_timer_t *__peerlist_timer = NULL;
static event_timer_t *__peerlist_save_timer = NULL;

static void peerlist_bootstrap(void);
static void ignorelist_init(void);
static void ignorelist_add_ipv4(struct in_addr addr);
static void ignorelist_add_ipv6(struct in6_addr addr);
static int ignorelist_is_ignored_ipv4(struct in_addr addr);
static int ignorelist_is_ignored_ipv6(struct in6_addr addr);

static void
__peerlist_load_entry_sanitize(char *tmp)
{
	size_t len;

	len = strlen(tmp);
	if (len > 1) {
		if (tmp[len - 1] == '\n') {
			tmp[len - 1] = '\0';
			len--;
		}
	}
	if (len > 1) {
		if (tmp[len - 1] == '\r') {
			tmp[len - 1] = '\0';
			len--;
		}
	}
}

void
peerlist_load(void)
{
	FILE *f;
	int r, s;
	char file[MAXPATHLEN + 1];
	char tmp[INET6_ADDRSTRLEN + 2];
	struct in_addr a4;
	struct in6_addr a6;

	peerlist.list4 = malloc(100 * sizeof(struct in_addr));
	peerlist.list6 = malloc(100 * sizeof(struct in6_addr));

	if ((f = fopen(config_path_r(file, "peerlist4.txt"), "r"))) {
		r = s = 0;
		while (!feof(f)) {
			fgets(tmp, INET6_ADDRSTRLEN + 1, f);
			__peerlist_load_entry_sanitize(tmp);
			if (inet_pton(AF_INET, tmp, &a4) == 1) {
				peerlist_add_ipv4(a4);
				s++;
			}
			r++;
		}
		fclose(f);
		lprintf("peerlist4: %d/%d peers loaded from cache", s, r - 1);
	} else {
		if (errno != ENOENT)
			lprintf("peerlist4: %s: %s", file, strerror(errno));
	}

	if ((f = fopen(config_path_r(file, "peerlist6.txt"), "r"))) {
		r = s = 0;
		while (!feof(f)) {
			fgets(tmp, INET6_ADDRSTRLEN + 1, f);
			__peerlist_load_entry_sanitize(tmp);
			if (inet_pton(AF_INET6, tmp, &a6) == 1) {
				peerlist_add_ipv6(a6);
				s++;
			}
			r++;
		}
		fclose(f);
		lprintf("peerlist6: %d/%d peers loaded from cache", s, r - 1);
	} else {
		if (errno != ENOENT)
			lprintf("peerlist6: %s: %s", file, strerror(errno));
	}

	ignorelist_init();

	peerlist_bootstrap();
}

static void
__peerlist_save_tick(void *info, void *payload)
{
	__peerlist_save_timer = NULL;
	peerlist_save_sync();
}

void
peerlist_save(void)
{
	uint64_t delay;

	if (__peerlist_save_timer)
		return;

	delay = randombytes_random() % PEERLIST_SAVE_DELAY_USECONDS;
	__peerlist_save_timer = event_timer_add(delay, FALSE,
		__peerlist_save_tick, NULL);
}

void
peerlist_save_sync(void)
{
	FILE *f;
	int w, len;
	char file[MAXPATHLEN + 1];
	char tmp[INET6_ADDRSTRLEN + 2];

	if ((f = fopen(config_path_r(file, "peerlist4.txt"), "w+"))) {
		w = 0;
		for (size_t i = 0; i < peerlist.list4_size; i++) {
			inet_ntop(AF_INET, &peerlist.list4[i], tmp,
				  INET_ADDRSTRLEN);
			len = strlen(tmp);
			tmp[len] = '\n';
			len++;
			if (fwrite(tmp, len, 1, f) > 0)
				w++;
		}
		lprintf("peerlist4: %d/%d peers saved to cache", w,
			peerlist.list4_size);
		fclose(f);
	} else {
		lprintf("peerlist4: save to %s: %s", file, strerror(errno));
	}

	if ((f = fopen(config_path_r(file, "peerlist6.txt"), "w+"))) {
		w = 0;
		for (size_t i = 0; i < peerlist.list6_size; i++) {
			inet_ntop(AF_INET6, &peerlist.list6[i], tmp,
				  INET6_ADDRSTRLEN);
			len = strlen(tmp);
			tmp[len] = '\n';
			len++;
			if (fwrite(tmp, len, 1, f) > 0)
				w++;
		}
		lprintf("peerlist6: %d/%d peers saved to cache", w,
			peerlist.list6_size);
		fclose(f);
	} else {
		lprintf("peerlist6: save to %s: %s", file, strerror(errno));
	}

	peerlist_save();
}

static void
__peerlist_request_tick(void *info, void *payload)
{
	__peerlist_timer = NULL;

	peerlist_request_broadcast();
}

void
peerlist_request_broadcast(void)
{
	uint64_t delay;

	if (__peerlist_timer)
		return;

	peerlist_bootstrap();

	message_broadcast(OP_PEERLIST, NULL, 0, getpeerlist_userinfo());

	delay = randombytes_random() % 20;

	__peerlist_timer = event_timer_add(delay * 60 * 60 * 1000, FALSE,
		__peerlist_request_tick, NULL);
}

static void
peerlist_bootstrap(void)
{
	struct addrinfo hints, *info, *addr;
	char hostname[64];

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	snprintf(hostname, 63, __bootstrap_server, __network);
	hostname[63] = '\0';
	if (getaddrinfo(hostname, NULL, &hints, &info) == 0) {
		for (addr = info; addr; addr = addr->ai_next)
			peerlist_add((struct sockaddr_storage *)addr->ai_addr);
		freeaddrinfo(info);
	} else {
		lprintf("peerlist_bootstrap: %s: %s", hostname,
			strerror(errno));
	}
}

void
peerlist_add(struct sockaddr_storage *addr)
{
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6;

	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		peerlist_add_ipv4(a4->sin_addr);
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		peerlist_add_ipv6(a6->sin6_addr);
		break;
	default:
		lprintf("peerlist_add: unsupported ss_family: %d",
			addr->ss_family);
		break;
	}
}

void
peerlist_add_ipv4(struct in_addr addr)
{
	size_t slen;
	struct sockaddr_in a4 = { };
#ifdef DEBUG_PEERLIST
	char tmp[INET_ADDRSTRLEN + 1];
	inet_ntop(AF_INET, &addr, tmp, INET_ADDRSTRLEN);
#endif

	if (ignorelist_is_ignored_ipv4(addr))
		return;

	a4.sin_family = AF_INET;
	a4.sin_addr = addr;
	if (is_local_interface_address((struct sockaddr_storage *)&a4)) {
#ifdef DEBUG_PEERLIST
		lprintf("is_local_interface_address: %s", tmp);
#endif
		return;
	}

	if (is_nonroutable_address((struct sockaddr_storage *)&a4)) {
#ifdef DEBUG_PEERLIST
		lprintf("is_nonroutable_address: %s", tmp);
#endif
		return;
	}

	slen = sizeof(struct in_addr);
	for (size_t i = 0; i < peerlist.list4_size; i++)
		if (memcmp(&peerlist.list4[i], &addr, slen) == 0)
			return;

	if (peerlist.list4_size % 100 == 0)
		peerlist.list4 = realloc(peerlist.list4,
			(peerlist.list4_size + 100) * slen);

	peerlist.list4[peerlist.list4_size] = addr;
	peerlist.list4_size++;
#ifdef DEBUG_PEERLIST
	lprintf("peerlist_add_ipv4: %s @ %d", tmp, peerlist.list4_size);
#endif
}

void
peerlist_add_ipv6(struct in6_addr addr)
{
	size_t slen;
	struct sockaddr_in6 a6;
#ifdef DEBUG_PEERLIST
	char tmp[INET6_ADDRSTRLEN + 1];
	inet_ntop(AF_INET6, &addr, tmp, INET6_ADDRSTRLEN);
#endif

	if (ignorelist_is_ignored_ipv6(addr))
		return;

	bzero(&a6, sizeof(struct sockaddr_in6));
	a6.sin6_family = AF_INET6;
	a6.sin6_addr = addr;

	if (is_local_interface_address((struct sockaddr_storage *)&a6)) {
#ifdef DEBUG_PEERLIST
		lprintf("is_local_interface_address: %s", tmp);
#endif
		return;
	}

	if (is_nonroutable_address((struct sockaddr_storage *)&a6)) {
#ifdef DEBUG_PEERLIST
		lprintf("is_nonroutable_address: %s", tmp);
#endif
		return;
	}

	slen = sizeof(struct in6_addr);
	for (size_t i = 0; i < peerlist.list6_size; i++)
		if (memcmp(&peerlist.list6[i], &addr, slen) == 0)
			return;

	if (peerlist.list6_size % 100 == 0)
		peerlist.list6 = realloc(peerlist.list6,
			(peerlist.list6_size + 100) * slen);

	peerlist.list6[peerlist.list6_size] = addr;
	peerlist.list6_size++;
#ifdef DEBUG_PEERLIST
	lprintf("peerlist_add_ipv6: %s @ %d", tmp, peerlist.list6_size);
#endif
}

void
peerlist_remove(struct sockaddr_storage *addr)
{
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6;

	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		peerlist_remove_ipv4(a4->sin_addr);
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		peerlist_remove_ipv6(a6->sin6_addr);
		break;
	default:
		lprintf("peerlist_remove: unsupported ss_family: %d",
			addr->ss_family);
		break;
	}

	if (peerlist.list4_size < 2)
		peerlist_bootstrap();
}

void
peerlist_remove_ipv4(struct in_addr addr)
{
	small_idx_t i, slen;

	slen = sizeof(struct in_addr);
	for (i = 0; i < peerlist.list4_size; i++)
		if (memcmp(&peerlist.list4[i], &addr, slen) == 0)
			break;

	if (i == peerlist.list4_size)
		return;
		
	for (i = 0; i < peerlist.list4_size - 1; i++)
		bcopy(&peerlist.list4[i + 1], &peerlist.list4[i], slen);

	peerlist.list4_size--;
#ifdef DEBUG_PEERLIST
	char tmp[INET_ADDRSTRLEN + 1];
	inet_ntop(AF_INET, &addr, tmp, INET_ADDRSTRLEN);
	lprintf("peerlist_remove_ipv4: %s", tmp);
#endif
}

void
peerlist_remove_ipv6(struct in6_addr addr)
{
	small_idx_t i, slen;

	slen = sizeof(struct in6_addr);
	for (i = 0; i < peerlist.list6_size; i++)
		if (memcmp(&peerlist.list6[i], &addr, slen) == 0)
			break;

	if (i == peerlist.list6_size)
		return;
		
	for (i = 0; i < peerlist.list6_size - 1; i++)
		bcopy(&peerlist.list6[i + 1], &peerlist.list6[i], slen);

	peerlist.list6_size--;
#ifdef DEBUG_PEERLIST
	char tmp[INET6_ADDRSTRLEN + 1];
	inet_ntop(AF_INET6, &addr, tmp, INET6_ADDRSTRLEN);
	lprintf("peerlist_remove_ipv6: %s", tmp);
#endif
}

int
peerlist_address_random(struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	int version;
	int rnd;

	if (!peerlist.list4_size && !peerlist.list6_size)
		return (FALSE);

	if (!network_is_ipv6_capable() && !peerlist.list4_size)
		return (FALSE);

	if (peerlist.list4_size && peerlist.list6_size) {
		if (network_is_ipv6_capable())
			version = randombytes_random() % 2;
		else
			version = 0;
	} else {
		if (peerlist.list4_size)
			version = 0;
		else
			version = 1;
	}

	bzero(addr, sizeof(struct sockaddr_storage));

	if (version == 0) {
		rnd = randombytes_random() % peerlist.list4_size;
		a4 = (struct sockaddr_in *)addr;
		a4->sin_family = AF_INET;
		a4->sin_addr = peerlist.list4[rnd];
	} else {
		rnd = randombytes_random() % peerlist.list6_size;
		a6 = (struct sockaddr_in6 *)addr;
		a6->sin6_family = AF_INET6;
		a6->sin6_addr = peerlist.list6[rnd];
	}

	return (TRUE);
}

static void
ignorelist_init(void)
{
	if (ignorelist.list4)
		free(ignorelist.list4);
	if (ignorelist.list6)
		free(ignorelist.list6);

	ignorelist.list4_size = 0;
	ignorelist.list6_size = 0;
	ignorelist.list4 = malloc(100 * sizeof(struct in_addr));
	ignorelist.list6 = malloc(100 * sizeof(struct in6_addr));
}

static void
ignorelist_add_ipv4(struct in_addr addr)
{
	size_t slen;
	time64_t now;

	now = time(NULL);

	slen = sizeof(struct in_addr);
	for (size_t i = 0; i < ignorelist.list4_size; i++) {
		if (memcmp(&ignorelist.list4[i].addr, &addr, slen) == 0) {
			ignorelist.list4[i].time = now;
			return;
		}
	}

	if (ignorelist.list4_size % 100 == 0)
		ignorelist.list4 = realloc(ignorelist.list4,
			(ignorelist.list4_size + 100) * slen);

	ignorelist.list4[ignorelist.list4_size].time = now;
	ignorelist.list4[ignorelist.list4_size].addr = addr;
	ignorelist.list4_size++;
}

static void
ignorelist_add_ipv6(struct in6_addr addr)
{
	size_t slen;
	time64_t now;

	now = time(NULL);

	slen = sizeof(struct in6_addr);
	for (size_t i = 0; i < ignorelist.list6_size; i++) {
		if (memcmp(&ignorelist.list6[i].addr, &addr, slen) == 0) {
			ignorelist.list6[i].time = now;
			return;
		}
	}

	if (ignorelist.list6_size % 100 == 0)
		ignorelist.list6 = realloc(ignorelist.list6,
			(ignorelist.list6_size + 100) * slen);

	ignorelist.list6[ignorelist.list6_size].time = now;
	ignorelist.list6[ignorelist.list6_size].addr = addr;
	ignorelist.list6_size++;
}

void
peerlist_ignore(struct sockaddr_storage *addr)
{
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6;

	peerlist_remove(addr);
	lprintf("peer %s has been ignored", peername(addr));

	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		ignorelist_add_ipv4(a4->sin_addr);
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		ignorelist_add_ipv6(a6->sin6_addr);
		break;
	default:
		lprintf("peerlist_ignore: unsupported ss_family: %d",
			addr->ss_family);
		break;
	}
}

static int
ignorelist_is_ignored_ipv4(struct in_addr addr)
{
	int res = FALSE;
	size_t slen, sz;
	time64_t expired;

	expired = time(NULL) - (30 * HOUR_SECONDS);

	slen = sizeof(struct in_addr);

	for (size_t i = 0; i < ignorelist.list4_size; i++) {
		if (ignorelist.list4[i].time < expired) {
			sz = sizeof(ban_ipv4_t) * (ignorelist.list4_size - i - 1);
			bcopy(ignorelist.list4 + 1, ignorelist.list4, sz);
			ignorelist.list4_size--;
			i--;
		} else if (memcmp(&ignorelist.list4[i].addr, &addr, slen) == 0) {
			res = TRUE;
		}
	}

	return (res);
}

static int
ignorelist_is_ignored_ipv6(struct in6_addr addr)
{
	int res = FALSE;
	size_t slen, sz;
	time64_t expired;

	expired = time(NULL) - (30 * HOUR_SECONDS);

	slen = sizeof(struct in6_addr);

	for (size_t i = 0; i < ignorelist.list6_size; i++) {
		if (ignorelist.list6[i].time < expired) {
			sz = sizeof(ban_ipv6_t) * (ignorelist.list6_size - i - 1);
			bcopy(ignorelist.list6 + 1, ignorelist.list6, sz);
			ignorelist.list6_size--;
			i--;
		} else if (memcmp(&ignorelist.list6[i].addr, &addr, slen) == 0) {
			res = TRUE;
		}
	}

	return (res);
}

int
ignorelist_is_ignored(struct sockaddr_storage *addr)
{
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6;

	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		return (ignorelist_is_ignored_ipv4(a4->sin_addr));
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		return (ignorelist_is_ignored_ipv6(a6->sin6_addr));
	default:
		lprintf("peerlist_ignore: unsupported ss_family: %d",
			addr->ss_family);
		break;
	}

	return (FALSE);
}

void
ignorelist_reset(void)
{
	ignorelist_init();
}

int
peerlistcache_remove(void)
{
	int r[2];

	r[0] = config_unlink("peerlist4.txt");
	r[1] = config_unlink("peerlist6.txt");

	return (r[0] && r[1]);
}

