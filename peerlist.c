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
#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include <netinet/in.h>
#include "peerlist.h"
#include "network.h"
#include "config.h"
#include "event.h"
#include "log.h"

peerlist_t peerlist = {
	.list4_size = 0,
	.list6_size = 0,
	.list4 = NULL,
	.list6 = NULL
};

#if defined(ALPHA)
static char *__network = "alpha";
#elif defined(BETA)
static char *__network = "beta";
#else
static char *__network = "gamma";
#endif

static const char *__bootstrap_server = "bootstrap.%s.tifa.network";

static event_info_t *__peerlist_timer = NULL;

static void peerlist_bootstrap(void);

void
peerlist_load()
{
	FILE *f;
	int r, s, len;
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
			len = strlen(tmp);
			if (len > 1) {
				tmp[len - 1] = '\0';
				if (inet_pton(AF_INET, tmp, &a4) == 1) {
					peerlist_add_ipv4(a4);
					s++;
				}
				r++;
			}
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
			len = strlen(tmp);
			if (len > 1) {
				tmp[len - 1] = '\0';
				if (inet_pton(AF_INET6, tmp, &a6) == 1) {
					peerlist_add_ipv6(a6);
					s++;
				}
				r++;
			}
		}
		fclose(f);
		lprintf("peerlist6: %d/%d peers loaded from cache", s, r - 1);
	} else {
		if (errno != ENOENT)
			lprintf("peerlist6: %s: %s", file, strerror(errno));
	}

	peerlist_bootstrap();
}

void
peerlist_save()
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
}

static void
__peerlist_request_tick(event_info_t *info, event_flags_t eventtype)
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

	message_broadcast(OP_PEERLIST, NULL, 0, 0);

	delay = randombytes_random() % 3600000;
	__peerlist_timer = timer_set(delay, __peerlist_request_tick, NULL);
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
		if (bcmp(&peerlist.list4[i], &addr, slen) == 0)
			return;

	if (peerlist.list4_size % 100 == 0)
		peerlist.list4 = realloc(peerlist.list4,
			(peerlist.list4_size + 100) * slen);

	peerlist.list4[peerlist.list4_size] = addr;
	peerlist.list4_size++;
#ifdef DEBUG_PEERLIST
	lprintf("peerlist_add_ipv4: %s", tmp);
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
		if (bcmp(&peerlist.list6[i], &addr, slen) == 0)
			return;

	if (peerlist.list6_size % 100 == 0)
		peerlist.list6 = realloc(peerlist.list6,
			(peerlist.list6_size + 100) * slen);

	peerlist.list6[peerlist.list6_size] = addr;
	peerlist.list6_size++;
#ifdef DEBUG_PEERLIST
	lprintf("peerlist_add_ipv6: %s", tmp);
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

	if ((network_is_ipv6_capable() && !peerlist.list4_size &&
		!peerlist.list6_size) ||
		(!network_is_ipv6_capable() && !peerlist.list4_size))
		peerlist_bootstrap();
}

void
peerlist_remove_ipv4(struct in_addr addr)
{
	small_idx_t i, slen;

	slen = sizeof(struct in_addr);
	for (i = 0; i < peerlist.list4_size; i++)
		if (bcmp(&peerlist.list4[i], &addr, slen) == 0)
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
		if (bcmp(&peerlist.list6[i], &addr, slen) == 0)
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
