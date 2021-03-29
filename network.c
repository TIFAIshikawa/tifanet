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
#include "log.h"
#include "event.h"
#include "notar.h"
#include "config.h"
#include "network.h"
#include "opcode_callback.h"

char *opcode_names[OP_MAXOPCODE] = {
	"OP_NONE",
	"OP_PEERLIST",
	"OP_LASTBLOCKINFO",
	"OP_GETBLOCK",
	"OP_ANNOUNCE_NOTAR",
	"OP_DENOUNCE_NOTAR",
	"OP_ANNOUNCE_BLOCK",
	"OP_TRANSACTION",
	"OP_GETTXCACHE",
	"OP_GETNOTARS"
};

peerlist_t peerlist = {
	.list4_size = 0,
	.list6_size = 0,
	.list4_alloc = 0,
	.list6_alloc = 0,
	.list4 = NULL,
	.list6 = NULL
};

static char *__network = "dev1";
static const char *__bootstrap_server = "bootstrap.%s.tifa.network";
static struct ifaddrs *__ifaddrs = NULL;

static void peerlist_lookup(void);

static void peerlist_add(struct sockaddr_storage *addr);
static void peerlist_add_ipv4(struct in_addr addr);
static void peerlist_add_ipv6(struct in6_addr addr);

static void accept_notar_connection(event_info_t *, event_flags_t);

static event_info_t *__listen_info = NULL;

static void socket_set_async(int fd)
{
	int opt;

        if ((opt = fcntl(fd, F_GETFL, 0)) == -1)
                FAIL(EX_TEMPFAIL, "socket_set_async: fcntl(F_GETFL): %s",
                                  strerror(errno));
        if ((opt = fcntl(fd, F_SETFL, opt | O_NONBLOCK)) == -1)
                FAIL(EX_TEMPFAIL, "socket_set_async: fcntl(F_SETFL): %s",
                                  strerror(errno));
}

static void
socket_set_timeout(int fd, unsigned int sec_timeout)
{
	int timeout;

	timeout = sec_timeout * 1000;

	setsockopt(fd, 6, 18, &timeout, sizeof(timeout));
}
 
void
peerlist_load()
{
	FILE *f;
	int r, s, len;
	char file[MAXPATHLEN + 1];
	char tmp[INET6_ADDRSTRLEN + 2];
	struct in_addr a4;
	struct in6_addr a6;

	peerlist.list4_alloc = 64;
	peerlist.list4 = malloc(peerlist.list4_alloc * sizeof(struct in_addr));
	peerlist.list6_alloc = 64;
	peerlist.list6 = malloc(peerlist.list6_alloc * sizeof(struct in6_addr));

	if ((f = fopen(config_path(file, "peerlist4.txt"), "r"))) {
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

	if ((f = fopen(config_path(file, "peerlist6.txt"), "r"))) {
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

	peerlist_lookup();
}

void peerlist_save()
{
return;
	FILE *f;
	int w, len;
	char tmp[INET6_ADDRSTRLEN + 2];

	if ((f = fopen(config_path(tmp, "peerlist4.txt"), "w+"))) {
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
		lprintf("peerlist4: save to %s: %s", tmp, strerror(errno));
	}

	if ((f = fopen(config_path(tmp, "peerlist6.txt"), "w+"))) {
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
		lprintf("peerlist6: save to %s: %s", tmp, strerror(errno));
	}
}

static void
peerlist_lookup(void)
{
	struct addrinfo hints, *info, *addr;
	char hostname[64];
	struct in_addr a4;
	struct in6_addr a6;

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	snprintf(hostname, 63, __bootstrap_server, __network);
	hostname[63] = '\0';
	if (getaddrinfo(hostname, NULL, &hints, &info) == 0) {
		for (addr = info; addr; addr = addr->ai_next) {
			switch(addr->ai_family) {
			case AF_INET:
				a4 = ((struct sockaddr_in *)addr->ai_addr)->sin_addr;
				peerlist_add_ipv4(a4);
				break;
			case AF_INET6:
				a6 = ((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr;
				peerlist_add_ipv6(a6);
				break;
			}
		}
		freeaddrinfo(info);
	} else {
		lprintf("peerlist_lookup: %s: %s", hostname, strerror(errno));
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
		lprintf("peerlist_add: unsupported ss_family: %d\n",
		addr->ss_family);
		break;
	}
}

void
peerlist_add_ipv4(struct in_addr addr)
{
	for (size_t i = 0; i < peerlist.list4_size; i++) {
		if (memcmp(&peerlist.list4[i], &addr,
			sizeof(struct in_addr)) == 0)
			return;
	}

	if (peerlist.list4_size == peerlist.list4_alloc) {
		peerlist.list4_alloc += 64;
		peerlist.list4 = realloc(peerlist.list4, peerlist.list4_alloc *
					 sizeof(struct in_addr));
	}

	peerlist.list4[peerlist.list4_size] = addr;
	peerlist.list4_size++;
}

void
peerlist_add_ipv6(struct in6_addr addr)
{
	for (size_t i = 0; i < peerlist.list6_size; i++) {
		if (memcmp(&peerlist.list6[i], &addr,
			sizeof(struct in6_addr)) == 0)
			return;
	}

	if (peerlist.list6_size == peerlist.list6_alloc) {
		peerlist.list6_alloc += 64;
		peerlist.list6 = realloc(peerlist.list6, peerlist.list6_alloc *
					 sizeof(struct in6_addr));
	}

	peerlist.list6[peerlist.list6_size] = addr;
	peerlist.list6_size++;
}

char *
peername(struct sockaddr_storage *addr, char *dst)
{
	void *p;
	struct sockaddr_in *a4;
	struct sockaddr_in6 *a6;

	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		p = &a4->sin_addr;
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		p = &a6->sin6_addr;
		break;
	default:
		snprintf(dst, INET6_ADDRSTRLEN, "ss_family unsupported: %d",
			addr->ss_family);
		return (dst);
	}
	inet_ntop(addr->ss_family, p, dst, INET6_ADDRSTRLEN);

	return (dst);
}

void
listen_socket_open()
{
	struct sockaddr_in addr;
	int opt = 1;
	int fd;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(TIFA_NETWORK_PORT);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		FAIL(EX_TEMPFAIL, "listen_socket_open: socket: %s",
				  strerror(errno));

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
		FAIL(EX_TEMPFAIL, "listen_socket_open: setsockopt: %s",
				  strerror(errno));

	socket_set_async(fd);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		FAIL(EX_TEMPFAIL, "listen_socket_open: bind: %s",
				  strerror(errno));

	if (listen(fd, SOMAXCONN) == -1)
		FAIL(EX_TEMPFAIL, "listen_socket_open: listen: %s",
				  strerror(errno));

	__listen_info = event_add(fd, EVENT_READ, accept_notar_connection,
				NULL);

	lprintf("listening for connections...");
}

void
accept_notar_connection(event_info_t *info, event_flags_t eventtype)
{
	struct sockaddr_in addr;
	network_event_t *nev;
	socklen_t len;
	int fd;

	if ((fd = accept(info->ident, (struct sockaddr *)&addr, &len)) == -1)
		FAIL(EX_TEMPFAIL, "accept_notar_connection: accept: %s",
				  strerror(errno));

	socket_set_async(fd);

	socket_set_timeout(fd, 10);

	nev = calloc(1, sizeof(network_event_t));
	nev->type = NETWORK_EVENT_TYPE_SERVER;
	event_add(fd, EVENT_READ | EVENT_TIMEOUT | EVENT_FREE_PAYLOAD,
		message_read, nev);
}

void
message_cancel(event_info_t *info)
{
	network_event_t *nev;

	nev = info->payload;
	if (nev->userdata && info->flags & EVENT_FREE_PAYLOAD)
		free(nev->userdata);

	event_remove(info);
}

void
message_read(event_info_t *info, event_flags_t eventtype)
{
	network_event_t *nev;
	small_idx_t size;
	message_t *msg;
	char *ptr;
	int want;
	int r;

	if (eventtype & EVENT_WRITE)
		return;

	nev = info->payload;
	msg = &nev->message_header;
	switch (nev->state) {
	case NETWORK_EVENT_STATE_HEADER:
		ptr = (void *)&nev->message_header + nev->read_idx;
		want = sizeof(message_t) - nev->read_idx;
		if ((r = read(info->ident, ptr, want)) == -1) {
			if (errno != EAGAIN) {
				message_cancel(info);
				return;
			}
			r = 0;
		}
		nev->read_idx += r;
		if (nev->read_idx == sizeof(message_t)) {
			if (bcmp(msg->magic, TIFA_IDENT,
				sizeof(magic_t)) != 0) {
				printf("message_read: invalid magic\n");
				message_cancel(info);
				return;
			}
			if ((size = be32toh(msg->payload_size))) {
				if (size > MAXPACKETSIZE) {
					printf("message_read: size too large: "
						"%d\n", size);
					message_cancel(info);
					return;
				}
				if (!opcode_valid(msg)) {
					printf("message_read: opcode invalid: "
						"%u\n", be32toh(msg->opcode));
					message_cancel(info);
					return;
				}
				if (!opcode_payload_size_valid(msg, nev->type)) {
					printf("message_read: size %d not "
						"valid for opcode %d\n", size,
						be32toh(msg->opcode));
					message_cancel(info);
					return;
				}
				nev->userdata = malloc(size);
			}
			nev->read_idx = 0;
			nev->state = NETWORK_EVENT_STATE_BODY;
			message_read(info, eventtype);
		}
		break;
	case NETWORK_EVENT_STATE_BODY:
		ptr = (void *)nev->userdata + nev->read_idx;
		want = be32toh(msg->payload_size) - nev->read_idx;
		if (nev->read_idx != want) {
			if ((r = read(info->ident, ptr, want)) == -1) {
				if (errno != EAGAIN) {
					message_cancel(info);
					return;
				}
				r = 0;
			}
			nev->read_idx += r;
		}

		if (nev->read_idx == be32toh(msg->payload_size)) {
			event_update(info, EVENT_READ, EVENT_WRITE);
			handle_network_call(info);
		}
		break;
	default:
		FAIL(EX_SOFTWARE, "message_read: illegal state: %d\n",
		      nev->state);
	}
}

void
message_write(event_info_t *info, event_flags_t eventtype)
{
	network_event_t *nev;
	message_t *msg;
	char *ptr;
	int want;
	int r;

	if (eventtype & EVENT_READ)
		return;

	nev = info->payload;
	msg = &nev->message_header;
	switch (nev->state) {
	case NETWORK_EVENT_STATE_HEADER:
		ptr = (void *)&nev->message_header + nev->write_idx;
		want = sizeof(message_t) - nev->write_idx;
		if ((r = write(info->ident, ptr, want)) <= 0) {
			message_cancel(info);
			return;
		}
		nev->write_idx += r;
		if (nev->write_idx == sizeof(message_t)) {
			nev->write_idx = 0;
			nev->state = NETWORK_EVENT_STATE_BODY;
			message_write(info, eventtype);
		}
		break;
	case NETWORK_EVENT_STATE_BODY:
		ptr = (void *)nev->userdata + nev->write_idx;
		want = be32toh(msg->payload_size) - nev->write_idx;
		if (nev->write_idx != want) {
			if ((r = write(info->ident, ptr, want)) <= 0) {
				message_cancel(info);
				return;
			}
			nev->write_idx += r;
		}

		if (nev->write_idx == be32toh(msg->payload_size)) {
			event_update(info, EVENT_WRITE, EVENT_READ);
			if (nev->type == NETWORK_EVENT_TYPE_CLIENT) {
				nev->state = NETWORK_EVENT_STATE_HEADER;
				info->callback = message_read;
			} else
				message_cancel(info);
		}
		break;
	default:
		FAIL(EX_SOFTWARE, "message_write: illegal state: %d\n",
		      nev->state);
	}
}

static event_info_t *
request_send(struct sockaddr_storage *addr, message_t *message, void *payload)
{
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	network_event_t *nev;
	event_info_t *res;
	socklen_t len;
	int fd;

	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		a4->sin_port = htons(TIFA_NETWORK_PORT);
		len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		a6->sin6_port = htons(TIFA_NETWORK_PORT);
		len = sizeof(struct sockaddr_in6);
		break;
	default:
		return (NULL);
	}

	if ((fd = socket(addr->ss_family, SOCK_STREAM, 0)) == -1)
		FAIL(EX_TEMPFAIL, "request_send: socket: %s\n",
			strerror(errno));

// TODO: don't use async connect() for now	socket_set_async(fd);

	if (connect(fd, (struct sockaddr *)addr, len) == -1) {
		// EINPROGRESS will be handled by event loop. Other errors
		// are fatal. Don't log common errors though.
		if (errno != EINPROGRESS) {
			if (errno != ECONNREFUSED && errno != ECONNRESET &&
				errno != EINTR)
				lprintf("request_send: connect: %s",
					strerror(errno));
			close(fd);
			return (NULL);
		}
	}

	nev = calloc(1, sizeof(network_event_t));
	nev->type = NETWORK_EVENT_TYPE_CLIENT;
	bcopy(message, &nev->message_header, sizeof(message_t));
	nev->userdata = payload;
	bcopy(&nev->remote_addr, addr, len);
	nev->remote_addr_len = len;
	nev->userdata_size = be32toh(message->payload_size);

	res = event_add(fd, EVENT_WRITE | EVENT_TIMEOUT | EVENT_FREE_PAYLOAD,
			message_write, nev);

	message_write(res, EVENT_WRITE);

	socket_set_timeout(fd, 10);

	return (res);

}

network_event_t *
network_event(event_info_t *info)
{
	return (info->payload);
}

message_t *
network_message(event_info_t *info)
{
	return &network_event(info)->message_header;
}

static message_t *
message_alloc(void)
{
	message_t *res;

	res = malloc(sizeof(message_t));
#ifdef DEBUG_ALLOC
	printf("+MESSAGE %p\n", res);
#endif

	return (res);
}

static message_t *
message_create(opcode_t opcode, small_idx_t size, userinfo_t info)
{
	time64_t t;
	message_t *res;

	t = time(NULL);

	res = message_alloc();
	bcopy(TIFA_IDENT, res->magic, sizeof(magic_t));
	res->opcode = htobe32(opcode);
	res->userinfo = info;
	res->payload_size = htobe32(size);

	return (res);
}

static void
message_free(message_t *message)
{
	free(message);
#ifdef DEBUG_ALLOC
	printf("-MESSAGE %p\n", message);
#endif
}

event_info_t *
message_send(struct sockaddr_storage *addr, opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info)
{
	event_info_t *res;
	message_t *msg;

	msg = message_create(opcode, size, info);

	if ((res = request_send(addr, msg, payload)))
		return (res);

	message_free(msg);
	return (NULL);
}

void
peer_address_random(struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	int version;
	int rnd;

	bzero(addr, sizeof(struct sockaddr_storage));

	if (peerlist.list6_size)
		version = randombytes_random() % 2;
	else
		version = 0;

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
}

int
is_local_address(struct sockaddr_storage *addr)
{
	struct sockaddr_in *ifa4, *a4;
	struct sockaddr_in6 *ifa6, *a6;

	if (!__ifaddrs) {
		if (getifaddrs(&__ifaddrs) == -1) {
			lprintf("is_local_address: getifaddrs: %s",
				strerror(errno));
			return (FALSE);
		}
	}

	for (struct ifaddrs *ifa = __ifaddrs; ifa; ifa = ifa->ifa_next) {
		switch (addr->ss_family) {
		case AF_INET:
			a4 = (struct sockaddr_in *)addr;
			ifa4 = (struct sockaddr_in *)ifa->ifa_addr;
			if (bcmp(&ifa4->sin_addr, &a4->sin_addr,
				sizeof(struct in_addr)) == 0)
				return (TRUE);
		case AF_INET6:
			a6 = (struct sockaddr_in6 *)addr;
			ifa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (bcmp(&ifa6->sin6_addr, &a6->sin6_addr,
				sizeof(struct in_addr)) == 0)
				return (TRUE);
		default:
			return (FALSE);
		}
	}


	return (FALSE);
}

size_t
message_broadcast(opcode_t opcode, void *payload, small_idx_t size,
	userinfo_t info)
{
	return (message_broadcast_with_callback(opcode, payload, size, info,
		NULL));
}

size_t
message_broadcast_with_callback(opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info, event_callback_t callback)
{
#ifdef NETWORK_DEBUG
	char tmp[INET6_ADDRSTRLEN + 1];
#endif
	struct sockaddr_storage addr;
	event_info_t *req;
	message_t *msg;
	size_t res = 0;
	small_idx_t n;

	n = MIN(100, peerlist.list4_size + peerlist.list6_size);

	for (small_idx_t i = 0; i < n; i++) {
		peer_address_random(&addr);

		msg = message_create(opcode, size, info);

#ifdef NETWORK_DEBUG
		lprintf("broadcasting message %s to %s",
			opcode_names[opcode], peername(addr, tmp));
#endif
		if ((req = request_send(&addr, msg, payload))) {
			req->on_close = callback;
			res++;
		} else {
			message_free(msg);
		}
	}

	return (res);
}

void
daemon_start(void)
{
	if (__listen_info)
		return;

	lprintf("Starting daemon...");

	listen_socket_open();
	notar_start();
}

static void
__getblock_again(event_info_t *info, event_flags_t eventflags)
{
        getblocks(0);
}

void
getblock(big_idx_t index)
{
	char tmp[INET6_ADDRSTRLEN + 1];
	struct sockaddr_storage addr;
	event_info_t *info;

	peer_address_random(&addr);
	lprintf("asking peer %s for block %ju", peername(&addr, tmp), index);
	if ((info = message_send(&addr, OP_GETBLOCK, NULL, 0, htobe64(index))))
		info->on_close = __getblock_again;
	else
		__getblock_again(info, EVENT_READ);
}
