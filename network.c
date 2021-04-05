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
#include "peerlist.h"
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

static struct ifaddrs *__ifaddrs = NULL;

static void accept_notar_connection(event_info_t *, event_flags_t);
static void message_event_on_close(event_info_t *, event_flags_t);

static event_info_t *__listen_info = NULL;
static int __ipv6_capable = 0;

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

int
network_is_ipv6_capable(void)
{
	return (__ipv6_capable);
}

static int
socket_create(int domain)
{
	int res;

	if ((res = socket(domain, SOCK_STREAM, 0)) == -1)
		lprintf("socket_create: socket(%d): %s",
			domain, strerror(errno));

	return (res);
}

static int
__listen_socket_open(struct sockaddr_storage *addr)
{
	socklen_t len;
	int opt = 1;
	int fd;

	switch (addr->ss_family) {
	case AF_INET: len = sizeof(struct sockaddr_in); break;
	case AF_INET6: len = sizeof(struct sockaddr_in6); break;
	default: return (FALSE);
	}

	if ((fd = socket_create(addr->ss_family)) == -1)
		return (FALSE);

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		close(fd);
		FAILBOOL("listen_socket_open: setsockopt: %s", strerror(errno));
	}

	socket_set_async(fd);

	if (bind(fd, (struct sockaddr *)addr, len) == -1) {
		close(fd);
		FAILBOOL("listen_socket_open: bind: %s", strerror(errno));
	}

	if (listen(fd, SOMAXCONN) == -1) {
		close(fd);
		FAILBOOL("listen_socket_open: listen: %s", strerror(errno));
	}

	__listen_info = event_add(fd, EVENT_READ, accept_notar_connection,
				NULL);

	lprintf("listening for connections...");

	return (TRUE);
}

void
listen_socket_open()
{
	struct sockaddr_in a4;
	struct sockaddr_in6 a6;

	bzero(&a6, sizeof(struct sockaddr_in6));
	a6.sin6_family = AF_INET6;
	a6.sin6_addr = in6addr_any;
	a6.sin6_port = htons(TIFA_NETWORK_PORT);
	if (__listen_socket_open((struct sockaddr_storage *)&a6)) {
		__ipv6_capable = 1;
		return;
	}

	bzero(&a4, sizeof(struct sockaddr_in));
	a4.sin_family = AF_INET;
	a4.sin_addr.s_addr = INADDR_ANY;
	a4.sin_port = htons(TIFA_NETWORK_PORT);
	if (!__listen_socket_open((struct sockaddr_storage *)&a4))
		FAILTEMP("could open neither IPv6 nor IPv4 listen sockets, "
			"exiting");
}

void
accept_notar_connection(event_info_t *info, event_flags_t eventtype)
{
	struct sockaddr_storage addr;
	network_event_t *nev;
	socklen_t len;
	int fd;

	len = sizeof(struct sockaddr_storage);
	if ((fd = accept(info->ident, (struct sockaddr *)&addr, &len)) == -1)
		FAIL(EX_TEMPFAIL, "accept_notar_connection: accept: %s",
				  strerror(errno));

	socket_set_async(fd);

	socket_set_timeout(fd, 10);

	nev = calloc(1, sizeof(network_event_t));
	bcopy(&addr, &nev->remote_addr, len);
	nev->remote_addr_len = len;
	nev->type = NETWORK_EVENT_TYPE_SERVER;
	event_add(fd, EVENT_READ | EVENT_TIMEOUT | EVENT_FREE_PAYLOAD,
		message_read, nev);
}

void
message_cancel(event_info_t *info)
{
	network_event_t *nev;

	nev = info->payload;
//	if (nev->userdata)
//		free(nev->userdata);

	event_remove(info);
}

static void
message_event_on_close(event_info_t *info, event_flags_t flags)
{
	network_event_t *nev;
	message_t *msg;

	nev = info->payload;
	msg = &nev->message_header;
lprintf("on_close msg %s type %d\n", opcode_names[be16toh(msg->opcode)], nev->type);

	if (nev->on_close)
		nev->on_close(info, flags);
}

static int
message_header_validate(event_info_t *info)
{
	network_event_t *nev;
	small_idx_t size;
	message_t *msg;

	nev = info->payload;
	msg = &nev->message_header;

	if (bcmp(msg->magic, TIFA_IDENT, sizeof(magic_t)) != 0) {
		lprintf("message_read: invalid magic");
		return (FALSE);
	}
	if ((size = be32toh(msg->payload_size))) {
		if (size > MAXPACKETSIZE) {
			lprintf("message_read: size too large: %d", size);
			return (FALSE);
		}
		if (!opcode_valid(msg)) {
			lprintf("message_read: opcode invalid: %u",
				be16toh(msg->opcode));
			return (FALSE);
		}
		if (!opcode_payload_size_valid(msg, nev->type)) {
			lprintf("message_read: size %d not valid for opcode "
				"%d", size, be16toh(msg->opcode));
			return (FALSE);
		}
	}

	return (TRUE);
}

void
message_read(event_info_t *info, event_flags_t eventtype)
{
	network_event_t *nev;
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
		if ((r = read(info->ident, ptr, want)) <= 0) {
			if (errno != EAGAIN && errno != EINTR)
				message_cancel(info);
			return;
		}
		nev->read_idx += r;
		if (nev->read_idx == sizeof(message_t)) {
			if (!message_header_validate(info))
				return message_cancel(info);
			if (opcode_message_ignore(info))
				return message_cancel(info);

			nev->userdata = malloc(be32toh(msg->payload_size));
			if (be16toh(msg->flags) & MESSAGE_FLAG_PEER)
				peerlist_add(&nev->remote_addr);
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
			opcode_execute(info);
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

	if ((fd = socket_create(addr->ss_family)) == -1)
		FAIL(EX_TEMPFAIL, "request_send: socket: %s\n",
			strerror(errno));

// TODO: don't use async connect() for now	socket_set_async(fd);

	if (connect(fd, (struct sockaddr *)addr, len) == -1) {
		// EINPROGRESS will be handled by event loop. Other errors
		// are fatal. Don't log common errors though.
		if (errno != EINPROGRESS) {
//			if (errno != ECONNREFUSED && errno != ECONNRESET &&
//				errno != EINTR)
				lprintf("request_send: connect: %s",
					strerror(errno));
			close(fd);
			peerlist_remove(addr);
			return (NULL);
		}
	}

	nev = calloc(1, sizeof(network_event_t));
	nev->type = NETWORK_EVENT_TYPE_CLIENT;
	bcopy(message, &nev->message_header, sizeof(message_t));
	nev->userdata = payload;
	bcopy(addr, &nev->remote_addr, len);
	nev->remote_addr_len = len;
	nev->userdata_size = be32toh(message->payload_size);

	res = event_add(fd, EVENT_WRITE | EVENT_TIMEOUT | EVENT_FREE_PAYLOAD,
			message_write, nev);
	res->on_close = message_event_on_close;

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

static void
message_init(message_t *msg, opcode_t opcode, small_idx_t size, userinfo_t info)
{
	time64_t t;

	t = time(NULL);

	bzero(msg, sizeof(message_t));
	bcopy(TIFA_IDENT, msg->magic, sizeof(magic_t));
	msg->opcode = htobe16(opcode);
	if (is_notar_node())
		msg->flags |= MESSAGE_FLAG_PEER;
	msg->flags = htobe16(msg->flags);
	msg->userinfo = info;
	msg->payload_size = htobe32(size);
}

event_info_t *
message_send(struct sockaddr_storage *addr, opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info)
{
	event_info_t *res;
	message_t msg;

	message_init(&msg, opcode, size, info);

	if ((res = request_send(addr, &msg, payload)))
		return (res);

	return (NULL);
}

int
is_local_interface_address(struct sockaddr_storage *addr)
{
	socklen_t slen;
	struct sockaddr_in *ifa4, *a4;
	struct sockaddr_in6 *ifa6, *a6;

	if (!__ifaddrs) {
		if (getifaddrs(&__ifaddrs) == -1) {
			lprintf("is_local_interface_address: getifaddrs: %s",
				strerror(errno));
			return (FALSE);
		}
	}

	for (struct ifaddrs *ifa = __ifaddrs; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != addr->ss_family)
			continue;
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			a4 = (struct sockaddr_in *)addr;
			ifa4 = (struct sockaddr_in *)ifa->ifa_addr;
			slen = sizeof(struct in_addr);
			if (bcmp(&ifa4->sin_addr, &a4->sin_addr, slen) == 0)
				return (TRUE);
			break;
		case AF_INET6:
			a6 = (struct sockaddr_in6 *)addr;
			ifa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			slen = sizeof(struct in6_addr);
			if (bcmp(&ifa6->sin6_addr, &a6->sin6_addr, slen) == 0)
				return (TRUE);
			break;
		default:
			continue;
		}
	}

	return (FALSE);
}

int
is_nonroutable_address(struct sockaddr_storage *addr)
{
#if defined(ALPHA) || defined(BETA)
	return (FALSE);
#else
	struct sockaddr_in *a4;
	uint32_t a4h;
	uint8_t *a4digits;
	struct sockaddr_in6 *a6;

	// These checks are all quite rudimentary. The point is to ignore
	// e.g. obvious RFC1918 and RFC5771 addresses, since peers need to
	// be able to all connect to each other. If some cases slip through,
	// such as subnet broadcast addresses, so be it; those will be deleted
	// anyway when connection attempts fail.
	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		a4h = be32toh(a4->sin_addr.s_addr);
		a4digits = (uint8_t *)&a4h;
		if (a4digits[0] == 127)
			return (TRUE);
		if (a4digits[0] == 10)
			return (TRUE);
		if (a4digits[0] == 172 && a4digits[1] >= 16 && a4digits[1] < 32)
			return (TRUE);
		if (a4digits[0] == 192 && a4digits[1] == 168)
			return (TRUE);
		if (a4digits[0] >= 224 && a4digits[0] < 240)
			return (TRUE);
		if (a4h == 0x00000000 || a4h == 0xffffffff)
			return (TRUE);
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		break;
	}

	return (TRUE);
#endif
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
	message_t msg;
	small_idx_t n;
	size_t res;

	n = MIN(100, peerlist.list4_size + peerlist.list6_size);
	for (res = 0; res < n; res++) {
		if (!peerlist_address_random(&addr))
			return (res);
		if (is_local_interface_address(&addr)) // res will be bodged
			continue;

		message_init(&msg, opcode, size, info);

#ifdef NETWORK_DEBUG
		lprintf("broadcasting message %s to %s",
			opcode_names[opcode], peername(&addr, tmp));
#endif
		if ((req = request_send(&addr, &msg, payload))) {
			req->on_close = callback;
			res++;
		}

		// recalculate this, as the list might have changed due
		// to a peer being removed from the list if it did not respond
		n = MIN(100, peerlist.list4_size + peerlist.list6_size);
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

	if (!peerlist_address_random(&addr))
		return;

	lprintf("asking peer %s for block %ju", peername(&addr, tmp), index);
	if ((info = message_send(&addr, OP_GETBLOCK, NULL, 0, htobe64(index))))
		info->on_close = __getblock_again;
	else
		__getblock_again(info, EVENT_READ);
}
