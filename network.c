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
#include <ifaddrs.h>
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

const char *const opcode_names[OP_MAXOPCODE] = {
	"OP_NONE",
	"OP_PEERLIST",
	"OP_LASTBLOCKINFO",
	"OP_GETBLOCK",
	"OP_NOTARANNOUNCE",
	"OP_NOTARDENOUNCE",
	"OP_BLOCKANNOUNCE",
	"OP_PACT",
	"OP_GETRXCACHE",
	"OP_GETNOTARS"
};

static struct ifaddrs *__ifaddrs = NULL;

static void accept_connection(event_info_t *, event_flags_t);
static void message_event_on_close(event_info_t *, event_flags_t);
static int message_event_timeout_check(event_info_t *, time64_t timeout);
static int message_event_connect_timeout_check(event_info_t *,
	time64_t timeout);

static event_info_t *__listen_info_ipv4 = NULL;
static event_info_t *__listen_info_ipv6 = NULL;

static void socket_set_async(int fd)
{
	int opt;

        if ((opt = fcntl(fd, F_GETFL, 0)) == -1)
                FAIL(EX_TEMPFAIL, "socket_set_async: fcntl(F_GETFL): %s",
                                  strerror(errno));
        if (fcntl(fd, F_SETFL, opt | O_NONBLOCK) == -1)
                FAIL(EX_TEMPFAIL, "socket_set_async: fcntl(F_SETFL): %s",
                                  strerror(errno));
}

static void
socket_set_timeout(int fd, unsigned int sec_timeout)
{
	int timeout;
	struct timeval timeout_tv;

	timeout = sec_timeout * 1000;
	setsockopt(fd, 6, 18, &timeout, sizeof(timeout));

	timeout_tv.tv_sec = sec_timeout;
	timeout_tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET,SO_RCVTIMEO, (void *)&timeout_tv,
		sizeof(timeout_tv));
	setsockopt(fd, SOL_SOCKET,SO_SNDTIMEO, (void *)&timeout_tv,
		sizeof(timeout_tv));
}

char *
peername(struct sockaddr_storage *addr)
{
	static char tmp[INET6_ADDRSTRLEN + 1];

	return (peername_r(addr, tmp));
}

char *
peername_r(struct sockaddr_storage *addr, char *dst)
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
	return (__listen_info_ipv6 != NULL);
}

static int
socket_create(int domain)
{
	int res;

	if ((res = socket(domain, SOCK_STREAM, 0)) == -1)
		lprintf("socket_create: socket(%d): %s",
			domain, strerror(errno));

	socket_set_async(res);

	return (res);
}

static event_info_t *
__listen_socket_open(struct sockaddr_storage *addr)
{
	event_info_t *res;
	socklen_t len;
	char *iptxt;
	int opt;
	int fd;

	switch (addr->ss_family) {
	case AF_INET: len = sizeof(struct sockaddr_in); iptxt = "IPv4"; break;
	case AF_INET6: len = sizeof(struct sockaddr_in6); iptxt = "IPv6"; break;
	default: return (FALSE);
	}

	if ((fd = socket_create(addr->ss_family)) == -1)
		return (FALSE);

	if (addr->ss_family == AF_INET6) {
		opt = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(int));
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		close(fd);
		FAILBOOL("listen_socket_open: setsockopt: %s", strerror(errno));
	}

	if (bind(fd, (struct sockaddr *)addr, len) == -1) {
		close(fd);
		FAILBOOL("listen_socket_open: bind %s: %s", iptxt,
			strerror(errno));
	}

	if (listen(fd, SOMAXCONN) == -1) {
		close(fd);
		FAILBOOL("listen_socket_open: listen %s: %s", iptxt,
			strerror(errno));
	}

	res = event_add(fd, EVENT_READ, accept_connection,
				NULL, 0);

	lprintf("listening for %s connections...", iptxt);

	return (res);
}

void
listen_socket_open()
{
	struct sockaddr_storage *s;
	struct sockaddr_in6 a6;
	struct sockaddr_in a4;

	bzero(&a4, sizeof(struct sockaddr_in));
	a4.sin_family = AF_INET;
	a4.sin_addr.s_addr = INADDR_ANY;
	a4.sin_port = htons(TIFA_NETWORK_PORT);
	s = (struct sockaddr_storage *)&a4;
	__listen_info_ipv4 = __listen_socket_open(s);

	bzero(&a6, sizeof(struct sockaddr_in6));
	a6.sin6_family = AF_INET6;
	a6.sin6_addr = in6addr_any;
	a6.sin6_port = htons(TIFA_NETWORK_PORT);
	s = (struct sockaddr_storage *)&a6;
	__listen_info_ipv6 = __listen_socket_open(s);

	if (!__listen_info_ipv4 && !__listen_info_ipv6)
		FAILTEMP("could open neither IPv6 nor IPv4 listen sockets, "
			"exiting");
}

void
accept_connection(event_info_t *info, event_flags_t eventtype)
{
	struct sockaddr_storage addr;
	network_event_t nev;
	event_info_t *event;
	socklen_t len;
	int fd;

	len = sizeof(struct sockaddr_storage);
	if ((fd = accept(info->ident, (struct sockaddr *)&addr, &len)) == -1)
		FAIL(EX_TEMPFAIL, "accept_connection: accept: %s",
				  strerror(errno));

	socket_set_async(fd);

	socket_set_timeout(fd, 10);

	bzero(&nev, sizeof(network_event_t));
	bcopy(&addr, &nev.remote_addr, len);
	nev.remote_addr_len = len;
	nev.type = NETWORK_EVENT_TYPE_SERVER;
	nev.state = NETWORK_EVENT_STATE_HEADER;
	event = event_add(fd, EVENT_READ | EVENT_TIMEOUT | EVENT_FREE_PAYLOAD,
		message_read, &nev, sizeof(network_event_t));
	event->on_close = message_event_on_close;
	event->timeout_check = message_event_timeout_check;
}

void
message_cancel(event_info_t *info)
{
	event_remove(info);
}

static void
message_event_on_close(event_info_t *info, event_flags_t flags)
{
	struct sockaddr_storage tmp;
	network_event_t *nev;
	message_t *msg;
	opcode_t opcode;
	socklen_t len;
	char c;

	nev = info->payload;
	msg = network_message(info);

	block_transit_message_remove(msg);

	if (!nev->read_idx && !nev->write_idx) {
		len = sizeof(struct sockaddr_storage);
		if (getpeername(info->ident, (struct sockaddr *)&tmp,
			&len) == -1) {
			if (errno != ENOTCONN) {
				read(info->ident, &c, 1);
				lprintf("message_event_on_close: connect %s: "
					"%s", peername(&nev->remote_addr),
					strerror(errno));
			}
			peerlist_remove(&nev->remote_addr);
		}
	}

	if (nev->on_close)
		nev->on_close(info, flags);

	if (!nev->userdata)
		return;

	opcode = msg->opcode;
	if ((nev->type == NETWORK_EVENT_TYPE_SERVER && opcode == OP_GETBLOCK) ||
		(nev->type == NETWORK_EVENT_TYPE_CLIENT && opcode == OP_BLOCKANNOUNCE) ||
		(nev->type == NETWORK_EVENT_TYPE_CLIENT && opcode == OP_NOTARANNOUNCE)) {
#ifdef DEBUG_ALLOC
		lprintf("NOT FREEING USERDATA %p", nev->userdata);
#endif
		return;
	}

#ifdef DEBUG_ALLOC
	lprintf("-USERDATA %p MESSAGE_READ", nev->userdata);
#endif
	free(nev->userdata);

	if (nev->type == NETWORK_EVENT_TYPE_CLIENT && opcode == OP_GETBLOCK)
		getblocks(0);
}

static int
message_event_timeout_check(event_info_t *info, time64_t timeout)
{
	return (timeout > 30);
}

static int
message_event_connect_timeout_check(event_info_t *info, time64_t timeout)
{
	return (timeout > 2);
}

static int
message_header_validate(event_info_t *info)
{
	network_event_t *nev;
	small_idx_t size;
	message_t *msg;

	nev = info->payload;
	msg = &nev->message_header;

	if (memcmp(msg->magic, TIFA_IDENT, sizeof(magic_t)) != 0) {
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
				msg->opcode);
			return (FALSE);
		}
		if (!opcode_payload_size_valid(msg, nev->type)) {
			lprintf("message_read: size %d not valid for opcode "
				"%d", size, msg->opcode);
			return (FALSE);
		}
	}
#ifdef DEBUG_NETWORK
	if (nev->type == NETWORK_EVENT_TYPE_SERVER)
		lprintf("msg(%s %lld %ld) <- %s",
			opcode_names[msg->opcode], be64toh(msg->userinfo),
			size, peername(&nev->remote_addr));
#endif

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

	info->timeout_check = message_event_timeout_check;
	nev = info->payload;
	msg = &nev->message_header;
	switch (nev->state) {
	case NETWORK_EVENT_STATE_HEADER:
		ptr = (void *)&nev->message_header + nev->read_idx;
		want = sizeof(message_t) - nev->read_idx;
		if ((r = read(info->ident, ptr, want)) <= 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK &&
				errno != EINTR)
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
#ifdef DEBUG_ALLOC
			lprintf("+USERDATA %p MESSAGE_READ", nev->userdata);
#endif
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
				if (errno != EAGAIN && errno != EWOULDBLOCK) {
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
		FAIL(EX_SOFTWARE, "message_read %p: illegal state: %d\n",
		      info, nev->state);
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

	info->timeout_check = message_event_timeout_check;
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
		FAIL(EX_SOFTWARE, "message_write %p: illegal state: %d\n",
		      info, nev->state);
	}
}

static event_info_t *
request_send(struct sockaddr_storage *addr, message_t *message, void *payload)
{
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	network_event_t nev;
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

	if (connect(fd, (struct sockaddr *)addr, len) == -1) {
		if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
			lprintf("request_send: connect %s: %s",
				peername(addr), strerror(errno));
			close(fd);
			peerlist_remove(addr);
			return (NULL);
		}
	}

	bzero(&nev, sizeof(network_event_t));
	nev.type = NETWORK_EVENT_TYPE_CLIENT;
	nev.state = NETWORK_EVENT_STATE_HEADER;
	bcopy(message, &nev.message_header, sizeof(message_t));
	nev.userdata = payload;
	bcopy(addr, &nev.remote_addr, len);
	nev.remote_addr_len = len;
	nev.userdata_size = be32toh(message->payload_size);

	res = event_add(fd, EVENT_WRITE | EVENT_TIMEOUT | EVENT_FREE_PAYLOAD,
			message_write, &nev, sizeof(network_event_t));
	res->on_close = message_event_on_close;
	res->timeout_check = message_event_connect_timeout_check;
#ifdef DEBUG_ALLOC
	lprintf("+USERDATA %p REQUEST_SEND", nev.userdata);
#endif

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
	bzero(msg, sizeof(message_t));
	bcopy(TIFA_IDENT, msg->magic, sizeof(magic_t));
	msg->version = TIFA_NETWORK_VERSION;
	msg->opcode = opcode;
	//if (config_is_notar_node())
	if (!config_is_sync_only() && !config_is_caches_only())
		msg->flags |= MESSAGE_FLAG_PEER;
	msg->flags = htobe16(msg->flags);
	msg->userinfo = info;
	msg->payload_size = htobe32(size);
}

static event_info_t *
message_send(struct sockaddr_storage *addr, opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info)
{
	event_info_t *res;
	message_t msg;

	message_init(&msg, opcode, size, info);

	if ((res = request_send(addr, &msg, payload))) {
#ifdef DEBUG_NETWORK
		lprintf("msg(%s %lld %ld) -> %s",
			opcode_names[opcode], be64toh(info), size,
			peername(addr));
#endif
		return (res);
	}

	return (NULL);
}

event_info_t *
message_send_random(opcode_t opcode, void *payload, small_idx_t size,
	userinfo_t info)
{
	struct sockaddr_storage addr;

	// attempt to get a non-local random IP address for at max 3 times
	for (int i = 0; i < 3; i++) {
		if (!peerlist_address_random(&addr))
			return (NULL);
		if (!is_local_interface_address(&addr))
			break;
	}

	return (message_send(&addr, opcode, payload, size, info));
}

static size_t
message_send_list_with_callback(struct sockaddr_storage *addrs, size_t naddrs,
	opcode_t opcode, void *payload, small_idx_t size, userinfo_t info,
	event_callback_t callback)
{
	size_t res;
	event_info_t *e;

	res = 0;
	for (size_t i = 0; i < naddrs; i++) {
		if ((e = message_send(&addrs[i], opcode, payload, size,
			info))) {
			message_set_callback(e, callback);
			res++;
		}
	}

	return (res);
}

event_info_t *
message_send_random_with_callback(opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info, event_callback_t callback)
{
	event_info_t *res;

	if ((res = message_send_random(opcode, payload, size, info)))
		message_set_callback(res, callback);

	return (res);
}

void
message_set_callback(event_info_t *info, event_callback_t callback)
{
	network_event_t *nev;

	nev = info->payload;

	nev->on_close = callback;
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

	for (struct ifaddrs *i = __ifaddrs; i; i = i->ifa_next) {
		if (!i->ifa_addr || i->ifa_addr->sa_family != addr->ss_family)
			continue;
		switch (i->ifa_addr->sa_family) {
		case AF_INET:
			a4 = (struct sockaddr_in *)addr;
			ifa4 = (struct sockaddr_in *)i->ifa_addr;
			slen = sizeof(struct in_addr);
			if (memcmp(&ifa4->sin_addr, &a4->sin_addr, slen) == 0)
				return (TRUE);
			break;
		case AF_INET6:
			a6 = (struct sockaddr_in6 *)addr;
			ifa6 = (struct sockaddr_in6 *)i->ifa_addr;
			slen = sizeof(struct in6_addr);
			if (memcmp(&ifa6->sin6_addr, &a6->sin6_addr, slen) == 0)
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
	//struct sockaddr_in6 *a6;

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
		//a6 = (struct sockaddr_in6 *)addr;
		break;
	}

	return (FALSE);
#endif
}

size_t
message_broadcast(opcode_t opcode, void *payload, small_idx_t size,
	userinfo_t info)
{
	return (message_broadcast_with_callback(opcode, payload, size, info,
		NULL));
}

static size_t
__sockaddr_list_fill(struct sockaddr_storage *list, size_t size)
{
	struct sockaddr_in6 a6;
	struct sockaddr_in a4;
	size_t n, i;
	size_t res;

	bzero(list, sizeof(struct sockaddr_storage) * size);
	
	res = MIN(size, peerlist.list4_size + peerlist.list6_size);
	if (res <= size) {
		for (i = 0; i < peerlist.list4_size; i++) {
			bzero(&a4, sizeof(struct sockaddr_in));
			a4.sin_family = AF_INET;
			a4.sin_addr = peerlist.list4[i];
			bcopy(&a4, &list[i], sizeof(struct sockaddr_in));
		}
		n = i;
		for (i = 0; i < peerlist.list6_size; i++) {
			bzero(&a6, sizeof(struct sockaddr_in6));
			a6.sin6_family = AF_INET6;
			a6.sin6_addr = peerlist.list6[i];
			bcopy(&a6, &list[n + i], sizeof(struct sockaddr_in6));
		}

		return (res);
	}

	for (i = 0, n = 0; i < res; i++)
		if (peerlist_address_random(&list[i]))
			n++;

	return (n);
}

size_t
message_broadcast_with_callback(opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info, event_callback_t callback)
{
	struct sockaddr_storage list[100];
	size_t res;
	size_t n;

	n = __sockaddr_list_fill(list, 100);

	res = message_send_list_with_callback(list, n, opcode, payload, size,
		info, callback);

	return (res);
}

void
daemon_start(void)
{
	size_t sz;

	if (__listen_info_ipv4 || __listen_info_ipv6)
		return;

	lprintf("Starting daemon...");

	notar_raw_block_add(raw_block_last(&sz));
	notar_elect_next();

	listen_socket_open();
	notar_start();
	block_poll_start();
}
