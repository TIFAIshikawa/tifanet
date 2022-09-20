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
#include <netinet/in.h>
#include "log.h"
#include "vlist.h"
#include "event.h"
#include "notar.h"
#include "endian.h"
#include "config.h"
#include "network.h"
#include "peerlist.h"
#include "opcode_callback.h"

#if defined(ALPHA)
char *__network = "alpha";
#elif defined(BETA)
char *__network = "beta";
#else
char *__network = "gamma";
#endif

#define MESSAGE_TIMEOUT 30
#define CONNECT_TIMEOUT 2

const char *const opcode_names[OP_MAXOPCODE] = {
	"OP_NONE",
	"OP_PEERLIST",
	"OP_BLOCKINFO",
	"OP_GETBLOCK",
	"OP_NOTARANNOUNCE",
	"OP_BLOCKANNOUNCE",
	"OP_PACT",
	"OP_GETRXCACHE",
	"OP_GETNOTARS"
};

static struct ifaddrs *__ifaddrs = NULL;

static int __ipv6_enabled = 1;

typedef struct {
	vlist_t *active;
	vlist_t *inactive;
} peers_t;
static peers_t __peers;

static void connection_accept(void *, void *payload);
static event_fd_t *__message_send(struct sockaddr_storage *addr,
	opcode_t opcode, void *payload, small_idx_t size, userinfo_t info);
static int message_header_validate(event_fd_t *info);

static event_fd_t *__listen_info_ipv4 = NULL;
static event_fd_t *__listen_info_ipv6 = NULL;

void
network_init(void)
{
	__peers.active = vlist_init(10);
	__peers.inactive = vlist_init(10);

	// init userinfo challenges so userinfo = 0 can't be exploited
	getrxcache_userinfo();
	getnotarscache_userinfo();
}

static int
sockaddr_equals(struct sockaddr_storage *s1, struct sockaddr_storage *s2)
{
	struct sockaddr_in *a14, *a24;
	struct sockaddr_in6 *a16, *a26;

	switch (s1->ss_family) {
	case AF_INET:
		a14 = (struct sockaddr_in *)s1;
		a24 = (struct sockaddr_in *)s2;
		if (s2->ss_family != AF_INET)
			return (FALSE);
		return (a14->sin_addr.s_addr == a24->sin_addr.s_addr);
	case AF_INET6:
		a16 = (struct sockaddr_in6 *)s1;
		a26 = (struct sockaddr_in6 *)s2;
		if (s2->ss_family != AF_INET6)
			return (FALSE);
		return (memcmp(&a16->sin6_addr, &a26->sin6_addr,
			sizeof(struct in6_addr)) == 0);
	default:
		lprintf("sockaddr_equals: unsupported ss_family: %d",
			s1->ss_family);
	}

	return (FALSE);
}

static void
socket_set_async(int fd)
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
peer_set_active(event_fd_t *event)
{
	vlist_item_add(__peers.active, event);
	vlist_item_remove(__peers.inactive, event);
}

static void
peer_set_inactive(event_fd_t *event)
{
	network_event_t *nev;

	nev = network_event(event);
	nev->read_idx = nev->write_idx = 0;
	vlist_item_remove(__peers.active, event);
	vlist_item_add(__peers.inactive, event);
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
	return (__listen_info_ipv6 && __ipv6_enabled);
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

static event_fd_t *
__listen_socket_open(struct sockaddr_storage *addr)
{
	event_fd_t *res;
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

	res = event_fd_add(fd, EVENT_READ, connection_accept, NULL, 0);

	lprintf("listening for %s connections...", iptxt);

	return (res);
}

void
listen_socket_open(void)
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

	if (ipv6_enabled()) {
		bzero(&a6, sizeof(struct sockaddr_in6));
		a6.sin6_family = AF_INET6;
		a6.sin6_addr = in6addr_any;
		a6.sin6_port = htons(TIFA_NETWORK_PORT);
		s = (struct sockaddr_storage *)&a6;
		__listen_info_ipv6 = __listen_socket_open(s);
	}

	if (!__listen_info_ipv4 && !__listen_info_ipv6)
		FAILTEMP("could open neither IPv6 nor IPv4 listen sockets, "
			"exiting");
}

void
connection_accept(void *info, void *payload)
{
	struct sockaddr_storage addr;
	network_event_t nev;
	event_fd_t *event;
	socklen_t len;
	int sfd, fd;

	len = sizeof(struct sockaddr_storage);
	sfd = event_fd_get((event_fd_t *)info);
	if ((fd = accept(sfd, (struct sockaddr *)&addr, &len)) == -1)
		FAIL(EX_TEMPFAIL, "connection_accept: accept: %s",
				  strerror(errno));

	socket_set_async(fd);

	bzero(&nev, sizeof(network_event_t));
	bcopy(&addr, &nev.remote_addr, len);
	nev.type = NETWORK_EVENT_TYPE_SERVER;
	nev.state = NETWORK_EVENT_STATE_HEADER;
	event = event_fd_add(fd, EVENT_READ, message_read, &nev,
			     sizeof(network_event_t));
	event_fd_timeout_set(event, 20000);

	if (addr.ss_family == AF_INET6)
		ipv6_set_enabled(TRUE);

}

static void
message_userdata_free(event_fd_t *info)
{
	network_event_t *nev;
	message_t *msg;

	nev = network_event(info);
	msg = network_message(info);

	// TODO do this in a better way
	if (nev->userdata) {
		switch (msg->opcode) {
		case OP_PEERLIST:
		case OP_BLOCKINFO:
		case OP_GETRXCACHE:
		case OP_GETNOTARS:
			free(nev->userdata);
			break;
		case OP_GETBLOCK:
			if (nev->type == NETWORK_EVENT_TYPE_CLIENT)
				free(nev->userdata);
			break;
		}
	}

	nev->userdata = NULL;
	nev->userdata_size = 0;
}

void
message_done(event_fd_t *info)
{
	network_event_t *nev;
	mseconds_t timeout;
	message_t *msg;

	if (errno)
		return message_cancel(info);

	nev = network_event(info);
	msg = network_message(info);

	event_fd_update(info, EVENT_READ);

	if (nev->on_close && message_flags(msg) & MESSAGE_FLAG_REPLY) {
		nev->on_close(info, nev->userdata);
		nev->on_close = NULL;
	}

	message_userdata_free(info);

	timeout = (message_flags(msg) & MESSAGE_FLAG_PEER) ? 60000 : 2000;

	event_fd_timeout_set(info, timeout);
	event_callback_set(info, message_read);
	nev->type = NETWORK_EVENT_TYPE_SERVER;
	nev->state = NETWORK_EVENT_STATE_HEADER;
	peer_set_inactive(info);
}

void
message_cancel(event_fd_t *info)
{
	network_event_t *nev;
	message_t *msg;

	nev = network_event(info);
	msg = network_message(info);

	if (errno == ENETUNREACH && nev->remote_addr.ss_family == AF_INET6)
		ipv6_set_enabled(FALSE);

	if (errno == ETIMEDOUT || errno == ECONNREFUSED || errno == EHOSTDOWN)
		peerlist_remove(&nev->remote_addr);

	if (nev->on_close && message_flags(msg) & MESSAGE_FLAG_REPLY) {
		nev->on_close(info, nev->userdata);
		nev->on_close = NULL;
	}

	vlist_item_remove(__peers.active, info);
	vlist_item_remove(__peers.inactive, info);

	message_userdata_free(info);

	close(event_fd_get(info));
	event_fd_remove(info);
}

static int
message_header_validate(event_fd_t *info)
{
	network_event_t *nev;
	small_idx_t size;
	message_t *msg;

	nev = network_event(info);
	msg = network_message(info);

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
	lprintf("recv(ip=%s fd=%d op=%s us=%llu sz=%ld)",
		peername(&nev->remote_addr), event_fd_get(info),
		opcode_names[msg->opcode], be64toh(msg->userinfo),
		size);
#endif

	return (TRUE);
}

static ssize_t
socket_read(event_fd_t *info, char *buf, size_t len)
{
	ssize_t res;

	if ((res = read(event_fd_get(info), buf, len)) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return (0);

		message_cancel(info);
		return (-1);
	}

	return (res);
}

static ssize_t
socket_write(event_fd_t *info, char *buf, size_t len)
{
	ssize_t res;

	if ((res = write(event_fd_get(info), buf, len)) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return (0);

		message_cancel(info);
		return (-1);
	}

	return (res);
}

void
message_read(void *_info, void *payload)
{
	network_event_t *nev;
	event_fd_t *info;
	ssize_t r, want;
	message_t *msg;
	char *ptr;

	info = (event_fd_t *)_info;
	nev = network_event(info);
	msg = network_message(info);

	if (errno)
		return message_cancel(info);

	switch (nev->state) {
	case NETWORK_EVENT_STATE_HEADER:
		ptr = (void *)msg + nev->read_idx;
		want = sizeof(message_t) - nev->read_idx;
		if ((r = socket_read(info, ptr, want)) <= 0)
			return;
		if (!nev->read_idx)
			peer_set_active(info);

		nev->read_idx += r;
		if (nev->read_idx == sizeof(message_t)) {
			if (message_flags(msg) & MESSAGE_FLAG_REPLY)
				nev->type = NETWORK_EVENT_TYPE_CLIENT;
			else
				nev->type = NETWORK_EVENT_TYPE_SERVER;

			if (!message_header_validate(info))
				return message_cancel(info);

			if (msg->payload_size)
				nev->userdata = malloc(be32toh(msg->payload_size));
			else
				nev->userdata = NULL;
			if (message_flags(msg) & MESSAGE_FLAG_PEER)
				peerlist_add(&nev->remote_addr);

			nev->read_idx = 0;
			nev->state = NETWORK_EVENT_STATE_BODY;
			message_read(info, payload);
		}
		break;
	case NETWORK_EVENT_STATE_BODY:
		ptr = (void *)nev->userdata + nev->read_idx;
		want = be32toh(msg->payload_size) - nev->read_idx;
		if (nev->read_idx != want) {
			if ((r = socket_read(info, ptr, want)) <= 0)
				return;
			nev->read_idx += r;
		}

		if (nev->read_idx == be32toh(msg->payload_size))
			opcode_execute(info);
		break;
	default:
		FAIL(EX_SOFTWARE, "message_read %p: illegal state: %d\n",
		      info, nev->state);
	}
}

void
message_write(void *_info, void *payload)
{
	network_event_t *nev;
	event_fd_t *info;
	ssize_t r, want;
	message_t *msg;
	char *ptr;

	info = (event_fd_t *)_info;
	nev = network_event(info);
	msg = network_message(info);

	if (errno)
		return message_cancel(info);

	switch (nev->state) {
	case NETWORK_EVENT_STATE_HEADER:
		ptr = (void *)msg + nev->write_idx;
		want = sizeof(message_t) - nev->write_idx;
		if ((r = socket_write(info, ptr, want)) <= 0)
			return;
		if (!nev->write_idx)
			peer_set_active(info);

		nev->write_idx += r;
		if (nev->write_idx == sizeof(message_t)) {
			nev->write_idx = 0;
			nev->state = NETWORK_EVENT_STATE_BODY;
			message_write(info, payload);
		}
		break;
	case NETWORK_EVENT_STATE_BODY:
		ptr = (void *)nev->userdata + nev->write_idx;
		want = be32toh(msg->payload_size) - nev->write_idx;
		if (nev->write_idx != want) {
			if ((r = socket_write(info, ptr, want)) <= 0)
				return;
			nev->write_idx += r;
		}

		if (nev->write_idx == be32toh(msg->payload_size))
			message_done(info);
		break;
	default:
		FAIL(EX_SOFTWARE, "message_write %p: illegal state: %d\n",
		      info, nev->state);
	}
}

static event_fd_t *
request_send(struct sockaddr_storage *addr, message_t *message, void *payload)
{
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	network_event_t nev;
	event_fd_t *res;
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
			if (errno == ENETUNREACH && addr->ss_family == AF_INET6)
				ipv6_set_enabled(FALSE);
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
	nev.userdata_size = be32toh(message->payload_size);

	res = event_fd_add(fd, EVENT_WRITE, message_write, &nev,
			sizeof(network_event_t));
	event_fd_timeout_set(res, 2000);

	return (res);

}

network_event_t *
network_event(event_fd_t *info)
{
	return (event_payload_get(info));
}

message_t *
network_message(event_fd_t *info)
{
	return (&network_event(info)->message_header);
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

void
message_send(event_fd_t *event, opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info)
{
	message_t *msg;
	network_event_t *nev;

	event_fd_update(event, EVENT_WRITE);
	peer_set_active(event);

	nev = network_event(event);
	msg = network_message(event);

	message_init(msg, opcode, size, info);
	nev->read_idx = nev->write_idx = 0;
	nev->type = NETWORK_EVENT_TYPE_CLIENT;
	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->userdata = payload;
	nev->userdata_size = be32toh(msg->payload_size);
	event_fd_timeout_set(event, 20000);

	event_callback_set(event, message_write);
}

static event_fd_t *
__message_send(struct sockaddr_storage *addr, opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info)
{
	event_fd_t *e, *res = NULL;
	network_event_t *nev;
	message_t msg;

	for (size_t i = 0; i < vlist_size(__peers.active); i++) {
		e = vlist_item_get(__peers.active, i);
		nev = network_event(e);
		// this connection is busy
		if (sockaddr_equals(&nev->remote_addr, addr))
			return (NULL);
	}
	for (size_t i = 0; i < vlist_size(__peers.inactive); i++) {
		e = vlist_item_get(__peers.inactive, i);
		nev = network_event(e);
		if (sockaddr_equals(&nev->remote_addr, addr)) {
			res = e;
			message_send(res, opcode, payload, size, info);
			break;
		}
	}
	if (!res) {
		message_init(&msg, opcode, size, info);
		res = request_send(addr, &msg, payload);
	}

	if (res) {
#ifdef DEBUG_NETWORK
		lprintf("send(ip=%s fd=%d op=%s us=%llu sz=%ld)",
			peername(addr), event_fd_get(res),
			opcode_names[opcode], be64toh(info), size);
#endif
		return (res);
	}

	return (NULL);
}

event_fd_t *
message_send_random_with_callback(opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info, event_callback_t callback)
{
	event_fd_t *res;
	struct sockaddr_storage addr;

	if ((res = vlist_item_random(__peers.inactive))) {
		message_send(res, opcode, payload, size, info);
	} else {
		// attempt to get a non-local random IP address
		for (int i = 0; i < 3; i++) {
			if (!peerlist_address_random(&addr))
				return (NULL);
			if (!is_local_interface_address(&addr))
				break;
		}
		res = __message_send(&addr, opcode, payload, size, info);
	}

	if (res) {
		if (callback)
			message_set_callback(res, callback);
		peer_set_active(res);
	}

	return (res);
}

event_fd_t *
message_send_random(opcode_t opcode, void *payload, small_idx_t size,
	userinfo_t info)
{
	return (message_send_random_with_callback(opcode, payload, size,
						  info, NULL));
}

static size_t
message_send_list_with_callback(struct sockaddr_storage *addrs, size_t naddrs,
	opcode_t opcode, void *payload, small_idx_t size, userinfo_t info,
	event_callback_t callback)
{
	size_t res;
	event_fd_t *e;

	res = 0;
	for (size_t i = 0; i < naddrs; i++) {
		if ((e = __message_send(&addrs[i], opcode, payload, size,
			info))) {
			message_set_callback(e, callback);
			res++;
		}
	}

	return (res);
}

void
message_set_callback(event_fd_t *info, event_callback_t callback)
{
	network_event_t *nev;

	nev = network_event(info);

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
	// so be it, those will be deleted anyway when connection attempts fail.
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
	notar_announce();
	block_poll_start();

	peerlist_save(); // bootstrap peerlist timer
}

int
ipv6_enabled(void)
{
	return __ipv6_enabled;
}

void
ipv6_set_enabled(int enabled)
{
	__ipv6_enabled = enabled;
}
