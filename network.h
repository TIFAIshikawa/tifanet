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

#ifndef __TIFA_NETWORK_H
#define __TIFA_NETWORK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "node.h"
#include "event.h"
#include "endian.h"
#include "address.h"

typedef char magic_t[4];
typedef uint8_t version_t;
typedef uint8_t opcode_t;

enum opcodes {
	OP_NONE = 0,

	OP_PEERLIST,			// Get list of peers.

	OP_BLOCKINFO,			// Get block info.
	OP_GETBLOCK,			// Get block X, potentially receiving
					// blocks X .. X + 1500

	OP_NOTARANNOUNCE,		// Announce self to the network,
					// if we want to be a notar.

	OP_BLOCKANNOUNCE,		// Announce the next block to
					// the network.

	OP_PACT,			// Publish pact

	OP_GETRXCACHE,			// Request current rxcache from notar

	OP_GETNOTARS,			// Request current list of notars

	OP_MAXOPCODE			// Number of opcodes.
};

enum message_flags {
	MESSAGE_FLAG_NONE  = 0,
	MESSAGE_FLAG_REPLY = (1 << 0),	// this message is a reply
	MESSAGE_FLAG_PEER  = (2 << 0)	// ask to join the remote's peerlist
};

extern const char *const opcode_names[];

typedef struct __attribute__((__packed__)) __message {
	magic_t magic;
	version_t version;
	opcode_t opcode;
	tiny_flags_t flags;
	userinfo_t userinfo;
	small_idx_t payload_size;
} message_t;

enum {
	NETWORK_EVENT_STATE_HEADER,
	NETWORK_EVENT_STATE_BODY
};
enum {
	NETWORK_EVENT_TYPE_SERVER,
	NETWORK_EVENT_TYPE_CLIENT
};

typedef struct __network_event {
	uint16_t state;
	uint16_t type;
	struct sockaddr_storage remote_addr;
	message_t message_header;
	size_t read_idx;
	size_t write_idx;
	void *userdata;
	size_t userdata_size;
	event_callback_t on_close;
} network_event_t;

extern char *peername(struct sockaddr_storage *addr);
extern char *peername_r(struct sockaddr_storage *addr, char *dst);

extern int network_is_ipv6_capable(void);

extern int is_local_interface_address(struct sockaddr_storage *addr);
extern int is_nonroutable_address(struct sockaddr_storage *addr);

extern void network_init(void);
extern void listen_socket_open(void);

extern network_event_t *network_event(event_fd_t *info);
extern message_t *network_message(event_fd_t *info);

extern void message_send(event_fd_t *event, opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info);
extern event_fd_t *message_send_random(opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info);
extern event_fd_t *message_send_random_with_callback(opcode_t opcode,
	void *payload, small_idx_t size, userinfo_t info,
	event_callback_t callback);
extern void message_set_callback(event_fd_t *event, event_callback_t callback);
extern void message_done(event_fd_t *info);
extern void message_cancel(event_fd_t *info);

extern size_t message_broadcast(opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info);
extern size_t message_broadcast_with_callback(opcode_t opcode, void *payload,
	small_idx_t size, userinfo_t info, event_callback_t callback);

extern void message_read(void *, void *payload);
extern void message_write(void *, void *payload);

extern void daemon_start(void);

extern int ipv6_enabled(void);
extern void ipv6_set_enabled(int enabled);

static inline int
message_flags(message_t *msg)
{
	return (be16toh(msg->flags));
}
#endif /* __TIFA_NETWORK_H */
