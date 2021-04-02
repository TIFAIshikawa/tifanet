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
#include <sodium.h>
#include <strings.h>
#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include "log.h"
#include "notar.h"
#include "error.h"
#include "config.h"
#include "keypair.h"
#include "network.h"
#include "opcode_callback.h"

typedef void (*opcode_callback_t)(event_info_t *info);
typedef int (*opcode_ignore_callback_t)(event_info_t *info);

typedef struct  __attribute__((__packed__)) __op_peerlist_response {
	small_idx_t peers_ipv4_count;
	small_idx_t peers_ipv6_count;
} op_peerlist_response_t;

typedef struct  __attribute__((__packed__)) __op_lastblockinfo_response {
	big_idx_t index;
	hash_t hash;
	hash_t prev_block_hash;
	public_key_t notar;
	signature_t signature;
} op_lastblockinfo_response_t;

typedef struct  __attribute__((__packed__)) __op_pact_response {
	error_t code;
	small_hash_t pact_hash;
} op_pact_response_t;

void op_peerlist(event_info_t *info);
void op_lastblockinfo(event_info_t *info);
void op_getblock(event_info_t *info);
void op_notar_announce(event_info_t *info);
void op_notar_denounce(event_info_t *info);
void op_block_announce(event_info_t *info);
void op_notarproof(event_info_t *info);
void op_pact(event_info_t *info);
void op_gettxcache(event_info_t *info);
void op_getnotars(event_info_t *info);

int op_block_announce_ignore(event_info_t *info);

void op_peerlist_server(event_info_t *info, network_event_t *nev);
void op_peerlist_client(event_info_t *info, network_event_t *nev);
void op_lastblockinfo_server(event_info_t *info, network_event_t *nev);
void op_lastblockinfo_client(event_info_t *info, network_event_t *nev);
void op_getblock_server(event_info_t *info, network_event_t *nev);
void op_getblock_client(event_info_t *info, network_event_t *nev);
void op_pact_server(event_info_t *info, network_event_t *nev);
void op_pact_client(event_info_t *info, network_event_t *nev);
void op_gettxcache_server(event_info_t *info, network_event_t *nev);
void op_gettxcache_client(event_info_t *info, network_event_t *nev);
void op_getnotars_server(event_info_t *info, network_event_t *nev);
void op_getnotars_client(event_info_t *info, network_event_t *nev);

opcode_ignore_callback_t opcode_ignore_callbacks[OP_MAXOPCODE] = {
	NULL,			// OP_NONE
	NULL,			// OP_PEERLIST
	NULL,			// OP_LASTBLOCKINFO
	NULL,			// OP_GETBLOCK
	NULL,			// OP_NOTAR_ANNOUNCE
	NULL,			// OP_NOTAR_DENOUNCE
	op_block_announce_ignore, // OP_BLOCK_ANNOUNCE
	NULL,			// OP_PACT
	NULL,			// OP_GETTXCACHE
	NULL,			// OP_GETNOTARS
};

opcode_callback_t opcode_callbacks[OP_MAXOPCODE] = {
	NULL,			// OP_NONE
	op_peerlist,		// OP_PEERLIST
	op_lastblockinfo,	// OP_LASTBLOCKINFO
	op_getblock,		// OP_GETBLOCK
	op_notar_announce,	// OP_NOTAR_ANNOUNCE
	op_notar_denounce,	// OP_NOTAR_DENOUNCE
	op_block_announce,	// OP_BLOCK_ANNOUNCE
	op_pact,		// OP_PACT
	op_gettxcache,		// OP_GETTXCACHE
	op_getnotars,		// OP_GETNOTARS
};

int
opcode_valid(message_t *msg)
{
	opcode_t opcode;

	opcode = be16toh(msg->opcode);

	return (opcode > OP_NONE && opcode < OP_MAXOPCODE);
}

int
opcode_payload_size_valid(message_t *msg, int direction)
{
	opcode_t opcode;

	opcode = be16toh(msg->opcode);

	switch (opcode) {
	case OP_PEERLIST:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (be32toh(msg->payload_size) == 0);
		else
			return (be32toh(msg->payload_size) >= sizeof(op_peerlist_response_t));
	case OP_LASTBLOCKINFO:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (be32toh(msg->payload_size) == 0);
		else
			return (be32toh(msg->payload_size) == sizeof(op_lastblockinfo_response_t));
	case OP_GETBLOCK:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (be32toh(msg->payload_size) == sizeof(big_idx_t));
		else
			return (be32toh(msg->payload_size) >= 256 && be32toh(msg->payload_size) < MAXPACKETSIZE);
	case OP_NOTAR_ANNOUNCE:
	case OP_NOTAR_DENOUNCE:
		return (be32toh(msg->payload_size) == sizeof(public_key_t));
	case OP_BLOCK_ANNOUNCE:
		return (be32toh(msg->payload_size) >= 256 && be32toh(msg->payload_size) < MAXPACKETSIZE);
	case OP_PACT:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (be32toh(msg->payload_size) >= sizeof(raw_pact_t) + sizeof(pact_rx_t) + sizeof(pact_tx_t) && be32toh(msg->payload_size) < MAXPACKETSIZE);
		else
			return sizeof(op_pact_response_t);
	case OP_GETTXCACHE:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (0);
		return (be32toh(msg->payload_size) < MAXPACKETSIZE);
	case OP_GETNOTARS:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (0);
		return (be32toh(msg->payload_size) < MAXPACKETSIZE);
	}

	return (FALSE);
}

int
opcode_message_ignore(event_info_t *info)
{
	message_t *msg;

	msg = network_message(info);
	if (opcode_ignore_callbacks[be16toh(msg->opcode)])
		return (opcode_ignore_callbacks[be16toh(msg->opcode)](info));

	return (FALSE);
}

void
opcode_execute(event_info_t *info)
{
	message_t *msg;

	msg = network_message(info);
	if (be16toh(msg->opcode) == OP_NONE || be16toh(msg->opcode) >= OP_MAXOPCODE) {
		lprintf("msg->opcode invalid: %d", be16toh(msg->opcode));
		event_remove(info);

		return;
	}

	opcode_callbacks[be16toh(msg->opcode)](info);
}

void
op_peerlist(event_info_t *info)
{
	network_event_t *nev;
	nev = info->payload;

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		op_peerlist_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_peerlist_client(info, nev);
		break;
	default:
		break;
	}
}

void
op_peerlist_server(event_info_t *info, network_event_t *nev)
{
	size_t size;
	message_t *msg;
	uint8_t *buf, *ptr;
	size_t ipv4_size, ipv6_size;
	op_peerlist_response_t *response;

	ipv4_size = peerlist.list4_size * sizeof(struct in_addr);
	ipv6_size = peerlist.list6_size * sizeof(struct in6_addr);
	size = sizeof(op_peerlist_response_t) + ipv4_size + ipv6_size;

	buf = malloc(size);
	response = (op_peerlist_response_t *)buf;

	response->peers_ipv4_count = htobe32(peerlist.list4_size);
	response->peers_ipv6_count = htobe32(peerlist.list6_size);

	ptr = buf + sizeof(op_peerlist_response_t);
	bcopy(peerlist.list4, ptr, ipv4_size);
	ptr += ipv4_size;
	bcopy(peerlist.list6, ptr, ipv6_size);

	nev = info->payload;
	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata = response;
	nev->userdata_size = size;
	msg = network_message(info);
	msg->payload_size = htobe32(size);

	event_update(info, EVENT_READ, EVENT_WRITE);
	info->callback = message_write;
	message_write(info, EVENT_WRITE);
}

void
op_peerlist_client(event_info_t *info, network_event_t *nev)
{
	uint8_t *buf;
	message_t *msg;
	op_peerlist_response_t *response;
	struct in_addr *addr4_list;
	struct in6_addr *addr6_list;

	msg = network_message(info);

	buf = nev->userdata;
	response = (op_peerlist_response_t *)buf;
	response->peers_ipv4_count = be32toh(response->peers_ipv4_count);
	response->peers_ipv6_count = be32toh(response->peers_ipv6_count);

	buf += sizeof(op_peerlist_response_t);
	addr4_list = (struct in_addr *)buf;
	buf += response->peers_ipv4_count * sizeof(struct in_addr);
	addr6_list = (struct in6_addr *)buf;
	buf += response->peers_ipv6_count * sizeof(struct in6_addr);

	if (buf - (uint8_t *)nev->userdata != be32toh(msg->payload_size))
		return (message_cancel(info));

	for (small_idx_t i = 0; i < response->peers_ipv4_count; i++)
		peerlist_add_ipv4(addr4_list[i]);
	for (small_idx_t i = 0; i < response->peers_ipv6_count; i++)
		peerlist_add_ipv6(addr6_list[i]);

	message_cancel(info);
}

void
op_lastblockinfo(event_info_t *info)
{
	network_event_t *nev;
	nev = info->payload;

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		op_lastblockinfo_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_lastblockinfo_client(info, nev);
		break;
	default:
		break;
	}
}

void
op_lastblockinfo_server(event_info_t *info, network_event_t *nev)
{
	size_t size;
	message_t *msg;
	raw_block_t *last;
	hash_t block_hash;
	op_lastblockinfo_response_t *blockinfo;

	last = raw_block_last(&size);
	raw_block_hash(last, size, block_hash);

	blockinfo = malloc(sizeof(op_lastblockinfo_response_t));
	blockinfo->index = last->index;
	bcopy(block_hash, blockinfo->hash, sizeof(hash_t));
	bcopy(last->prev_block_hash, blockinfo->prev_block_hash,
		sizeof(hash_t));

	nev = info->payload;
	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata = blockinfo;
	nev->userdata_size = sizeof(op_lastblockinfo_response_t);
	msg = network_message(info);
	msg->payload_size = htobe32(sizeof(op_lastblockinfo_response_t));

	event_update(info, EVENT_READ, EVENT_WRITE);
	info->callback = message_write;
	message_write(info, EVENT_WRITE);
}

void
op_lastblockinfo_client(event_info_t *info, network_event_t *nev)
{
	big_idx_t lcl_idx, rmt_idx;
	op_lastblockinfo_response_t *blockinfo;

	lcl_idx = block_idx_last();

	blockinfo = nev->userdata;
	rmt_idx = be64toh(blockinfo->index);

	lprintf("last block is #%ju", rmt_idx);

	if (lcl_idx < rmt_idx) {
		getblocks(rmt_idx);
	} else {
		lprintf("fully synchronized");
		if (is_sync_only())
			exit(0);

		daemon_start();
	}

	info->on_close = NULL;

	message_cancel(info);
}

void
op_getblock(event_info_t *info)
{
	network_event_t *nev;
	nev = info->payload;

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		op_getblock_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_getblock_client(info, nev);
		break;
	default:
		break;
	}
}

void
op_getblock_server(event_info_t *info, network_event_t *nev)
{
	raw_block_t *block;
	message_t *msg;
	size_t size;

	msg = network_message(info);
	if (!(block = block_load(be64toh(msg->userinfo), &size))) {
		message_cancel(info);
		return;
	}

	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata = block;
	nev->userdata_size = sizeof(size);
	msg->payload_size = htobe32(size);

	event_update(info, EVENT_READ, EVENT_WRITE);
	info->callback = message_write;
	message_write(info, EVENT_WRITE);
}

void
op_getblock_client(event_info_t *info, network_event_t *nev)
{
	message_t *msg;

	msg = network_message(info);

	if (raw_block_validate(nev->userdata, be32toh(msg->payload_size)))
		raw_block_process(nev->userdata, be32toh(msg->payload_size));

	info->on_close = NULL;
	message_cancel(info);
	getblocks(0);
}

void
op_notar_announce(event_info_t *info)
{
	network_event_t *nev;
	public_key_t new_notar;

	nev = info->payload;
	bcopy(nev->userdata, new_notar, sizeof(public_key_t));
	notar_pending_add(new_notar);

	message_cancel(info);
}

void
op_notar_denounce(event_info_t *info)
{
printf("denounce\n");
}

void
op_block_announce(event_info_t *info)
{
	network_event_t *nev;
	raw_block_t *block;
	big_idx_t index;
	message_t *msg;
	size_t size;

	nev = info->payload;
	block = nev->userdata;
	index = block_idx(block);
	lprintf("received block %ju", index);

	msg = network_message(info);

	if (raw_block_validate(nev->userdata, be32toh(msg->payload_size))) {
		raw_block_process(nev->userdata, nev->read_idx);

		// get block from block storage (which is permanent, whereas
		// nev->userdata will be freed), then redistribute
        	block = block_load(index, &size);
        	message_broadcast(OP_BLOCK_ANNOUNCE, block, size,
			htobe64(index));
	}

	message_cancel(info);
}

int
op_block_announce_ignore(event_info_t *info)
{
	message_t *msg;
	int res;

	msg = network_message(info);
	res = block_exists(be64toh(msg->userinfo));

	return (res);
}

void
op_notarproof(event_info_t *info)
{
printf("notarproof\n");
}

void
op_pact(event_info_t *info)
{
	network_event_t *nev;
	nev = info->payload;

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		op_pact_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_pact_client(info, nev);
		break;
	default:
		break;
	}
}

void
op_pact_server(event_info_t *info, network_event_t *nev)
{
	int err;
	int delay;
	size_t size;
	time64_t tm;
	message_t *msg;
	raw_pact_t *t;
	op_pact_response_t *response;

	msg = network_message(info);

	t = nev->userdata;
	size = pact_size(t);

	response = calloc(1, sizeof(op_pact_response_t));
	pact_hash(t, response->pact_hash);

	if (size != be32toh(msg->payload_size)) {
		err = ERR_MALFORMED;
	} else {
		if ((err = raw_pact_validate(t)) == NO_ERR)
			err = pact_pending_add(t);
	}
	if (err == NO_ERR)
		if ((delay = pact_delay(t, 0)) >= 10)
			err = ERR_TX_FLOOD;
	if (err == NO_ERR) {
		tm = time(NULL);
		t->time = htobe64(tm + delay * 60);
	}

	if (err != NO_ERR)
		free(t);
	response->code = htobe32(err);
	
	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata = response;
	nev->userdata_size = sizeof(op_pact_response_t);
	msg->payload_size = htobe32(nev->userdata_size);

	event_update(info, EVENT_READ, EVENT_WRITE);
	info->callback = message_write;
	message_write(info, EVENT_WRITE);
}

void
op_pact_client(event_info_t *info, network_event_t *nev)
{
	op_pact_response_t *response;

	response = nev->userdata;
	printf("  - result: %s\n", schkerror(be32toh(response->code)));
	printf("    code: %u\n", be32toh(response->code));
	printf("    pact_hash: ");
	for (size_t i = 0; i < sizeof(small_hash_t); i++)
		printf("%02x", response->pact_hash[i]);
	printf("\n");


	message_cancel(info);
}

void
op_gettxcache(event_info_t *info)
{
	network_event_t *nev;
	nev = info->payload;

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		op_gettxcache_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_gettxcache_client(info, nev);
		break;
	default:
		break;
	}
}

void
op_gettxcache_server(event_info_t *info, network_event_t *nev)
{
	char tmp[MAXPATHLEN + 1];
	message_t *msg;
	size_t size;
	FILE *f;

	config_path(tmp, "blocks/txcache.bin");
	if (!(f = fopen(tmp, "r")))
		return message_cancel(info);

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (!(nev->userdata = malloc(size)))
		return message_cancel(info);
	if (fread(nev->userdata + sizeof(big_idx_t), 1, size, f) != size)
		return message_cancel(info);

	msg = network_message(info);

	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata_size = size;
	msg->payload_size = htobe32(nev->userdata_size);

	event_update(info, EVENT_READ, EVENT_WRITE);
	info->callback = message_write;
	message_write(info, EVENT_WRITE);
}

static int
__cache_write(char *filename, char *buffer, size_t size)
{
	char tmp0[MAXPATHLEN + 1];
	char tmp1[MAXPATHLEN + 1];
	size_t w, wr;
	FILE *f;

	snprintf(tmp0, MAXPATHLEN, "blocks/%s.bin", filename);
	config_path(tmp1, tmp0);
	if (!(f = fopen(tmp1, "w+")))
		return (FALSE);

	for (w = wr = 0; w >= 0; wr += w)
		w = fwrite(buffer + wr, 1, size - wr, f);

	if (wr != size)
		FAILTEMP("failed writing txcache: %s", strerror(errno));

	fclose(f);

	return (TRUE);
}

void
op_gettxcache_client(event_info_t *info, network_event_t *nev)
{
	message_t *msg;

	msg = network_message(info);

	__cache_write("txcache", nev->userdata, be32toh(msg->payload_size));

	info->on_close = NULL;
	message_cancel(info);
}

void
op_getnotars(event_info_t *info)
{
	network_event_t *nev;
	nev = info->payload;

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		op_getnotars_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_getnotars_client(info, nev);
		break;
	default:
		break;
	}
}

void
op_getnotars_server(event_info_t *info, network_event_t *nev)
{
	char tmp[MAXPATHLEN + 1];
	message_t *msg;
	size_t size;
	FILE *f;

	config_path(tmp, "blocks/notarscache.bin");
	if (!(f = fopen(tmp, "r")))
		return message_cancel(info);

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (!(nev->userdata = malloc(size)))
		return message_cancel(info);
	if (fread(nev->userdata, 1, size, f) != size)
		return message_cancel(info);

	msg = network_message(info);

	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata_size = size;
	msg->payload_size = htobe32(nev->userdata_size);

	event_update(info, EVENT_READ, EVENT_WRITE);
	info->callback = message_write;
	message_write(info, EVENT_WRITE);
}

void
op_getnotars_client(event_info_t *info, network_event_t *nev)
{
	message_t *msg;

	msg = network_message(info);

	__cache_write("notarscache", nev->userdata, be32toh(msg->payload_size));

	info->on_close = NULL;
	message_cancel(info);
}
