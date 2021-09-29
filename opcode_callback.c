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
#include "log.h"
#include "notar.h"
#include "error.h"
#include "cache.h"
#include "config.h"
#include "endian.h"
#include "keypair.h"
#include "network.h"
#include "opcode_callback.h"

#define GETBLOCKS_MAX_BLOCKS 1500

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

static void op_peerlist(event_info_t *info);
static void op_lastblockinfo(event_info_t *info);
static void op_getblock(event_info_t *info);
static void op_notarannounce(event_info_t *info);
static void op_notardenounce(event_info_t *info);
static void op_blockannounce(event_info_t *info);
static void op_notarproof(event_info_t *info);
static void op_pact(event_info_t *info);
static void op_getrxcache(event_info_t *info);
static void op_getnotars(event_info_t *info);

static int op_blockannounce_ignore(event_info_t *info);

static void op_peerlist_server(event_info_t *info, network_event_t *nev);
static void op_peerlist_client(event_info_t *info, network_event_t *nev);
static void op_lastblockinfo_server(event_info_t *info, network_event_t *nev);
static void op_lastblockinfo_client(event_info_t *info, network_event_t *nev);
static void op_getblock_server(event_info_t *info, network_event_t *nev);
static void op_getblock_client(event_info_t *info, network_event_t *nev);
static void op_pact_server(event_info_t *info, network_event_t *nev);
static void op_pact_client(event_info_t *info, network_event_t *nev);
static void op_getrxcache_server(event_info_t *info, network_event_t *nev);
static void op_getrxcache_client(event_info_t *info, network_event_t *nev);
static void op_getnotars_server(event_info_t *info, network_event_t *nev);
static void op_getnotars_client(event_info_t *info, network_event_t *nev);

static int __verify_lastblockinfo(op_lastblockinfo_response_t *info,
	network_event_t *nev);

opcode_ignore_callback_t opcode_ignore_callbacks[OP_MAXOPCODE] = {
	NULL,			// OP_NONE
	NULL,			// OP_PEERLIST
	NULL,			// OP_LASTBLOCKINFO
	NULL,			// OP_GETBLOCK
	NULL,			// OP_NOTARANNOUNCE
	NULL,			// OP_NOTARDENOUNCE
	op_blockannounce_ignore,// OP_BLOCKANNOUNCE
	NULL,			// OP_PACT
	NULL,			// OP_GETRXCACHE
	NULL,			// OP_GETNOTARS
};

opcode_callback_t opcode_callbacks[OP_MAXOPCODE] = {
	NULL,			// OP_NONE
	op_peerlist,		// OP_PEERLIST
	op_lastblockinfo,	// OP_LASTBLOCKINFO
	op_getblock,		// OP_GETBLOCK
	op_notarannounce,	// OP_NOTARANNOUNCE
	op_notardenounce,	// OP_NOTARDENOUNCE
	op_blockannounce,	// OP_BLOCKANNOUNCE
	op_pact,		// OP_PACT
	op_getrxcache,		// OP_GETRXCACHE
	op_getnotars,		// OP_GETNOTARS
};

int
opcode_valid(message_t *msg)
{
	return (msg->opcode > OP_NONE && msg->opcode < OP_MAXOPCODE);
}

int
opcode_payload_size_valid(message_t *msg, int direction)
{
	switch (msg->opcode) {
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
	case OP_NOTARANNOUNCE:
	case OP_NOTARDENOUNCE:
		return (be32toh(msg->payload_size) == sizeof(public_key_t));
	case OP_BLOCKANNOUNCE:
		return (be32toh(msg->payload_size) >= 256 && be32toh(msg->payload_size) < MAXPACKETSIZE);
	case OP_PACT:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (be32toh(msg->payload_size) >= sizeof(raw_pact_t) + sizeof(pact_tx_t) + sizeof(pact_rx_t) && be32toh(msg->payload_size) < MAXPACKETSIZE);
		else
			return (0);
	case OP_GETRXCACHE:
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
	if (opcode_ignore_callbacks[msg->opcode])
		return (opcode_ignore_callbacks[msg->opcode](info));

	return (FALSE);
}

void
opcode_execute(event_info_t *info)
{
	message_t *msg;

	msg = network_message(info);
	if (msg->opcode == OP_NONE || msg->opcode >= OP_MAXOPCODE) {
		lprintf("msg->opcode invalid: %d", msg->opcode);
		event_remove(info);

		return;
	}

	opcode_callbacks[msg->opcode](info);
}

static void
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

static void
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
#ifdef DEBUG_ALLOC
	lprintf("+USERDATA %p PEERLIST", response);
#endif

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

static void
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

	peerlist_save();
}

static void
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

static void
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
#ifdef DEBUG_ALLOC
	lprintf("+USERDATA %p BLOCKINFO", blockinfo);
#endif
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

static int
__verify_lastblockinfo(op_lastblockinfo_response_t *info, network_event_t *nev)
{
	size_t size;
	hash_t hash;
	raw_block_t *block;

	if (!(block = block_load(be64toh(info->index), &size)))
		return (FALSE);

	if (!hash_equals(block->prev_block_hash, info->prev_block_hash)) {
		lprintf("peer %s, block %ju, has different prev_block_hash!",
			peername(&nev->remote_addr), be64toh(info->index)); 
		return (FALSE);
	}

	raw_block_hash(block, size, hash);
	if (!hash_equals(hash, info->hash)) {
		lprintf("peer %s, block %ju, has different block hash!",
			peername(&nev->remote_addr), be64toh(info->index)); 
		return (FALSE);
	}

	return (TRUE);
}

static void
op_lastblockinfo_client(event_info_t *info, network_event_t *nev)
{
	big_idx_t lcl_idx, rmt_idx;
	op_lastblockinfo_response_t *blockinfo;

	lcl_idx = block_idx_last();

	blockinfo = nev->userdata;
	rmt_idx = be64toh(blockinfo->index);

	if (rmt_idx != lcl_idx)
		lprintf("%s's last block is %ju (our last is %ju)",
			peername(&nev->remote_addr), rmt_idx, lcl_idx);

	if (lcl_idx < rmt_idx) {
		getblocks(rmt_idx);
		notar_elect_next();
	} else if (lcl_idx > rmt_idx) {
		if (!__verify_lastblockinfo(blockinfo, nev)) {
			peerlist_remove(&nev->remote_addr);
			blockchain_dns_verify();
		}

		daemon_start();
		notar_elect_next();
	}

	message_cancel(info);
}

static void
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

static void
op_getblock_server(event_info_t *info, network_event_t *nev)
{
	raw_block_t *block;
	message_t *msg;
	size_t size;

	msg = network_message(info);
	if (!(block = blocks_load(be64toh(msg->userinfo), &size,
		GETBLOCKS_MAX_BLOCKS, MAXPACKETSIZE))) {
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

static void
op_getblock_client(event_info_t *info, network_event_t *nev)
{
	size_t size, bufsize;
	message_t *msg;
	void *block;
	size_t p;

	msg = network_message(info);

	block = nev->userdata;
	bufsize = be32toh(msg->payload_size);

	for (p = 0; bufsize > 0; p++) {
        	// check block size
		if (bufsize < sizeof(raw_block_t) + sizeof(raw_pact_t) +
			sizeof(pact_rx_t)) {
			lprintf("incoming block is smaller than block "
				"skeleton: %d", bufsize);
			break;
		}

		size = raw_block_size(block, bufsize);
		if (size > bufsize) {
			lprintf("incoming block is larger than incoming data",
				": %d vs %d", size, bufsize);
			break;
		}
		if (block_idx(block) == block_idx_last() + 1) {
			if (!raw_block_validate(block, size))
				break;

			lprintf("received block %ju, size %ld",
				block_idx(block), size);
			raw_block_process(block, size);
		}

		block += size;
		bufsize -= size;
	}

	if (p > 100)
		blockchain_dns_verify();

	message_cancel(info);
}

static void
op_notarannounce(event_info_t *info)
{
	network_event_t *nev;
	public_key_t new_notar;

	nev = info->payload;
	bcopy(nev->userdata, new_notar, sizeof(public_key_t));
	notar_pending_add(new_notar);

	message_cancel(info);
}

static void
op_notardenounce(event_info_t *info)
{
	lprintf("OP_DENOUNCE not implemented");
	message_cancel(info);
}

static void
op_blockannounce(event_info_t *info)
{
	network_event_t *nev;
	raw_block_t *block;
	big_idx_t index;
	message_t *msg;
	size_t size;

	nev = info->payload;
	block = nev->userdata;
	index = block_idx(block);

	msg = network_message(info);
	size = be32toh(msg->payload_size);

	if (raw_block_validate(nev->userdata, size)) {
		lprintf("received block %ju, size %ld", index, size);

		raw_block_process(block, size);

		// The received block may be an incomplete denouncement
		// block, in which case it's not saved yet. If this is
		// an incomplete denouncement block, it will be broadcast
		// elsewhere.
		if (block_idx_last() == index)
			raw_block_broadcast(index);
	} else {
		if (raw_block_future_buffer_add(nev->userdata, size))
			nev->userdata = NULL;
	}

	message_cancel(info);
}

static int
op_blockannounce_ignore(event_info_t *info)
{
	message_t *msg;
	int res;

	msg = network_message(info);
	if (!(res = block_exists(be64toh(msg->userinfo))))
		if (!(res = block_idx_in_transit(msg->userinfo)))
			block_transit_message_add(msg);

	return (res);
}

static void
op_notarproof(event_info_t *info)
{
	lprintf("OP_NOTARPROOF not implemented");
	message_cancel(info);
}

static void
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

static void
op_pact_server(event_info_t *info, network_event_t *nev)
{
	size_t size;
	time64_t tm;
	raw_pact_t *p;
	int delay = 0;
	message_t *msg;
	small_idx_t sz;
	userinfo_t err;

	msg = network_message(info);

	p = nev->userdata;
	size = pact_size(p);

	if (size != be32toh(msg->payload_size))
		err = ERR_MALFORMED;
	else
		if ((err = raw_pact_validate(p)) == NO_ERR)
			err = pact_pending_add(p);

	if (err == NO_ERR) {
		if ((delay = pact_delay(p, 0)) >= 10)
			err = ERR_RX_FLOOD;
	}
	if (err == NO_ERR) {
		tm = time(NULL);
		p->time = htobe64(tm + delay);
	}

	if (err == NO_ERR)
		nev->userdata = NULL;

	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata_size = 0;
	msg->payload_size = 0;
	msg->userinfo = htobe64(err);

	event_update(info, EVENT_READ, EVENT_WRITE);
	info->callback = message_write;
	message_write(info, EVENT_WRITE);

	pacts_pending(&sz);
	if (sz >= 2 && notar_should_generate_block())
		block_generate_next();
}

static void
op_pact_client(event_info_t *info, network_event_t *nev)
{
	message_cancel(info);
}

static void
op_getrxcache(event_info_t *info)
{
	network_event_t *nev;
	nev = info->payload;

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		op_getrxcache_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_getrxcache_client(info, nev);
		break;
	default:
		break;
	}
}

static void
op_getrxcache_server(event_info_t *info, network_event_t *nev)
{
	message_t *msg;
	size_t size;
	FILE *f;

	if (!(f = config_fopen("blocks/rxcache.bin", "r")))
		return message_cancel(info);

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (!(nev->userdata = malloc(size)))
		return message_cancel(info);
#ifdef DEBUG_ALLOC
	lprintf("+USERDATA %p RXCACHE", nev->userdata);
#endif
	if (fread(nev->userdata, 1, size, f) != size) {
		fclose(f);
		return message_cancel(info);
	}
	fclose(f);

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

static void
op_getrxcache_client(event_info_t *info, network_event_t *nev)
{
	message_t *msg;

	msg = network_message(info);
	cache_write("rxcache", nev->userdata, be32toh(msg->payload_size));

	message_cancel(info);
}

static void
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

static void
op_getnotars_server(event_info_t *info, network_event_t *nev)
{
	message_t *msg;
	size_t size;
	FILE *f;

	if (!(f = config_fopen("blocks/notarscache.bin", "r")))
		return message_cancel(info);

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (!(nev->userdata = malloc(size)))
		return message_cancel(info);
#ifdef DEBUG_ALLOC
	lprintf("+USERDATA %p NOTARS", nev->userdata);
#endif
	if (fread(nev->userdata, 1, size, f) != size) {
		fclose(f);
		return message_cancel(info);
	}
	fclose(f);

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

static void
op_getnotars_client(event_info_t *info, network_event_t *nev)
{
	message_t *msg;

	msg = network_message(info);

	cache_write("notarscache", nev->userdata, be32toh(msg->payload_size));

	message_cancel(info);
}
