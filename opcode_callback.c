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
#include <sys/socket.h>

#include "log.h"
#include "dns.h"
#include "notar.h"
#include "error.h"
#include "cache.h"
#include "config.h"
#include "endian.h"
#include "keypair.h"
#include "network.h"
#include "rxcache.h"
#include "block_storage.h"
#include "opcode_callback.h"

#define GETBLOCKS_MAX_BLOCKS 1500

typedef void (*opcode_callback_t)(event_fd_t *info);

typedef struct  __attribute__((__packed__)) __op_peerlist_response {
	small_idx_t peers_ipv4_count;
	small_idx_t peers_ipv6_count;
} op_peerlist_response_t;

typedef struct  __attribute__((__packed__)) __op_blockinfo_response {
	big_idx_t index;
	hash_t hash;
	hash_t prev_block_hash;
	public_key_t notar;
	signature_t signature;
} op_blockinfo_response_t;

static userinfo_t __getrxcache_userinfo;
static userinfo_t __getnotarscache_userinfo;
static userinfo_t __getpeerlist_userinfo;

static void op_peerlist(event_fd_t *info);
static void op_blockinfo(event_fd_t *info);
static void op_getblock(event_fd_t *info);
static void op_notarannounce(event_fd_t *info);
static void op_blockannounce(event_fd_t *info);
static void op_pact(event_fd_t *info);
static void op_getrxcache(event_fd_t *info);
static void op_getnotars(event_fd_t *info);

static void op_peerlist_server(event_fd_t *info, network_event_t *nev);
static void op_peerlist_client(event_fd_t *info, network_event_t *nev);
static void op_blockinfo_server(event_fd_t *info, network_event_t *nev);
static void op_blockinfo_client(event_fd_t *info, network_event_t *nev);
static void op_getblock_server(event_fd_t *info, network_event_t *nev);
static void op_getblock_client(event_fd_t *info, network_event_t *nev);
static void op_pact_server(event_fd_t *info, network_event_t *nev);
static void op_pact_client(event_fd_t *info, network_event_t *nev);
static void op_getrxcache_server(event_fd_t *info, network_event_t *nev);
static void op_getrxcache_client(event_fd_t *info, network_event_t *nev);
static void op_getnotars_server(event_fd_t *info, network_event_t *nev);
static void op_getnotars_client(event_fd_t *info, network_event_t *nev);

static int __verify_blockinfo(op_blockinfo_response_t *info,
	network_event_t *nev);

opcode_callback_t opcode_callbacks[OP_MAXOPCODE] = {
	NULL,			// OP_NONE
	op_peerlist,		// OP_PEERLIST
	op_blockinfo,		// OP_BLOCKINFO
	op_getblock,		// OP_GETBLOCK
	op_notarannounce,	// OP_NOTARANNOUNCE
	op_blockannounce,	// OP_BLOCKANNOUNCE
	op_pact,		// OP_PACT
	op_getrxcache,		// OP_GETRXCACHE
	op_getnotars,		// OP_GETNOTARS
};

static int
__userinfo_equals(message_t *msg, userinfo_t userinfo)
{
	return (memcmp(&msg->userinfo, &userinfo, sizeof(userinfo_t)) == 0);
}

static inline void
__userinfo_random_fill(userinfo_t *userinfo)
{
	uint32_t *info;

	info = (uint32_t *)userinfo;
	info[0] = randombytes_random();
	info[1] = randombytes_random();
}

userinfo_t
getrxcache_userinfo(void)
{
	__userinfo_random_fill(&__getrxcache_userinfo);

	return (__getrxcache_userinfo);
}

userinfo_t
getnotarscache_userinfo(void)
{
	__userinfo_random_fill(&__getnotarscache_userinfo);

	return (__getnotarscache_userinfo);
}

userinfo_t
getpeerlist_userinfo(void)
{
	__userinfo_random_fill(&__getpeerlist_userinfo);

	return (__getpeerlist_userinfo);
}

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
	case OP_BLOCKINFO:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (be32toh(msg->payload_size) == 0);
		else
			return (be32toh(msg->payload_size) == sizeof(op_blockinfo_response_t));
	case OP_GETBLOCK:
		if (direction == NETWORK_EVENT_TYPE_SERVER)
			return (be32toh(msg->payload_size) == sizeof(big_idx_t));
		else
			return (be32toh(msg->payload_size) >= 224 && be32toh(msg->payload_size) < MAXPACKETSIZE);
	case OP_NOTARANNOUNCE:
		return (be32toh(msg->payload_size) == sizeof(public_key_t));
	case OP_BLOCKANNOUNCE:
		return (be32toh(msg->payload_size) == 0);
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

void
opcode_execute(event_fd_t *info)
{
	message_t *msg;

	msg = network_message(info);
	if (msg->opcode == OP_NONE || msg->opcode >= OP_MAXOPCODE) {
		lprintf("msg->opcode invalid: %d", msg->opcode);
		event_fd_remove(info);

		return;
	}

	opcode_callbacks[msg->opcode](info);
}

static void
op_peerlist(event_fd_t *info)
{
	network_event_t *nev;
	nev = network_event(info);

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		nev->message_header.flags |= htons(MESSAGE_FLAG_REPLY);
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
op_peerlist_server(event_fd_t *info, network_event_t *nev)
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

	nev = network_event(info);
	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata = response;
	nev->userdata_size = size;
	msg = network_message(info);
	msg->payload_size = htobe32(size);

	event_fd_update(info, EVENT_WRITE);
	event_callback_set(info, message_write);
	message_write(info, event_payload_get(info));
}

static void
op_peerlist_client(event_fd_t *info, network_event_t *nev)
{
	uint8_t *buf;
	message_t *msg;
	op_peerlist_response_t *response;
	struct in_addr *addr4_list;
	struct in6_addr *addr6_list;

	msg = network_message(info);

	if (!nev->userdata)
		return (message_done(info));

	if (!__userinfo_equals(msg, __getpeerlist_userinfo))
		return (message_cancel(info));

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

	message_done(info);

	peerlist_save();
}

static void
op_blockinfo(event_fd_t *info)
{
	network_event_t *nev;
	nev = event_payload_get(info);

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		nev->message_header.flags |= htons(MESSAGE_FLAG_REPLY);
		op_blockinfo_server(info, nev);
		break;
	case NETWORK_EVENT_TYPE_CLIENT:
		op_blockinfo_client(info, nev);
		break;
	default:
		break;
	}
}

static void
op_blockinfo_server(event_fd_t *info, network_event_t *nev)
{
	size_t size;
	big_idx_t idx;
	message_t *msg;
	raw_block_t *block;
	hash_t block_hash;
	op_blockinfo_response_t *blockinfo;

	msg = network_message(info);

	idx = be64toh(msg->userinfo);
	if (!idx || idx > block_idx_last())
		block = raw_block_last(&size);
	else
		block = block_load(idx, &size);

	raw_block_hash(block, size, block_hash);

	blockinfo = malloc(sizeof(op_blockinfo_response_t));
	blockinfo->index = block->index;
	bcopy(block_hash, blockinfo->hash, sizeof(hash_t));
	bcopy(block->prev_block_hash, blockinfo->prev_block_hash,
		sizeof(hash_t));

	nev = event_payload_get(info);
	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata = blockinfo;
	nev->userdata_size = sizeof(op_blockinfo_response_t);

	msg->payload_size = htobe32(sizeof(op_blockinfo_response_t));

	event_fd_update(info, EVENT_WRITE);
	event_callback_set(info, message_write);
	message_write(info, event_payload_get(info));
}

static int
__verify_blockinfo(op_blockinfo_response_t *info, network_event_t *nev)
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
op_blockinfo_client(event_fd_t *info, network_event_t *nev)
{
	big_idx_t lcl_idx, rmt_idx;
	op_blockinfo_response_t *blockinfo;

	if (!nev->userdata)
		return (message_done(info));
		
	if (ignorelist_is_ignored(&network_event(info)->remote_addr))
		return (message_cancel(info));

	lcl_idx = block_idx_last();

	blockinfo = nev->userdata;
	rmt_idx = be64toh(blockinfo->index);

#ifdef DEBUG_CHAINCHECK
	lprintf("%s's last block is %ju (our last is %ju)",
		peername(&nev->remote_addr), rmt_idx, lcl_idx);
#endif

	if (lcl_idx < rmt_idx) {
		getblocks(rmt_idx);
		notar_elect_next();
	} else {
		// if the peer gives false information - we think - ,
		// boycott this peer. DNS verification will prove the
		// peer either wrong or correct in time
		if (!__verify_blockinfo(blockinfo, nev))
			peerlist_ignore(&nev->remote_addr);
#ifdef DEBUG_CHAINCHECK
		else
			lprintf("block is %ju verified with %s", rmt_idx,
				peername(&nev->remote_addr));
#endif
	}

	message_done(info);
}

static void
op_getblock(event_fd_t *info)
{
	network_event_t *nev;
	nev = event_payload_get(info);

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		nev->message_header.flags |= htons(MESSAGE_FLAG_REPLY);
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
op_getblock_server(event_fd_t *info, network_event_t *nev)
{
	raw_block_t *block;
	message_t *msg;
	big_idx_t idx;
	size_t size;

	msg = network_message(info);
	idx = be64toh(msg->userinfo);

	if ((block = (raw_block_t *)denouncement_block_load(msg->userinfo)))
		size = sizeof(raw_block_timeout_t);
	else if (!(block = blocks_load(idx, &size, GETBLOCKS_MAX_BLOCKS,
		MAXPACKETSIZE))) {
		message_cancel(info);
		return;
	}

	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata = block;
	nev->userdata_size = sizeof(size);
	msg->payload_size = htobe32(size);

	event_fd_update(info, EVENT_WRITE);
	event_callback_set(info, message_write);
	message_write(info, event_payload_get(info));
}

static void
op_getblock_client(event_fd_t *info, network_event_t *nev)
{
	size_t size, bufsize, csz;
	hash_t bh, ch;
	raw_block_t *check;
	message_t *msg;
	big_idx_t idx;
	void *block;
	size_t p;

	if (!nev->userdata)
		return (message_done(info));
		
	if (ignorelist_is_ignored(&network_event(info)->remote_addr))
		return (message_cancel(info));

	msg = network_message(info);

	block = nev->userdata;
	bufsize = be32toh(msg->payload_size);

	for (p = 0; bufsize > 0; p++) {
        	// check block size
		if (bufsize < sizeof(raw_block_t) + sizeof(raw_pact_t) +
			sizeof(pact_rx_t)) {
			lprintf("incoming block is smaller than block "
				"skeleton: %ld vs %ld", bufsize, bufsize);
			break;
		}

		size = raw_block_size(block, bufsize);
		if (size > bufsize) {
			lprintf("incoming block %ju is larger than "
				"incoming data: %ld vs %ld", block_idx(block),
				size, bufsize);
			break;
		}

		idx = block_idx(block);

		if (config_is_caches_only() && !block_idx_last())
			block_load_initial(block, size);

		if (idx <= block_idx_last() && !config_is_caches_only()) {
			check = block_load(idx, &csz);
			raw_block_hash(block, size, bh);
			raw_block_hash(check, csz, ch);
			if (!hash_equals(bh, ch)) {
				lprintf("peer %s, block %ju, has different "
					"block hash!",
					peername(&nev->remote_addr), idx);
				peerlist_ignore(&nev->remote_addr);
				break;
			}
		}
		if (idx == block_idx_last() + 1) {
			if (!raw_block_validate(block, size))
				break;

			lprintf("received block %ju, size %ld", idx, size);
			raw_block_process(block, size);
		}

		block += size;
		bufsize -= size;
	}

	if (p > 100)
		blockchain_dns_verify();

	message_done(info);

	if (notar_should_generate_block())
		block_generate_next();

	if (config_is_sync_only()) {
		peerlist_save();
		rxcache_save(htobe64(block_idx_last()));
		notarscache_save(htobe64(block_idx_last()));
		exit(0);
	}
}

static void
op_notarannounce(event_fd_t *info)
{
	network_event_t *nev;
	public_key_t new_notar;

	if (ignorelist_is_ignored(&network_event(info)->remote_addr))
		return (message_cancel(info));

	nev = event_payload_get(info);
	bcopy(nev->userdata, new_notar, sizeof(public_key_t));
	notar_pending_add(new_notar);

	message_done(info);
}

static void
op_blockannounce(event_fd_t *info)
{
	big_idx_t index, last;
	message_t *msg;

	if (ignorelist_is_ignored(&network_event(info)->remote_addr))
		return (message_cancel(info));

	msg = network_message(info);
	index = be64toh(msg->userinfo);

	last = block_idx_last();
	if (last < index)
		message_send(info, OP_GETBLOCK, NULL, 0, htobe64(last + 1));
	else
		message_done(info);
}

static void
op_pact(event_fd_t *info)
{
	network_event_t *nev;
	nev = event_payload_get(info);

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		nev->message_header.flags |= htons(MESSAGE_FLAG_REPLY);
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
op_pact_server(event_fd_t *info, network_event_t *nev)
{
	size_t size;
	time64_t tm;
	raw_pact_t *p;
	int delay = 0;
	message_t *msg;
	small_idx_t sz;
	userinfo_t err;

	if (ignorelist_is_ignored(&network_event(info)->remote_addr))
		return (message_cancel(info));

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

	event_fd_update(info, EVENT_WRITE);
	event_callback_set(info, message_write);
	message_write(info, event_payload_get(info));

	pacts_pending(&sz);
	if (notar_should_generate_block())
		block_generate_next();
}

static void
op_pact_client(event_fd_t *info, network_event_t *nev)
{
	message_cancel(info);
}

static void
op_getrxcache(event_fd_t *info)
{
	network_event_t *nev;
	nev = event_payload_get(info);

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		nev->message_header.flags |= htons(MESSAGE_FLAG_REPLY);
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
op_getrxcache_server(event_fd_t *info, network_event_t *nev)
{
	message_t *msg;
	size_t size;
	FILE *f;

	if (!(f = config_fopen("blocks/rxcache.bin", "r")))
		return (message_cancel(info));

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (!(nev->userdata = malloc(size)))
		return (message_cancel(info));
	if (fread(nev->userdata, 1, size, f) != size) {
		fclose(f);
		return (message_cancel(info));
	}
	fclose(f);

	msg = network_message(info);

	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata_size = size;
	msg->payload_size = htobe32(nev->userdata_size);

	event_fd_update(info, EVENT_WRITE);
	event_callback_set(info, message_write);
	message_write(info, event_payload_get(info));
}

static void
op_getrxcache_client(event_fd_t *info, network_event_t *nev)
{
	message_t *msg;

	if (ignorelist_is_ignored(&network_event(info)->remote_addr))
		return (message_cancel(info));

	if (!nev->userdata)
		return (message_done(info));

	msg = network_message(info);

	if (!__userinfo_equals(msg, __getrxcache_userinfo))
		return (message_cancel(info));

	cache_write("rxcache", nev->userdata, be32toh(msg->payload_size));

	message_done(info);
}

static void
op_getnotars(event_fd_t *info)
{
	network_event_t *nev;
	nev = event_payload_get(info);

	switch (nev->type) {
	case NETWORK_EVENT_TYPE_SERVER:
		nev->message_header.flags |= htons(MESSAGE_FLAG_REPLY);
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
op_getnotars_server(event_fd_t *info, network_event_t *nev)
{
	message_t *msg;
	size_t size;
	FILE *f;

	if (!(f = config_fopen("blocks/notarscache.bin", "r")))
		return (message_cancel(info));

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (!(nev->userdata = malloc(size)))
		return (message_cancel(info));
	if (fread(nev->userdata, 1, size, f) != size) {
		fclose(f);
		return (message_cancel(info));
	}
	fclose(f);

	msg = network_message(info);

	nev->state = NETWORK_EVENT_STATE_HEADER;
	nev->read_idx = 0;
	nev->write_idx = 0;
	nev->userdata_size = size;
	msg->payload_size = htobe32(nev->userdata_size);

	event_fd_update(info, EVENT_WRITE);
	event_callback_set(info, message_write);
	message_write(info, event_payload_get(info));
}

static void
op_getnotars_client(event_fd_t *info, network_event_t *nev)
{
	message_t *msg;

	if (!nev->userdata)
		return (message_done(info));

	if (ignorelist_is_ignored(&network_event(info)->remote_addr))
		return (message_cancel(info));

	msg = network_message(info);

	if (!__userinfo_equals(msg, __getnotarscache_userinfo))
		return (message_cancel(info));

	cache_write("notarscache", nev->userdata, be32toh(msg->payload_size));

	message_done(info);
}
