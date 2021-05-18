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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>
#include <sysexits.h>
#include <sys/param.h>
#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include "log.h"
#include "notar.h"
#include "block.h"
#include "event.h"
#include "config.h"

#include <time.h>
#include <sys/time.h>

#define PENDING_NOTARS_MAX 100

static public_key_t *__notars = NULL;
static big_idx_t __notars_size = 0;
static big_idx_t __notars_count = 0;
static big_idx_t __next_notar_idx = 0;
static int __is_notar = FALSE;
static big_idx_t __notars_last_block_idx = 0;

static public_key_t *__pending_notars = NULL;
static small_idx_t __pending_notars_base = 0;
static small_idx_t __pending_notars_size = 0;
static small_idx_t __pending_notars_count = 0;

static event_info_t *__notar_timer = NULL;
static event_info_t *__notar_announce_timer = NULL;

static void notar_tick(event_info_t *info, event_flags_t eventtype);
static void schedule_generate_block_retry(void);
static void notar_pending_remove(public_key_t new_notar);
static big_idx_t notar_elect_raw_block(big_idx_t raw_block_idx);
static void *notar_block0(void);

big_idx_t
notars_last_block_idx(void)
{
	return (__notars_last_block_idx);
}

public_key_t *
notar_next(void)
{
	return (&__notars[__next_notar_idx]);
}

public_key_t *
notars(big_idx_t *num_notars)
{
	*num_notars = __notars_count;
	return (__notars);
}

int
node_is_notar(void)
{
	return (__is_notar);
}

static int
should_generate_block(void)
{
	return (pubkey_equals(__notars[__next_notar_idx], node_public_key()));
}

static void
__notar_announce_tick(event_info_t *info, event_flags_t eventtype)
{
	__notar_announce_timer = NULL;

	notar_start();
}

static void
notar_announce(void)
{
	uint64_t delay;

	if (__notar_announce_timer)
		return;

	message_broadcast(OP_NOTARANNOUNCE, node_public_key(), sizeof(hash_t),
		0);

	delay = randombytes_random() % 3600000;

	__notar_announce_timer = timer_set(delay, __notar_announce_tick, NULL);
}

void
notar_start(void)
{
	if (!node_is_notar() && config_is_notar_node())
		notar_announce();
}

int
notar_exists(public_key_t notar)
{
	for (big_idx_t i = 0; i < __notars_size; i++) {
		if (pubkey_equals(__notars[i], notar))
			return (TRUE);
	}

	return (FALSE);
}

static void
notar_add(public_key_t new_notar)
{
	node_name_t node_name;
	big_idx_t ia = 0;
	int cr;

	if (pubkey_equals(node_public_key(), new_notar))
		__is_notar = TRUE;

	for (big_idx_t i = 0; i < __notars_count; i++) {
		cr = pubkey_compare(__notars[i], new_notar);
		if (cr < 0)
			ia = i;
		else if (cr == 0) {
			lprintf("notar_add: attempted to add existing notar %s",
				public_key_node_name(new_notar, node_name));
			return;
		}
	}

	notar_pending_remove(new_notar);

#ifdef DEBUG_NOTAR
	public_key_node_name(new_notar, node_name);
	lprintf("notar_add: adding %s", node_name);
#endif
	if (__notars_size == __notars_count) {
		__notars = realloc(__notars, sizeof(public_key_t) *
				(__notars_size + 100));
		bzero(__notars + __notars_size, sizeof(public_key_t) * 100);
		__notars_size += 100;
	}

	for (big_idx_t i = ia; i <= __notars_count; i++)
		bcopy(__notars[i], __notars[i + 1], sizeof(public_key_t));
	bcopy(new_notar, __notars[ia], sizeof(public_key_t));
	__notars_count++;
}

static void
notar_remove(public_key_t remove_notar)
{
#ifdef DEBUG_NOTAR
	node_name_t node_name;
#endif
	big_idx_t i;

	for (i = 0; i < __notars_count; i++)
		if (pubkey_equals(__notars[i], remove_notar))
			break;

	if (i == __notars_count)
		return;

	if (pubkey_equals(node_public_key(), remove_notar))
		__is_notar = FALSE;

#ifdef DEBUG_NOTAR
	public_key_node_name(remove_notar, node_name);
	lprintf("notar_remove: removing %s", node_name);
#endif
	__notars_count--;
	for (; i < __notars_count; i++)
		bcopy(__notars[i + 1], __notars[i], sizeof(public_key_t));
	bzero(__notars[i], sizeof(public_key_t));
}

static void
notar_tick(event_info_t *info, event_flags_t eventtype)
{
	__notar_timer = NULL;

	block_generate_next();
}

static void
schedule_generate_block_retry(void)
{
	if (__notar_timer)
		return;

//	lprintf("should create block but no pacts, delaying");

	__notar_timer = timer_set(3000, notar_tick, NULL);
//	__notar_timer = timer_set(100, notar_tick, NULL);
}

static big_idx_t
notar_elect_raw_block(big_idx_t raw_block_idx)
{
	raw_block_t *raw_block;
	big_idx_t idx;
	hash_t hash;
	size_t size;

	if (!(raw_block = block_load(raw_block_idx, &size)))
		FAIL(EX_SOFTWARE, "notar_elect_raw_block: invalid block index "
			"%ju", raw_block_idx);
	
	bzero(hash, sizeof(hash_t));
	crypto_generichash(hash, sizeof(hash_t), (void *)raw_block, size,
			   NULL, 0);

	bcopy(hash, &idx, sizeof(big_idx_t));

	idx = idx % __notars_count;

	return (idx);
}

void
notar_elect_next(void)
{
	node_name_t name;

	__next_notar_idx = notar_elect_raw_block(block_idx_last());

	lprintf("block(%ju) = %s (%d)", block_idx_last() + 1,
		public_key_node_name(__notars[__next_notar_idx], name),
		__next_notar_idx);

#ifdef DEBUG_NOTAR
	for (big_idx_t i = 0; i < __notars_count; i++)
		lprintf("%ld: %s", i, public_key_node_name(__notars[i], name));
	lprintf("-----");
#endif

	if (should_generate_block() && !blockchain_is_updating()) {
		if (!has_pending_pacts())
			schedule_generate_block_retry();
		else
			block_generate_next();
	}
}

static void *
notar_block0(void)
{
	raw_block_t *rb;
	size_t sz;

	rb = block_load(0, &sz);

	return (rb->notar);
}

void *
notar_denounce_emergency_node(void)
{
	return (notar_block0());
}

void *
notar_denounce_node(uint8_t node_idx)
{
	void *denounce_node;
	big_idx_t idx;
	int8_t found;
	void *res;

	if (node_idx >= 2)
		FAIL(EX_SOFTWARE, "notar_denounce_node: illegal index %hhd",
			node_idx);

	if ((idx = block_idx_last()) < 2)
		return (notar_denounce_emergency_node());

	denounce_node = notar_next();

	for (idx -= 1, found = -1; idx > 0; idx--) {
		res = __notars[notar_elect_raw_block(idx)];
		if (!pubkey_equals(res, denounce_node))
			found++;

		if (found == node_idx)
			return (res);
	}

	return (notar_denounce_emergency_node());
}

void
notarscache_save(big_idx_t block_idx)
{
	big_idx_t size;
	size_t wsize;
	FILE *f;

	__notars_last_block_idx = be64toh(block_idx);
	lprintf("saving notars @ block %ju...", __notars_last_block_idx);

	if (!(f = config_fopen("blocks/notarscache.bin", "w+")))
		FAILTEMP("notarscache_save: %s", strerror(errno));

	if (fwrite(&block_idx, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("notarscache_save: failed writing index: %s",
			 strerror(errno));
	size = htobe64(__notars_count);
	if (fwrite(&size, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("notarscache_save: failed writing size: %s",
			 strerror(errno));

	wsize = __notars_count * sizeof(public_key_t);
	if (fwrite(__notars, 1, wsize, f) != wsize)
		FAILTEMP("notarscache_save: failed writing list: %s",
			 strerror(errno));

	fclose(f);
}

void
notar_raw_block_add(raw_block_t *raw_block)
{
	raw_block_timeout_t *rb;

	rb = (raw_block_timeout_t *)raw_block;
	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT)
		return notar_remove(rb->denounced_notar);

	if (block_flags(raw_block) & BLOCK_FLAG_NEW_NOTAR)
		notar_add((void *)raw_block + sizeof(raw_block_t));

	if (block_idx(raw_block) % CACHE_HASH_BLOCK_INTERVAL == 0)
		notarscache_save(raw_block->index);
}

static void
notarscache_create(void)
{
	size_t sz;
	raw_block_t *b;

	__notars = calloc(1, sizeof(public_key_t) * 100);
	__notars_size = 100;

	for (big_idx_t idx = 0; (b = block_load(idx, &sz)); idx++)
		notar_raw_block_add(b);
}

static void
notarscache_read(FILE *f)
{
	size_t rsize, sz;
	raw_block_t *b;

	if (fread(&__notars_last_block_idx, 1,
		sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("read_notarscache: failed reading index: %s",
			 strerror(errno));
	__notars_last_block_idx = be64toh(__notars_last_block_idx);
	if (fread(&rsize, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("read_notarscache: failed reading size: %s",
			 strerror(errno));
	__notars_count = be64toh(rsize);
	rsize = __notars_count * sizeof(public_key_t);
	__notars_size = ((__notars_count + 99) / 100) * 100;
	sz = __notars_size * sizeof(public_key_t);

	__notars = calloc(1, sz);
	if (fread(__notars, 1, rsize, f) != rsize)
		FAILTEMP("read_rxcache: failed reading cache: %s",
			 strerror(errno));

	if (block_idx_last() > __notars_last_block_idx) {
		for (big_idx_t block_idx = __notars_last_block_idx + 1;
			(b = block_load(block_idx, &sz)); block_idx++)
			notar_raw_block_add(b);
	}

	for (big_idx_t i = 0; i < __notars_count; i++) {
		if (pubkey_equals(__notars[i], node_public_key())) {
			__is_notar = TRUE;
			break;
		}
	}

	lprintf("read notarscache @ block idx %ju, updated to idx %ju",
		__notars_last_block_idx, block_idx_last());
}

void
notarscache_load(void)
{
	FILE *f;

	if (__notars)
		return;

	__pending_notars = calloc(1, sizeof(public_key_t) * PENDING_NOTARS_MAX);
	__pending_notars_size = PENDING_NOTARS_MAX;

	if (!(f = config_fopen("blocks/notarscache.bin", "r"))) {
		notarscache_create();
	} else {
		notarscache_read(f);
		fclose(f);
	}
}

static int
notar_pending_exists(public_key_t notar)
{
	for (size_t i = 0; i < PENDING_NOTARS_MAX; i++)
		if (pubkey_equals(__pending_notars[i], notar))
			return (TRUE);

	return (FALSE);
}

void
notar_pending_add(public_key_t new_notar)
{
	node_name_t notarname;
	small_idx_t idx;

	if (__pending_notars_count >= PENDING_NOTARS_MAX)
		return;

	if (notar_pending_exists(new_notar))
		return;

	idx = __pending_notars_base + __pending_notars_count;
	if (idx >= PENDING_NOTARS_MAX)
		idx -= PENDING_NOTARS_MAX;

	bcopy(new_notar, __pending_notars[idx], sizeof(public_key_t));
	__pending_notars_count++;

	public_key_node_name(new_notar, notarname);
	lprintf("adding pending notar: %s", notarname);
}

static void
notar_pending_remove(public_key_t remove_notar)
{
	void *n;

	n = __pending_notars + __pending_notars_base;
	if (pubkey_equals(remove_notar, n)) {
		notar_pending_next();
		return;
	}

	for (size_t i = 0; i < PENDING_NOTARS_MAX; i++)
		if (pubkey_equals(__pending_notars[i], remove_notar))
			bzero(__pending_notars[i], sizeof(public_key_t));
}

uint8_t *
notar_pending_next(void)
{
	void *res;

	if (__pending_notars_count == 0)
		return (NULL);

	for (; __pending_notars_count;) {
		res = __pending_notars + __pending_notars_base;
		__pending_notars_count--;
		__pending_notars_base++;
		if (__pending_notars_base == __pending_notars_size)
			__pending_notars_base = 0;

		if (!pubkey_equals(res, (void *)pubkey_zero))
			return (res);
	}

	return (NULL);
}

void
notarscache_hash(hash_t result_hash)
{
	crypto_generichash_state crx;
        big_idx_t idx;
        big_idx_t size;

        idx = htobe64(block_idx_last());
        size = htobe64(__notars_count);

        crypto_generichash_init(&crx, NULL, 0, sizeof(hash_t));
        crypto_generichash_update(&crx, (void *)&idx, sizeof(big_idx_t));
        crypto_generichash_update(&crx, (void *)&size, sizeof(big_idx_t));
        crypto_generichash_update(&crx, (void *)__notars,
                                  sizeof(public_key_t) * __notars_count);
        crypto_generichash_final(&crx, result_hash, sizeof(hash_t));
}
