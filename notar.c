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
#include "log.h"
#include "notar.h"
#include "block.h"
#include "event.h"
#include "endian.h"
#include "config.h"

#include <time.h>
#include <sys/time.h>

#define BLOCK_EMPTY_DELAY_USECONDS 2000
#define PENDING_NOTARS_MAX 100

static public_key_t *__notars = NULL;
static big_idx_t __notars_size = 0;
static big_idx_t __notars_count = 0;
static big_idx_t __next_notar_idx = 0;
static int __is_notar = FALSE;
static big_idx_t __notars_last_block_idx = 0;

static public_key_t *__pending_notars = NULL;

static event_timer_t *__notar_announce_timer = NULL;

static void notar_pending_remove(public_key_t new_notar);
static big_idx_t notar_elect_raw_block(raw_block_t *raw_block, size_t size);
static void *notar_block0(void);

big_idx_t
notars_last_block_idx(void)
{
	return (__notars_last_block_idx);
}

uint8_t *
notar_prev(void)
{
	return (raw_block_last(NULL)->notar);
}

uint8_t *
notar_next(void)
{
	return ((uint8_t *)&__notars[__next_notar_idx]);
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

int
notar_should_generate_block(void)
{
	small_idx_t sz;
	time64_t now, last, diff;

	now = time(NULL);
	last = block_time(raw_block_last(NULL));
	if (last >= now)
		diff = 0;
	else
		diff = now - last;
	pacts_pending(&sz);

	return (config_is_notar_node() && __is_notar &&
		!blockchain_is_updating() &&
		pubkey_equals(__notars[__next_notar_idx], node_public_key()) &&
		(sz >= 2 || diff >= 2));
}

static void
__notar_announce_tick(void *info, void *payload)
{
	__notar_announce_timer = NULL;

	notar_announce();
}

void
notar_announce(void)
{
	uint64_t delay;

	if (__notar_announce_timer)
		return;

	if (!node_is_notar() && config_is_notar_node())
		message_broadcast(OP_NOTARANNOUNCE, node_public_key(),
			sizeof(hash_t), 0);

	delay = randombytes_random() % HOUR_USECONDS;

	__notar_announce_timer = event_timer_add(delay, FALSE,
		__notar_announce_tick, NULL);
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
	big_idx_t ia = 0;
	size_t sz;
	int cr;

	if (pubkey_equals(node_public_key(), new_notar))
		__is_notar = TRUE;

	for (big_idx_t i = 0; i < __notars_count; i++) {
		cr = pubkey_compare(__notars[i], new_notar);
		if (cr < 0)
			ia = i;
		else if (cr == 0) {
			lprintf("notar_add: attempted to add existing notar %s",
				public_key_node_name(new_notar));
			return;
		}
	}

	notar_pending_remove(new_notar);

#ifdef DEBUG_NOTAR
	lprintf("notar_add: adding %s", public_key_node_name(new_notar));
#endif
	if (__notars_size == __notars_count) {
		__notars = realloc(__notars, sizeof(public_key_t) *
				(__notars_size + 100));
		bzero(__notars + __notars_size, sizeof(public_key_t) * 100);
		__notars_size += 100;
	}

	sz = sizeof(public_key_t);
	bcopy(__notars + ia, __notars + ia + 1, sz * __notars_count - ia);

	bcopy(new_notar, __notars + ia, sz);
	__notars_count++;
}

static void
notar_remove(public_key_t remove_notar)
{
	big_idx_t i;

	for (i = 0; i < __notars_count; i++)
		if (pubkey_equals(__notars[i], remove_notar))
			break;

	if (i == __notars_count)
		return;

	if (pubkey_equals(node_public_key(), remove_notar))
		__is_notar = FALSE;

#ifdef DEBUG_NOTAR
	lprintf("notar_remove: removing %s",
		public_key_node_name(remove_notar));
#endif
	__notars_count--;
	for (; i < __notars_count; i++)
		bcopy(__notars[i + 1], __notars[i], sizeof(public_key_t));
	bzero(__notars[i], sizeof(public_key_t));
}

static big_idx_t
notar_elect_raw_block(raw_block_t *raw_block, size_t size)
{
	big_idx_t idx;
	hash_t hash;

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
	raw_block_t *raw_block;
	size_t size;

	raw_block = raw_block_last(&size);

	__next_notar_idx = notar_elect_raw_block(raw_block, size);

	lprintf("notar(%ju) = %s (%d)", block_idx_last() + 1,
		public_key_node_name(__notars[__next_notar_idx]),
		__next_notar_idx);

#ifdef DEBUG_NOTAR
	for (big_idx_t i = 0; i < __notars_count; i++)
		lprintf("%ld: %s", i, public_key_node_name(__notars[i]));
	lprintf("-----");
#endif

	if (notar_should_generate_block() && has_pending_pacts() &&
		!blockchain_is_updating())
		block_generate_next();
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
		notar_add(raw_block_new_notar(raw_block));

	if (block_is_syncblock(raw_block))
		notarscache_save(raw_block->index);
}

void
notar_raw_block_rewind(raw_block_t *raw_block)
{
	raw_block_timeout_t *rb;

	rb = (raw_block_timeout_t *)raw_block;
	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT)
		return notar_add(rb->denounced_notar);
	if (block_flags(raw_block) & BLOCK_FLAG_NEW_NOTAR)
		notar_remove((void *)raw_block + sizeof(raw_block_t));
	
	if (block_is_syncblock(raw_block))
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
	if (pubkey_is_zero(new_notar))
		return;
	if (notar_pending_exists(new_notar))
		return;

	for (size_t i = 0; i < PENDING_NOTARS_MAX; i++) {
		if (pubkey_is_zero(__pending_notars[i])) {
			bcopy(new_notar, __pending_notars[i],
				sizeof(public_key_t));
			lprintf("adding pending notar: %s",
				public_key_node_name(new_notar));

			return;
		}
	}
}

static void
notar_pending_remove(public_key_t remove_notar)
{
	if (pubkey_is_zero(remove_notar))
		return;

	for (size_t i = 0; i < PENDING_NOTARS_MAX; i++) {
		if (pubkey_equals(__pending_notars[i], remove_notar)) {
			bzero(__pending_notars[i], sizeof(public_key_t));
			for (size_t n = i + 1; n < PENDING_NOTARS_MAX; n++)
				bcopy(__pending_notars[n],
					__pending_notars[n - 1],
					sizeof(public_key_t));
			bzero(__pending_notars[PENDING_NOTARS_MAX - 1],
				sizeof(public_key_t));
		}
	}
}

uint8_t *
notar_pending_next(void)
{
	size_t count;

	for (count = 0; !pubkey_is_zero(__pending_notars[count]); count++) { }
	if (!count)
		return (NULL);

	return (__pending_notars[randombytes_random() % count]);
}

void
notarscache_hash(hash_t result_hash, big_idx_t block_idx)
{
	crypto_generichash_state crx;
        big_idx_t idx;
        big_idx_t size;

        idx = htobe64(block_idx);
        size = htobe64(__notars_count);

        crypto_generichash_init(&crx, NULL, 0, sizeof(hash_t));
        crypto_generichash_update(&crx, (void *)&idx, sizeof(big_idx_t));
        crypto_generichash_update(&crx, (void *)&size, sizeof(big_idx_t));
        crypto_generichash_update(&crx, (void *)__notars,
                                  sizeof(public_key_t) * __notars_count);
        crypto_generichash_final(&crx, result_hash, sizeof(hash_t));
}

int
notarscache_exists(void)
{
	return (access(config_path("blocks/notarscache.bin"), R_OK) == 0);
}
