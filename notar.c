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

static const public_key_t empty_notar = { 0 };
static public_key_t *__notars = NULL;
static big_idx_t __notars_size = 0;
static big_idx_t __notars_count = 0;
static big_idx_t __next_notar_idx = 0;
static time64_t __last_block_time = 0;
static int __is_notar = FALSE;
static big_idx_t __notars_last_block_idx = 0;

static public_key_t *__pending_notars = NULL;
static small_idx_t __pending_notars_base = 0;
static small_idx_t __pending_notars_size = 0;
static small_idx_t __pending_notars_count = 0;

static void notar_tick(event_info_t *info, event_flags_t eventtype);
static void schedule_generate_block_retry(void);

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

static int
notars_compare(const void *v1, const void *v2)
{
	public_key_t *p1, *p2;

	p1 = (public_key_t *)v1;
	p2 = (public_key_t *)v2;

	return -(pubkey_compare(p1, p2));
}

public_key_t *
notars(big_idx_t *num_notars)
{
	*num_notars = __notars_count;
	return (__notars);
}

static int
node_is_notar()
{
	return (__is_notar);
}

static int
should_generate_block()
{
	int res;

	res = pubkey_compare(__notars[__next_notar_idx], node_public_key());

	return (res == 0);
}

static void
notar_announce(void)
{
	message_broadcast(OP_NOTAR_ANNOUNCE, node_public_key(), sizeof(hash_t),
		0);
}

void
notar_start(void)
{
	if (!node_is_notar() && is_notar_node())
		notar_announce();
}

static void
notar_add(public_key_t new_notar)
{
	big_idx_t i;
	int64_t first_empty = -1;

	if (pubkey_compare(node_public_key(), new_notar) == 0)
		__is_notar = TRUE;

	for (i = 0; i < __notars_size; i++) {
		if (pubkey_compare(__notars[i], new_notar) == 0)
			return;

		if (pubkey_compare(__notars[i], (void *)empty_notar) == 0 &&
			first_empty == -1)
			first_empty = i;
	}

	if (first_empty != -1) {
		bcopy(new_notar, __notars[first_empty], sizeof(public_key_t));
		__notars_count++;

		qsort(__notars, __notars_size, sizeof(public_key_t),
			notars_compare);

		return;
	}

	__notars = realloc(__notars, sizeof(public_key_t) *
			(__notars_size + 100));
	bzero((void *)__notars + sizeof(public_key_t) *
			__notars_size, sizeof(public_key_t) * 100);
	__notars_size += 100;

	bcopy(new_notar, __notars[i], sizeof(public_key_t));
	__notars_count++;

	qsort(__notars, __notars_size, sizeof(public_key_t), notars_compare);
}

static void
notar_tick(event_info_t *info, event_flags_t eventtype)
{
	block_generate_next();
}

static void
schedule_generate_block_retry(void)
{
//	lprintf("should create block but no pacts, delaying");

	timer_set(4000, notar_tick, NULL);
}

void
notar_elect_next(void)
{
	raw_block_t *raw_block;
	node_name_t name;
	big_idx_t idx;
	size_t size;
	hash_t hash;

	raw_block = raw_block_last(&size);
	bzero(hash, sizeof(hash_t));
	crypto_generichash(hash, sizeof(hash_t), (void *)raw_block, size,
			   NULL, 0);

	bcopy(hash, &idx, sizeof(big_idx_t));

	idx = idx % __notars_count;

	__next_notar_idx = idx;

	lprintf("next notar(%ju)=%s for block %ju", idx,
		public_key_node_name(__notars[__next_notar_idx], name),
		block_idx_last() + 1);

	if (should_generate_block() && !blockchain_is_updating()) {
		if (!has_pending_pacts())
			schedule_generate_block_retry();
		else
			block_generate_next();
	}
}

static void
notars_cache_save(big_idx_t block_idx)
{
	char tmp[MAXPATHLEN + 1];
	big_idx_t size;
	size_t wsize;
	FILE *f;

	__notars_last_block_idx = be64toh(block_idx);
	lprintf("saving notars @ block %ju...", __notars_last_block_idx);

	config_path(tmp, "blocks/notarscache.bin");
	if (!(f = fopen(tmp, "w+")))
		FAILTEMP("notars_cache_save: %s", strerror(errno));

	if (fwrite(&block_idx, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("notars_cache_save: failed writing index: %s",
			 strerror(errno));
	size = htobe64(__notars_count);
	if (fwrite(&size, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("notars_cache_save: failed writing size: %s",
			 strerror(errno));

	wsize = __notars_count * sizeof(public_key_t);
	if (fwrite(__notars, 1, wsize, f) != wsize)
		FAILTEMP("notars_cache_save: failed writing list: %s",
			 strerror(errno));

	fclose(f);
}

void
notar_raw_block_add(raw_block_t *raw_block)
{
	if (be64toh(raw_block->flags) & BLOCK_FLAG_NEW_NOTAR)
		notar_add((void *)raw_block + sizeof(raw_block_t));

	if (block_idx(raw_block) % CACHE_HASH_BLOCK_INTERVAL == 0)
		notars_cache_save(raw_block->index);
 
	__last_block_time = be64toh(raw_block->time);
}

static void
notars_cache_create(void)
{
	size_t sz;
	raw_block_t *b;

	__notars = calloc(1, sizeof(public_key_t) * 100);
	__notars_size = 100;

	for (big_idx_t idx = 0; (b = block_load(idx, &sz)); idx++)
		notar_raw_block_add(b);
}

static void
notars_cache_read(FILE *f)
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
		if (pubkey_compare(__notars[i], node_public_key()) == 0) {
			__is_notar = TRUE;
			break;
		}
	}

	lprintf("read notarscache @ block idx %ju, updated to idx %ju",
		__notars_last_block_idx, block_idx_last());
}

void
notars_cache_load(void)
{
	FILE *f;
	char tmp[MAXPATHLEN + 1];

	if (__notars)
		return;

	__pending_notars = calloc(1, sizeof(public_key_t) * 100);
	__pending_notars_size = 100;

	config_path(tmp, "blocks/notarscache.bin");
	if (!(f = fopen(tmp, "r"))) {
		notars_cache_create();
	} else {
		notars_cache_read(f);
		fclose(f);
	}
}

int
notars_pending(void)
{
	return (__pending_notars_count != 0);
}

void
notar_pending_add(public_key_t new_notar)
{
	node_name_t notarname;
	small_idx_t idx;

	if (__pending_notars_count >= 100)
		return;

	idx = __pending_notars_base + __pending_notars_count;
	if (idx >= 100)
		idx -= 100;

	bcopy(new_notar, __pending_notars[idx], sizeof(public_key_t));
	__pending_notars_count++;

	public_key_node_name(new_notar, notarname);
	lprintf("adding pending notar: %s", notarname);
}

uint8_t *
notar_pending_next(void)
{
	void *res;

	if (__pending_notars_count == 0)
		return (NULL);

	res = __pending_notars + __pending_notars_base;
	__pending_notars_count--;
	__pending_notars_base++;
	if (__pending_notars_base == __pending_notars_size)
		__pending_notars_base = 0;

	return (res);
}

void
notars_cache_hash(hash_t result_hash)
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
