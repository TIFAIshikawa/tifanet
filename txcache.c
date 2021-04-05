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
#include <sys/types.h>
#include <sys/param.h>
#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include "log.h"
#include "block.h"
#include "config.h"
#include "txcache.h"

static txcache_t *__txcache = NULL;
static big_idx_t __txcache_size = 0;
static big_idx_t __txcache_last_block_idx = 0;

static int
txcache_compare(const void *v1, const void *v2)
{
	txcache_t *t1, *t2;
	big_idx_t idx1, idx2;
	small_idx_t tidx1, tidx2;
  
	t1 = (txcache_t *)v1;
	t2 = (txcache_t *)v2;
	idx1 = be64toh(t1->block_idx);
	idx2 = be64toh(t2->block_idx);
	tidx1 = be32toh(t1->block_tx_idx);
	tidx2 = be32toh(t2->block_tx_idx);
 
	if (idx1 < idx2)
		return (1);
	if (idx1 > idx2)
		return (-1);

	if (tidx1 < tidx2)
		return (1);
	if (tidx1 > tidx2)
		return (-1);

	return (0);
}

big_idx_t
txcache_last_block_idx()
{
	return (__txcache_last_block_idx);
}

txcache_t *
txcache(big_idx_t *size)
{
	*size = __txcache_size;
	return (__txcache);
}

void
txcache_hash(hash_t result_hash)
{
	crypto_generichash_state ctx;
	big_idx_t idx;
	big_idx_t size;

	idx = htobe64(block_idx_last());
	size = htobe64(__txcache_size);

	crypto_generichash_init(&ctx, NULL, 0, sizeof(hash_t));
	crypto_generichash_update(&ctx, (void *)&idx, sizeof(big_idx_t));
	crypto_generichash_update(&ctx, (void *)&size, sizeof(big_idx_t));
	crypto_generichash_update(&ctx, (void *)__txcache,
				  sizeof(txcache_t) * __txcache_size);
	crypto_generichash_final(&ctx, result_hash, sizeof(hash_t));
}

static void
txcache_add(big_idx_t block_idx, small_idx_t block_tx_idx, pact_tx_t *tx)
{
	txcache_t *item;

	for (big_idx_t i = 0; i < __txcache_size; i++) {
		item = &__txcache[i];
		if (!item->tx.amount) {
			item->block_idx = block_idx;
			item->block_tx_idx = block_tx_idx;
			bcopy(tx, &item->tx, sizeof(pact_tx_t));

			return;
		}
	}

	__txcache = realloc(__txcache, sizeof(txcache_t) * (__txcache_size + 100));
	bzero(__txcache + sizeof(txcache_t) * __txcache_size, sizeof(txcache_t) * 100);
	__txcache_size += 100;
}

txcache_t **
txcaches_for_address(address_t *address, size_t *amount)
{
	txcache_t **res = NULL;
	size_t count = 0;
	public_key_t *pk;
	txcache_t item;

	pk = (void *)address_public_key(address);
	for (big_idx_t i = 0; i < __txcache_size; i++) {
		item = __txcache[i];
		if (pubkey_compare(item.tx.address, pk) == 0 &&
			 item.tx.amount) {
			if (!res)
				res = malloc(sizeof(txcache_t *) * 10);

			res[count] = __txcache + i;
			count++;
			if (count % 10 == 0)
				res = realloc(res, sizeof(txcache_t *) * count + 10);
		}
	}

	*amount = count;

	return (res);
}

txcache_t *
txcache_for_idxs(big_idx_t block_idx, small_idx_t block_tx_idx)
{
	txcache_t item;

	for (big_idx_t i = 0; i < __txcache_size; i++) {
		item = __txcache[i];
		if (block_idx == item.block_idx &&
		    block_tx_idx == item.block_tx_idx && item.tx.amount)
			return (__txcache + i);
	}

	return (NULL);
}

int
txcache_exists(big_idx_t block_idx, small_idx_t block_tx_idx)
{
	return (txcache_for_idxs(block_idx, block_tx_idx) != NULL);
}

void
txcache_remove(big_idx_t block_idx, small_idx_t block_tx_idx)
{
	txcache_t item;

	for (big_idx_t i = 0; i < __txcache_size; i++) {
		item = __txcache[i];
		if (block_idx == item.block_idx &&
		    block_tx_idx == item.block_tx_idx &&
		    item.tx.amount) {
			bzero(&__txcache[i], sizeof(txcache_t));

			return;
		}
	}

	//FAIL(EX_SOFTWARE, "txcache_remove: block_idx %ju, block_tx_idx %u doesn't exist in cache!", block_idx, block_tx_idx);
	lprintf("txcache_remove: block_idx %ju, block_tx_idx %u doesn't exist in cache!", block_idx, block_tx_idx);
}

static void
txcache_save(big_idx_t block_idx)
{
	char tmp[MAXPATHLEN + 1];
	big_idx_t size;
	size_t wsize;
	FILE *f;

	__txcache_last_block_idx = be64toh(block_idx);
	lprintf("saving txcache @ block %ju...", __txcache_last_block_idx);

	config_path(tmp, "blocks/txcache.bin");
	if (!(f = fopen(tmp, "w+")))
		FAILTEMP("txcache_save: %s", strerror(errno));

	if (fwrite(&block_idx, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("txcache_save: failed writing index: %s",
			 strerror(errno));
	size = htobe64(__txcache_size);
	if (fwrite(&size, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("txcache_save: failed writing size: %s",
			 strerror(errno));

	wsize = __txcache_size * sizeof(txcache_t);
	if (fwrite(__txcache, 1, wsize, f) != wsize)
		FAILTEMP("txcache_save: failed writing cache: %s",
			 strerror(errno));

	fclose(f);
}

void
txcache_raw_block_add(raw_block_t *raw_block)
{
	pact_rx_t *rx;
	pact_tx_t *tx;
	big_idx_t idx;
	raw_pact_t *t;
	small_idx_t nt, nrx, ntx, txidx;

	idx = block_idx(raw_block);

	txidx = 0;
	nt = num_pacts(raw_block);
	t = raw_block_pacts(raw_block);
	
	for (small_idx_t it = 0; it < nt; it++) {
		nrx = pact_num_rx(t);
		ntx = pact_num_tx(t);
		rx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t ri = 0; ri < nrx; ri++) {
			txcache_remove(rx->block_idx, rx->block_tx_idx);
			rx = (void *)rx + sizeof(pact_rx_t);
		}
		tx = pact_tx_ptr(t);
		for (small_idx_t ti = 0; ti < ntx; ti++) {
			txcache_add(htobe64(idx), htobe32(txidx), tx);
			tx = (void *)tx + sizeof(pact_tx_t);
			txidx++;
		}
		t = (void *)tx;
	}

	qsort(__txcache, __txcache_size, sizeof(txcache_t), txcache_compare);

	if ((block_idx(raw_block) % CACHE_HASH_BLOCK_INTERVAL) == 0)
		txcache_save(raw_block->index);
}

static void
txcache_create()
{
	FILE *f;
	size_t sz;
	raw_block_t *b;
	char tmp[MAXPATHLEN + 1];

	lprintf("scanning blocks for unspent tx entries...");

	if (!(f = fopen(config_path(tmp, "blocks/txcache.bin"), "w+")))
		FAILTEMP("txcache_create: %s", strerror(errno));

	for (big_idx_t idx = 0; (b = block_load(idx, &sz)); idx++)
		txcache_raw_block_add(b);
}

static void
txcache_read(FILE *f)
{
	size_t rsize, sz;
	raw_block_t *b;

	if (fread(&__txcache_last_block_idx, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("txcache_read: failed reading index: %s",
			 strerror(errno));
	__txcache_last_block_idx = be64toh(__txcache_last_block_idx);
	if (fread(&rsize, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("txcache_read: failed reading size: %s",
			 strerror(errno));
	__txcache_size = be64toh(rsize);
	rsize = __txcache_size * sizeof(txcache_t);

	__txcache = malloc(rsize);
	if (fread(__txcache, 1, rsize, f) != rsize)
		FAILTEMP("txcache_read: failed reading cache: %s",
			 strerror(errno));

	if (block_idx_last() > __txcache_last_block_idx) {
		for (big_idx_t block_idx = __txcache_last_block_idx + 1;
			(b = block_load(block_idx, &sz)); block_idx++)
			txcache_raw_block_add(b);
	}

	lprintf("read txcache @ block idx %ju, updated to idx %ju",
		__txcache_last_block_idx, block_idx_last());
}

static void
txcache_alloc()
{
	if (__txcache)
		return;

	__txcache = calloc(1, sizeof(txcache_t) * 100);
	__txcache_size = 100;
}

void
txcache_load()
{
	FILE *f;
	char tmp[MAXPATHLEN + 1];

	txcache_alloc();

	config_path(tmp, "blocks/txcache.bin");
	if (!(f = fopen(tmp, "r"))) {
		txcache_create();
	} else {
		txcache_read(f);
		fclose(f);
	}
}

void
txcache_reset()
{
	char tmp[MAXPATHLEN + 1];

	if (__txcache)
		free(__txcache);
	__txcache = NULL;

	config_path(tmp, "blocks/txcache.bin");
	unlink(tmp);
	txcache_load();
}

amount_t
unspent_for_public_key(public_key_t address)
{

	txcache_t item;
	amount_t res = 0;

	for (big_idx_t i = 0; i < __txcache_size; i++) {
		item = __txcache[i];

		if (pubkey_compare(item.tx.address, address) == 0)
			res += be64toh(item.tx.amount);
	}

	return (res);
}
