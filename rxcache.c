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
#include "rxcache.h"

static rxcache_t *__rxcache = NULL;
static big_idx_t __rxcache_size = 0;
static big_idx_t __rxcache_last_block_idx = 0;

static int
rxcache_compare(const void *v1, const void *v2)
{
	rxcache_t *t1, *t2;
	big_idx_t idx1, idx2;
	small_idx_t tidx1, tidx2;
  
	t1 = (rxcache_t *)v1;
	t2 = (rxcache_t *)v2;
	idx1 = be64toh(t1->block_idx);
	idx2 = be64toh(t2->block_idx);
	tidx1 = be32toh(t1->block_rx_idx);
	tidx2 = be32toh(t2->block_rx_idx);
 
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
rxcache_last_block_idx()
{
	return (__rxcache_last_block_idx);
}

rxcache_t *
rxcache(big_idx_t *size)
{
	*size = __rxcache_size;
	return (__rxcache);
}

void
rxcache_hash(hash_t result_hash)
{
	crypto_generichash_state crx;
	big_idx_t idx;
	big_idx_t size;

	idx = htobe64(block_idx_last());
	size = htobe64(__rxcache_size);

	crypto_generichash_init(&crx, NULL, 0, sizeof(hash_t));
	crypto_generichash_update(&crx, (void *)&idx, sizeof(big_idx_t));
	crypto_generichash_update(&crx, (void *)&size, sizeof(big_idx_t));
	crypto_generichash_update(&crx, (void *)__rxcache,
				  sizeof(rxcache_t) * __rxcache_size);
	crypto_generichash_final(&crx, result_hash, sizeof(hash_t));
}

static void
rxcache_add(big_idx_t block_idx, small_idx_t block_rx_idx, pact_rx_t *rx)
{
	rxcache_t *item;

	for (big_idx_t i = 0; i < __rxcache_size; i++) {
		item = &__rxcache[i];
		if (!item->rx.amount) {
			item->block_idx = block_idx;
			item->block_rx_idx = block_rx_idx;
			bcopy(rx, &item->rx, sizeof(pact_rx_t));

			return;
		}
	}

	__rxcache = realloc(__rxcache, sizeof(rxcache_t) * (__rxcache_size + 100));
#ifdef DEBUG_ALLOC
	lprintf("*RXCACHE %p", __rxcache);
#endif
	bzero(__rxcache + sizeof(rxcache_t) * __rxcache_size, sizeof(rxcache_t) * 100);
	__rxcache_size += 100;
}

rxcache_t **
rxcaches_for_address(address_t *address, size_t *amount)
{
	rxcache_t **res = NULL;
	size_t count = 0;
	public_key_t *pk;
	rxcache_t item;

	pk = (void *)address_public_key(address);
	for (big_idx_t i = 0; i < __rxcache_size; i++) {
		item = __rxcache[i];
		if (pubkey_compare(item.rx.address, pk) == 0 &&
			 item.rx.amount) {
			if (!res) {
				res = malloc(sizeof(rxcache_t *) * 10);
#ifdef DEBUG_ALLOC
				lprintf("+RXCACHESFORADDRESS %p", res);
#endif
			}

			res[count] = __rxcache + i;
			count++;
			if (count % 10 == 0) {
				res = realloc(res, sizeof(rxcache_t *) *
					count + 10);
#ifdef DEBUG_ALLOC
				lprintf("*RXCACHESFORADDRESS %p", res);
#endif
			}
		}
	}

	*amount = count;

	return (res);
}

rxcache_t *
rxcache_for_idxs(big_idx_t block_idx, small_idx_t block_rx_idx)
{
	rxcache_t item;

	for (big_idx_t i = 0; i < __rxcache_size; i++) {
		item = __rxcache[i];
		if (block_idx == item.block_idx &&
		    block_rx_idx == item.block_rx_idx && item.rx.amount)
			return (__rxcache + i);
	}

	return (NULL);
}

int
rxcache_exists(big_idx_t block_idx, small_idx_t block_rx_idx)
{
	return (rxcache_for_idxs(block_idx, block_rx_idx) != NULL);
}

void
rxcache_remove(big_idx_t block_idx, small_idx_t block_rx_idx)
{
	rxcache_t item;

	for (big_idx_t i = 0; i < __rxcache_size; i++) {
		item = __rxcache[i];
		if (block_idx == item.block_idx &&
		    block_rx_idx == item.block_rx_idx &&
		    item.rx.amount) {
			bzero(&__rxcache[i], sizeof(rxcache_t));

			return;
		}
	}

	//FAIL(EX_SOFTWARE, "rxcache_remove: block_idx %ju, block_rx_idx %u doesn't exist in cache!", block_idx, block_rx_idx);
	lprintf("rxcache_remove: block_idx %ju, block_rx_idx %u doesn't exist in cache!", be64toh(block_idx), be16toh(block_rx_idx));
}

void
rxcache_save(big_idx_t block_idx)
{
	big_idx_t size;
	size_t wsize;
	FILE *f;

	__rxcache_last_block_idx = be64toh(block_idx);
	lprintf("saving rxcache @ block %ju...", __rxcache_last_block_idx);

	if (!(f = config_fopen("blocks/rxcache.bin", "w+")))
		FAILTEMP("rxcache_save: %s", strerror(errno));

	if (fwrite(&block_idx, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("rxcache_save: failed writing index: %s",
			 strerror(errno));
	size = htobe64(__rxcache_size);
	if (fwrite(&size, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("rxcache_save: failed writing size: %s",
			 strerror(errno));

	wsize = __rxcache_size * sizeof(rxcache_t);
	if (fwrite(__rxcache, 1, wsize, f) != wsize)
		FAILTEMP("rxcache_save: failed writing cache: %s",
			 strerror(errno));

	fclose(f);
}

void
rxcache_raw_block_add(raw_block_t *raw_block)
{
	pact_tx_t *tx;
	pact_rx_t *rx;
	big_idx_t idx;
	raw_pact_t *t;
	small_idx_t nt, ntx, nrx, rxidx;

	idx = block_idx(raw_block);

	rxidx = 0;
	nt = num_pacts(raw_block);
	t = raw_block_pacts(raw_block);
	
	for (small_idx_t it = 0; it < nt; it++) {
		ntx = pact_num_tx(t);
		nrx = pact_num_rx(t);
		tx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t ri = 0; ri < ntx; ri++) {
			rxcache_remove(tx->block_idx, tx->block_rx_idx);
			tx = (void *)tx + sizeof(pact_tx_t);
		}
		rx = pact_rx_ptr(t);
		for (small_idx_t ti = 0; ti < nrx; ti++) {
			rxcache_add(htobe64(idx), htobe32(rxidx), rx);
			rx = (void *)rx + sizeof(pact_rx_t);
			rxidx++;
		}
		t = (void *)rx;
	}

	qsort(__rxcache, __rxcache_size, sizeof(rxcache_t), rxcache_compare);

	if ((block_idx(raw_block) % CACHE_HASH_BLOCK_INTERVAL) == 0)
		rxcache_save(raw_block->index);
}

static void
rxcache_create(void)
{
	FILE *f;
	size_t sz;
	raw_block_t *b;

	lprintf("scanning blocks for unspent rx entries...");

	if (!(f = config_fopen("blocks/rxcache.bin", "w+")))
		FAILTEMP("rxcache_create: %s", strerror(errno));
	fclose(f);

	for (big_idx_t idx = 0; (b = block_load(idx, &sz)); idx++)
		rxcache_raw_block_add(b);
}

static void
rxcache_read(FILE *f)
{
	size_t rsize;

	if (fread(&__rxcache_last_block_idx, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("rxcache_read: failed reading index: %s",
			 strerror(errno));
	__rxcache_last_block_idx = be64toh(__rxcache_last_block_idx);
	if (fread(&rsize, 1, sizeof(big_idx_t), f) != sizeof(big_idx_t))
		FAILTEMP("rxcache_read: failed reading size: %s",
			 strerror(errno));
	__rxcache_size = be64toh(rsize);
	rsize = __rxcache_size * sizeof(rxcache_t);

	__rxcache = malloc(rsize);
#ifdef DEBUG_ALLOC
	lprintf("+RXCACHE %p READ", __rxcache);
#endif
	if (fread(__rxcache, 1, rsize, f) != rsize)
		FAILTEMP("rxcache_read: failed reading cache: %s",
			 strerror(errno));
}

static void
rxcache_blocks_update(void)
{
	raw_block_t *b;
	size_t sz;

	if (block_idx_last() > __rxcache_last_block_idx) {
		for (big_idx_t block_idx = __rxcache_last_block_idx + 1;
			(b = block_load(block_idx, &sz)); block_idx++)
			rxcache_raw_block_add(b);
	}

	lprintf("read rxcache @ block idx %ju, updated to idx %ju",
		__rxcache_last_block_idx, block_idx_last());
}

static void
rxcache_alloc(void)
{
	if (__rxcache)
		return;

	__rxcache = calloc(1, sizeof(rxcache_t) * 100);
#ifdef DEBUG_ALLOC
	lprintf("+RXCACHE %p ALLOC", __rxcache);
#endif
	__rxcache_size = 100;
}

void
rxcache_load(void)
{
	FILE *f;

	rxcache_alloc();

	if (!(f = config_fopen("blocks/rxcache.bin", "r"))) {
		rxcache_create();
	} else {
		rxcache_read(f);
		fclose(f);
		rxcache_blocks_update();
	}
}

void
rxcache_reset(void)
{
	char *tmp;

	if (__rxcache)
		free(__rxcache);
	__rxcache = NULL;

	tmp = config_path("blocks/rxcache.bin");
	unlink(tmp);
	rxcache_load();
}

amount_t
unspent_for_public_key(public_key_t address)
{

	rxcache_t item;
	amount_t res = 0;

	for (big_idx_t i = 0; i < __rxcache_size; i++) {
		item = __rxcache[i];

		if (pubkey_compare(item.rx.address, address) == 0)
			res += be64toh(item.rx.amount);
	}

	return (res);
}
