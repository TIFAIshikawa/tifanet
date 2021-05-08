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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include "log.h"
#include "block.h"
#include "error.h"
#include "notar.h"
#include "cache.h"
#include "config.h"
#include "wallet.h"
#include "keypair.h"
#include "network.h"
#include "rxcache.h"
#include "pact.h"

#define BLOCKS_FILESIZE_MAX 268435456

// 3 mmap'ed files
static char *__blocks = NULL;
static big_idx_t *__block_idxs = NULL;
static big_idx_t *__last_block_idx = NULL;

static raw_block_t *__raw_block_last = NULL;
static size_t __raw_block_last_size = 0;

static raw_block_timeout_t *__raw_block_timeout_tmp = NULL;

static big_idx_t __getblocks_target_idx = 0;

static int __blockchain_is_updating = 0;

static event_info_t *__block_poll_timer = NULL;

void raw_block_broadcast(big_idx_t index);
void add_notar_reward(block_t *block, raw_pact_t **rt, size_t nrt);

big_idx_t
block_idx_last()
{
	if (is_caches_only()) {
		if (__raw_block_last)
			return (block_idx(__raw_block_last));
		else
			return (0);
	}

	return (*__last_block_idx);
}

raw_block_t *
raw_block_last(size_t *size)
{
	*size = __raw_block_last_size;

	return (__raw_block_last);
}

static void *
mmap_file(char *filename, off_t truncsize)
{
	int fd;
	void *res;
	char file[MAXPATHLEN + 1];

	if ((fd = open(config_path_r(file, filename), O_CREAT | O_RDWR)) == -1)
		FAILTEMP("open %s: %s\n", file, strerror(errno));
	ftruncate(fd, truncsize);
	if ((res = mmap(0, truncsize, PROT_READ | PROT_WRITE,
#ifdef __linux__
		MAP_SHARED,
#else
		MAP_SHARED | MAP_NOCORE,
#endif
		fd, 0)) == MAP_FAILED)
		FAILTEMP("mmap %s: %s\n", file, strerror(errno));
	close(fd);

#ifdef __linux__
	madvise(res, truncsize, MADV_DONTDUMP);
#endif

	return (res);
}

void
blockchain_load(void)
{
	size_t sz;

	sz = BLOCKS_FILESIZE_MAX;
	__blocks = mmap_file("blocks/blocks0.bin", sz);
	__block_idxs = mmap_file("blocks/blocks0.idx", (sz * 8) / 256);
	__last_block_idx = mmap_file("blocks/lastblock.idx", sizeof(big_idx_t));
}

static void *
raw_block_last_load(size_t *blocksize)
{
	big_idx_t last_offset;

	last_offset = __block_idxs[block_idx_last()];

	*blocksize = raw_block_size((raw_block_t *)(__blocks + last_offset), 0);

	return (__blocks + last_offset);
}

void
block_last_load()
{
	__raw_block_last = raw_block_last_load(&__raw_block_last_size);
}

static block_t *
block_alloc()
{
	block_t *res;

	res = calloc(1, sizeof(block_t));

	res->num_pacts = 1;
	res->pacts = malloc(sizeof(pact_t *) * 10);
	res->pacts[0] = NULL; // pact 0 will be added later

#ifdef DEBUG_ALLOC
	lprintf("+BLOCK %p", res);
#endif

	return (res);
}

static void
raw_block_sign(raw_block_t *raw_block, size_t size, signature_t result)
{
	keypair_t *notar_kp;

	notar_kp = node_keypair();
	keypair_sign_start(notar_kp, raw_block, size);
	keypair_sign_finalize(notar_kp, result);
}

void
raw_block_hash(raw_block_t *block, size_t size, hash_t result)
{
	crypto_generichash(result, sizeof(hash_t),
			   (void *)block, size, NULL, 0);
}

static int
cache_in_pacts(rxcache_t *cache, pact_t **pacts,
	small_idx_t tsize)
{
	pact_t *t;
	pact_tx_t *tx;

	for (small_idx_t i = 0; i < tsize; i++) {
		if (!(t = pacts[i]))
			continue;
		for (small_idx_t ri = 0; ri < t->num_tx; ri++) {
			tx = t->tx[ri];
			if (be64toh(cache->block_idx) == tx->block_idx &&
			    be32toh(cache->block_rx_idx) == tx->block_rx_idx)
				return (TRUE);
		}
	}

	return (FALSE);
}

static int
cache_in_raw_pacts(rxcache_t *cache, raw_pact_t **pacts,
	small_idx_t tsize)
{
	raw_pact_t *t;
	pact_tx_t *tx;

	for (small_idx_t i = 0; i < tsize; i++) {
		t = pacts[i];
		tx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t ri = 0; ri < be32toh(t->num_tx); ri++) {
			if (cache->block_idx == tx->block_idx &&
			    cache->block_rx_idx == tx->block_rx_idx)
				return (TRUE);
			tx = (void *)tx + sizeof(pact_tx_t);
		}
	}

	return (FALSE);
}

amount_t
block_reward(big_idx_t idx)
{
	return (itos(TIFA_NOTAR_REWARD));
}

void
add_notar_reward(block_t *block, raw_pact_t **rt, size_t nrt)
{
	size_t tsize;
	wallet_t *wallet;
	pact_t *t;
	rxcache_t **caches;
	size_t num_addresses;
	address_t **addresses;
	public_key_t *feeaddress;
	amount_t amount;

	amount = block_reward(block->index);

	if (block->pacts[0])
		FAIL(EX_SOFTWARE, "new block %ju: pact 0 already filled",
			block->index);

	if (!(wallet = wallet_load("notar")))
		wallet = wallet_create("notar");
	addresses = wallet_addresses(wallet, &num_addresses);

	feeaddress = (void *)address_public_key(addresses[0]);

	t = pact_create();

	if ((caches = rxcaches_for_address(addresses[0], &tsize))) {
		for (size_t i = 0; i < tsize; i++) {
			if (!cache_in_pacts(caches[i],
			    block->pacts, block->num_pacts) &&
			    !cache_in_raw_pacts(caches[i], rt, nrt)) {
				pact_tx_add(t, caches[i]->block_idx,
					caches[i]->block_rx_idx);
				amount += be64toh(caches[i]->rx.amount);
			}
		}

		free(caches);
#ifdef DEBUG_ALLOC
		lprintf("-RXCACHESFORADDRESS %p", caches);
#endif
	}

	pact_rx_add(t, (void *)feeaddress, amount);
	block->pacts[0] = t;
}

static block_t *
block_create(void)
{
	block_t *res;

	res = block_alloc();

	res->time = time(NULL);

if (__raw_block_last) {
	res->index = block_idx_last() + 1;
	raw_block_hash(__raw_block_last, __raw_block_last_size,
		res->prev_block_hash);
}

	res->flags |= notars_pending() ? BLOCK_FLAG_NEW_NOTAR : 0;
	bcopy(node_public_key(), res->notar, sizeof(public_key_t));
	if (notars_pending())
		bcopy(notar_pending_next(), res->new_notar,
			sizeof(public_key_t));

	return (res);
}

raw_block_t *
block_load(big_idx_t block_index, size_t *size)
{
	raw_block_t *res;
	big_idx_t soffset;
	big_idx_t eoffset;

	*size = 0;

	if (block_index > block_idx_last())
		return (NULL);

	soffset = __block_idxs[block_index];
	if (block_index < block_idx_last())
		eoffset = __block_idxs[block_index + 1];
	else
		eoffset = soffset + __raw_block_last_size;

	res = (raw_block_t *)(__blocks + soffset);
	*size = eoffset - soffset;

	return (res);
}

static void
raw_block_write(raw_block_t *raw_block, size_t blocksize)
{
	size_t bsize;
	char *dst;

	if (is_caches_only()) {
		if (__raw_block_last)
			free(__raw_block_last);
		__raw_block_last = malloc(blocksize);
		__raw_block_last_size = blocksize;
		bcopy(raw_block, __raw_block_last, blocksize);
		return;
	}

	bsize = (char *)__raw_block_last - __blocks + __raw_block_last_size;

	dst = (char *)__raw_block_last + __raw_block_last_size;
	bcopy(raw_block, dst, blocksize);
	__raw_block_last = (raw_block_t *)dst;
	__raw_block_last_size = blocksize;

	*__last_block_idx = block_idx(__raw_block_last);
	__block_idxs[block_idx_last()] = (char *)__raw_block_last - __blocks;

	msync(__blocks, bsize, MS_SYNC);
	msync(__block_idxs, block_idx_last() * sizeof(big_idx_t), MS_SYNC);
	msync(__last_block_idx, sizeof(big_idx_t), MS_SYNC);
}

void
block_generate_next()
{
	size_t size;
	block_t *block;
	raw_block_t *rb;

	block = block_create();

/*
bcopy(block->notar, block->new_notar, sizeof(public_key_t));
block->flags |= BLOCK_FLAG_NEW_NOTAR;
*/
	rb = block_finalize(block, &size);
/*
FILE *f = fopen("block0.bin", "w+");
fwrite(rb, 1, size, f);
fclose(f);
raw_block_print(rb);
exit(1);
*/
	block_free(block);

	lprintf("generated block %ju", block_idx(rb));

	raw_block_process(rb, size);

	raw_block_broadcast(block_idx(rb));

	free(rb);
}

size_t
raw_block_size(raw_block_t *raw_block, size_t limit)
{
	size_t tbs;
	size_t res;
	raw_pact_t *t;

	res = sizeof(raw_block_t);
	if (be64toh(raw_block->flags) & BLOCK_FLAG_NEW_NOTAR)
		res += sizeof(public_key_t);
	t = raw_block_pacts(raw_block);
	for (small_idx_t i = 0; i < num_pacts(raw_block); i++) {
		if (limit && res + sizeof(raw_pact_t) > limit)
			break;
		tbs = pact_size(t);
		res += tbs;
		t = (void *)t + tbs;
	}

	return (res);
}

static int
raw_block_timeout_validate(raw_block_t *raw_block, size_t blocksize)
{
	raw_block_timeout_t *rb;
	time_t ct, bt, lbt;
	size_t size;
	void *crx;

	if (blocksize != sizeof(raw_block_timeout_t))
		return (FALSE);

	rb = (raw_block_timeout_t *)raw_block;

	ct = time(NULL);
	bt = block_time(raw_block);
	lbt = block_time(__raw_block_last);
	if (bt > ct) {
		lprintf("denounce timeout block with index %ju has time in "
			"future: %ld vs %ld", block_idx(raw_block), bt, ct);
		return (FALSE);
	}
	if (lbt + 19 != bt) {
		lprintf("denounce timeout block with index %ju has invalid "
			"time: %ld vs %ld", block_idx(raw_block), bt, lbt + 19);
		return (FALSE);
	}

	if (pubkey_compare((void *)pubkey_zero, rb->notar[0]) == 0 &&
		pubkey_compare((void *)pubkey_zero, rb->notar[1]) == 0) {
		lprintf("denounce timeout block with index %ju has no notars",
			block_idx(raw_block));
		return (FALSE);
	}

	if (pubkey_compare(notar_next(), rb->denounced_notar) != 0) {
		lprintf("illegal denounced notar for denounce timeout block "
			"index %ju", block_idx(raw_block));
		return (FALSE);
	}

	size = offsetof(raw_block_timeout_t, notar);
	for (int i = 0; i < 2; i++) {
		if (pubkey_compare((void *)pubkey_zero, rb->notar[i]) != 0) {
			if (pubkey_compare(rb->notar[i], notar_prev(i)) != 0) {
				lprintf("denounce timeout block with index %ju "
					"has invalid notar %d", i,
					block_idx(raw_block));
				return (FALSE);
			}
			crx = keypair_verify_start(rb, size);
			if (!keypair_verify_finalize(crx, rb->notar[i],
					rb->signature[i])) {
					lprintf("denounce timeout block has "
						"incorrect signature %d, "
						"index %ju", i,
						block_idx(raw_block));
					return (FALSE);
			}
		}
	}

	return (TRUE);
}

int
raw_block_validate(raw_block_t *raw_block, size_t blocksize)
{
	int err;
	void *crx;
	hash_t pbh;
	big_idx_t idx;
	signature_t sig;
	time_t ct, bt, lbt;
	raw_pact_t *t, *tt;
	size_t tbs, size, scount;

	// check block size
	if (blocksize < sizeof(raw_block_t) + sizeof(raw_pact_t) +
		sizeof(pact_rx_t)) {
		lprintf("block with index %ju smaller than block skeleton: %d",
			block_idx(raw_block), blocksize);
		return (FALSE);
	}

	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT)
		return (raw_block_timeout_validate(raw_block, blocksize));

	size = raw_block_size(raw_block, blocksize);
	if (blocksize != size) {
		lprintf("block with index %ju has illegal size: %d vs %d",
			block_idx(raw_block), size, blocksize);
		return (FALSE);
	}

	ct = time(NULL);
	bt = block_time(raw_block);
	lbt = block_time(__raw_block_last);
	if (bt > ct) {
		lprintf("block with index %ju has time in future: %ld vs %ld",
			block_idx(raw_block), bt, ct);
		return (FALSE);
	}
	if (lbt > bt) {
		lprintf("block with index %ju has time earlier than previous "
			"block: %ld vs %ld", block_idx(raw_block), bt, lbt);
		return (FALSE);
	}

	// check block index, if we have a last block (in case of caches only)
	if (!is_caches_only() || (is_caches_only() && __raw_block_last)) {
		if (block_idx(__raw_block_last) == block_idx(raw_block)) {
			lprintf("already have block with index %ju",
				block_idx(raw_block));
			return (FALSE);
		}

		// check block index
		if (block_idx(__raw_block_last) >= block_idx(raw_block)) {
			lprintf("gotten block with index in the past: %ju",
				block_idx(raw_block));
			return (FALSE);
		}
		if (block_idx(raw_block) > block_idx(__raw_block_last) + 1) {
			lprintf("gotten block with index %ju, reject for now",
				block_idx(raw_block));
			blockchain_set_updating(1);
			blockchain_update();
			return (FALSE);
		}

		// check prev block hash
		raw_block_hash(__raw_block_last, __raw_block_last_size, pbh);
		if (hash_compare(pbh, raw_block->prev_block_hash) != 0) {
			lprintf("gotten block with illegal prev_block_hash, "
				"index %ju", block_idx(raw_block));
			return (FALSE);
		}

		// check notar
		if (pubkey_compare(notar_next(), raw_block->notar) != 0) {
			lprintf("illegal notar for block index %ju",
				block_idx(raw_block));
			return (FALSE);
		}
	}

	// check signature
	bcopy(raw_block->signature, sig, sizeof(signature_t));
	bzero(raw_block->signature, sizeof(signature_t));
	crx = keypair_verify_start(raw_block, blocksize);
	if (!keypair_verify_finalize(crx, raw_block->notar, sig)) {
		lprintf("block has incorrect signature, index %ju",
			block_idx(raw_block));
		return (FALSE);
	}
	bcopy(sig, raw_block->signature, sizeof(signature_t));

	// check pacts
	t = raw_block_pacts(raw_block);
	tbs = blocksize - ((void *)t - (void *)raw_block);
	for (small_idx_t ti = 0; ti < num_pacts(raw_block); ti++) {
		size = pact_size(t);
		idx = block_idx(raw_block);
		if (ti == 0)
			err = raw_pact_notar_reward_validate(t,
				block_idx(raw_block));
		else
			err = raw_pact_validate(t);

		if (is_caches_only() && err == ERR_RX_SPENT &&
			rxcache_last_block_idx() == block_idx(raw_block))
			err = 0;
		switch (err) {
		case 0: break;
		case ERR_RX_SPENT:
			lprintf("processing block %ju, pact %u: "
        			"rx unknown or already spent", idx, ti);
			return (FALSE);
		case ERR_BADSIG:
			lprintf("processing block %ju, pact %u: "
        			"bad signature in tx", idx, ti);
			return (FALSE);
		case ERR_BADBALANCE:
			lprintf("processing block %ju, pact %u: "
        			"bad balance", idx, ti);
			return (FALSE);
		default:
			lprintf("processing block %ju, pact %u: "
        			"unknown error occurred: %d", idx, ti, err);
			return (FALSE);
		}
		scount = 0;
		tt = raw_block_pacts(raw_block);
		for (small_idx_t tti = 0; tti < num_pacts(raw_block);
			tti++) {
			if (pacts_overlap(t, tt))
				scount++;
			tt = (void *)tt + pact_size(tt);
		}
		if (scount > 1) {
			lprintf("processing block %ju, pact %u: "
        			"tx overlap %d times", idx, ti, scount);
			return (FALSE);
		}

		tbs -= size;
		t = (void *)t + size;
	}

	return (TRUE);
}

static int
raw_block_timeout_process_block(raw_block_timeout_t *rt, size_t blocksize)
{
	raw_block_t *rb;

	rb = (raw_block_t *)rt;

	if (pubkey_compare((void *)pubkey_zero, rt->notar[0]) != 0 &&
		pubkey_compare((void *)pubkey_zero, rt->notar[1]) != 0) {
		notar_raw_block_add(rb);
		raw_block_write(rb, blocksize);
		if (__raw_block_timeout_tmp) {
			free(__raw_block_timeout_tmp);
			__raw_block_timeout_tmp = NULL;
		}

		raw_block_broadcast(block_idx(rb));

		return (TRUE);
	}

	return (FALSE);
}

static void
raw_block_timeout_process(raw_block_t *raw_block, size_t blocksize)
{
	raw_block_timeout_t *rb;
	raw_block_timeout_t *rt;

	rb = (raw_block_timeout_t *)raw_block;

	if (raw_block_timeout_process_block(rb, blocksize))
		return;

	if (!__raw_block_timeout_tmp) {
		__raw_block_timeout_tmp = malloc(blocksize);
		bcopy(raw_block, __raw_block_timeout_tmp, blocksize);
		return;
	}

	rt = __raw_block_timeout_tmp;
	for (int i = 0; i < 2; i++) {
		if (pubkey_compare((void *)pubkey_zero, rb->notar[i]) == 0 &&
			pubkey_compare((void *)pubkey_zero, rt->notar[i]) != 0){
			bcopy(rt->notar[i], rb->notar[i], sizeof(public_key_t));
			bcopy(rt->signature[i], rb->signature[i],
				sizeof(signature_t));
		}
	}

	raw_block_timeout_process_block(rt, blocksize);
}

void
raw_block_process(raw_block_t *raw_block, size_t blocksize)
{
	raw_pact_t *t;
	size_t size;

	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT)
		return (raw_block_timeout_process(raw_block, blocksize));

	// if this node created last this block, caches_*_add is done elsewhere
	if (pubkey_compare(node_public_key(), raw_block->notar) != 0) {
		rxcache_raw_block_add(raw_block);
		notar_raw_block_add(raw_block);
	}

	t = raw_block_pacts(raw_block);
	for (small_idx_t ti = 0; ti < num_pacts(raw_block); ti++) {
		size = pact_size(t);
		pact_pending_remove(t);
		t = (void *)t + size;
	}

	raw_block_write(raw_block, blocksize);

	notar_elect_next();
}

void
block_pacts_add(block_t *block, pact_t **pacts,
	small_idx_t num_pacts)
{
	for (small_idx_t i = 0; i < num_pacts; i++)
		block_pact_add(block, pacts[i]);
}

void
block_pact_add(block_t *block, pact_t *pact)
{
	if (block->num_pacts % 10 == 0)
		block->pacts = realloc(block->pacts,
			sizeof(pact_t *) * block->num_pacts + 10);
	block->pacts[block->num_pacts] = pact;
	block->num_pacts++;
}

raw_block_t *
block_finalize(block_t *block, size_t *blocksize)
{
	size_t bs;
	size_t size;
	char *curbuf;
	small_idx_t rts;
	pact_t *t;
	raw_block_t *res;
	signature_t signature;
	raw_pact_t *rt;
	raw_pact_t **rtl;
	small_idx_t max_tr, max_rtr;

	bs = sizeof(raw_block_t);
	if (block->flags & BLOCK_FLAG_NEW_NOTAR)
		bs += sizeof(public_key_t);

	max_tr = max_rtr = 0;

	rtl = pacts_pending(&rts);

	add_notar_reward(block, rtl, rts);

	for (small_idx_t ti = 0; ti < block->num_pacts; ti++) {
		t = block->pacts[ti];
		size = sizeof(raw_pact_t);
		size += t->num_tx * sizeof(pact_tx_t);
		size += t->num_rx * sizeof(pact_rx_t);
		if (bs + size > MAXPACKETSIZE)
			break;
		bs += size;
		max_tr++;
	}
	for (small_idx_t ti = 0; ti < rts; ti++) {
		rt = rtl[ti];
//		if (be64toh(rt->time) < tm) {
			size = sizeof(raw_pact_t);
			size += be32toh(rt->num_tx) * sizeof(pact_tx_t);
			size += be32toh(rt->num_rx) * sizeof(pact_rx_t);
			if (bs + size > MAXPACKETSIZE)
				break;
			bs += size;
			max_rtr++;
//		}
	}

	res = calloc(1, bs);
	res->index = htobe64(block->index);
	res->time = htobe64(block->time);
	res->flags = htobe64(block->flags);
	bcopy(block->prev_block_hash, res->prev_block_hash, sizeof(hash_t));
	bcopy(block->notar, res->notar, sizeof(public_key_t));
	res->num_pacts = htobe32(max_tr + max_rtr);
	curbuf = (void *)res + sizeof(raw_block_t);
	if (block->flags & BLOCK_FLAG_NEW_NOTAR) {
		bcopy(block->new_notar, curbuf, sizeof(public_key_t));
		curbuf += sizeof(public_key_t);
	}

	for (small_idx_t ti = 0; ti < max_tr; ti++) {
		t = block->pacts[ti];
		pact_finalize(t);
		bcopy(t, curbuf, sizeof(raw_pact_t));
		curbuf += sizeof(raw_pact_t);
		for (small_idx_t ri = 0; ri < be32toh(t->num_tx); ri++) {
			bcopy(t->tx[ri], curbuf, sizeof(pact_tx_t));
			curbuf += sizeof(pact_tx_t);
		}
		for (small_idx_t ti = 0; ti < be32toh(t->num_rx); ti++) {
			bcopy(t->rx[ti], curbuf, sizeof(pact_rx_t));
			curbuf += sizeof(pact_rx_t);
		}
	}

	for (small_idx_t ti = 0; ti < max_rtr; ti++) {
		rt = rtl[ti];
//		if (be64toh(rt->time) < tm) {
			size = sizeof(raw_pact_t);
			size += be32toh(rt->num_tx) * sizeof(pact_tx_t) +
				be32toh(rt->num_rx) * sizeof(pact_rx_t);
			bcopy(rt, curbuf, size);
			curbuf += size;
//		}
	}

	rxcache_raw_block_add(res);
	notar_raw_block_add(res);

	cache_hash(res->cache_hash);

	bzero(res->signature, sizeof(signature_t));
	raw_block_sign(res, bs, signature);
	bcopy(signature, res->signature, sizeof(signature_t));

	*blocksize = bs;

	return (res);
}

uint8_t *
public_key_find_by_rx_idx(raw_block_t *block, small_idx_t rx_idx)
{
	void *buf;
	raw_pact_t *t;
	small_idx_t nrx = 0;

	buf = raw_block_pacts(block);
	for (small_idx_t ti = 0; ti < num_pacts(block); ti++) {
		t = (void *)buf;
		buf += sizeof(raw_pact_t);
		buf += sizeof(pact_tx_t) * be32toh(t->num_tx);
		if (nrx + pact_num_rx(t) <= rx_idx) {
			nrx += pact_num_rx(t);
			buf += sizeof(pact_rx_t) * pact_num_rx(t);
			continue;
		}
		buf += sizeof(pact_rx_t) * (rx_idx - nrx);

		return ((pact_rx_t *)buf)->address;
	}

	return (NULL);
}

raw_pact_t *
pact_for_rx_idx(raw_block_t *block, small_idx_t rx_idx)
{
	raw_pact_t *t;
	small_idx_t nrx = 0;

	t = raw_block_pacts(block);
	for (small_idx_t ti = 0; ti < num_pacts(block); ti++) {
		if (rx_idx <= nrx + pact_num_rx(t))
			return (t);

		nrx += pact_num_rx(t);
		t = (void *)t + pact_size(t);
	}

	return (NULL);
}

void
block_free(block_t *block)
{
	for (small_idx_t i = 0; i < block->num_pacts; i++)
		if (block->pacts[i])
			pact_free(block->pacts[i]);
	free(block->pacts);
#ifdef DEBUG_ALLOC
	lprintf("-BLOCK %p", block);
#endif
	free(block);
}

raw_pact_t *
raw_block_pacts(raw_block_t *raw_block)
{
	void *res;

	res = (void *)raw_block + sizeof(raw_block_t);
	if (be64toh(raw_block->flags) & BLOCK_FLAG_NEW_NOTAR)
		res += sizeof(public_key_t);

	return (res);
}

static void
raw_block_timeout_print(raw_block_t *raw_block)
{
	raw_block_timeout_t *rb;
	node_name_t node_name;

	rb = (raw_block_timeout_t *)raw_block;

	printf("\n");

	public_key_node_name(rb->denounced_notar, node_name);
	printf("  denounced_notar: %s\n", node_name);
	printf("  notars:\n");
	for (int i = 0; i < 2; i++) {
		public_key_node_name(rb->notar[i], node_name);
		printf("    - %s\n", node_name);
	}
}

void
raw_block_print(raw_block_t *raw_block)
{
	char stmp[SIGNATURE_STR_LENGTH];
	char htmp[HASH_STR_LENGTH];
	small_idx_t tx_num, rx_num;
	address_name_t addr_name;
	node_name_t node_name;
	raw_pact_t *t;
	small_hash_t thash;
	pact_tx_t *tx;
	pact_rx_t *rx;
	time_t tm;

	tm = (time_t)block_time(raw_block);
	printf("---\nresult:\n");
	printf("  index: %ju\n", block_idx(raw_block));
	printf("  time: %ju %s", be64toh(raw_block->time), ctime(&tm));
	printf("  flags: %ju", be64toh(raw_block->flags));
	if (block_flags(raw_block) & BLOCK_FLAG_NEW_NOTAR)
		printf(" BLOCK_FLAG_NEW_NOTAR");
	if (block_flags(raw_block) & BLOCK_FLAG_DENOUNCE_NOTAR)
		printf(" BLOCK_FLAG_DENOUNCE_NOTAR");

	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT) {
		printf(" BLOCK_FLAG_TIMEOUT");
		return raw_block_timeout_print(raw_block);
	}

	printf("\n");
	printf("  prev_block_hash: %s\n",
		hash_str(raw_block->prev_block_hash, htmp));
	public_key_node_name(raw_block->notar, node_name);
	printf("  notar: %s\n", node_name);
	if (be64toh(raw_block->flags) & BLOCK_FLAG_NEW_NOTAR) {
		public_key_node_name((void *)raw_block + sizeof(raw_block_t),
			node_name);
		printf("  new_notar: %s\n", node_name);
	}
	printf("  signature: %s\n", signature_str(raw_block->signature, stmp));
	printf("  cache_hash: %s\n", hash_str(raw_block->cache_hash, htmp));
	printf("  num_pacts: %d\n", num_pacts(raw_block));
	printf("  pacts:\n");
	t = raw_block_pacts(raw_block);
	
	for (small_idx_t i = 0; i < num_pacts(raw_block); i++) {
		pact_hash(t, thash);
		tx_num = pact_num_tx(t);
		rx_num = pact_num_rx(t);
		tx = (void *)t + sizeof(raw_pact_t);
		printf("    - pact_hash: %s\n", small_hash_str(thash, htmp));
		
		printf("      tx:%s\n", tx_num ? "" : " []");
		for (small_idx_t ri = 0; ri < tx_num; ri++) {
			printf("        - block_idx: %ju\n",
				be64toh(tx->block_idx));
			printf("          block_rx_idx: %d\n",
				be32toh(tx->block_rx_idx));
			printf("          signature: %s\n",
				signature_str(tx->signature, stmp));
			tx = (void *)tx + sizeof(pact_tx_t);
		}
		rx = (void *)tx;
		printf("      rx:\n");
		for (small_idx_t ti = 0; ti < rx_num; ti++) {
			public_key_address_name(rx->address, addr_name);
			printf("        - address: %s\n", addr_name);
			printf("          amount: %2.2f\n",
				stoi(be64toh(rx->amount)));
			rx = (void *)rx + sizeof(pact_rx_t);
		}
		t = (void *)rx;
	}
}

void
raw_block_broadcast(big_idx_t index)
{
	raw_block_t *block;
	size_t size;

	block = block_load(index, &size);
	message_broadcast(OP_BLOCKANNOUNCE, block, size, htobe64(index));
}

void
blockchain_update()
{
	blockchain_set_updating(1);
	if (!message_send_random(OP_LASTBLOCKINFO, NULL, 0, 0)) {
#ifdef DEBUG_NETWORK
		lprintf("blockchain_update: failed retrieving last block, "
			"trying again...");
#endif
		blockchain_update();
	}
}

void
blockchain_set_updating(int updating)
{
	__blockchain_is_updating = updating;
}

int
blockchain_is_updating(void)
{
	return __blockchain_is_updating;
}

 
void
getblock(big_idx_t index)
{
	if (!message_send_random(OP_GETBLOCK, NULL, 0, htobe64(index)))
		getblock(index);
}

void
getblocks(big_idx_t target_idx)
{
	big_idx_t cur_idx;

	if (!__getblocks_target_idx && !target_idx)
		return;

	if (target_idx)
		__getblocks_target_idx = target_idx;

	cur_idx = block_idx_last();
	if (cur_idx < __getblocks_target_idx) {
		cur_idx++;
		return getblock(cur_idx);
	}

	__getblocks_target_idx = 0;
	blockchain_set_updating(0);

	lprintf("fully synchronized");

	if (is_sync_only())
		exit(0);

	notar_elect_next();
	if (!is_caches_only())
		daemon_start();
	return;
}

void
blocks_remove(void)
{
	config_unlink("blocks/blocks0.bin");
	config_unlink("blocks/blocks0.idx");
	config_unlink("blocks/lastblock.idx");
}

static void
__block_poll_tick(event_info_t *info, event_flags_t eventtype)
{
	time_t t;

	__block_poll_timer = NULL;

	t = time(NULL);
	if (t > block_time(__raw_block_last) + 5) {
		lprintf("no blocks seen in the last 5 seconds, polling...");
		blockchain_update();
	}
	if (t > block_time(__raw_block_last) + 18)
		notar_timeout_denounce();

	block_poll_start();
}

void
block_poll_start(void)
{
	if (__block_poll_timer)
		return;

	__block_poll_timer = timer_set(3000, __block_poll_tick, NULL);
}
