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
#include <dirent.h>
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

#define BLOCKS_FILESIZE_MAX 268435456UL
#define BLOCK_IDX_FILESIZE_MAX ((BLOCKS_FILESIZE_MAX * 8UL) / 256UL)
#define BLOCK_POLL_INTERVAL_USECONDS 300
#define BLOCK_DENOUNCE_DELAY_SECONDS 19
#define BLOCK_TRANSIT_MESSAGES_MAX 20
#define BLOCK_FUTURE_BUFFERS_MAX 20

typedef struct __block_storage {
	void *blocks;
	big_idx_t *block_idxs;
	big_idx_t first_block_idx;
	big_idx_t last_block_idx;
} block_storage_t;

static block_storage_t **__block_storage = NULL;
static block_storage_t *__block_storage_current = NULL;
static size_t __num_block_storages = 0;

static raw_block_t *__raw_block_last = NULL;
static size_t __raw_block_last_size = 0;

static raw_block_timeout_t *__raw_block_timeout_tmp = NULL;

static big_idx_t __getblocks_target_idx = 0;

static event_info_t *__block_poll_timer = NULL;

static message_t *__block_transit_messages[BLOCK_TRANSIT_MESSAGES_MAX] = { 0 };
static raw_block_t *__block_future_buffer[BLOCK_FUTURE_BUFFERS_MAX] = { 0 };

static void raw_block_broadcast(big_idx_t index);
static void add_notar_reward(block_t *block, raw_pact_t **rt, size_t nrt);
static void __raw_block_process(raw_block_t *raw_block, size_t blocksize,
	int process_caches);
static int raw_block_timeout_validate(raw_block_t *raw_block, size_t blocksize);
static int raw_block_timeout_process_block(raw_block_timeout_t *rt);
static void raw_block_timeout_process(raw_block_t *raw_block);
static void raw_block_timeout_free(void);
static void raw_block_fprint_base(FILE *f, raw_block_t *raw_block);
static void raw_block_timeout_fprint(FILE *f, raw_block_timeout_t *raw_block);
static void block_transit_messages_cleanup(void);
static raw_block_t *raw_block_future_get(big_idx_t idx);
static void raw_block_future_free(raw_block_t *rb);


big_idx_t
block_idx_last()
{
	if (config_is_caches_only()) {
		if (__raw_block_last)
			return (block_idx(__raw_block_last));
		else
			return (0);
	}

	return (__raw_block_last ? block_idx(__raw_block_last) : 0);
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

	if ((fd = open(config_path_r(file, filename),
		O_CREAT | O_RDWR, 0644)) == -1)
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

static inline void
block_storage_names_fill(char *blockname, char *idxname, size_t idx,
	size_t size)
{
	if (snprintf(blockname, size, "blocks/blocks%ld.bin", idx) >= size - 1)
		FAILTEMP("path overflow: %s", blockname);
	if (snprintf(idxname, size, "blocks/blocks%ld.idx", idx) >= size - 1)
		FAILTEMP("path overflow: %s", idxname);
}

static int
block_storage_exists(small_idx_t idx)
{
	char bpath[MAXPATHLEN + 1];
	char ipath[MAXPATHLEN + 1];
	char bpart[32];
	char ipart[32];

	block_storage_names_fill(bpart, ipart, idx, 32);
	config_path_r(bpath, bpart);
	config_path_r(ipath, ipart);

	return (access(bpath, R_OK | W_OK) == 0 &&
		access(ipath, R_OK | W_OK) == 0);
}

static block_storage_t *
block_storage_load_storage(small_idx_t idx, big_idx_t first_block_idx)
{
	block_storage_t *res;
	small_idx_t i, n;
	char bpath[32];
	char ipath[32];

	block_storage_names_fill(bpath, ipath, idx, 32);

	res = calloc(1, sizeof(block_storage_t));
	res->first_block_idx = first_block_idx;

	if (!(res->blocks = mmap_file(bpath, BLOCKS_FILESIZE_MAX)))
		FAILTEMP("block_storage_load: %s: %s", bpath, strerror(errno));
	if (!(res->block_idxs = mmap_file(ipath, BLOCK_IDX_FILESIZE_MAX)))
		FAILTEMP("block_storage_load: %s: %s", bpath, strerror(errno));

	n = BLOCK_IDX_FILESIZE_MAX / sizeof(big_idx_t);
	i = 0;
	if (res->block_idxs[1]) {
		for (i = 1; i < n; i++) {
			if (!res->block_idxs[i]) {
				i--;
				break;
			}
			if (res->block_idxs[n - i]) {
				i = n - i;
				break;
			}
		}
	}

	res->last_block_idx = first_block_idx + i;

	return (res);
}

static void
block_storage_list_resize(void)
{
	size_t sz, curr;

	sz = sizeof(block_storage_t *);
	curr = __num_block_storages;
	__num_block_storages = curr + 10;
	__block_storage = realloc(__block_storage, sz * __num_block_storages);
	bzero(__block_storage + curr, sz * 10);
}

static block_storage_t *
block_storage_create(void)
{
	block_storage_t *res;
	big_idx_t fbi;
	size_t i;

	for (i = 0; i < __num_block_storages; i++)
		if (!__block_storage[i])
			break;

	if (i == __num_block_storages)
		block_storage_list_resize();

	fbi = block_idx_last() + 1;
	res = block_storage_load_storage(i, fbi);
	__block_storage[i] = res;

	return (res);
}

static void
blockchain_storage_load(void)
{
	block_storage_t *cb;

	__num_block_storages = 10;
	__block_storage = calloc(1,
		sizeof(block_storage_t *) * __num_block_storages);

	for (size_t i = 0, fbi = 0; block_storage_exists(i); i++) {
		if (i == __num_block_storages)
			block_storage_list_resize();
		cb = block_storage_load_storage(i, fbi);
		__block_storage[i] = cb;
		__block_storage_current = cb;

		fbi = cb->last_block_idx + 1;
	}
}

void
blockchain_load(void)
{
	blockchain_storage_load();
}

static void *
raw_block_last_load(size_t *blocksize)
{
	big_idx_t last_offset;
	raw_block_t *rb;
	big_idx_t lbi;

	lbi = __block_storage_current->last_block_idx;
	last_offset = __block_storage_current->block_idxs[lbi];

	rb = (raw_block_t *)(__block_storage_current->blocks + last_offset);
	if (blocksize)
		*blocksize = raw_block_size(rb, 0);

	return (rb);
}

void
block_last_load()
{
	__raw_block_last = raw_block_last_load(&__raw_block_last_size);
}

static block_t *
block_alloc(void)
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

amount_t
block_reward(big_idx_t idx)
{
	return (itos(TIFA_NOTAR_REWARD));
}

static void
add_notar_reward(block_t *block, raw_pact_t **rp, size_t nrp)
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
			    block->pacts, block->num_pacts)) {
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
	time64_t tm;
	void *pn;

	res = block_alloc();

	res->time = time(NULL);

	if (__raw_block_last) {
		res->index = block_idx_last() + 1;
		raw_block_hash(__raw_block_last, __raw_block_last_size,
			res->prev_block_hash);

		tm = be64toh(__raw_block_last->time);
		if (tm > res->time)
			res->time = tm;
	}

	pn = notar_pending_next();
	res->flags |= pn != NULL ? BLOCK_FLAG_NEW_NOTAR : 0;
	bcopy(node_public_key(), res->notar, sizeof(public_key_t));
	if (pn)
		bcopy(pn, res->new_notar, sizeof(public_key_t));

	return (res);
}

raw_block_t *
block_load(big_idx_t block_idx, size_t *size)
{
	block_storage_t *bs;
	raw_block_t *res;
	big_idx_t soffset;
	big_idx_t idx;
	size_t i;

	*size = 0;

	if (block_idx > block_idx_last())
		return (NULL);

	for (i = 0; __block_storage[i]->last_block_idx < block_idx; i++) { }

	bs = __block_storage[i];
	while (bs->last_block_idx < block_idx)
		bs++;

	idx = block_idx - bs->first_block_idx;
	soffset = bs->block_idxs[idx];

	res = (raw_block_t *)(bs->blocks + soffset);
	*size = raw_block_size(res, 0);

	return (res);
}

static void
raw_block_write(raw_block_t *raw_block, size_t blocksize)
{
	block_storage_t *bs;
	size_t bsize, isize;
	big_idx_t idx;
	void *dst;

	if (config_is_caches_only()) {
		if (__raw_block_last)
			free(__raw_block_last);
		__raw_block_last = malloc(blocksize);
		__raw_block_last_size = blocksize;
		bcopy(raw_block, __raw_block_last, blocksize);
		return;
	}

	bs = __block_storage_current;
	dst = (void *)__raw_block_last + __raw_block_last_size;
	if (dst + blocksize > bs->blocks + BLOCKS_FILESIZE_MAX) {
		bs = block_storage_create();
		__block_storage_current = bs;
		dst = bs->blocks;
	} else
		bs->last_block_idx++;

	bcopy(raw_block, dst, blocksize);
	__raw_block_last = (raw_block_t *)dst;
	__raw_block_last_size = blocksize;

	idx = block_idx(raw_block) - bs->first_block_idx;
	bs->block_idxs[idx] = (void *)__raw_block_last - bs->blocks;

	bsize = bs->block_idxs[idx] + blocksize;
	isize = idx * sizeof(big_idx_t);
	msync(bs->blocks, bsize, MS_SYNC);
	msync(bs->block_idxs, isize, MS_SYNC);
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

	__raw_block_process(rb, size, FALSE);

	raw_block_broadcast(block_idx(rb));

	free(rb);
}

size_t
raw_block_size(raw_block_t *raw_block, size_t limit)
{
	size_t tbs;
	size_t res;
	raw_pact_t *t;

	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT)
		return (sizeof(raw_block_timeout_t));

	res = sizeof(raw_block_t);
	if (block_flags(raw_block) & BLOCK_FLAG_NEW_NOTAR)
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

static size_t
block_denounce_timeout_fill(raw_block_timeout_t *rt)
{
	size_t signsize;
	size_t res = 0;
	void *self;
	void *prev;

	self = node_public_key();
	signsize = offsetof(raw_block_timeout_t, notar);

	for (big_idx_t i = 0; i < 2; i++) {
		prev = notar_denounce_node(i);
		bcopy(prev, rt->notar[i], sizeof(public_key_t));

		if (!pubkey_equals(self, prev))
			continue;

		raw_block_sign((raw_block_t *)rt, signsize, rt->signature[i]);
		res++;
	}

	return (res);
}

static void
block_denounce_timeout_init(raw_block_timeout_t *rt)
{
	size_t sz, size;

	size = sizeof(raw_block_timeout_t);

	rt->index = htobe64(block_idx_last() + 1);
	rt->time = htobe64(block_time(raw_block_last(&sz)) +
		BLOCK_DENOUNCE_DELAY_SECONDS);
	rt->flags = htobe64(BLOCK_FLAG_TIMEOUT);
	raw_block_hash((raw_block_t *)rt, size, rt->prev_block_hash);
	bcopy(notar_next(), rt->denounced_notar, sizeof(public_key_t));
}

static void
block_denounce_timeout_create(void)
{
	raw_block_t *rb;
	size_t size;

	if (!node_is_notar())
		return;

	if (block_idx_last() < 2)
		return;

	size = sizeof(raw_block_timeout_t);

	if (!__raw_block_timeout_tmp) {
		__raw_block_timeout_tmp = calloc(1, size);
#ifdef DEBUG_ALLOC
		lprintf("+RAW_BLOCK_TIMEOUT_TMP %p", __raw_block_timeout_tmp);
#endif
		block_denounce_timeout_init(__raw_block_timeout_tmp);
	}
	rb = (raw_block_t *)__raw_block_timeout_tmp;

	if (!__raw_block_timeout_tmp->index)
		block_denounce_timeout_init(__raw_block_timeout_tmp);

	if (block_denounce_timeout_fill(__raw_block_timeout_tmp))
		if (raw_block_timeout_validate(rb, size))
			raw_block_timeout_process(rb);
}

static int
raw_block_timeout_validate(raw_block_t *raw_block, size_t blocksize)
{
	raw_block_timeout_t *rb;
	time_t ct, bt, lbt;
	size_t size;
	void *prev;
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
	if (lbt + BLOCK_DENOUNCE_DELAY_SECONDS != bt) {
		lprintf("denounce timeout block with index %ju has invalid "
			"time: %ld vs %ld", block_idx(raw_block), bt,
			lbt + BLOCK_DENOUNCE_DELAY_SECONDS);
		return (FALSE);
	}

	if (pubkey_is_zero(rb->notar[0]) && pubkey_is_zero(rb->notar[1])) {
		lprintf("denounce timeout block with index %ju has no notars",
			block_idx(raw_block));
		return (FALSE);
	}

	if (!pubkey_equals(notar_next(), rb->denounced_notar)) {
		lprintf("illegal denounced notar for denounce timeout block "
			"index %ju", block_idx(raw_block));
		return (FALSE);
	}

	size = offsetof(raw_block_timeout_t, notar);
	for (big_idx_t i = 0; i < 2; i++) {
		prev = notar_denounce_node(i);
		if (!pubkey_equals(rb->notar[i], prev)) {
			lprintf("denounce timeout block with index %ju "
				"has invalid notar %d", i,
				block_idx(raw_block));
			return (FALSE);
		}
		if (!signature_is_zero(rb->signature[i])) {
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
	void *new_notar;
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

	if (block_idx(raw_block) <= block_idx_last()) {
		// check with our blockchain and possibly take some action
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
	if (!config_is_caches_only() || (config_is_caches_only() && __raw_block_last)) {
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
			blockchain_update();
			return (FALSE);
		}

		// check prev block hash
		raw_block_hash(__raw_block_last, __raw_block_last_size, pbh);
		if (!hash_equals(pbh, raw_block->prev_block_hash)) {
			lprintf("gotten block with illegal prev_block_hash, "
				"index %ju", block_idx(raw_block));
			return (FALSE);
		}

		// check notar
		if (!pubkey_equals(notar_next(), raw_block->notar)) {
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

	if ((new_notar = raw_block_new_notar(raw_block))) {
		if (pubkey_is_zero(new_notar)) {
			lprintf("block tried adding invalid notar %s, index "
				"%ju", public_key_node_name(new_notar),
				block_idx(raw_block));
			return (FALSE);
		}
		if (notar_exists(new_notar)) {
			lprintf("block tried adding existing notar %s, index "
				"%ju", public_key_node_name(new_notar),
				block_idx(raw_block));
			return (FALSE);
		}
	}

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

		if (config_is_caches_only() && err == ERR_RX_SPENT &&
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

static void
raw_block_timeout_free(void)
{
	if (__raw_block_timeout_tmp) {
#ifdef DEBUG_ALLOC
		lprintf("-RAW_BLOCK_TIMEOUT_TMP %p", __raw_block_timeout_tmp);
#endif
		free(__raw_block_timeout_tmp);
		__raw_block_timeout_tmp = NULL;
	}
}

static int
raw_block_timeout_process_block(raw_block_timeout_t *rt)
{
	raw_block_t *rb;

	rb = (raw_block_t *)rt;

	if (!signature_is_zero(rt->signature[0]) &&
		!signature_is_zero(rt->signature[1])) {
		notar_raw_block_add(rb);
		raw_block_write(rb, sizeof(raw_block_timeout_t));
		raw_block_timeout_free();

		notar_elect_next();

		raw_block_broadcast(block_idx(rb));

		return (TRUE);
	}

	return (FALSE);
}

static void
block_denounce_timeout_merge(raw_block_timeout_t *dst, raw_block_timeout_t *src)
{
	for (int i = 0; i < 2; i++)
		if (signature_is_zero(dst->signature[i]) &&
			!signature_is_zero(src->signature[i]))
				bcopy(src->signature[i], dst->signature[i],
					sizeof(signature_t));
}

static void
raw_block_timeout_process(raw_block_t *raw_block)
{
	raw_block_timeout_t *rb;
	raw_block_timeout_t *rt;
	size_t blocksize;
	size_t size;

	blocksize = sizeof(raw_block_timeout_t);
	rb = (raw_block_timeout_t *)raw_block;

	if (raw_block_timeout_process_block(rb))
		return;

	if (!__raw_block_timeout_tmp) {
		__raw_block_timeout_tmp = malloc(blocksize);
#ifdef DEBUG_ALLOC
		lprintf("+RAW_BLOCK_TIMEOUT_TMP %p", __raw_block_timeout_tmp);
#endif
		bcopy(raw_block, __raw_block_timeout_tmp, blocksize);
		return;
	} else {
		block_denounce_timeout_merge(__raw_block_timeout_tmp, rb);
	}

	rt = __raw_block_timeout_tmp;
	size = sizeof(raw_block_timeout_t);
	if (block_denounce_timeout_fill(rt))
		message_broadcast(OP_BLOCKANNOUNCE, __raw_block_timeout_tmp,
			size, rt->index);

	raw_block_timeout_process_block(rt);
}

void
raw_block_process(raw_block_t *raw_block, size_t blocksize)
{
	__raw_block_process(raw_block, blocksize, TRUE);
}

void
__raw_block_process(raw_block_t *raw_block, size_t blocksize,
	int process_caches)
{
	raw_pact_t *t;
	raw_block_t *fb;
	size_t size;

	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT)
		return (raw_block_timeout_process(raw_block));

	if (process_caches) {
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

	raw_block_timeout_free();

	if (block_idx_last() >= __getblocks_target_idx)
		__getblocks_target_idx = 0;

	notar_elect_next();

	if ((fb = raw_block_future_get(block_idx_last() + 1))) {
		raw_block_process(fb, raw_block_size(fb, 0));
		raw_block_future_free(fb);
	}
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
//		if (be64toh(rt->time) <= tm) {
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
//		if (be64toh(rt->time) <= tm) {
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

void *
raw_block_new_notar(raw_block_t *raw_block)
{
	if (!(block_flags(raw_block) & BLOCK_FLAG_NEW_NOTAR))
		return (NULL);

	return ((void *)raw_block + sizeof(raw_block_t));
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
raw_block_timeout_fprint(FILE *f, raw_block_timeout_t *rb)
{
	char *node_name;

	raw_block_fprint_base(f, (raw_block_t *)rb);

	node_name = public_key_node_name(rb->denounced_notar);
	fprintf(f, "  denounced_notar: %s\n", node_name);
	fprintf(f, "  notars:\n");
	for (int i = 0; i < 2; i++) {
		node_name = public_key_node_name(rb->notar[i]);
		fprintf(f, "    - notar: %s\n", node_name);
		fprintf(f, "      signature: %s\n",
			signature_str(rb->signature[i]));
	}
}

void
raw_block_print(raw_block_t *raw_block)
{
	raw_block_fprint(stdout, raw_block);
}

static void
raw_block_fprint_base(FILE *f, raw_block_t *raw_block)
{
	time_t tm;

	tm = (time_t)block_time(raw_block);
	fprintf(f, "---\nresult:\n");
	fprintf(f, "  index: %ju\n", block_idx(raw_block));
	fprintf(f, "  raw_time: %ju\n", be64toh(raw_block->time));
	fprintf(f, "  time: %s", ctime(&tm));
	fprintf(f, "  raw_flags: %ju", be64toh(raw_block->flags));
	if (block_flags(raw_block)) {
		fprintf(f, "\n  flags:");
		if (block_flags(raw_block) & BLOCK_FLAG_NEW_NOTAR)
			fprintf(f, " BLOCK_FLAG_NEW_NOTAR");
		if (block_flags(raw_block) & BLOCK_FLAG_DENOUNCE_NOTAR)
			fprintf(f, " BLOCK_FLAG_DENOUNCE_NOTAR");
	
		if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT) {
			fprintf(f, " BLOCK_FLAG_TIMEOUT");
		}
	}

	fprintf(f, "\n");
}

void
raw_block_fprint(FILE *f, raw_block_t *raw_block)
{
	small_idx_t tx_num, rx_num;
	small_hash_t thash;
	char *node_name;
	char *addr_name;
	raw_pact_t *t;
	pact_tx_t *tx;
	pact_rx_t *rx;
	void *ptr;

	if (block_flags(raw_block) & BLOCK_FLAG_TIMEOUT)
		return (raw_block_timeout_fprint(f,
			(raw_block_timeout_t *)raw_block));

	raw_block_fprint_base(f, raw_block);

	fprintf(f, "  prev_block_hash: %s\n",
		hash_str(raw_block->prev_block_hash));
	node_name = public_key_node_name(raw_block->notar);
	fprintf(f, "  notar: %s\n", node_name);
	if (be64toh(raw_block->flags) & BLOCK_FLAG_NEW_NOTAR) {
		ptr = (void *)raw_block + sizeof(raw_block_t);
		fprintf(f, "  new_notar: %s\n", public_key_node_name(ptr));
	}
	fprintf(f, "  signature: %s\n", signature_str(raw_block->signature));
	fprintf(f, "  cache_hash: %s\n", hash_str(raw_block->cache_hash));
	fprintf(f, "  num_pacts: %d\n", num_pacts(raw_block));
	fprintf(f, "  pacts:\n");
	t = raw_block_pacts(raw_block);
	
	for (small_idx_t i = 0; i < num_pacts(raw_block); i++) {
		pact_hash(t, thash);
		tx_num = pact_num_tx(t);
		rx_num = pact_num_rx(t);
		tx = (void *)t + sizeof(raw_pact_t);
		fprintf(f, "    - pact_hash: %s\n", small_hash_str(thash));
		
		fprintf(f, "      tx:%s\n", tx_num ? "" : " []");
		for (small_idx_t ri = 0; ri < tx_num; ri++) {
			fprintf(f, "        - block_idx: %ju\n",
				be64toh(tx->block_idx));
			fprintf(f, "          block_rx_idx: %d\n",
				be32toh(tx->block_rx_idx));
			fprintf(f, "          signature: %s\n",
				signature_str(tx->signature));
			tx = (void *)tx + sizeof(pact_tx_t);
		}
		rx = (void *)tx;
		fprintf(f, "      rx:\n");
		for (small_idx_t ti = 0; ti < rx_num; ti++) {
			addr_name = public_key_address_name(rx->address);
			fprintf(f, "        - address: %s\n", addr_name);
			fprintf(f, "          amount: %2.2f\n",
				stoi(be64toh(rx->amount)));
			rx = (void *)rx + sizeof(pact_rx_t);
		}
		t = (void *)rx;
	}
}

static void
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
	if (!message_send_random(OP_LASTBLOCKINFO, NULL, 0, 0)) {
#ifdef DEBUG_NETWORK
		lprintf("blockchain_update: failed retrieving last block, "
			"trying again...");
#endif
		blockchain_update();
	}
}

int
blockchain_is_updating(void)
{
	return (__getblocks_target_idx != 0);
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
	if (cur_idx < __getblocks_target_idx)
		return getblock(cur_idx + 1);

	__getblocks_target_idx = 0;

	lprintf("fully synchronized");

	if (config_is_sync_only()) {
		peerlist_save();
		exit(0);
	}

	notar_elect_next();
	if (!config_is_caches_only())
		daemon_start();
	return;
}

int
blocks_remove(void)
{
	char path[MAXPATHLEN + 1];
	struct dirent *dire;
	char *name;
	DIR *dirp;
	int r;

	r = 1;
	if ((dirp = opendir(config_path("blocks")))) {
		for (name = NULL; (dire = readdir(dirp));) {
			if (strcmp(dire->d_name, "lastblock.idx") == 0)
				name = dire->d_name;
			if (strncmp(dire->d_name, "blocks", 6) == 0)
				name = dire->d_name;

			if (name) {
				snprintf(path, MAXPATHLEN + 1, "blocks/%s",
					name);
				if (!config_unlink(path))
					r = 0;
				name = NULL;
			}
		}
		closedir(dirp);
	}

	return (r);
}

static void
block_getnext_broadcast(void)
{
	big_idx_t nextidx;

	nextidx = block_idx(__raw_block_last) + 1;
	message_broadcast(OP_GETBLOCK, NULL, 0, htobe64(nextidx));
}

static void
__block_poll_tick(event_info_t *info, event_flags_t eventtype)
{
	time64_t t;
	time64_t last;

	__block_poll_timer = NULL;

	t = time(NULL);

	if (!blockchain_is_updating() && !notar_should_generate_block()) {
		block_transit_messages_cleanup();
		last = block_time(__raw_block_last);
		if (t > last + 2) {
#ifdef DEBUG_NETWORK
			lprintf("no blocks seen in the last 2 seconds, "
				"polling...");
#endif
			block_getnext_broadcast();
			blockchain_update();
		}
		if (t >= last + BLOCK_DENOUNCE_DELAY_SECONDS) {
			lprintf("no blocks seen in the last %d seconds, "
				"notar will be denounced...",
				BLOCK_DENOUNCE_DELAY_SECONDS);
			block_denounce_timeout_create();
		}
	}
	block_poll_start();
}

void
block_poll_start(void)
{
	if (__block_poll_timer)
		return;

	__block_poll_timer = timer_set(BLOCK_POLL_INTERVAL_USECONDS,
		__block_poll_tick, NULL);
}

int
block_idx_in_transit(big_idx_t idx_be)
{
	int n;

	n = 0;
	for (small_idx_t i = 0; i < BLOCK_TRANSIT_MESSAGES_MAX; i++)
		if (__block_transit_messages[i])
			if (__block_transit_messages[i]->userinfo == idx_be)
				n++;

	return (n >= 2);
}

void
block_transit_message_add(message_t *msg)
{
	for (small_idx_t i = 0; i < BLOCK_TRANSIT_MESSAGES_MAX; i++) {
		if (!__block_transit_messages[i]) {
			__block_transit_messages[i] = msg;
			return;
		}
	}
}

void
block_transit_message_remove(message_t *msg)
{
	for (small_idx_t i = 0; i < BLOCK_TRANSIT_MESSAGES_MAX; i++)
		if (__block_transit_messages[i] == msg)
			__block_transit_messages[i] = NULL;
}

static void
block_transit_messages_cleanup(void)
{
	for (small_idx_t i = 0; i < BLOCK_TRANSIT_MESSAGES_MAX; i++)
		__block_transit_messages[i] = NULL;
}

int
raw_block_future_buffer_add(raw_block_t *rb, size_t size)
{
	small_idx_t i;

	if (raw_block_size(rb, size) != size)
		return (FALSE);

	if ((block_idx(rb) > block_idx_last() + 20) ||
		(block_idx(rb) <= block_idx_last() + 1))
		return (FALSE);

	for (i = 0; i < BLOCK_FUTURE_BUFFERS_MAX; i++)
		if (!__block_future_buffer[i])
			break;

	if (i == BLOCK_FUTURE_BUFFERS_MAX)
		return (FALSE);

	__block_future_buffer[i] = rb;

	return (TRUE);
}

static raw_block_t *
raw_block_future_get(big_idx_t idx)
{
	big_idx_t idx_be;

	idx_be = htobe64(idx);
	for (small_idx_t i = 0; i < BLOCK_FUTURE_BUFFERS_MAX; i++)
		if (__block_future_buffer[i])
			if (__block_future_buffer[i]->index == idx_be)
				return (__block_future_buffer[i]);

	return (NULL);
}

static void
raw_block_future_free(raw_block_t *rb)
{
	big_idx_t last_be;

	last_be = __raw_block_last->index;
	for (small_idx_t i = 0; i < BLOCK_FUTURE_BUFFERS_MAX; i++) {
		if (__block_future_buffer[i]) {
			if (__block_future_buffer[i]->index <= last_be) {
				__block_future_buffer[i] = NULL;
				free(__block_future_buffer[i]);
			}
		}

		if (__block_future_buffer[i] == rb)
			__block_future_buffer[i] = NULL;
	}

	free(rb);
}
