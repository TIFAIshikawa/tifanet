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
#include "network.h"
#include "txcache.h"
#include "pact.h"

// 3 mmap'ed files
static char *__blocks = NULL;
static big_idx_t *__block_idxs = NULL;
static big_idx_t *__last_block_idx = NULL;

static raw_block_t *__raw_block_last;
static size_t __raw_block_last_size;

static big_idx_t __getblocks_target_idx = 0;

static int __blockchain_is_updating = 0;

void raw_block_broadcast(big_idx_t index);
void add_notar_reward(block_t *block, raw_pact_t **rt, size_t nrt);

big_idx_t
block_idx_last()
{
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
	char tmp[MAXPATHLEN + 1];

	if ((fd = open(config_path(tmp,
		filename), O_CREAT | O_RDWR)) == -1)
		FAILTEMP("open %s: %s\n", tmp, strerror(errno));
	ftruncate(fd, truncsize);
	if ((res = mmap(0, truncsize,
		PROT_READ | PROT_WRITE, MAP_NOCORE | MAP_SHARED,
		fd, 0)) == MAP_FAILED)
		FAILTEMP("mmap %s: %s\n", tmp, strerror(errno));
	close(fd);

	return (res);
}

static void *
raw_block_last_load(size_t *blocksize)
{
	big_idx_t last_offset;

	__blocks = mmap_file("blocks/blocks0.bin", 2147483648);
	__block_idxs = mmap_file("blocks/blocks0.idx", 536870912);
	__last_block_idx = mmap_file("blocks/lastblock.idx", sizeof(big_idx_t));

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
	printf("+BLOCK %p\n", res);
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
cache_in_pacts(txcache_t *cache, pact_t **pacts,
	small_idx_t tsize)
{
	pact_t *t;
	pact_rx_t *rx;

	for (small_idx_t i = 0; i < tsize; i++) {
		if (!(t = pacts[i]))
			continue;
		for (small_idx_t ri = 0; ri < t->num_rx; ri++) {
			rx = t->rx[ri];
			if (be64toh(cache->block_idx) == rx->block_idx &&
			    be32toh(cache->block_tx_idx) == rx->block_tx_idx)
				return (TRUE);
		}
	}

	return (FALSE);
}

static int
cache_in_raw_pacts(txcache_t *cache, raw_pact_t **pacts,
	small_idx_t tsize)
{
	raw_pact_t *t;
	pact_rx_t *rx;

	for (small_idx_t i = 0; i < tsize; i++) {
		t = pacts[i];
		rx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t ri = 0; ri < be32toh(t->num_rx); ri++) {
			if (cache->block_idx == rx->block_idx &&
			    cache->block_tx_idx == rx->block_tx_idx)
				return (TRUE);
			rx = (void *)rx + sizeof(pact_rx_t);
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
	txcache_t **caches;
	size_t num_addresses;
	address_t **addresses;
	public_key_t *feeaddress;
	amount_t amount;

	amount = block_reward(block->index);

	if (block->pacts[0])
		FAIL(EX_SOFTWARE, "new block %ju: pact 0 already filled",
			block->index);

	wallet = wallets()[0];
	addresses = wallet_addresses(wallet, &num_addresses);

	feeaddress = (void *)address_public_key(addresses[0]);

	t = pact_create();

	if ((caches = txcaches_for_address(addresses[0], &tsize))) {
		for (size_t i = 0; i < tsize; i++) {
			if (!cache_in_pacts(caches[i],
			    block->pacts, block->num_pacts) &&
			    !cache_in_raw_pacts(caches[i], rt, nrt)) {
				pact_rx_add(t,
					be64toh(caches[i]->block_idx),
					be32toh(caches[i]->block_tx_idx));
				amount += be64toh(caches[i]->tx.amount);
			}
		}

		free(caches);
	}

	pact_tx_add(t, (void *)feeaddress, amount);
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

int
raw_block_validate(raw_block_t *raw_block, size_t blocksize)
{
	int err;
	void *ctx;
	hash_t pbh;
	big_idx_t idx;
	signature_t sig;
	size_t tbs, size, scount;
	raw_pact_t *t, *tt;

	// check block size
	if (blocksize < sizeof(raw_block_t) + sizeof(raw_pact_t) +
		sizeof(pact_tx_t)) {
		lprintf("block with index %ju smaller than block skeleton: %d",
			block_idx(raw_block), blocksize);
		return (FALSE);
	}
	size = raw_block_size(raw_block, blocksize);
	if (blocksize != size) {
		lprintf("block with index %ju has illegal size: %d vs %d",
			block_idx(raw_block), size, blocksize);
		return (FALSE);
	}

	// check block index
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
		blockchain_set_updating(0);
		return (FALSE);
	}

	// check prev block hash
	raw_block_hash(__raw_block_last, __raw_block_last_size, pbh);
	if (bcmp(pbh, raw_block->prev_block_hash, sizeof(hash_t)) != 0) {
		lprintf("gotten block with illegal prev_block_hash, index %ju",
			block_idx(raw_block));
		return (FALSE);
	}

	// check notar
	if (pubkey_compare(notar_next(), raw_block->notar) != 0) {
		lprintf("illegal notar for block index %ju",
			block_idx(raw_block));
		return (FALSE);
	}

	// check signature
	bcopy(raw_block->signature, sig, sizeof(signature_t));
	bzero(raw_block->signature, sizeof(signature_t));
	ctx = keypair_verify_start(raw_block, blocksize);
	if (!keypair_verify_finalize(ctx, raw_block->notar, sig)) {
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
		switch (err) {
		case 0: break;
		case ERR_TX_SPENT:
			lprintf("processing block %ju, pact %u: "
        			"tx unknown or already spent", idx, ti);
			return (FALSE);
		case ERR_BADSIG:
			lprintf("processing block %ju, pact %u: "
        			"bad signature in rx", idx, ti);
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
        			"rx overlap %d times", idx, ti, scount);
			return (FALSE);
		}

		tbs -= size;
		t = (void *)t + size;
	}

	return (TRUE);
}

void
raw_block_process(raw_block_t *raw_block, size_t blocksize)
{
	raw_pact_t *t;
	size_t size;

	if (pubkey_compare(node_public_key(), raw_block->notar) != 0) {
		txcache_raw_block_add(raw_block);
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
	time64_t tm;
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

	tm = time(NULL);

	rtl = pacts_pending(&rts);

	add_notar_reward(block, rtl, rts);

	for (small_idx_t ti = 0; ti < block->num_pacts; ti++) {
		t = block->pacts[ti];
		size = sizeof(raw_pact_t);
		size += t->num_rx * sizeof(pact_rx_t);
		size += t->num_tx * sizeof(pact_tx_t);
		if (bs + size > MAXPACKETSIZE)
			break;
		bs += size;
		max_tr++;
	}
	for (small_idx_t ti = 0; ti < rts; ti++) {
		rt = rtl[ti];
//		if (be64toh(rt->time) < tm) {
			size = sizeof(raw_pact_t);
			size += be32toh(rt->num_rx) * sizeof(pact_rx_t);
			size += be32toh(rt->num_tx) * sizeof(pact_tx_t);
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
		for (small_idx_t ri = 0; ri < be32toh(t->num_rx); ri++) {
			bcopy(t->rx[ri], curbuf, sizeof(pact_rx_t));
			curbuf += sizeof(pact_rx_t);
		}
		for (small_idx_t ti = 0; ti < be32toh(t->num_tx); ti++) {
			bcopy(t->tx[ti], curbuf, sizeof(pact_tx_t));
			curbuf += sizeof(pact_tx_t);
		}
	}

	for (small_idx_t ti = 0; ti < max_rtr; ti++) {
		rt = rtl[ti];
//		if (be64toh(rt->time) < tm) {
			size = sizeof(raw_pact_t);
			size += be32toh(rt->num_rx) * sizeof(pact_rx_t) +
				be32toh(rt->num_tx) * sizeof(pact_tx_t);
			bcopy(rt, curbuf, size);
			curbuf += size;
//		}
	}

	txcache_raw_block_add(res);
	notar_raw_block_add(res);

	cache_hash(res->cache_hash);

	bzero(res->signature, sizeof(signature_t));
	raw_block_sign(res, bs, signature);
	bcopy(signature, res->signature, sizeof(signature_t));

	*blocksize = bs;

	return (res);
}

uint8_t *
public_key_find_by_tx_idx(raw_block_t *block, small_idx_t tx_idx)
{
	void *buf;
	raw_pact_t *t;
	small_idx_t ntx = 0;

	buf = raw_block_pacts(block);
	for (small_idx_t ti = 0; ti < num_pacts(block); ti++) {
		t = (void *)buf;
		buf += sizeof(raw_pact_t);
		buf += sizeof(pact_rx_t) * be32toh(t->num_rx);
		if (ntx + pact_num_tx(t) <= tx_idx) {
			ntx += pact_num_tx(t);
			buf += sizeof(pact_tx_t) * pact_num_tx(t);
			continue;
		}
		buf += sizeof(pact_tx_t) * (tx_idx - ntx);

		return ((pact_tx_t *)buf)->address;
	}

	return (NULL);
}

raw_pact_t *
pact_for_tx_idx(raw_block_t *block, small_idx_t tx_idx)
{
	raw_pact_t *t;
	small_idx_t ntx = 0;

	t = raw_block_pacts(block);
	for (small_idx_t ti = 0; ti < num_pacts(block); ti++) {
		if (tx_idx <= ntx + pact_num_tx(t))
			return (t);

		ntx += pact_num_tx(t);
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
	free(block);
#ifdef DEBUG_ALLOC
	printf("-BLOCK %p\n", block);
#endif
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

void
raw_block_print(raw_block_t *raw_block)
{
	small_idx_t rx_num, tx_num;
	address_name_t addr_name;
	node_name_t node_name;
	raw_pact_t *t;
	small_hash_t thash;
	pact_rx_t *rx;
	pact_tx_t *tx;
	time_t tm;

	tm = (time_t)be64toh(raw_block->time);
	printf("---\nresult:\n");
	printf("  index: %ju\n", block_idx(raw_block));
	printf("  time: %ju %s", be64toh(raw_block->time), ctime(&tm));
	printf("  flags: %ju", be64toh(raw_block->flags));
	if (be64toh(raw_block->flags) & BLOCK_FLAG_NEW_NOTAR)
		printf(" BLOCK_FLAG_NEW_NOTAR");
	printf("\n");
	printf("  prev_block_hash: ");
	for (size_t i = 0; i < sizeof(hash_t); i++)
		printf("%02x", raw_block->prev_block_hash[i]);
	printf("\n");
	public_key_node_name(raw_block->notar, node_name);
	printf("  notar: %s\n", node_name);
	if (be64toh(raw_block->flags) & BLOCK_FLAG_NEW_NOTAR) {
		public_key_node_name((void *)raw_block + sizeof(raw_block_t),
			node_name);
		printf("  new_notar: %s\n", node_name);
	}
	printf("  signature: ");
	for (size_t i = 0; i < sizeof(signature_t); i++)
		printf("%02x", raw_block->signature[i]);
	printf("\n");
	printf("  cache_hash: ");
	for (size_t i = 0; i < sizeof(hash_t); i++)
		printf("%02x", raw_block->cache_hash[i]);
	printf("\n");
	printf("  num_pacts: %d\n", num_pacts(raw_block));
	printf("  pacts:\n");
	t = raw_block_pacts(raw_block);
	
	for (small_idx_t i = 0; i < num_pacts(raw_block); i++) {
		pact_hash(t, thash);
		rx_num = pact_num_rx(t);
		tx_num = pact_num_tx(t);
		rx = (void *)t + sizeof(raw_pact_t);
		printf("    - pact_hash: ");
		for (size_t i = 0; i < sizeof(small_hash_t); i++)
			printf("%02x", thash[i]);
		printf("\n");
		
		printf("      rx:%s\n", rx_num ? "" : " []");
		for (small_idx_t ri = 0; ri < rx_num; ri++) {
			printf("        - block_idx: %ju\n",
				be64toh(rx->block_idx));
			printf("          block_tx_idx: %d\n",
				be32toh(rx->block_tx_idx));
			printf("          signature: ");
			for (size_t i = 0; i < sizeof(signature_t); i++)
				printf("%02x", rx->signature[i]);
			printf("\n");
			rx = (void *)rx + sizeof(pact_rx_t);
		}
		tx = (void *)rx;
		printf("      tx:\n");
		for (small_idx_t ti = 0; ti < tx_num; ti++) {
			public_key_address_name(tx->address, addr_name);
			printf("        - address: %s\n", addr_name);
			printf("          amount: %2.2f\n",
				stoi(be64toh(tx->amount)));
			tx = (void *)tx + sizeof(pact_tx_t);
		}
		t = (void *)tx;
	}
}

void
raw_block_broadcast(big_idx_t index)
{
	raw_block_t *block;
	size_t size;

	block = block_load(index, &size);
	message_broadcast(OP_BLOCK_ANNOUNCE, block, size, htobe64(index));
}

static void
__blockchain_update(event_info_t *info, event_flags_t eventflags)
{
	blockchain_update();
}

void
blockchain_update()
{
	event_info_t *info;
	char tmp[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;

	peer_address_random(&addr);
	lprintf("asking peer %s for last block...", peername(&addr, tmp));
	info = message_send(&addr, OP_LASTBLOCKINFO, NULL, 0, 0);

	if (info)
		info->on_close = __blockchain_update;
	else
		blockchain_update();
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
getblocks(big_idx_t target_idx)
{
	big_idx_t cur_idx;

	if (target_idx)
		__getblocks_target_idx = target_idx;

	cur_idx = block_idx_last();
	if (cur_idx >= __getblocks_target_idx) {
		__getblocks_target_idx = 0;
		blockchain_update();
		return;
	}

	cur_idx++;
	getblock(cur_idx);
}
