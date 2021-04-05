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
#include "block.h"
#include "error.h"
#include "config.h"
#include "wallet.h"
#include "txcache.h"
#include "pact.h"

static raw_pact_t **__pending_pacts;
static small_idx_t __pending_pacts_size = 0;

static pact_t *
pact_alloc(void)
{
	pact_t *res;

	res = malloc(sizeof(pact_t));
#ifdef DEBUG_ALLOC
	printf("+PACT %p\n", res);
#endif

	res->time = time(NULL);
	res->flags = PACT_TYPE_RX_TX | PACT_VERSION_1;
	res->num_rx = res->num_tx = 0;
	res->rx = malloc(sizeof(pact_rx_t *) * 10);
	res->tx = malloc(sizeof(pact_tx_t *) * 10);

	return (res);
}

pact_t *
pact_create(void)
{
	return (pact_alloc());
}

int
pact_rx_add(pact_t *pact, big_idx_t block_idx, small_idx_t tx_idx)
{
	pact_rx_t *rx;

	// check validity of block & tx idx

	if (pact->num_rx % 10 == 0)
		pact->rx = realloc(pact->rx,
			sizeof(pact_rx_t *) * pact->num_rx + 10);
	rx = malloc(sizeof(pact_rx_t));
	rx->block_idx = block_idx;
	rx->block_tx_idx = tx_idx;
	bzero(rx->signature, sizeof(signature_t));
	pact->rx[pact->num_rx] = rx;
	pact->num_rx += 1;

	return (1);
}

void
pact_tx_add(pact_t *pact, public_key_t tx_public_key, amount_t amount)
{
	pact_tx_t *tx;

	if (pact->num_tx % 10 == 0)
		pact->tx = realloc(pact->tx,
			sizeof(pact_tx_t *) * pact->num_tx + 10);
	tx = malloc(sizeof(pact_tx_t));
	bcopy(tx_public_key, tx->address, sizeof(public_key_t));
	tx->amount = amount;
	pact->tx[pact->num_tx] = tx;
	pact->num_tx += 1;
}

void
pact_finalize(pact_t *pact)
{
	size_t sz;
	big_idx_t idx;
	pact_rx_t *rx;
	pact_tx_t *tx;
	raw_block_t *b;
	address_t *addr;
	small_idx_t txidx;
	keypair_t *addr_kp;
	address_name_t addr_name;
	public_key_t *addr_pubkey;

	for (small_idx_t i = 0; i < pact->num_tx; i++) {
		tx = pact->tx[i];
		tx->amount = htobe64(tx->amount);
	}
	for (small_idx_t ri = 0; ri < pact->num_rx; ri++) {
		rx = pact->rx[ri];
		if (!(b = block_load(rx->block_idx, &sz)))
			FAIL(EX_SOFTWARE, "finalize_pact: "
			     "block not found: %ld\n", rx->block_idx);
		if (!(addr_pubkey = (void *)public_key_find_by_tx_idx(b, rx->block_tx_idx)))
			FAIL(EX_SOFTWARE, "finalize_pact: block %ld: "
			     "tx_idx not found: %d\n",
			     rx->block_idx, rx->block_tx_idx);
		if (!(addr = address_find_by_public_key(*addr_pubkey)))
			FAIL(EX_SOFTWARE, "finalize_pact: address "
			     "not found for public key: %s\n",
			     public_key_address_name(*addr_pubkey, addr_name));
		addr_kp = address_keypair(addr);

		idx = be64toh(rx->block_idx);
		txidx = be32toh(rx->block_tx_idx);
		keypair_sign_start(addr_kp, NULL, 0);
		keypair_sign_update(addr_kp, &idx, sizeof(big_idx_t));
		keypair_sign_update(addr_kp, &txidx, sizeof(small_idx_t));
		for (small_idx_t ti = 0; ti < pact->num_tx; ti++) {
			tx = pact->tx[ti];
			keypair_sign_update(addr_kp, tx, sizeof(pact_tx_t));
		}
		keypair_sign_finalize(addr_kp, rx->signature);
	}
	for (small_idx_t i = 0; i < pact->num_rx; i++) {
		rx = pact->rx[i];
		rx->block_idx = htobe64(rx->block_idx);
		rx->block_tx_idx = htobe32(rx->block_tx_idx);
	}

	pact->time = htobe64(pact->time);
	pact->flags = htobe64(pact->flags);
	pact->num_rx = htobe32(pact->num_rx);
	pact->num_tx = htobe32(pact->num_tx);
}

static raw_pact_t *
raw_pact_alloc(pact_t *t, size_t *size)
{
	raw_pact_t *res;

	*size = sizeof(raw_pact_t) +
		sizeof(pact_rx_t) * be32toh(t->num_rx) +
		sizeof(pact_tx_t) * be32toh(t->num_tx);
	res = malloc(*size);
#ifdef DEBUG_ALLOC
	printf("+RAWPACT %p\n", res);
#endif

	return (res);
}

void
raw_pact_free(raw_pact_t *raw_pact)
{
	free(raw_pact);
#ifdef DEBUG_ALLOC
	printf("-RAWPACT %p\n", raw_pact);
#endif
}

raw_pact_t *
raw_pact_create(pact_t *t, size_t *size)
{
	raw_pact_t *res;
	size_t sz;
	void *buf;

	res = raw_pact_alloc(t, size);
	sz = *size;
	buf = res;

	bcopy(t, buf, sizeof(raw_pact_t));
	buf += sizeof(raw_pact_t);
	for (small_idx_t ri = 0; ri < be32toh(t->num_rx); ri++) {
		bcopy(t->rx[ri], buf, sizeof(pact_rx_t));
		buf += sizeof(pact_rx_t);
	}
	for (small_idx_t ti = 0; ti < be32toh(t->num_tx); ti++) {
		bcopy(t->tx[ti], buf, sizeof(pact_tx_t));
		buf += sizeof(pact_tx_t);
	}

	return (res);
}

void
pact_free(pact_t *pact)
{
	for (small_idx_t i = 0; i < be32toh(pact->num_rx); i++)
		free(pact->rx[i]);
	for (small_idx_t i = 0; i < be32toh(pact->num_tx); i++)
		free(pact->tx[i]);
	free(pact->rx);
	free(pact->tx);
	free(pact);
#ifdef DEBUG_ALLOC
	printf("-PACT %p\n", pact);
#endif
}

static int
pact_rx_pending(raw_pact_t *t)
{
	raw_pact_t *pt;
	pact_rx_t *trx, *ptrx;

	for (small_idx_t i = 0; i < __pending_pacts_size; i++) {
		if (!(pt = __pending_pacts[i]))
			continue;

		trx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t nrx = 0; nrx < be32toh(t->num_rx); nrx++) {
			ptrx = (void *)pt + sizeof(raw_pact_t);
			for (small_idx_t prx = 0; prx < be32toh(pt->num_rx); prx++) {
				if (trx->block_idx == ptrx->block_idx &&
				    trx->block_tx_idx == ptrx->block_tx_idx)
					return (TRUE);

				ptrx = (void *)ptrx + sizeof(pact_rx_t);
			}
			trx = (void *)trx + sizeof(pact_rx_t);
		}
	}

	return (FALSE);
}

int
pact_pending_add(raw_pact_t *pact)
{
	small_idx_t i;

	if (!__pending_pacts_size) {
		__pending_pacts_size = 10;
		__pending_pacts = calloc(1, sizeof(raw_pact_t) * __pending_pacts_size);
	}

	if (pact_rx_pending(pact))
		return (ERR_TX_PENDING);

	for (i = 0; i < __pending_pacts_size; i++)
		if (!__pending_pacts[i])
			break;

	if (i == __pending_pacts_size) {
		__pending_pacts_size += 10;
		__pending_pacts = realloc(__pending_pacts,
			sizeof(raw_pact_t) * __pending_pacts_size);
		for (small_idx_t n = i; n < __pending_pacts_size; n++)
			__pending_pacts[n] = NULL;
	}

	__pending_pacts[i] = pact;
	__pending_pacts_size++;

	return (NO_ERR);
}

void
pact_pending_remove(raw_pact_t *t)
{
	raw_pact_t *pt;
	pact_rx_t *trx, *prx;

	for (small_idx_t i = 0; i < __pending_pacts_size; i++) {
		if (!(pt = __pending_pacts[i]))
			continue;

		trx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t tri = 0; tri < be32toh(t->num_rx); tri++) {
			prx = (void *)pt + sizeof(raw_pact_t);
			for (small_idx_t pri = 0; pri < be32toh(pt->num_rx); pri++) {
				if (trx->block_idx == prx->block_idx &&
				    trx->block_tx_idx == prx->block_tx_idx) {
					__pending_pacts[i] = NULL;
					continue;
				}
				prx = (void *)prx + sizeof(pact_rx_t);
			}
			trx = (void *)trx + sizeof(pact_rx_t);
		}
	}
}

int
has_pending_pacts(void)
{
	return (__pending_pacts_size > 0);
}

raw_pact_t **
pacts_pending(small_idx_t *size)
{
	small_idx_t s;
	small_idx_t j;

	if (!__pending_pacts) {
		*size = 0;
		return (NULL);
	}

	j = s = 0;
	for (small_idx_t i = 0; i < __pending_pacts_size; i++) {
		if (__pending_pacts[i]) {
			s++;
			__pending_pacts[j] = __pending_pacts[i];
			j++;
		}
	}

	*size = s;

	return (__pending_pacts);
}

static int
raw_pact_balance(raw_pact_t *pact, amount_t *rcv, amount_t *snd)
{
	txcache_t *cache;
	size_t txsize;
	pact_rx_t *rx;
	pact_tx_t *tx;
	void *ctx;

	*rcv = *snd = 0;
	rx = pact_rx_ptr(pact);
	tx = pact_tx_ptr(pact);
	txsize = pact_tx_size(pact);
	for (small_idx_t ri = 0; ri < pact_num_rx(pact); ri++) {
		if (!(cache = txcache_for_idxs(rx->block_idx,
			rx->block_tx_idx)))
			return (ERR_TX_SPENT);

		ctx = keypair_verify_start(NULL, 0);
		keypair_verify_update(ctx, &rx->block_idx, sizeof(big_idx_t));
		keypair_verify_update(ctx, &rx->block_tx_idx,
			sizeof(small_idx_t));
		keypair_verify_update(ctx, tx, txsize);
		if (!keypair_verify_finalize(ctx, cache->tx.address,
			rx->signature))
			return (ERR_BADSIG);

		*snd += be64toh(cache->tx.amount);

		rx = (void *)rx + sizeof(pact_rx_t);
	}
	for (small_idx_t ti = 0; ti < pact_num_tx(pact); ti++) {
		*rcv += be64toh(tx->amount);
		tx = (void *)tx + sizeof(pact_tx_t);
	}

	return (NO_ERR);
}

int
raw_pact_notar_reward_validate(raw_pact_t *pact, big_idx_t block_idx)
{
	amount_t rcv, snd;
	int res;

	if ((res = raw_pact_balance(pact, &rcv, &snd)) != NO_ERR)
		return (res);

	return (rcv - snd == block_reward(block_idx) ? NO_ERR : ERR_BADBALANCE);
}

int
raw_pact_validate(raw_pact_t *pact)
{
	amount_t rcv, snd;
	int res;

	if ((res = raw_pact_balance(pact, &rcv, &snd)) != NO_ERR)
		return (res);

	return (rcv == snd ? NO_ERR : ERR_BADBALANCE);
}

void *
pact_hash(raw_pact_t *t, void *hash)
{
	crypto_generichash_state ctx;
	size_t size, offset;

	size = pact_size(t) - sizeof(small_hash_t);

	offset = sizeof(time64_t);
	crypto_generichash_init(&ctx, NULL, 0, sizeof(small_hash_t));
	crypto_generichash_update(&ctx, (void *)t + offset, size);
	crypto_generichash_final(&ctx, hash, sizeof(small_hash_t));

	return (hash);
}

int
pact_delay(raw_pact_t *rt, int nesting)
{
	raw_pact_t *nrt;
	raw_block_t *b;
	pact_rx_t *rx;
	big_idx_t lbi;
	big_idx_t idx;
	int delay = 0;
	int res = 0;
	size_t bs;

	if (nesting >= 9)
		return (0);

	lbi = block_idx_last();
	rx = (void *)rt + sizeof(raw_pact_t);
	for (small_idx_t i = 0; i < be32toh(rt->num_rx); i++) {
		idx = be64toh(rx->block_idx);
		if (lbi - idx < 10 + nesting * 2) {
			delay = 10 - (lbi - idx);
			res = MAX(res, delay);

			b = block_load(be64toh(rx->block_idx), &bs);
			nrt = pact_for_tx_idx(b, be32toh(rx->block_tx_idx));
			res += pact_delay(nrt, nesting + 1);
		}

		rx = (void *)rx + sizeof(pact_rx_t);
	}

	return (res / 5);
}

int
pacts_overlap(raw_pact_t *t1, raw_pact_t *t2)
{
	pact_rx_t *rx1, *rx2;

	rx1 = pact_rx_ptr(t1);
	for (small_idx_t ri1 = 0; ri1 < pact_num_rx(t1); ri1++) {
		rx2 = pact_rx_ptr(t2);
		for (small_idx_t ri2 = 0; ri2 < pact_num_rx(t2); ri2++) {
			if (rx1->block_idx == rx2->block_idx &&
			    rx1->block_tx_idx == rx2->block_tx_idx)
				return (TRUE);

			rx2 = (void *)rx2 + sizeof(pact_rx_t);
		}
		rx1 = (void *)rx1 + sizeof(pact_rx_t);
	}

	return (FALSE);
}
