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
#include "rxcache.h"
#include "pact.h"

static raw_pact_t **__pending_pacts;
static small_idx_t __pending_pacts_size = 0;

static pact_t *
pact_alloc(void)
{
	pact_t *res;

	res = malloc(sizeof(pact_t));
#ifdef DEBUG_ALLOC
	lprintf("+PACT %p", res);
#endif

	res->time = time(NULL);
	res->flags = PACT_TYPE_RTX | PACT_VERSION_1;
	res->num_tx = res->num_rx = 0;
	res->tx = malloc(sizeof(pact_tx_t *) * 10);
	res->rx = malloc(sizeof(pact_rx_t *) * 10);

	return (res);
}

pact_t *
pact_create(void)
{
	return (pact_alloc());
}

int
pact_tx_add(pact_t *pact, big_idx_t block_idx, small_idx_t rx_idx)
{
	pact_tx_t *tx;

	// check validity of block & rx idx

	if (pact->num_tx % 10 == 0)
		pact->tx = realloc(pact->tx,
			sizeof(pact_tx_t *) * pact->num_tx + 10);
	tx = malloc(sizeof(pact_tx_t));
	tx->block_idx = block_idx;
	tx->block_rx_idx = rx_idx;
	bzero(tx->signature, sizeof(signature_t));
	pact->tx[pact->num_tx] = tx;
	pact->num_tx += 1;

	return (1);
}

void
pact_rx_add(pact_t *pact, public_key_t rx_public_key, amount_t amount)
{
	pact_rx_t *rx;

	if (pact->num_rx % 10 == 0)
		pact->rx = realloc(pact->rx,
			sizeof(pact_rx_t *) * pact->num_rx + 10);
	rx = malloc(sizeof(pact_rx_t));
	bcopy(rx_public_key, rx->address, sizeof(public_key_t));
	rx->amount = amount;
	pact->rx[pact->num_rx] = rx;
	pact->num_rx += 1;
}

void
pact_finalize(pact_t *pact)
{
	big_idx_t idx;
	pact_tx_t *tx;
	pact_rx_t *rx;
	rxcache_t *rxc;
	address_t *addr;
	small_idx_t rxidx;
	keypair_t *addr_kp;
	address_name_t addr_name;

	for (small_idx_t i = 0; i < pact->num_rx; i++) {
		rx = pact->rx[i];
		rx->amount = htobe64(rx->amount);
	}
	for (small_idx_t ri = 0; ri < pact->num_tx; ri++) {
		tx = pact->tx[ri];

		idx = tx->block_idx;
		rxidx = tx->block_rx_idx;

		if (!(rxc = rxcache_for_idxs(idx, rxidx)))
			FAIL(EX_SOFTWARE, "finalize_pact: "
		     		"rxcache not found: block idx %ju, rx idx %d\n",
				idx, rxidx);
		if (!(addr = address_find_by_public_key(rxc->rx.address)))
			FAIL(EX_SOFTWARE, "finalize_pact: address "
			     "not found for public key: %s\n",
			     public_key_address_name(rxc->rx.address,
				addr_name));
		addr_kp = address_keypair(addr);

		keypair_sign_start(addr_kp, NULL, 0);
		keypair_sign_update(addr_kp, &idx, sizeof(big_idx_t));
		keypair_sign_update(addr_kp, &rxidx, sizeof(small_idx_t));
		for (small_idx_t ti = 0; ti < pact->num_rx; ti++) {
			rx = pact->rx[ti];
			keypair_sign_update(addr_kp, rx, sizeof(pact_rx_t));
		}
		keypair_sign_finalize(addr_kp, tx->signature);
	}
	for (small_idx_t i = 0; i < pact->num_tx; i++) {
		tx = pact->tx[i];
		tx->block_idx = tx->block_idx;
		tx->block_rx_idx = tx->block_rx_idx;
	}

	pact->time = htobe64(pact->time);
	pact->flags = htobe64(pact->flags);
	pact->num_tx = htobe32(pact->num_tx);
	pact->num_rx = htobe32(pact->num_rx);
}

static raw_pact_t *
raw_pact_alloc(pact_t *t, size_t *size)
{
	raw_pact_t *res;

	*size = sizeof(raw_pact_t) +
		sizeof(pact_tx_t) * be32toh(t->num_tx) +
		sizeof(pact_rx_t) * be32toh(t->num_rx);
	res = malloc(*size);
#ifdef DEBUG_ALLOC
	lprintf("+RAWPACT %p", res);
#endif

	return (res);
}

void
raw_pact_free(raw_pact_t *raw_pact)
{
#ifdef DEBUG_ALLOC
	lprintf("-RAWPACT %p", raw_pact);
#endif
	free(raw_pact);
}

raw_pact_t *
raw_pact_create(pact_t *t, size_t *size)
{
	raw_pact_t *res;
	uint8_t *buf;

	res = raw_pact_alloc(t, size);
	buf = (uint8_t *)res;

	bcopy(t, buf, sizeof(raw_pact_t));
	buf += sizeof(raw_pact_t);
	for (small_idx_t ri = 0; ri < be32toh(t->num_tx); ri++) {
		bcopy(t->tx[ri], buf, sizeof(pact_tx_t));
		buf += sizeof(pact_tx_t);
	}
	for (small_idx_t ti = 0; ti < be32toh(t->num_rx); ti++) {
		bcopy(t->rx[ti], buf, sizeof(pact_rx_t));
		buf += sizeof(pact_rx_t);
	}

	return (res);
}

void
pact_free(pact_t *pact)
{
	for (small_idx_t i = 0; i < be32toh(pact->num_tx); i++)
		free(pact->tx[i]);
	for (small_idx_t i = 0; i < be32toh(pact->num_rx); i++)
		free(pact->rx[i]);
	free(pact->tx);
	free(pact->rx);
#ifdef DEBUG_ALLOC
	lprintf("-PACT %p", pact);
#endif
	free(pact);
}

static int
pact_tx_pending(raw_pact_t *t)
{
	raw_pact_t *pt;
	pact_tx_t *ttx, *pttx;

	for (small_idx_t i = 0; i < __pending_pacts_size; i++) {
		if (!(pt = __pending_pacts[i]))
			continue;

		ttx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t ntx = 0; ntx < be32toh(t->num_tx); ntx++) {
			pttx = (void *)pt + sizeof(raw_pact_t);
			for (small_idx_t ptx = 0; ptx < be32toh(pt->num_tx); ptx++) {
				if (ttx->block_idx == pttx->block_idx &&
				    ttx->block_rx_idx == pttx->block_rx_idx)
					return (TRUE);

				pttx = (void *)pttx + sizeof(pact_tx_t);
			}
			ttx = (void *)ttx + sizeof(pact_tx_t);
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
		__pending_pacts = calloc(1, sizeof(raw_pact_t *) *
			__pending_pacts_size);
	}

	if (pact_tx_pending(pact))
		return (ERR_RX_PENDING);

	for (i = 0; i < __pending_pacts_size; i++)
		if (!__pending_pacts[i])
			break;

	if (i == __pending_pacts_size) {
		__pending_pacts_size += 10;
		__pending_pacts = realloc(__pending_pacts,
			sizeof(raw_pact_t *) * __pending_pacts_size);
		for (small_idx_t n = i; n < __pending_pacts_size; n++)
			__pending_pacts[n] = NULL;
	}

	__pending_pacts[i] = pact;

	return (NO_ERR);
}

void
pact_pending_remove(raw_pact_t *t)
{
	pact_tx_t *ttx, *ptx;
	raw_pact_t *pt;
	int remove;

int q = 0;
	for (small_idx_t i = 0; i < __pending_pacts_size; i++) {
		if (!(pt = __pending_pacts[i]))
			continue;
q++;

		remove = 0;

		ttx = (void *)t + sizeof(raw_pact_t);
		for (small_idx_t tri = 0; tri < pact_num_tx(t); tri++) {
			ptx = (void *)pt + sizeof(raw_pact_t);
			for (small_idx_t pri = 0; pri < pact_num_tx(pt); pri++){
				if (ttx->block_idx == ptx->block_idx &&
				    ttx->block_rx_idx == ptx->block_rx_idx) {
					remove = 1;
					continue;
				}
				ptx = (void *)ptx + sizeof(pact_tx_t);
			}
			ttx = (void *)ttx + sizeof(pact_tx_t);
		}

		if (remove) {
#ifdef DEBUG_ALLOC
			lprintf("-RAWPACT %p", pt);
#endif
			__pending_pacts[i] = NULL;
			free(pt);
		}
	}
if (q) lprintf("PENDINGPACTS: %d", q);
}

int
has_pending_pacts(void)
{
	time64_t tm;

	tm = time(NULL);

	for (small_idx_t i = 0; i < __pending_pacts_size; i++)
		if (__pending_pacts[i])
			if (__pending_pacts[i]->time <= tm)
				return (TRUE);

	return (FALSE);
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
// TODO fix this...	__pending_pacts[j] = __pending_pacts[i];
			j++;
		}
	}

	*size = s;

	return (__pending_pacts);
}

static int
raw_pact_balance(raw_pact_t *pact, amount_t *rcv, amount_t *snd)
{
	rxcache_t *cache;
	size_t rxsize;
	pact_tx_t *tx;
	pact_rx_t *rx;
	void *crx;

	*rcv = *snd = 0;
	tx = pact_tx_ptr(pact);
	rx = pact_rx_ptr(pact);
	rxsize = pact_rx_size(pact);
	for (small_idx_t ri = 0; ri < pact_num_tx(pact); ri++) {
		if (!(cache = rxcache_for_idxs(tx->block_idx,
			tx->block_rx_idx)))
			return (ERR_RX_SPENT);

		crx = keypair_verify_start(NULL, 0);
		keypair_verify_update(crx, &tx->block_idx, sizeof(big_idx_t));
		keypair_verify_update(crx, &tx->block_rx_idx,
			sizeof(small_idx_t));
		keypair_verify_update(crx, rx, rxsize);
		if (!keypair_verify_finalize(crx, cache->rx.address,
			tx->signature))
			return (ERR_BADSIG);

		*snd += be64toh(cache->rx.amount);

		tx = (void *)tx + sizeof(pact_tx_t);
	}
	for (small_idx_t ti = 0; ti < pact_num_rx(pact); ti++) {
		*rcv += be64toh(rx->amount);
		rx = (void *)rx + sizeof(pact_rx_t);
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
	crypto_generichash_state crx;
	size_t size, offset;

	size = pact_size(t) - sizeof(small_hash_t);

	offset = sizeof(time64_t);
	crypto_generichash_init(&crx, NULL, 0, sizeof(small_hash_t));
	crypto_generichash_update(&crx, (void *)t + offset, size);
	crypto_generichash_final(&crx, hash, sizeof(small_hash_t));

	return (hash);
}

int
pact_delay(raw_pact_t *rt, int nesting)
{
	raw_pact_t *nrt;
	raw_block_t *b;
	pact_tx_t *tx;
	big_idx_t lbi;
	big_idx_t idx;
	int delay = 0;
	int res = 0;
	size_t bs;

	if (nesting >= 9)
		return (0);

	lbi = block_idx_last();
	tx = (void *)rt + sizeof(raw_pact_t);
	for (small_idx_t i = 0; i < be32toh(rt->num_tx); i++) {
		idx = be64toh(tx->block_idx);
		if (lbi - idx < 10 + nesting * 2) {
			delay = 10 - (lbi - idx);
			res = MAX(res, delay);

			b = block_load(be64toh(tx->block_idx), &bs);
			nrt = pact_for_rx_idx(b, be32toh(tx->block_rx_idx));
			res += pact_delay(nrt, nesting + 1);
		}

		tx = (void *)tx + sizeof(pact_tx_t);
	}

return 0;
	return (res / 5);
}

int
pacts_overlap(raw_pact_t *t1, raw_pact_t *t2)
{
	pact_tx_t *tx1, *tx2;

	tx1 = pact_tx_ptr(t1);
	for (small_idx_t ri1 = 0; ri1 < pact_num_tx(t1); ri1++) {
		tx2 = pact_tx_ptr(t2);
		for (small_idx_t ri2 = 0; ri2 < pact_num_tx(t2); ri2++) {
			if (tx1->block_idx == tx2->block_idx &&
			    tx1->block_rx_idx == tx2->block_rx_idx)
				return (TRUE);

			tx2 = (void *)tx2 + sizeof(pact_tx_t);
		}
		tx1 = (void *)tx1 + sizeof(pact_tx_t);
	}

	return (FALSE);
}
