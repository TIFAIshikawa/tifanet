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

#ifndef __TIFA_PACT_H
#define __TIFA_PACT_H

#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include "config.h"
#include "keypair.h"

typedef struct __attribute__((__packed__)) __pact_tx {
	big_idx_t block_idx;
	small_idx_t block_rx_idx;
	signature_t signature; // over this tx and all rx records
} pact_tx_t;

typedef struct __attribute__((__packed__)) __pact_rx {
	public_key_t address;
	amount_t amount;
} pact_rx_t;

enum pact_flags {
	PACT_TYPE_RTX	= (1LL << 0),
	PACT_VERSION_1	= (1LL << 32)
};

typedef struct __attribute__((__packed__)) __raw_pact {
	time64_t time;
	flags_t flags;
	small_idx_t num_tx;
	small_idx_t num_rx;
	// tx & rx after here...
} raw_pact_t;

typedef struct __attribute__((__packed__)) __pact {
	time64_t time;
	flags_t flags;
	small_idx_t num_tx;
	small_idx_t num_rx;
	pact_tx_t **tx;
	pact_rx_t **rx;
} pact_t;

extern pact_t *pact_create(void);

extern int pact_tx_add(pact_t *pact, big_idx_t block_idx, small_idx_t rx_idx);
extern void pact_rx_add(pact_t *pact, public_key_t rx_public_key, amount_t amount);
extern void pact_finalize(pact_t *pact);

extern raw_pact_t *raw_pact_create(pact_t *pact, size_t *size);
extern void raw_pact_free(raw_pact_t *raw_pact);

extern void pact_free(pact_t *pact);

extern int pact_pending_add(raw_pact_t *pact);
extern void pact_pending_remove(raw_pact_t *pact);
extern int has_pending_pacts(void);
extern raw_pact_t **pacts_pending(small_idx_t *size);

extern int raw_pact_notar_reward_validate(raw_pact_t *pact,
	big_idx_t block_idx);
extern int raw_pact_validate(raw_pact_t *pact);

extern void *pact_hash(raw_pact_t *pact, void *hash);

extern int pact_delay(raw_pact_t *rt, int nesting);

extern int pacts_overlap(raw_pact_t *t1, raw_pact_t *t2);

inline static small_idx_t
pact_num_tx(raw_pact_t *raw_pact)
{
	return (be32toh(raw_pact->num_tx));
}

inline static small_idx_t
pact_num_rx(raw_pact_t *raw_pact)
{
	return (be32toh(raw_pact->num_rx));
}

inline static size_t
pact_tx_size(raw_pact_t *raw_pact)
{
	return (pact_num_tx(raw_pact) * sizeof(pact_tx_t));
}

inline static size_t
pact_rx_size(raw_pact_t *raw_pact)
{
	return (pact_num_rx(raw_pact) * sizeof(pact_rx_t));
}

inline static pact_tx_t *
pact_tx_ptr(raw_pact_t *raw_pact)
{
	return ((void *)raw_pact + sizeof(raw_pact_t));
}

inline static pact_rx_t *
pact_rx_ptr(raw_pact_t *raw_pact)
{
	return ((void *)pact_tx_ptr(raw_pact) + pact_tx_size(raw_pact));
}

inline static size_t
pact_size(raw_pact_t *raw_pact)
{
	return (sizeof(raw_pact_t) + pact_tx_size(raw_pact) +
		pact_rx_size(raw_pact));
}

#endif /* __TIFA_PACT_H */
