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

#ifndef __TIFA_TXCACHE_H
#define __TIFA_TXCACHE_H

#include "pact.h"
#include "block.h"

typedef struct __txcache {
	big_idx_t block_idx;
	small_idx_t block_tx_idx;
	pact_tx_t tx;
} txcache_t;

extern big_idx_t txcache_last_block_idx(void);

extern txcache_t *txcache(big_idx_t *size);

extern void txcache_hash(hash_t result_hash);

extern void txcache_load(void);
extern void txcache_reset(void);

extern void txcache_raw_block_add(raw_block_t *raw_block);

extern txcache_t **txcaches_for_address(address_t *address, size_t *amount);
extern txcache_t *txcache_for_idxs(big_idx_t block_idx, small_idx_t block_tx_idx);

extern int txcache_exists(big_idx_t block_idx, small_idx_t block_tx_idx);
extern void txcache_remove(big_idx_t block_idx, small_idx_t block_tx_idx);

extern amount_t unspent_for_public_key(public_key_t address);

#endif /* __TIFA_TXCACHE_H */
