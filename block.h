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

#ifndef __TIFA_BLOCK_H
#define __TIFA_BLOCK_H

#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include "peerlist.h"
#include "network.h"
#include "config.h"
#include "pact.h"

enum block_flags {
	BLOCK_FLAG_NEW_NOTAR = (1LL << 0)	// Block introduces new notar
};

typedef struct __attribute__((__packed__)) __raw_block {
	big_idx_t index;
	time64_t time;
	flags_t flags;
	hash_t prev_block_hash;
	public_key_t notar;
	signature_t signature;
	hash_t cache_hash;
	small_idx_t num_banned_notars;
	small_idx_t num_pacts;
	// public_key_t new_notar;
	// pacts & banned notars after here...
} raw_block_t;

typedef struct __attribute__((__packed__)) __block {
	big_idx_t index;
	time64_t time;
	flags_t flags;
	hash_t prev_block_hash;
	public_key_t notar;
	signature_t signature;
	small_idx_t num_banned_notars;
	small_idx_t num_pacts;
	public_key_t new_notar;
	pact_t **pacts;
	ban_message_t **banned_notars;
} block_t;

extern big_idx_t block_idx_last(void);
extern raw_block_t *raw_block_last(size_t *size);

extern raw_block_t *block_load(big_idx_t idx, size_t *size);

extern void block_last_load(void);

extern void block_pacts_add(block_t *block, pact_t **pacts, small_idx_t num_pacts);
extern void block_pact_add(block_t *block, pact_t *pact);

extern uint8_t *public_key_find_by_tx_idx(raw_block_t *block, small_idx_t tx_idx);

extern void raw_block_hash(raw_block_t *block, size_t size, hash_t result);

extern void block_generate_next(void);

extern amount_t block_reward(big_idx_t idx);

extern void raw_block_process(raw_block_t *raw_block, size_t blocksize);

extern size_t raw_block_size(raw_block_t *raw_block, size_t limit);

extern raw_block_t *block_finalize(block_t *block, size_t *blocksize);

extern void block_free(block_t *block);

extern raw_pact_t *raw_block_pacts(raw_block_t *block);
extern raw_pact_t *pact_for_tx_idx(raw_block_t *block, small_idx_t tx_idx);

extern void raw_block_print(raw_block_t *raw_block);

extern void blockchain_update(void);
extern void blockchain_set_updating(int updating);
extern int blockchain_is_updating(void);

extern void getblocks(big_idx_t target_idx);

extern int raw_block_validate(raw_block_t *raw_block, size_t blocksize); 

extern void block_poll_start(void);

inline static int
block_exists(big_idx_t index)
{
	return (index <= block_idx_last());
}

inline static big_idx_t
block_idx(raw_block_t *raw_block)
{
	return (be64toh(raw_block->index));
}

inline static small_idx_t
num_pacts(raw_block_t *raw_block)
{
	return (be32toh(raw_block->num_pacts));
}
#endif /* __TIFA_BLOCK_H */
