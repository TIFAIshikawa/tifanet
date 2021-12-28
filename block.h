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

#include "peerlist.h"
#include "network.h"
#include "endian.h"
#include "config.h"
#include "pact.h"

#define SYNCBLOCK 1000

enum block_flags_t {
	BLOCK_FLAG_NEW_NOTAR		= (1LL << 0),	// Block introduces
							// new notar
	BLOCK_FLAG_DENOUNCE_NOTAR	= (1LL << 1),	// Block is trailed by
							// list of denounced
							// notars and respecitve
							// reasons
	BLOCK_FLAG_TIMEOUT		= (1LL << 2)	// Block is special
							// raw_block_timeout
};

typedef struct __attribute__((__packed__)) __raw_block {
	big_idx_t index;
	time64_t time;
	flags_t flags;
	hash_t prev_block_hash;
	public_key_t notar;
	signature_t signature;
	small_idx_t num_banned_notars;
	small_idx_t num_pacts;
	// optional:
	//   hash_t cache_hash; /* every SYNCBLOCK blocks */
	//   public_key_t new_notar; /* optionally every SYNCBLOCK blocks */
	//   raw_pact_t pacts[]; /* >= 1 pacts */
	//   public_key_t denounced_notars[]; /* optional, not used yet */
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
} block_t;

typedef struct __attribute__((__packed__)) __raw_block_timeout {
	big_idx_t index;
	time64_t time;
	flags_t flags;
	hash_t prev_block_hash;
	public_key_t denounced_notar;
	public_key_t notar[2];
	signature_t signature[2];
} raw_block_timeout_t;

extern big_idx_t block_idx_last(void);
extern raw_block_t *raw_block_last(size_t *size);

extern raw_block_t *block_load(big_idx_t idx, size_t *size);
extern raw_block_t *blocks_load(big_idx_t idx, size_t *size,
	big_idx_t max_blocks, size_t max_size);

extern void block_last_load(void);

extern void block_pacts_add(block_t *block, pact_t **pacts,
	small_idx_t num_pacts);
extern void block_pact_add(block_t *block, pact_t *pact);

extern void raw_block_hash(raw_block_t *block, size_t size, hash_t result);

extern void block_generate_next(void);

extern amount_t block_reward(big_idx_t idx);

extern void raw_block_process(raw_block_t *raw_block, size_t blocksize);

extern size_t raw_block_size(raw_block_t *raw_block, size_t limit);

extern raw_block_t *block_finalize(block_t *block, size_t *blocksize);

extern void raw_block_broadcast(big_idx_t index);

extern void block_free(block_t *block);

extern void *raw_block_new_notar(raw_block_t *raw_block);
extern raw_pact_t *raw_block_pacts(raw_block_t *block);
extern pact_rx_t *pact_rx_by_rx_idx(big_idx_t idx, small_idx_t rx_idx);
extern raw_pact_t *pact_for_rx_idx(raw_block_t *block, small_idx_t rx_idx);

extern void raw_block_print(raw_block_t *raw_block);
extern void raw_block_fprint(FILE *f, raw_block_t *raw_block);

extern void blockchain_load(void);
extern void blockchain_update(void);
extern int blockchain_is_updating(void);

extern void getblock(big_idx_t index);
extern void getblocks(big_idx_t target_idx);

extern int blocks_remove(void);

extern int raw_block_validate(raw_block_t *raw_block, size_t blocksize); 

extern void block_poll_start(void);

extern int block_is_syncblock(raw_block_t *rb);
extern void *block_cache_hash(raw_block_t *rb);

extern int block_idx_in_transit(big_idx_t idx_be);
extern void block_transit_message_add(message_t *msg);
extern void block_transit_message_remove(message_t *msg);

extern int raw_block_future_buffer_add(raw_block_t *rb, size_t size);

extern void blockchain_rewind(big_idx_t to_idx);

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

inline static time64_t
block_time(raw_block_t *raw_block)
{
	return (be64toh(raw_block->time));
}

inline static flags_t
block_flags(raw_block_t *raw_block)
{
	return (be64toh(raw_block->flags));
}

inline static small_idx_t
num_pacts(raw_block_t *raw_block)
{
	return (be32toh(raw_block->num_pacts));
}
#endif /* __TIFA_BLOCK_H */
