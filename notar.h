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

#ifndef __TIFA_NOTAR_H
#define __TIFA_NOTAR_H

#include "block.h"
#include "config.h"
#include "keypair.h"

extern big_idx_t notars_last_block_idx(void);
extern public_key_t *notars(big_idx_t *num_notars);
extern uint8_t *notar_prev(void);		// returned is a public_key_t
extern uint8_t *notar_next(void);		// returned is a public_key_t
extern int notar_exists(public_key_t notar);

extern void notar_raw_block_add(raw_block_t *raw_block);
extern void notar_raw_block_rewind(raw_block_t *raw_block);

extern void notar_pending_add(public_key_t new_notar);
extern uint8_t *notar_pending_next(void);

extern int node_is_notar(void);

extern void notar_announce(void);

extern int notar_should_generate_block(void);
extern void notar_elect_next(void);

extern void *notar_denounce_emergency_node(void);

extern void notarscache_hash(hash_t result_hash, big_idx_t block_idx);
extern void notarscache_load(void);
extern void notarscache_save(big_idx_t idx);
extern int notarscache_exists(void);

#endif /* __TIFA_NOTAR_H */
