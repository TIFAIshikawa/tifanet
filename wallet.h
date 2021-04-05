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

#ifndef __TIFA_WALLET_H
#define __TIFA_WALLET_H

#include <sys/types.h>
#include "address.h"

struct __wallet;
typedef struct __wallet wallet_t;

extern wallet_t **wallets_load(void);
extern wallet_t **wallets(void);

extern wallet_t *wallet_create(const char *name);
extern int wallet_exists(const char *name);
extern char *wallet_name(wallet_t *wallet);
extern wallet_t *wallet_load(const char *name);
extern address_t **wallet_addresses(wallet_t *wallet, size_t *amount);
extern void wallet_address_add(wallet_t *wallet, address_t *address);
extern address_t *wallet_address_generate(wallet_t *wallet);

extern address_t *address_find_by_public_key(public_key_t public_key);
extern address_t *address_find_by_name(const char *name);

extern amount_t wallet_balance(wallet_t *wallet);

extern void wallet_save(wallet_t *wallet);
extern void wallet_free(wallet_t *wallet);

#endif /* __TIFA_WALLET_H */
