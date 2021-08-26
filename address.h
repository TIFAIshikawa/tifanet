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

#ifndef __TIFA_ADDRESS_H
#define __TIFA_ADDRESS_H

#include "config.h"
#include "keypair.h"

#define ADDRESS_NAME_LENGTH (sizeof(TIFA_IDENT) * 2 + KEYPAIR_NAME_LENGTH)

typedef char address_name_t[ADDRESS_NAME_LENGTH + 1];

struct __address;
typedef struct __address address_t;

extern address_t *address_create(void);
extern void address_free(address_t *address);

extern keypair_t *address_keypair(address_t *address);

extern address_t *address_load(const char *path);
extern void address_save(address_t *address, const char *path);

extern int is_address(const char *ident);

extern char *public_key_address_name(public_key_t public_key);
extern char *public_key_address_name_r(public_key_t public_key,
		address_name_t name);
extern char *address_name(address_t *address);
extern uint8_t *address_public_key(address_t *address);

extern amount_t address_unspent(address_t *address);

extern int address_name_to_public_key(const char *name, void *dst);

#endif /* __TIFA_ADDRESS_H */
