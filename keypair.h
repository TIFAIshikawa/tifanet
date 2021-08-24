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

#ifndef __TIFA_KEYPAIR_H
#define __TIFA_KEYPAIR_H

//#define KEYPAIR_NAME_LENGTH (512 / 8 * 2)
#define KEYPAIR_NAME_LENGTH (48 + 4 + 1)

#define SMALL_HASH_STR_LENGTH ((2 * 16) + 1)
#define HASH_STR_LENGTH ((2 * 32) + 1)
#define SIGNATURE_STR_LENGTH ((2 * 64) + 1)

struct __keypair;
typedef struct __keypair keypair_t;

typedef uint8_t public_key_t[32];
typedef uint8_t signature_t[64];
typedef uint8_t small_hash_t[16];
typedef uint8_t hash_t[32];

extern const public_key_t pubkey_zero;
extern const signature_t signature_zero;

extern keypair_t *keypair_create(void);
extern keypair_t *keypair_load(const char *filename);
extern int keypair_save(keypair_t *keypair, const char *filename);
extern void keypair_free(keypair_t *keypair);

extern char *keypair_name(keypair_t *keypair, char *buffer);
extern char *public_key_name(public_key_t public_key, char *buffer);

extern uint8_t *keypair_public_key(keypair_t *keypair);
extern void *keypair_sign(keypair_t *keypair, void *payload, size_t size, void *signature);

extern void keypair_sign_start(keypair_t *keypair, void *payload, size_t size);
extern void keypair_sign_update(keypair_t *keypair, void *payload, size_t size);
extern void keypair_sign_finalize(keypair_t *keypair, void *signature);

extern void *keypair_verify_start(void *payload, size_t size);
extern void keypair_verify_update(void *context, void *payload, size_t size);
extern int keypair_verify_finalize(void *context, void *public_key, void *signature);

extern int pubkey_compare(const public_key_t l, const public_key_t r);
extern int pubkey_equals(const public_key_t l, const public_key_t r);
extern int hash_compare(const void *l, const void *r);
extern int hash_equals(const void *l, const void *r);
extern int signature_compare(const void *l, const void *r);
extern int signature_equals(const void *l, const void *r);

extern char *small_hash_str(small_hash_t h);
extern char *small_hash_str_r(small_hash_t h, char *tmp);
extern char *hash_str(hash_t h);
extern char *hash_str_r(hash_t h, char *tmp);
extern char *signature_str(signature_t s);
extern char *signature_str_r(signature_t s, char *tmp);

#endif /* __TIFA_KEYPAIR_H */
