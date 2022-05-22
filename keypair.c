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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "log.h"
#include "base64.h"
#include "config.h"
#include "keypair.h"

struct __keypair {
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];

	crypto_sign_state sign_state;
};

const public_key_t pubkey_zero = { 0 };
const signature_t signature_zero = { 0 };

keypair_t *
keypair_create()
{
	keypair_t *res;

	res = malloc(sizeof(keypair_t));
	crypto_sign_keypair(res->pk, res->sk);

	return (res);
}

keypair_t *
keypair_load(const char *filename)
{
	keypair_t *res;
	FILE *f;

	res = malloc(sizeof(keypair_t));

	if (!(f = fopen(filename, "r")))
		FAILTEMP("load_keypair: %s: %s\n", filename,
			 strerror(errno));
	if (fread(res->pk, 1, crypto_sign_PUBLICKEYBYTES, f) != crypto_sign_PUBLICKEYBYTES)
		FAILTEMP("load_keypair: public key: %s: "
			 "failed\n", filename);

	if (fread(res->sk, 1, crypto_sign_SECRETKEYBYTES, f) != crypto_sign_SECRETKEYBYTES)
		FAILTEMP("load_keypair: secret key: %s: "
			 "failed\n", filename);

	fclose(f);

	return (res);
}

int
keypair_save(keypair_t *keypair, const char *filename)
{
	FILE *f;

	if (!(f = fopen(filename, "w+")))
		FAILTEMP("save_keypair: %s: %s\n", filename,
			 strerror(errno));
	fchmod(fileno(f), 0600);

	if (fwrite(keypair->pk, 1, crypto_sign_PUBLICKEYBYTES, f) != crypto_sign_PUBLICKEYBYTES)
		FAILTEMP("save_keypair: public key: %s: "
			 "failed\n", filename);

	if (fwrite(keypair->sk, 1, crypto_sign_SECRETKEYBYTES, f) != crypto_sign_SECRETKEYBYTES)
		FAILTEMP("save_keypair: secret key: %s: "
			 "failed\n", filename);

	fclose(f);

	return (0);
}

void
keypair_free(keypair_t *keypair)
{
	free(keypair);
}

char *
keypair_name(keypair_t *keypair, char *buffer)
{
	return (public_key_name(keypair->pk, buffer));
}

char *
public_key_name(public_key_t public_key, char *buffer)
{
	base64_ntop(public_key, crypto_sign_PUBLICKEYBYTES, buffer, 48);
	buffer[KEYPAIR_NAME_LENGTH] = '\0';

	return (buffer);
}

uint8_t *
keypair_public_key(keypair_t *keypair)
{
	return (keypair->pk);
}

void *
keypair_sign(keypair_t *keypair, void *payload, size_t size, void *signature)
{
	crypto_sign_state state;

	crypto_sign_init(&state);
	crypto_sign_update(&state, payload, size);
	crypto_sign_final_create(&state, signature, NULL, keypair->sk);

	return (signature);
}

void
keypair_sign_start(keypair_t *keypair, void *payload, size_t size)
{
	crypto_sign_init(&keypair->sign_state);
	if (size)
		keypair_sign_update(keypair, payload, size);
}

void
keypair_sign_update(keypair_t *keypair, void *payload, size_t size)
{
	crypto_sign_update(&keypair->sign_state, payload, size);
}

void
keypair_sign_finalize(keypair_t *keypair, void *signature)
{
	crypto_sign_final_create(&keypair->sign_state, signature, NULL,
				 keypair->sk);
}

void *keypair_verify_start(void *payload, size_t size)
{
	crypto_sign_state *res;

	res = malloc(sizeof(crypto_sign_state));
	crypto_sign_init(res);
	if (size)
		keypair_verify_update(res, payload, size);

	return (res);
}

void
keypair_verify_update(void *context, void *payload, size_t size)
{
	crypto_sign_update(context, payload, size);
}

int
keypair_verify_finalize(void *context, void *public_key, void *signature)
{
	int res;

	res = crypto_sign_final_verify(context, signature, public_key);
	free(context);

	return res == 0;
}

int
pubkey_compare(const public_key_t l, const public_key_t r)
{
	if (!l || !r)
		return (0);

	return (memcmp(l, r, sizeof(public_key_t)));
}

int
pubkey_equals(const public_key_t l, const public_key_t r)
{
	if (!l || !r)
		return (0);

	return (pubkey_compare(l, r) == 0);
}

int
pubkey_is_zero(const public_key_t pubkey)
{
	return (pubkey_equals(pubkey_zero, pubkey));
}

int
hash_compare(const void *l, const void *r)
{
	return (memcmp(l, r, sizeof(hash_t)));
}

int
hash_equals(const void *l, const void *r)
{
	return (hash_compare(l, r) == 0);
}

int
signature_compare(const void *l, const void *r)
{
	return (memcmp(l, r, sizeof(signature_t)));
}

int
signature_equals(const void *l, const void *r)
{
	return (signature_compare(l, r) == 0);
}

int
signature_is_zero(const void *signature)
{
	return (signature_equals(signature_zero, signature));
}

char *
small_hash_str(small_hash_t h)
{
	static char tmp[SMALL_HASH_STR_LENGTH];

	return (small_hash_str_r(h, tmp));
}

char *
small_hash_str_r(small_hash_t h, char *tmp)
{
	uint8_t *p;

	p = (uint8_t *)h;

	sprintf(tmp,
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

	return (tmp);
}

char *
hash_str(hash_t h)
{
	static char tmp[HASH_STR_LENGTH];

	return (hash_str_r(h, tmp));
}

char *
hash_str_r(hash_t h, char *tmp)
{
	uint8_t *p;

	p = (uint8_t *)h;

	sprintf(tmp,
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
		p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
		p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31]);

	return (tmp);
}

char *signature_str(signature_t s)
{
	static char tmp[SIGNATURE_STR_LENGTH];

	return (signature_str_r(s, tmp));
}

char *signature_str_r(signature_t s, char *tmp)
{
	uint8_t *p;

	p = (uint8_t *)s;

	sprintf(tmp,
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
		"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
		p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
		p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31],
		p[32], p[33], p[34], p[35], p[36], p[37], p[38], p[39],
		p[40], p[41], p[42], p[43], p[44], p[45], p[46], p[47],
		p[48], p[49], p[50], p[51], p[52], p[53], p[54], p[55],
		p[56], p[57], p[58], p[59], p[60], p[61], p[62], p[63]);

	return (tmp);
}
