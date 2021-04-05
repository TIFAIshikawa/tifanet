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

	return res;
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
pubkey_compare(void *l, void *r)
{
	return (bcmp(l, r, sizeof(public_key_t)));
}
