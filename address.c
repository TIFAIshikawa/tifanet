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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sodium.h>
#include "log.h"
#include "base64.h"
#include "config.h"
#include "rxcache.h"
#include "address.h"

struct __address {
	keypair_t *keypair;
	char name[ADDRESS_NAME_LENGTH + 1];
};

keypair_t *
address_keypair(address_t *address)
{
	return (address->keypair);
}

static char *
address_checksum(char *ident, char *buffer)
{
	uint8_t c;
	char hex[3];
	unsigned char checksum[sizeof(TIFA_IDENT)];

	crypto_generichash(checksum, sizeof(TIFA_IDENT) - 1,
			   (uint8_t *)ident, strlen(ident), NULL, 0);
	for (size_t i = 0; i < strlen(TIFA_IDENT); i++) {
		c = checksum[i] - TIFA_IDENT[i];
		sprintf(hex, "%02hhx", c);
		buffer[i] = hex[1];
	}

	buffer[strlen(TIFA_IDENT)] = '\0';

	return (buffer);
}

char *
public_key_address_name(public_key_t public_key)
{
	static address_name_t name;

	return (public_key_address_name_r(public_key, name));
}

char *
public_key_address_name_r(public_key_t public_key, address_name_t name)
{
	char ident[KEYPAIR_NAME_LENGTH + 1];
	char prepend_chksum[strlen(TIFA_IDENT) + 1];

	public_key_name(public_key, ident);

	address_checksum(ident, prepend_chksum);

	snprintf(name, ADDRESS_NAME_LENGTH + 1, "%s:%s:%s",
		 TIFA_IDENT, prepend_chksum, ident);

	return (name);
}

static void
address_name_generate(address_t *address)
{
	char ident[KEYPAIR_NAME_LENGTH + 1];
	char prepend_chksum[strlen(TIFA_IDENT) + 1];

	keypair_name(address->keypair, ident);

	address_checksum(ident, prepend_chksum);

	snprintf(address->name, ADDRESS_NAME_LENGTH + 1, "%s:%s:%s",
		 TIFA_IDENT, prepend_chksum, ident);
}

static address_t *
address_alloc(void)
{
	address_t *res;

	res = malloc(sizeof(address_t));
#ifdef DEBUG_ALLOC
	lprintf("+ADDRESS %p", res);
#endif

	return (res);
}

address_t *
address_create()
{
	address_t *res;

	res = address_alloc();
	res->keypair = keypair_create();
	address_name_generate(res);
	lprintf("created address %s", res->name);

	return (res);
}

void
address_free(address_t *address)
{
	keypair_free(address->keypair);
#ifdef DEBUG_ALLOC
	lprintf("-ADDRESS %p", address);
#endif
	free(address);
}

char *
address_name(address_t *address)
{
	return (address->name);
}

uint8_t *
address_public_key(address_t *address)
{
	return (keypair_public_key(address->keypair));
}

int
is_address(const char *name)
{
	char buf[ADDRESS_NAME_LENGTH + 1];
	int colon1idx, colon2idx;
	char checksum[strlen(TIFA_IDENT) + 1];

	if (strlen(name) > ADDRESS_NAME_LENGTH) {
		lprintf("is_address: not a tifa address: "
			"illegal length (actual: %d > expected: %ld): %s",
			strlen(name), ADDRESS_NAME_LENGTH, name);
		return (FALSE);
	}

	strncpy(buf, name, ADDRESS_NAME_LENGTH);
	buf[ADDRESS_NAME_LENGTH] = '\0';

	colon1idx = strlen(TIFA_IDENT);
	colon2idx = strlen(TIFA_IDENT) + 1 + strlen(TIFA_IDENT);
	if (buf[colon1idx] != ':' || buf[colon2idx] != ':') {
		lprintf("is_address: not a tifa address: "
			"format error: %s", name);
		return (FALSE);
	}
	buf[colon1idx] = '\0';
	buf[colon2idx] = '\0';

	if (strcmp(TIFA_IDENT, buf) != 0) {
		lprintf("is_address: not a tifa address: "
			"header error: %s", name);
		return (FALSE);
	}

	address_checksum(buf + colon2idx + 1, checksum);
	if (strcmp(checksum, buf + colon1idx + 1) != 0) {
		lprintf("is_address: invalid checksum: %s: %s (should be=%s)",
			name, buf + colon1idx, checksum);
		return (FALSE);
	}

	return (TRUE);
}

address_t *
address_load(const char *path)
{
	address_t *res;
	keypair_t *keypair;

	if (!(keypair = keypair_load(path)))
		return (NULL);

	res = address_alloc();
	res->keypair = keypair;
	address_name_generate(res);

	return (res);
}

void
address_save(address_t *address, const char *path)
{
	keypair_save(address->keypair, path);
}

amount_t
address_balance(address_t *address)
{
	public_key_t *pk;

	pk = (void *)address_public_key(address);

	return (public_key_balance((void *)pk));
}

int
address_name_to_public_key(const char *name, void *dst)
{
	if (!is_address(name))
		return (0);

	name += sizeof(TIFA_IDENT) * 2;
	base64_pton(name, dst, sizeof(public_key_t));

	return (1);
}
