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
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "log.h"
#include "wallet.h"
#include "config.h"

struct __wallet {
	char *name;
	address_t **addresses;
	size_t num_addresses;
};

static wallet_t **__wallets = NULL;
static size_t __num_wallets = 0;

static void
wallet_add(wallet_t *wallet)
{
	size_t wlen;

	wlen = sizeof(wallet_t *);
	if (__num_wallets % 10 == 0) {
		__wallets = realloc(__wallets, (__num_wallets + 10) * wlen);
		bzero(__wallets + __num_wallets, 10 * wlen);
	}
	__wallets[__num_wallets] = wallet;
	__num_wallets++;
}

wallet_t **
wallets_load()
{
	DIR *dir;
	struct dirent *ent;

	__wallets = calloc(10, sizeof(wallet_t *));
	wallet_create(NULL);

	if ((dir = opendir(config_path("wallets")))) {
		while ((ent = readdir(dir))) {
			if (ent->d_type & DT_DIR && ent->d_name[0] != '.')
				wallet_add(wallet_load(ent->d_name));
		}
		closedir(dir);
	}

	return (__wallets);
}

wallet_t **
wallets()
{
	if (!__wallets)
		return (wallets_load());

	return (__wallets);
}

static char *
wallet_path(const char *name, char *buffer)
{
	char tmp[MAXPATHLEN + 1];

	snprintf(tmp, MAXPATHLEN + 1, "wallets/%s", name);

	return (config_path_r(buffer, tmp));
}


static char *
address_path(const char *name, const char *address_name, char *buffer)
{
	char tmp[MAXPATHLEN + 1];

	snprintf(tmp, MAXPATHLEN + 1, "wallets/%s/%s", name, address_name);

	return (config_path_r(buffer, tmp));
}

int
wallet_exists(const char *name)
{
	char tmp[MAXPATHLEN + 1];
	
	return access(wallet_path(name, tmp), R_OK | X_OK) == 0;
}

char *
wallet_name(wallet_t *wallet)
{
	return (wallet->name);
}

static wallet_t *
wallet_alloc(const char *name)
{
	wallet_t *res;

	res = malloc(sizeof(wallet_t));
	res->name = strdup(name);
	res->num_addresses = 0;
	res->addresses = malloc(sizeof(address_t *) * 10);

	return (res);
}

wallet_t *
wallet_create(const char *name)
{
	wallet_t *res;

	if (!name || !name[0])
		name = "default";

	if (wallet_exists(name))
		return (wallet_load(name));

	res = wallet_alloc(name);

	wallet_save(res); // creates the directory

	wallet_address_generate(res);

	wallet_save(res); // saves the address

	wallet_add(res);

	lprintf("created wallet '%s', %s", res->name,
		address_name(res->addresses[0]));

	return (res);
}

wallet_t *
wallet_load(const char *name)
{
	DIR *dir;
	wallet_t *res;
	address_t *addr;
	struct dirent *ent;
	char tmp[MAXPATHLEN + 1];

	if (!wallet_exists(name))
		return NULL;

	for (size_t i = 0; __wallets[i]; i++)
		if (strcmp(name, wallet_name(__wallets[i])) == 0)
			return (__wallets[i]);

	res = wallet_alloc(name);

	wallet_path(name, tmp);
	if ((dir = opendir(tmp))) {
		while ((ent = readdir(dir))) {
			if (ent->d_type & DT_REG && is_address(ent->d_name)) {
				address_path(res->name, ent->d_name, tmp);
				if ((addr = address_load(tmp)))
					wallet_address_add(res, addr);
			}
		}
		closedir(dir);
	}

	if (!res->num_addresses)
		wallet_address_generate(res);

	lprintf("loaded wallet '%s', %s", res->name,
		address_name(res->addresses[0]));

	return (res);
}

address_t **
wallet_addresses(wallet_t *wallet, size_t *amount)
{
	*amount = wallet->num_addresses;

	return(wallet->addresses);
}

address_t *
wallet_address_generate(wallet_t *wallet)
{
	address_t *res;

	res = address_create();
	wallet_address_add(wallet, res);

	return (res);
}

void
wallet_address_add(wallet_t *wallet, address_t *address)
{
	char tmp[MAXPATHLEN + 1];

	for (size_t i = 0; i < wallet->num_addresses; i++)
		if (wallet->addresses[i] == address)
			return;

	if (wallet->num_addresses % 10 == 0) {
		wallet->addresses = realloc(wallet->addresses,
			sizeof(address_t *) * wallet->num_addresses + 10);
	}
	wallet->addresses[wallet->num_addresses] = address;
	wallet->num_addresses++;

	address_path(wallet->name, address_name(address), tmp);
	address_save(address, tmp);
}

amount_t
wallet_balance(wallet_t *w)
{
        address_t **addrs;
        amount_t res = 0;
        size_t naddrs;

        addrs = wallet_addresses(w, &naddrs);
        for (size_t i = 0; i < naddrs; i++)
                res += address_unspent(addrs[i]);

        return (res);
}

void
wallet_save(wallet_t *wallet)
{
	address_t *addr;
	char tmp[MAXPATHLEN + 1];

	wallet_path(wallet->name, tmp); 
	mkdir(tmp, 0700);

	for (size_t i = 0; i < wallet->num_addresses; i++) {
		addr = wallet->addresses[i];
		address_path(wallet->name, address_name(addr), tmp);
		address_save(addr, tmp);
	}
}

void
wallet_free(wallet_t *wallet)
{
	free(wallet->name);
	for (size_t i = 0; i < wallet->num_addresses; i++)
		address_free(wallet->addresses[i]);
	free(wallet->addresses);
	free(wallet);
}

address_t *
address_find_by_public_key(public_key_t public_key)
{
	wallet_t *w;
	uint8_t *pk;
	address_t *addr;

	for (size_t wi = 0; wi < __num_wallets; wi++) {
		w = __wallets[wi];
		for (size_t ai = 0; ai < w->num_addresses; ai++) {
			addr = w->addresses[ai];
			pk = address_public_key(addr);
			if (pubkey_compare(public_key, pk) == 0)
				return (addr);
		}
	}

	return (NULL);
}

address_t *
address_find_by_name(const char *name)
{
	wallet_t *w;
	address_t *addr;

	for (size_t wi = 0; wi < __num_wallets; wi++) {
		w = __wallets[wi];
		for (size_t ai = 0; ai < w->num_addresses; ai++) {
			addr = w->addresses[ai];
			if (strcmp(name, address_name(addr)) == 0)
				return (addr);
		}
	}

	return (NULL);
}
