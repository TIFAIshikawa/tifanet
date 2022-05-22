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
#include <unistd.h>
#include <string.h>
#include <sodium.h>
#include "log.h"
#include "notar.h"
#include "cache.h"
#include "config.h"
#include "keypair.h"
#include "rxcache.h"
#include "opcode_callback.h"

#define CACHE_HASH_AMOUNT 2

static int __caches_only_downloaded = 0;

void
cache_hash(hash_t resulthash, big_idx_t block_idx)
{
	hash_t hash[CACHE_HASH_AMOUNT];

	rxcache_hash(hash[0], block_idx);
	notarscache_hash(hash[1], block_idx);

	crypto_generichash(resulthash, sizeof(hash_t),
			   (void *)hash, sizeof(hash_t) * CACHE_HASH_AMOUNT,
			   NULL, 0);
}

int
cache_write(char *filename, char *buffer, size_t size)
{
	char tmp[MAXPATHLEN + 1];
	size_t w, wr;
	FILE *f;
 
	snprintf(tmp, MAXPATHLEN, "blocks/%s.bin", filename);
	if (!(f = config_fopen(tmp, "w+")))
		return (FALSE);

	for (w = wr = 0; wr < size && w >= 0; wr += w)
		w = fwrite(buffer + wr, 1, size - wr, f);

	if (wr != size)
		FAILTEMP("failed writing rxcache: %s", strerror(errno));

	fclose(f);

	return (TRUE);
}

static void
caches_get_blocks(void *info, void *payload)
{
	hash_t hash;
	size_t size;
	raw_block_t *rb;

	rb = raw_block_last(&size);
	if (!block_is_syncblock(rb))
		return;

	cache_hash(hash, block_idx(rb));
	if (!hash_equals(hash, block_cache_hash(rb))) {
		lprintf("local cache hash doesn't equal block cache_hash "
			"@ idx %ju (rxcache idx %ju notarscache idx %ju)",
			block_idx_last(), rxcache_last_block_idx(),
			notars_last_block_idx());
		//return cache_download();
	}
}

static void
caches_only_download_callback(void *info, void *payload)
{
	big_idx_t index;
	__caches_only_downloaded++;

	if (__caches_only_downloaded < 2)
		return;

	notarscache_load();
	rxcache_load();
	if (notars_last_block_idx() != rxcache_last_block_idx())
		FAILTEMP("notarscache idx %ju != rxcache idx %ju",
			notars_last_block_idx(), rxcache_last_block_idx());

	index = notars_last_block_idx();
	lprintf("asking for block %ju", index);
	if (!message_send_random_with_callback(OP_GETBLOCK, NULL, 0,
		htobe64(index), caches_get_blocks))
		FAILTEMP("failed to request block idx %ju", index);
}

void
cache_download(void)
{
	message_send_random_with_callback(OP_GETRXCACHE, NULL, 0,
		getrxcache_userinfo(), caches_only_download_callback);
	message_send_random_with_callback(OP_GETNOTARS, NULL, 0,
		getnotarscache_userinfo(), caches_only_download_callback);
}

int
cache_remove(void)
{
	int r[4];

	r[0] = config_unlink("blocks/rxcache.bin");
	r[1] = config_unlink("blocks/notarscache.bin");
	r[2] = config_unlink("peerlist4.txt");
	r[3] = config_unlink("peerlist6.txt");

	return (r[0] && r[1] && r[2] && r[3]);
}
