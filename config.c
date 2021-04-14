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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/types.h>
#include "log.h"
#include "config.h"
#include "wallet.h"
#include "block0.h"

static char __config_dir[MAXPATHLEN + 1];
static int __is_notar_node = 0;
static int __sync_only = 0;
static int __caches_only = 0;

static void
rewrite_file(char *filename, void *content, size_t size)
{
	FILE *f;
	char tmp[MAXPATHLEN + 1];
	
	config_path(tmp, filename);

	unlink(tmp);
	if (!(f = fopen(tmp, "w+")))
		FAILTEMP("write %s: %s", filename, strerror(errno));
 	fwrite(content, 1, size, f);
	fclose(f);
}

void
config_load()
{
	FILE *f;
	big_idx_t idx = 0;
	char tmp[MAXPATHLEN + 1];

	snprintf(__config_dir, MAXPATHLEN + 1, "%s/.tifanet", getenv("HOME"));
	mkdir(__config_dir, 0700);
	mkdir(config_path(tmp, "wallets"), 0700);
	mkdir(config_path(tmp, "blocks"), 0700);

/*
	config_path(tmp, "blocks/blocks0.bin");
	if (access(tmp, F_OK | R_OK | W_OK) != 0) {
		rewrite_file("blocks/blocks0.bin", __block0, sizeof(__block0));
		rewrite_file("blocks/blocks0.idx", &idx, sizeof(big_idx_t));
		rewrite_file("blocks/lastblock.idx", &idx, sizeof(big_idx_t));
	}
*/

	config_path(tmp, "config");
	__config_dir[MAXPATHLEN] = '\0';

	if (!(f = fopen(tmp, "r"))) {
		if (errno != ENOENT)
			fprintf(stderr, "configfile: %s: %s\n", tmp,
				strerror(errno));
//		exit (EX_CONFIG);
	}
}

char *
config_path(char *buffer, const char *filename)
{
 	snprintf(buffer, MAXPATHLEN + 1, "%s/%s", __config_dir, filename);

	return (buffer);
}

void
set_is_notar_node(int is_notar)
{
	__is_notar_node = is_notar;
}

int
is_notar_node()
{
	return (__is_notar_node);
}

void
set_sync_only(int sync_only)
{
	__sync_only = sync_only;
}

int
is_sync_only(void)
{
	return (__sync_only);
}

void
set_caches_only(int caches_only)
{
	__caches_only = caches_only;
}

int
is_caches_only(void)
{
	return (__caches_only);
}
