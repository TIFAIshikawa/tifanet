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

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sodium.h>
#include <inttypes.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include "log.h"
#include "endian.h"
#include "block.h"
#include "error.h"
#include "notar.h"
#include "config.h"
#include "rxcache.h"
#include "block_storage.h"

#define BLOCKS_FILESIZE_MAX 268435456UL
#define BLOCK_IDX_FILESIZE_MAX ((BLOCKS_FILESIZE_MAX * 8UL) / 256UL)

typedef struct __block_storage {
	void *blocks;
	big_idx_t *block_idxs;
	big_idx_t first_block_idx;
	big_idx_t last_block_idx;
} block_storage_t;

static raw_block_t *__raw_block_last = NULL;
static size_t __raw_block_last_size = 0;

static block_storage_t **__block_storage = NULL;
static block_storage_t *__block_storage_current = NULL;
static size_t __num_block_storages = 0;

static void *mmap_file(char *filename, off_t truncsize);
static int block_storage_exists(small_idx_t idx);
static block_storage_t *block_storage_load_storage(small_idx_t idx,
	big_idx_t first_block_idx);
static void block_storage_list_resize(void);
static block_storage_t *block_storage_create(void);

raw_block_t *
raw_block_last(size_t *size)
{
	if (size)
		*size = __raw_block_last_size;

	return (__raw_block_last);
}

void
block_last_load()
{
	__raw_block_last = raw_block_last_load(&__raw_block_last_size);
}

static void *
mmap_file(char *filename, off_t truncsize)
{
	int fd;
	void *res;
	char file[MAXPATHLEN + 1];

	if ((fd = open(config_path_r(file, filename),
		O_CREAT | O_RDWR, 0644)) == -1)
		FAILTEMP("open %s: %s\n", file, strerror(errno));
	ftruncate(fd, truncsize);
	if ((res = mmap(0, truncsize, PROT_READ | PROT_WRITE,
#if !defined(__FreeBSD__) && !defined(__DragonFly__)
		MAP_SHARED,
#else
		MAP_SHARED | MAP_NOCORE,
#endif
		fd, 0)) == MAP_FAILED)
		FAILTEMP("mmap %s: %s\n", file, strerror(errno));
	close(fd);

#ifdef __linux__
	madvise(res, truncsize, MADV_DONTDUMP);
#endif

	return (res);
}

static inline void
block_storage_names_fill(char *blockname, char *idxname, size_t idx,
	size_t size)
{
	if (snprintf(blockname, size, "blocks/blocks%ld.bin", idx) >= size - 1)
		FAILTEMP("path overflow: %s", blockname);
	if (snprintf(idxname, size, "blocks/blocks%ld.idx", idx) >= size - 1)
		FAILTEMP("path overflow: %s", idxname);
}

static int
block_storage_exists(small_idx_t idx)
{
	char bpath[MAXPATHLEN + 1];
	char ipath[MAXPATHLEN + 1];
	char bpart[32];
	char ipart[32];

	block_storage_names_fill(bpart, ipart, idx, 32);
	config_path_r(bpath, bpart);
	config_path_r(ipath, ipart);

	return (access(bpath, R_OK | W_OK) == 0 &&
		access(ipath, R_OK | W_OK) == 0);
}

static block_storage_t *
block_storage_load_storage(small_idx_t idx, big_idx_t first_block_idx)
{
	block_storage_t *res;
	small_idx_t i, n;
	char bpath[32];
	char ipath[32];

	block_storage_names_fill(bpath, ipath, idx, 32);

	res = calloc(1, sizeof(block_storage_t));
	res->first_block_idx = first_block_idx;

	if (!(res->blocks = mmap_file(bpath, BLOCKS_FILESIZE_MAX)))
		FAILTEMP("block_storage_load: %s: %s", bpath, strerror(errno));
	if (!(res->block_idxs = mmap_file(ipath, BLOCK_IDX_FILESIZE_MAX)))
		FAILTEMP("block_storage_load: %s: %s", bpath, strerror(errno));

	n = BLOCK_IDX_FILESIZE_MAX / sizeof(big_idx_t);
	i = 0;
	if (res->block_idxs[1]) {
		for (i = 1; i < n; i++) {
			if (!res->block_idxs[i]) {
				i--;
				break;
			}
			if (res->block_idxs[n - i]) {
				i = n - i;
				break;
			}
		}
	}

	res->last_block_idx = first_block_idx + i;

	return (res);
}

static void
block_storage_list_resize(void)
{
	size_t sz, curr;

	sz = sizeof(block_storage_t *);
	curr = __num_block_storages;
	__num_block_storages = curr + 10;
	__block_storage = realloc(__block_storage, sz * __num_block_storages);
	bzero(__block_storage + curr, sz * 10);
}

static block_storage_t *
block_storage_create(void)
{
	block_storage_t *res;
	big_idx_t fbi;
	size_t i;

	for (i = 0; i < __num_block_storages; i++)
		if (!__block_storage[i])
			break;

	if (i == __num_block_storages)
		block_storage_list_resize();

	fbi = block_idx_last() + 1;
	res = block_storage_load_storage(i, fbi);
	__block_storage[i] = res;

	return (res);
}

void
blockchain_storage_load(void)
{
	block_storage_t *cb;

	__num_block_storages = 10;
	__block_storage = calloc(1,
		sizeof(block_storage_t *) * __num_block_storages);

	for (size_t i = 0, fbi = 0; block_storage_exists(i); i++) {
		if (i == __num_block_storages)
			block_storage_list_resize();
		cb = block_storage_load_storage(i, fbi);
		__block_storage[i] = cb;
		__block_storage_current = cb;

		fbi = cb->last_block_idx + 1;
	}
}

void
blockchain_rewind(big_idx_t to_idx)
{
	raw_block_t *block;
	block_storage_t *bs;
	big_idx_t curr_idx, sidx, count;

	curr_idx = block_idx_last();

	// fix caches
	for (big_idx_t i = curr_idx; i > to_idx; i--) {
		block = block_load(i, NULL);
		notar_raw_block_rewind(block);
		rxcache_raw_block_rewind(block);
	}

	// fix block storage
	for (ssize_t i = __num_block_storages - 1; i >= 0; i--) {
		if (!(bs = __block_storage[i]))
			continue;
		if (bs->first_block_idx > to_idx) {
			// obliterate
			munmap(bs->blocks, BLOCKS_FILESIZE_MAX);
			munmap(bs->block_idxs, BLOCK_IDX_FILESIZE_MAX);
			free(bs);
			__block_storage[i] = NULL;
		} else if (bs->last_block_idx > to_idx) {
			// trim to to_idx
			count = bs->last_block_idx - to_idx;
			sidx = to_idx - bs->first_block_idx;
			bzero(bs->block_idxs + sidx, sizeof(big_idx_t) * count);
			block_last_load();
		} else if (bs->last_block_idx < to_idx)
			break;
	}
}

void *
raw_block_last_load(size_t *blocksize)
{
	big_idx_t last_offset;
	block_storage_t *bs;
	raw_block_t *rb;
	big_idx_t lbi;

	bs = __block_storage_current;
	lbi = bs->last_block_idx - bs->first_block_idx;
	last_offset = bs->block_idxs[lbi];

	rb = (raw_block_t *)(bs->blocks + last_offset);
	if (blocksize)
		*blocksize = raw_block_size(rb, 0);

	return (rb);
}

raw_block_t *
blocks_load(big_idx_t block_idx, size_t *size, big_idx_t max_blocks,
	size_t max_size)
{
	block_storage_t *bs;
	raw_block_t *res;
	big_idx_t soffset;
	big_idx_t boffset;
	big_idx_t idx;
	size_t sz, i;
	size_t mb;

	if (size)
		*size = 0;

	if (block_idx > block_idx_last())
		return (NULL);

	for (i = 0; __block_storage[i]->last_block_idx < block_idx; i++) { }
	bs = __block_storage[i];

	idx = block_idx - bs->first_block_idx;
	soffset = bs->block_idxs[idx];

	res = (raw_block_t *)(bs->blocks + soffset);
	sz = raw_block_size(res, 0);
	mb = MIN(bs->last_block_idx, block_idx + max_blocks);
	for (big_idx_t b = 1; block_idx + b < mb; b++) {
		boffset = bs->block_idxs[idx + b];
		if (boffset - soffset > max_size)
			break;
		sz += raw_block_size((raw_block_t *)(bs->blocks + boffset), 0);
	}

	if (size)
		*size = sz;

	return (res);
}

void
raw_block_write(raw_block_t *raw_block, size_t blocksize)
{
	block_storage_t *bs;
	size_t bsize, isize;
	big_idx_t idx;
	hash_t hash;
	void *dst;

	raw_block_hash(raw_block, blocksize, hash);
	lprintf("block(%ju) = %s", block_idx(raw_block), hash_str(hash));
	if (config_is_caches_only()) {
		if (__raw_block_last)
			free(__raw_block_last);
		__raw_block_last = malloc(blocksize);
		__raw_block_last_size = blocksize;
		bcopy(raw_block, __raw_block_last, blocksize);
		return;
	}

	bs = __block_storage_current;
	dst = (void *)__raw_block_last + __raw_block_last_size;
	if (dst + blocksize > bs->blocks + BLOCKS_FILESIZE_MAX) {
		bs = block_storage_create();
		__block_storage_current = bs;
		dst = bs->blocks;
	} else
		bs->last_block_idx++;

	bcopy(raw_block, dst, blocksize);
	__raw_block_last = (raw_block_t *)dst;
	__raw_block_last_size = blocksize;

	idx = block_idx(raw_block) - bs->first_block_idx;
	bs->block_idxs[idx] = (void *)__raw_block_last - bs->blocks;

	bsize = bs->block_idxs[idx] + blocksize;
	isize = idx * sizeof(big_idx_t);
	msync(bs->blocks, bsize, MS_SYNC);
	msync(bs->block_idxs, isize, MS_SYNC);
}

int
blocks_remove(void)
{
	char path[MAXPATHLEN + 1];
	struct dirent *dire;
	DIR *dirp;
	int r;

	r = 1;
	if ((dirp = opendir(config_path("blocks")))) {
		while ((dire = readdir(dirp))) {
			if (strncmp(dire->d_name, "blocks", 6) == 0) {
				snprintf(path, MAXPATHLEN + 1, "blocks/%s",
					dire->d_name);
				if (!config_unlink(path))
					r = 0;
			}
		}
		closedir(dirp);
	}

	return (r);
}

void
block_load_initial(raw_block_t *block, size_t size)
{
	if (__raw_block_last)
		FAIL(EX_SOFTWARE, "block_load_initial: already loaded %ju",
			block_idx_last());

	__raw_block_last = malloc(size);
	bcopy(block, __raw_block_last, size);
	__raw_block_last_size = size;

	notar_elect_next();
}
