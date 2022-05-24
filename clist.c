/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2022, Mitsumete Ishikawa
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "config.h"
#include "clist.h"
#include "log.h"

struct __clist {
	size_t size;
	size_t allocated;
	size_t item_size;
	char *list;
};

static void clist_resize(clist_t *list, size_t increase);

clist_t *
clist_init(size_t initial_size, size_t item_size)
{
	clist_t *res;

	res = calloc(1, sizeof(clist_t));
	res->size = 0;
	res->item_size = item_size;
	res->allocated = initial_size;
	res->list = calloc(1, res->item_size * res->allocated);

	return (res);
}

void
clist_destroy(clist_t *list)
{
	free(list->list);
	free(list);
}

size_t
clist_size(clist_t *list)
{
	return (list->size);
}

static void
clist_resize(clist_t *list, size_t increase)
{
	size_t prev_end, size_new;

	prev_end = list->item_size * list->allocated;
	list->allocated += increase;

	size_new = list->item_size * list->allocated;
	list->list = realloc(list->list, size_new);
	bzero(list->list + prev_end, size_new - prev_end);
}

void
clist_item_add(clist_t *list, void *item)
{
	char *ptr;

	if (!item)
		return;

	if (list->size == list->allocated)
		clist_resize(list, 10);

	ptr = list->list + list->item_size * list->size;
	bcopy(item, ptr, list->item_size);
	list->size++;
}

void
clist_item_remove(clist_t *list, void *item)
{
	char *ptr;

	if (!item)
		return;

	ptr = list->list;
	for (size_t i = 0; i < list->size; i++, ptr += list->item_size) {
		if (memcmp(ptr, item, list->item_size) == 0) {
			if (i < list->size - 1)
				ptr = list->list + list->item_size * list->size;
			bzero(ptr, list->item_size);
			list->size--;
		}
	}
}

void
clist_item_remove_all(clist_t *list)
{
	list->size = 0;
	bzero(list->list, list->allocated * list->item_size);
}

int
clist_item_exists(clist_t *list, void *item)
{
	char *ptr;

	ptr = list->list;
	for (size_t i = 0; i < list->size; i++, ptr += list->item_size)
		if (memcmp(ptr, item, list->item_size) == 0)
			return (TRUE);

	return (FALSE);
}

void
clist_loop(clist_t *list, list_loop_function_t func, void *userdata)
{
	char *ptr;

	if (!list)
		return;

	ptr = list->list;
	for (size_t i = 0; i < list->size; i++, ptr += list->item_size)
		func(ptr, userdata);
}
