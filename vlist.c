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
#include <sodium.h>
#include <strings.h>
#include "config.h"
#include "vlist.h"
#include "log.h"

struct __vlist {
	size_t size;
	size_t allocated;
	char **list;
};

static void vlist_resize(vlist_t *list, size_t increase);

vlist_t *
vlist_init(size_t initial_size)
{
	vlist_t *res;

	res = calloc(1, sizeof(vlist_t));
	res->size = 0;
	res->allocated = initial_size;
	res->list = calloc(1, sizeof(char *) * res->allocated);

	return (res);
}

void
vlist_destroy(vlist_t *list)
{
	free(list->list);
	free(list);
}

size_t
vlist_size(vlist_t *list)
{
	return (list->size);
}

static void
vlist_resize(vlist_t *list, size_t increase)
{
	size_t prev_end, size_new;

	prev_end = sizeof(char *) * list->allocated;
	list->allocated += increase;

	size_new = sizeof(char *) * list->allocated;
	list->list = realloc(list->list, size_new);
	bzero((void *)(list->list) + prev_end, increase * sizeof(char *));
}

void
vlist_item_add(vlist_t *list, void *item)
{
	if (!item)
		return;

	if (list->size == list->allocated)
		vlist_resize(list, 10);

	for (size_t i = 0; i < list->allocated; i++) {
		if (!list->list[i]) {
			list->list[i] = item;
			list->size++;
			return;
		}
	}

	lprintf("vlist_item_add: internal error: list %p(%ld, %ld) reached end",
		list, list->size, list->allocated);
}

void
vlist_item_remove(vlist_t *list, void *item)
{
	if (!item)
		return;

	for (size_t i = 0; i < list->allocated; i++) {
		if (list->list[i] == item) {
			list->list[i] = NULL;
			list->size--;
		}
	}
}

void
vlist_item_remove_all(vlist_t *list)
{
	list->size = 0;
	bzero(list->list, list->allocated * sizeof(char *));
}

int
vlist_item_exists(vlist_t *list, void *item)
{
	for (size_t i = 0; i < list->allocated; i++)
		if (list->list[i] == item)
			return (TRUE);

	return (FALSE);
}

void *
vlist_item_get(vlist_t *list, size_t index)
{
	for (size_t i = 0, n = 0; i < list->allocated; i++) {
		if (list->list[i]) {
			if (n == index)
				return (list->list[i]);
			n++;
		}
	}

	return (NULL);
}

void *
vlist_item_random(vlist_t *list)
{
	void *res = NULL;
	size_t rnd;

	if (!list->size)
		return (NULL);

	for (; !res;) {
		rnd = randombytes_random() % list->allocated;
		res = list->list[rnd];
	}

	return (res);
}

void
vlist_loop(vlist_t *list, list_loop_function_t func, void *userdata)
{
	if (!list)
		return;

	for (size_t i = 0; i < list->allocated; i++)
		if (list->list[i])
			func(list->list[i], userdata);
}
