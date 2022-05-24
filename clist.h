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

#ifndef __TIFA_CLIST_H
#define __TIFA_CLIST_H
#include <stdio.h>
#include <unistd.h>
#include "list.h"

/*
 * clist: a list type where the list consists of contiguous item data.
 */
struct __clist;
typedef struct __clist clist_t;

extern clist_t *clist_init(size_t initial_size, size_t item_size);
extern void clist_destroy(clist_t *list);

extern size_t clist_size(clist_t *list);
extern void clist_item_add(clist_t *list, void *item);
extern void clist_item_remove(clist_t *list, void *item);
extern void clist_item_remove_all(clist_t *list);
extern int clist_item_exists(clist_t *list, void *item);

extern void clist_loop(clist_t *list, list_loop_function_t func,
	void *userdata);

#endif // TIFA_CLIST_H
