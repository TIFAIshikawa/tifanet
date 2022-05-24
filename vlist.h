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

#ifndef __TIFA_VLIST_H
#define __TIFA_VLIST_H
#include <stdio.h>
#include <unistd.h>
#include "list.h"

/*
 * vlist: a list type where the list consists of pointers
 *        to the actual items.
 */
struct __vlist;
typedef struct __vlist vlist_t;

extern vlist_t *vlist_init(size_t initial_size);
extern void vlist_destroy(vlist_t *list);

extern size_t vlist_size(vlist_t *list);
extern void vlist_item_add(vlist_t *list, void *item);
extern void vlist_item_remove(vlist_t *list, void *item);
extern void vlist_item_remove_all(vlist_t *list);
extern int vlist_item_exists(vlist_t *list, void *item);

extern void *vlist_item_get(vlist_t *list, size_t index);
extern void *vlist_item_random(vlist_t *list);

extern void vlist_loop(vlist_t *list, list_loop_function_t func,
	void *userdata);

#endif // TIFA_VLIST_H
