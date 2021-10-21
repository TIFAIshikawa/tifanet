/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2021, Mitsumete Ishikawa
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

#ifndef __TIFA_PEERLIST_H
#define __TIFA_PEERLIST_H

#include <sys/types.h>
#include <netinet/in.h>
#include "config.h"


typedef struct {
        small_idx_t list4_size;
        small_idx_t list6_size;

        struct in_addr *list4;
        struct in6_addr *list6;
} peerlist_t;

extern peerlist_t peerlist;

extern void peerlist_load(void);
extern void peerlist_save(void);
extern void peerlist_save_sync(void);

extern void peerlist_add(struct sockaddr_storage *addr);
extern void peerlist_add_ipv4(struct in_addr addr);
extern void peerlist_add_ipv6(struct in6_addr addr);
extern void peerlist_remove(struct sockaddr_storage *addr);
extern void peerlist_remove_ipv4(struct in_addr addr);
extern void peerlist_remove_ipv6(struct in6_addr addr);

extern void peerlist_ban(struct sockaddr_storage *addr);
extern int banlist_is_banned(struct sockaddr_storage *addr);
extern void banlist_reset(void);

extern void peerlist_request_broadcast(void);

extern int peerlist_address_random(struct sockaddr_storage *addr);

#endif /* __TIFA_PEERLIST_H */
