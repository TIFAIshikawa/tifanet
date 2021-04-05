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

#ifndef __TIFA_CONFIG_H
#define __TIFA_CONFIG_H

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

/*
 * Roadmap:
 * 0.1: base functionality working, send & receive of pact type I
 * 0.3: peerlist & IP version agnostic code
 * 0.4: thin client mode: run thin tifanetd with only caches
 * 0.5: robustify network: fault tolerance and denouncement
 * 0.7: pact type I, go live
 * 0.8: pact type II (masked pacts)
 * 0.9: pact type III (Solidity & ERC20) ?
 */
#define TIFA_VERSION_STR	"0.2.0"
#define TIFA_VERSION	100

/*     If you fork TIFAnet, change these defines!!!!     */
/* vv =============================================== vv */
#define TIFA_IDENT		"TIFA"
#define TIFA_NODE_IDENT		"N" TIFA_IDENT
#define TIFA_NETWORK_PORT	6174
/* ^^ =============================================== ^^ */

#define TIFA_NOTAR_REWARD	50

#ifndef FALSE
#define FALSE   0
#endif
#ifndef TRUE
#define TRUE    1
#endif

#define TIFA_MULT_FACTOR (1000000)
#define itos(amount) (amount * TIFA_MULT_FACTOR)
#define stoi(amount) ((double)amount / (double)TIFA_MULT_FACTOR)

#define MAXPACKETSIZE (20 * 1024 * 1024)

#define CACHE_HASH_BLOCK_INTERVAL 1000

typedef uint32_t small_idx_t;
typedef uint64_t big_idx_t;
typedef uint64_t flags_t;
typedef uint64_t time64_t;
typedef uint64_t amount_t;

extern void config_load(void);

extern char *config_path(char *buffer, const char *filename);

extern void set_is_notar_node(int is_notar);
extern int is_notar_node(void);

extern void set_sync_only(int sync_only);
extern int is_sync_only(void);

extern void set_caches_only(int caches_only);
extern int is_caches_only(void);

#endif /* __TIFA_CONFIG_H */
