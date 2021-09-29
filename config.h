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

//#define DEBUG_NETWORK 1
//#define DEBUG_ALLOC 1
//#define DEBUG_PEERLIST 1
//#define DEBUG_NOTAR 1
/*
 * Roadmap
 * ver: [eta date] description
 *
 * 0.9: [etaunknown] Pact type III (Solidity compatible smart contracts) ?
 * 0.8: [etaunknown] Pact type II (masked pacts)
 *      [2021-10-01] Go live ???
 * 0.7: [2021-06-15] Nicify code, use DNS
 * 0.6: [2021-05-23] Denounce notar, e.g. upon block timeout
 * 0.5: [2021-05-04] Robustify network: fault tolerance, e.g. fix possible
 *      infinite loops
 * 0.4: [2021-04-14] Thin client mode: run thin tifanetd with only caches
 * 0.3: [2021-04-01] Peerlist IPv4 & IPv6
 * 0.2: Connect to both IPv4 & IPv6
 * 0.1: Base functionality working, send & receive of pact type I
 */
#define TIFA_VERSION_STR	"0.7.0-dev"
#define TIFA_NETWORK_VERSION	1

/*     If you fork TIFAnet, change these defines!!!!     */
/* vv =============================================== vv */
#define TIFA_IDENT		"TIFA"
#define TIFA_NODE_IDENT		TIFA_IDENT "N"
#if defined(ALPHA)
#define TIFA_NETWORK_PORT	6172
#elif defined(BETA)
#define TIFA_NETWORK_PORT	6173
#else
#define TIFA_NETWORK_PORT	6174
#endif
/* ^^ =============================================== ^^ */

#define TIFA_NOTAR_REWARD	10

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

#define MINUTE_USECONDS 60000
#define HOUR_USECONDS 3600000

extern char *__network;

typedef uint32_t small_idx_t;
typedef uint64_t big_idx_t;
typedef uint16_t tiny_flags_t;
typedef uint64_t flags_t;
typedef uint64_t time64_t;
typedef uint64_t userinfo_t;
typedef uint64_t amount_t;

extern void config_load(void);

extern char *config_path(const char *filename);
extern char *config_path_r(char *buffer, const char *filename);

extern FILE *config_fopen(const char *filename, const char * restrict mode);
extern int config_unlink(const char *filename);

extern void config_set_notar_node(int is_notar);
extern int config_is_notar_node(void);

extern void config_set_sync_only(int sync_only);
extern int config_is_sync_only(void);

extern void config_set_caches_only(int caches_only);
extern int config_is_caches_only(void);

#endif /* __TIFA_CONFIG_H */
