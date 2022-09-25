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
#include <netinet/in.h>
#include <arpa/nameser.h>
#ifndef __OpenBSD__
#include <arpa/nameser_compat.h>
#endif
#include <resolv.h>
#include "log.h"
#include "dns.h"
#include "error.h"
#include "block.h"
#include "config.h"
#include "block_storage.h"

#ifndef __OpenBSD__
static int __dns_txt_request(char *request, char *response, size_t size);

static int
__dns_txt_request(char *request, char *response, size_t size)
{
	ns_rr rr;
	size_t sz;
	size_t nmesg;
	ns_msg nsmsg = {0};
	char dnsres[PACKETSZ];

	if ((sz = res_query(request, ns_c_in, ns_t_txt, (u_char *)dnsres,
		PACKETSZ)) == -1) {
		lprintf("blockchain_dns_verify: failed to retrieve %s",
			request);
		return (FALSE);
	}

	if (ns_initparse((u_char *)dnsres, sz, &nsmsg) != 0) {
		lprintf("blockchain_dns_verify: failed to parse %s",
			request);
		return (FALSE);
	}

	nmesg = ns_msg_count(nsmsg, ns_s_an);
	for (size_t i = 0; i < nmesg; i++) {
		if (ns_parserr(&nsmsg, ns_s_an, i, &rr) != 0)
			continue;

		if (ns_rr_type(rr) != ns_t_txt)
			continue;

		if ((sz = ns_rr_rdlen(rr)) < 2)
			continue;

		bcopy((void *)ns_rr_rdata(rr) + 1, response, sz - 1);
		response[sz - 1] = '\0';
		return (TRUE);
	}

	return (FALSE);
}
#endif

void
blockchain_dns_verify(void)
{
#if !defined(__OpenBSD__) && !defined(__NetBSD__)
	hash_t bh;
	size_t sz, bs;
	big_idx_t idx;
	char *hashstr;
	char dnsreq[256];
	char txtres[256];
	raw_block_t *block;
	static big_idx_t __dns_last_verified = 0;

	res_init();
	_res.retrans = 1;
	_res.retry = blockchain_is_updating() ? 3 : 1;

	sz = snprintf(dnsreq, 256, "last.blocks.%s.tifa.network", __network);

	if (!__dns_txt_request(dnsreq, txtres, 256)) {
		lprintf("blockchain_dns_verify: no valid responses found while "
			"retrieving %s", dnsreq);
		return;
	}

	if (!(hashstr = index(txtres, ' '))) {
		lprintf("blockchain_dns_verify: invalid response while "
			"retrieving %s: %s", dnsreq, txtres);
		return;
	}
	*hashstr = '\0';
	hashstr++;

	if (strlen(hashstr) != 64) {
		lprintf("blockchain_dns_verify: invalid hash while "
			"retrieving %s: %s %s", dnsreq, txtres, hashstr);
		return;
	}

	for (size_t i = 0; txtres[i]; i++) {
		if (txtres[i] < '0' || txtres[i] > '9') {
			lprintf("blockchain_dns_verify: block index not a "
				"number while retrieving %s: %s", dnsreq,
				txtres);
			return;
		}
	}
	idx = strtoimax(txtres, NULL, 10);

	if (idx > block_idx_last()) {
		idx = block_idx_last();

		if (idx == __dns_last_verified)
			return;

		if (!(block = block_load(idx, &bs)))
			return;

		sz = snprintf(dnsreq, 256, "%ju.blocks.%s.tifa.network",
			idx, __network);
		if (!__dns_txt_request(dnsreq, txtres, 256)) {
			lprintf("blockchain_dns_verify: no valid responses "
				"found while retrieving %s", dnsreq);
			return;
		}

		raw_block_hash(block, bs, bh);
		if (strcmp(txtres, hash_str(bh)) == 0) {
			__dns_last_verified = idx;
#ifdef DEBUG_CHAINCHECK
			lprintf("block %ju verified with DNS", idx);
#endif
			return;
		}
	}

	if (idx == __dns_last_verified)
		return;

	if (!(block = block_load(idx, &bs)))
		return;

	raw_block_hash(block, bs, bh);
	if (strcmp(hashstr, hash_str(bh)) == 0) {
		__dns_last_verified = idx;
#ifdef DEBUG_CHAINCHECK
		lprintf("block %ju verified with DNS", idx);
#endif
		return;
	}

	lprintf("blockchain_dns_verify: block with index %ju differs from "
		"DNS! Rewinding to a previous correct point", idx);
	// hash wasn't the same! now rewind until we find a valid
	// block index & hash combination.
	idx = __dns_last_verified;
	if (__dns_last_verified) {
		idx = __dns_last_verified;
	} else {
		for (; idx; idx--) {
			sz = snprintf(dnsreq, 256, "%ju.blocks.%s.tifa.network",
				idx, __network);
			if (!__dns_txt_request(dnsreq, txtres, 256)) {
				lprintf("blockchain_dns_verify: no valid "
					"responses found while retrieving %s",
					dnsreq);
				continue;
			}
	
			raw_block_hash(block, bs, bh);
			if (strcmp(txtres, hash_str(bh)) == 0)
				break;
		}
	}

	lprintf("blockchain_dns_verify: last correct block appears to be %ju, "
		"rewinding", idx);

	blockchain_rewind(idx);
#endif
}
