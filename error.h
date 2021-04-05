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

#ifndef __TIFA_ERROR_H
#define __TIFA_ERROR_H

#ifdef __linux__
#include <netinet/in.h>
#endif
#include <sys/types.h>

typedef uint32_t error_t;

enum {
	NO_ERR			= 0,	/* No error */

	ERR_BADSIG		= 1,	/* Bad signature */
	ERR_BADNOTAR		= 2,	/* Bad notar */

	ERR_MSG_TOOBIG		= 3,	/* Message too big */
	ERR_MALFORMED		= 4,	/* Malformed content */

	ERR_TX_PENDING		= 5,	/* TX already in pending pact */
	ERR_TX_SPENT		= 6,	/* TX already spent */
	ERR_TX_UNCOMPRESSED	= 7,	/* TX entries not compressed */
	ERR_TX_FLOOD		= 8,	/* Too many subsequent pacts */
	ERR_BADBALANCE		= 9,	/* Transaction balance incorrect */

	ERR_BLK_EARLY		= 10,	/* Block too early */
	ERR_BLK_LATE		= 11,	/* Block too late */

	__ERR_MAX
};

extern const char *schkerror(error_t error);

#endif /* __TIFA_ERROR_H */
