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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sodium.h>
#include "log.h"
#include "node.h"
#include "config.h"

static keypair_t *__node_key = NULL;
static char __node_name[NODE_NAME_LENGTH + 1];

static char *
node_checksum(char *ident, char *buffer)
{
	char hex[3];
	unsigned char checksum[sizeof(TIFA_NODE_IDENT)];

        crypto_generichash(checksum, sizeof(TIFA_NODE_IDENT) - 1,
                           (uint8_t *)ident, strlen(ident), NULL, 0);
	for (size_t i = 0; i < strlen(TIFA_NODE_IDENT); i++) {
		uint8_t c;

		c = checksum[i] - TIFA_NODE_IDENT[i];
		sprintf(hex, "%02hhx", c);
		buffer[i] = hex[1];
	}

	buffer[strlen(TIFA_NODE_IDENT)] = '\0';

	return (buffer);
}

char *
public_key_node_name(public_key_t public_key)
{
	static node_name_t node_name;

	return (public_key_node_name_r(public_key, node_name));
}

char *
public_key_node_name_r(public_key_t public_key, node_name_t name)
{
	char ident[KEYPAIR_NAME_LENGTH + 1];
	char prepend_chksum[strlen(TIFA_NODE_IDENT) + 1];

	public_key_name(public_key, ident);
	node_checksum(ident, prepend_chksum);

	snprintf(name, NODE_NAME_LENGTH + 1, "%s:%s:%s",
		 TIFA_NODE_IDENT, prepend_chksum, ident);
	name[NODE_NAME_LENGTH] = '\0';

	return (name);
}

static void
generate_node_name(void)
{
	char ident[KEYPAIR_NAME_LENGTH + 1];
	char prepend_chksum[strlen(TIFA_NODE_IDENT) + 1];

	keypair_name(__node_key, ident);
	node_checksum(ident, prepend_chksum);

	snprintf(__node_name, NODE_NAME_LENGTH + 1, "%s:%s:%s",
		 TIFA_NODE_IDENT, prepend_chksum, ident);
	__node_name[NODE_NAME_LENGTH] = '\0';
}

void
node_keypair_load()
{
	char file[MAXPATHLEN + 1];

	if (access(config_path_r(file, "node_identity.keypair"), F_OK) == -1) {
		__node_key = keypair_create();
		keypair_save(__node_key, file);
		generate_node_name();
		lprintf("created node identity = %s", __node_name);
	} else {
		__node_key = keypair_load(file);
		generate_node_name();
		lprintf("loaded node keypair = %s", __node_name);
	}
}

char *
node_name()
{
	return (__node_name);
}

int
is_node(const char *name)
{
	char buf[NODE_NAME_LENGTH + 1];
	int colon1idx, colon2idx;
	char checksum[strlen(TIFA_NODE_IDENT) + 1];

	if (strlen(name) != NODE_NAME_LENGTH) {
		lprintf("is_node: not a tifa node: %s", name);
		return (FALSE);
	}
	strncpy(buf, name, NODE_NAME_LENGTH);
	buf[NODE_NAME_LENGTH] = '\0';

	colon1idx = strlen(TIFA_NODE_IDENT);
	colon2idx = strlen(TIFA_NODE_IDENT) + 1 + strlen(TIFA_NODE_IDENT);
	if (buf[colon1idx] != ':' || buf[colon2idx] != ':') {
		lprintf("is_node: not a tifa node: %s", name);
		return (FALSE);
	}
	buf[colon1idx] = '\0';
	buf[colon2idx] = '\0';

	if (strcmp(TIFA_NODE_IDENT, buf) != 0) {
		lprintf("is_node: not a tifa node: %s", name);
		return (FALSE);
	}

	node_checksum(buf + colon2idx + 1, checksum);
	if (strcmp(checksum, buf + colon1idx + 1) != 0) {
		lprintf("is_node: invalid checksum: %s: %s (should be=%s)",
			name, buf + colon1idx, checksum);
		return (FALSE);
	}

	return (TRUE);
}

keypair_t *
node_keypair()
{
	return (__node_key);
}

void *
node_public_key()
{
	return (keypair_public_key(__node_key));
}
