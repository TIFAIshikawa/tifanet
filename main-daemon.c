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
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <strings.h>
#include <sysexits.h>
#include <sys/stat.h>
#include "peerlist.h"
#include "network.h"
#include "rxcache.h"
#include "config.h"
#include "wallet.h"
#include "event.h"
#include "notar.h"
#include "cache.h"
#include "node.h"
#include "lock.h"
#include "log.h"

#include "pact.h"
#include "block.h"

static void
save_state(int signal)
{
	big_idx_t idx;

	if (config_is_caches_only()) {
		idx = be64toh(block_idx_last());
		rxcache_save(idx);
		notarscache_save(idx);
	}
	peerlist_save_sync();
	exit(0);
}

static int
usage(char *cmd, int deliberate)
{
	FILE *f;

	f = deliberate ? stdout : stderr;

	fprintf(f, "TIFAnet version %s.\n\n", TIFA_VERSION_STR);


	fprintf(f, "Usage: %s [-f] [-n] [-s] [-c] [-h]\n\n", cmd);
	fprintf(f, "	-f	don't daemonize, run on foreground\n");
	fprintf(f, "	-n	run in notar mode\n");
	fprintf(f, "	-s	synchronize the blockchain and quit when "
		"done\n");
	fprintf(f, "	-c	synchronize only caches\n");
	fprintf(f, "	-h 	show this help text\n");
	fprintf(f, "\n");

	return (deliberate ? 0 : EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int should_fork = 1;
	int ch, pid, fd;

	while ((ch = getopt(argc, argv, "fhnsSc")) != -1) {
		switch (ch) {
		case 'f':
			should_fork = 0;
			break;
		case 'n':
			config_set_notar_node(TRUE);
			break;
		case 's':
			config_set_sync_only(TRUE);
			break;
		case 'c':
			config_set_caches_only(TRUE);
			break;
		case 'h':
			return usage(argv[0], TRUE);
		default:
			return usage(argv[0], FALSE);
		}
	}

	if (config_is_sync_only() && config_is_notar_node()) {
		fprintf(stderr, "tifanetd: -s and -n options cannot "
			"be enabled simultaneously\n");
		exit(EX_USAGE);
	}
	if (config_is_caches_only() && config_is_notar_node()) {
		fprintf(stderr, "tifanetd: -c and -n options cannot "
			"be enabled simultaneously\n");
		exit(EX_USAGE);
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_load();

	if (should_fork)
		log_open();

	peerlist_load();

	if (!lockfile_create() || lockfile_is_locked()) {
		lprintf("lockfile already locked. Exiting.");
		exit(EX_TEMPFAIL);
	}
	daemon_lock();

	node_keypair_load();
	wallets_load();

	if (config_is_caches_only()) {
		blocks_remove();
	} else {
		blockchain_load();
		block_last_load();
		notarscache_load();
		rxcache_load();
		if (notars_last_block_idx() != rxcache_last_block_idx()) {
			lprintf("notarscache block idx %ju != rxcache block "
				"idx %ju", notars_last_block_idx(),
				rxcache_last_block_idx());
			exit(EX_TEMPFAIL);
		}
	}

	signal(SIGTERM, save_state);
	signal(SIGINT, save_state);

	if (should_fork) {
		if ((pid = fork())) {
			return (0);
		} else {
			setsid();
			chdir("/");
			if (fork()) { // fork again so no tty can be attached
				exit(0);
			} else {
				if ((fd = open("/dev/null", O_RDWR)) != -1) {
					dup2(fd, STDIN_FILENO);
					dup2(fd, STDOUT_FILENO);
					dup2(fd, STDERR_FILENO);
					close(fd);
				}
				umask(0);

				if (lockfile_is_locked()) {
					// re-lock after fork
					lprintf("lockfile already locked. "
						"Exiting.");
					exit(EX_TEMPFAIL);
				}
				daemon_lock();
			}
		}
	}

	event_handler_init();

	peerlist_request_broadcast();

	if (config_is_caches_only()) {
		cache_download();
	} else {
		daemon_start();
	}

	event_loop_start();

	save_state(SIGTERM);

	return (0);
}
