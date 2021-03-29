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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <sysexits.h>
#ifdef __linux__
#  include <endian.h>
#else
#  include <sys/endian.h>
#endif
#include "network.h"
#include "txcache.h"
#include "config.h"
#include "wallet.h"
#include "block.h"
#include "node.h"
#include "lock.h"
#include "log.h"

static char *cmd;
static size_t send_count;

static int usage(int deliberate);

static int opt_wallets(int argc, char *argv[]);
static int opt_addresses(int argc, char *argv[]);
static int opt_blocks(int argc, char *argv[]);
static int opt_history(int argc, char *argv[]);
static int opt_send(int argc, char *argv[]);
static int opt_node(int argc, char *argv[]);
static int opt_resetblocks(int argc, char *argv[]);

static int
usage(int deliberate)
{
	FILE *f;

	f = deliberate ? stdout : stderr;

	fprintf(f, "TIFAnet version %s.\n\n", TIFA_VERSION_STR);

	fprintf(f, "Usage: %s [<command>] [<opts...>]\n\n", cmd);
	fprintf(f, "  help             show this help\n");
	fprintf(f, "  node             show some node information\n");
	fprintf(f, "  resetblocks      remove all blocks data and caches\n");
	fprintf(f, "  wallets          list wallets and balances\n");
	fprintf(f, "  wallet\n");
	fprintf(f, "    -l             only list wallets, not balances\n");
	fprintf(f, "    -c <name>      create new wallet with <name>\n");
	fprintf(f, "  addresses        enumerate addresses\n");
	fprintf(f, "  address\n");
	fprintf(f, "    <wallet>       enumerate addresses in <wallet>\n");
	fprintf(f, "    -c <wallet>    create new addresss in <wallet>\n");
	fprintf(f, "    -v <address>   validate an address\n");
	fprintf(f, "  history          show pact history\n");
	fprintf(f, "    <wallet>       for <wallet>\n");
	fprintf(f, "    <address>      for <address>\n");
	fprintf(f, "  send             sends <amount> from <wallet> or "
		"<address> to <destination>\n");
	fprintf(f, "    <wallet|address> <destination> <amount>\n");

	return (deliberate ? 0 : EX_USAGE);
}

static void
wallet_balance_show(wallet_t *w)
{
	double balance;

	balance = wallet_balance(w);
	printf("  - \"%s\": %2.2f\n", wallet_name(w), stoi(balance));
}

static int
opt_wallets(int argc, char *argv[])
{
	wallet_t **w;
	wallet_t *n;

	w = wallets();

	switch(argc) {
	case 0:
		printf("---\nresult:\n");
		for (size_t i = 0; w[i]; i++)
			wallet_balance_show(w[i]);
		return (0);
	case 1:
		if (strcmp(argv[0], "-l") == 0) {
			printf("---\nresult:\n");
			for (size_t i = 0; w[i]; i++)
				printf("  - \"%s\"\n", wallet_name(w[i]));
			break;
		} else
			return usage(FALSE);
	case 2:
		if (strcmp(argv[0], "-c") == 0) {
			if (argv[1][0] == '.') {
				printf("error: %s: name can't start with a "
					"dot.\n", argv[1]);
				return (EX_USAGE);
			}
			if (index(argv[1], '/')) {
				printf("error: %s: name can't contain a "
					"slash.\n", argv[1]);
				return (EX_USAGE);
			}
			if (index(argv[1], '"')) {
				printf("error: %s: name can't contain a "
					"double quote.\n", argv[1]);
				return (EX_USAGE);
			}
			if (!(n = wallet_create(argv[1]))) {
				printf("error: %s: failed to create wallet\n",
					argv[1]);
				return usage(FALSE);
			}
			printf("---\nresult: \"%s\"\n", argv[1]);
			break;
		} else
			return usage(FALSE);
	default:
			return usage(FALSE);
	}

	return (0);
}

static int
opt_addresses(int argc, char *argv[])
{
	wallet_t *n;
	wallet_t **w;
	address_t *addr;
	address_t **addrs;
	size_t num_addrs;

	w = wallets();

	switch (argc) {
	case 0:
		printf("---\nresult:\n");
		for (size_t i = 0; w[i]; i++) {
			printf("  - \"%s\":\n", wallet_name(w[i]));
			addrs = wallet_addresses(w[i], &num_addrs);
			for (size_t j = 0; j < num_addrs; j++)
				printf("     - \"%s\": %2.2f\n",
					address_name(addrs[j]),
					stoi(address_unspent(addrs[j])));
		}
		break;
	case 1:
		if (!(n = wallet_load(argv[0]))) {
			printf("error: \"can't load wallet: %s\"\n",
				argv[0]);
			return (EX_USAGE);
		}
		printf("---\nresult:\n");
		addrs = wallet_addresses(n, &num_addrs);
		for (size_t j = 0; j < num_addrs; j++)
			printf("  - \"%s\": %2.2f\n", address_name(addrs[j]),
				stoi(address_unspent(addrs[j])));
		break;
	case 2:
		if (strcmp(argv[0], "-c") == 0) {
			if (!(n = wallet_load(argv[1]))) {
				printf("error: \"can't load wallet: %s\"\n",
					argv[1]);
				return (EX_USAGE);
			}
			addr = wallet_address_generate(n);
			printf("---\nresult: \"%s\"\n", address_name(addr));
			break;
		} else if (strcmp(argv[0], "-v") == 0) {
			printf("---\nresult: ");
			if (is_address(argv[1])) {
				printf("true\n");
			} else {
				printf("false\n");
			}
			break;
		} else
			return usage(FALSE);
	default:
		return usage(FALSE);
	}

	return (0);
}

static int
opt_blocks(int argc, char *argv[])
{
	size_t sz;
	big_idx_t idx;
	raw_block_t *raw_block;

	switch (argc) {
	case 0:
		raw_block = raw_block_last(&sz); // sz not used
		raw_block_print(raw_block);
		break;
	case 1:
		idx = strtoimax(argv[0], NULL, 10);
		if (idx > block_idx_last()) {
			printf("error: index out of range: %ju\n", idx);
			return (EX_DATAERR);
		}
		raw_block = block_load(idx, &sz);
		raw_block_print(raw_block);
		break;
	default:
		return usage(FALSE);
	}

	return (0);
}

static void
show_tx_history(raw_block_t *b, pact_tx_t *tx, pact_rx_t *rxb, size_t num_rx)
{
	amount_t prev_amount = 0;
	address_name_t addrname;
	raw_pact_t *pt;
	raw_block_t *pb;
	pact_tx_t *ptx;
	pact_rx_t *rx;
	amount_t txa;
	double a;
	size_t sz;

	txa = be64toh(tx->amount);
	printf("  - block_idx: %ju\n", block_idx(b));
	printf("    from: \n");
	rx = rxb;
	for (size_t ri = 0; ri < num_rx; ri++) {
		pb = block_load(be64toh(rx->block_idx), &sz);
		pt = pact_for_tx_idx(pb, be32toh(rx->block_tx_idx));
		ptx = pact_tx_ptr(pt);
		for (size_t ti = 0; ti < pact_num_tx(pt); ti++) {
			if (pubkey_compare(tx->address, ptx->address) == 0) {
				prev_amount += be64toh(ptx->amount);
			} else {
				printf("      - \"%s\"\n",
					public_key_address_name(ptx->address,
						addrname));
			}
			ptx = (void *)ptx + sizeof(pact_tx_t);
		}
	}
	a = stoi(txa) - stoi(prev_amount);

	printf("    to: \"%s\"\n", public_key_address_name(tx->address,
		addrname));
	printf("    amount: %2.2f\n", a);
}

static void
show_pact_history(raw_block_t *b, raw_pact_t *t,
	public_key_t *addrs, size_t num_addrs)
{
	pact_rx_t *rx = pact_rx_ptr(t);
	pact_tx_t *tx = pact_tx_ptr(t);
	for (small_idx_t ti = 0; ti < pact_num_tx(t); ti++) {
		for (size_t ai = 0; ai < num_addrs; ai++)
			if (pubkey_compare(addrs[ai], tx->address) == 0)
				show_tx_history(b, tx, rx, pact_num_rx(t));

		tx = (void *)tx + sizeof(pact_tx_t);
	}
}

static void
show_history(public_key_t *addrs, size_t num_addrs)
{
	size_t bs;
	raw_block_t *b;
	raw_pact_t *t;

	for (b = block_load(0, &bs); b; b = block_load(block_idx(b) + 1, &bs)) {
		t = raw_block_pacts(b);
		for (small_idx_t ti = 0; ti < num_pacts(b); ti++) {
			show_pact_history(b, t, addrs, num_addrs);
			t = (void *)t + pact_size(t);
		}
	}
}

static int
opt_history(int argc, char *argv[])
{
	size_t addrs_size;
	wallet_t **w, *wlt;
	size_t num_addrs = 0;
	public_key_t addrs[100];
	address_t **a;

	w = wallets();
	switch (argc) {
	case 0:
		w = wallets();
		for (size_t wi = 0; w[wi]; wi++) {
			a = wallet_addresses(w[wi], &addrs_size);
			for (size_t ai = 0; ai < addrs_size; ai++) {
				bcopy(address_public_key(a[ai]),
					addrs[num_addrs], sizeof(public_key_t));
				num_addrs++;
			}
		}
		break;
	case 1:
		if (is_address(argv[0])) {
			address_name_to_public_key(argv[0], addrs);
			num_addrs = 1;
		} else {
			if (!(wlt = wallet_load(argv[0]))) {
				printf("---\nresult:\n  wallet not found\n");
				return (FALSE);
			}
			a = wallet_addresses(wlt, &addrs_size);
			for (size_t ai = 0; ai < addrs_size; ai++) {
				bcopy(address_public_key(a[ai]),
					addrs[num_addrs], sizeof(public_key_t));
				num_addrs++;
			}
		}
		break;
	default:
		return usage(FALSE);
	}

	printf("---\nresult:\n");

	show_history(addrs, num_addrs);

	return (TRUE);
}

static int
check_amount(const char *amount)
{
	int dotcount = 0;

	for (size_t i = 0; amount[i]; i++) {
		if (amount[i] == '.') {
			dotcount++;
			if (dotcount > 1)
				return (FALSE);
			continue;
		}
		if (amount[i] < '0' || amount[i] > '9')
			return (FALSE);
	}

	return (TRUE);
}

static void
send_callback(event_info_t *info, event_flags_t eventflags)
{
	send_count--;
	if (!send_count)
		exit(0);
}

static int
opt_send(int argc, char *argv[])
{
	amount_t amount, tmp_amount, a_amount;
	char *src_str, *dst_str, *amount_str;
	raw_pact_t *raw_pact;
	wallet_t *wallet = NULL;
	amount_t balance = 0;
	address_t **addrs;
	double amount_src;
	txcache_t **items;
	public_key_t dst;
	pact_t *t;
	address_t *src;
	size_t naddrs;
	size_t tsize;
	int delay;

	if (argc != 3)
		return usage(FALSE);

	src_str = argv[0];
	dst_str = argv[1];
	amount_str = argv[2];

	if (!wallet_exists(src_str)) {
		wallet = NULL;
		if (!(src = address_find_by_name(src_str))) {
			printf("---\nresult:\n");
			printf("  error: source wallet/address not found\n");
			return (FALSE);
		}
	} else {
		src = NULL;
		wallet = wallet_load(src_str);
	}

	if (!address_name_to_public_key(dst_str, dst)) {
		printf("---\nresult:\n  error: malformed destination "
			"address\n");
		return (FALSE);
	}

	if (!check_amount(amount_str)) {
		printf("---\nresult:\n  error: malformed amount\n");
		return (FALSE);
	}
	amount_src = strtod(amount_str, NULL);
	if (amount_src == 0.0) {
		printf("---\nresult:\n  error: amount is 0\n");
		return (FALSE);
	}
	amount = itos(amount_src);

	if (wallet)
		balance = wallet_balance(wallet);
	if (src)
		balance = address_unspent(src);

	if (balance < amount) {
		printf("---\nresult:\n  error: amount %.2f exceeds balance "
			"%.2f\n", stoi(amount), stoi(balance));
		return (FALSE);
	}

	t = pact_create();
	pact_tx_add(t, dst, amount);
	if (src) {
		items = txcaches_for_address(src, &tsize);
		for (size_t i = 0; i < tsize; i++)
			pact_rx_add(t, be64toh(items[i]->block_idx),
				be32toh(items[i]->block_tx_idx));
		if (balance - amount > 0)
			pact_tx_add(t, address_public_key(src),
				balance - amount);
	} else {
		addrs = wallet_addresses(wallet, &naddrs);
		for (size_t i = 0; i < naddrs; i++) {
			if (address_unspent(addrs[i]) == amount) {
				src = addrs[i];
				break;
			}
		}
		if (src) {
			items = txcaches_for_address(src, &tsize);
			for (size_t i = 0; i < tsize; i++)
				pact_rx_add(t,
					be64toh(items[i]->block_idx),
					be32toh(items[i]->block_tx_idx));
		} else {
			tmp_amount = amount;
			for (size_t i = 0; i < naddrs && tmp_amount; i++) {
				a_amount = address_unspent(addrs[i]);
				if (tmp_amount >= a_amount) {
					tmp_amount -= a_amount;
					items = txcaches_for_address(addrs[i],
						&tsize);
					for (size_t i = 0; i < tsize; i++)
						pact_rx_add(t, be64toh(items[i]->block_idx), be32toh(items[i]->block_tx_idx));
				} else {
					items = txcaches_for_address(addrs[i], &tsize);
					for (size_t i = 0; i < tsize; i++)
						pact_rx_add(t, be64toh(items[i]->block_idx), be32toh(items[i]->block_tx_idx));
					pact_tx_add(t, address_public_key(addrs[i]), a_amount - tmp_amount);
					tmp_amount = 0;
				}
			}
			
		}
	}
	printf("---\nresult:\n");
	pact_finalize(t);
	raw_pact = raw_pact_create(t, &tsize);
	if ((delay = pact_delay(raw_pact, 0))) {
		if (delay >= 10) {
			printf("  - message: pact would be delayed "
				"for %d blocks, not sending. Consider "
				"trying again in five minutes.\n", delay);
			exit(0);
		}
		printf("  - message: pact will be delayed for %d "
			"blocks.\n", delay);
	}

	peerlist_load();

	event_handler_init();

	send_count = message_broadcast_with_callback(OP_PACT,
			raw_pact, tsize, 0, send_callback);

	event_loop_start();

	return (TRUE);
}

static int
opt_node(int argc, char *argv[])
{
	if (argc != 0)
		return (FALSE);

	printf("---\nresult:\n  node: %s\n", node_name());

	return (TRUE);
}

static int
opt_resetblocks(int argc, char *argv[])
{
	//int res;

	if (argc != 0)
		return (FALSE);

	// unlink blocks*.bin, txcache.bin and notars.bin
	printf("---\nresult: true\n");

	return (TRUE);
}

int
main(int argc, char *argv[])
{
	char *opt;

	cmd = argv[0];
	opt = argv[1];

	if (argc == 1)
		return usage(FALSE);

	loglevel = 0;

	config_load();

	if (!lockfile_create()) {
		lprintf("couldn't create lockfile");
		exit(EX_TEMPFAIL);
	}
	if (!lockfile_is_locked())
		system("tifanetd -f -s");

	node_keypair_load();
	wallets_load();
/*
block_generate_next();
raw_block_t *rb = raw_block_last();
exit(1);
*/
	block_last_load();
	txcache_load();

	argc -= 2;
	argv += 2;
	if (strcmp(opt, "-h") == 0 || strcmp(opt, "help") == 0)
		return usage(TRUE);
	else if (strcmp(opt, "wallets") == 0 || strcmp(opt, "wallet") == 0)
		return opt_wallets(argc, argv);
	else if (strcmp(opt, "addresses") == 0 || strcmp(opt, "address") == 0)
		return opt_addresses(argc, argv);
	else if (strcmp(opt, "history") == 0)
		return opt_history(argc, argv);
	else if (strcmp(opt, "blocks") == 0 || strcmp(opt, "block") == 0)
		return opt_blocks(argc, argv);
	else if (strcmp(opt, "send") == 0)
		return opt_send(argc, argv);
	else if (strcmp(opt, "node") == 0)
		return opt_node(argc, argv);
	else if (strcmp(opt, "resetblocks") == 0)
		return opt_resetblocks(argc, argv);

	return (usage(FALSE));
}
