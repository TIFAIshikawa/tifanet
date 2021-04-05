INTRODUCTION
------------
TIFAnet (This Is F'ing Awesome network).

RATIONALE
---------
Altough an interesting attempt, the proposed Bitcoin solution - and by
extension most if not all of the so-called "altcoins" the Bitcoin project
spawned, if not by code forks then at least in spirit - still fell for
several pitfalls of old ideas and greed-- be it by design or uncontiously
implored by "common sense", "group think" or "we've always done it like this."
For all of the percieved "forward thinking," "Satoshi" had it surprisingly
backwards in some areas when this entity designed Bitcoin.

Take "mining." Besides the point, mining itself is something humanity should
not continue doing unless absolutely necessary. On point, the process
of "mining" Bitcoin has grown to an exceedingly computationally laborious
task. For what? The "mining" entity does not know anything or for that matter
_do_ anything that another node on the network could not have done. The
Bitcoin algorithm makes it impose authority by solving a useless puzzle
slightly faster than competing "mining" nodes on the network. For this
authority and optionally (!) including Bitcoin transactions onto its ledger,
it is then awarded an amount of Bitcoin. Proof-of-work simply proves the
node did computational work **absolutely not relevant** to the act of adding
transactions to the ledger while the latter clearly is the goal of the former,
algorithm-wise. Think about it. Avoiding double-spending is not solved by
calculating a hash starting with an X number of zeroes slightly faster than any
other node. Double-spending is solved by _checking_. Repurposing a failed
anti-spam measure as a "proof-of-delay" to ensure chain size seems counter
intuitive.
"Mining" taken by itself is an institutionalized race condition, only tamed
by the 51 percent rule: truely this rule only exists to fix the race
condition introduced by the misguided notion that one needs this computation
in order to appear trustworthy.

Take fees. Transaction fees incentivise "miners" to include the respective
transactions onto the ledger. Ergo: some transactions are prioritized,
playing right into the hand of the age-old separation of classes-- if you
have money to spend, you are preferred. All transactions are equal, but some
are simply more equal than others. The selection of transactions for inclusion
on the ledger should not depend on petty things like if the issuer of the
transaction doesn't care to throw money away to be prioritized or not. The
_only_ requirement should be the validity of the transaction. Inclusion should
be as chronological as possible. Fees are a signal of greed in this case,
since the act of "mining"/including on the ledger already brings the "miner"
gains. Incentivising adding more transactions is not the problem. It can
be done as a fixed function reward which takes into account the nunber of
included transactions. Transactions should **never** be special.

Take the maximum of 21 million "coins." Inflation itself is not a problem;
rampant inflation is, just like rampant everything else. A maximum amount
of "coins" was a greedy inclusion in the sofware, be it intentional or not.
"Coins" get sent to wrong addresses, addresses on other forked ledgers, wallets
get deleted and passphrases forgotten. 21 million is not enough, not even for
a small nation, let alone the world. Controlled inflation - it's, like,
_encoded in the protocol, it's impossible to get any more controlled
than that_ - takes away the concerns around "coins" getting lost due to
the several means they can get lost and incentivise people to not HODL since
money's purpose isn't to not change hands.

SOLUTION
--------
The solution is TIFAnet. This currency abolishes "mining". It abolishes fees.
Nodes in the network can be a client node and optionally, voluntarily, under
certain circumstances, also be a notarial node. For every block, notar nodes
elect one of the notar nodes to create the next block on the ledger, including
the next set of selected transactions. The election of the next block notar
abolishes the need for "mining." The block is published by the notar node,
which includes a block reward for this node and is checked by all other
notars. The next notar is selected algorithmically and so the process
continues. If the block fails checks, the block notar is repelled from the
network by the checking nodes, likewise if a notar tries to propose a block
while it is not the next block notar. This might cause the blockchain to split,
but since all facts are encoded in the process and algorithm itself, the
sofware has only one choice: follow the computationally correct ledger.
In comparison, Bitcoin very phallilcally follows the biggest ledger even if
it's a fraudulent one.

TECHNOLOGY
----------
The Bitcoin ledger, although increasingly growing in size, is not an immediate
problem. Likewise Bitcoin traceability: some cryptocurrencies attempt to
hide accounting information from their transactions. It never seemed to be
a problem that Bitcoin was created to solve as its current implementation
was even addressed in the Bitcoin whitepaper, and quite frankly isn't a problem
worth throwing the added complexity at.
Fees are a problem, "mining" is a problem: both are not integral to the
currency and add unwanted and unnecessary complexity. Code complexity is
also a problem. The TIFAnet code was written from scratch and is as
simple as possible to achieve its goal. TIFAnet might share some
general ideas with Bitcoin. Good ideas should get picked up and be improved
upon. Bad ideas had better be left behind.
