# Proofs

A design is a promise. This page lists what Everpool claims, what would prove
each claim, and where that proof stands. Every entry ends in something anyone
can check without trusting the project: a test that runs in CI, a script that
reruns on a fresh machine, or a transaction on a public chain.

Status: **done** (proof published), **partial** (some of it published),
**planned** (defined, not yet run). Each result is added here with its date,
its numbers and the command or transaction that shows it.

| # | claim | what proves it | status |
|---|---|---|---|
| 1 | Attacks cost the attacker and buy little | attack scripts against a testnet pool, with measured cost and effect | planned (Phase C, D) |
| 2 | A pool outlives its creator and its guardians | testnet runs: creator gone for good, every guardian down at once, revival from a carrier and from the record alone | done |
| 3 | Payouts are exact and need no one | every coinbase checked to the satoshi against the share chain, across reorgs and restarts, then spent | partial |
| 4 | It scales to hundreds of pools | a load harness: 200 pools, 2000 simulated miners, CPU, memory, disk and bandwidth per node | planned |
| 5 | Modest computers can take part | sync time, RAM and traffic measured on a low-end machine, over Tor and over a bridge | planned |
| 6 | Anyone can audit it | reproducible tests and vectors, reproducible builds, independent review of the final code | partial |
| 7 | Other chains can adopt it | the portable library and vectors, then Everpool running on a second chain's test network | partial |
| 8 | Using it takes no expertise | create, join and mine a pool in a few commands, then from the wallet's interface | partial |

## 1. Attacks

Each attack in SPEC section 12 gets a script that runs it on testnet, and a
result with what it cost and what it changed:

- **Sybil on tickets:** an attacker with as much ticket work as all honest
  nodes together. Measure how many pools' places it holds, against the
  (A / (H + A))^16 estimate of section 12.
- **Ticket flooding:** fill the 4096 places; show honest guardians keep what
  they hold and `poolwho` still finds the pool.
- **Withholding:** every guardian of one pool refuses to serve for a whole
  epoch; show a new miner still gets the line from a miner or carrier.
- **Stale or private line:** a guardian serves an old line; show the reviving
  node logs the anchor warning and takes the heavier line.
- **Share manipulation:** invalid shares, shares with forged work, a forged
  deep history, shares replayed from another network. Each must be refused
  and scored as section 8 says, and pool zero must be unaffected.
- **Flooding:** `p2x*` messages for pools not carried, oversized shares,
  history asks past the budgets. Measure CPU and memory during the flood.

## 2. Survival

SPEC section 15, Phase D, steps 3 to 5, on testnet with real coins:

- The creator shuts down for good; the pool keeps finding blocks.
- Every miner stops; past an epoch change a fresh node fetches the line from
  the guardians and its first block pays the old window.
- Every guardian of both sets stops at once during a handoff, with one carrier
  left; a fresh node finds the line through `poolwho`.
- Every copy is deleted; a fresh miner restarts the pool from its record, same
  id, and finds a block.

Done so far, private pools on Bitflash testnet (16 and 17 November 2026),
three nodes, one of them given a wrong password (it got nothing):

- Block 24619 paid two members 30 and 20 BTF from the shares they mined
  together; each member spent its own output, confirmed at height 24739
  (`915fb205...3525`, `cec291ea...f7de`).
- Again with the salted share format: block 24740 paid each member 25 BTF.
  Its coinbase carries one `"p2l"` anchor and no pool id. Knowing the code
  and the right password, 39,390 rebuilds of the share data from chain data
  matched nothing; only the salt from a member's own share file makes the
  anchor match. A member restarted from its file and caught up. Both outputs
  were spent after maturity, confirmed at height 24862
  (`71a47721...5d27`, `2d99c5c1...7733`).

- Members on two separate machines, one of them reaching the network only
  through Snowflake bridges (its Tor's every circuit had a Snowflake bridge
  as first hop, and Tor made no connection outside the machine except
  through it): block 24870 paid 26.875 and 23.125 BTF to the two members;
  after maturity each spent its own output, confirmed at heights 24991 and
  24992 (`6e25c18a...99af`, `a7001044...9b8d`).

Done so far, registered pools on an isolated two-node test chain (17
November 2026), with the node's own `poolcreate everpool` and a real 1 BTF
burn: the pool was pending, then reorged out at 4 confirmations and left
`poollist`; the same burn mined again on the new branch brought it back with
the same id, active at 30 confirmations; a reorg after 31 confirmations
removed it again, as SPEC section 3 says (depth decides when a pool starts
counting, never that the chain cannot remove it). The index file was read
back on every restart with the same answers.

Done so far, guardians on Bitflash testnet (18 November 2026), four nodes on
the reference node with phase C: each made real RandomX tickets for epochs 35
and 36, they exchanged them and drew. One node mined the registered pool
`p2xproof` (pool blocks 25809 and 25812); the two nodes the draw named pulled
its whole line, 506 shares. The miner was then stopped. A fresh node with no
pool files, connected only to those two guardians, had the complete line in
41 seconds and mined on it. Its first block, 25817 (`e4972095...7a73`),
paid the creator fee and the old window: 23.41657107 and 21.85110944 BTF to
the two miners of the earlier run, 3.76316535 BTF to the stopped miner, and
0.46915414 BTF to itself. A script rebuilt that coinbase to the satoshi from
both a guardian's copy of the line and the fresh node's. After maturity the
fresh node spent its own payout and the stopped miner, brought back, spent
what the window paid it; both confirmed in block 25938 (`48906eb5...4c50`,
`f6c3477f...bd39`).

Phase D on Bitflash testnet (18 and 19 November 2026), on the reference node
with phases B and C:

- **The creator leaves for good.** Pool `phasedB` (id `8279b9ae...115d`) was
  registered and mined by one node. That node spent its own payout (block
  26151) and was then shut down for good at height 26151. Another node kept
  mining B: block 26153 (`84bf17b8...f811`) paid the creator fee, the
  window the departed creator had mined (48.04156133 BTF) and the new miner
  (1.45843867 BTF), checked to the satoshi against two other nodes' copies of
  the line. The new miner spent its output, confirmed in block 26273
  (`f1569abc...8593`).
- **Revived from the record alone.** Every node holding pool `phasedA`'s line
  was stopped and every copy deleted, on both machines. A fresh node with
  only the chain found no one announcing the pool and no one to ask, started
  the line again from a first share with no parent, under the same id, and
  found block 26050 (`17bfe9c0...506e`), checked to the satoshi against two
  nodes that fetched the new line afterwards. Its payout was spent, confirmed
  in block 26172 (`27dbdb38...91d0`).
- **An "edit" makes another pool.** `phasedA` with only its window changed
  (720 to 1080) got a different id (`4a7b5c45...9969` against
  `e3468049...5afa`); both are listed as separate pools, each flagged as
  sharing its name with the other, and the original's record, id and line
  were untouched and it kept finding blocks.

- **Every guardian down at once, one carrier left.** At height 26613 every
  node the draw had named a guardian of `phasedA` was stopped at once; the
  only copy of the line left online was a carrier on a second machine. A
  fresh node with no pool files and one fixed peer that did not hold the
  line found nobody to ask, asked its peers who carries the pool
  (`poolwho`), was given two names, dialled them and had the complete line
  three minutes after it started. Its block 26616 (`c0d1dd07...f617`) was
  checked to the satoshi, creator fee included, against its own copy and
  against a guardian's copy fetched after the block; its payout was spent,
  confirmed in block 26736 (`8ee3b6a5...ecad`).

## 3. Payouts

For every block a test pool finds: the coinbase is rebuilt from the share
chain and compared to the satoshi, including the creator fee output. Coins are
then left to mature and are spent, so the payout is proved by moving it, not
by reading it. The same check runs after a reorg of the main chain, after a
reorg of the share chain, and after nodes restart mid-window.

Done so far: pool zero, the P2Pool Everpool extends, was proved this way on
Bitflash testnet (paid, matured, spent); the first local pool payout above.

A registered pool on Bitflash testnet (17 November 2026): pool `p2xproof`,
id `16e4d33e...4508`, 1% creator fee, burned in block 25233 (txid
`bffb4c0f...8f71`); no node served a template for it before 30
confirmations. Block 25268 paid the two miners 45.96428572 and 3.53571428
BTF and the creator 0.5 BTF, with the `"p2x"` anchor in its coinbase. An
independent script rebuilt that coinbase to the satoshi from the line a
third node had fetched over the network (`p2xsync`) without mining. Both
miners spent their outputs after maturity, confirmed in block 25389
(`5d44733d...44be`, `7fd3970d...c50f`). Over about 4.5 hours the pool found 56
blocks, the three nodes ended on the same line, no share was refused and no
peer was scored; a 1.2.34 node mining pool zero alongside had 847 shares
accepted and none rejected.

Two registered pools at once on Bitflash testnet (18 November 2026): pool
`phasedA` (spacing 20 s, window 720, no fee) and pool `phasedB` (spacing 30
s, window 1440, 1% fee to a fresh address), both burned in block 25999 and
active at 26028, mined on different nodes. A found blocks 26035 to 26042, B
found 26030, 26038, 26051, 26054 and 26055. Each of the first five A blocks
and B's 26030 and 26038 was rebuilt to the satoshi from two independent
copies of the line, one on each machine; B's fee output was exactly 0.5 BTF
every time. A node on release 1.2.34 mined pool zero alongside the whole
time with no share refused. Spent after maturity: A's 26035 payout
(`b16140d8...ba84`, block 26157), and from B's 26030 both the miner's output
and the creator fee (`fe69a0ff...5f23`, `5f428be7...1ae9`, block 26151).

Miners behind Tor bridges on Bitflash testnet (19 and 20 November 2026),
SPEC section 17: pool `phasedA` (one share every 20 s) mined by two nodes
with ordinary Tor and two nodes that reach the network only through a
bridge, one obfs4 node and one Snowflake node on a second machine, each
bridge node with about a tenth of the pool's hashrate. Counted over ten
hours (shares 1082 onwards):

| bridge | shares found | on the line | uncles | lost | paid | the model said |
|---|---|---|---|---|---|---|
| Snowflake | 214 | 184 | 25 | 5 (2.3%) | 95.35% | 98.25% |
| obfs4 | 219 | 207 | 12 | 0 | 98.96% | 98.87% |

Both stayed inside the marks set before the run (at most 5% lost, paid
within 3 points of the model). One way, the median delay from a bridge node
to the first ordinary node was 0.61 s (Snowflake) and 0.50 s (obfs4); from
the ordinary nodes back to the bridge node 1.14 s and 0.68 s, with stalls of
up to 33 s on the Snowflake side. Four of the Snowflake node's five lost
shares came during those stalls, which a model fed the median delay does
not see; fed the delay of the newest share instead, it says 97.33%. Over the
whole run no socket of either node or of its Tor left the machine except
through the bridge's own transport process (905 snapshots).

Block 26619 (`a43f84aa...8baa`) paid the obfs4 node 3.35397661 BTF and the
Snowflake node 0.62111801 BTF, checked to the satoshi against four copies of
the line on both machines. After maturity each spent its own output, confirmed in blocks 27038 and
27051 (`c12594df...101e`, `7257037d...0ebb`).

A fresh obfs4 node fetching the live line, stopped at 700 shares and
restarted, resumed with only 4 shares sent twice and then kept the same tip
as an ordinary node. A fresh Snowflake node from an empty data directory,
its Tor killed at 900 shares, resumed, refused to hand its miner work until
the line was complete, and found its first share 58 seconds after.

Both bridge nodes then guarded the pool. In the draw for epoch 37, which
every node computed the same way from the chain and the tickets, the obfs4
node took place 1 and the Snowflake node place 5; in the draw for epoch 38,
settled ahead of time, the Snowflake node took place 1. A fresh node with no pool files, isolated so that its only peer was
one bridge node, fetched the whole line (1518 shares) from that node alone:
in 182 seconds from the Snowflake node and in 124 seconds from the obfs4 node.

## 4. Scale

A harness on an isolated test network (regtest, so no public chain is
touched):

- 200 registered pools at once, 2000 simulated miners submitting shares
  through stratum, spread unevenly the way real hashrate is.
- Per node: CPU time per share checked, resident memory, disk used by share
  chains and the registry, bytes sent and received per hour.
- The guard budget at its limits: more pools than places, lines near the
  per-pool cap, a ticket set at 4096.

Results are published against the bounds of SPEC section 11, so a reader can
see the margin.

Done so far: the registry index reads a full copy of Bitflash mainnet in 27
seconds and testnet in 14 seconds, and stays bounded when every block names a
fake pool (4000 blocks, at most 3743 anchors kept).

## 5. Small miners

A node on a low-end machine (a 4 GB laptop and an ARM board), measured from
an empty data directory to its first accepted share in a registered pool:
time to fetch the pool's line, peak memory, traffic, and CPU left for mining.
Measured twice, on a direct Tor connection and through a Snowflake bridge
(SPEC section 17).

## 6. Auditability

- **Done:** the library passes 1469 checks against vectors generated from
  the reference node, in CI with g++, clang++ and sanitizers
  ([vectors](vectors/), [workflow](.github/workflows/lib.yml)): 967 for the
  record and the pool id, 90 for local pool codes, keys and the `"p2l"` tag,
  412 for share data, anchor pushes and coinbase scripts. Its own SHA-256,
  HMAC-SHA256, BLAKE2b and Argon2id also pass the test vectors published
  with their standards.
- **Done in the reference node:** self-tests run on every build, fuzz
  targets for the parsers and handlers, and reproducible release builds.
- **Planned:** vectors for share rules and the hello; every
  attack and survival run above published as a script; an independent review
  of the final implementation before anything reaches a mainnet. Review is
  open now ([issue #3](https://github.com/bitflash-network/everpool/issues/3)).

## 7. Other chains

- **Done:** the portable C++ library for the record, the pool id, local
  pool codes and keys, and the coinbase anchors takes the chain's own magic
  and parameters as inputs and needs no other library ([lib](lib/),
  [ADOPTING.md](ADOPTING.md)).
- **Planned:** the rest of the library (share rules, the hello, the
  messages), then Everpool running on a second proof-of-work chain's test
  network, built only from this repository, with no Bitflash code or
  infrastructure.

## 8. Ease of use

- **Built in the reference node, merged:** a private pool is one command
  to create and one to join (`poolcreate`, `pooljoin` with a `btfl1:` code); mining it is
  one startup option.
- **Built in the reference node, merged:** creating a registered pool in one
  command (`poolcreate everpool`, which shows the record before anything is
  sent) and mining it with one startup option (`-p2pool=<poolid>`).
- **Planned:** both kinds from the wallet's interface, which
  shows each pool's fingerprint, age, fee and work, never its name alone.
