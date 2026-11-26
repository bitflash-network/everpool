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
| 1 | Attacks cost the attacker and buy little | attack scripts against a testnet pool, with measured cost and effect | partial: every attack run as self-tests on an isolated chain; public testnet run to do |
| 2 | A pool outlives its creator and its guardians | testnet runs: creator gone for good, every guardian down at once, revival from a carrier and from the record alone | done on testnet |
| 3 | Payouts are exact and need no one | every coinbase checked to the satoshi against the share chain, across reorgs and restarts, then spent | partial |
| 4 | It scales to hundreds of pools | a load harness: 200 pools, 2000 simulated miners, CPU, memory, disk and bandwidth per node | partial: 200 pools and 2002 miners in one process; disk and a node's own memory to do |
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

Done so far (26 November 2026): every attack above, run as self-tests of
the reference node on an isolated test chain (`bitflash-node
-selftest=attack-sybil`, `attack-ticket-flood`, `attack-withhold`,
`attack-stale`, `attack-shares`, `attack-flood`; Bitflash main `d979483`),
plus one live node flooded over loopback. A run against pools on the public
testnet is still to do.

- **Sybil on tickets.** With 4096 honest tickets, an attacker with as much
  ticket work as the honest nodes, twice and three times as much held
  49.5%, 66.6% and 75.0% of the set (its share of the work: 50, 66.7 and
  75%). Over 20,000 pools drawn, it held all 16 places of 0, 28 and 202
  pools; the estimate (A / (H + A))^16 of section 12 says 0.3, 29.5 and
  198.5, so it holds as the upper side. Aiming at one given pool is
  heavy-tailed: taking all 16 of its places cost a median of 20.5 times the
  honest ticket work (10th percentile 5.8, 90th 97.4); section 12 now gives
  these figures.
- **Ticket flooding.** 12,288 valid attacker tickets (0.04 ms of CPU each to
  check here) left the set at exactly 4096; 89 of 300 honest tickets stayed,
  where about 98 were expected by lowest work hash; no valid ticket was
  scored, and `poolwho` still named the pool's announcer. At the node's
  check budget such a flood takes at least 50 minutes to be read.
- **Withholding.** With all 16 guardians of a pool silent, a new miner
  started its own line after about 12 minutes; when the live miner's shares
  reached it, the node ended on the miner's line, the heavier, and its own
  lone shares were orphaned, the window untouched.
- **Stale line.** The test found that the anchor check of section 10 was not
  in the node. It is now (Bitflash PR #106): a line that reaches back past
  the pool's newest anchor on the main chain but does not hold its share is
  logged as stale, up to four other announcers are asked for theirs, and the
  result is logged ten minutes later. The tip stays the line with the most
  work.
- **Share manipulation.** Every forged or invalid share was refused: a share
  naming another pool, a payout list that is not the window's, a wrong
  height, forged work, a forged deep history (sender scored 60). Shares
  replayed from another network were dropped unread and unscored, and pool
  zero was unaffected.
- **Flooding.** 300,000 `p2xshare` messages for pools not carried cost 2.9 µs
  of CPU each, with nothing answered and nobody scored; 250 KB ones 518 µs
  each. 300,000 history asks for pools not carried got at most 8 short
  answers an interval. 2000 history asks from one unproven connection got
  one history's worth (0.33 MB). Shares over the 256 KB cap were refused and
  their senders scored. A live node flooded over loopback stayed between 58
  and 75 MB of resident memory, its worst case 793 µs per 250 KB message.

A separate review of the whole implementation before mainnet (Bitflash
PR #106) found no blocker and fixed four should-fix issues: a pool's line
could grow to about 2 GB on every node mining or carrying it (now let go
past 1.5 times its cap, 192 MB at the default); an empty "end of history"
part completed a fetch with nothing; guardians rewrote whole lines every
two minutes (now all registered lines together at 64 KB/s at most); and
the anchor check above. Its ASan and UBSan fuzzing of the four pool fuzz
targets found nothing.

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

- **No guardian up, one carrier left.** The draw had named eight guardians
  of `phasedA`. Five were already off (one was the creator that left, four
  were nodes of an earlier run); the three still running were stopped at
  once at height 26613. The copy left online was a carrier on a second
  machine. A
  fresh node with no pool files and one fixed peer that did not hold the
  line found nobody to ask, asked its peers who carries the pool
  (`poolwho`), was told of carriers, reached that one and had the complete line
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
not see; fed the delay of the newest share instead, it says 97.33%. In
905 socket snapshots taken through the run, across the four bridge nodes
used, no socket of a node or of its Tor left the machine; only the bridge's
own transport process did. (The 97.33% variant was added after the run.)

Block 26619 (`a43f84aa...8baa`) paid the obfs4 node 3.35397661 BTF and the
Snowflake node 0.62111801 BTF, checked to the satoshi against four copies of
the line on both machines. After maturity each spent its own output, confirmed in blocks 27038 and
27051 (`c12594df...101e`, `7257037d...0ebb`).

A fresh obfs4 node fetching the live line, stopped at 700 shares and
restarted, resumed with only 4 shares sent twice and then kept the same tip
as an ordinary node. A fresh Snowflake node from an empty data directory,
its Tor killed at 900 shares, resumed, refused to hand its miner work until
the line was complete, and found its first share 58 seconds after.

Both bridge nodes were drawn as guardians: in the list for epoch 37, the
same on the four nodes asked, the obfs4 node had place 1 and the Snowflake
node place 5. Both held and announced the line because they had mined the
pool, so neither shows a bridge node pulling a line only because it was
drawn. A fresh node with no pool files, isolated so that its only peer was
one bridge node, fetched the whole line (1518 shares) from that node alone:
in 182 seconds from the Snowflake node and in 124 seconds from the obfs4
node.

The handoff of a dormant pool on Bitflash testnet (23 to 26 November 2026),
SPEC section 15, step 4, with 26 guardian nodes making real tickets, one
obfs4 node and one Snowflake node among them, and a carrier on a second
machine:

- **Handoff while nobody mines.** Pool `phasedA`'s only miner was stopped at
  height 29706, in epoch 41. At the switch to epoch 42 (height 30212), six
  nodes the new draw named that had not been in the old set were started with
  no copy of the line and pulled it from the old guardians while the pool was
  dormant. The obfs4 node (place 1) took it through its obfs4 bridge, and the
  Snowflake node (place 3) through Snowflake. All eleven copies, old and new,
  were byte for byte the same line (1510 shares, tip height 3131). The first
  pass is not counted: the six had pulled a copy earlier, while making
  tickets, and still remembered their guard state. The pull was done again
  with no line file and no remembered guard state on any of them, each node
  complete in 100 to 182 seconds; those are the times given here. A node on the second
  machine set to carry the pool and never guard it (`-poolcarry`,
  `-poolguard=0`) also took the line. Once epoch 41's linger ended (height
  30420) the old guardians that were not drawn again dropped it.
- **Revived from the new set.** A fresh node synced from genesis, with no
  pool files, fetched the line from a guardian of the new set and found block
  30449 (`1922046e...172b`), checked to the satoshi, creator fee included,
  against its own copy and against a guardian's. Its payout was spent,
  confirmed in block 30569 (`3b97067b...18d5`). A fresh node isolated so that
  its only peer was the obfs4 guardian had the whole line in 227 seconds,
  and one whose only peer was the Snowflake guardian had it in 163 seconds:
  bridge nodes that hold the line only because they were drawn serve it
  alone.
- **Every guardian of both sets gone during a handoff.** At the next switch
  (epoch 42 to 43, height 30932), all 21 guardians still running, the old set
  and the new one, were stopped at once at height 30937. The only copy left
  online was that carrier on the second machine. A fresh node with no pool files and one fixed peer that did not
  hold the line asked who carries the pool (`poolwho`), reached the carrier
  and had the complete line (1508 shares, tip height 3180). Its block 30939
  (`743369de...4fbf`) paid the old window to the satoshi, creator fee
  included; its payout was spent, confirmed in block 31059
  (`53e8990a...f484`).

With this, every step of SPEC section 15's Phase D has been run on testnet
with real coins.

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

Done so far (26 November 2026, `bitflash-node -selftest=attack-scale`, main
`d979483`): 200 registered pools and 2002 miners spread by a Zipf law, 61 MB
of lines, against one node's draw and guard budget. Miners and shares are
simulated inside one process, not separate nodes or stratum sessions, so
this measures the node's own work, not a network. Per share, the node spent
195 to 498 µs of CPU for windows of up to 720 miners and 1.1 to 1.4 ms at
1000 to 2000 miners; relaying to 8 peers took 1 to 22 MB an hour, 62 MB at
2000 miners. The guard budget held: at most 8 pools kept, the others turned
away for lack of room; with ten 22 MB pools and one of 79 MB, four were kept
(109 MB of the 134 MB budget) and the 79 MB one by nobody, past the 64 MB a
guardian gives one pool. Disk use and a node's own resident memory are not
measured yet (the test's figures include its own copies of every line).

Also: the registry index reads a full copy of Bitflash mainnet in 27
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
