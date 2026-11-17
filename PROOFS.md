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
| 2 | A pool outlives its creator and its guardians | testnet runs: creator gone for good, every guardian down at once, revival from a carrier and from the record alone | partial |
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

Still to do for private pools: members on two separate machines, one of them
behind a Snowflake bridge.

## 3. Payouts

For every block a test pool finds: the coinbase is rebuilt from the share
chain and compared to the satoshi, including the creator fee output. Coins are
then left to mature and are spent, so the payout is proved by moving it, not
by reading it. The same check runs after a reorg of the main chain, after a
reorg of the share chain, and after nodes restart mid-window.

Done so far: pool zero, the P2Pool Everpool extends, was proved this way on
Bitflash testnet (paid, matured, spent); the first local pool payout above.

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

- **Done:** the record and pool id library passes 967 vectors generated from
  the reference node, in CI with g++, clang++ and sanitizers
  ([vectors](vectors/), [workflow](.github/workflows/lib.yml)).
- **Done in the reference node:** self-tests run on every build, fuzz
  targets for the parsers and handlers, and reproducible release builds.
- **Planned:** vectors for local pool codes, anchors and share rules; every
  attack and survival run above published as a script; an independent review
  of the final implementation before anything reaches a mainnet. Review is
  open now ([issue #3](https://github.com/bitflash-network/everpool/issues/3)).

## 7. Other chains

- **Done:** the portable C++ library for the record and the pool id takes
  the chain's own magic and parameters as inputs ([lib](lib/),
  [ADOPTING.md](ADOPTING.md)).
- **Planned:** the rest of the library (codes, anchors, share rules), then
  Everpool running on a second proof-of-work chain's test network, built only
  from this repository, with no Bitflash code or infrastructure.

## 8. Ease of use

- **Built in the reference node, in review:** a private pool is one command
  to create and one to join (`poolcreate`, `pooljoin` with a `btfl1:` code); mining it is
  one startup option.
- **Planned:** creating a registered pool in one command
  (`poolcreate everpool`), and both kinds from the wallet's interface, which
  shows each pool's fingerprint, age, fee and work, never its name alone.
