# Everpool

**A P2Pool that no one can delete, edit or shut down: not its creator, not
the developers who ship the node.**

Everpool is an open protocol for decentralized mining pools. Each pool is
defined by a record on the blockchain itself. Once mined, that record is
permanent: the pool's rules can never change. The pool's share chain moves
from node to node, so the pool keeps running when the person who created it
goes offline for good.

The reference implementation lives in the
[Bitflash](https://github.com/bitflash-network/bitflash) node, a RandomX
CPU-mined chain whose nodes all run as Tor onion services. The protocol itself
is not tied to Bitflash. This repository holds the specification and a
portable library with test vectors, so other chains can adopt it.

## Why

P2Pool removed the pool operator: no custody, no central template, no
company. One lever is still there. The share-chain rules (window, share
spacing, payout split) are hard-coded in the node, so whoever publishes the
release can change them for everyone. Alternative pools can only be found on
some website.

Everpool removes that lever too:

- **Anyone can create a pool.** It takes one transaction that burns a small
  amount of coins into an `OP_RETURN` output carrying the pool's rules: share
  spacing, window, difficulty floor, an optional creator fee with a hard cap.
- **No one can delete or edit a pool.** The pool's id is the hash of its
  rules, so changing one byte gives a different pool with a different id. The
  original stays on the chain as long as the chain exists.
- **The creator has no special role.** After the burn there is no admin key,
  no server and no vote. The pool is the record plus the share chain its
  miners keep.
- **Pools move between nodes.** Every day a draw picks a few nodes per pool
  as *guardians*. They keep and serve the pool's share chain even if they do
  not mine it, and hand it to the next day's set. A pool nobody mines sleeps
  with its guardians, and any miner can wake it.
- **Guardians are availability, not trust.** Every share carries its own
  proof of work, and the line with the most work wins. A guardian cannot forge
  a share or change a payout. The worst it can do is stay silent, and the
  design bounds that.
- **No consensus change.** Everything is node software and pool protocol. A
  chain adopts it in an ordinary release, with no fork.

## Two kinds of pool, plus the default

| | Everpool | Private local pool |
|---|---|---|
| where it is defined | a record on the chain, a small burn | a pool code the members share; nothing on the chain |
| who can find it | everyone | only whoever is given the code (and password) |
| who keeps its share chain | its miners, drawn guardians, volunteers | only its members' nodes |
| when all its nodes leave | it lives on, and the record restarts it | it is gone, by design |

The chain's existing default pool becomes **pool zero**: entry zero of the
registry, with today's rules and no fee. Nodes that never upgrade keep mining
it unchanged.

## How it works, in one page

1. **Record** (spec section 1): a few dozen bytes in `OP_RETURN`: version,
   network, share rules, fee, name. Strict canonical encoding; anything odd is
   rejected.
2. **Pool id** (section 2): the hash of the record plus the network magic. The
   same rules on another chain are a different pool, so shares cannot be
   replayed across chains.
3. **Index** (section 3): every node reads registrations from its own active
   chain. A pool becomes active after 30 confirmations, and reorgs undo and
   redo appearances.
4. **Shares** (sections 5 to 7): a share commits to exactly one pool. Blocks
   found through a pool carry a small anchor in the coinbase, so anyone can see
   which pool found them.
5. **Guardians** (section 10): each node publishes one signed ticket per day
   that costs a few minutes of CPU work. A rendezvous-hash draw over the
   tickets gives each pool its own random order: 8 guardians and 8 reserves.
   Capturing one chosen pool needs about 22 times the honest ticket work, and
   even then it only buys silence for a day.
6. **Bounds** (sections 11 and 12): every node has fixed memory, bandwidth and
   CPU budgets, and the threat model covers each attack with its defence.
7. **Hostile networks** (section 17): built to work over slow, censored links
   (Tor bridges such as Snowflake and obfs4) with paced, resumable transfers.

The full specification is in [SPEC.md](SPEC.md).

## Status

| phase | content | status |
|---|---|---|
| A | design, reviewed | done |
| B1 | share rules as parameters, private local pools, traffic isolation | built, paid on testnet, final review |
| B2 | the on-chain registry index, creating and mining registered pools | index and `poolcreate everpool` built, in review |
| C | guardians: tickets, the draw, handoff, revival | next |
| D | end-to-end proof on testnet with real coins, including a node behind a bridge | after C |

Nothing is on mainnet yet. Progress is tracked in the Bitflash repository's
pull requests. What each claim needs to be proved, and what is already
proved, is in [PROOFS.md](PROOFS.md).

## Library and vectors

[`lib/`](lib/) is a small C++17 library with no dependencies: it carries its
own SHA-256, HMAC-SHA256, BLAKE2b and Argon2id, written from FIPS 180-4, RFC
2104, RFC 7693 and RFC 9106 and checked against their published test
vectors. It covers the parts whose format is settled:

- the pool registry record (encode, parse, validate, read from an
  `OP_RETURN`) and the pool id (spec sections 1, 2 and 4);
- the private local pool (section 18): the `btfl1:` pool code, and the
  derivation from the code and the password of the key `K`, the local pool
  id and the keys `A` and `C`;
- the coinbase anchors (sections 6, 7 and 18): the share data each kind of
  pool commits to, the `"p2p"`, `"p2x"` and `"p2l"` pushes, whether a
  coinbase carries a pool's anchor and no other, and which pool a block
  counts for.

The chain's magics, network floor and pool zero are inputs;
[`lib/examples/bitflash.h`](lib/examples/bitflash.h) holds Bitflash's values.

[`vectors/`](vectors/) holds test vectors generated from the reference
implementation, not from this library. An implementation in any language can
check itself against them.

| file | content |
|---|---|
| [`record.json`](vectors/record.json) | valid records of every length from 42 to 73 bytes, every reason a record is refused (with the rule order), the script shape, the compact canonical form, pool ids on mainnet and testnet |
| [`local.json`](vectors/local.json) | pool codes, valid and refused for every reason (prefix, length, hex, checksum, each record rule, a registry record); `K`, id, `A` and `C` on both networks with no password, text, UTF-8, bytes with a NUL and the longest password; the keyed `"p2l"` tag |
| [`anchor.json`](vectors/anchor.json) | share data bytes and hashes for the three kinds of pool; the push of each; 90 coinbase scripts (no anchor, two anchors, kinds mixed, wrong sizes, pushes cut short, every push opcode) with what the count of section 7 makes of each and whether pool zero, a registered pool and a local pool take it; pools and share data that do not agree |

A local pool's share data carries a 32-byte salt after the pool id, as the
reference implementation does (so a block gives nothing to test a password
against); SPEC.md describes it once that change is merged there.

```
make test       # runs the vectors against lib/
make example    # prints pool zero's record and ids
```

Deriving a local pool's keys takes 64 MiB of memory and a fraction of a
second. Share rules, the hello between members and the network messages come
later, once they are final in the reference implementation.

## Using it in another chain

Everpool needs no consensus change. See [ADOPTING.md](ADOPTING.md) for what a
chain needs and which parameters it sets.

## Contributing

Review of the specification is the most useful contribution right now:
attacks we missed, simpler mechanisms, numbers that look wrong. Open an issue.
Developers of other chains interested in adopting Everpool are welcome too.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
