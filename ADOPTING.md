# Adopting Everpool in another chain

Everpool changes no consensus rule. A chain adopts it in an ordinary node
release, and nodes that do not upgrade keep validating every block and keep
mining the default pool.

The specification ([SPEC.md](SPEC.md)) is written for Bitflash, the reference
implementation. This page lists what a chain needs, which values it sets for
itself, and which parts are specific to Bitflash.

## What the chain needs

| need | why | in Bitflash |
|---|---|---|
| standard `OP_RETURN` outputs of up to about 80 bytes, with value | a pool is created by burning coins into an `OP_RETURN` carrying its record (42 to 73 bytes) | standard since 1.2.28 |
| room for a short push in the coinbase scriptSig | each share commits to one pool, and the block anchors the pool that found it | coinbase scriptSig up to 100 bytes |
| a P2Pool-style share chain in or beside the node | Everpool generalizes one share chain into many, with the same PPLNS logic | P2Pool built into the node |
| a stable, dialable node identity with a Schnorr key | guardians publish signed tickets and must be reachable by whoever needs a pool's line | the `.btf` address: a BIP340 key bound to the node's Tor onion |
| a CPU-hard proof of work for tickets | a ticket must cost real work to make and be cheap to check | RandomX, the chain's own PoW, at idle priority |

Tor is not required by the protocol. Bitflash uses onion services for every
node, which is why section 17 covers bridges and slow links; a clearnet chain
can use its own peer addresses as long as identities are signed and dialable.

## Values a chain sets for itself

- **Network magic** (in the pool id and the tickets): the chain's own message
  start, so pools and shares cannot be replayed across chains.
- **Registration burn**: 1 BTF in Bitflash. Pick an amount that makes spam
  registrations cost something real without keeping honest creators out.
- **Record magic**: `"BTFP"` in Bitflash (`"BTFL"` for private local pools).
  A chain may keep these or pick its own.
- **Pool zero**: the chain's existing P2Pool rules, written as entry zero.
- **Confirmations before a pool is active** (30 in Bitflash, with 2-minute
  blocks) and the **epoch length** for the guardian draw (720 blocks, about a
  day). Scale both to the chain's block time.
- **Network floor** for share targets, and the **ticket target**, measured so
  an ordinary node spends a few minutes of one core per day.
- **Budgets** (section 11): memory, bandwidth and pools guarded per node. The
  defaults are sized for home machines.

## Parts specific to Bitflash

- References to `src/...`, `docs/...`, RPC names and release numbers point to
  the Bitflash repository.
- Section 17 (Tor bridges: Snowflake, obfs4, webtunnel, meek) matters only for
  chains whose nodes run over Tor, but its pacing and resumable transfers help
  on any slow link.
- The private local pool (section 18) identifies members by their onion;
  another chain substitutes its own node identity. Its key derivation is
  Argon2id with the parameters of libsodium's `crypto_pwhash` (version 1.3,
  3 passes, 64 MiB, one lane); the library carries its own Argon2id, so
  libsodium is not needed.

## Getting help

Open an issue in this repository describing your chain (PoW, block time,
existing pool setup).

## Library and vectors

Start from the portable C++ library in [`lib/`](lib/) and the test vectors in
[`vectors/`](vectors/) (see the README's "Library and vectors"). Copy [`lib/examples/bitflash.h`](lib/examples/bitflash.h), put in
your chain's network magic, record magics, network floor and pool zero, and
check them with `everpool::check_params`. The record format, its ranges and
the pool id tag (`"Bitflash/pool/1"`) are part of the protocol and stay as
they are; the network magic is what keeps pools apart across chains. The
burn is checked by the caller, which knows the output's value.

The library also covers the private local pool's code and keys and the
coinbase anchors, with [`vectors/local.json`](vectors/local.json) and
[`vectors/anchor.json`](vectors/anchor.json):

- `parse_code` and `local_code` read and write a `btfl1:` pool code;
  `derive_local` gives `K`, the local pool id, `A` and `C` from the record,
  your network magic and the password. The code prefix and the derivation
  tags (`"Bitflash/localpool/1/..."`) are part of the protocol, like the pool
  id tag; the network magic keeps chains apart here too.
- `serialize` and `share_data_hash` give what a coinbase commits to;
  `anchor_push` gives the push for pool zero (`"p2p"`), a registered pool
  (`"p2x"`) or a local pool (`"p2l"`); `check_anchor` says whether a coinbase
  scriptSig carries a pool's anchor and nothing that would let the same work
  count on another share chain; `classify_anchor` says which pool a block
  counts for. These read a script exactly as the reference node does, so a
  chain whose script reader differs (two-byte opcodes from `0xf0`, pushes up
  to `OP_PUSHDATA4`) should check `next_op` against its own.

Share rules as parameters, the hello and the network messages follow once
they are final and proven in the reference implementation. Writing the
library in another language? Run it against the vectors: they come from the
reference implementation itself.
