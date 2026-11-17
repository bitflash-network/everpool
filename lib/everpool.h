// Everpool portable library: the pool registry record and the pool id
// (SPEC.md sections 1, 2 and 4).
//
// Pure C++17, no dependencies: no node, no chain, no socket. Everything a
// chain chooses for itself (its network magic, its record magic, its network
// floor, its pool zero) comes in through ChainParams; the record format and
// its ranges are the protocol's and are fixed here. examples/bitflash.h holds
// the values of the reference chain.
//
// Not covered yet: local pool codes, local pool ids and keys, coinbase
// anchors, share rules. A record carrying the local magic is recognised (and
// refused on the chain), nothing more.
//
// MIT license, see LICENSE.

#ifndef EVERPOOL_H
#define EVERPOOL_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace everpool
{

// ---- the record format (SPEC.md section 1), fixed by the protocol ----

constexpr uint8_t RECORD_FORMAT = 1;
constexpr uint8_t SHARE_RULES_V1 = 1;

constexpr size_t FIXED_BYTES = 41;  // everything before the name
constexpr size_t MAX_NAME_LEN = 32;
constexpr size_t MIN_RECORD_BYTES = FIXED_BYTES + 1;             // 42
constexpr size_t MAX_RECORD_BYTES = FIXED_BYTES + MAX_NAME_LEN;  // 73

constexpr unsigned MIN_SPACING = 20, MAX_SPACING = 120;
constexpr unsigned MIN_UNCLE_SECONDS = 60;  // spacing x uncle depth
constexpr unsigned MIN_WINDOW = 360, MAX_WINDOW = 2160;
constexpr unsigned MIN_RETARGET = 120, MAX_RETARGET = 720;
constexpr unsigned MIN_UNCLE_DEPTH = 1, MAX_UNCLE_DEPTH = 3;
constexpr unsigned MIN_UNCLE_PCT = 80, MAX_UNCLE_PCT = 100;
constexpr unsigned MAX_FEE_BPS = 300;

// The domain tag of the pool id (SPEC.md section 2). Chains are kept apart by
// the network magic that follows it, so the tag is the same everywhere.
constexpr char ID_TAG[] = "Bitflash/pool/1";

enum FeeType : uint8_t
{
    FEE_NONE = 0,
    FEE_P2PKH = 1,
    FEE_P2SH = 2,
};

using Magic = std::array<uint8_t, 4>;
using Hash160 = std::array<uint8_t, 20>;
using PoolId = std::array<uint8_t, 32>;

struct Record
{
    bool local = false;              // carried the local magic instead of the record magic
    uint8_t format = RECORD_FORMAT;  // offset 4
    uint8_t rules = SHARE_RULES_V1;  // offset 5
    uint16_t spacing = 0;            // offset 6, seconds per share
    uint16_t window = 0;             // offset 8, PPLNS window, shares
    uint16_t retarget = 0;           // offset 10, retarget window, shares
    uint32_t floor = 0;              // offset 12, compact share floor
    uint8_t uncle_depth = 0;         // offset 16
    uint8_t uncle_pct = 0;           // offset 17, percent of its work an uncle is paid
    uint16_t fee_bps = 0;            // offset 18, creator fee, basis points
    uint8_t fee_type = FEE_NONE;     // offset 20, FeeType
    Hash160 fee_hash{};              // offset 21, HASH160 of the fee address
    std::string name;                // offset 41, 1 to 32 bytes, no length byte
};

// What a chain sets for itself (ADOPTING.md).
struct ChainParams
{
    Magic network_magic{};    // message start; goes into the pool id
    Magic record_magic{};     // first 4 bytes of an on-chain record ("BTFP" in Bitflash)
    bool has_local_magic = false;
    Magic local_magic{};      // first 4 bytes of a local pool record ("BTFL" in Bitflash)
    uint32_t network_floor = 0;  // compact form of the easiest share target allowed
    Record pool_zero;         // the chain's existing pool, entry zero (SPEC.md section 4)
};

// Why a record was refused. The order is the order the rules are checked:
// a record that breaks several is refused with the first.
enum class Status
{
    ok,
    size,                // not 42 to 73 bytes
    magic,               // neither the record magic nor the local magic
    format,              // unknown record format
    rules,               // unknown share rules version
    spacing,             // outside 20 to 120 s, pool zero's own record excepted
    window,              // outside 360 to 2160
    retarget,            // outside 120 to 720, or above the window
    floor_noncanonical,  // not the one form SetCompact/GetCompact gives back, or not positive
    floor_easy,          // easier than the network floor
    uncle_depth,         // outside 1 to 3
    uncle_seconds,       // spacing x uncle depth under 60, pool zero's own record excepted
    uncle_pct,           // outside 80 to 100
    fee_high,            // above 300 basis points
    fee_type,            // not 0, 1 or 2
    fee_dest_no_fee,     // fee 0 with a type or a nonzero hash
    fee_no_dest,         // fee above 0 with type 0
    name,                // breaks the name rule
    noncanonical,        // does not write back to the same bytes (cannot happen; checked anyway)
    not_op_return,       // script: does not start with OP_RETURN
    push,                // script: not one direct push of 42 to 73 bytes and nothing after it
    local_on_chain,      // script: a local pool record, never read from the chain
};

// A short stable code ("floor_easy") and the reference implementation's text.
const char* status_code(Status s);
const char* status_text(Status s);

// The record's bytes. Does not check: check() says whether parse() would
// read them back.
std::vector<uint8_t> encode(const Record& r, const ChainParams& p);

// Whether the fields form a record parse() would accept.
Status check(const Record& r, const ChainParams& p);

// Read a record from its bytes (an OP_RETURN's data, or a local pool's
// record). Status::ok only if the bytes are a record in exactly its canonical
// form; out.local says which magic it carried. On failure out is reset.
Status parse(const uint8_t* data, size_t len, const ChainParams& p, Record& out);
Status parse(const std::vector<uint8_t>& data, const ChainParams& p, Record& out);

// Read a record from an output's scriptPubKey: OP_RETURN (0x6a), one direct
// push of the record (opcode equal to its length), nothing after it. A local
// record is refused. The burn (1 BTF in Bitflash) is the caller's to check.
Status parse_script(const uint8_t* script, size_t len, const ChainParams& p, Record& out);
Status parse_script(const std::vector<uint8_t>& script, const ChainParams& p, Record& out);

// The fee destination as a scriptPubKey: P2PKH (25 bytes) or P2SH (23 bytes);
// empty for FEE_NONE.
std::vector<uint8_t> fee_script(const Record& r);

// SHA256d(ID_TAG || network magic || record), in internal byte order (as it
// goes into the coinbase anchor). Hashes the bytes as given.
PoolId pool_id(const uint8_t* record, size_t len, const Magic& network_magic);
PoolId pool_id(const std::vector<uint8_t>& record, const Magic& network_magic);
// Shown like a block hash: the bytes reversed, lowercase hex.
std::string id_hex(const PoolId& id);

// The name rule: 1 to 32 bytes of A-Z, a-z, 0-9, '-' and '_', as byte ranges.
bool name_ok(const std::string& name);

// Whether a compact target is positive and in the one form GetCompact gives
// back after SetCompact (Bitcoin's CBigNum MPI encoding).
bool compact_canonical(uint32_t compact);

// For two canonical positive compacts: whether target(c) <= target(limit).
bool compact_no_easier(uint32_t c, uint32_t limit);

// Whether the chain's parameters are usable: a canonical network floor, a
// local magic (if any) unlike the record magic, and a pool zero that is not
// local and passes check(). why gets a reason on failure.
bool check_params(const ChainParams& p, std::string* why = nullptr);

// SHA-256 and double SHA-256 (FIPS 180-4).
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void sha256d(const uint8_t* data, size_t len, uint8_t out[32]);

} // namespace everpool

#endif
