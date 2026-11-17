// Everpool portable library: the pool registry record and the pool id
// (SPEC.md sections 1, 2 and 4), the private local pool's code, keys and
// anchor (section 18), and the coinbase anchors (sections 6 and 7).
//
// Pure C++17, no dependencies: no node, no chain, no socket. Everything a
// chain chooses for itself (its network magic, its record magic, its network
// floor, its pool zero) comes in through ChainParams; the record format and
// its ranges are the protocol's and are fixed here. examples/bitflash.h holds
// the values of the reference chain.
//
// Not covered yet: share rules v1 (targets, the window, payouts), the share
// itself (header, coinbase, merkle branch), the local pool's hello, the
// network messages and the guardians.
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
using Hash256 = std::array<uint8_t, 32>;
using PoolId = Hash256;

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
    // A local pool's code and keys (SPEC.md section 18). A code is refused
    // with the first of these it breaks, then with the record's own reason.
    code_prefix,         // code: does not start with "btfl1:"
    code_length,         // code: an odd number of hex digits, or not 46 to 77 bytes
    code_hex,            // code: something other than 0-9 a-f after the prefix
    code_checksum,       // code: the last 4 bytes are not the record's SHA256d
    not_local,           // a valid record, but not under the local magic
    password_long,       // more than 1024 bytes
    kdf_memory,          // the 64 MiB Argon2id needs could not be had
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

// ---- the private local pool (SPEC.md section 18) ----
//
// A local pool is a record under the local magic that never goes on the
// chain. Its members hand each other a pool code and, if they chose one, a
// password; from those two every member derives the same pool id and keys.

// The pool code: this prefix, the record in lowercase hex, then the first 4
// bytes of the record's SHA256d in hex. It never holds the password.
constexpr char LOCAL_CODE_PREFIX[] = "btfl1:";

// The domain tags of the derivation. Like ID_TAG they are the same on every
// chain: the network magic that follows them keeps chains apart.
constexpr char LOCAL_SALT_TAG[] = "Bitflash/localpool/1/salt";
constexpr char LOCAL_ID_TAG[] = "Bitflash/localpool/1/id";
constexpr char LOCAL_AUTH_TAG[] = "Bitflash/localpool/1/auth";
constexpr char LOCAL_ANCHOR_TAG[] = "Bitflash/localpool/1/anchor";

// Argon2id version 1.3 as libsodium's crypto_pwhash runs it: 3 passes over
// 64 MiB, one lane, a 16-byte salt, a 32-byte key.
constexpr uint32_t KDF_PASSES = 3;
constexpr uint32_t KDF_MEMORY_KIB = 64 * 1024;
constexpr size_t KDF_SALT_BYTES = 16;
constexpr size_t MAX_PASSWORD_LEN = 1024;

// The code of a record's bytes. Does not check them: parse_code() says
// whether the code would be read back.
std::string local_code(const uint8_t* record, size_t len);
std::string local_code(const std::vector<uint8_t>& record);

// Read a pool code. Status::ok only if the text is a code in exactly that
// form (lowercase, nothing before or after), its checksum holds, and the
// record inside is a valid record under the local magic. On failure out is
// reset.
Status parse_code(const std::string& code, const ChainParams& p, Record& out);

struct LocalKeys
{
    Hash256 K{};   // the stretched password; what a node stores instead of the password
    Hash256 id{};  // the local pool id, internal byte order; ShareData.pool_id
    Hash256 A{};   // authenticates members to each other (the hello)
    Hash256 C{};   // keys the coinbase anchor
};

// The Argon2id salt: the first 16 bytes of
// SHA256d(LOCAL_SALT_TAG || network magic || record).
std::array<uint8_t, KDF_SALT_BYTES> local_salt(const uint8_t* record, size_t len, const Magic& network_magic);

// K  = Argon2id(password, local_salt), 32 bytes;
// id = SHA256d(LOCAL_ID_TAG || network magic || record || K);
// A  = HMAC-SHA256(K, LOCAL_AUTH_TAG || id);
// C  = HMAC-SHA256(K, LOCAL_ANCHOR_TAG || id).
// The password is bytes: nothing is trimmed or normalized, and no password
// is the empty string. Refused, in this order: a record that is not a valid
// local record (its own reason, or not_local), a password over 1024 bytes,
// no memory for Argon2id. Takes 64 MiB and a fraction of a second. On
// failure out is zeroed.
Status derive_local(const std::vector<uint8_t>& record, const ChainParams& p, const std::string& password,
                    LocalKeys& out);

// The same from a stored K: no Argon2id run.
Status derive_local_from_k(const std::vector<uint8_t>& record, const ChainParams& p, const Hash256& K,
                           LocalKeys& out);

// ---- share data and the coinbase anchor (SPEC.md sections 6, 7 and 18) ----

enum class PoolKind : uint8_t
{
    zero,        // the chain's default pool: "p2p" anchor, share data without a pool id
    registered,  // a pool with a record on the chain: "p2x" anchor, the pool id in the share data
    local,       // a private local pool: "p2l" anchor, the pool id and a salt in the share data
};

// What a coinbase commits to: the share chain side of a share. The kind says
// which fields are part of it: pool_id for registered and local, salt for
// local only. The salt is 32 random bytes, fresh for every template, that
// members receive with the share and that never go on the chain; without it
// a block would let anyone holding the code test passwords offline.
struct ShareData
{
    PoolKind kind = PoolKind::zero;
    PoolId pool_id{};                   // registered, local; internal byte order
    Hash256 salt{};                     // local
    Hash256 prev_share{};               // zero for the first share of a chain
    std::vector<Hash256> uncles;
    uint32_t height = 0;
    uint32_t bits = 0;                  // compact share target
    std::vector<uint8_t> payout_script;
};

// The bytes that are hashed: [pool_id] [salt] prev_share, the uncles behind
// their count, height and bits as 4 bytes little-endian, the payout script
// behind its length. Counts and lengths are Bitcoin's compact size. No bound
// is checked here (a share may name at most 2 uncles and 64 script bytes).
std::vector<uint8_t> serialize(const ShareData& d);
// SHA256d of those bytes, in internal byte order.
Hash256 share_data_hash(const ShareData& d);

constexpr size_t ANCHOR_BYTES = 35;             // "p2p" or "p2l" and 32 bytes
constexpr size_t REGISTERED_ANCHOR_BYTES = 67;  // "p2x", the pool id, 32 bytes

// The data of the push each kind of pool puts in its coinbase scriptSig
// (the push opcode is the caller's: 0x23 for 35 bytes, 0x43 for 67).
std::vector<uint8_t> anchor_zero(const Hash256& share_data_hash);                          // "p2p" || hash
std::vector<uint8_t> anchor_registered(const PoolId& id, const Hash256& share_data_hash);  // "p2x" || id || hash
std::vector<uint8_t> anchor_local(const Hash256& C, const Hash256& share_data_hash);       // "p2l" || tag
// HMAC-SHA256(C, hash): what follows "p2l".
Hash256 local_anchor_tag(const Hash256& C, const Hash256& share_data_hash);
// Whether pushed bytes are "p2l" and this key's tag for this hash. The tag
// is compared in constant time.
bool local_anchor_matches(const uint8_t* pushed, size_t len, const Hash256& C, const Hash256& share_data_hash);

// The pool a share is checked against.
struct AnchorPool
{
    PoolKind kind = PoolKind::zero;
    PoolId id{};   // registered, local
    Hash256 C{};   // local: the anchor key
};

// The push of this pool for this share data, by the pool's kind.
std::vector<uint8_t> anchor_push(const AnchorPool& pool, const ShareData& d);

// Whether a coinbase scriptSig carries this pool's commitment to this share
// data, and nothing that would let the same work count on another share
// chain. A push is known by its data alone, whatever opcode carried it.
//  - pool zero (its rule is frozen): the data has no pool id, the script
//    parses, and it has exactly one 35-byte "p2p" push, holding the hash;
//    other pools' pushes do not matter;
//  - a registered pool: the data names this pool and has no salt, the pool
//    id is not zero, the script parses and has exactly one 67-byte "p2x"
//    push, holding this id and the hash, and no "p2p" and no "p2l" push;
//  - a local pool: the data names this pool and has a salt (its value is not
//    checked), the script parses and has exactly one 35-byte "p2l" push,
//    holding the tag of the hash under C, and no "p2p" and no "p2x" push.
// That the transaction is a coinbase, and a scriptSig's size limit, are the
// caller's to check.
bool check_anchor(const AnchorPool& pool, const uint8_t* script_sig, size_t len, const ShareData& d);
bool check_anchor(const AnchorPool& pool, const std::vector<uint8_t>& script_sig, const ShareData& d);

// Which pool a block's coinbase counts for (SPEC.md section 7), from the
// main chain alone. These are claims: anybody can write a push.
enum class AnchorKind
{
    none,        // does not parse, no anchor, more than one, or kinds mixed; a "p2l" alone is none
    zero,        // exactly one "p2p" push and no "p2x" push
    registered,  // exactly one "p2x" push, no "p2p" and no "p2l" push
};

struct Anchor
{
    AnchorKind kind = AnchorKind::none;
    PoolId pool_id{};  // registered: the pool the push names
    Hash256 hash{};    // zero, registered: the share data hash in the push
};

// The raw reading of a coinbase scriptSig. A count per pool must also treat
// a "p2x" push naming pool zero's own id as none: pool zero's shares never
// carry its id, so such a push is a label for no share chain.
Anchor classify_anchor(const uint8_t* script_sig, size_t len);
Anchor classify_anchor(const std::vector<uint8_t>& script_sig);

// One step through a script, as the reference's GetOp reads it: an opcode
// (two bytes when the first is 0xf0 or more) and, for opcodes up to
// OP_PUSHDATA4 (0x4e), the bytes it pushes. False at the end of the script
// or when the script is cut short; pos moves past what was read.
bool next_op(const uint8_t* script, size_t len, size_t& pos, unsigned& opcode, const uint8_t*& data,
             size_t& data_len);

// ---- hashes ----

// SHA-256 and double SHA-256 (FIPS 180-4).
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void sha256d(const uint8_t* data, size_t len, uint8_t out[32]);

// HMAC-SHA256 (RFC 2104).
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]);

// BLAKE2b (RFC 7693): 1 to 64 bytes out, an optional key of up to 64 bytes.
// False on a size out of range.
bool blake2b(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len, const uint8_t* key = nullptr,
             size_t key_len = 0);

// Argon2 version 1.3 (RFC 9106). Lanes are filled one after the other (the
// result does not depend on threads). False on parameters out of range
// (passes and lanes at least 1, memory at least 8 KiB per lane, a salt of at
// least 8 bytes, 4 bytes or more out) or when the memory cannot be had.
enum class Argon2Type : uint8_t
{
    d = 0,
    i = 1,
    id = 2,
};
bool argon2(Argon2Type type, uint32_t passes, uint32_t memory_kib, uint32_t lanes, const uint8_t* password,
            size_t password_len, const uint8_t* salt, size_t salt_len, const uint8_t* secret, size_t secret_len,
            const uint8_t* ad, size_t ad_len, uint8_t* out, size_t out_len);

// Overwrite a secret so the compiler cannot drop the write.
void wipe(void* p, size_t len);

} // namespace everpool

#endif
