// Everpool portable library. See everpool.h. MIT license, see LICENSE.

#include "everpool.h"

#include <cstring>
#include <exception>

namespace everpool
{

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), written for this library.

namespace
{

const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline uint32_t Rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void Compress(uint32_t st[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)block[4 * i] << 24 | (uint32_t)block[4 * i + 1] << 16 | (uint32_t)block[4 * i + 2] << 8 |
               (uint32_t)block[4 * i + 3];
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++)
    {
        uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
}

} // namespace

void sha256(const uint8_t* data, size_t len, uint8_t out[32])
{
    uint32_t st[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    size_t done = 0;
    for (; len - done >= 64; done += 64)
        Compress(st, data + done);
    uint8_t tail[128] = { 0 };
    size_t rest = len - done;
    if (rest)
        memcpy(tail, data + done, rest);
    tail[rest] = 0x80;
    size_t tailLen = rest < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        tail[tailLen - 1 - i] = (uint8_t)(bits >> (8 * i));
    Compress(st, tail);
    if (tailLen == 128)
        Compress(st, tail + 64);
    for (int i = 0; i < 8; i++)
    {
        out[4 * i] = (uint8_t)(st[i] >> 24);
        out[4 * i + 1] = (uint8_t)(st[i] >> 16);
        out[4 * i + 2] = (uint8_t)(st[i] >> 8);
        out[4 * i + 3] = (uint8_t)st[i];
    }
}

void sha256d(const uint8_t* data, size_t len, uint8_t out[32])
{
    uint8_t h[32];
    sha256(data, len, h);
    sha256(h, sizeof(h), out);
}

// ---------------------------------------------------------------------------
// The record.

const char* status_code(Status s)
{
    switch (s)
    {
    case Status::ok: return "ok";
    case Status::size: return "size";
    case Status::magic: return "magic";
    case Status::format: return "format";
    case Status::rules: return "rules";
    case Status::spacing: return "spacing";
    case Status::window: return "window";
    case Status::retarget: return "retarget";
    case Status::floor_noncanonical: return "floor_noncanonical";
    case Status::floor_easy: return "floor_easy";
    case Status::uncle_depth: return "uncle_depth";
    case Status::uncle_seconds: return "uncle_seconds";
    case Status::uncle_pct: return "uncle_pct";
    case Status::fee_high: return "fee_high";
    case Status::fee_type: return "fee_type";
    case Status::fee_dest_no_fee: return "fee_dest_no_fee";
    case Status::fee_no_dest: return "fee_no_dest";
    case Status::name: return "name";
    case Status::noncanonical: return "noncanonical";
    case Status::not_op_return: return "not_op_return";
    case Status::push: return "push";
    case Status::local_on_chain: return "local_on_chain";
    case Status::code_prefix: return "code_prefix";
    case Status::code_length: return "code_length";
    case Status::code_hex: return "code_hex";
    case Status::code_checksum: return "code_checksum";
    case Status::not_local: return "not_local";
    case Status::password_long: return "password_long";
    case Status::kdf_memory: return "kdf_memory";
    }
    return "unknown";
}

const char* status_text(Status s)
{
    switch (s)
    {
    case Status::ok: return "ok";
    case Status::size: return "not 42 to 73 bytes";
    case Status::magic: return "not a pool record";
    case Status::format: return "unknown record format";
    case Status::rules: return "unknown share rules version";
    case Status::spacing: return "share spacing out of range (20 to 120 s)";
    case Status::window: return "PPLNS window out of range (360 to 2160 shares)";
    case Status::retarget: return "retarget window out of range (120 to 720 shares, no more than the window)";
    case Status::floor_noncanonical: return "share floor is not a canonical positive compact target";
    case Status::floor_easy: return "share floor easier than the network floor";
    case Status::uncle_depth: return "uncle depth out of range (1 to 3)";
    case Status::uncle_seconds: return "spacing x uncle depth under 60 s (depth 3 below 30 s, 2 below 60 s)";
    case Status::uncle_pct: return "uncle share out of range (80 to 100)";
    case Status::fee_high: return "creator fee above 3%";
    case Status::fee_type: return "unknown fee script type";
    case Status::fee_dest_no_fee: return "a fee destination with no fee";
    case Status::fee_no_dest: return "a fee with no destination";
    case Status::name: return "bad name (1 to 32 of A-Z a-z 0-9 - _)";
    case Status::noncanonical: return "not in canonical form";
    case Status::not_op_return: return "not an OP_RETURN";
    case Status::push: return "not one direct push of a record";
    case Status::local_on_chain: return "a local pool record, never read from the chain";
    case Status::code_prefix: return "not a local pool code (it starts with btfl1:)";
    case Status::code_length: return "a local pool code of the wrong length";
    case Status::code_hex: return "a local pool code is lowercase hex after btfl1:";
    case Status::code_checksum: return "the pool code's checksum does not match (mistyped or cut short)";
    case Status::not_local: return "not a local pool's record";
    case Status::password_long: return "password too long (1024 bytes at most)";
    case Status::kdf_memory: return "could not stretch the password (64 MiB of memory are needed)";
    }
    return "unknown";
}

namespace
{

void Put16(std::vector<uint8_t>& v, uint16_t n)
{
    v.push_back((uint8_t)(n & 0xff));
    v.push_back((uint8_t)(n >> 8));
}

void Put32(std::vector<uint8_t>& v, uint32_t n)
{
    for (int i = 0; i < 4; i++)
        v.push_back((uint8_t)(n >> (8 * i)));
}

uint16_t Get16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }

uint32_t Get32(const uint8_t* p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

bool AllZero(const Hash160& h)
{
    for (uint8_t b : h)
        if (b)
            return false;
    return true;
}

} // namespace

std::vector<uint8_t> encode(const Record& r, const ChainParams& p)
{
    const Magic& m = r.local ? p.local_magic : p.record_magic;
    std::vector<uint8_t> v(m.begin(), m.end());
    v.reserve(FIXED_BYTES + r.name.size());
    v.push_back(r.format);
    v.push_back(r.rules);
    Put16(v, r.spacing);
    Put16(v, r.window);
    Put16(v, r.retarget);
    Put32(v, r.floor);
    v.push_back(r.uncle_depth);
    v.push_back(r.uncle_pct);
    Put16(v, r.fee_bps);
    v.push_back(r.fee_type);
    v.insert(v.end(), r.fee_hash.begin(), r.fee_hash.end());
    v.insert(v.end(), r.name.begin(), r.name.end());
    return v;
}

bool name_ok(const std::string& name)
{
    if (name.empty() || name.size() > MAX_NAME_LEN)
        return false;
    for (char ch : name)
    {
        unsigned char c = (unsigned char)ch;
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

// SetCompact reads the size byte, then that many of the three mantissa bytes
// as a big-endian MPI magnitude whose top bit is the sign, zeros past the
// third. GetCompact writes the minimal MPI back: a leading zero byte only
// when the next byte's top bit is set, unused bytes zero. So a positive
// compact is canonical when the bytes SetCompact ignores are zero and the
// magnitude starts with a byte from 0x01 to 0x7f, or with a zero followed by
// a byte of 0x80 or more.
bool compact_canonical(uint32_t c)
{
    unsigned size = c >> 24;
    uint8_t d[3] = { (uint8_t)(c >> 16), (uint8_t)(c >> 8), (uint8_t)c };
    if (size == 0)
        return false;  // zero
    for (unsigned i = size; i < 3; i++)
        if (d[i] != 0)
            return false;  // bytes SetCompact never reads
    if (d[0] >= 0x80)
        return false;  // negative
    if (d[0] != 0)
        return true;
    return size >= 2 && d[1] >= 0x80;  // the one leading zero MPI allows
}

// Canonical positive compacts order by (size, mantissa): each size covers
// its own range of values, above every smaller size's.
bool compact_no_easier(uint32_t c, uint32_t limit)
{
    uint32_t size = c >> 24, mant = c & 0xffffff;
    uint32_t lsize = limit >> 24, lmant = limit & 0xffffff;
    return size < lsize || (size == lsize && mant <= lmant);
}

Status check(const Record& r, const ChainParams& p)
{
    if (r.format != RECORD_FORMAT)
        return Status::format;
    if (r.rules != SHARE_RULES_V1)
        return Status::rules;
    // Pool zero's exact record (under the record magic) is the only one
    // excused from the spacing rules; a copy with any byte changed is an
    // ordinary record.
    Record zero = p.pool_zero;
    zero.local = false;
    bool pool_zero = encode(r, p) == encode(zero, p);
    if (!pool_zero && (r.spacing < MIN_SPACING || r.spacing > MAX_SPACING))
        return Status::spacing;
    if (r.window < MIN_WINDOW || r.window > MAX_WINDOW)
        return Status::window;
    if (r.retarget < MIN_RETARGET || r.retarget > MAX_RETARGET || r.retarget > r.window)
        return Status::retarget;
    if (!compact_canonical(r.floor))
        return Status::floor_noncanonical;
    if (!compact_no_easier(r.floor, p.network_floor))
        return Status::floor_easy;
    if (r.uncle_depth < MIN_UNCLE_DEPTH || r.uncle_depth > MAX_UNCLE_DEPTH)
        return Status::uncle_depth;
    if (!pool_zero && (unsigned)r.spacing * r.uncle_depth < MIN_UNCLE_SECONDS)
        return Status::uncle_seconds;
    if (r.uncle_pct < MIN_UNCLE_PCT || r.uncle_pct > MAX_UNCLE_PCT)
        return Status::uncle_pct;
    if (r.fee_bps > MAX_FEE_BPS)
        return Status::fee_high;
    if (r.fee_type > FEE_P2SH)
        return Status::fee_type;
    bool zero_hash = AllZero(r.fee_hash);
    if (r.fee_bps == 0 && (r.fee_type != FEE_NONE || !zero_hash))
        return Status::fee_dest_no_fee;
    if (r.fee_bps != 0 && r.fee_type == FEE_NONE)
        return Status::fee_no_dest;
    if (!name_ok(r.name))
        return Status::name;
    return Status::ok;
}

Status parse(const uint8_t* d, size_t len, const ChainParams& p, Record& out)
{
    out = Record();
    if (len < MIN_RECORD_BYTES || len > MAX_RECORD_BYTES)
        return Status::size;
    bool local = p.has_local_magic && memcmp(d, p.local_magic.data(), 4) == 0;
    if (!local && memcmp(d, p.record_magic.data(), 4) != 0)
        return Status::magic;
    Record r;
    r.local = local;
    r.format = d[4];
    r.rules = d[5];
    r.spacing = Get16(d + 6);
    r.window = Get16(d + 8);
    r.retarget = Get16(d + 10);
    r.floor = Get32(d + 12);
    r.uncle_depth = d[16];
    r.uncle_pct = d[17];
    r.fee_bps = Get16(d + 18);
    r.fee_type = d[20];
    memcpy(r.fee_hash.data(), d + 21, 20);
    r.name.assign((const char*)d + FIXED_BYTES, len - FIXED_BYTES);
    Status s = check(r, p);
    if (s != Status::ok)
        return s;
    // Every field is fixed width or bounded by the push, so a record that
    // passed check() writes back to the same bytes; say so rather than assume.
    std::vector<uint8_t> back = encode(r, p);
    if (back.size() != len || memcmp(back.data(), d, len) != 0)
        return Status::noncanonical;
    out = r;
    return Status::ok;
}

Status parse(const std::vector<uint8_t>& data, const ChainParams& p, Record& out)
{
    return parse(data.data(), data.size(), p, out);
}

Status parse_script(const uint8_t* s, size_t len, const ChainParams& p, Record& out)
{
    out = Record();
    if (len < 2 || s[0] != 0x6a)
        return Status::not_op_return;
    size_t n = s[1];
    if (n < MIN_RECORD_BYTES || n > MAX_RECORD_BYTES || len != 2 + n)
        return Status::push;
    Status st = parse(s + 2, n, p, out);
    if (st != Status::ok)
        return st;
    if (out.local)
    {
        out = Record();
        return Status::local_on_chain;
    }
    return Status::ok;
}

Status parse_script(const std::vector<uint8_t>& script, const ChainParams& p, Record& out)
{
    return parse_script(script.data(), script.size(), p, out);
}

std::vector<uint8_t> fee_script(const Record& r)
{
    std::vector<uint8_t> s;
    if (r.fee_type == FEE_P2PKH)
    {
        // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        s = { 0x76, 0xa9, 20 };
        s.insert(s.end(), r.fee_hash.begin(), r.fee_hash.end());
        s.push_back(0x88);
        s.push_back(0xac);
    }
    else if (r.fee_type == FEE_P2SH)
    {
        // OP_HASH160 <20> OP_EQUAL
        s = { 0xa9, 20 };
        s.insert(s.end(), r.fee_hash.begin(), r.fee_hash.end());
        s.push_back(0x87);
    }
    return s;
}

PoolId pool_id(const uint8_t* record, size_t len, const Magic& network_magic)
{
    std::vector<uint8_t> buf(ID_TAG, ID_TAG + sizeof(ID_TAG) - 1);
    buf.insert(buf.end(), network_magic.begin(), network_magic.end());
    buf.insert(buf.end(), record, record + len);
    PoolId id;
    sha256d(buf.data(), buf.size(), id.data());
    return id;
}

PoolId pool_id(const std::vector<uint8_t>& record, const Magic& network_magic)
{
    return pool_id(record.data(), record.size(), network_magic);
}

std::string id_hex(const PoolId& id)
{
    static const char* hx = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 31; i >= 0; i--)
    {
        s += hx[id[i] >> 4];
        s += hx[id[i] & 15];
    }
    return s;
}

bool check_params(const ChainParams& p, std::string* why)
{
    auto fail = [why](const char* w) {
        if (why)
            *why = w;
        return false;
    };
    if (!compact_canonical(p.network_floor))
        return fail("network floor is not a canonical positive compact target");
    if (p.has_local_magic && p.local_magic == p.record_magic)
        return fail("local magic equals the record magic");
    if (p.pool_zero.local)
        return fail("pool zero is a local record");
    Status s = check(p.pool_zero, p);
    if (s != Status::ok)
        return fail(status_text(s));
    return true;
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (RFC 2104), written for this library.

namespace
{
// Called through a volatile pointer, so the compiler cannot prove the write
// dead and drop it.
void* (*const volatile g_memset)(void*, int, size_t) = memset;
} // namespace

void wipe(void* p, size_t len)
{
    if (len)
        g_memset(p, 0, len);
}

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32])
{
    uint8_t k[64] = { 0 };
    if (key_len > 64)
        sha256(key, key_len, k);
    else if (key_len)
        memcpy(k, key, key_len);
    std::vector<uint8_t> inner(64 + msg_len);
    for (size_t i = 0; i < 64; i++)
        inner[i] = (uint8_t)(k[i] ^ 0x36);
    if (msg_len)
        memcpy(inner.data() + 64, msg, msg_len);
    uint8_t outer[64 + 32];
    for (size_t i = 0; i < 64; i++)
        outer[i] = (uint8_t)(k[i] ^ 0x5c);
    sha256(inner.data(), inner.size(), outer + 64);
    sha256(outer, sizeof(outer), out);
    wipe(k, sizeof(k));
    wipe(inner.data(), 64);
    wipe(outer, sizeof(outer));
}

// ---------------------------------------------------------------------------
// BLAKE2b (RFC 7693), written for this library.

namespace
{

const uint64_t B2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

const uint8_t B2B_SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
};

inline uint64_t Rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

inline uint64_t Load64(const uint8_t* p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

inline void Store64(uint8_t* p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

inline void Store32(uint8_t* p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

struct Blake2b
{
    uint64_t h[8];
    uint64_t t0 = 0, t1 = 0;  // bytes hashed so far, 128 bits
    uint8_t buf[128];
    size_t n = 0;             // bytes waiting in buf
    size_t out_len = 0;

    void Init(size_t outLen, const uint8_t* key, size_t keyLen)
    {
        for (int i = 0; i < 8; i++)
            h[i] = B2B_IV[i];
        h[0] ^= 0x01010000ULL ^ ((uint64_t)keyLen << 8) ^ (uint64_t)outLen;
        out_len = outLen;
        if (keyLen)
        {
            uint8_t block[128] = { 0 };
            memcpy(block, key, keyLen);
            Update(block, sizeof(block));
            wipe(block, sizeof(block));
        }
    }

    void Compress(bool last)
    {
        uint64_t m[16], v[16];
        for (int i = 0; i < 16; i++)
            m[i] = Load64(buf + 8 * i);
        for (int i = 0; i < 8; i++)
        {
            v[i] = h[i];
            v[i + 8] = B2B_IV[i];
        }
        v[12] ^= t0;
        v[13] ^= t1;
        if (last)
            v[14] = ~v[14];
        auto G = [&](int r, int i, int a, int b, int c, int d) {
            v[a] = v[a] + v[b] + m[B2B_SIGMA[r][2 * i]];
            v[d] = Rotr64(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = Rotr64(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + m[B2B_SIGMA[r][2 * i + 1]];
            v[d] = Rotr64(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = Rotr64(v[b] ^ v[c], 63);
        };
        for (int r = 0; r < 12; r++)
        {
            G(r, 0, 0, 4, 8, 12);
            G(r, 1, 1, 5, 9, 13);
            G(r, 2, 2, 6, 10, 14);
            G(r, 3, 3, 7, 11, 15);
            G(r, 4, 0, 5, 10, 15);
            G(r, 5, 1, 6, 11, 12);
            G(r, 6, 2, 7, 8, 13);
            G(r, 7, 3, 4, 9, 14);
        }
        for (int i = 0; i < 8; i++)
            h[i] ^= v[i] ^ v[i + 8];
    }

    void Count(size_t bytes)
    {
        t0 += bytes;
        if (t0 < bytes)
            t1++;
    }

    void Update(const uint8_t* p, size_t len)
    {
        while (len)
        {
            // A full buffer is compressed only when more follows: the last
            // block, full or not, is the one that carries the final flag.
            if (n == 128)
            {
                Count(128);
                Compress(false);
                n = 0;
            }
            size_t take = 128 - n < len ? 128 - n : len;
            memcpy(buf + n, p, take);
            n += take;
            p += take;
            len -= take;
        }
    }

    void Final(uint8_t* out)
    {
        Count(n);
        memset(buf + n, 0, 128 - n);
        Compress(true);
        uint8_t full[64];
        for (int i = 0; i < 8; i++)
            Store64(full + 8 * i, h[i]);
        memcpy(out, full, out_len);
        wipe(full, sizeof(full));
        wipe(buf, sizeof(buf));
        wipe(h, sizeof(h));
    }
};

} // namespace

bool blake2b(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len, const uint8_t* key, size_t key_len)
{
    if (out_len < 1 || out_len > 64 || key_len > 64)
        return false;
    Blake2b b;
    b.Init(out_len, key, key_len);
    b.Update(in, in_len);
    b.Final(out);
    return true;
}

// ---------------------------------------------------------------------------
// Argon2 version 1.3 (RFC 9106), written for this library.

namespace
{

const size_t A2_WORDS = 128;  // a block: 1024 bytes as 64-bit words

// H' of RFC 9106 section 3.3: BLAKE2b stretched to any length.
void Argon2LongHash(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len)
{
    uint8_t le[4];
    Store32(le, (uint32_t)out_len);
    Blake2b b;
    if (out_len <= 64)
    {
        b.Init(out_len, nullptr, 0);
        b.Update(le, 4);
        b.Update(in, in_len);
        b.Final(out);
        return;
    }
    uint8_t v[64], next[64];
    b.Init(64, nullptr, 0);
    b.Update(le, 4);
    b.Update(in, in_len);
    b.Final(v);
    memcpy(out, v, 32);
    out += 32;
    size_t left = out_len - 32;
    while (left > 64)
    {
        blake2b(next, 64, v, 64);
        memcpy(v, next, 64);
        memcpy(out, v, 32);
        out += 32;
        left -= 32;
    }
    blake2b(out, left, v, 64);
    wipe(v, sizeof(v));
    wipe(next, sizeof(next));
}

inline void A2G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d)
{
    auto mul = [](uint64_t x, uint64_t y) { return 2 * (x & 0xffffffffULL) * (y & 0xffffffffULL); };
    a = a + b + mul(a, b);
    d = Rotr64(d ^ a, 32);
    c = c + d + mul(c, d);
    b = Rotr64(b ^ c, 24);
    a = a + b + mul(a, b);
    d = Rotr64(d ^ a, 16);
    c = c + d + mul(c, d);
    b = Rotr64(b ^ c, 63);
}

// The permutation P on 16 words, given by their places in the block.
inline void A2P(uint64_t* z, size_t i0, size_t step, size_t pair)
{
    // Word k of the 16 sits at i0 + (k / 2) * step + (k % 2) * pair.
    auto w = [&](size_t k) -> uint64_t& { return z[i0 + (k / 2) * step + (k % 2) * pair]; };
    A2G(w(0), w(4), w(8), w(12));
    A2G(w(1), w(5), w(9), w(13));
    A2G(w(2), w(6), w(10), w(14));
    A2G(w(3), w(7), w(11), w(15));
    A2G(w(0), w(5), w(10), w(15));
    A2G(w(1), w(6), w(11), w(12));
    A2G(w(2), w(7), w(8), w(13));
    A2G(w(3), w(4), w(9), w(14));
}

// The compression G of RFC 9106 section 3.5: next = P(prev ^ ref) ^ prev ^
// ref, and from the second pass on also ^ the block being replaced. next may
// be ref.
void Argon2FillBlock(const uint64_t* prev, const uint64_t* ref, uint64_t* next, bool with_xor)
{
    uint64_t r[A2_WORDS], z[A2_WORDS];
    for (size_t i = 0; i < A2_WORDS; i++)
    {
        r[i] = prev[i] ^ ref[i];
        z[i] = r[i];
    }
    if (with_xor)
        for (size_t i = 0; i < A2_WORDS; i++)
            r[i] ^= next[i];
    // Rows: 8 runs of 16 consecutive words. Columns: 8 sets of 16 words, two
    // side by side out of every 16.
    for (size_t i = 0; i < 8; i++)
        A2P(z, 16 * i, 2, 1);
    for (size_t i = 0; i < 8; i++)
        A2P(z, 2 * i, 16, 1);
    for (size_t i = 0; i < A2_WORDS; i++)
        next[i] = z[i] ^ r[i];
}

} // namespace

bool argon2(Argon2Type type, uint32_t passes, uint32_t memory_kib, uint32_t lanes, const uint8_t* password,
            size_t password_len, const uint8_t* salt, size_t salt_len, const uint8_t* secret, size_t secret_len,
            const uint8_t* ad, size_t ad_len, uint8_t* out, size_t out_len)
{
    if (passes < 1 || lanes < 1 || lanes > 0xffffff || out_len < 4 || salt_len < 8)
        return false;
    if (memory_kib / 8 < lanes)
        return false;
    if (password_len > 0xffffffffULL || salt_len > 0xffffffffULL || secret_len > 0xffffffffULL ||
        ad_len > 0xffffffffULL || out_len > 0xffffffffULL)
        return false;

    const uint32_t blocks = 4 * lanes * (memory_kib / (4 * lanes));  // m'
    const uint32_t lane_len = blocks / lanes;                         // q
    const uint32_t seg_len = lane_len / 4;

    std::vector<uint64_t> mem;
    try
    {
        mem.resize((size_t)blocks * A2_WORDS);
    }
    catch (const std::exception&)
    {
        return false;
    }

    // H0 (section 3.2).
    uint8_t h0[64 + 8];
    {
        Blake2b b;
        b.Init(64, nullptr, 0);
        uint8_t le[4];
        auto put = [&](uint32_t v) {
            Store32(le, v);
            b.Update(le, 4);
        };
        put(lanes);
        put((uint32_t)out_len);
        put(memory_kib);
        put(passes);
        put(0x13);
        put((uint32_t)type);
        put((uint32_t)password_len);
        b.Update(password, password_len);
        put((uint32_t)salt_len);
        b.Update(salt, salt_len);
        put((uint32_t)secret_len);
        b.Update(secret, secret_len);
        put((uint32_t)ad_len);
        b.Update(ad, ad_len);
        b.Final(h0);
    }

    // The first two blocks of every lane.
    {
        uint8_t bytes[1024];
        for (uint32_t l = 0; l < lanes; l++)
            for (uint32_t j = 0; j < 2; j++)
            {
                Store32(h0 + 64, j);
                Store32(h0 + 68, l);
                Argon2LongHash(bytes, sizeof(bytes), h0, sizeof(h0));
                uint64_t* blk = &mem[((size_t)l * lane_len + j) * A2_WORDS];
                for (size_t i = 0; i < A2_WORDS; i++)
                    blk[i] = Load64(bytes + 8 * i);
            }
        wipe(bytes, sizeof(bytes));
    }
    wipe(h0, sizeof(h0));

    for (uint32_t pass = 0; pass < passes; pass++)
        for (uint32_t slice = 0; slice < 4; slice++)
            for (uint32_t lane = 0; lane < lanes; lane++)
            {
                // Argon2i addresses blocks independently of the data
                // everywhere, Argon2id in the first half of the first pass.
                const bool indep = type == Argon2Type::i || (type == Argon2Type::id && pass == 0 && slice < 2);
                uint64_t zero[A2_WORDS] = { 0 }, input[A2_WORDS] = { 0 }, addr[A2_WORDS];
                if (indep)
                {
                    input[0] = pass;
                    input[1] = lane;
                    input[2] = slice;
                    input[3] = blocks;
                    input[4] = passes;
                    input[5] = (uint64_t)type;
                }
                auto next_addresses = [&]() {
                    input[6]++;
                    Argon2FillBlock(zero, input, addr, false);
                    Argon2FillBlock(zero, addr, addr, false);
                };

                uint32_t start = 0;
                if (pass == 0 && slice == 0)
                {
                    start = 2;  // the two blocks made from H0
                    if (indep)
                        next_addresses();
                }
                uint32_t cur = lane * lane_len + slice * seg_len + start;
                uint32_t prev = cur % lane_len == 0 ? cur + lane_len - 1 : cur - 1;
                for (uint32_t i = start; i < seg_len; i++, cur++, prev++)
                {
                    if (cur % lane_len == 1)
                        prev = cur - 1;
                    uint64_t rnd;
                    if (indep)
                    {
                        if (i % A2_WORDS == 0)
                            next_addresses();
                        rnd = addr[i % A2_WORDS];
                    }
                    else
                        rnd = mem[(size_t)prev * A2_WORDS];

                    // The lane and the block to mix in (section 3.4).
                    uint32_t ref_lane = (uint32_t)((rnd >> 32) % lanes);
                    if (pass == 0 && slice == 0)
                        ref_lane = lane;
                    const bool same = ref_lane == lane;
                    uint32_t area;
                    if (pass == 0)
                    {
                        if (slice == 0)
                            area = i - 1;
                        else if (same)
                            area = slice * seg_len + i - 1;
                        else
                            area = slice * seg_len - (i == 0 ? 1 : 0);
                    }
                    else if (same)
                        area = lane_len - seg_len + i - 1;
                    else
                        area = lane_len - seg_len - (i == 0 ? 1 : 0);
                    uint64_t rel = rnd & 0xffffffffULL;
                    rel = (rel * rel) >> 32;
                    rel = area - 1 - ((area * rel) >> 32);
                    uint32_t first = 0;
                    if (pass != 0 && slice != 3)
                        first = (slice + 1) * seg_len;
                    uint32_t ref = (uint32_t)((first + rel) % lane_len);

                    Argon2FillBlock(&mem[(size_t)prev * A2_WORDS], &mem[((size_t)ref_lane * lane_len + ref) * A2_WORDS],
                                    &mem[(size_t)cur * A2_WORDS], pass != 0);
                }
            }

    // The tag: H' of the last blocks of all lanes XORed together.
    uint64_t last[A2_WORDS];
    for (size_t i = 0; i < A2_WORDS; i++)
        last[i] = mem[((size_t)lane_len - 1) * A2_WORDS + i];
    for (uint32_t l = 1; l < lanes; l++)
        for (size_t i = 0; i < A2_WORDS; i++)
            last[i] ^= mem[((size_t)l * lane_len + lane_len - 1) * A2_WORDS + i];
    uint8_t bytes[1024];
    for (size_t i = 0; i < A2_WORDS; i++)
        Store64(bytes + 8 * i, last[i]);
    Argon2LongHash(out, out_len, bytes, sizeof(bytes));
    wipe(bytes, sizeof(bytes));
    wipe(last, sizeof(last));
    wipe(mem.data(), mem.size() * sizeof(uint64_t));
    return true;
}

// ---------------------------------------------------------------------------
// The private local pool (SPEC.md section 18).

namespace
{

void Append(std::vector<uint8_t>& v, const char* tag) { v.insert(v.end(), tag, tag + strlen(tag)); }

void Append(std::vector<uint8_t>& v, const uint8_t* p, size_t n) { v.insert(v.end(), p, p + n); }

int HexVal(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

// A valid record under the local magic.
Status LocalRecordOk(const std::vector<uint8_t>& record, const ChainParams& p)
{
    Record r;
    Status s = parse(record, p, r);
    if (s != Status::ok)
        return s;
    return r.local ? Status::ok : Status::not_local;
}

} // namespace

std::string local_code(const uint8_t* record, size_t len)
{
    static const char* hx = "0123456789abcdef";
    uint8_t sum[32];
    sha256d(record, len, sum);
    std::string s(LOCAL_CODE_PREFIX);
    s.reserve(s.size() + 2 * (len + 4));
    auto put = [&](uint8_t b) {
        s += hx[b >> 4];
        s += hx[b & 15];
    };
    for (size_t i = 0; i < len; i++)
        put(record[i]);
    for (size_t i = 0; i < 4; i++)
        put(sum[i]);
    return s;
}

std::string local_code(const std::vector<uint8_t>& record) { return local_code(record.data(), record.size()); }

Status parse_code(const std::string& code, const ChainParams& p, Record& out)
{
    out = Record();
    const size_t prefix = sizeof(LOCAL_CODE_PREFIX) - 1;
    if (code.size() < prefix || code.compare(0, prefix, LOCAL_CODE_PREFIX) != 0)
        return Status::code_prefix;
    const size_t hex = code.size() - prefix;
    if (hex % 2 != 0 || hex / 2 < MIN_RECORD_BYTES + 4 || hex / 2 > MAX_RECORD_BYTES + 4)
        return Status::code_length;
    std::vector<uint8_t> v(hex / 2);
    for (size_t i = 0; i < v.size(); i++)
    {
        int hi = HexVal(code[prefix + 2 * i]), lo = HexVal(code[prefix + 2 * i + 1]);
        if (hi < 0 || lo < 0)
            return Status::code_hex;
        v[i] = (uint8_t)(hi * 16 + lo);
    }
    std::vector<uint8_t> rec(v.begin(), v.end() - 4);
    uint8_t sum[32];
    sha256d(rec.data(), rec.size(), sum);
    if (memcmp(sum, v.data() + rec.size(), 4) != 0)
        return Status::code_checksum;
    Record r;
    Status s = parse(rec, p, r);
    if (s != Status::ok)
        return s;
    if (!r.local)
        return Status::not_local;
    out = r;
    return Status::ok;
}

std::array<uint8_t, KDF_SALT_BYTES> local_salt(const uint8_t* record, size_t len, const Magic& network_magic)
{
    std::vector<uint8_t> buf;
    Append(buf, LOCAL_SALT_TAG);
    Append(buf, network_magic.data(), 4);
    Append(buf, record, len);
    uint8_t h[32];
    sha256d(buf.data(), buf.size(), h);
    std::array<uint8_t, KDF_SALT_BYTES> salt;
    memcpy(salt.data(), h, salt.size());
    return salt;
}

Status derive_local_from_k(const std::vector<uint8_t>& record, const ChainParams& p, const Hash256& K, LocalKeys& out)
{
    const Hash256 k = K;  // K may be out.K
    out = LocalKeys();
    Status s = LocalRecordOk(record, p);
    if (s != Status::ok)
        return s;
    out.K = k;

    std::vector<uint8_t> buf;
    Append(buf, LOCAL_ID_TAG);
    Append(buf, p.network_magic.data(), 4);
    Append(buf, record.data(), record.size());
    Append(buf, k.data(), 32);
    sha256d(buf.data(), buf.size(), out.id.data());
    wipe(buf.data(), buf.size());

    std::vector<uint8_t> a;
    Append(a, LOCAL_AUTH_TAG);
    Append(a, out.id.data(), 32);
    hmac_sha256(k.data(), 32, a.data(), a.size(), out.A.data());

    std::vector<uint8_t> c;
    Append(c, LOCAL_ANCHOR_TAG);
    Append(c, out.id.data(), 32);
    hmac_sha256(k.data(), 32, c.data(), c.size(), out.C.data());
    return Status::ok;
}

Status derive_local(const std::vector<uint8_t>& record, const ChainParams& p, const std::string& password,
                    LocalKeys& out)
{
    out = LocalKeys();
    Status s = LocalRecordOk(record, p);
    if (s != Status::ok)
        return s;
    if (password.size() > MAX_PASSWORD_LEN)
        return Status::password_long;
    std::array<uint8_t, KDF_SALT_BYTES> salt = local_salt(record.data(), record.size(), p.network_magic);
    Hash256 k;
    if (!argon2(Argon2Type::id, KDF_PASSES, KDF_MEMORY_KIB, 1, (const uint8_t*)password.data(), password.size(),
                salt.data(), salt.size(), nullptr, 0, nullptr, 0, k.data(), k.size()))
        return Status::kdf_memory;
    s = derive_local_from_k(record, p, k, out);
    wipe(k.data(), k.size());
    return s;
}

// ---------------------------------------------------------------------------
// Share data and the coinbase anchor (SPEC.md sections 6, 7 and 18).

namespace
{

const uint8_t TAG_P2P[3] = { 'p', '2', 'p' };
const uint8_t TAG_P2X[3] = { 'p', '2', 'x' };
const uint8_t TAG_P2L[3] = { 'p', '2', 'l' };

// Bitcoin's compact size.
void PutCompactSize(std::vector<uint8_t>& v, uint64_t n)
{
    if (n < 253)
        v.push_back((uint8_t)n);
    else if (n <= 0xffff)
    {
        v.push_back(253);
        Put16(v, (uint16_t)n);
    }
    else if (n <= 0xffffffffULL)
    {
        v.push_back(254);
        Put32(v, (uint32_t)n);
    }
    else
    {
        v.push_back(255);
        Put32(v, (uint32_t)n);
        Put32(v, (uint32_t)(n >> 32));
    }
}

bool IsZero(const Hash256& h)
{
    for (uint8_t b : h)
        if (b)
            return false;
    return true;
}

bool IsPush(const uint8_t* data, size_t n, size_t want, const uint8_t tag[3])
{
    return n == want && memcmp(data, tag, 3) == 0;
}

} // namespace

std::vector<uint8_t> serialize(const ShareData& d)
{
    std::vector<uint8_t> v;
    if (d.kind != PoolKind::zero)
        Append(v, d.pool_id.data(), 32);
    if (d.kind == PoolKind::local)
        Append(v, d.salt.data(), 32);
    Append(v, d.prev_share.data(), 32);
    PutCompactSize(v, d.uncles.size());
    for (const Hash256& u : d.uncles)
        Append(v, u.data(), 32);
    Put32(v, d.height);
    Put32(v, d.bits);
    PutCompactSize(v, d.payout_script.size());
    v.insert(v.end(), d.payout_script.begin(), d.payout_script.end());
    return v;
}

Hash256 share_data_hash(const ShareData& d)
{
    std::vector<uint8_t> v = serialize(d);
    Hash256 h;
    sha256d(v.data(), v.size(), h.data());
    return h;
}

std::vector<uint8_t> anchor_zero(const Hash256& h)
{
    std::vector<uint8_t> v(TAG_P2P, TAG_P2P + 3);
    v.insert(v.end(), h.begin(), h.end());
    return v;
}

std::vector<uint8_t> anchor_registered(const PoolId& id, const Hash256& h)
{
    std::vector<uint8_t> v(TAG_P2X, TAG_P2X + 3);
    v.insert(v.end(), id.begin(), id.end());
    v.insert(v.end(), h.begin(), h.end());
    return v;
}

Hash256 local_anchor_tag(const Hash256& C, const Hash256& h)
{
    Hash256 tag;
    hmac_sha256(C.data(), 32, h.data(), 32, tag.data());
    return tag;
}

std::vector<uint8_t> anchor_local(const Hash256& C, const Hash256& h)
{
    std::vector<uint8_t> v(TAG_P2L, TAG_P2L + 3);
    Hash256 tag = local_anchor_tag(C, h);
    v.insert(v.end(), tag.begin(), tag.end());
    return v;
}

bool local_anchor_matches(const uint8_t* pushed, size_t len, const Hash256& C, const Hash256& h)
{
    if (len != ANCHOR_BYTES || memcmp(pushed, TAG_P2L, 3) != 0)
        return false;
    Hash256 tag = local_anchor_tag(C, h);
    unsigned diff = 0;
    for (size_t i = 0; i < 32; i++)
        diff |= (unsigned)(tag[i] ^ pushed[3 + i]);
    return diff == 0;
}

std::vector<uint8_t> anchor_push(const AnchorPool& pool, const ShareData& d)
{
    Hash256 h = share_data_hash(d);
    if (pool.kind == PoolKind::local)
        return anchor_local(pool.C, h);
    if (pool.kind == PoolKind::registered)
        return anchor_registered(pool.id, h);
    return anchor_zero(h);
}

bool next_op(const uint8_t* s, size_t len, size_t& pos, unsigned& opcode, const uint8_t*& data, size_t& data_len)
{
    opcode = 0xffff;  // OP_INVALIDOPCODE
    data = nullptr;
    data_len = 0;
    if (pos >= len)
        return false;
    unsigned op = s[pos++];
    if (op >= 0xf0)  // a two-byte opcode
    {
        if (pos >= len)
            return false;
        op = (op << 8) | s[pos++];
    }
    if (op <= 0x4e)  // OP_PUSHDATA4
    {
        size_t size = op;
        if (op == 0x4c)  // OP_PUSHDATA1
        {
            if (len - pos < 1)
                return false;
            size = s[pos++];
        }
        else if (op == 0x4d)  // OP_PUSHDATA2
        {
            if (len - pos < 2)
                return false;
            size = (size_t)s[pos] | (size_t)s[pos + 1] << 8;
            pos += 2;
        }
        else if (op == 0x4e)
        {
            if (len - pos < 4)
                return false;
            uint32_t n = Get32(s + pos);
            pos += 4;
            if (len - pos < n)
                return false;
            size = n;
        }
        if (len - pos < size)
            return false;
        data = s + pos;
        data_len = size;
        pos += size;
    }
    opcode = op;
    return true;
}

bool check_anchor(const AnchorPool& pool, const uint8_t* s, size_t len, const ShareData& d)
{
    const Hash256 h = share_data_hash(d);
    size_t pos = 0;
    unsigned op;
    const uint8_t* push;
    size_t n;

    if (pool.kind == PoolKind::zero)
    {
        // Pool zero's rule, frozen: exactly one "p2p" push, whatever else.
        if (d.kind != PoolKind::zero)
            return false;
        int found = 0;
        bool same = false;
        while (pos < len)
        {
            if (!next_op(s, len, pos, op, push, n))
                return false;
            if (IsPush(push, n, ANCHOR_BYTES, TAG_P2P))
            {
                same = memcmp(push + 3, h.data(), 32) == 0;
                found++;
            }
        }
        return found == 1 && same;
    }

    // A share of another pool names that pool, and never in pool zero's
    // form; a local pool's carries a salt, a registered pool's none.
    if (d.kind == PoolKind::zero || d.pool_id != pool.id || IsZero(pool.id))
        return false;
    if (d.kind != pool.kind)
        return false;
    int own = 0;
    while (pos < len)
    {
        if (!next_op(s, len, pos, op, push, n))
            return false;
        bool p2p = IsPush(push, n, ANCHOR_BYTES, TAG_P2P);
        bool p2l = IsPush(push, n, ANCHOR_BYTES, TAG_P2L);
        bool p2x = IsPush(push, n, REGISTERED_ANCHOR_BYTES, TAG_P2X);
        if (p2p)
            return false;
        if (pool.kind == PoolKind::local)
        {
            if (p2x)
                return false;
            if (p2l)
            {
                if (!local_anchor_matches(push, n, pool.C, h))
                    return false;
                own++;
            }
        }
        else
        {
            if (p2l)
                return false;
            if (p2x)
            {
                if (memcmp(push + 3, pool.id.data(), 32) != 0 || memcmp(push + 35, h.data(), 32) != 0)
                    return false;
                own++;
            }
        }
    }
    return own == 1;
}

bool check_anchor(const AnchorPool& pool, const std::vector<uint8_t>& script_sig, const ShareData& d)
{
    return check_anchor(pool, script_sig.data(), script_sig.size(), d);
}

Anchor classify_anchor(const uint8_t* s, size_t len)
{
    Anchor none;
    size_t pos = 0;
    unsigned op;
    const uint8_t* push;
    size_t n;
    int p2p = 0, p2x = 0, p2l = 0;
    Anchor zero, reg;
    while (pos < len)
    {
        if (!next_op(s, len, pos, op, push, n))
            return none;
        if (IsPush(push, n, ANCHOR_BYTES, TAG_P2P))
        {
            memcpy(zero.hash.data(), push + 3, 32);
            p2p++;
        }
        else if (IsPush(push, n, ANCHOR_BYTES, TAG_P2L))
            p2l++;
        else if (IsPush(push, n, REGISTERED_ANCHOR_BYTES, TAG_P2X))
        {
            memcpy(reg.pool_id.data(), push + 3, 32);
            memcpy(reg.hash.data(), push + 35, 32);
            p2x++;
        }
    }
    if (p2p == 1 && p2x == 0)
    {
        zero.kind = AnchorKind::zero;
        return zero;
    }
    if (p2x == 1 && p2p == 0 && p2l == 0)
    {
        reg.kind = AnchorKind::registered;
        return reg;
    }
    return none;
}

Anchor classify_anchor(const std::vector<uint8_t>& script_sig)
{
    return classify_anchor(script_sig.data(), script_sig.size());
}

} // namespace everpool
