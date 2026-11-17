// Everpool portable library. See everpool.h. MIT license, see LICENSE.

#include "everpool.h"

#include <cstring>

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

} // namespace everpool
