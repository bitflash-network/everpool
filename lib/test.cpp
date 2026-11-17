// Runs the vectors (record.json, local.json, anchor.json) against the
// library, plus the published test vectors of its own hashes: SHA-256 (FIPS
// 180-4), HMAC-SHA256 (RFC 4231), BLAKE2b (RFC 7693) and Argon2 (RFC 9106).
//
//   test [path/to/vectors]
//
// The vectors were generated from the reference implementation, not from
// this library. Exit code 0 when everything passes.

#include "everpool.h"
#include "examples/bitflash.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// A minimal JSON reader: enough for the vectors (objects, arrays, strings,
// unsigned integers, booleans, null).

struct Json
{
    enum Type { NUL, BOOL, NUM, STR, ARR, OBJ } type = NUL;
    bool b = false;
    unsigned long long n = 0;
    std::string s;
    std::vector<Json> a;
    std::vector<std::pair<std::string, Json>> o;

    const Json& operator[](const char* key) const
    {
        for (const auto& kv : o)
            if (kv.first == key)
                return kv.second;
        fprintf(stderr, "missing key: %s\n", key);
        exit(2);
    }
    bool has(const char* key) const
    {
        for (const auto& kv : o)
            if (kv.first == key)
                return true;
        return false;
    }
};

class Reader
{
public:
    explicit Reader(const std::string& t) : t_(t) {}
    Json Parse()
    {
        Json v = Value();
        Ws();
        if (i_ != t_.size())
            Die("trailing data");
        return v;
    }

private:
    const std::string& t_;
    size_t i_ = 0;

    [[noreturn]] void Die(const char* why)
    {
        fprintf(stderr, "bad JSON at %u: %s\n", (unsigned)i_, why);
        exit(2);
    }
    void Ws()
    {
        while (i_ < t_.size() && (t_[i_] == ' ' || t_[i_] == '\n' || t_[i_] == '\r' || t_[i_] == '\t'))
            i_++;
    }
    char Peek()
    {
        Ws();
        if (i_ >= t_.size())
            Die("unexpected end");
        return t_[i_];
    }
    void Expect(char c)
    {
        if (Peek() != c)
            Die("unexpected character");
        i_++;
    }
    bool Word(const char* w)
    {
        size_t n = strlen(w);
        if (t_.compare(i_, n, w) == 0)
        {
            i_ += n;
            return true;
        }
        return false;
    }
    std::string Str()
    {
        Expect('"');
        std::string s;
        while (true)
        {
            if (i_ >= t_.size())
                Die("unterminated string");
            char c = t_[i_++];
            if (c == '"')
                return s;
            if (c != '\\')
            {
                s += c;
                continue;
            }
            if (i_ >= t_.size())
                Die("bad escape");
            c = t_[i_++];
            switch (c)
            {
            case '"': s += '"'; break;
            case '\\': s += '\\'; break;
            case '/': s += '/'; break;
            case 'n': s += '\n'; break;
            case 't': s += '\t'; break;
            case 'r': s += '\r'; break;
            case 'b': s += '\b'; break;
            case 'f': s += '\f'; break;
            case 'u':
            {
                if (i_ + 4 > t_.size())
                    Die("bad \\u escape");
                unsigned cp = (unsigned)strtoul(t_.substr(i_, 4).c_str(), nullptr, 16);
                i_ += 4;
                if (cp < 0x80)
                    s += (char)cp;
                else if (cp < 0x800)
                {
                    s += (char)(0xc0 | (cp >> 6));
                    s += (char)(0x80 | (cp & 0x3f));
                }
                else
                {
                    s += (char)(0xe0 | (cp >> 12));
                    s += (char)(0x80 | ((cp >> 6) & 0x3f));
                    s += (char)(0x80 | (cp & 0x3f));
                }
                break;
            }
            default: Die("bad escape");
            }
        }
    }
    Json Value()
    {
        Json v;
        char c = Peek();
        if (c == '{')
        {
            v.type = Json::OBJ;
            i_++;
            if (Peek() == '}')
            {
                i_++;
                return v;
            }
            while (true)
            {
                std::string k = Str();
                Expect(':');
                v.o.emplace_back(k, Value());
                if (Peek() == ',')
                {
                    i_++;
                    continue;
                }
                Expect('}');
                return v;
            }
        }
        if (c == '[')
        {
            v.type = Json::ARR;
            i_++;
            if (Peek() == ']')
            {
                i_++;
                return v;
            }
            while (true)
            {
                v.a.push_back(Value());
                if (Peek() == ',')
                {
                    i_++;
                    continue;
                }
                Expect(']');
                return v;
            }
        }
        if (c == '"')
        {
            v.type = Json::STR;
            v.s = Str();
            return v;
        }
        if (Word("true"))
        {
            v.type = Json::BOOL;
            v.b = true;
            return v;
        }
        if (Word("false"))
        {
            v.type = Json::BOOL;
            return v;
        }
        if (Word("null"))
            return v;
        if (c >= '0' && c <= '9')
        {
            v.type = Json::NUM;
            size_t start = i_;
            while (i_ < t_.size() && t_[i_] >= '0' && t_[i_] <= '9')
                i_++;
            v.n = strtoull(t_.substr(start, i_ - start).c_str(), nullptr, 10);
            return v;
        }
        Die("unexpected value");
    }
};

// ---------------------------------------------------------------------------

static int g_pass = 0, g_fail = 0;

static void Fail(const std::string& what)
{
    printf("  FAIL %s\n", what.c_str());
    g_fail++;
}

static std::string Hex(const uint8_t* p, size_t n)
{
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++)
    {
        s += hx[p[i] >> 4];
        s += hx[p[i] & 15];
    }
    return s;
}
static std::string Hex(const std::vector<uint8_t>& v) { return Hex(v.data(), v.size()); }

static std::vector<uint8_t> Unhex(const std::string& h)
{
    if (h.size() % 2)
    {
        fprintf(stderr, "odd hex: %s\n", h.c_str());
        exit(2);
    }
    std::vector<uint8_t> v;
    for (size_t i = 0; i < h.size(); i += 2)
        v.push_back((uint8_t)strtoul(h.substr(i, 2).c_str(), nullptr, 16));
    return v;
}

static everpool::Magic MagicOf(const Json& j)
{
    std::vector<uint8_t> v = Unhex(j.s);
    if (v.size() != 4)
    {
        fprintf(stderr, "bad magic\n");
        exit(2);
    }
    return { v[0], v[1], v[2], v[3] };
}

static everpool::Record FieldsOf(const Json& f)
{
    everpool::Record r;
    r.local = f["local"].b;
    r.format = (uint8_t)f["format"].n;
    r.rules = (uint8_t)f["rules"].n;
    r.spacing = (uint16_t)f["spacing"].n;
    r.window = (uint16_t)f["window"].n;
    r.retarget = (uint16_t)f["retarget"].n;
    r.floor = (uint32_t)f["floor"].n;
    r.uncle_depth = (uint8_t)f["uncle_depth"].n;
    r.uncle_pct = (uint8_t)f["uncle_pct"].n;
    r.fee_bps = (uint16_t)f["fee_bps"].n;
    r.fee_type = (uint8_t)f["fee_type"].n;
    std::vector<uint8_t> h = Unhex(f["fee_hash"].s);
    if (h.size() != 20)
    {
        fprintf(stderr, "bad fee hash\n");
        exit(2);
    }
    for (size_t i = 0; i < 20; i++)
        r.fee_hash[i] = h[i];
    std::vector<uint8_t> nm = Unhex(f["name_hex"].s);
    r.name.assign(nm.begin(), nm.end());
    return r;
}

static bool SameRecord(const everpool::Record& a, const everpool::Record& b)
{
    return a.local == b.local && a.format == b.format && a.rules == b.rules && a.spacing == b.spacing &&
           a.window == b.window && a.retarget == b.retarget && a.floor == b.floor && a.uncle_depth == b.uncle_depth &&
           a.uncle_pct == b.uncle_pct && a.fee_bps == b.fee_bps && a.fee_type == b.fee_type &&
           a.fee_hash == b.fee_hash && a.name == b.name;
}

// The outcome must match: valid, or refused with the same reason and text.
static bool SameOutcome(const Json& v, everpool::Status s, std::string& why)
{
    bool want = v["valid"].b;
    if (want != (s == everpool::Status::ok))
    {
        why = std::string("expected ") + (want ? "valid" : v["reason"].s.c_str()) + ", got " + everpool::status_code(s);
        return false;
    }
    if (!want && (v["reason"].s != everpool::status_code(s) || v["error"].s != everpool::status_text(s)))
    {
        why = "expected " + v["reason"].s + " (" + v["error"].s + "), got " + everpool::status_code(s) + " (" +
              everpool::status_text(s) + ")";
        return false;
    }
    return true;
}

static everpool::Hash256 HashOf(const Json& j)
{
    std::vector<uint8_t> v = Unhex(j.s);
    if (v.size() != 32)
    {
        fprintf(stderr, "bad 32-byte value: %s\n", j.s.c_str());
        exit(2);
    }
    everpool::Hash256 h;
    for (size_t i = 0; i < 32; i++)
        h[i] = v[i];
    return h;
}

static Json Load(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        fprintf(stderr, "cannot open %s\n", path.c_str());
        exit(2);
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string text = ss.str();
    return Reader(text).Parse();
}

// Counts one group of checks and prints "name: passed/total".
struct Group
{
    const char* name;
    int n = 0, bad = 0;
    explicit Group(const char* nm) : name(nm) {}
    void Check(bool ok, const std::string& what)
    {
        n++;
        if (ok)
            g_pass++;
        else
        {
            Fail(std::string(name) + "/" + what);
            bad++;
        }
    }
    ~Group() { printf("%s: %d/%d\n", name, n - bad, n); }
};

// RFC 4231, test cases 1 to 4, 6 and 7.
static void HmacVectors()
{
    struct
    {
        std::string key, msg;
        const char* hex;
    } v[] = {
        { std::string(20, '\x0b'), "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
        { "Jefe", "what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
        { std::string(20, '\xaa'), std::string(50, '\xdd'),
          "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" },
        { std::string("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25),
          std::string(50, '\xcd'), "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" },
        { std::string(131, '\xaa'), "Test Using Larger Than Block-Size Key - Hash Key First",
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
        { std::string(131, '\xaa'),
          "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be "
          "hashed before being used by the HMAC algorithm.",
          "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" },
    };
    Group g("hmac-sha256 (RFC 4231)");
    for (const auto& t : v)
    {
        uint8_t h[32];
        everpool::hmac_sha256((const uint8_t*)t.key.data(), t.key.size(), (const uint8_t*)t.msg.data(), t.msg.size(), h);
        g.Check(Hex(h, 32) == t.hex, "key of " + std::to_string(t.key.size()) + " bytes");
    }
}

// RFC 7693: the "abc" example of appendix A and the self-test of appendix E,
// which hashes 24 inputs with and without a key at four output lengths and
// hashes the results.
static void Blake2bVectors()
{
    Group g("blake2b (RFC 7693)");
    uint8_t out[64];
    g.Check(everpool::blake2b(out, 64, (const uint8_t*)"abc", 3) &&
                Hex(out, 64) == "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            "abc");
    g.Check(everpool::blake2b(out, 64, nullptr, 0) &&
                Hex(out, 64) == "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                                "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            "empty");

    auto seq = [](std::vector<uint8_t>& v, size_t len, uint32_t seed) {
        uint32_t a = 0xDEAD4BAD * seed, b = 1;
        v.resize(len);
        for (size_t i = 0; i < len; i++)
        {
            uint32_t t = a + b;
            a = b;
            b = t;
            v[i] = (uint8_t)(t >> 24);
        }
    };
    const size_t md_len[4] = { 20, 32, 48, 64 };
    const size_t in_len[6] = { 0, 3, 128, 129, 255, 1024 };
    std::vector<uint8_t> all, in, key;
    bool ok = true;
    for (size_t outlen : md_len)
        for (size_t inlen : in_len)
        {
            uint8_t md[64];
            seq(in, inlen, (uint32_t)inlen);
            ok = ok && everpool::blake2b(md, outlen, in.data(), inlen);
            all.insert(all.end(), md, md + outlen);
            seq(key, outlen, (uint32_t)outlen);
            ok = ok && everpool::blake2b(md, outlen, in.data(), inlen, key.data(), outlen);
            all.insert(all.end(), md, md + outlen);
        }
    ok = ok && everpool::blake2b(out, 32, all.data(), all.size());
    g.Check(ok && Hex(out, 32) == "c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475", "self-test");
    g.Check(!everpool::blake2b(out, 0, nullptr, 0) && !everpool::blake2b(out, 65, nullptr, 0), "sizes out of range");
}

// RFC 9106, section 5: Argon2d, Argon2i and Argon2id with 32 KiB, 3 passes,
// 4 lanes, a secret and associated data.
static void Argon2Vectors()
{
    Group g("argon2 (RFC 9106)");
    const std::vector<uint8_t> pwd(32, 1), salt(16, 2), secret(8, 3), ad(12, 4);
    struct
    {
        everpool::Argon2Type type;
        const char* name;
        const char* hex;
    } v[] = {
        { everpool::Argon2Type::d, "argon2d", "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb" },
        { everpool::Argon2Type::i, "argon2i", "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8" },
        { everpool::Argon2Type::id, "argon2id", "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" },
    };
    for (const auto& t : v)
    {
        uint8_t tag[32];
        bool ok = everpool::argon2(t.type, 3, 32, 4, pwd.data(), pwd.size(), salt.data(), salt.size(), secret.data(),
                                   secret.size(), ad.data(), ad.size(), tag, sizeof(tag));
        g.Check(ok && Hex(tag, 32) == t.hex, t.name);
    }
    uint8_t tag[32];
    g.Check(!everpool::argon2(everpool::Argon2Type::id, 0, 32, 4, pwd.data(), 32, salt.data(), 16, nullptr, 0, nullptr, 0,
                              tag, 32) &&
                !everpool::argon2(everpool::Argon2Type::id, 3, 31, 4, pwd.data(), 32, salt.data(), 16, nullptr, 0, nullptr,
                                  0, tag, 32) &&
                !everpool::argon2(everpool::Argon2Type::id, 3, 32, 0, pwd.data(), 32, salt.data(), 16, nullptr, 0, nullptr,
                                  0, tag, 32) &&
                !everpool::argon2(everpool::Argon2Type::id, 3, 32, 4, pwd.data(), 32, salt.data(), 7, nullptr, 0, nullptr,
                                  0, tag, 32) &&
                !everpool::argon2(everpool::Argon2Type::id, 3, 32, 4, pwd.data(), 32, salt.data(), 16, nullptr, 0, nullptr,
                                  0, tag, 3),
            "parameters out of range");
}

static bool KindOf(const std::string& s, everpool::PoolKind& k)
{
    if (s == "zero")
        k = everpool::PoolKind::zero;
    else if (s == "registered")
        k = everpool::PoolKind::registered;
    else if (s == "local")
        k = everpool::PoolKind::local;
    else
        return false;
    return true;
}

static everpool::ShareData DataOf(const Json& j)
{
    everpool::ShareData d;
    if (!KindOf(j["kind"].s, d.kind))
    {
        fprintf(stderr, "bad share data kind\n");
        exit(2);
    }
    if (j.has("pool_id"))
        d.pool_id = HashOf(j["pool_id"]);
    if (j.has("salt"))
        d.salt = HashOf(j["salt"]);
    d.prev_share = HashOf(j["prev_share"]);
    for (const Json& u : j["uncles"].a)
        d.uncles.push_back(HashOf(u));
    d.height = (uint32_t)j["height"].n;
    d.bits = (uint32_t)j["bits"].n;
    d.payout_script = Unhex(j["payout_script"].s);
    return d;
}

static everpool::AnchorPool PoolOf(const Json& j)
{
    everpool::AnchorPool p;
    if (!KindOf(j["kind"].s, p.kind))
    {
        fprintf(stderr, "bad pool kind\n");
        exit(2);
    }
    if (j.has("pool_id"))
        p.id = HashOf(j["pool_id"]);
    if (j.has("C"))
        p.C = HashOf(j["C"]);
    return p;
}

// vectors/local.json: the pool code, the derivation, the p2l tag.
static void LocalVectors(const Json& doc, const everpool::ChainParams& main, const everpool::ChainParams& test)
{
    {
        Group g("local params");
        const Json& p = doc["params"];
        const Json& kdf = p["kdf"];
        g.Check(p["code_prefix"].s == everpool::LOCAL_CODE_PREFIX, "code prefix");
        g.Check(MagicOf(p["record_magic"]) == main.record_magic && MagicOf(p["local_magic"]) == main.local_magic,
                "record magics");
        g.Check(MagicOf(p["network_magic"]["mainnet"]) == main.network_magic &&
                    MagicOf(p["network_magic"]["testnet"]) == test.network_magic,
                "network magics");
        g.Check(kdf["algorithm"].s == "argon2id" && kdf["version"].n == 0x13 && kdf["passes"].n == everpool::KDF_PASSES &&
                    kdf["memory_kib"].n == everpool::KDF_MEMORY_KIB && kdf["lanes"].n == 1 &&
                    kdf["salt_bytes"].n == everpool::KDF_SALT_BYTES && kdf["key_bytes"].n == 32 &&
                    kdf["max_password_bytes"].n == everpool::MAX_PASSWORD_LEN,
                "kdf");
        g.Check(p["tags"]["salt"].s == everpool::LOCAL_SALT_TAG && p["tags"]["id"].s == everpool::LOCAL_ID_TAG &&
                    p["tags"]["auth"].s == everpool::LOCAL_AUTH_TAG && p["tags"]["anchor"].s == everpool::LOCAL_ANCHOR_TAG,
                "tags");
    }
    {
        Group g("local code");
        for (const Json& v : doc["code"].a)
        {
            everpool::Record out;
            everpool::Status s = everpool::parse_code(v["code"].s, main, out);
            std::string why;
            bool ok = SameOutcome(v, s, why);
            if (ok && s == everpool::Status::ok)
            {
                std::vector<uint8_t> rec = Unhex(v["record"].s);
                if (!SameRecord(out, FieldsOf(v["fields"])) || !out.local)
                    ok = false, why = "fields differ";
                else if (everpool::encode(out, main) != rec)
                    ok = false, why = "record differs";
                else if (everpool::local_code(rec) != v["code"].s)
                    ok = false, why = "does not write back to the same code";
            }
            g.Check(ok, v["name"].s + ": " + why);
        }
    }
    {
        Group g("local derive");
        for (const Json& v : doc["derive"].a)
        {
            const everpool::ChainParams& p = v["network"].s == "testnet" ? test : main;
            std::vector<uint8_t> rec = Unhex(v["record"].s), pw = Unhex(v["password_hex"].s);
            everpool::LocalKeys k;
            everpool::Status s = everpool::derive_local(rec, p, std::string(pw.begin(), pw.end()), k);
            std::string why;
            bool ok = SameOutcome(v, s, why);
            if (ok && s == everpool::Status::ok)
            {
                everpool::LocalKeys k2;
                auto salt = everpool::local_salt(rec.data(), rec.size(), p.network_magic);
                if (Hex(salt.data(), salt.size()) != v["salt"].s)
                    ok = false, why = "salt differs";
                else if (k.K != HashOf(v["K"]))
                    ok = false, why = "K differs";
                else if (k.id != HashOf(v["id"]))
                    ok = false, why = "id differs";
                else if (k.A != HashOf(v["A"]))
                    ok = false, why = "A differs";
                else if (k.C != HashOf(v["C"]))
                    ok = false, why = "C differs";
                else if (everpool::derive_local_from_k(rec, p, k.K, k2) != everpool::Status::ok || k2.K != k.K ||
                         k2.id != k.id || k2.A != k.A || k2.C != k.C)
                    ok = false, why = "the stored K gives other keys";
            }
            else if (ok)
            {
                // What refuses the password also refuses a stored K, but for
                // the password's own length.
                everpool::LocalKeys k2;
                everpool::Status s2 = everpool::derive_local_from_k(rec, p, everpool::Hash256(), k2);
                if ((s2 == everpool::Status::ok) != (s == everpool::Status::password_long) ||
                    (s2 != everpool::Status::ok && s2 != s))
                    ok = false, why = "the stored K is refused differently";
                else if (k.K != everpool::Hash256() || k.id != everpool::Hash256())
                    ok = false, why = "keys left behind on failure";
            }
            g.Check(ok, v["name"].s + ": " + why);
        }
    }
    {
        Group g("local anchor tag");
        for (const Json& v : doc["anchor_tag"].a)
        {
            everpool::Hash256 C = HashOf(v["C"]), h = HashOf(v["share_data_hash"]);
            std::vector<uint8_t> pushed = Unhex(v["pushed"].s);
            bool want = v["matches"].b;
            bool ok = everpool::local_anchor_matches(pushed.data(), pushed.size(), C, h) == want &&
                      (everpool::anchor_local(C, h) == pushed) == want;
            g.Check(ok, v["name"].s);
        }
    }
}

// vectors/anchor.json: share data, the pushes, scripts.
static void AnchorVectors(const Json& doc)
{
    static const char* kinds[3] = { "zero", "registered", "local" };
    everpool::AnchorPool pools[3];
    everpool::ShareData datas[3];
    {
        Group g("anchor context");
        const Json& c = doc["context"];
        for (int i = 0; i < 3; i++)
        {
            const Json& e = c[kinds[i]];
            pools[i] = PoolOf(e["pool"]);
            datas[i] = DataOf(e["data"]);
            g.Check(everpool::share_data_hash(datas[i]) == HashOf(e["hash"]) &&
                        Hex(everpool::anchor_push(pools[i], datas[i])) == e["push"].s,
                    kinds[i]);
        }
    }
    {
        Group g("anchor share data");
        for (const Json& v : doc["share_data"].a)
        {
            everpool::ShareData d = DataOf(v["data"]);
            g.Check(Hex(everpool::serialize(d)) == v["serialized"].s && everpool::share_data_hash(d) == HashOf(v["hash"]),
                    v["name"].s);
        }
    }
    {
        Group g("anchor push");
        for (const Json& v : doc["push"].a)
        {
            everpool::AnchorPool pool = PoolOf(v["pool"]);
            everpool::ShareData d = DataOf(v["data"]);
            everpool::Hash256 h = everpool::share_data_hash(d);
            std::vector<uint8_t> push = everpool::anchor_push(pool, d), want = Unhex(v["push"].s);
            bool ok = h == HashOf(v["hash"]) && push == want;
            // The same through the function of each kind, and back through
            // check_anchor behind a direct push or OP_PUSHDATA1.
            if (pool.kind == everpool::PoolKind::zero)
                ok = ok && everpool::anchor_zero(h) == want;
            else if (pool.kind == everpool::PoolKind::registered)
                ok = ok && everpool::anchor_registered(pool.id, h) == want;
            else
                ok = ok && everpool::anchor_local(pool.C, h) == want &&
                     everpool::local_anchor_matches(want.data(), want.size(), pool.C, h);
            std::vector<uint8_t> script;
            if (push.size() > 75)
                script.push_back(0x4c);
            script.push_back((uint8_t)push.size());
            script.insert(script.end(), push.begin(), push.end());
            ok = ok && everpool::check_anchor(pool, script, d);
            g.Check(ok, v["name"].s);
        }
    }
    {
        Group gk("anchor check"), gc("anchor classify");
        for (const Json& v : doc["scripts"].a)
        {
            std::vector<uint8_t> script = Unhex(v["script"].s);
            const Json& want = v["classify"];
            everpool::Anchor a = everpool::classify_anchor(script);
            bool ok;
            if (want["kind"].s == "zero")
                ok = a.kind == everpool::AnchorKind::zero && a.hash == HashOf(want["hash"]);
            else if (want["kind"].s == "registered")
                ok = a.kind == everpool::AnchorKind::registered && a.pool_id == HashOf(want["pool_id"]) &&
                     a.hash == HashOf(want["hash"]);
            else
                ok = want["kind"].s == "none" && a.kind == everpool::AnchorKind::none;
            gc.Check(ok, v["name"].s);
            for (int i = 0; i < 3; i++)
                gk.Check(everpool::check_anchor(pools[i], script, datas[i]) == v["check"][kinds[i]].b,
                         v["name"].s + " for " + kinds[i]);
        }
    }
    {
        Group g("anchor mismatch");
        for (const Json& v : doc["mismatch"].a)
            g.Check(everpool::check_anchor(PoolOf(v["pool"]), Unhex(v["script"].s), DataOf(v["data"])) == v["valid"].b,
                    v["name"].s);
    }
}

static void Sha256Vectors()
{
    // FIPS 180-4 examples and lengths around the padding boundary.
    struct
    {
        std::string msg;
        const char* hex;
    } v[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
        { std::string(55, 'a'), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318" },
        { std::string(56, 'a'), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a" },
        { std::string(64, 'a'), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" },
        { std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },
    };
    int bad = 0;
    for (const auto& t : v)
    {
        uint8_t h[32];
        everpool::sha256((const uint8_t*)t.msg.data(), t.msg.size(), h);
        if (Hex(h, 32) != t.hex)
        {
            Fail("sha256 of " + std::to_string(t.msg.size()) + " bytes");
            bad++;
        }
        else
            g_pass++;
    }
    printf("sha256: %d/%d\n", (int)(sizeof(v) / sizeof(v[0])) - bad, (int)(sizeof(v) / sizeof(v[0])));
}

int main(int argc, char** argv)
{
    const std::string dir = argc > 1 ? argv[1] : "vectors";
    Json doc = Load(dir + "/record.json");

    Sha256Vectors();
    HmacVectors();
    Blake2bVectors();
    Argon2Vectors();

    // The example parameters must be the ones the vectors were made with.
    everpool::ChainParams main = bitflash::Mainnet(), test = bitflash::Testnet();
    {
        const Json& p = doc["params"];
        int bad = 0;
        auto expect = [&](bool ok, const char* what) {
            if (ok)
                g_pass++;
            else
            {
                Fail(what);
                bad++;
            }
        };
        expect(MagicOf(p["record_magic"]) == main.record_magic, "record magic");
        expect(main.has_local_magic && MagicOf(p["local_magic"]) == main.local_magic, "local magic");
        expect(p["network_floor"].n == main.network_floor, "network floor");
        expect(MagicOf(p["network_magic"]["mainnet"]) == main.network_magic, "mainnet magic");
        expect(MagicOf(p["network_magic"]["testnet"]) == test.network_magic, "testnet magic");
        expect(Hex(everpool::encode(main.pool_zero, main)) == p["pool_zero"].s, "pool zero record");
        expect(p["id_tag"].s == everpool::ID_TAG, "id tag");
        std::string why;
        expect(everpool::check_params(main, &why) && everpool::check_params(test, &why), "check_params");
        printf("params: %s\n", bad ? "MISMATCH" : "match");
    }

    const std::map<std::string, const everpool::ChainParams*> nets = { { "mainnet", &main }, { "testnet", &test } };

    // Records as bytes.
    {
        const Json& list = doc["parse"];
        int bad = 0;
        for (const Json& v : list.a)
        {
            std::vector<uint8_t> data = Unhex(v["record"].s);
            everpool::Record out;
            everpool::Status s = everpool::parse(data, main, out);
            std::string why;
            bool ok = SameOutcome(v, s, why);
            if (ok && s == everpool::Status::ok)
            {
                everpool::Record want = FieldsOf(v["fields"]);
                if (!SameRecord(out, want))
                    ok = false, why = "fields differ";
                else if (everpool::encode(out, main) != data)
                    ok = false, why = "does not encode back";
                else if (Hex(everpool::fee_script(out)) != v["fee_script"].s)
                    ok = false, why = "fee script differs";
                else if (everpool::check(want, main) != everpool::Status::ok)
                    ok = false, why = "check refuses its fields";
            }
            if (ok)
                g_pass++;
            else
            {
                Fail("parse/" + v["name"].s + ": " + why);
                bad++;
            }
        }
        printf("parse: %d/%d\n", (int)list.a.size() - bad, (int)list.a.size());
    }

    // Records inside an OP_RETURN script.
    {
        const Json& list = doc["script"];
        int bad = 0;
        for (const Json& v : list.a)
        {
            everpool::Record out;
            everpool::Status s = everpool::parse_script(Unhex(v["script"].s), main, out);
            std::string why;
            bool ok = SameOutcome(v, s, why);
            if (ok && s == everpool::Status::ok && Hex(everpool::encode(out, main)) != v["record"].s)
                ok = false, why = "record differs";
            if (ok)
                g_pass++;
            else
            {
                Fail("script/" + v["name"].s + ": " + why);
                bad++;
            }
        }
        printf("script: %d/%d\n", (int)list.a.size() - bad, (int)list.a.size());
    }

    // Fields through check(), including records Parse cannot reach.
    {
        const Json& list = doc["check"];
        int bad = 0;
        for (const Json& v : list.a)
        {
            everpool::Record r = FieldsOf(v["fields"]);
            std::string why;
            bool ok = true;
            if (Hex(everpool::encode(r, main)) != v["encoded"].s)
                ok = false, why = "encoding differs";
            else
                ok = SameOutcome(v, everpool::check(r, main), why);
            if (ok)
                g_pass++;
            else
            {
                Fail("check/" + v["name"].s + ": " + why);
                bad++;
            }
        }
        printf("check: %d/%d\n", (int)list.a.size() - bad, (int)list.a.size());
    }

    // Pool ids on both networks.
    {
        const Json& list = doc["pool_id"];
        int bad = 0, n = 0;
        for (const Json& v : list.a)
        {
            std::vector<uint8_t> rec = Unhex(v["record"].s);
            for (const auto& net : nets)
            {
                n++;
                const Json& want = v["ids"][net.first.c_str()];
                everpool::PoolId id = everpool::pool_id(rec, net.second->network_magic);
                if (Hex(id.data(), 32) == want["internal"].s && everpool::id_hex(id) == want["shown"].s)
                    g_pass++;
                else
                {
                    Fail("pool_id/" + v["name"].s + " on " + net.first);
                    bad++;
                }
            }
        }
        printf("pool_id: %d/%d\n", n - bad, n);
    }

    // The compact canonical form.
    {
        const Json& list = doc["compact"];
        int bad = 0;
        for (const Json& v : list.a)
        {
            uint32_t c = (uint32_t)v.a.at(0).n;
            if (everpool::compact_canonical(c) == v.a.at(1).b)
                g_pass++;
            else
            {
                char b[64];
                snprintf(b, sizeof(b), "compact/0x%08x", c);
                Fail(b);
                bad++;
            }
        }
        printf("compact: %d/%d\n", (int)list.a.size() - bad, (int)list.a.size());
    }

    LocalVectors(Load(dir + "/local.json"), main, test);
    AnchorVectors(Load(dir + "/anchor.json"));

    printf("\n%s: %d passed, %d failed\n", g_fail ? "FAILED" : "all passed", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
