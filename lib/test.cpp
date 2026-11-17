// Runs vectors/record.json against the library, plus SHA-256 test vectors.
//
//   test [path/to/record.json]
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
    const char* path = argc > 1 ? argv[1] : "vectors/record.json";
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        fprintf(stderr, "cannot open %s\n", path);
        return 2;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string text = ss.str();
    Json doc = Reader(text).Parse();

    Sha256Vectors();

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

    printf("\n%s: %d passed, %d failed\n", g_fail ? "FAILED" : "all passed", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
