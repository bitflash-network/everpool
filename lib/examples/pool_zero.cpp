// Prints Bitflash's pool zero record and its ids, then builds, checks and
// parses a new pool's record. A starting point for wiring the library into a
// node or wallet.

#include "bitflash.h"

#include <cstdio>

static std::string Hex(const std::vector<uint8_t>& v)
{
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v)
    {
        s += hx[b >> 4];
        s += hx[b & 15];
    }
    return s;
}

int main()
{
    everpool::ChainParams main = bitflash::Mainnet(), test = bitflash::Testnet();
    std::string why;
    if (!everpool::check_params(main, &why))
    {
        printf("bad parameters: %s\n", why.c_str());
        return 1;
    }

    std::vector<uint8_t> zero = everpool::encode(main.pool_zero, main);
    printf("pool zero record (%u bytes): %s\n", (unsigned)zero.size(), Hex(zero).c_str());
    printf("pool zero id, mainnet: %s\n", everpool::id_hex(everpool::pool_id(zero, main.network_magic)).c_str());
    printf("pool zero id, testnet: %s\n", everpool::id_hex(everpool::pool_id(zero, test.network_magic)).c_str());

    // A new pool: 30 s shares, uncles two deep, a 1% fee to a P2SH address.
    everpool::Record r = main.pool_zero;
    r.spacing = 30;
    r.uncle_depth = 2;
    r.uncle_pct = 90;
    r.fee_bps = 100;
    r.fee_type = everpool::FEE_P2SH;
    r.fee_hash.fill(0xab);
    r.name = "example-pool";
    everpool::Status s = everpool::check(r, main);
    if (s != everpool::Status::ok)
    {
        printf("refused: %s\n", everpool::status_text(s));
        return 1;
    }
    std::vector<uint8_t> rec = everpool::encode(r, main);
    printf("new pool record (%u bytes): %s\n", (unsigned)rec.size(), Hex(rec).c_str());
    printf("new pool id, mainnet: %s\n", everpool::id_hex(everpool::pool_id(rec, main.network_magic)).c_str());

    // What a node does with an OP_RETURN output of at least bitflash::MIN_BURN.
    std::vector<uint8_t> script;
    script.reserve(2 + rec.size());
    script.push_back(0x6a);  // OP_RETURN
    script.push_back((uint8_t)rec.size());  // a direct push of the record
    for (uint8_t b : rec)
        script.push_back(b);
    everpool::Record back;
    s = everpool::parse_script(script, main, back);
    printf("read back from its OP_RETURN: %s\n", everpool::status_code(s));
    return s == everpool::Status::ok ? 0 : 1;
}
