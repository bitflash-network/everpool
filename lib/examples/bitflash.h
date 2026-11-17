// Example chain parameters: Bitflash, the reference implementation
// (SPEC.md sections 1, 2 and 4). Another chain writes its own copy of this
// file with its own magics, floor and pool zero (ADOPTING.md).

#ifndef EVERPOOL_EXAMPLES_BITFLASH_H
#define EVERPOOL_EXAMPLES_BITFLASH_H

#include "../everpool.h"

namespace bitflash
{

// Today's P2Pool share chain written as a record (SPEC.md section 4).
inline everpool::Record PoolZero()
{
    everpool::Record r;
    r.spacing = 10;
    r.window = 2160;
    r.retarget = 720;
    r.floor = 0x1f0fffff;
    r.uncle_depth = 3;
    r.uncle_pct = 80;
    r.fee_bps = 0;
    r.fee_type = everpool::FEE_NONE;
    r.name = "bitflash";
    return r;
}

inline everpool::ChainParams Params(const everpool::Magic& network_magic)
{
    everpool::ChainParams p;
    p.network_magic = network_magic;
    p.record_magic = { 'B', 'T', 'F', 'P' };
    p.has_local_magic = true;
    p.local_magic = { 'B', 'T', 'F', 'L' };
    p.network_floor = 0x1f0fffff;  // bnProofOfWorkLimit, ~uint256(0) >> 12
    p.pool_zero = PoolZero();
    return p;
}

inline everpool::ChainParams Mainnet() { return Params({ 0xbf, 0x20, 0x5c, 0xfd }); }
inline everpool::ChainParams Testnet() { return Params({ 0xce, 0xe2, 0xc0, 0xff }); }

// What a registration must burn: 1 BTF. The library leaves this check to
// the caller, who knows the output's value.
constexpr int64_t MIN_BURN = 100000000;

} // namespace bitflash

#endif
