// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/scrypt.h>

uint256 CBlockHeader::GetHash() const
{
    if(nVersion > 7){
        return Hash(UintToUCharBegin(nVersion), nAccumulatorCheckpoint.end());
    } else if ( nVersion == 7 ) {
        return  Hash(UintToCharBegin(nVersion), UintToCharEnd(nNonce));
    } else {
        return GetPoWHash();
    }
}

uint256 CBlockHeader::GetPoWHash() const
{
    return scrypt_blockhash(((const void*)&(nVersion)));
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

bool CBlock::IsZerocoinStake() const
{
    return IsProofOfStake() && vtx[1]->IsZerocoinSpend();
}