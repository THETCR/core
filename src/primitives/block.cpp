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

#define CVOIDBEGIN(a)        ((const void*)&(a))

uint256 CBlockHeader::GetHash() const
{
    if(nVersion > 7){
        return Hash(BEGIN(nVersion), END(nAccumulatorCheckpoint));
    } else if ( nVersion == 7 ) {
        return  Hash(BEGIN(nVersion), END(nNonce));
    } else {
        return GetPoWHash();
    }
}

uint256 CBlockHeader::GetPoWHash() const
{
    return scrypt_blockhash(CVOIDBEGIN(nVersion));
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
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}

bool CBlock::IsZerocoinStake() const
{
    return IsProofOfStake() && vtx[1].IsZerocoinSpend();
}