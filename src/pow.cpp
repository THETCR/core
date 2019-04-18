// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

#include "chainparams.h"
#include <util/system.h>

#include <math.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    /* current difficulty formula, wispr - DarkGravity v3, written by Evan Duffield - evan@dashpay.io */
    int nHeight = pindexLast->nHeight;
    uint256 PastDifficultyAverage;
    uint256 PastDifficultyAveragePrev;

//    if (BlockLastSolved == nullptr || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) {
//        return params.powLimit.GetCompact();
//    }

    if (nHeight > params.nLastPOWBlock) {
        uint256 bnTargetLimit = (~uint256(0) >> 24);
        int64_t nTargetSpacing = 60;
        int64_t nTargetTimespan = 60 * 40;

        int64_t nActualSpacing = 0;
        if (pindexLast->nHeight != 0)
            nActualSpacing = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();

        if (nActualSpacing < 0)
            nActualSpacing = 1;

        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        uint256 bnNew;
        bnNew.SetCompact(pindexLast->nBits);

        int64_t nInterval = nTargetTimespan / nTargetSpacing;
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);

        if (bnNew <= 0 || bnNew > bnTargetLimit)
            bnNew = bnTargetLimit;

        return bnNew.GetCompact();
    }

    unsigned int nProofOfWorkLimit = params.powLimit.GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nTargetSpacingV2*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

//unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
//{
//    assert(pindexLast != nullptr);
//    unsigned int nProofOfWorkLimit = params.powLimit.GetCompact();
//
//    // Only change once per difficulty adjustment interval
//    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
//    {
//        if (params.fPowAllowMinDifficultyBlocks)
//        {
//            // Special difficulty rule for testnet:
//            // If the new block's timestamp is more than 2* 10 minutes
//            // then allow mining of a min-difficulty block.
//            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nTargetSpacingV2*2)
//                return nProofOfWorkLimit;
//            else
//            {
//                // Return the last non-special-min-difficulty-rules-block
//                const CBlockIndex* pindex = pindexLast;
//                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
//                    pindex = pindex->pprev;
//                return pindex->nBits;
//            }
//        }
//        return pindexLast->nBits;
//    }
//
//    // Go back by what we want to be 14 days worth of blocks
//    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
//    assert(nHeightFirst >= 0);
//    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
//    assert(pindexFirst);
//
//    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
//}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nTargetTimespanV2/3)
        nActualTimespan = params.nTargetTimespanV2/3;
    if (nActualTimespan > params.nTargetTimespanV2*3)
        nActualTimespan = params.nTargetTimespanV2*3;

    // Retarget
    const uint256 bnPowLimit = params.powLimit;
    uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nTargetTimespanV2;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake) {
    uint256 bnTargetLimit = fProofOfStake ? Params().ProofOfStakeLimit() : Params().ProofOfWorkLimit();

    if (Params().GetConsensus().fAllowMinDifficultyBlocks)
    {
            return bnTargetLimit.GetCompact();
    }

    if (pindexLast == nullptr)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex *pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == nullptr)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex *pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == nullptr)
        return bnTargetLimit.GetCompact(); // second block
    int64_t nTargetTimespan = Params().TargetTimespanV1();
    int64_t nTargetSpacing = Params().TargetSpacingV1();
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    if (nActualSpacing < 0)
        nActualSpacing = nTargetSpacing;
    if (nActualSpacing > nTargetSpacing * 10)
        nActualSpacing = nTargetSpacing * 10;

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    if (params.fSkipProofOfWorkCheck){
        return true;
    }

    if(hash == params.hashGenesisBlock){
        return true;
    }

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > params.powLimit){
        return false;
    }

    // Check proof of work matches claimed amount
    if (hash > bnTarget){
        return false;
    }

    return true;
}
