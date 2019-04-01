// Copyright (c) 2017-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WISPR_ACCUMULATORS_H
#define WISPR_ACCUMULATORS_H

#include "libzerocoin/Accumulator.h"
#include "libzerocoin/Coin.h"
#include "libzerocoin/Denominations.h"
#include "zpiv/zerocoin.h"
#include <zpiv/accumulatormap.h>
#include "chain.h"
#include "uint256.h"
#include "bloom.h"

class CBlockIndex;

std::map<libzerocoin::CoinDenomination, int> GetMintMaturityHeight();

/**
 * Calculate the acc witness for a single coin.
 * @return true if the witness was calculated well
 */
bool GenerateAccumulatorWitness(const libzerocoin::PublicCoin &coin,
                                libzerocoin::Accumulator& accumulator,
                                libzerocoin::AccumulatorWitness& witness,
                                int nSecurityLevel,
                                int& nMintsAdded,
                                std::string& strError,
                                CBlockIndex* pindexCheckpoint = nullptr
                                        );

bool CalculateAccumulatorWitnessFor(
        const libzerocoin::ZerocoinParams* params,
        int startingHeight,
        int maxCalculationRange,
        libzerocoin::CoinDenomination den,
        const CBloomFilter& filter,
        libzerocoin::Accumulator& accumulator,
        libzerocoin::AccumulatorWitness& witness,
        int nSecurityLevel,
        int& nMintsAdded,
        std::string& strError,
        std::list<CBigNum>& ret,
        int &heightStop
);


std::list<libzerocoin::PublicCoin> GetPubcoinFromBlock(const CBlockIndex* pindex);
bool GetAccumulatorValueFromDB(uint256 nCheckpoint, libzerocoin::CoinDenomination denom, CBigNum& bnAccValue);
bool GetAccumulatorValue(int& nHeight, const libzerocoin::CoinDenomination denom, CBigNum& bnAccValue);
bool GetAccumulatorValueFromChecksum(uint32_t nChecksum, bool fMemoryOnly, CBigNum& bnAccValue);
void AddAccumulatorChecksum(const uint32_t nChecksum, const CBigNum &bnValue, bool fMemoryOnly);
bool CalculateAccumulatorCheckpoint(int nHeight, uint256& nCheckpoint, AccumulatorMap& mapAccumulators);
void DatabaseChecksums(AccumulatorMap& mapAccumulators);
bool LoadAccumulatorValuesFromDB(const uint256 nCheckpoint);
bool EraseAccumulatorValues(const uint256& nCheckpointErase, const uint256& nCheckpointPrevious);
uint32_t ParseChecksum(uint256 nChecksum, libzerocoin::CoinDenomination denomination);
uint32_t GetChecksum(const CBigNum &bnValue);
int GetChecksumHeight(uint32_t nChecksum, libzerocoin::CoinDenomination denomination);
bool InvalidCheckpointRange(int nHeight);
bool ValidateAccumulatorCheckpoint(const CBlock& block, CBlockIndex* pindex, AccumulatorMap& mapAccumulators);


// Exceptions

class NotEnoughMintsException : public std::exception {
public:
    std::string message;
    NotEnoughMintsException(const std::string &message) : message(message) {}
};

class GetPubcoinException : public std::exception {
public:
    std::string message;
    GetPubcoinException(const std::string &message) : message(message) {}
};

class ChecksumInDbNotFoundException : public std::exception {
public:
    std::string message;
    ChecksumInDbNotFoundException(const std::string &message) : message(message) {}
};

class searchMintHeightException : public std::exception {
public:
    std::string message;
    searchMintHeightException(const std::string &message) : message(message) {}
};

#endif //WISPR_ACCUMULATORS_H
