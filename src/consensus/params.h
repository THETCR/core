// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_CONSENSUS_PARAMS_H

#include "uint256.h"
#include "amount.h"


namespace Consensus {
/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Used to check majorities for block version upgrade */
    int nEnforceBlockUpgradeMajority;
    int nRejectBlockOutdatedMajority;
    int nToCheckBlockUpgradeMajority;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fAllowMinDifficultyBlocks;

  int nMaxReorganizationDepth;
  int64_t nTargetTimespanV1;
  int64_t nTargetTimespanV2;
  int64_t nTargetSpacingV1;
  int64_t nTargetSpacingV2;
  int nLastPOWBlock;
  int nMasternodeCountDrift;
  int nMaturity;
  CAmount nMaxMoneyOut;
  bool fSkipProofOfWorkCheck;
  int nPoolMaxTransactions;
  std::string strSporkKey;
  std::string strObfuscationPoolDummyAddress;
  int64_t nStartMasternodePayments;
  std::string zerocoinModulus;
  int nMaxZerocoinSpendsPerTransaction;
  CAmount nMinZerocoinMintFee;
  int nMintRequiredConfirmations;
  int nRequiredAccumulation;
  int nDefaultSecurityLevel;
  int nZerocoinHeaderVersion;
  int64_t nBudget_Fee_Confirmations;
  int nZerocoinStartHeight;
  int nNewProtocolStartHeight;

  int nZerocoinStartTime;
  int nNewProtocolStartTime;
  int nZerocoinRequiredStakeDepth;
  uint256 stakeLimit;
  uint256 nMinimumChainWork;
  uint256 defaultAssumeValid;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_CONSENSUS_PARAMS_H
