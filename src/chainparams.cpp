// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libzerocoin/Params.h"
#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <versionbitsinfo.h>

#include <chainparamsimport.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <util/splitstring.h>

int64_t CChainParams::GetCoinYearReward(int64_t nTime) const
{
    static const int64_t nSecondsInYear = 365 * 24 * 60 * 60;

    if (strNetworkID != "regtest")
    {
        // Y1 5%, Y2 4%, Y3 3%, Y4 2%, ... YN 2%
        int64_t nYearsSinceGenesis = (nTime - genesis.nTime) / nSecondsInYear;

        if (nYearsSinceGenesis >= 0 && nYearsSinceGenesis < 3)
            return (5 - nYearsSinceGenesis) * CENT;
    };

    return nCoinYearReward;
};

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const
{
//    int64_t nSubsidy;

//    nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward(pindexPrev->nTime) / (365 * 24 * (60 * 60 / nTargetSpacing));
//    if (pindexPrev->IsProofOfWork()) {
//        return 125000 * COIN;
//    }
    int64_t nSubsidy = 0;
    if (pindexPrev->nHeight == 0) {
        nSubsidy = 125000 * COIN;
    } else if (pindexPrev->nHeight + 1 < Params().NEW_PROTOCOLS_STARTHEIGHT() && pindexPrev->nHeight + 1 > 450) {
        nSubsidy = 5 * COIN;
    } else {
        nSubsidy = 10 * COIN;
    }

    return nSubsidy + nFees;
};

bool CChainParams::CheckImportCoinbase(int nHeight, uint256 &hash) const
{
    for (auto &cth : Params().vImportedCoinbaseTxns)
    {
        if (cth.nHeight != (uint32_t)nHeight)
            continue;

        if (hash == cth.hash)
            return true;
        return error("%s - Hash mismatch at height %d: %s, expect %s.", __func__, nHeight, hash.ToString(), cth.hash.ToString());
    };

    return error("%s - Unknown height.", __func__);
};


const DevFundSettings *CChainParams::GetDevFundSettings(int64_t nTime) const
{
    for (size_t i = vDevFundSettings.size(); i-- > 0; )
    {
        if (nTime > vDevFundSettings[i].first)
            return &vDevFundSettings[i].second;
    };

    return nullptr;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const
{
    for (auto &hrp : bech32Prefixes)  {
        if (vchPrefixIn == hrp) {
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        auto &hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k)
    {
        const auto &hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0
            && slen > hrplen
            && strncmp(ps, (const char*)&hrp[0], hrplen) == 0)
        {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        };
    };

    return false;
};
libzerocoin::ZerocoinParams* CChainParams::Zerocoin_Params(bool useModulusV1) const
{
    assert(this);
    static CBigNum bnHexModulus = 0;
    if (!bnHexModulus)
        bnHexModulus.SetHex(zerocoinModulus);
    static libzerocoin::ZerocoinParams ZCParamsHex = libzerocoin::ZerocoinParams(bnHexModulus);
    static CBigNum bnDecModulus = 0;
    if (!bnDecModulus)
        bnDecModulus.SetDec(zerocoinModulus);
    static libzerocoin::ZerocoinParams ZCParamsDec = libzerocoin::ZerocoinParams(bnDecModulus);

    if (useModulusV1)
        return &ZCParamsHex;

    return &ZCParamsDec;
}
static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "I would rather be without a state than without a voice";
    const CScript genesisOutputScript = CScript() << ParseHex("0433f2952f9002c9088a19607e3d4a54d3d9dfe1cf5c78168b8ba6524fb19fc5d7d3202948e6b8b09e98c425875af6af78fd4f64ff07d97a9ae31ebda5162fbac3") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

const std::pair<const char*, CAmount> regTestOutputs[] = {
//    std::make_pair("585c2b3914d9ee51f8e710304e386531c3abcc82", 10000 * COIN),
//    std::make_pair("c33f3603ce7c46b423536f0434155dad8ee2aa1f", 10000 * COIN),
//    std::make_pair("72d83540ed1dcf28bfaca3fa2ed77100c2808825", 10000 * COIN),
//    std::make_pair("69e4cc4c219d8971a253cd5db69a0c99c4a5659d", 10000 * COIN),
//    std::make_pair("eab5ed88d97e50c87615a015771e220ab0a0991a", 10000 * COIN),
//    std::make_pair("119668a93761a34a4ba1c065794b26733975904f", 10000 * COIN),
//    std::make_pair("6da49762a4402d199d41d5778fcb69de19abbe9f", 10000 * COIN),
//    std::make_pair("27974d10ff5ba65052be7461d89ef2185acbe411", 10000 * COIN),
//    std::make_pair("89ea3129b8dbf1238b20a50211d50d462a988f61", 10000 * COIN),
//    std::make_pair("3baab5b42a409b7c6848a95dfd06ff792511d561", 10000 * COIN),
//
//    std::make_pair("649b801848cc0c32993fb39927654969a5af27b0", 5000 * COIN),
//    std::make_pair("d669de30fa30c3e64a0303cb13df12391a2f7256", 5000 * COIN),
//    std::make_pair("f0c0e3ebe4a1334ed6a5e9c1e069ef425c529934", 5000 * COIN),
//    std::make_pair("27189afe71ca423856de5f17538a069f22385422", 5000 * COIN),
//    std::make_pair("0e7f6fe0c4a5a6a9bfd18f7effdd5898b1f40b80", 5000 * COIN),
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {
//    std::make_pair("62a62c80e0b41f2857ba83eb438d5caa46e36bcb",7017084118),
//    std::make_pair("c515c636ae215ebba2a98af433a3fa6c74f84415",221897417980),
//    std::make_pair("711b5e1fd0b0f4cdf92cb53b00061ef742dda4fb",120499999),
//    std::make_pair("20c17c53337d80408e0b488b5af7781320a0a311",18074999),
//    std::make_pair("aba8c6f8dbcf4ecfb598e3c08e12321d884bfe0b",92637054909),
//    std::make_pair("1f3277a84a18f822171d720f0132f698bcc370ca",3100771006662),
//    std::make_pair("8fff14bea695ffa6c8754a3e7d518f8c53c3979a",465115650998),
//    std::make_pair("e54967b4067d91a777587c9f54ee36dd9f1947c4",669097504996),
//    std::make_pair("7744d2ac08f2e1d108b215935215a4e66d0262d2",802917005996),
//    std::make_pair("a55a17e86246ea21cb883c12c709476a09b4885c",267639001997),
//    std::make_pair("4e00dce8ab44fd4cafa34839edf8f68ba7839881",267639001997),
//    std::make_pair("702cae5d2537bfdd5673ac986f910d6adb23510a",254257051898),
//    std::make_pair("b19e494b0033c5608a7d153e57d7fdf3dfb51bb7",1204260290404),
//    std::make_pair("6909b0f1c94ea1979ed76e10a5a49ec795a8f498",1204270995964),
//    std::make_pair("05a06af3b29dade9f304244d934381ac495646c1",236896901156),
//    std::make_pair("557e2b3205719931e22853b27920d2ebd6147531",155127107700),
//    std::make_pair("ad16fb301bd21c60c5cb580b322aa2c61b6c5df2",115374999),
//    std::make_pair("182c5cfb9d17aa8d8ff78940135ca8d822022f32",17306249),
//    std::make_pair("b8a374a75f6d44a0bd1bf052da014efe564ae412",133819500998),
//    std::make_pair("fadee7e2878172dad55068c8696621b1788dccb3",133713917412),
//    std::make_pair("eacc4b108c28ed73b111ff149909aacffd2cdf78",173382671567),
//    std::make_pair("dd87cc0b8e0fc119061f33f161104ce691d23657",245040727620),
//    std::make_pair("1c8b0435eda1d489e9f0a16d3b9d65182f885377",200226012806),
//    std::make_pair("15a724f2bc643041cb35c9475cd67b897d62ca52",436119839355),
//    std::make_pair("626f86e9033026be7afbb2b9dbe4972ef4b3e085",156118097804),
//    std::make_pair("a4a73d99269639541cb7e845a4c6ef3e3911fcd6",108968353176),
//    std::make_pair("27929b31f11471aa4b77ca74bb66409ff76d24a2",126271503135),
//    std::make_pair("2d6248888c7f72cc88e4883e4afd1025c43a7f0e",35102718156),
//    std::make_pair("25d8debc253f5c3f70010f41c53348ed156e7baa",80306152234),
};
const size_t nGenesisOutputs = sizeof(genesisOutputs) / sizeof(genesisOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputsTestnet[] = {
//    std::make_pair("46a064688dc7beb5f70ef83569a0f15c7abf4f28",7017084118),
//    std::make_pair("9c97b561ac186bd3758bf690036296d36b1fd019",221897417980),
//    std::make_pair("118a92e28242a73244fb03c96b7e1429c06f979f",120499999),
//    std::make_pair("cae4bf990ce39624e2f77c140c543d4b15428ce7",18074999),
//    std::make_pair("9d6b7b5874afc100eb82a4883441a73b99d9c306",92637054909),
//    std::make_pair("f989e2deedb1f09ed10310fc0d7da7ebfb573326",3100771006662),
//    std::make_pair("4688d6701fb4ae2893d3ec806e6af966faf67545",465115650998),
//    std::make_pair("40e07b038941fb2616a54a498f763abae6d4f280",669097504996),
//    std::make_pair("c43f7c57448805a068a440cc51f67379ca946264",802917005996),
//    std::make_pair("98b7269dbf0c2e3344fb41cd60e75db16d6743a6",267639001997),
//    std::make_pair("85dceec8cdbb9e24fe07af783e4d273d1ae39f75",267639001997),
//    std::make_pair("ddc05d332b7d1a18a55509f34c786ccb65bbffbc",245040727620),
//    std::make_pair("8b04d0b2b582c986975414a01cb6295f1c33d0e9",1204260290404),
//    std::make_pair("1e9ff4c3ac6d0372963e92a13f1e47409eb62d37",1204270995964),
//    std::make_pair("687e7cf063cd106c6098f002fa1ea91d8aee302a",236896901156),
//    std::make_pair("dc0be0edcadd4cc97872db40bb8c2db2cebafd1c",155127107700),
//    std::make_pair("21efcbfe37045648180ac68b406794bde77f9983",115374999),
//    std::make_pair("deaf53dbfbc799eed1171269e84c733dec22f517",17306249),
//    std::make_pair("200a0f9dba25e00ea84a4a3a43a7ea6983719d71",133819500998),
//    std::make_pair("2d072fb1a9d1f7dd8df0443e37e9f942eab58680",133713917412),
//    std::make_pair("0850f3b7caf3b822bb41b9619f8edf9b277402d0",173382671567),
//    std::make_pair("ec62fbd782bf6f48e52eea75a3c68a4c3ab824c0",254257051898),
//    std::make_pair("c6dcb0065e98f5edda771c594265d61e38cf63a0",200226012806),
//    std::make_pair("e5f9a711ccd7cb0d2a70f9710229d0d0d7ef3bda",436119839355),
//    std::make_pair("cae1527d24a91470aeb796f9d024630f301752ef",156118097804),
//    std::make_pair("604f36860d79a9d72b827c99409118bfe16711bd",108968353176),
//    std::make_pair("f02e5891cef35c9c5d9a770756b240aba5ba3639",126271503135),
//    std::make_pair("8251b4983be1027a17dc3b977502086f08ba8910",35102718156),
//    std::make_pair("b991d98acde28455ecb0193fefab06841187c4e7",80306152234),
};
const size_t nGenesisOutputsTestnet = sizeof(genesisOutputsTestnet) / sizeof(genesisOutputsTestnet[0]);


static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char* pszTimestamp = "I would rather be without a state than without a voice";

    CMutableTransaction txNew;
//    txNew.nVersion = 1;
    txNew.nTime = nTime;
    txNew.nLockTime = 0;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
//    txNew.SetType(TXN_COINBASE);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << nHeight;
    txNew.vout[0].SetEmpty();

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);


    return genesis;
}

static CBlock CreateGenesisBlockTestNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char* pszTimestamp = "I would rather be without a state than without a voice";

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = nTime;
    txNew.nLockTime = 0;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    uint32_t nHeight = 0;  // bip34

//    txNew.SetType(TXN_COINBASE);
//    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockMainNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char* pszTimestamp = "I would rather be without a state than without a voice";

    uint32_t nHeight = 0;  // bip34
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = nTime;
    txNew.nLockTime = 0;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = 125000 * COIN;
    txNew.vout[0].scriptPubKey = CScript() << ParseHex("0433f2952f9002c9088a19607e3d4a54d3d9dfe1cf5c78168b8ba6524fb19fc5d7d3202948e6b8b09e98c425875af6af78fd4f64ff07d97a9ae31ebda5162fbac3") << OP_CHECKSIG;
//    txNew.SetType(TXN_COINBASE);

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 1;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}


/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 0;
        consensus.BIP34Height = 500000;
        consensus.BIP65Height = 500000;
        consensus.BIP66Height = 500000;
        consensus.OpIsCoinstakeTime = 1539963322; // 2017-11-10 00:00:00 UTC
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0x3AFE130E00; // 9999 TODO: lower
        consensus.csp2shHeight = 0x7FFFFFFF;
//        consensus.powLimit = uint256S("000000000000bfffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = ~uint256(0) >> 16;

        consensus.nPowTargetTimespan = 16 * 60; // two weeks
        consensus.nPowTargetSpacing = 64;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 14; // 95% of 2016
        consensus.nMinerConfirmationWindow = 15; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1539963322; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1539963322; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1539963322; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1539963322; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1539963322; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1539963322; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000088a0e852d98f1e3e41");

        // By default assume that the signatures in ancestors of this block are valid.
//        consensus.defaultAssumeValid = uint256S("0xcf86529d0243cb653da92cbbaddc7f0a4f275bcf557cc112d03c33b756af25d3"); //400000

        consensus.nMinRCTOutputDepth = 12;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x20;
        pchMessageStart[1] = 0x45;
        pchMessageStart[2] = 0x12;
        pchMessageStart[3] = 0x77;
        nDefaultPort = 17000;
        nBIP44ID = 0x8000002C;
        bnProofOfWorkLimit = ~uint256(0) >> 16; // WISPR starting difficulty is 1 / 2^12
        bnProofOfStakeLimit = ~uint256(0) >> 48;
        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 100;   // 225 * 2 minutes

        nTargetTimespanV1 =  16 * 60; // WISPR Old: 1 day
        nTargetTimespanV2 =  1 * 60; // WISPR New: 1 day
        nTargetTimespan = 16 * 60;      // 24 mins
        nTargetSpacingV1 = 64;  // WISPR Old: 1 minute
        nTargetSpacingV2 = 1 * 60;  // WISPR New: 1 minute
        nTargetSpacing = 64;           // 2 minutes

        AddImportHashesMain(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 500000;

        genesis = CreateGenesisBlockMainNet(1513403825, 36156, bnProofOfWorkLimit.GetCompact()); // 2017-07-17 13:00:00
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000ec93e0a3fe0aafa3be7dafe1290f5fca039a4037dd5174bc3dd7a35d67f0"));
        assert(genesis.hashMerkleRoot == uint256S("0xbcd0064f46daed0b3c1ccff16656a0da04b5509924118b7c13d21c81d62ec521"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
//        vSeeds.emplace_back("mainnet-seed.wispr.io");
//        vSeeds.emplace_back("dnsseed-mainnet.wispr.io");
//        vSeeds.emplace_back("mainnet.wispr.io");


//        vDevFundSettings.emplace_back(0,
//            DevFundSettings("RJAPhgckEgRGVPZa9WoGSWW24spskSfLTQ", 10, 60));
//        vDevFundSettings.emplace_back(consensus.OpIsCoinstakeTime,
//            DevFundSettings("RBiiQBnQsVPPQkUaJVQTjsZM9K2xMKozST", 10, 60));
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 73);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 135);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 145);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04,0x88,0xAD,0xE4};
        base58Prefixes[EXT_COIN_TYPE] = {0x80,0x00,0x00,0x77};
        base58Prefixes[PUBKEY_ADDRESS_256] = std::vector<unsigned char>(1, 73);
        base58Prefixes[SCRIPT_ADDRESS_256] = std::vector<unsigned char>(1, 135);

//        base58Prefixes[PUBKEY_ADDRESS]     = {0x49}; // P
//        base58Prefixes[SCRIPT_ADDRESS]     = {0x87};
//        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
//        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
//        base58Prefixes[SECRET_KEY]         = {0x91};
//        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04, 0x88, 0xB2, 0x1E}; // PPAR
//        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0xAD, 0xE4}; // XPAR
//        base58Prefixes[EXT_COIN_TYPE]     =  {0x80, 0x00, 0x00, 0x77}; // XPAR
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

//        bech32Prefixes[PUBKEY_ADDRESS].assign       ("ph","ph"+2);
//        bech32Prefixes[SCRIPT_ADDRESS].assign       ("pr","pr"+2);
//        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("pl","pl"+2);
//        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("pj","pj"+2);
//        bech32Prefixes[SECRET_KEY].assign           ("px","px"+2);
//        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("pep","pep"+3);
//        bech32Prefixes[EXT_SECRET_KEY].assign       ("pex","pex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ps","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("pek","pek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("pea","pea"+3);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("pcs","pcs"+3);

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        //DASH
        consensus.nMasternodePaymentsStartBlock = 400000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 400000;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 400000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 400000; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256S("00000000cffabc0f646867fba0550afd6e30e0f4b0fc54e34d3e101a1552df5d");
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.lastPowBlock = 450;
        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        nMaxMoneyOut = 120000000 * COIN;

        strSporkAddress = "Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh";
        //!WISPR
        /** Height or Time Based Activations **/
        nLastPOWBlock = 450;
        nNewProtocolStartHeight = 400000;
        nNewProtocolStartTime = 1539963322; //Friday, October 19, 2018 3:35:22 PM
        nZerocoinStartHeight = nNewProtocolStartHeight;
        nZerocoinStartTime = nNewProtocolStartTime;
        /** Zerocoin */
        zerocoinModulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                          "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                          "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                          "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                          "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                          "31438167899885040445364023527381951378636564391212010397122822120720357";
        nMaxZerocoinSpendsPerTransaction = 7; // Assume about 20kb each
        nMinZerocoinMintFee = 1 * CENT; //high fee required for zerocoin mints
        nMintRequiredConfirmations = 20; //the maximum amount of confirmations until accumulated in 19
        nRequiredAccumulation = 1;
        nDefaultSecurityLevel = 100; //full security level for accumulators
        nZerocoinHeaderVersion = 8; //Block headers must be this version once zerocoin is active
        nZerocoinRequiredStakeDepth = 200; //The required confirmations for a zwsp to be stakable

        checkpointData = {
            {
                {0, uint256S("0x0000ec93e0a3fe0aafa3be7dafe1290f5fca039a4037dd5174bc3dd7a35d67f0")},
                {14317, uint256S("0x50929653a7146de37b82b9125e55ea03aa4ae062ce3a2e3098026eea07e5bc81")}, // 125.000 Coin Burn Confirmation
                {50000, uint256S("0xb177127054381243141e809bbfb2d568aeae2dd9b3c486e54f0989d4546d0d80")}, // Block 50.000
                {75000, uint256S("06f162fe22851c400c1532a6d49d7894640ea0aa292fad5f02f348480da6b20d")}, // Block 75.000
                {100000, uint256S("ed8cccfb51c901af271892966160686177a05f101bd3fd517d5b82274a8f6611")}, // Block 100.000
                {125000, uint256S("76d5412ec389433de6cd22345209c859b4c18b6d8f8893df479c9f7520d19901")}, // Block 125.000
                {150000, uint256S("a7e0dfdc9c3197e9e763e858aafa9553c0235c0e328371a5f8c5ba0b6e44919d")}, // Block 150.000
                {200000, uint256S("385e915b52f0ad669b91005ab7ddb22356b6a220e8b98cbcf2c8aca5c5dd3b03")}, // Block 200.000
                {250000, uint256S("40ee22bd8b2cc23f83e16d19a53aa8591617772f9722c56b86d16163b2a10416")}, // Block 250.000
                {300000, uint256S("700c33f9bf03c018f33167c2c455f05762b49e1f1f06e14833a5e8e269beebe7")}, // Block 300.000
                    {350000, uint256S("ffb49991aa635992305029cb629037cf5d08e945d2027c79f4f737c11e7d680e")}, // Block 350.000
                    {400000, uint256S("cf86529d0243cb653da92cbbaddc7f0a4f275bcf557cc112d03c33b756af25d3")}, // Block 400.000
            }
        };

        chainTxData = ChainTxData {
            // Data from rpc: getchaintxstats 4096 7cc035d7888ee6d824cec8ff01a6287a71873d874f72a5fd3706d227b88f8e99
            /* nTime    */ 1540087953,
            /* nTxCount */ 815060,
            /* dTxRate  */ 2000
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }

    void SetOld()
    {
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 500000;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 500000; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 500000; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        genesis = CreateGenesisBlock(1513403825, 36156, bnProofOfWorkLimit.GetCompact(), 1, 125000); // 2017-07-17 13:00:00

        consensus.hashGenesisBlock = genesis.GetHash();
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 73);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 135);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 145);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04,0x88,0xAD,0xE4};
        base58Prefixes[EXT_COIN_TYPE] = {0x80,0x00,0x00,0x77};
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 0;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = true; // TODO: clear for next testnet
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shHeight = 0x7FFFFFFF;

        consensus.powLimit = uint256S("000000000005ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x000000000871ee6842d3648317ccc8a435eb8cc3c2429aee94faff9ba26b05a0"); //1043841

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x21;
        pchMessageStart[1] = 0x46;
        pchMessageStart[2] = 0x13;
        pchMessageStart[3] = 0x78;
        nDefaultPort = 17002;
        nBIP44ID = 0x80000001;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 100;   // 225 * 2 minutes
//        nTargetSpacing = 120;           // 2 minutes
//        nTargetTimespan = 24 * 60;      // 24 mins


        AddImportHashesTest(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 1000;

        bnProofOfWorkLimit = ~uint256(0) >> 16; // WISPR starting difficulty is 1 / 2^12
        bnProofOfStakeLimit = ~uint256(0) >> 48;
        genesis = CreateGenesisBlockTestNet(1512932225, 142000, bnProofOfWorkLimit.GetCompact());
        consensus.hashGenesisBlock = genesis.GetHash();

//        printf("Test net block\n");
//        printf("Genesis hash = %s\n", consensus.hashGenesisBlock.ToString());
//        printf("Genesis merkle = %s\n", genesis.hashMerkleRoot.ToString());
//        printf("Genesis hash = %s\n", genesis.hashWitnessMerkleRoot.ToString());
//        printf("Genesis = %s\n", genesis.ToString().c_str());

        assert(consensus.hashGenesisBlock == uint256S("0x03205c57ebefb02d86c2c0c2de368fa48e92f7df7240f1b528ebbeae70fdbdb1"));
        assert(genesis.hashMerkleRoot == uint256S("0x26069b04c7c7b5b8773824b15cfbf0ddaf11ee261657a1aeb28aa5c8163909ee"));

//        assert(genesis.hashWitnessMerkleRoot == uint256S("0xf9e2235c9531d5a19263ece36e82c4d5b71910d73cd0b677b81c5e50d17b6cda"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.wispr.io");
        vSeeds.emplace_back("dnsseed-testnet.wispr.io");

//        vDevFundSettings.push_back(std::make_pair(0, DevFundSettings("rTvv9vsbu269mjYYEecPYinDG8Bt7D86qD", 10, 60)));

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, uint256S("0x03205c57ebefb02d86c2c0c2de368fa48e92f7df7240f1b528ebbeae70fdbdb1")},
                {210920, uint256S("0x5534f546c3b5a264ca034703b9694fabf36d749d66e0659eef5f0734479b9802")},
                {259290, uint256S("0x58267bdf935a2e0716cb910d055b8cdaa019089a5f71c3db90765dc7101dc5dc")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 58267bdf935a2e0716cb910d055b8cdaa019089a5f71c3db90765dc7101dc5dc
            /* nTime    */ 1512932225,
            /* nTxCount */ 0,
            /* dTxRate  */ 450
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 0;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shHeight = 0;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 1;

        pchMessageStart[0] = 0xFF;
        pchMessageStart[1] = 0xAF;
        pchMessageStart[2] = 0xB7;
        pchMessageStart[3] = 0xDF;
        nDefaultPort = 17004;
        nBIP44ID = 0x80000001;


        nModifierInterval = 2 * 60;     // 2 minutes
        nStakeMinConfirmations = 12;
        nTargetTimespanV1 = 16 * 60; // WISPR Old: 1 day
        nTargetTimespanV2 = 1 * 60; // WISPR New: 1 day
        nTargetSpacingV1 = 64;        // WISPR Old: 1 minutes
        nTargetSpacingV2 = 1 * 60;        // WISPR New: 1 minute
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        nTargetSpacing = 5;             // 5 seconds
        nTargetTimespan = 16 * 60;      // 16 mins
        nStakeTimestampMask = 0;

        SetLastImportHeight();

        nPruneAfterHeight = 1000;

        UpdateVersionBitsParametersFromArgs(args);

//        printf("Create reg net block\n");
        genesis = CreateGenesisBlockRegTest(1411111111, 2, bnProofOfWorkLimit.GetCompact());

        consensus.hashGenesisBlock = genesis.GetHash();

//        printf("Regression net block\n");
//        printf("Genesis = %s\n", genesis.ToString().c_str());

//        assert(consensus.hashGenesisBlock == uint256S("0x33a525cad9e251b88c6b9882a431bd7c3cecec59bb61d745c76ea919d8335039"));
//        assert(genesis.hashMerkleRoot == uint256S("0x529915432b67f7a86f0fd19d15ea1ba0c0bccb4a159e6d6f56c08530a70bfb4b"));
//        assert(genesis.hashWitnessMerkleRoot == uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "bcrt";

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    void SetOld()
    {
        genesis = CreateGenesisBlock(1411111111, 2, bnProofOfWorkLimit.GetCompact(), 1, 125000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        pchMessageStart[0] = 0xFF;
        pchMessageStart[1] = 0xAF;
        pchMessageStart[2] = 0xB7;
        pchMessageStart[3] = 0xDF;

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 110);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 8);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04,0x35,0x83,0x94};
        base58Prefixes[EXT_COIN_TYPE] = {0x80,0x00,0x00,0x01};
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        Split(vDeploymentParams, strDeployment, ":");
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams *pParams() {
    return globalChainParams.get();
};

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}


void SetOldParams(std::unique_ptr<CChainParams> &params)
{
    if (params->NetworkID() == CBaseChainParams::MAIN) {
        return ((CMainParams*)params.get())->SetOld();
    }
    if (params->NetworkID() == CBaseChainParams::REGTEST) {
        return ((CRegTestParams*)params.get())->SetOld();
    }
};

void ResetParams(std::string sNetworkId, bool fWisprModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fWisprModeIn) {
        SetOldParams(globalChainParams);
    }
};

/**
 * Mutable handle to regtest params
 */
CChainParams &RegtestParams()
{
    return *globalChainParams.get();
};
