// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018 The WISPR developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libzerocoin/Params.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include <tinyformat.h>
#include <util/system.h>
#include "util/strencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;

#include "chainparamsseeds.h"

/**
 * Main network
 */

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
                (0, uint256("0x0000ec93e0a3fe0aafa3be7dafe1290f5fca039a4037dd5174bc3dd7a35d67f0"))
                (14317, uint256("0x50929653a7146de37b82b9125e55ea03aa4ae062ce3a2e3098026eea07e5bc81")) // 125.000 Coin Burn Confirmation
                (50000, uint256("0xb177127054381243141e809bbfb2d568aeae2dd9b3c486e54f0989d4546d0d80")) // Block 50.000
                (75000, uint256("06f162fe22851c400c1532a6d49d7894640ea0aa292fad5f02f348480da6b20d")) // Block 75.000
                (100000, uint256("ed8cccfb51c901af271892966160686177a05f101bd3fd517d5b82274a8f6611")) // Block 100.000
                (125000, uint256("76d5412ec389433de6cd22345209c859b4c18b6d8f8893df479c9f7520d19901")) // Block 125.000
                (150000, uint256("a7e0dfdc9c3197e9e763e858aafa9553c0235c0e328371a5f8c5ba0b6e44919d")) // Block 150.000
                (200000, uint256("385e915b52f0ad669b91005ab7ddb22356b6a220e8b98cbcf2c8aca5c5dd3b03")) // Block 200.000
                (250000, uint256("40ee22bd8b2cc23f83e16d19a53aa8591617772f9722c56b86d16163b2a10416")) // Block 250.000
                (300000, uint256("700c33f9bf03c018f33167c2c455f05762b49e1f1f06e14833a5e8e269beebe7")) // Block 300.000
                (350000, uint256("ffb49991aa635992305029cb629037cf5d08e945d2027c79f4f737c11e7d680e")) // Block 350.000
                (400000, uint256("cf86529d0243cb653da92cbbaddc7f0a4f275bcf557cc112d03c33b756af25d3")); // Block 400.000
static const Checkpoints::CCheckpointData data = {
        mapCheckpoints,
        1540087953, // * UNIX timestamp of last checkpoint block (Done)
        815060,    // * total number of transactions between genesis and last checkpoint TODO: keep using correct number
        //   (the tx=... number in the SetBestChain debug.log lines)
        2000        // * estimated number of transactions per day after checkpoint
};


static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {
        mapCheckpointsTestnet,
        1512932225,
        0,
        450};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
        mapCheckpointsRegtest,
        1411111111,
        0,
        100};

libzerocoin::ZerocoinParams* CChainParams::Zerocoin_Params(bool useModulusV1) const
{
    assert(this);
    static CBigNum bnHexModulus = 0;
    if (!bnHexModulus)
        bnHexModulus.SetHex(consensus.zerocoinModulus);
    static libzerocoin::ZerocoinParams ZCParamsHex = libzerocoin::ZerocoinParams(bnHexModulus);
    static CBigNum bnDecModulus = 0;
    if (!bnDecModulus)
        bnDecModulus.SetDec(consensus.zerocoinModulus);
    static libzerocoin::ZerocoinParams ZCParamsDec = libzerocoin::ZerocoinParams(bnDecModulus);

    if (useModulusV1)
        return &ZCParamsHex;

    return &ZCParamsDec;
}

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 0;
        consensus.nEnforceBlockUpgradeMajority = 750;
        consensus.nRejectBlockOutdatedMajority = 950;
        consensus.nToCheckBlockUpgradeMajority = 1000;
        consensus.nMaxReorganizationDepth = 500;
        consensus.powLimit = ~uint256(0) >> 16; // WISPR starting difficulty is 1 / 2^12
        consensus.stakeLimit = ~uint256(0) >> 48;
        consensus.nTargetTimespanV1 =  16 * 60; // WISPR Old: 1 day
        consensus.nTargetTimespanV2 =  1 * 60; // WISPR New: 1 day
        consensus.nTargetSpacingV1 = 64;  // WISPR Old: 1 minute
        consensus.nTargetSpacingV2 = 1 * 60;  // WISPR New: 1 minute
        consensus.nMaturity = 100;
        consensus.nMasternodeCountDrift = 20;
        consensus.nMaxMoneyOut = 120000000 * COIN;
        consensus.fAllowMinDifficultyBlocks = false;
        /** Height or Time Based Activations **/
        consensus.nLastPOWBlock = 450;
        consensus.nNewProtocolStartHeight = 400000;
        consensus.nNewProtocolStartTime = 1539963322; //Friday, October 19, 2018 3:35:22 PM
        consensus.nZerocoinStartHeight = consensus.nNewProtocolStartHeight;
        consensus.nZerocoinStartTime = consensus.nNewProtocolStartTime;

        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1556638704; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1556638704; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1556638704; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1556638704; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1556638704; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1556638704; // November 15th, 2017.

        /**
         * The message start std::string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x20;
        pchMessageStart[1] = 0x45;
        pchMessageStart[2] = 0x12;
        pchMessageStart[3] = 0x77;
        vAlertPubKey=ParseHex("0411f84b889c61c1842ec84a15e3093d7dd99d955ab797b24c984cdcfe3aca23f04ec06bd840e8093aaf83488c039027ecc4ad704261245be30289be166f667c61");
        nDefaultPort = 17000;
        nPruneAfterHeight = 600000;
        nMinerThreads = 0;

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
         *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
         *   vMerkleTree: e0028e
         */
        const char* pszTimestamp = "I would rather be without a state than without a voice";
        CMutableTransaction txNew;
        txNew.nVersion = 1;
        txNew.nTime = 1513403825;
        txNew.nLockTime = 0;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 125000 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0433f2952f9002c9088a19607e3d4a54d3d9dfe1cf5c78168b8ba6524fb19fc5d7d3202948e6b8b09e98c425875af6af78fd4f64ff07d97a9ae31ebda5162fbac3") << OP_CHECKSIG;
        genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.nVersion = 1;
        genesis.nTime = 1513403825;
        genesis.nBits = consensus.powLimit.GetCompact();
        genesis.nNonce = 36156;

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("0x0000ec93e0a3fe0aafa3be7dafe1290f5fca039a4037dd5174bc3dd7a35d67f0"));
        assert(genesis.hashMerkleRoot == uint256("0xbcd0064f46daed0b3c1ccff16656a0da04b5509924118b7c13d21c81d62ec521"));

        vSeeds.emplace_back("dnsseed.wispr.tech");     // Primary DNS Seeder for wispr
        vSeeds.emplace_back("main.wispr-seeds.nl");     // Secondary DNS Seeder for wispr

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 73);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 135);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 145);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x77).convert_to_container<std::vector<unsigned char> >();

        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
//        base58Prefixes[EXT_COIN_TYPE] = {0x80, 0x00, 0x00, 0x77};
        bech32_hrp = "wr";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fDefaultCheckMemPool = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        consensus.fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = true;

        consensus.nPoolMaxTransactions = 3;
        consensus.strSporkKey = "04ac60266c909c22b95415270278b8ea90bec852922d3b2bd110cfba62fc4da20f7d5d6c7f109c9604a421c6e75e47a3c8963dcd1b9b7ca71aaeef3d410e4cc65a";
        consensus.strObfuscationPoolDummyAddress = "WYCSnxDBqGkcruCwreLtBfpXtSMgoo5yUJ";
        consensus.nStartMasternodePayments = consensus.nNewProtocolStartTime; // July 2, 2018

        /** Zerocoin */
        consensus.zerocoinModulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                          "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                          "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                          "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                          "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                          "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.nMaxZerocoinSpendsPerTransaction = 7; // Assume about 20kb each
        consensus.nMinZerocoinMintFee = 1 * CENT; //high fee required for zerocoin mints
        consensus.nMintRequiredConfirmations = 20; //the maximum amount of confirmations until accumulated in 19
        consensus.nRequiredAccumulation = 1;
        consensus.nDefaultSecurityLevel = 100; //full security level for accumulators
        consensus.nZerocoinHeaderVersion = 8; //Block headers must be this version once zerocoin is active
        consensus.nZerocoinRequiredStakeDepth = 200; //The required confirmations for a zwsp to be stakable

        consensus.nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 0;
        consensus.nEnforceBlockUpgradeMajority = 51;
        consensus.nRejectBlockOutdatedMajority = 75;
        consensus.nToCheckBlockUpgradeMajority = 100;
        consensus.nMaxReorganizationDepth = 500;
        consensus.powLimit = ~uint256(0) >> 16; // WISPR starting difficulty is 1 / 2^12
        consensus.stakeLimit = ~uint256(0) >> 48;
        consensus.fAllowMinDifficultyBlocks = true;
        consensus.nTargetTimespanV1 =  16 * 60; // WISPR Old: 1 day
        consensus.nTargetTimespanV2 =  1 * 60; // WISPR New: 1 day
        consensus.nTargetSpacingV1 = 64;  // WISPR Old: 1 minute
        consensus.nTargetSpacingV2 = 1 * 60;  // WISPR New: 1 minute
        consensus.nLastPOWBlock = 450;
        consensus.nMaturity = 10;
        consensus.nMasternodeCountDrift = 4;
        consensus.nMaxMoneyOut = 120000000 * COIN;
        consensus.nNewProtocolStartHeight = 750;
        consensus.nNewProtocolStartTime = 1537830552;
        consensus.nZerocoinStartHeight = consensus.nNewProtocolStartHeight;
        consensus.nZerocoinStartTime = consensus.nNewProtocolStartTime; // July 2, 2018

        pchMessageStart[0] = 0x21;
        pchMessageStart[1] = 0x46;
        pchMessageStart[2] = 0x13;
        pchMessageStart[3] = 0x78;
        vAlertPubKey=ParseHex("04b20dd657f5e4fe0cf9aebb956498c383bac98a079c1003df02c2f121574cd280b8900248a8c6a43074b356e670ef83ec1aadfec60602df7c2366bae732372bba");
        nDefaultPort = 17002;
        nPruneAfterHeight = 100000;
        nMinerThreads = 0;

        const char* pszTimestamp = "I would rather be without a state than without a voice";
        genesis.SetNull();
        CMutableTransaction txNew2;
        txNew2.nVersion = 1;
        txNew2.nTime = 1512932225;
        txNew2.nLockTime = 0;
        txNew2.vin.resize(1);
        txNew2.vout.resize(1);
        txNew2.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew2.vout[0].SetEmpty();
        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.vtx.push_back(MakeTransactionRef(std::move(txNew2)));
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        genesis.nVersion = 1;
        genesis.nTime    = 1512932225;
        genesis.nBits    = consensus.powLimit.GetCompact();
        genesis.nNonce   = 142000;

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256("03205c57ebefb02d86c2c0c2de368fa48e92f7df7240f1b528ebbeae70fdbdb1"));
        assert(genesis.hashMerkleRoot == uint256("0x26069b04c7c7b5b8773824b15cfbf0ddaf11ee261657a1aeb28aa5c8163909ee"));


        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("testnet-seed.wispr.tech");     // Primary DNS Seeder for testnet wispr
        vSeeds.emplace_back("test.wispr-seeds.nl");     // Secondary DNS Seeder for testnet wispr


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 110);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 8);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();
        bech32_hrp = "tw";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        consensus.fSkipProofOfWorkCheck = false;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fDefaultCheckMemPool = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = true;

        consensus.nPoolMaxTransactions = 2;
        consensus.strSporkKey = "04e175173ea919f973cf4bf00d10e1c29c8ef75568c59056630d5a5cce8f6d8ac6edf0bb21baa2a24ecff17ce83b9863a88a54c54ca87c709c8a3f1dfef9d268e6";
        consensus.strObfuscationPoolDummyAddress = "mbTYaNZm7TaPt5Du65aPsL8FNTktufYydC";
        consensus.nStartMasternodePayments = consensus.nNewProtocolStartTime;
        consensus.nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
        // here because we only have a 8 block finalization window on testnet

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    explicit CRegTestParams(const ArgsManager& args)
    {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 0;
        consensus.nEnforceBlockUpgradeMajority = 750;
        consensus.nRejectBlockOutdatedMajority = 950;
        consensus.nToCheckBlockUpgradeMajority = 1000;
        consensus.nMaxReorganizationDepth = 500;
        consensus.powLimit = ~uint256(0) >> 1; // WISPR starting difficulty is 1 / 2^12
        consensus.stakeLimit = ~uint256(0) >> 48;
        consensus.nTargetTimespanV1 = 16 * 60; // WISPR Old: 1 day
        consensus.nTargetTimespanV2 = 1 * 60; // WISPR New: 1 day
        consensus.nTargetSpacingV1 = 64;        // WISPR Old: 1 minutes
        consensus.nTargetSpacingV2 = 1 * 60;        // WISPR New: 1 minute
        consensus.fAllowMinDifficultyBlocks = true;


        pchMessageStart[0] = 0xFF;
        pchMessageStart[1] = 0xAF;
        pchMessageStart[2] = 0xB7;
        pchMessageStart[3] = 0xDF;
        nMinerThreads = 1;
        genesis.nTime = 1411111111;
        genesis.nBits  = consensus.powLimit.GetCompact();
        genesis.nNonce = 2;

        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 17004;
        nPruneAfterHeight = 100000;
//        printf("Req net\n");
//        printf("genesis = %s\n", genesis.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256("0302157c185ae0018bb60f0c506087be772aa2015150f994cc1a6db55e8e23bd"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fDefaultCheckMemPool = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
        bech32_hrp = "wrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        strNetworkID = "unittest";
        nDefaultPort = 17005;
        nPruneAfterHeight = 100000;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        consensus.fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;

        /* enable fallback fee on unittest */
        m_fallback_fee_enabled = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { consensus.nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { consensus.nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { consensus.nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { consensus.nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { consensus.fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { consensus.fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = nullptr;
static std::unique_ptr<const CChainParams> globalChainParams;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    else if (chain == CBaseChainParams::UNITTEST)
        return std::unique_ptr<CChainParams>(new CUnitTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
