// Copyright (c) 2012-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <memory>
#include <set>
#include <stdint.h>
#include <utility>
#include <vector>

#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <rpc/server.h>
#include <test/test_wispr.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/test/wallet_test_fixture.h>
#include <policy/policy.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

extern UniValue importmulti(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static void AddKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.cs_wallet);
    wallet.AddKeyPubKey(key, key.GetPubKey());
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions, TestChain100Setup)
{
    auto chain = interfaces::MakeChain();

    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = chainActive.Tip();
    GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = chainActive.Tip();

    LockAnnotation lock(::cs_main);
    auto locked_chain = chain->lock();

    // Verify ScanForWalletTransactions accommodates a null start block.
    {
        CWallet wallet(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions({} /* start_block */, {} /* stop_block */, reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, 0);
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(oldTip->GetBlockHash(), {} /* stop_block */, reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, 100 * COIN);
    }

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(oldTip->GetBlockHash(), {} /* stop_block */, reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, oldTip->GetBlockHash());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, 50 * COIN);
    }

    // Prune the remaining block file.
    PruneOneBlockFile(newTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({newTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions scans no blocks.
    {
        CWallet wallet(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(oldTip->GetBlockHash(), {} /* stop_block */, reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, newTip->GetBlockHash());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(wallet.GetBalance().m_mine_immature, 0);
    }
}

BOOST_FIXTURE_TEST_CASE(importmulti_rescan, TestChain100Setup)
{
    auto chain = interfaces::MakeChain();

    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = chainActive.Tip();
    GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = chainActive.Tip();

    LockAnnotation lock(::cs_main);
    auto locked_chain = chain->lock();

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
        AddWallet(wallet);
        UniValue keys;
        keys.setArray();
        UniValue key;
        key.setObject();
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.pushKV("timestamp", 0);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        key.clear();
        key.setObject();
        CKey futureKey;
        futureKey.MakeNewKey(true);
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.pushKV("timestamp", newTip->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(keys);

        UniValue response = importmulti(request);
        BOOST_CHECK_EQUAL(response.write(),
            strprintf("[{\"success\":false,\"error\":{\"code\":-1,\"message\":\"Rescan failed for key with creation "
                      "timestamp %d. There was an error reading a block from time %d, which is after or within %d "
                      "seconds of key creation, and could contain transactions pertaining to the key. As a result, "
                      "transactions and coins using this key may not appear in the wallet. This error could be caused "
                      "by pruning or data corruption (see bitcoind log for details) and could be dealt with by "
                      "downloading and rescanning the relevant blocks (see -reindex and -rescan "
                      "options).\"}},{\"success\":true}]",
                              0, oldTip->GetBlockTimeMax(), TIMESTAMP_WINDOW));
        RemoveWallet(wallet);
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain100Setup)
{
    auto chain = interfaces::MakeChain();

    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = chainActive.Tip()->GetBlockTimeMax() + 5;
    SetMockTime(BLOCK_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + TIMESTAMP_WINDOW;
    SetMockTime(KEY_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    auto locked_chain = chain->lock();

    std::string backup_file = (SetDataDir("importwallet_rescan") / "wallet.backup").string();

    // Import key into wallet and call dumpwallet to create backup file.
    {
        std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
        LOCK(wallet->cs_wallet);
        wallet->mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime = KEY_TIME;
        wallet->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(backup_file);
        AddWallet(wallet);
        ::dumpwallet(request);
        RemoveWallet(wallet);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());

        JSONRPCRequest request;
        request.params.setArray();
        request.params.push_back(backup_file);
        AddWallet(wallet);
        ::importwallet(request);
        RemoveWallet(wallet);

        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 3U);
        BOOST_CHECK_EQUAL(m_coinbase_txns.size(), 103U);
        for (size_t i = 0; i < m_coinbase_txns.size(); ++i) {
            bool found = wallet->GetWalletTx(m_coinbase_txns[i]->GetHash());
            bool expected = i >= 100;
            BOOST_CHECK_EQUAL(found, expected);
        }
    }

    SetMockTime(0);
}

// Check that GetImmatureCredit() returns a newly calculated value instead of
// the cached value after a MarkDirty() call.
//
// This is a regression test written to verify a bugfix for the immature credit
// function. Similar tests probably should be written for the other credit and
// debit functions.
BOOST_FIXTURE_TEST_CASE(coin_mark_dirty_immature_credit, TestChain100Setup)
{
    auto chain = interfaces::MakeChain();
    CWallet wallet(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    CWalletTx wtx(&wallet, m_coinbase_txns.back());
    auto locked_chain = chain->lock();
    LOCK(wallet.cs_wallet);
    wtx.hashBlock = chainActive.Tip()->GetBlockHash();
    wtx.nIndex = 0;

    // Call GetImmatureCredit() once before adding the key to the wallet to
    // cache the current immature credit amount, which is 0.
    BOOST_CHECK_EQUAL(wtx.GetImmatureCredit(*locked_chain), 0);

    // Invalidate the cached value, add the key, and make sure a new immature
    // credit amount is calculated.
    wtx.MarkDirty();
    wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
    BOOST_CHECK_EQUAL(wtx.GetImmatureCredit(*locked_chain), 50*COIN);
}

static int64_t AddTx(CWallet& wallet, uint32_t lockTime, int64_t mockTime, int64_t blockTime)
{
    CMutableTransaction tx;
    tx.nLockTime = lockTime;
    SetMockTime(mockTime);
    CBlockIndex* block = nullptr;
    if (blockTime > 0) {
        LockAnnotation lock(::cs_main);
        auto locked_chain = wallet.chain().lock();
        auto inserted = mapBlockIndex.emplace(GetRandHash(), new CBlockIndex);
        assert(inserted.second);
        const uint256& hash = inserted.first->first;
        block = inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
    }

    CWalletTx wtx(&wallet, MakeTransactionRef(tx));
    if (block) {
        wtx.SetMerkleBranch(block->GetBlockHash(), 0);
    }
    {
        LOCK(cs_main);
        wallet.AddToWallet(wtx);
    }
    LOCK(wallet.cs_wallet);
    return wallet.mapWallet.at(wtx.GetHash()).nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart)
{
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 1, 100, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 1, 200, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 2, 300, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 3, 420, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 4, 500, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 5, 50, 600), 300);

    // Reset mock time for other tests.
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(LoadReceiveRequests)
{
    CTxDestination dest = CKeyID();
    LOCK(m_wallet.cs_wallet);
    m_wallet.AddDestData(dest, "misc", "val_misc");
    m_wallet.AddDestData(dest, "rr0", "val_rr0");
    m_wallet.AddDestData(dest, "rr1", "val_rr1");

    auto values = m_wallet.GetDestValues("rr");
    BOOST_CHECK_EQUAL(values.size(), 2U);
    BOOST_CHECK_EQUAL(values[0], "val_rr0");
    BOOST_CHECK_EQUAL(values[1], "val_rr1");
}

class ListCoinsTestingSetup : public TestChain100Setup
{
public:
    ListCoinsTestingSetup()
    {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = MakeUnique<CWallet>(m_chain.get(), WalletLocation(), WalletDatabase::CreateMock());
        bool firstRun;
        wallet->LoadWallet(firstRun);
        AddKey(*wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet.get());
        reserver.reserve();
        CWallet::ScanResult result = wallet->ScanForWalletTransactions(chainActive.Genesis()->GetBlockHash(), {} /* stop_block */, reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK_EQUAL(result.last_scanned_block, chainActive.Tip()->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, chainActive.Height());
        BOOST_CHECK(result.last_failed_block.IsNull());
    }

    ~ListCoinsTestingSetup()
    {
        wallet.reset();
    }

    CWalletTx& AddTx(CRecipient recipient)
    {
        CTransactionRef tx;
        CReserveKey reservekey(wallet.get());
        CAmount fee;
        int changePos = -1;
        std::string error;
        CCoinControl dummy;
        BOOST_CHECK(wallet->CreateTransaction(*m_locked_chain, {recipient}, tx, reservekey, fee, changePos, error, dummy));
        CValidationState state;
        BOOST_CHECK(wallet->CommitTransaction(tx, {}, {}, reservekey, state));
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx = CMutableTransaction(*wallet->mapWallet.at(tx->GetHash()).tx);
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        LOCK(wallet->cs_wallet);
        auto it = wallet->mapWallet.find(tx->GetHash());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.SetMerkleBranch(chainActive.Tip()->GetBlockHash(), 1);
        return it->second;
    }

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain();
    std::unique_ptr<interfaces::Chain::Lock> m_locked_chain = m_chain->assumeLocked();  // Temporary. Removed in upcoming lock cleanup
    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(ListCoins, ListCoinsTestingSetup)
{
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<COutput>> list;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        list = wallet->ListCoins(*m_locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(boost::get<CKeyID>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 1U);

    // Check initial balance from one mature coinbase transaction.
    BOOST_CHECK_EQUAL(125000 * COIN, wallet->GetAvailableBalance());

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{GetScriptForRawPubKey({}), 1 * COIN, false /* subtract fee */});
    {
        LOCK2(cs_main, wallet->cs_wallet);
        list = wallet->ListCoins(*m_locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(boost::get<CKeyID>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::vector<COutput> available;
        wallet->AvailableCoins(*m_locked_chain, available);
        BOOST_CHECK_EQUAL(available.size(), 2U);
    }
    for (const auto& group : list) {
        for (const auto& coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(COutPoint(coin.tx->GetHash(), coin.i));
        }
    }
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::vector<COutput> available;
        wallet->AvailableCoins(*m_locked_chain, available);
        BOOST_CHECK_EQUAL(available.size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        LOCK2(cs_main, wallet->cs_wallet);
        list = wallet->ListCoins(*m_locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(boost::get<CKeyID>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup)
{
    auto chain = interfaces::MakeChain();
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(chain.get(), WalletLocation(), WalletDatabase::CreateDummy());
    wallet->SetMinVersion(FEATURE_LATEST);
    wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    BOOST_CHECK(!wallet->TopUpKeyPool(1000));
    CPubKey pubkey;
    BOOST_CHECK(!wallet->GetKeyFromPool(pubkey, false));
}

// Explicit calculation which is used to test the wallet constant
// We get the same virtual size due to rounding(weight/4) for both use_max_sig values
static size_t CalculateNestedKeyhashInputSize(bool use_max_sig)
{
    // Generate ephemeral valid pubkey
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Generate pubkey hash
    uint160 key_hash(Hash160(pubkey.begin(), pubkey.end()));

    // Create inner-script to enter into keystore. Key hash can't be 0...
    CScript inner_script = CScript() << OP_0 << std::vector<unsigned char>(key_hash.begin(), key_hash.end());

    // Create outer P2SH script for the output
    uint160 script_id(Hash160(inner_script.begin(), inner_script.end()));
    CScript script_pubkey = CScript() << OP_HASH160 << std::vector<unsigned char>(script_id.begin(), script_id.end()) << OP_EQUAL;

    // Add inner-script to key store and key to watchonly
    CBasicKeyStore keystore;
    keystore.AddCScript(inner_script);
    keystore.AddKeyPubKey(key, pubkey);

    // Fill in dummy signatures for fee calculation.
    SignatureData sig_data;

    if (!ProduceSignature(keystore, use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR, script_pubkey, sig_data)) {
        // We're hand-feeding it correct arguments; shouldn't happen
        assert(false);
    }

    CTxIn tx_in;
    UpdateInput(tx_in, sig_data);
    return (size_t)GetVirtualTransactionInputSize(tx_in);
}

BOOST_FIXTURE_TEST_CASE(dummy_input_size_test, TestChain100Setup)
{
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(false), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(true), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
}

//! OLD TESTS

// how many times to run all the tests to have a chance to catch errors that only show up with particular random shuffles
//#define RUN_TESTS 100
//
//// some tests fail 1% of the time due to bad luck.
//// we repeat those tests this many times and only complain if all iterations of the test fail
//#define RANDOM_REPEATS 5
//
//typedef set<pair<const CWalletTx*,unsigned int> > CoinSet;
//
//static std::vector<COutput> vCoins;
//
//static void add_coin(const CAmount& nValue, int nAge = 6*24, bool fIsFromMe = false, int nInput=0)
//{
//    const std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
//    CWallet* pwallet = nullptr;
//    if(!wallets.empty()){
//        pwallet = wallets.at(0).get();
//    }
//    static int nextLockTime = 0;
//    CMutableTransaction tx;
//    tx.nLockTime = nextLockTime++;        // so all transactions get different hashes
//    tx.vout.resize(nInput+1);
//    tx.vout[nInput].nValue = nValue;
//    if (fIsFromMe) {
//        // IsFromMe() returns (GetDebit() > 0), and GetDebit() is 0 if vin.empty(),
//        // so stop vin being empty, and cache a non-zero Debit to fake out IsFromMe()
//        tx.vin.resize(1);
//    }
//    CWalletTx* wtx = new CWalletTx(pwallet, MakeTransactionRef(tx));
//    if (fIsFromMe)
//    {
//        wtx->fDebitCached = true;
//        wtx->nDebitCached = 1;
//    }
//    COutput output(wtx, nInput, nAge, true, true, true);
//    vCoins.push_back(output);
//}
//
//static void empty_wallet(void)
//{
//    for(COutput output: vCoins)
//        delete output.tx;
//    vCoins.clear();
//}
//
//static bool equal_sets(CoinSet a, CoinSet b)
//{
//    pair<CoinSet::iterator, CoinSet::iterator> ret = mismatch(a.begin(), a.end(), b.begin());
//    return ret.first == a.end() && ret.second == b.end();
//}
//
//
//BOOST_AUTO_TEST_CASE(coin_selection_tests)
//{
//    CoinSet setCoinsRet, setCoinsRet2;
//    CAmount nValueRet;
//
//    LOCK(m_wallet.cs_wallet);
//
//    // test multiple times to allow for differences in the shuffle order
//    for (int i = 0; i < RUN_TESTS; i++)
//    {
//        empty_wallet();
//
//        // with an empty wallet we can't even pay one cent
//        BOOST_CHECK(!m_wallet.SelectCoinsMinConf( 1 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));
//
//        add_coin(1*CENT, 4);        // add a new 1 cent coin
//
//        // with a new 1 cent coin, we still can't find a mature 1 cent
//        BOOST_CHECK(!m_wallet.SelectCoinsMinConf( 1 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));
//
//        // but we can find a new 1 cent
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf( 1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT);
//
//        add_coin(2*CENT);           // add a mature 2 cent coin
//
//        // we can't make 3 cents of mature coins
//        BOOST_CHECK(!m_wallet.SelectCoinsMinConf( 3 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));
//
//        // we can make 3 cents of new  coins
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf( 3 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 3 * CENT);
//
//        add_coin(5*CENT);           // add a mature 5 cent coin,
//        add_coin(10*CENT, 3, true); // a new 10 cent coin sent from one of our own addresses
//        add_coin(20*CENT);          // and a mature 20 cent coin
//
//        // now we have new: 1+10=11 (of which 10 was self-sent), and mature: 2+5+20=27.  total = 38
//
//        // we can't make 38 cents only if we disallow new coins:
//        BOOST_CHECK(!m_wallet.SelectCoinsMinConf(38 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));
//        // we can't even make 37 cents if we don't allow new coins even if they're from us
//        BOOST_CHECK(!m_wallet.SelectCoinsMinConf(38 * CENT, 6, 6, vCoins, setCoinsRet, nValueRet));
//        // but we can make 37 cents if we accept new coins from ourself
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(37 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 37 * CENT);
//        // and we can make 38 cents if we accept all new coins
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(38 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 38 * CENT);
//
//        // try making 34 cents from 1,2,5,10,20 - we can't do it exactly
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(34 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_GT(nValueRet, 34 * CENT);         // but should get more than 34 cents
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);     // the best should be 20+10+5.  it's incredibly unlikely the 1 or 2 got included (but possible)
//
//        // when we try making 7 cents, the smaller coins (1,2,5) are enough.  We should see just 2+5
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf( 7 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 7 * CENT);
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);
//
//        // when we try making 8 cents, the smaller coins (1,2,5) are exactly enough.
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf( 8 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK(nValueRet == 8 * CENT);
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);
//
//        // when we try making 9 cents, no subset of smaller coins is enough, and we get the next bigger coin (10)
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf( 9 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 10 * CENT);
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);
//
//        // now clear out the wallet and start again to test choosing between subsets of smaller coins and the next biggest coin
//        empty_wallet();
//
//        add_coin( 6*CENT);
//        add_coin( 7*CENT);
//        add_coin( 8*CENT);
//        add_coin(20*CENT);
//        add_coin(30*CENT); // now we have 6+7+8+20+30 = 71 cents total
//
//        // check that we have 71 and not 72
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(71 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK(!m_wallet.SelectCoinsMinConf(72 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//
//        // now try making 16 cents.  the best smaller coins can do is 6+7+8 = 21; not as good at the next biggest coin, 20
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(16 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 20 * CENT); // we should get 20 in one coin
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);
//
//        add_coin( 5*CENT); // now we have 5+6+7+8+20+30 = 75 cents total
//
//        // now if we try making 16 cents again, the smaller coins can make 5+6+7 = 18 cents, better than the next biggest coin, 20
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(16 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 18 * CENT); // we should get 18 in 3 coins
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);
//
//        add_coin( 18*CENT); // now we have 5+6+7+8+18+20+30
//
//        // and now if we try making 16 cents again, the smaller coins can make 5+6+7 = 18 cents, the same as the next biggest coin, 18
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(16 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 18 * CENT);  // we should get 18 in 1 coin
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U); // because in the event of a tie, the biggest coin wins
//
//        // now try making 11 cents.  we should get 5+6
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(11 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 11 * CENT);
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);
//
//        // check that the smallest bigger coin is used
//        add_coin( 1*COIN);
//        add_coin( 2*COIN);
//        add_coin( 3*COIN);
//        add_coin( 4*COIN); // now we have 5+6+7+8+18+20+30+100+200+300+400 = 1094 cents
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(95 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1 * COIN);  // we should get 1 BTC in 1 coin
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);
//
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(195 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 2 * COIN);  // we should get 2 BTC in 1 coin
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);
//
//        // empty the wallet and start again, now with fractions of a cent, to test sub-cent change avoidance
//        empty_wallet();
//        add_coin(0.1*CENT);
//        add_coin(0.2*CENT);
//        add_coin(0.3*CENT);
//        add_coin(0.4*CENT);
//        add_coin(0.5*CENT);
//
//        // try making 1 cent from 0.1 + 0.2 + 0.3 + 0.4 + 0.5 = 1.5 cents
//        // we'll get sub-cent change whatever happens, so can expect 1.0 exactly
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT);
//
//        // but if we add a bigger coin, making it possible to avoid sub-cent change, things change:
//        add_coin(1111*CENT);
//
//        // try making 1 cent from 0.1 + 0.2 + 0.3 + 0.4 + 0.5 + 1111 = 1112.5 cents
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT); // we should get the exact amount
//
//        // if we add more sub-cent coins:
//        add_coin(0.6*CENT);
//        add_coin(0.7*CENT);
//
//        // and try again to make 1.0 cents, we can still make 1.0 cents
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT); // we should get the exact amount
//
//        // run the 'mtgox' test (see http://blockexplorer.com/tx/29a3efd3ef04f9153d47a990bd7b048a4b2d213daaa5fb8ed670fb85f13bdbcf)
//        // they tried to consolidate 10 50k coins into one 500k coin, and ended up with 50k in change
//        empty_wallet();
//        for (int i = 0; i < 20; i++)
//            add_coin(50000 * COIN);
//
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(500000 * COIN, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 500000 * COIN); // we should get the exact amount
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 10U); // in ten coins
//
//        // if there's not enough in the smaller coins to make at least 1 cent change (0.5+0.6+0.7 < 1.0+1.0),
//        // we need to try finding an exact subset anyway
//
//        // sometimes it will fail, and so we use the next biggest coin:
//        empty_wallet();
//        add_coin(0.5 * CENT);
//        add_coin(0.6 * CENT);
//        add_coin(0.7 * CENT);
//        add_coin(1111 * CENT);
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1111 * CENT); // we get the bigger coin
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1U);
//
//        // but sometimes it's possible, and we use an exact subset (0.4 + 0.6 = 1.0)
//        empty_wallet();
//        add_coin(0.4 * CENT);
//        add_coin(0.6 * CENT);
//        add_coin(0.8 * CENT);
//        add_coin(1111 * CENT);
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT);   // we should get the exact amount
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U); // in two coins 0.4+0.6
//
//        // test avoiding sub-cent change
//        empty_wallet();
//        add_coin(0.0005 * COIN);
//        add_coin(0.01 * COIN);
//        add_coin(1 * COIN);
//
//        // trying to make 1.0001 from these three coins
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(1.0001 * COIN, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1.0105 * COIN);   // we should get all coins
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3U);
//
//        // but if we try to make 0.999, we should take the bigger of the two small coins to avoid sub-cent change
//        BOOST_CHECK( m_wallet.SelectCoinsMinConf(0.999 * COIN, 1, 1, vCoins, setCoinsRet, nValueRet));
//        BOOST_CHECK_EQUAL(nValueRet, 1.01 * COIN);   // we should get 1 + 0.01
//        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2U);
//
//        // test randomness
//        {
//            empty_wallet();
//            for (int i2 = 0; i2 < 100; i2++)
//                add_coin(COIN);
//
//            // picking 50 from 100 coins doesn't depend on the shuffle,
//            // but does depend on randomness in the stochastic approximation code
//            BOOST_CHECK(m_wallet.SelectCoinsMinConf(50 * COIN, 1, 6, vCoins, setCoinsRet , nValueRet));
//            BOOST_CHECK(m_wallet.SelectCoinsMinConf(50 * COIN, 1, 6, vCoins, setCoinsRet2, nValueRet));
//            BOOST_CHECK(!equal_sets(setCoinsRet, setCoinsRet2));
//
//            int fails = 0;
//            for (int i = 0; i < RANDOM_REPEATS; i++)
//            {
//                // selecting 1 from 100 identical coins depends on the shuffle; this test will fail 1% of the time
//                // run the test RANDOM_REPEATS times and only complain if all of them fail
//                BOOST_CHECK(m_wallet.SelectCoinsMinConf(COIN, 1, 6, vCoins, setCoinsRet , nValueRet));
//                BOOST_CHECK(m_wallet.SelectCoinsMinConf(COIN, 1, 6, vCoins, setCoinsRet2, nValueRet));
//                if (equal_sets(setCoinsRet, setCoinsRet2))
//                    fails++;
//            }
//            BOOST_CHECK_NE(fails, RANDOM_REPEATS);
//
//            // add 75 cents in small change.  not enough to make 90 cents,
//            // then try making 90 cents.  there are multiple competing "smallest bigger" coins,
//            // one of which should be picked at random
//            add_coin( 5*CENT); add_coin(10*CENT); add_coin(15*CENT); add_coin(20*CENT); add_coin(25*CENT);
//
//            fails = 0;
//            for (int i = 0; i < RANDOM_REPEATS; i++)
//            {
//                // selecting 1 from 100 identical coins depends on the shuffle; this test will fail 1% of the time
//                // run the test RANDOM_REPEATS times and only complain if all of them fail
//                BOOST_CHECK(m_wallet.SelectCoinsMinConf(90*CENT, 1, 6, vCoins, setCoinsRet , nValueRet));
//                BOOST_CHECK(m_wallet.SelectCoinsMinConf(90*CENT, 1, 6, vCoins, setCoinsRet2, nValueRet));
//                if (equal_sets(setCoinsRet, setCoinsRet2))
//                    fails++;
//            }
//            BOOST_CHECK_NE(fails, RANDOM_REPEATS);
//        }
//    }
//    empty_wallet();
//}

BOOST_AUTO_TEST_SUITE_END()
