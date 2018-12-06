// Copyright (c) 2017-2018 The Wispr Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwallet.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <interfaces/chain.h>

#include <wallet/test/hdwallet_test_fixture.h>
#include <base58.h>
#include <chainparams.h>
#include <miner.h>
#include <pos/miner.h>
#include <pos/kernel.h>
#include <timedata.h>
#include <coins.h>
#include <net.h>
#include <validation.h>
#include <blind.h>
#include <txdb.h>

#include <rpc/server.h>
#include <consensus/validation.h>

#include <chrono>
#include <thread>


#include <boost/test/unit_test.hpp>

extern UniValue CallRPC(std::string args, std::string wallet="");

struct StakeTestingSetup: public TestingSetup {
    StakeTestingSetup(const std::string& chainName = CBaseChainParams::REGTEST):
        TestingSetup(chainName, true) // fWisprMode = true
    {
        bool fFirstRun;
        pwalletMain = std::make_shared<CHDWallet>(*m_chain, WalletLocation(), WalletDatabase::CreateMock());
        AddWallet(pwalletMain);
        pwalletMain->LoadWallet(fFirstRun);
        RegisterValidationInterface(pwalletMain.get());

        RegisterWalletRPCCommands(tableRPC);
        RegisterHDWalletRPCCommands(tableRPC);
        ECC_Start_Stealth();
        ECC_Start_Blinding();
        SetMockTime(0);
    }

    ~StakeTestingSetup()
    {
        UnregisterValidationInterface(pwalletMain.get());
        RemoveWallet(pwalletMain);
        pwalletMain.reset();

        mapStakeSeen.clear();
        listStakeSeen.clear();
        ECC_Stop_Stealth();
        ECC_Stop_Blinding();
    }

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain();
    std::unique_ptr<interfaces::Chain::Lock> m_locked_chain = m_chain->assumeLocked();  // Temporary. Removed in upcoming lock cleanup
    std::shared_ptr<CHDWallet> pwalletMain;
};

BOOST_FIXTURE_TEST_SUITE(stake_tests, StakeTestingSetup)


void StakeNBlocks(CHDWallet *pwallet, size_t nBlocks)
{
    int nBestHeight;
    size_t nStaked = 0;
    size_t k, nTries = 10000;
    for (k = 0; k < nTries; ++k) {
        {
            LOCK(cs_main);
            nBestHeight = chainActive.Height();
        }

        int64_t nSearchTime = GetAdjustedTime() & ~Params().GetStakeTimestampMask(nBestHeight+1);
        if (nSearchTime <= pwallet->nLastCoinStakeSearchTime) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        CScript coinbaseScript;
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript, true, false));
        BOOST_REQUIRE(pblocktemplate.get());

        if (pwallet->SignBlock(pblocktemplate.get(), nBestHeight+1, nSearchTime)) {
            CBlock *pblock = &pblocktemplate->block;

            if (CheckStake(pblock)) {
                nStaked++;
            }
        }

        if (nStaked >= nBlocks) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    BOOST_REQUIRE(k < nTries);
};

static void AddAnonTxn(CHDWallet *pwallet, CBitcoinAddress &address, CAmount amount)
{
    {
    auto locked_chain = pwallet->chain().lock();
    CValidationState state;
    BOOST_REQUIRE(address.IsValid());

    std::vector<CTempRecipient> vecSend;
    std::string sError;
    CTempRecipient r;
    r.nType = OUTPUT_RINGCT;
    r.SetAmount(amount);
    r.address = address.Get();
    vecSend.push_back(r);

    CTransactionRef tx_new;
    CWalletTx wtx(pwallet, std::move(tx_new));
    CTransactionRecord rtx;
    CAmount nFee;
    CCoinControl coinControl;
    BOOST_CHECK(0 == pwallet->AddStandardInputs(wtx, rtx, vecSend, true, nFee, &coinControl, sError));

    wtx.BindWallet(pwallet);
    BOOST_REQUIRE(wtx.AcceptToMemoryPool(*locked_chain, maxTxFee, state));
    } // cs_main
    SyncWithValidationInterfaceQueue();
}

static void DisconnectTip(CBlock &block, CBlockIndex *pindexDelete, CCoinsViewCache &view, const CChainParams &chainparams)
{
    CValidationState state;
    BOOST_REQUIRE(DISCONNECT_OK == DisconnectBlock(block, pindexDelete, view));
    BOOST_REQUIRE(FlushView(&view, state, true));
    BOOST_REQUIRE(FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED));
    chainActive.SetTip(pindexDelete->pprev);
    UpdateTip(pindexDelete->pprev, chainparams);
};

BOOST_AUTO_TEST_CASE(stake_test)
{
    int i =0;
    SeedInsecureRand();
    CHDWallet *pwallet = pwalletMain.get();
    UniValue rv;
    printf("Stake tests: %d\n", i++);

    std::unique_ptr<CChainParams> regtestChainParams = CreateChainParams(CBaseChainParams::REGTEST);
    const CChainParams &chainparams = *regtestChainParams;
    printf("Stake tests: %d\n", i++);

    BOOST_REQUIRE(chainparams.GenesisBlock().GetHash() == chainActive.Tip()->GetBlockHash());

    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4"));
    printf("Stake tests: %d\n", i++);

    // Import the key to the last 5 outputs in the regtest genesis coinbase
    BOOST_CHECK_NO_THROW(rv = CallRPC("extkeyimportmaster tprv8ZgxMBicQKsPe3x7bUzkHAJZzCuGqN6y28zFFyg5i7Yqxqm897VCnmMJz6QScsftHDqsyWW5djx6FzrbkF9HSD3ET163z1SzRhfcWxvwL4G"));
    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblHDKey"));
    printf("Stake tests: %d\n", i++);

    {
        LOCK(pwallet->cs_wallet);
        CBitcoinAddress addr("pdtYqn1fBVpgRa6Am6VRRLH8fkrFr1TuDq");
        CKeyID idk;
        BOOST_CHECK(addr.GetKeyID(idk));
        BOOST_CHECK(pwallet->IsMine(idk) == ISMINE_SPENDABLE);
        printf("Stake tests: %d\n", i++);

        const CEKAKey *pak = nullptr;
        const CEKASCKey *pasc = nullptr;
        CExtKeyAccount *pa = nullptr;
        BOOST_CHECK(pwallet->HaveKey(idk, pak, pasc, pa));
        BOOST_REQUIRE(pa);
        BOOST_REQUIRE(pak);
        BOOST_CHECK(pak->nParent == 1);
        BOOST_CHECK(pak->nKey == 1);
        BOOST_CHECK(!pasc);
        printf("Stake tests: %d\n", i++);

        CEKAKey ak;
        CKey key;
        CKeyID idStealth;
        BOOST_CHECK(pwallet->GetKey(idk, key, pa, ak, idStealth));
        BOOST_CHECK(idk == key.GetPubKey().GetID());
    }
    printf("Stake tests: %d\n", i++);

    {
        LOCK2(cs_main, pwallet->cs_wallet);
        BOOST_REQUIRE(pwallet->GetBalance() == 12500000000000);
    }
    BOOST_REQUIRE(chainActive.Tip()->nMoneySupply == 12500000000000);
    printf("Stake tests: %d\n", i++);

    StakeNBlocks(pwallet, 2);
    BOOST_REQUIRE(chainActive.Tip()->nMoneySupply == 12500000079274);
    printf("Stake tests: %d\n", i++);

    CBlockIndex *pindexDelete = chainActive.Tip();
    BOOST_REQUIRE(pindexDelete);
    printf("Stake tests: %d\n", i++);

    CBlock block;
    BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));
    printf("Stake tests: %d\n", i++);

    const CTxIn &txin = block.vtx[0]->vin[0];
    printf("Stake tests: %d\n", i++);

    CCoinsViewCache view(pcoinsTip.get());
    const Coin &coin = view.AccessCoin(txin.prevout);
    BOOST_REQUIRE(coin.IsSpent());
    printf("Stake tests: %d\n", i++);

    DisconnectTip(block, pindexDelete, view, chainparams);
    printf("Stake tests: %d\n", i++);

    BOOST_REQUIRE(pindexDelete->pprev->GetBlockHash() == chainActive.Tip()->GetBlockHash());
    printf("Stake tests: %d\n", i++);

    const Coin &coin2 = view.AccessCoin(txin.prevout);
    BOOST_REQUIRE(!coin2.IsSpent());
    printf("Stake tests: %d\n", i++);

    BOOST_CHECK(chainActive.Height() == pindexDelete->nHeight - 1);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == pindexDelete->pprev->GetBlockHash());
    BOOST_REQUIRE(chainActive.Tip()->nMoneySupply == 12500000039637);

    printf("Stake tests: %d\n", i++);

    // Reconnect block
    {
        CValidationState state;
        std::shared_ptr<const CBlock> pblock = std::make_shared<const CBlock>(block);
        BOOST_REQUIRE(ActivateBestChain(state, chainparams, pblock));
        printf("Stake tests: %d\n", i++);

        CCoinsViewCache view(pcoinsTip.get());
        const Coin &coin = view.AccessCoin(txin.prevout);
        BOOST_REQUIRE(coin.IsSpent());
        BOOST_REQUIRE(chainActive.Tip()->nMoneySupply == 12500000079274);
    }
    printf("Stake tests: InsecureNewKey\n");

    CKey kRecv;
    InsecureNewKey(kRecv, true);
    CKeyID idRecv = kRecv.GetPubKey().GetID();
    printf("Stake tests: %d\n", i++);

    bool fSubtractFeeFromAmount = false;
    CAmount nAmount = 10000;
    CTransactionRef tx_new;
    printf("Stake tests: %d\n", i++);

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(idRecv);
    printf("Stake tests: %d\n", i++);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain.get());
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    printf("Stake tests: %d\n", i++);

    CCoinControl coinControl;
    {
        auto locked_chain = pwallet->chain().lock();
        BOOST_CHECK(pwallet->CreateTransaction(*locked_chain, vecSend, tx_new, reservekey, nFeeRequired, nChangePosRet, strError, coinControl));
    }
    {
        g_connman = std::unique_ptr<CConnman>(new CConnman(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())));
        CValidationState state;
        pwallet->SetBroadcastTransactions(true);
        mapValue_t mapValue;
        BOOST_CHECK(pwallet->CommitTransaction(tx_new, std::move(mapValue), {} /* orderForm */, reservekey, g_connman.get(), state));
    }
    printf("Stake tests: %d\n", i++);

    StakeNBlocks(pwallet, 1);
    printf("Stake tests: %d\n", i++);

    CBlock blockLast;
    BOOST_REQUIRE(ReadBlockFromDisk(blockLast, chainActive.Tip(), chainparams.GetConsensus()));
    printf("Stake tests: %d\n", i++);

    BOOST_REQUIRE(blockLast.vtx.size() == 2);
    BOOST_REQUIRE(blockLast.vtx[1]->GetHash() == tx_new->GetHash());
    printf("Stake tests: %d\n", i++);

    {
        uint256 tipHash = chainActive.Tip()->GetBlockHash();
        uint256 prevTipHash = chainActive.Tip()->pprev->GetBlockHash();
        printf("Stake tests: %d\n", i++);

        // Disconnect last block
        CBlockIndex *pindexDelete = chainActive.Tip();
        BOOST_REQUIRE(pindexDelete);
        printf("Stake tests: %d\n", i++);

        CBlock block;
        BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));
        printf("Stake tests: %d\n", i++);

        CCoinsViewCache view(pcoinsTip.get());
        DisconnectTip(block, pindexDelete, view, chainparams);
        printf("Stake tests: %d\n", i++);


        BOOST_CHECK(prevTipHash == chainActive.Tip()->GetBlockHash());

        printf("Stake tests: %d\n", i++);

        // Reduce the reward
        RegtestParams().SetCoinYearReward(1 * CENT);
        BOOST_CHECK(Params().GetCoinYearReward(0) == 1 * CENT);

        {
            LOCK(cs_main);
            printf("Stake tests: %d\n", i++);

            CValidationState state;
            CCoinsViewCache view(pcoinsTip.get());
            BOOST_REQUIRE(false == ConnectBlock(block, state, pindexDelete, view, chainparams, false));
            printf("Stake tests: %d\n", i++);

            BOOST_CHECK(state.IsInvalid());
            BOOST_CHECK(state.GetRejectReason() == "bad-cs-amount");
            BOOST_CHECK(prevTipHash == chainActive.Tip()->GetBlockHash());
            printf("Stake tests: %d\n", i++);

            // restore the reward
            RegtestParams().SetCoinYearReward(2 * CENT);
            BOOST_CHECK(Params().GetCoinYearReward(0) == 2 * CENT);
            printf("Stake tests: %d\n", i++);

            // block should connect now
            CValidationState clearstate;
            CCoinsViewCache clearview(pcoinsTip.get());
            BOOST_REQUIRE(ConnectBlock(block, clearstate, pindexDelete, clearview, chainparams, false));
            printf("Stake tests: %d\n", i++);

            BOOST_CHECK(!clearstate.IsInvalid());
            BOOST_REQUIRE(FlushView(&clearview, state, false));
            BOOST_REQUIRE(FlushStateToDisk(chainparams, clearstate, FlushStateMode::IF_NEEDED));
            chainActive.SetTip(pindexDelete);
            UpdateTip(pindexDelete, chainparams);
            printf("Stake tests: %d\n", i++);

            BOOST_CHECK(tipHash == chainActive.Tip()->GetBlockHash());
            BOOST_CHECK(chainActive.Tip()->nMoneySupply == 12500000153511);
        }
    }

    BOOST_CHECK_NO_THROW(rv = CallRPC("getnewextaddress lblTestKey"));
    std::string extaddr = StripQuotes(rv.write());
    printf("Stake tests: %d\n", i++);

    BOOST_CHECK(pwallet->GetBalance() + pwallet->GetStaked() == 12500000108911);

    {
        BOOST_CHECK_NO_THROW(rv = CallRPC("getnewstealthaddress"));
        std::string sSxAddr = StripQuotes(rv.write());
        printf("Stake tests: %d\n", i++);

        CBitcoinAddress address(sSxAddr);
        printf("Stake tests: %d\n", i++);


        AddAnonTxn(pwallet, address, 10 * COIN);
        AddAnonTxn(pwallet, address, 20 * COIN);
        printf("Stake tests: %d\n", i++);

        StakeNBlocks(pwallet, 2);
        CCoinControl coinControl;
        BOOST_CHECK(30 * COIN == pwallet->GetAvailableAnonBalance(&coinControl));
        printf("Stake tests: %d\n", i++);

        BOOST_CHECK(chainActive.Tip()->nAnonOutputs == 4);
        printf("Stake tests: %d\n", i++);

        for (size_t i = 0; i < 2; ++i) {
            // Disconnect last block
            uint256 prevTipHash = chainActive.Tip()->pprev->GetBlockHash();
            CBlockIndex *pindexDelete = chainActive.Tip();
            BOOST_REQUIRE(pindexDelete);
            printf("Stake tests: %d\n", i++);

            CBlock block;
            BOOST_REQUIRE(ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()));
            printf("Stake tests: %d\n", i++);

            CCoinsViewCache view(pcoinsTip.get());
            DisconnectTip(block, pindexDelete, view, chainparams);
            printf("Stake tests: %d\n", i++);

            BOOST_CHECK(prevTipHash == chainActive.Tip()->GetBlockHash());
        }

        BOOST_CHECK(chainActive.Tip()->nAnonOutputs == 0);
        BOOST_CHECK(chainActive.Tip()->nMoneySupply == 12500000153511);
    }
}

BOOST_AUTO_TEST_SUITE_END()
