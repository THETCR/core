// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_wispr.h"

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "miner.h"
#include "random.h"
#include "ui_interface.h"
#include "util.h"
#ifdef ENABLE_WALLET
#include "db.h"
#include "wallet.h"
#include "walletdb.h"
#include "accumulators.h"
#endif

#include <boost/filesystem.hpp>


extern bool fPrintToConsole;
extern void noui_connect();
BasicTestingSetup::BasicTestingSetup(CBaseChainParams::Network chainName)
{
    ECC_Start();
    SetupEnvironment();
    SetupNetworking();
    fPrintToDebugLog = false; // don't want to write to debug.log file
    fCheckBlockIndex = true;
    SelectParams(CBaseChainParams::UNITTEST);
    noui_connect();
#ifdef ENABLE_WALLET
    bitdb.MakeMock();
#endif
}

BasicTestingSetup::~BasicTestingSetup()
{
    ECC_Stop();
    g_connman.reset();
}
TestingSetup::TestingSetup(CBaseChainParams::Network chainName) : BasicTestingSetup(chainName)
{
//    const CChainParams& chainparams = Params();
    // Ideally we'd move all the RPC tests to the functional testing framework
    // instead of unit tests, but for now we need these here.

//    RegisterAllCoreRPCCommands(tableRPC);
//    ClearDatadirCache();
    pathTemp = GetTempPath() / strprintf("test_bitcoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
    boost::filesystem::create_directories(pathTemp);
    mapArgs["-datadir"] = pathTemp.string();
//    mempool.setSanityCheck(1.0);
    pblocktree = new CBlockTreeDB(1 << 20, true);
    pcoinsdbview = new CCoinsViewDB(1 << 23, true);
    pcoinsTip = new CCoinsViewCache(pcoinsdbview);
    InitBlockIndex();
    {
        CValidationState state;
        if (!ActivateBestChain(state)) {
            throw std::runtime_error("ActivateBestChain failed");
        }
    }
#ifdef ENABLE_WALLET
    bool fFirstRun;
    pwalletMain = new CWallet("wallet.dat");
    pwalletMain->LoadWallet(fFirstRun);
    RegisterValidationInterface(pwalletMain);
#endif
    nScriptCheckThreads = 3;
    for (int i=0; i < nScriptCheckThreads-1; i++)
        threadGroup.create_thread(&ThreadScriptCheck);
    g_connman = std::unique_ptr<CConnman>(new CConnman()); // Deterministic randomness for tests.
    connman = g_connman.get();
    RegisterNodeSignals(GetNodeSignals());
}

TestingSetup::~TestingSetup()
{
    UnregisterNodeSignals(GetNodeSignals());
    threadGroup.interrupt_all();
    threadGroup.join_all();
    UnloadBlockIndex();
#ifdef ENABLE_WALLET
    delete pwalletMain;
    pwalletMain = nullptr;
#endif
    delete pcoinsTip;
    delete pcoinsdbview;
    delete pblocktree;
    boost::filesystem::remove_all(pathTemp);
}

//void Shutdown(void* parg)
//{
//  exit(0);
//}
//
//void StartShutdown()
//{
//  exit(0);
//}
//
//bool ShutdownRequested()
//{
//  return false;
//}
