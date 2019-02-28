// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/test_wispr.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <main.h>
#include <miner.h>
#include <net_processing.h>
#include <noui.h>
#include <pow.h>
#include <rpc/server.h>
#include <script/sigcache.h>
#include <streams.h>
#include <ui_interface.h>
#include <txdb.h>
#include <util/system.h>
#include <memory>

#ifdef ENABLE_WALLET
#include <wallet/db.h>
#include <wallet/wallet.h>
#endif


const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;
FastRandomContext g_insecure_rand_ctx;

extern bool fPrintToConsole;

BasicTestingSetup::BasicTestingSetup(const std::string& chainName)
        : m_path_root(fs::temp_directory_path() / "test_wispr" / strprintf("%lu_%i", (unsigned long)GetTime(), (int)(InsecureRandRange(1 << 30))))
{
    std::cout << "AutoDetect\n";
    SHA256AutoDetect();
    ECC_Start();
    std::cout << "SetupEnvironment\n";
    SetupEnvironment();
    std::cout << "SetupNetworking\n";
    SetupNetworking();
    InitSignatureCache();
    InitScriptExecutionCache();
    fCheckBlockIndex = true;
    SelectParams(chainName);
    noui_connect();
#ifdef ENABLE_WALLET
    bitdb.MakeMock();
#endif
}

BasicTestingSetup::~BasicTestingSetup()
{
    fs::remove_all(m_path_root);
    ECC_Stop();
}

fs::path BasicTestingSetup::SetDataDir(const std::string& name)
{
    fs::path ret = m_path_root / name;
    fs::create_directories(ret);
    gArgs.ForceSetArg("-datadir", ret.string());
    return ret;
}

TestingSetup::TestingSetup(const std::string& chainName) : BasicTestingSetup(chainName)
{
    std::cout << "SetDataDir\n";
    SetDataDir("tempdir");
    const CChainParams& chainparams = Params();
    // Ideally we'd move all the RPC tests to the functional testing framework
    // instead of unit tests, but for now we need these here.

//    RegisterAllCoreRPCCommands(tableRPC);
    std::cout << "ClearDatadirCache\n";
    ClearDatadirCache();
    // We have to run a scheduler thread to prevent ActivateBestChain
    // from blocking due to queue overrun.
    threadGroup.create_thread(std::bind(&CScheduler::serviceQueue, &scheduler));
    GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

//    mempool.setSanityCheck(1.0);
    pblocktree.reset(new CBlockTreeDB(1 << 20, true));
    pcoinsdbview.reset(new CCoinsViewDB(1 << 23, true));
    pcoinsTip.reset(new CCoinsViewCache(pcoinsdbview.get()));
    std::cout << "InitBlockIndex\n";
    InitBlockIndex(chainparams);
    {
        CValidationState state;
        if (!ActivateBestChain(state)) {
            throw std::runtime_error(strprintf("ActivateBestChain failed. (%s)", FormatStateMessage(state)));
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
    g_connman = MakeUnique<CConnman>(); // Deterministic randomness for tests.
    connman = g_connman.get();
    RegisterNodeSignals(GetNodeSignals());
}

TestingSetup::~TestingSetup()
{
    UnregisterNodeSignals(GetNodeSignals());
    threadGroup.interrupt_all();
    threadGroup.join_all();
    GetMainSignals().FlushBackgroundCallbacks();
    GetMainSignals().UnregisterBackgroundSignalScheduler();
    g_connman.reset();
    UnloadBlockIndex();
#ifdef ENABLE_WALLET
    UnregisterValidationInterface(pwalletMain);
    delete pwalletMain;
    pwalletMain = nullptr;
#endif
    pcoinsTip.reset();
    pcoinsdbview.reset();
    pblocktree.reset();
#ifdef ENABLE_WALLET
    bitdb.Flush(true);
#endif
}
