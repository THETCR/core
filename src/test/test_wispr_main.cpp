// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Wispr Test Suite

//#include <net.h>
#include <net_processing.h>
//#include <memory>

//std::unique_ptr<CConnman> g_connman;

#include "main.h"
#include "random.h"
#include "txdb.h"
#include "ui_interface.h"
#include "util.h"
#ifdef ENABLE_WALLET
#include "db.h"
#include "wallet.h"
#endif

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

extern CClientUIInterface uiInterface;
extern CWallet* pwalletMain;

extern bool fPrintToConsole;
extern void noui_connect();
//const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

struct TestingSetup {
  CCoinsViewDB *pcoinsdbview;
  boost::filesystem::path pathTemp;
  boost::thread_group threadGroup;
  ECCVerifyHandle globalVerifyHandle;

  TestingSetup() {
      BOOST_TEST_PASSPOINT();
      ECC_Start();
      BOOST_TEST_PASSPOINT();
      SetupEnvironment();
      BOOST_TEST_PASSPOINT();
      fPrintToDebugLog = false; // don't want to write to debug.log file
      BOOST_TEST_PASSPOINT();
      fCheckBlockIndex = true;
      BOOST_TEST_PASSPOINT();
      SelectParams(CBaseChainParams::UNITTEST);
      BOOST_TEST_PASSPOINT();
      noui_connect();
      BOOST_TEST_PASSPOINT();
#ifdef ENABLE_WALLET
      BOOST_TEST_PASSPOINT();
      bitdb.MakeMock();
#endif
      BOOST_TEST_PASSPOINT();
      pathTemp = GetTempPath() / strprintf("test_pivx_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
      BOOST_TEST_PASSPOINT();
      boost::filesystem::create_directories(pathTemp);
      BOOST_TEST_PASSPOINT();
      mapArgs["-datadir"] = pathTemp.string();
      BOOST_TEST_PASSPOINT();
      pblocktree = new CBlockTreeDB(1 << 20, true);
      BOOST_TEST_PASSPOINT();
      pcoinsdbview = new CCoinsViewDB(1 << 23, true);
      BOOST_TEST_PASSPOINT();
      pcoinsTip = new CCoinsViewCache(pcoinsdbview);
      BOOST_TEST_PASSPOINT();
      InitBlockIndex();
      BOOST_TEST_PASSPOINT();
#ifdef ENABLE_WALLET
      bool fFirstRun;
      BOOST_TEST_PASSPOINT();
      pwalletMain = new CWallet("wallet.dat");
      BOOST_TEST_PASSPOINT();
      pwalletMain->LoadWallet(fFirstRun);
      BOOST_TEST_PASSPOINT();
      RegisterValidationInterface(pwalletMain);
      BOOST_TEST_PASSPOINT();
#endif
      nScriptCheckThreads = 3;
      for (int i=0; i < nScriptCheckThreads-1; i++)
          threadGroup.create_thread(&ThreadScriptCheck);
      BOOST_TEST_PASSPOINT();
      RegisterNodeSignals(GetNodeSignals());
      BOOST_TEST_PASSPOINT();
  }
  ~TestingSetup()
  {
      threadGroup.interrupt_all();
      threadGroup.join_all();
      UnregisterNodeSignals(GetNodeSignals());
#ifdef ENABLE_WALLET
      delete pwalletMain;
      pwalletMain = NULL;
#endif
      delete pcoinsTip;
      delete pcoinsdbview;
      delete pblocktree;
#ifdef ENABLE_WALLET
      bitdb.Flush(true);
#endif
      boost::filesystem::remove_all(pathTemp);
      ECC_Stop();
  }
};


BOOST_GLOBAL_FIXTURE(TestingSetup);


[[noreturn]] void Shutdown(void* parg) {
  std::exit(EXIT_SUCCESS);
}

[[noreturn]] void StartShutdown() {
  std::exit(EXIT_SUCCESS);
}

bool ShutdownRequested() {
  return false;
}
//BOOST_GLOBAL_FIXTURE(TestingSetup);
