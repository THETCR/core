// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Wispr Test Suite

#include <net.h>
#include <net_processing.h>
#include <memory>

std::unique_ptr<CConnman> g_connman;

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

//CClientUIInterface uiInterface;
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
      ECC_Start();
      SetupEnvironment();
      fPrintToDebugLog = false; // don't want to write to debug.log file
      fCheckBlockIndex = true;
      SelectParams(CBaseChainParams::UNITTEST);
      noui_connect();
#ifdef ENABLE_WALLET
      bitdb.MakeMock();
#endif
      pathTemp = GetTempPath() / strprintf("test_pivx_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
      boost::filesystem::create_directories(pathTemp);
      mapArgs["-datadir"] = pathTemp.string();
      pblocktree = new CBlockTreeDB(1 << 20, true);
      pcoinsdbview = new CCoinsViewDB(1 << 23, true);
      pcoinsTip = new CCoinsViewCache(pcoinsdbview);
      InitBlockIndex();
#ifdef ENABLE_WALLET
      bool fFirstRun;
      pwalletMain = new CWallet("wallet.dat");
      pwalletMain->LoadWallet(fFirstRun);
      RegisterValidationInterface(pwalletMain);
#endif
      nScriptCheckThreads = 3;
      for (int i=0; i < nScriptCheckThreads-1; i++)
          threadGroup.create_thread(&ThreadScriptCheck);
      RegisterNodeSignals(GetNodeSignals());
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
