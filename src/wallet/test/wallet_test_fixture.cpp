// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/test/wallet_test_fixture.h>

#include <rpc/server.h>
#include <wallet/db.h>
#include <wallet/rpcwallet.h>

WalletTestingSetup::WalletTestingSetup(const std::string& chainName):
    TestingSetup(chainName), m_wallet(*m_chain, WalletLocation(), WalletDatabase::CreateMock())
{
    bool fFirstRun;
    std::cout << "LoadWallet\n";
    m_wallet.LoadWallet(fFirstRun);
    std::cout << "handleNotifications\n";
    m_wallet.m_chain_notifications_handler = m_chain->handleNotifications(m_wallet);

    std::cout << "registerRcs\n";
    m_chain_client->registerRpcs();

    std::cout << "Create CzWSPWallet\n";
//    uint256 seedMaster("3a1947364362e2e7c073b386869c89c905c0cf462448ffd6c2021bd03ce689f6");
//    CzWSPWallet zWallet(m_wallet.chain(), m_wallet.GetLocation(), m_wallet.GetDBHandle(), &m_wallet);
//    zWallet.SetMasterSeed(seedMaster);
//    m_wallet.setZWallet(&zWallet);
//    m_wallet.zwspTracker = std::unique_ptr<CzWSPTracker>(new CzWSPTracker(m_wallet.chain(), m_wallet.GetLocation(), m_wallet.GetDBHandle(), &m_wallet));

}
