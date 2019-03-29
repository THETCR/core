// Copyright (c) 2017-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libzerocoin/Denominations.h"
#include "amount.h"
#include "chainparams.h"
#include <wallet/coincontrol.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include "txdb.h"
#include <boost/test/unit_test.hpp>
#include <iostream>

using namespace libzerocoin;


BOOST_AUTO_TEST_SUITE(zerocoin_transactions_tests)


BOOST_AUTO_TEST_CASE(zerocoin_spend_test)
{
    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain();
    WalletLocation m_location = WalletLocation("unlocked.dat");
    std::shared_ptr<CWallet> pwallet(new CWallet(*m_chain, m_location, WalletDatabase::Create(m_location.GetPath())));

    SelectParams(CBaseChainParams::MAIN);
    ZerocoinParams *ZCParams = Params().Zerocoin_Params(false);
    (void)ZCParams;

    bool fFirstRun;
    pwallet->LoadWallet(fFirstRun);
    pwallet->zwspTracker = unique_ptr<CzWSPTracker>(new CzWSPTracker(pwallet->chain(), pwallet->GetLocation(), pwallet->GetDBHandle(), pwallet.get()));
    CTransactionRef tx;
    CWalletTx* wtx = new CWalletTx(pwallet.get(), tx);
    bool fMintChange=true;
    bool fMinimizeChange=true;
    std::vector<CZerocoinSpend> vSpends;
    std::vector<CZerocoinMint> vMints;
    CAmount nAmount = COIN;
    int nSecurityLevel = 100;

    CZerocoinSpendReceipt receipt;
    pwallet->SpendZerocoin(nAmount, nSecurityLevel, *wtx, receipt, vMints, fMintChange, fMinimizeChange);

    BOOST_CHECK_MESSAGE(receipt.GetStatus() == ZWSP_TRX_FUNDS_PROBLEMS, "Failed Invalid Amount Check");

    nAmount = 1;
    CZerocoinSpendReceipt receipt2;
    pwallet->SpendZerocoin(nAmount, nSecurityLevel, *wtx, receipt2, vMints, fMintChange, fMinimizeChange);

    // if using "wallet.dat", instead of "unlocked.dat" need this
    /// BOOST_CHECK_MESSAGE(vString == "Error: Wallet locked, unable to create transaction!"," Locked Wallet Check Failed");

    BOOST_CHECK_MESSAGE(receipt2.GetStatus() == ZWSP_TRX_FUNDS_PROBLEMS, "Failed Invalid Amount Check");

}

BOOST_AUTO_TEST_SUITE_END()
