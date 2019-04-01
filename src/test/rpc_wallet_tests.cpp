// Copyright (c) 2013-2014 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "rpc/client.h"
#include <key_io.h>
#include <validation.h>

#include "base58.h"
#include <wallet/wallet.h>

#include <test/test_wispr.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

extern JSONRPCRequest createArgs(int nRequired, const char* address1 = nullptr, const char* address2 = nullptr);
extern UniValue CallRPC(string args);

BOOST_FIXTURE_TEST_SUITE(rpc_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(rpc_addmultisig)
{
    LOCK(m_wallet.cs_wallet);

//    rpcfn_type addmultisig = tableRPC["addmultisigaddress"]->actor;

    // old, 65-byte-long:
    const char address1Hex[] = "041431A18C7039660CD9E3612A2A47DC53B69CB38EA4AD743B7DF8245FD0438F8E7270415F1085B9DC4D7DA367C69F1245E27EE5552A481D6854184C80F0BB8456";
    // new, compressed:
    const char address2Hex[] = "029BBEFF390CE736BD396AF43B52A1C14ED52C086B1E5585C15931F68725772BAC";

    UniValue v;
    CTxDestination address;
    BOOST_CHECK_NO_THROW(v = CallRPC(string("addmultisig ")+createArgs(1, address1Hex).params.get_str()));
//    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex)));
    address = DecodeDestination(v.get_str());
    BOOST_CHECK(IsValidDestination(address));

    BOOST_CHECK_NO_THROW(v = CallRPC(string("addmultisig ")+createArgs(1, address1Hex, address2Hex).params.get_str()));
//    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex, address2Hex)));
    address = DecodeDestination(v.get_str());
    BOOST_CHECK(IsValidDestination(address));
    BOOST_CHECK_NO_THROW(v = CallRPC(string("addmultisig ")+createArgs(2, address1Hex, address2Hex).params.get_str()));
//    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(2, address1Hex, address2Hex)));
    address = DecodeDestination(v.get_str());
    BOOST_CHECK(IsValidDestination(address));

    BOOST_CHECK_THROW(CallRPC(string("addmultisig ")+createArgs(0).params.get_str()), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(string("addmultisig ")+createArgs(1).params.get_str()), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(string("addmultisig ")+createArgs(2, address1Hex).params.get_str()), std::runtime_error);
//    BOOST_CHECK_THROW(addmultisig(createArgs(0)), std::runtime_error);
//    BOOST_CHECK_THROW(addmultisig(createArgs(1)), std::runtime_error);
//    BOOST_CHECK_THROW(addmultisig(createArgs(2, address1Hex)), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC(string("addmultisig ")+createArgs(1, "").params.get_str()), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(string("addmultisig ")+createArgs(1, "NotAValidPubkey").params.get_str()), std::runtime_error);
//    BOOST_CHECK_THROW(addmultisig(createArgs(1, "")), std::runtime_error);
//    BOOST_CHECK_THROW(addmultisig(createArgs(1, "NotAValidPubkey")), std::runtime_error);

    std::string short1(address1Hex, address1Hex + sizeof(address1Hex) - 2); // last byte missing
    BOOST_CHECK_THROW(CallRPC(string("addmultisig ")+createArgs(2, short1.c_str()).params.get_str()), std::runtime_error);
//    BOOST_CHECK_THROW(addmultisig(createArgs(2, short1.c_str())), std::runtime_error);

    std::string short2(address1Hex + 1, address1Hex + sizeof(address1Hex)); // first byte missing
    BOOST_CHECK_THROW(CallRPC(string("addmultisig ")+createArgs(2, short2.c_str()).params.get_str()), std::runtime_error);
//    BOOST_CHECK_THROW(addmultisig(createArgs(2, short2.c_str())), std::runtime_error);
    std::cout << "addmultisig finished\n";
}

BOOST_AUTO_TEST_CASE(rpc_wallet)
{
    // Test RPC calls for various wallet statistics
    UniValue r;
    std::cout << "lock\n";
    LOCK2(cs_main, m_wallet.cs_wallet);

    std::cout << "walletdb\n";
    WalletBatch walletdb(m_wallet.GetDBHandle());
    std::cout << "GenerateNewKey\n";
    CPubKey demoPubkey = m_wallet.GenerateNewKey(walletdb);
    std::string demoAddress = EncodeDestination(CTxDestination(demoPubkey.GetID()));
    UniValue retValue;
    std::string strAccount = "walletDemoAccount";
    std::string strPurpose = "receive";
    BOOST_TEST_PASSPOINT();
    std::cout << "BOOST_CHECK_NO_THROW\n";
    BOOST_CHECK_NO_THROW({ /*Initialize Wallet with an account */
        WalletBatch walletdb(m_wallet.GetDBHandle());
        CAccount account;
        account.vchPubKey = demoPubkey;
        m_wallet.SetAddressBook(account.vchPubKey.GetID(), strAccount, strPurpose);
        walletdb.WriteAccount(strAccount, account);
    });
    BOOST_TEST_PASSPOINT();
    std::cout << "GenerateNewKey 2\n";
    CPubKey setaccountDemoPubkey = m_wallet.GenerateNewKey(walletdb);
    std::string setaccountDemoAddress = EncodeDestination(CTxDestination(setaccountDemoPubkey.GetID()));

    std::cout << "setaccount rpc\n";
    /*********************************
     * 			setaccount
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("setaccount " + setaccountDemoAddress + " nullaccount"));
    /* WfJehDzxfR7hMDdvgadn6ppZF7BLHTGmDW is not owned by the test wallet. */
    BOOST_CHECK_THROW(CallRPC("setaccount WfJehDzxfR7hMDdvgadn6ppZF7BLHTGmDW nullaccount"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("setaccount"), std::runtime_error);
    /* WfJehDzxfR7hMDdvgadn6ppZF7BLHTGmD (33 chars) is an illegal address (should be 34 chars) */
    BOOST_CHECK_THROW(CallRPC("setaccount WfJehDzxfR7hMDdvgadn6ppZF7BLHTGmD nullaccount"), std::runtime_error);

    std::cout << "listunspent rpc\n";
    /*********************************
     * 			listunspent
     *********************************/
    std::cout << "listunspent 1\n";
    BOOST_CHECK_NO_THROW(CallRPC("listunspent"));
    std::cout << "listunspent 2\n";
    BOOST_CHECK_THROW(CallRPC("listunspent string"), std::runtime_error);
    std::cout << "listunspent 3\n";
    BOOST_CHECK_THROW(CallRPC("listunspent 0 string"), std::runtime_error);
    std::cout << "listunspent 4\n";
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 not_array"), std::runtime_error);
    std::cout << "listunspent 5\n";
    BOOST_CHECK_THROW(CallRPC("listunspent 0 1 [] extra"), std::runtime_error);
    std::cout << "listunspent 6\n";
    BOOST_CHECK_NO_THROW(r = CallRPC("listunspent 0 1 []"));
    std::cout << "listunspent 7\n";
    BOOST_CHECK(r.get_array().empty());

    std::cout << "listreceivedbyaddress rpc\n";
    /*********************************
     * 		listreceivedbyaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress"));
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress not_int"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 not_bool"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaddress 0 true"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaddress 0 true extra"), std::runtime_error);

    std::cout << "listreceivedbyaccount rpc\n";
    /*********************************
     * 		listreceivedbyaccount
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount"));
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount 0"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount not_int"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount 0 not_bool"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("listreceivedbyaccount 0 true"));
    BOOST_CHECK_THROW(CallRPC("listreceivedbyaccount 0 true extra"), std::runtime_error);
    std::cout << "getrawchangeaddress rpc\n";
    /*********************************
     * 		getrawchangeaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getrawchangeaddress"));
    std::cout << "getnewaddress rpc\n";
    /*********************************
     * 		getnewaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress"));
    BOOST_CHECK_NO_THROW(CallRPC("getnewaddress getnewaddress_demoaccount"));
    std::cout << "getaccountaddress rpc\n";
    /*********************************
     * 		getaccountaddress
     *********************************/
    BOOST_CHECK_NO_THROW(CallRPC("getaccountaddress \"\""));
    BOOST_CHECK_NO_THROW(CallRPC("getaccountaddress accountThatDoesntExists")); // Should generate a new account
    BOOST_CHECK_NO_THROW(retValue = CallRPC("getaccountaddress " + strAccount));
    BOOST_CHECK(retValue.get_str() == demoAddress);
    std::cout << "getaccount rpc\n";
    /*********************************
     * 			getaccount
     *********************************/
    BOOST_CHECK_THROW(CallRPC("getaccount"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("getaccount " + demoAddress));
    std::cout << "verifymessage rpc\n";
    /*********************************
     * 	signmessage + verifymessage
     *********************************/
    BOOST_CHECK_NO_THROW(retValue = CallRPC("signmessage " + demoAddress + " mymessage"));
    BOOST_CHECK_THROW(CallRPC("signmessage"), std::runtime_error);
    /* Should throw error because this address is not loaded in the wallet */
    BOOST_CHECK_THROW(CallRPC("signmessage WfJehDzxfR7hMDdvgadn6ppZF7BLHTGmDW mymessage"), std::runtime_error);

    /* missing arguments */
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("verifymessage " + demoAddress + " " + retValue.get_str()), std::runtime_error);
    /* Illegal address */
    BOOST_CHECK_THROW(CallRPC("verifymessage WfJehDzxfR7hMDdvgadn6ppZF7BLHTGmD " + retValue.get_str() + " mymessage"), std::runtime_error);
    /* wrong address */
    BOOST_CHECK(CallRPC("verifymessage WfJehDzxfR7hMDdvgadn6ppZF7BLHTGmDW " + retValue.get_str() + " mymessage").get_bool() == false);
    /* Correct address and signature but wrong message */
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress + " " + retValue.get_str() + " wrongmessage").get_bool() == false);
    /* Correct address, message and signature*/
    BOOST_CHECK(CallRPC("verifymessage " + demoAddress + " " + retValue.get_str() + " mymessage").get_bool() == true);
    std::cout << "getaddressesbyaccount rpc\n";
    /*********************************
     * 		getaddressesbyaccount
     *********************************/
    BOOST_CHECK_THROW(CallRPC("getaddressesbyaccount"), std::runtime_error);
    BOOST_CHECK_NO_THROW(retValue = CallRPC("getaddressesbyaccount " + strAccount));
    UniValue arr = retValue.get_array();
    BOOST_CHECK(arr.size() > 0);
    BOOST_CHECK(arr[0].get_str() == demoAddress);
}

BOOST_AUTO_TEST_SUITE_END()
