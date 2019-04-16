// Copyright (c) 2014-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <net.h>
#include <validation.h>

#include <test/setup_common.h>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

CAmount nMoneySupplyPoWEnd = 56250000 * COIN;

//static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
//{
//    int maxHalvings = 64;
//    CAmount nInitialSubsidy = 50 * COIN;
//
//    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == 0
//    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
//    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
//        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval;
//        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
//        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
//        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
//        nPreviousSubsidy = nSubsidy;
//    }
//    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval, consensusParams), 0);
//}
//
//static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
//{
//    Consensus::Params consensusParams;
//    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
//    TestBlockSubsidyHalvings(consensusParams);
//}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    CAmount nSum = 0;
    for (int nHeight = 0; nHeight < 1; nHeight += 1) {
        /* premine in block 1 (125,000 WSP) */
        CAmount nSubsidy = GetBlockSubsidy(nHeight, Params().GetConsensus());
        BOOST_CHECK(nSubsidy <= 125000 * COIN);
        nSum += nSubsidy;
    }

    for (int nHeight = 1; nHeight < 450; nHeight += 1) {
        /* PoW Phase One */
        CAmount nSubsidy = GetBlockSubsidy(nHeight, Params().GetConsensus());
        BOOST_CHECK(nSubsidy <= 125000 * COIN);
        nSum += nSubsidy;
        BOOST_CHECK(nSum > 0 && nSum <= nMoneySupplyPoWEnd);
    }

    BOOST_CHECK(nSum == nMoneySupplyPoWEnd);
}

static bool ReturnFalse() { return false; }
static bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}
BOOST_AUTO_TEST_SUITE_END()
