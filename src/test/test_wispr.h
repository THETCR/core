// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_TEST_BITCOIN_H
#define BITCOIN_TEST_TEST_BITCOIN_H

#include <chainparamsbase.h>
#include <fs.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <scheduler.h>
#include <txdb.h>
#include <txmempool.h>

#include <memory>
#include <type_traits>

#include <boost/thread.hpp>

// Enable BOOST_CHECK_EQUAL for enum class types
template <typename T>
std::ostream& operator<<(typename std::enable_if<std::is_enum<T>::value, std::ostream>::type& stream, const T& e)
{
    return stream << static_cast<typename std::underlying_type<T>::type>(e);
}

/** Basic testing setup.
 * This just configures logging and chain parameters.
 */
struct BasicTestingSetup {
    ECCVerifyHandle globalVerifyHandle;

    explicit BasicTestingSetup(CBaseChainParams::Network chainName = CBaseChainParams::UNITTEST);
    ~BasicTestingSetup();
};

/** Testing setup that configures a complete environment.
 * Included are data directory, coins database, script check threads setup.
 */
class CConnman;
class CNode;
class PeerLogicValidation;

struct TestingSetup: public BasicTestingSetup {
    CCoinsViewDB *pcoinsdbview;
    fs::path pathTemp;
    boost::thread_group threadGroup;
    CScheduler scheduler;

    explicit TestingSetup(CBaseChainParams::Network chainName = CBaseChainParams::UNITTEST);
    ~TestingSetup();
};

class CBlock;
struct CMutableTransaction;
class CScript;

//BOOST_GLOBAL_FIXTURE(BasicTestingSetup);

// Testing fixture that pre-creates a
// 100-block REGTEST-mode block chain

//struct TestChain100Setup : public TestingSetup {
//    TestChain100Setup();
//
//    // Create a new block with just given transactions, coinbase paying to
//    // scriptPubKey, and try to add it to the current chain.
//    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
//                                 const CScript& scriptPubKey);
//
//    ~TestChain100Setup();
//
//    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
//    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
//};
//
//class CTxMemPoolEntry;
//class CTxMemPool;
//
//struct TestMemPoolEntryHelper
//{
//    // Default values
//    CAmount nFee;
//    int64_t nTime;
//    double dPriority;
//    unsigned int nHeight;
//    bool hadNoDependencies;
//    bool spendsCoinbase;
//    unsigned int sigOpCost;
//    LockPoints lp;
//
//    TestMemPoolEntryHelper() :
//        nFee(0), nTime(0), dPriority(0.0), nHeight(1),
//        hadNoDependencies(false), spendsCoinbase(false), sigOpCost(4) { }
//
//    CTxMemPoolEntry FromTx(CMutableTransaction &tx, CTxMemPool *pool = NULL);
//    CTxMemPoolEntry FromTx(CTransaction &tx, CTxMemPool *pool = NULL);
//
//    // Change the default value
//    TestMemPoolEntryHelper &Fee(CAmount _fee) { nFee = _fee; return *this; }
//    TestMemPoolEntryHelper &Time(int64_t _time) { nTime = _time; return *this; }
//    TestMemPoolEntryHelper &Priority(double _priority) { dPriority = _priority; return *this; }
//    TestMemPoolEntryHelper &Height(unsigned int _height) { nHeight = _height; return *this; }
//    TestMemPoolEntryHelper &HadNoDependencies(bool _hnd) { hadNoDependencies = _hnd; return *this; }
//    TestMemPoolEntryHelper &SpendsCoinbase(bool _flag) { spendsCoinbase = _flag; return *this; }
//    TestMemPoolEntryHelper &SigOpsCost(unsigned int _sigopsCost) { sigOpCost = _sigopsCost; return *this; }
//};

// define an implicit conversion here so that uint256 may be used directly in BOOST_CHECK_*
std::ostream& operator<<(std::ostream& os, const uint256& num);

#endif
