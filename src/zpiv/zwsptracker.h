// Copyright (c) 2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WISPR_ZWSPTRACKER_H
#define WISPR_ZWSPTRACKER_H

#include <zpiv/zerocoin.h>
#include <zpiv/witness.h>
#include <sync.h>
#include <interfaces/chain.h>
#include <wallet/db.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <list>

using WalletDatabase = BerkeleyDatabase;

class CDeterministicMint;
class CWallet;
class CzWSPWallet;

class CzWSPTracker
{
private:
    bool fInitialized;
    std::map<uint256, CMintMeta> mapSerialHashes;
    std::map<uint256, uint256> mapPendingSpends; //serialhash, txid of spend
    std::map<uint256, std::unique_ptr<CoinWitnessData> > mapStakeCache; //serialhash, witness value, height
    bool UpdateStatusInternal(const std::set<uint256>& setMempool, CMintMeta& mint);
    /** Interface for accessing chain state. */
    interfaces::Chain& m_chain;

    /** Wallet location which includes wallet name (see WalletLocation). */
    WalletLocation m_location;
    /** Internal database handle. */
    WalletDatabase& database;

    /** Wallet that holds this zerocoin tracker. */
    CWallet& pwallet;
public:
    CzWSPTracker(interfaces::Chain& chain, const WalletLocation& location, WalletDatabase& database, CWallet& pwallet);
    ~CzWSPTracker();
    void Add(const CDeterministicMint& dMint, bool isNew = false, bool isArchived = false, CzWSPWallet* zWSPWallet = nullptr);
    void Add(const CZerocoinMint& mint, bool isNew = false, bool isArchived = false);
    bool Archive(CMintMeta& meta);
    bool HasPubcoin(const CBigNum& bnValue) const;
    bool HasPubcoinHash(const uint256& hashPubcoin) const;
    bool HasSerial(const CBigNum& bnSerial) const;
    bool HasSerialHash(const uint256& hashSerial) const;
    bool HasMintTx(const uint256& txid);
    bool IsEmpty() const { return mapSerialHashes.empty(); }
    void Init();
    CMintMeta Get(const uint256& hashSerial);
    CMintMeta GetMetaFromPubcoin(const uint256& hashPubcoin);
    bool GetMetaFromStakeHash(const uint256& hashStake, CMintMeta& meta) const;
    CAmount GetBalance(interfaces::Chain::Lock& locked_chain, bool fConfirmedOnly, bool fUnconfirmedOnly) const;
    std::vector<uint256> GetSerialHashes();
    mutable CCriticalSection cs_spendcache;
    CoinWitnessData* GetSpendCache(const uint256& hashStake) EXCLUSIVE_LOCKS_REQUIRED(cs_spendcache);
    bool ClearSpendCache() EXCLUSIVE_LOCKS_REQUIRED(cs_spendcache);
    std::vector<CMintMeta> GetMints(bool fConfirmedOnly) const;
    CAmount GetUnconfirmedBalance(interfaces::Chain::Lock& locked_chain) const;
    std::set<CMintMeta> ListMints(bool fUnusedOnly, bool fMatureOnly, bool fUpdateStatus, bool fWrongSeed = false);
    void RemovePending(const uint256& txid);
    void SetPubcoinUsed(const uint256& hashPubcoin, const uint256& txid);
    void SetPubcoinNotUsed(const uint256& hashPubcoin);
    bool UnArchive(const uint256& hashPubcoin, bool isDeterministic);
    bool UpdateZerocoinMint(const CZerocoinMint& mint);
    bool UpdateState(const CMintMeta& meta);
    void Clear();

    friend struct WalletTestingSetup;

};

#endif //WISPR_ZWSPTRACKER_H
