// Copyright (c) 2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WISPR_ZWSPTRACKER_H
#define WISPR_ZWSPTRACKER_H

#include <primitives/zerocoin.h>
#include <list>

class CDeterministicMint;
class CHDWallet;
class WalletLocation;

class CzWSPTracker
{
private:
    bool fInitialized;
    WalletLocation *m_location;
    std::map<uint256, CMintMeta> mapSerialHashes;
    std::map<uint256, uint256> mapPendingSpends; //serialhash, txid of spend
    bool UpdateStatusInternal(CHDWallet *pwallet, const std::set<uint256>& setMempool, CMintMeta& mint);
public:
    CzWSPTracker(CHDWallet *pwallet, WalletLocation *location);
    ~CzWSPTracker();
    void Add(CHDWallet *pwallet, const CDeterministicMint& dMint, bool isNew = false, bool isArchived = false);
    void Add(CHDWallet *pwallet, const CZerocoinMint& mint, bool isNew = false, bool isArchived = false);
    bool Archive(CHDWallet *pwallet, CMintMeta& meta);
    bool HasPubcoin(const CBigNum& bnValue) const;
    bool HasPubcoinHash(const uint256& hashPubcoin) const;
    bool HasSerial(const CBigNum& bnSerial) const;
    bool HasSerialHash(const uint256& hashSerial) const;
    bool HasMintTx(const uint256& txid);
    bool IsEmpty() const { return mapSerialHashes.empty(); }
    void Init(CHDWallet *pwallet);
    CMintMeta Get(const uint256& hashSerial);
    CMintMeta GetMetaFromPubcoin(const uint256& hashPubcoin);
    bool GetMetaFromStakeHash(const uint256& hashStake, CMintMeta& meta) const;
    CAmount GetBalance(bool fConfirmedOnly, bool fUnconfirmedOnly) const;
    std::vector<uint256> GetSerialHashes();
    std::vector<CMintMeta> GetMints(bool fConfirmedOnly) const;
    CAmount GetUnconfirmedBalance() const;
    std::set<CMintMeta> ListMints(CHDWallet *pwallet, bool fUnusedOnly, bool fMatureOnly, bool fUpdateStatus);
    void RemovePending(const uint256& txid);
    void SetPubcoinUsed(CHDWallet *pwallet, const uint256& hashPubcoin, const uint256& txid);
    void SetPubcoinNotUsed(CHDWallet *pwallet, const uint256& hashPubcoin);
    bool UnArchive(CHDWallet *pwallet, const uint256& hashPubcoin, bool isDeterministic);
    bool UpdateZerocoinMint(CHDWallet *pwallet, const CZerocoinMint& mint);
    bool UpdateState(CHDWallet *pwallet, const CMintMeta& meta);
    void Clear();
};

#endif //WISPR_ZWSPTRACKER_H
