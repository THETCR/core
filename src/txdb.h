// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include "coins.h"
#include "leveldbwrapper.h"
#include "chain.h"
#include "libzerocoin/Coin.h"
#include "libzerocoin/CoinSpend.h"
#include "primitives/zerocoin.h"
#include <primitives/block.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class CBlockIndex;
class CDiskTxPos;
class CCoins;
class uint256;
class CBigNum;

//! No need to periodic flush if at least this much space still available.
static constexpr int MAX_BLOCK_COINSDB_USAGE = 10;
//! -dbcache default (MiB)
static const int64_t nDefaultDbCache = 450;
//! -dbbatchsize default (bytes)
static const int64_t nDefaultDbBatchSize = 16 << 20;
//! max. -dbcache in (MiB)
static const int64_t nMaxDbCache = sizeof(void*) > 4 ? 4096 : 1024;
//! min. -dbcache in (MiB)
static const int64_t nMinDbCache = 4;
//! Max memory allocated to block tree DB specific cache, if no -txindex (MiB)
static const int64_t nMaxBlockDBCache = 2;
//! Max memory allocated to block tree DB specific cache, if -txindex (MiB)
// Unlike for the UTXO database, for the txindex scenario the leveldb cache make
// a meaningful difference: https://github.com/bitcoin/bitcoin/pull/8273#issuecomment-229601991
static const int64_t nMaxTxIndexCache = 1024;
//! Max memory allocated to coin DB specific cache (MiB)
static const int64_t nMaxCoinsDBCache = 8;

class CCoinsViewDBCursor;

struct CDiskTxPos : public CDiskBlockPos {
  unsigned int nTxOffset; // after header

  ADD_SERIALIZE_METHODS;

  template <typename Stream, typename Operation>
  inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
  {
      READWRITE(*(CDiskBlockPos*)this);
      READWRITE(VARINT(nTxOffset));
  }

  CDiskTxPos(const CDiskBlockPos& blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn)
  {
  }

  CDiskTxPos()
  {
      SetNull();
  }

  void SetNull()
  {
      CDiskBlockPos::SetNull();
      nTxOffset = 0;
  }
};

/** CCoinsView backed by the LevelDB coin database (chainstate/) */
class CCoinsViewDB final : public CCoinsView
{
protected:
    CLevelDBWrapper db;

public:
    explicit CCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetCoins(const uint256& txid, CCoins& coins) const override;
    bool HaveCoins(const uint256& txid) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    bool BatchWrite(CCoinsMap& mapCoins, const uint256& hashBlock) override;
    CCoinsViewCursor *Cursor() const override;

    //! Attempt to update from an older database format. Returns whether an error occurred.
//    bool Upgrade();
    size_t EstimateSize() const override;
};

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
  ~CCoinsViewDBCursor() {}

  bool GetKey(uint256 &key) const override;
  bool GetValue(CCoins &coins) const override;
  unsigned int GetValueSize() const override;

  bool Valid() const override;
  void Next() override;

private:
  CCoinsViewDBCursor(CLevelDBIterator* pcursorIn, const uint256 &hashBlockIn):
      CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
  boost::scoped_ptr<CLevelDBIterator> pcursor;
  std::pair<char, uint256> keyTmp;

  friend class CCoinsViewDB;
};

/** Access to the block database (blocks/index/) */
class CBlockTreeDB : public CLevelDBWrapper
{
public:
    explicit CBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CBlockTreeDB(const CBlockTreeDB&);
    void operator=(const CBlockTreeDB&);

public:
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo& fileinfo);
    bool WriteBlockFileInfo(int nFile, const CBlockFileInfo& fileinfo);
    bool ReadLastBlockFile(int& nFile);
    bool WriteLastBlockFile(int nFile);
    bool WriteReindexing(bool fReindex);
    bool ReadReindexing(bool& fReindex);
    bool ReadTxIndex(const uint256& txid, CDiskTxPos& pos);
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >& list);
    bool WriteFlag(const std::string& name, bool fValue);
    bool ReadFlag(const std::string& name, bool& fValue);
    bool WriteInt(const std::string& name, int nValue);
    bool ReadInt(const std::string& name, int& nValue);
    bool LoadBlockIndexGuts(std::function<CBlockIndex*(const uint256&)> insertBlockIndex);
};

/** Zerocoin database (zerocoin/) */
class CZerocoinDB : public CLevelDBWrapper
{
public:
    explicit CZerocoinDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CZerocoinDB(const CZerocoinDB&);
    void operator=(const CZerocoinDB&);

public:
    /** Write zWSP mints to the zerocoinDB in a batch */
    bool WriteCoinMintBatch(const std::vector<std::pair<libzerocoin::PublicCoin, uint256> >& mintInfo);
    bool ReadCoinMint(const CBigNum& bnPubcoin, uint256& txHash);
    bool ReadCoinMint(const uint256& hashPubcoin, uint256& hashTx);
    /** Write zWSP spends to the zerocoinDB in a batch */
    bool WriteCoinSpendBatch(const std::vector<std::pair<libzerocoin::CoinSpend, uint256> >& spendInfo);
    bool ReadCoinSpend(const CBigNum& bnSerial, uint256& txHash);
    bool ReadCoinSpend(const uint256& hashSerial, uint256 &txHash);
    bool EraseCoinMint(const CBigNum& bnPubcoin);
    bool EraseCoinSpend(const CBigNum& bnSerial);
    bool WipeCoins(const std::string& strType);
    bool WriteAccumulatorValue(const uint32_t& nChecksum, const CBigNum& bnValue);
    bool ReadAccumulatorValue(const uint32_t& nChecksum, CBigNum& bnValue);
    bool EraseAccumulatorValue(const uint32_t& nChecksum);
};

#endif // BITCOIN_TXDB_H
