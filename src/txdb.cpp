// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2016-2018 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <accumulators.h>
#include <chainparams.h>
#include <hash.h>
#include <random.h>
#include <pow.h>
#include <shutdown.h>
#include <uint256.h>
#include <util/system.h>
#include <ui_interface.h>

#include <stdint.h>

#include <boost/thread.hpp>

using namespace libzerocoin;

static const char DB_COIN = 'C';
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';
static const char DB_HEAD_BLOCKS = 'H';

namespace {

struct CoinEntry {
  COutPoint* outpoint;
  char key;
  explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

  template<typename Stream>
  void Serialize(Stream &s) const {
      s << key;
      s << outpoint->hash;
      s << VARINT(outpoint->n, VarIntMode::NONNEGATIVE_SIGNED);
  }

  template<typename Stream>
  void Unserialize(Stream& s) {
      s >> key;
      s >> outpoint->hash;
      s >> VARINT(outpoint->n, VarIntMode::NONNEGATIVE_SIGNED);
  }
};

}

void static BatchWriteCoins(CLevelDBBatch& batch, const uint256& hash, const CCoins& coins)
{
    if (coins.IsPruned())
        batch.Erase(std::make_pair('c', hash));
    else
        batch.Write(std::make_pair('c', hash), coins);
}

void static BatchWriteHashBestChain(CLevelDBBatch& batch, const uint256& hash)
{
    batch.Write('B', hash);
}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, true)
{
}

bool CCoinsViewDB::GetCoins(const uint256& txid, CCoins& coins) const
{
    return db.Read(std::make_pair('c', txid), coins);
}

bool CCoinsViewDB::HaveCoins(const uint256& txid) const
{
    return db.Exists(std::make_pair('c', txid));
}

uint256 CCoinsViewDB::GetBestBlock() const
{
    uint256 hashBestChain;
    if (!db.Read('B', hashBestChain))
        return uint256(0);
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!db.Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap& mapCoins, const uint256& hashBlock)
{
    CLevelDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            BatchWriteCoins(batch, it->first, it->second.coins);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }
    if (hashBlock != uint256(0))
        BatchWriteHashBestChain(batch, hashBlock);

    LogPrint(BCLog::COINDB, "Committing %u changed transactions (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return db.WriteBatch(batch);
}

size_t CCoinsViewDB::EstimateSize() const
{
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}
CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDBWrapper(gArgs.IsArgSet("-blocksdir") ? GetDataDir() / "blocks" / "index" : GetBlocksDir() / "index", nCacheSize, fMemory, fWipe)
{
}

bool CBlockTreeDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(std::make_pair('b', blockindex.GetBlockHash()), blockindex);
}

bool CBlockTreeDB::WriteBlockFileInfo(int nFile, const CBlockFileInfo& info)
{
    return Write(std::make_pair('f', nFile), info);
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo& info)
{
    return Read(std::make_pair('f', nFile), info);
}

bool CBlockTreeDB::WriteLastBlockFile(int nFile)
{
    return Write('l', nFile);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing)
{
    if (fReindexing)
        return Write('R', '1');
    else
        return Erase('R');
}

bool CBlockTreeDB::ReadReindexing(bool& fReindexing)
{
    fReindexing = Exists('R');
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int& nFile)
{
    return Read('l', nFile);
}

CCoinsViewCursor *CCoinsViewDB::Cursor() const
{
    CCoinsViewDBCursor *i = new CCoinsViewDBCursor(const_cast<CLevelDBWrapper*>(&db)->NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COINS);
    // Cache key of first record
    i->pcursor->GetKey(i->keyTmp);
    return i;
}

bool CCoinsViewDBCursor::GetKey(uint256 &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COINS) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(CCoins &coins) const
{
    return pcursor->GetValue(coins);
}

unsigned int CCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COINS;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    if (pcursor->Valid()) {
        bool ok = pcursor->GetKey(keyTmp);
        assert(ok); // If GetKey fails here something must be wrong with underlying database, we cannot handle that here
    } else {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    }
}

bool CBlockTreeDB::ReadTxIndex(const uint256& txid, CDiskTxPos& pos)
{
    return Read(std::make_pair('t', txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >& vect)
{
    CLevelDBBatch batch(*this);
    for (auto it = vect.begin(); it != vect.end(); it++){
        batch.Write(std::make_pair('t', it->first), it->second);
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteFlag(const std::string& name, bool fValue)
{
    return Write(std::make_pair('F', name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string& name, bool& fValue)
{
    char ch;
    if (!Read(std::make_pair('F', name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::WriteInt(const std::string& name, int nValue)
{
    return Write(std::make_pair('I', name), nValue);
}

bool CBlockTreeDB::ReadInt(const std::string& name, int& nValue)
{
    return Read(std::make_pair('I', name), nValue);
}
bool CBlockTreeDB::LoadBlockIndexGuts(std::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    std::unique_ptr<CLevelDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, uint256()));

    // Load mapBlockIndex
    uint256 nPreviousCheckpoint;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct block index object
                CBlockIndex* pindexNew = insertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev = insertBlockIndex(diskindex.hashPrev);
                pindexNew->pnext = insertBlockIndex(diskindex.hashNext);
                pindexNew->nHeight = diskindex.nHeight;
                pindexNew->nFile = diskindex.nFile;
                pindexNew->nDataPos = diskindex.nDataPos;
                pindexNew->nUndoPos = diskindex.nUndoPos;
                pindexNew->nVersion = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime = diskindex.nTime;
                pindexNew->nBits = diskindex.nBits;
                pindexNew->nNonce = diskindex.nNonce;
                pindexNew->nStatus = diskindex.nStatus;
                pindexNew->nTx = diskindex.nTx;

                //zerocoin
                pindexNew->nAccumulatorCheckpoint = diskindex.nAccumulatorCheckpoint;
                pindexNew->mapZerocoinSupply = diskindex.mapZerocoinSupply;
                pindexNew->vMintDenominationsInBlock = diskindex.vMintDenominationsInBlock;

                //Proof Of Stake
                pindexNew->nMint = diskindex.nMint;
                pindexNew->nMoneySupply = diskindex.nMoneySupply;
                pindexNew->nFlags = diskindex.nFlags;
                pindexNew->nStakeModifier = diskindex.nStakeModifier;
                pindexNew->bnStakeModifierV2 = diskindex.bnStakeModifierV2;
                pindexNew->prevoutStake = diskindex.prevoutStake;
                pindexNew->nStakeTime = diskindex.nStakeTime;
                pindexNew->hashProofOfStake = diskindex.hashProofOfStake;

                if (pindexNew->IsProofOfWork()) {
                    if (!CheckProofOfWork(pindexNew->GetBlockHeader().GetPoWHash(), pindexNew->nBits))
                        return error("LoadBlockIndex() : CheckProofOfWork failed: %s", pindexNew->ToString());
                }

                //populate accumulator checksum map in memory
                if(pindexNew->nAccumulatorCheckpoint != 0 && pindexNew->nAccumulatorCheckpoint != nPreviousCheckpoint) {
                    //Don't load any checkpoints that exist before v2 zwsp. The accumulator is invalid for v1 and not used.
                    if (pindexNew->nHeight >= Params().NEW_PROTOCOLS_STARTHEIGHT())
                        LoadAccumulatorValuesFromDB(pindexNew->nAccumulatorCheckpoint);

                    nPreviousCheckpoint = pindexNew->nAccumulatorCheckpoint;
                }

                pcursor->Next();
            } else {
                return error("%s: failed to read value", __func__);
            }
        } else {
            break;
        }
    }

    return true;
}

CZerocoinDB::CZerocoinDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDBWrapper(GetDataDir() / "zerocoin", nCacheSize, fMemory, fWipe)
{
}

bool CZerocoinDB::WriteCoinMintBatch(const std::vector<std::pair<libzerocoin::PublicCoin, uint256> >& mintInfo)
{
    CLevelDBBatch batch(*this);
    size_t count = 0;
    for (auto it=mintInfo.begin(); it != mintInfo.end(); it++) {
        PublicCoin pubCoin = it->first;
        uint256 hash = GetPubCoinHash(pubCoin.getValue());
        batch.Write(std::make_pair('m', hash), it->second);
        ++count;
    }

    LogPrint(BCLog::ZERO, "Writing %u coin mints to db.\n", (unsigned int)count);
    return WriteBatch(batch, true);
}

bool CZerocoinDB::ReadCoinMint(const CBigNum& bnPubcoin, uint256& hashTx)
{
    return ReadCoinMint(GetPubCoinHash(bnPubcoin), hashTx);
}

bool CZerocoinDB::ReadCoinMint(const uint256& hashPubcoin, uint256& hashTx)
{
    return Read(std::make_pair('m', hashPubcoin), hashTx);
}

bool CZerocoinDB::EraseCoinMint(const CBigNum& bnPubcoin)
{
    uint256 hash = GetPubCoinHash(bnPubcoin);
    return Erase(std::make_pair('m', hash));
}

bool CZerocoinDB::WriteCoinSpendBatch(const std::vector<std::pair<libzerocoin::CoinSpend, uint256> >& spendInfo)
{
    CLevelDBBatch batch(*this);
    size_t count = 0;
    for (auto it=spendInfo.begin(); it != spendInfo.end(); it++) {
        CBigNum bnSerial = it->first.getCoinSerialNumber();
        CDataStream ss(SER_GETHASH, 0);
        ss << bnSerial;
        uint256 hash = Hash(ss.begin(), ss.end());
        batch.Write(std::make_pair('s', hash), it->second);
        ++count;
    }

    LogPrint(BCLog::ZERO, "Writing %u coin spends to db.\n", (unsigned int)count);
    return WriteBatch(batch, true);
}

bool CZerocoinDB::ReadCoinSpend(const CBigNum& bnSerial, uint256& txHash)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnSerial;
    uint256 hash = Hash(ss.begin(), ss.end());

    return Read(std::make_pair('s', hash), txHash);
}

bool CZerocoinDB::ReadCoinSpend(const uint256& hashSerial, uint256 &txHash)
{
    return Read(std::make_pair('s', hashSerial), txHash);
}

bool CZerocoinDB::EraseCoinSpend(const CBigNum& bnSerial)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnSerial;
    uint256 hash = Hash(ss.begin(), ss.end());

    return Erase(std::make_pair('s', hash));
}

bool CZerocoinDB::WipeCoins(const std::string& strType)
{
    if (strType != "spends" && strType != "mints")
        return error("%s: did not recognize type %s", __func__, strType);

    std::unique_ptr<CLevelDBIterator> pcursor(NewIterator());

    char type = (strType == "spends" ? 's' : 'm');
    pcursor->Seek(std::make_pair(type, uint256()));

    // Load mapBlockIndex
    std::set<uint256> setDelete;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == type) {
            uint256 hash;
            if (pcursor->GetValue(hash)) {
                // Construct block index object
                setDelete.insert(hash);
                pcursor->Next();
            } else {
                return error("%s: failed to read value", __func__);
            }
        } else {
            break;
        }
    }

    for (auto& hash : setDelete) {
        if (!Erase(std::make_pair(type, hash)))
            LogPrintf("%s: error failed to delete %s\n", __func__, hash.GetHex());
    }

    return true;
}

bool CZerocoinDB::WriteAccumulatorValue(const uint32_t& nChecksum, const CBigNum& bnValue)
{
    LogPrint(BCLog::ZERO,"%s : checksum:%d val:%s\n", __func__, nChecksum, bnValue.GetHex());
    return Write(std::make_pair('2', nChecksum), bnValue);
}

bool CZerocoinDB::ReadAccumulatorValue(const uint32_t& nChecksum, CBigNum& bnValue)
{
    return Read(std::make_pair('2', nChecksum), bnValue);
}

bool CZerocoinDB::EraseAccumulatorValue(const uint32_t& nChecksum)
{
    LogPrint(BCLog::ZERO, "%s : checksum:%d\n", __func__, nChecksum);
    return Erase(std::make_pair('2', nChecksum));
}
/** Upgrade the database from older formats.
 *
 * Currently implemented: from the per-tx utxo model (0.8..0.14.x) to per-txout.
 */
//bool CCoinsViewDB::Upgrade() {
//    std::unique_ptr<CLevelDBIterator> pcursor(db.NewIterator());
//    pcursor->Seek(std::make_pair(DB_COINS, uint256()));
//    if (!pcursor->Valid()) {
//        return true;
//    }
//
//    int64_t count = 0;
//    LogPrintf("Upgrading utxo-set database...\n");
//    LogPrintf("[0%%]..."); /* Continued */
//    uiInterface.ShowProgress(_("Upgrading UTXO database"), 0, true);
//    size_t batch_size = 1 << 24;
//    CLevelDBBatch batch(db);
//    int reportDone = 0;
//    std::pair<unsigned char, uint256> key;
//    std::pair<unsigned char, uint256> prev_key = {DB_COINS, uint256()};
//    while (pcursor->Valid()) {
//        boost::this_thread::interruption_point();
//        if (ShutdownRequested()) {
//            break;
//        }
//        if (pcursor->GetKey(key) && key.first == DB_COINS) {
//            if (count++ % 256 == 0) {
//                uint32_t high = 0x100 * *key.second.begin() + *(key.second.begin() + 1);
//                int percentageDone = (int)(high * 100.0 / 65536.0 + 0.5);
//                uiInterface.ShowProgress(_("Upgrading UTXO database"), percentageDone, true);
//                if (reportDone < percentageDone/10) {
//                    // report max. every 10% step
//                    LogPrintf("[%d%%]...", percentageDone); /* Continued */
//                    reportDone = percentageDone/10;
//                }
//            }
//            CCoins old_coins;
//            if (!pcursor->GetValue(old_coins)) {
//                return error("%s: cannot parse CCoins record", __func__);
//            }
//            COutPoint outpoint(key.second, 0);
//            for (size_t i = 0; i < old_coins.vout.size(); ++i) {
//                if (!old_coins.vout[i].IsNull() && !old_coins.vout[i].scriptPubKey.IsUnspendable()) {
//                    Coin newcoin(std::move(old_coins.vout[i]), old_coins.nHeight, old_coins.fCoinBase);
//                    outpoint.n = i;
//                    CoinEntry entry(&outpoint);
//                    batch.Write(entry, newcoin);
//                }
//            }
//            batch.Erase(key);
//            if (batch.SizeEstimate() > batch_size) {
//                db.WriteBatch(batch);
//                batch.Clear();
//                db.CompactRange(prev_key, key);
//                prev_key = key;
//            }
//            pcursor->Next();
//        } else {
//            break;
//        }
//    }
//    db.WriteBatch(batch);
//    db.CompactRange({DB_COINS, uint256()}, key);
//    uiInterface.ShowProgress("", 100);
//    uiInterface.ShowProgress("", 100, false);
//    LogPrintf("[%s].\n", ShutdownRequested() ? "CANCELLED" : "DONE");
//    return !ShutdownRequested();
//}
