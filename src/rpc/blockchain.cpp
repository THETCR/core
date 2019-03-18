// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "checkpoints.h"
#include "clientversion.h"
#include "consensus/validation.h"
#include <core_io.h>
#include "main.h"
#include "policy/feerate.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "sync.h"
#include "txdb.h"
#include <util/system.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include "hash.h"
#include "accumulatormap.h"
#include "accumulators.h"
#include "txmempool.h"
#include <wallet/wallet.h>
#include "libzerocoin/Coin.h"
#include <script/descriptor.h>
#include <stdint.h>
#include <fstream>
#include <iostream>
#include <univalue.h>
#include "libzerocoin/bignum.h"

#include <boost/thread/thread.hpp> // boost::thread::interrupt

using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == nullptr) {
        if (chainActive.Tip() == nullptr)
            return 1.0;
        else
            blockindex = chainActive.Tip();
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", blockindex->nVersion);
    result.pushKV("merkleroot", blockindex->hashMerkleRoot.GetHex());
    result.pushKV("time", (int64_t)blockindex->nTime);
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("nonce", (uint64_t)blockindex->nNonce);
    result.pushKV("bits", strprintf("%08x", blockindex->nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());
    result.pushKV("acc_checkpoint", blockindex->nAccumulatorCheckpoint.GetHex());

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", block.GetHash().GetHex());
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.pushKV("confirmations", confirmations);
    result.pushKV("size", (int)::GetSerializeSize(block, PROTOCOL_VERSION));
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", block.nVersion);
    result.pushKV("merkleroot", block.hashMerkleRoot.GetHex());
    result.pushKV("acc_checkpoint", block.nAccumulatorCheckpoint.GetHex());
    UniValue txs(UniValue::VARR);
    for (const auto& tx: block.vtx) {
        if (txDetails) {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(*tx, uint256(0), objTx);
            txs.push_back(objTx);
        } else
            txs.push_back(tx->GetHash().GetHex());
    }
    result.pushKV("tx", txs);
    result.pushKV("time", block.GetBlockTime());
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("nonce", (uint64_t)block.nNonce);
    result.pushKV("bits", strprintf("%08x", block.nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    CBlockIndex* pnext = chainActive.Next(blockindex);
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());

    result.pushKV("moneysupply",ValueFromAmount(blockindex->nMoneySupply));

    UniValue zwspObj(UniValue::VOBJ);
    for (auto denom : libzerocoin::zerocoinDenomList) {
        zwspObj.pushKV(to_string(denom), ValueFromAmount(blockindex->mapZerocoinSupply.at(denom) * (denom*COIN)));
    }
    zwspObj.pushKV("total", ValueFromAmount(blockindex->GetZerocoinSupply()));
    result.pushKV("zWSPsupply", zwspObj);

    return result;
}

UniValue getblockcount(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"

            "\nResult:\n"
            "n    (numeric) The current block count\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockcount", "") + HelpExampleRpc("getblockcount", ""));

    LOCK(cs_main);
    return chainActive.Height();
}

UniValue getbestblockhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"

            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"

            "\nExamples\n" +
            HelpExampleCli("getbestblockhash", "") + HelpExampleRpc("getbestblockhash", ""));

    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash().GetHex();
}

UniValue getdifficulty(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"

            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"

            "\nExamples:\n" +
            HelpExampleCli("getdifficulty", "") + HelpExampleRpc("getdifficulty", ""));

    LOCK(cs_main);
    return GetDifficulty();
}


UniValue mempoolToJSON(bool fVerbose = false)
{
    if (fVerbose) {
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        for (const CTxMemPoolEntry& e: mempool.mapTx) {
            const uint256& hash = e.GetSharedTx()->GetHash();
            UniValue info(UniValue::VOBJ);
            info.pushKV("size", (int)e.GetTxSize());
            info.pushKV("fee", ValueFromAmount(e.GetFee()));
            info.pushKV("time", e.GetTime());
            info.pushKV("height", (int)e.GetHeight());
//            info.pushKV("startingpriority", e.GetPriority(e.GetHeight()));
//            info.pushKV("currentpriority", e.GetPriority(chainActive.Height()));
            const CTransaction& tx = e.GetTx();
            set<string> setDepends;
            for (const CTxIn& txin: tx.vin) {
                if (mempool.exists(txin.prevout.hash))
                    setDepends.insert(txin.prevout.hash.ToString());
            }

            UniValue depends(UniValue::VARR);
            for(const std::string& dep: setDepends) {
                depends.push_back(dep);
            }

            info.pushKV("depends", depends);
            o.pushKV(hash.ToString(), info);
        }
        return o;
    } else {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        for (const uint256& hash: vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getrawmempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of std::string transaction ids.\n"

            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"

            "\nResult: (for verbose = false):\n"
            "[                     (json array of std::string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"

            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            "    \"size\" : n,             (numeric) transaction size in bytes\n"
            "    \"fee\" : n,              (numeric) transaction fee in wispr\n"
            "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
            "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
            "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
            "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
            "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
            "        \"transactionid\",    (string) parent transaction id\n"
            "       ... ]\n"
            "  }, ...\n"
            "]\n"

            "\nExamples\n" +
            HelpExampleCli("getrawmempool", "true") + HelpExampleRpc("getrawmempool", "true"));

    LOCK(cs_main);

    bool fVerbose = false;
    if (request.params.size() > 0)
        fVerbose = request.params[0].get_bool();

    return mempoolToJSON(fVerbose);
}

UniValue getblockhash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"

            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"

            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockhash", "1000") + HelpExampleRpc("getblockhash", "1000"));

    LOCK(cs_main);

    int nHeight = request.params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

UniValue getblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "getblock \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a std::string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbose is true, returns an Object with information about block <hash>.\n"

            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"

            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of std::string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "  \"moneysupply\" : \"supply\"       (numeric) The money supply when this block was added to the blockchain\n"
            "  \"zWSPsupply\" :\n"
            "  {\n"
            "     \"1\" : n,            (numeric) supply of 1 zWSP denomination\n"
            "     \"5\" : n,            (numeric) supply of 5 zWSP denomination\n"
            "     \"10\" : n,           (numeric) supply of 10 zWSP denomination\n"
            "     \"50\" : n,           (numeric) supply of 50 zWSP denomination\n"
            "     \"100\" : n,          (numeric) supply of 100 zWSP denomination\n"
            "     \"500\" : n,          (numeric) supply of 500 zWSP denomination\n"
            "     \"1000\" : n,         (numeric) supply of 1000 zWSP denomination\n"
            "     \"5000\" : n,         (numeric) supply of 5000 zWSP denomination\n"
            "     \"total\" : n,        (numeric) The total supply of all zWSP denominations\n"
            "  }\n"
            "}\n"

            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A std::string that is serialized, hex-encoded data for block 'hash'.\n"

            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    LOCK(cs_main);

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (request.params.size() > 1)
        fVerbose = request.params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!ReadBlockFromDisk(block, pblockindex))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex);
}

struct CCoinsStats {
  int nHeight;
  uint256 hashBlock;
  uint64_t nTransactions;
  uint64_t nTransactionOutputs;
  uint64_t nSerializedSize;
  uint256 hashSerialized;
  CAmount nTotalAmount;

  CCoinsStats() : nHeight(0), hashBlock(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), hashSerialized(0), nTotalAmount(0) {}
};

static void ApplyStats(CCoinsStats &stats, CHashWriter& ss, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    ss << hash;
    ss << VARINT(outputs.begin()->second.nHeight * 2 + outputs.begin()->second.fCoinBase ? 1u : 0u);
    stats.nTransactions++;
    for (const auto& output : outputs) {
        ss << VARINT(output.first + 1);
        ss << output.second.out.scriptPubKey;
        ss << VARINT(output.second.out.nValue, VarIntMode::NONNEGATIVE_SIGNED);
        stats.nTransactionOutputs++;
        stats.nTotalAmount += output.second.out.nValue;
//        stats.nBogoSize += 32 /* txid */ + 4 /* vout index */ + 4 /* height + coinbase */ + 8 /* amount */ +
//                           2 /* scriptPubKey len */ + output.second.out.scriptPubKey.size() /* scriptPubKey */;
    }
    ss << VARINT(0u);
}


//! Calculate statistics about the unspent transaction output set
static bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    assert(pcursor);

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(cs_main);
        stats.nHeight = LookupBlockIndex(stats.hashBlock)->nHeight;
    }
    ss << stats.hashBlock;
    uint256 prevkey;
    std::map<uint32_t, Coin> outputs;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                ApplyStats(stats, ss, prevkey, outputs);
                outputs.clear();
            }
            prevkey = key.hash;
            outputs[key.n] = std::move(coin);
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    if (!outputs.empty()) {
        ApplyStats(stats, ss, prevkey, outputs);
    }
    stats.hashSerialized = ss.GetHash();
//    stats.nDiskSize = view->EstimateSize();
    return true;
}

UniValue getblockheader(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a std::string that is serialized, hex-encoded data for block 'hash' header.\n"
            "If verbose is true, returns an Object with information about block <hash> header.\n"

            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"

            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "}\n"

            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A std::string that is serialized, hex-encoded data for block 'hash' header.\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (request.params.size() > 1)
        fVerbose = request.params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockheaderToJSON(pblockindex);
}

UniValue gettxoutsetinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"

            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("gettxoutsetinfo", "") + HelpExampleRpc("gettxoutsetinfo", ""));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (GetUTXOStats(pcoinsTip.get(), stats)) {
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("transactions", (int64_t)stats.nTransactions);
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("bytes_serialized", (int64_t)stats.nSerializedSize);
        ret.pushKV("hash_serialized", stats.hashSerialized.GetHex());
        ret.pushKV("total_amount", ValueFromAmount(stats.nTotalAmount));
    }
    return ret;
}

UniValue gettxout(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"

            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional) Whether to included the mem pool\n"

            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in btc\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of std::string) array of wispr addresses\n"
            "     \"wispraddress\"   	 	(string) wispr address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nView the details\n" +
            HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("gettxout", "\"txid\", 1"));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);
    int n = request.params[1].get_int();
    COutPoint out(hash, n);
    bool fMempool = true;
    if (request.params.size() > 2)
        fMempool = request.params[2].get_bool();

    Coin coin;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip.get(), mempool);
        if (!view.GetCoin(out, coin) || mempool.isSpent(out)) {
            return NullUniValue;
        }
    } else {
        if (!pcoinsTip->GetCoin(out, coin)) {
            return NullUniValue;
        }
    }

    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    CBlockIndex* pindex = it->second;
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if ((unsigned int)coin.nHeight == MEMPOOL_HEIGHT)
        ret.pushKV("confirmations", 0);
    else
        ret.pushKV("confirmations", pindex->nHeight - coin.nHeight + 1);
    ret.pushKV("value", ValueFromAmount(coin.out.nValue));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coin.out.scriptPubKey, o, true);
    ret.pushKV("scriptPubKey", o);
    ret.pushKV("version", 0);
    ret.pushKV("coinbase", coin.fCoinBase);

    return ret;
}

UniValue verifychain(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "verifychain ( numblocks )\n"
            "\nVerifies blockchain database.\n"

            "\nArguments:\n"
            "1. numblocks    (numeric, optional, default=288, 0=all) The number of blocks to check.\n"

            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"

            "\nExamples:\n" +
            HelpExampleCli("verifychain", "") + HelpExampleRpc("verifychain", ""));

    LOCK(cs_main);

    int nCheckLevel = 4;
    int nCheckDepth = gArgs.GetArg("-checkblocks", 288);
    if (request.params.size() > 0)
        nCheckDepth = request.params[0].get_int();

    fVerifyingBlocks = true;
    bool fVerified = CVerifyDB().VerifyDB(pcoinsTip.get(), nCheckLevel, nCheckDepth);
    fVerifyingBlocks = false;

    return fVerified;
}

/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int minVersion, CBlockIndex* pindex, int nRequired)
{
    int nFound = 0;
    CBlockIndex* pstart = pindex;
    for (int i = 0; i < Params().ToCheckBlockUpgradeMajority() && pstart != nullptr; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    UniValue rv(UniValue::VOBJ);
    rv.pushKV("status", nFound >= nRequired);
    rv.pushKV("found", nFound);
    rv.pushKV("required", nRequired);
    rv.pushKV("window", Params().ToCheckBlockUpgradeMajority());
    return rv;
}
static UniValue SoftForkDesc(const std::string &name, int version, CBlockIndex* pindex)
{
    UniValue rv(UniValue::VOBJ);
    rv.pushKV("id", name);
    rv.pushKV("version", version);
    rv.pushKV("enforce", SoftForkMajorityDesc(version, pindex, Params().EnforceBlockUpgradeMajority()));
    rv.pushKV("reject", SoftForkMajorityDesc(version, pindex, Params().RejectBlockOutdatedMajority()));
    return rv;
}

UniValue getblockchaininfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"

            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) block version\n"
            "        \"enforce\": {           (object) progress toward enforcing the softfork rules for new-version blocks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "           \"found\": xx,        (numeric) number of blocks with the new version found\n"
            "           \"required\": xx,     (numeric) number of blocks required to trigger\n"
            "           \"window\": xx,       (numeric) maximum size of examined window of recent blocks\n"
            "        },\n"
            "        \"reject\": { ... }      (object) progress toward rejecting pre-softfork blocks (same fields as \"enforce\")\n"
            "     }, ...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockchaininfo", "") + HelpExampleRpc("getblockchaininfo", ""));

    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", Params().NetworkIDString());
    obj.pushKV("blocks", (int)chainActive.Height());
    obj.pushKV("headers", pindexBestHeader ? pindexBestHeader->nHeight : -1);
    obj.pushKV("bestblockhash", chainActive.Tip()->GetBlockHash().GetHex());
    obj.pushKV("difficulty", (double)GetDifficulty());
    obj.pushKV("verificationprogress", Checkpoints::GuessVerificationProgress(chainActive.Tip()));
    obj.pushKV("chainwork", chainActive.Tip()->nChainWork.GetHex());
    CBlockIndex* tip = chainActive.Tip();
    UniValue softforks(UniValue::VARR);
    softforks.push_back(SoftForkDesc("bip65", 5, tip));
    obj.pushKV("softforks",             softforks);
    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight {
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
            return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue getchaintips(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"

            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"

            "\nExamples:\n" +
            HelpExampleCli("getchaintips", "") + HelpExampleRpc("getchaintips", ""));

    LOCK(cs_main);

    /* Build up a list of chain tips.  We start with the list of all
       known blocks, and successively remove blocks that appear as pprev
       of another block.  */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    for (const std::pair<const uint256, CBlockIndex*> & item : mapBlockIndex)
        setTips.insert(item.second);
    for (const std::pair<const uint256, CBlockIndex*> & item : mapBlockIndex) {
        const CBlockIndex* pprev = item.second->pprev;
        if (pprev)
            setTips.erase(pprev);
    }

    // Always report the currently active tip.
    setTips.insert(chainActive.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block: setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->nHeight - chainActive.FindFork(block)->nHeight;
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (chainActive.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (block->nChainTx == 0) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(obj);
    }

    return res;
}

UniValue getfeeinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "getfeeinfo blocks\n"
            "\nReturns details of transaction fees over the last n blocks.\n"

            "\nArguments:\n"
            "1. blocks     (int, required) the number of blocks to get transaction data from\n"

            "\nResult:\n"
            "{\n"
            "  \"txcount\": xxxxx                (numeric) Current tx count\n"
            "  \"txbytes\": xxxxx                (numeric) Sum of all tx sizes\n"
            "  \"ttlfee\": xxxxx                 (numeric) Sum of all fees\n"
            "  \"feeperkb\": xxxxx               (numeric) Average fee per kb over the block range\n"
            "  \"rec_highpriorityfee_perkb\": xxxxx    (numeric) Recommended fee per kb to use for a high priority tx\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getfeeinfo", "5") + HelpExampleRpc("getfeeinfo", "5"));

    LOCK(cs_main);

    int nBlocks = request.params[0].get_int();
    int nBestHeight = chainActive.Height();
    int nStartHeight = nBestHeight - nBlocks;
    if (nBlocks < 0 || nStartHeight <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid start height");

    CAmount nFees = 0;
    int64_t nBytes = 0;
    int64_t nTotal = 0;
    for (int i = nStartHeight; i <= nBestHeight; i++) {
        CBlockIndex* pindex = chainActive[i];
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex))
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to read block from disk");

        CAmount nValueIn = 0;
        CAmount nValueOut = 0;
        for (const auto& tx : block.vtx) {
            if (tx->IsCoinBase() || tx->IsCoinStake())
                continue;

            for (unsigned int j = 0; j < tx->vin.size(); j++) {
                if (tx->vin[j].scriptSig.IsZerocoinSpend()) {
                    nValueIn += tx->vin[j].nSequence * COIN;
                    continue;
                }

                COutPoint prevout = tx->vin[j].prevout;
                CTransaction txPrev;
                uint256 hashBlock;
                if(!GetTransaction(prevout.hash, txPrev, hashBlock, true))
                    throw JSONRPCError(RPC_DATABASE_ERROR, "failed to read tx from disk");
                nValueIn += txPrev.vout[prevout.n].nValue;
            }

            for (unsigned int j = 0; j < tx->vout.size(); j++) {
                nValueOut += tx->vout[j].nValue;
            }

            nFees += nValueIn - nValueOut;
            nBytes += GetSerializeSize(tx, CLIENT_VERSION);
            nTotal++;
        }

        pindex = chainActive.Next(pindex);
        if (!pindex)
            break;
    }

    UniValue ret(UniValue::VOBJ);
    CFeeRate nFeeRate = CFeeRate(nFees, nBytes);
    ret.pushKV("txcount", (int64_t)nTotal);
    ret.pushKV("txbytes", (int64_t)nBytes);
    ret.pushKV("ttlfee", FormatMoney(nFees));
    ret.pushKV("feeperkb", FormatMoney(nFeeRate.GetFeePerK()));
    ret.pushKV("rec_highpriorityfee_perkb", FormatMoney(nFeeRate.GetFeePerK() + 1000));

    return ret;
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("size", (int64_t) mempool.size());
    ret.pushKV("bytes", (int64_t) mempool.GetTotalTxSize());
    //ret.pushKV("usage", (int64_t) mempool.DynamicMemoryUsage()));

    return ret;
}

UniValue getmempoolinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"

            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx                (numeric) Current tx count\n"
            "  \"bytes\": xxxxx               (numeric) Sum of all tx sizes\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getmempoolinfo", "") + HelpExampleRpc("getmempoolinfo", ""));

    return mempoolInfoToJSON();
}

UniValue invalidateblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"

            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"

            "\nExamples:\n" +
            HelpExampleCli("invalidateblock", "\"blockhash\"") + HelpExampleRpc("invalidateblock", "\"blockhash\""));

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        InvalidateBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"

            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"

            "\nExamples:\n" +
            HelpExampleCli("reconsiderblock", "\"blockhash\"") + HelpExampleRpc("reconsiderblock", "\"blockhash\""));

    std::string strHash = request.params[0].get_str();
    uint256 hash(strHash);
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue findserial(const JSONRPCRequest& request)
{
    if(request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "findserial \"serial\"\n"
            "\nSearches the zerocoin database for a zerocoin spend transaction that contains the specified serial\n"

            "\nArguments:\n"
            "1. serial   (string, required) the serial of a zerocoin spend to search for.\n"

            "\nResult:\n"
            "{\n"
            "  \"success\": true|false        (boolean) Whether the serial was found\n"
            "  \"txid\": \"xxx\"              (string) The transaction that contains the spent serial\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("findserial", "\"serial\"") + HelpExampleRpc("findserial", "\"serial\""));

    std::string strSerial = request.params[0].get_str();
    CBigNum bnSerial = 0;
    bnSerial.SetHex(strSerial);
    if (!bnSerial)
	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid serial");

    uint256 txid = 0;
    bool fSuccess = zerocoinDB->ReadCoinSpend(bnSerial, txid);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("success", fSuccess);
    ret.pushKV("txid", txid.GetHex());
    return ret;
}

UniValue getaccumulatorvalues(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "getaccumulatorvalues \"height\"\n"
                    "\nReturns the accumulator values associated with a block height\n"

                    "\nArguments:\n"
                    "1. height   (numeric, required) the height of the checkpoint.\n"

                    "\nExamples:\n" +
            HelpExampleCli("getaccumulatorvalues", "\"height\"") + HelpExampleRpc("getaccumulatorvalues", "\"height\""));

    int nHeight = request.params[0].get_int();

    CBlockIndex* pindex = chainActive[nHeight];
    if (!pindex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid block height");

    UniValue ret(UniValue::VARR);
    for (libzerocoin::CoinDenomination denom : libzerocoin::zerocoinDenomList) {
        CBigNum bnValue;
        if(!GetAccumulatorValueFromDB(pindex->nAccumulatorCheckpoint, denom, bnValue))
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to find value in database");

        UniValue obj(UniValue::VOBJ);
        obj.pushKV(std::to_string(denom), bnValue.GetHex());
        ret.push_back(obj);
    }

    return ret;
}


UniValue getaccumulatorwitness(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
                "getaccumulatorwitness \"commitmentCoinValue, coinDenomination\"\n"
                "\nReturns the accumulator witness value associated with the coin\n"

                "\nArguments:\n"
                "1. coinValue             (string, required) the commitment value of the coin in HEX.\n"
                "2. coinDenomination      (numeric, required) the coin denomination.\n"

                "\nResult:\n"
                "{\n"
                "  \"Accumulator Value\": \"xxx\"  (string) Accumulator hex value\n"
                "  \"Denomination\": \"d\"         (integer) Accumulator denomination\n"
                "  \"Mints added\": \"d\"          (integer) Number of mints added to the accumulator\n"
                "  \"Witness Value\": \"xxx\"      (string) Witness hex value\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getaccumulatorwitness", "\"5fb87fb7bb638e83bfc14bcf33ac6f8064c9884dc72a4e652666abcf42cc47f9da0a7aca58076b0122a19b25629a6b6e7461f188baa7c00865b862cdb270d934873648aa12dd66e3242da40e4c17c78b70fded35e2d9c72933b455fadce9684586b1d48b10570d66feebe51ccebb1d98595217d06f41e66d5a0d9246d46ec3dd\" 5") + HelpExampleRpc("getaccumulatorwitness", "\"5fb87fb7bb638e83bfc14bcf33ac6f8064c9884dc72a4e652666abcf42cc47f9da0a7aca58076b0122a19b25629a6b6e7461f188baa7c00865b862cdb270d934873648aa12dd66e3242da40e4c17c78b70fded35e2d9c72933b455fadce9684586b1d48b10570d66feebe51ccebb1d98595217d06f41e66d5a0d9246d46ec3dd\", 5"));


    CBigNum coinValue;
    coinValue.SetHex(request.params[0].get_str());

    int d = request.params[1].get_int();
    libzerocoin::CoinDenomination denomination = libzerocoin::IntToZerocoinDenomination(d);
    libzerocoin::ZerocoinParams* zcparams = Params().Zerocoin_Params(false);

    // Public coin
    libzerocoin::PublicCoin pubCoin(zcparams, coinValue, denomination);

    //Compute Accumulator and Witness
    libzerocoin::Accumulator accumulator(zcparams, pubCoin.getDenomination());
    libzerocoin::AccumulatorWitness witness(zcparams, accumulator, pubCoin);
    std::string strFailReason = "";
    int nMintsAdded = 0;
    CZerocoinSpendReceipt receipt;
    if (!GenerateAccumulatorWitness(pubCoin, accumulator, witness, 100, nMintsAdded, strFailReason)) {
        receipt.SetStatus(_(strFailReason.c_str()), ZWSP_FAILED_ACCUMULATOR_INITIALIZATION);
        throw JSONRPCError(RPC_DATABASE_ERROR, receipt.GetStatusMessage());
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("Accumulator Value", accumulator.getValue().GetHex());
    obj.pushKV("Denomination", accumulator.getDenomination());
    obj.pushKV("Mints added",nMintsAdded);
    obj.pushKV("Witness Value", witness.getValue().GetHex());

    return obj;
}

UniValue getmintsinblocks(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() != 3)
        throw runtime_error(
                "getmintsinblocks \"height\" \"range\" \"coinDenomination\"\n"
                "\nReturns the number of mints of a certain denomination"
                "\noccurred in blocks [height, height+1, height+2, ..., height+range-1]\n"

                "\nArguments:\n"
                "1. height             (numeric, required) block height where the search starts.\n"
                "2. range              (numeric, required) number of blocks to include.\n"
                "2. coinDenomination   (numeric, required) coin denomination.\n"

                "\nResult:\n"
                "{\n"
                "  \"Starting block\": \"x\"           (integer) First counted block\n"
                "  \"Ending block\": \"x\"             (integer) Last counted block\n"
                "  \"Number of d-denom mints\": \"x\"  (integer) number of mints of the required d denomination\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getmintsinblocks", "1200000 1000 5") +
                HelpExampleRpc("getmintsinblocks", "1200000, 1000, 5"));

    int nBestHeight = chainActive.Height();

    int heightStart = request.params[0].get_int();
    if (heightStart < Params().NEW_PROTOCOLS_STARTHEIGHT())
        heightStart = Params().NEW_PROTOCOLS_STARTHEIGHT();

    int range = request.params[1].get_int();
    if (range < 1)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range. Must be strictly positive.");

    int heightEnd = heightStart + range - 1;
    if (heightEnd > nBestHeight)
        heightEnd = nBestHeight;

    int d = request.params[2].get_int();
    libzerocoin::CoinDenomination denom = libzerocoin::IntToZerocoinDenomination(d);
    if (denom == libzerocoin::CoinDenomination::ZQ_ERROR)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid denomination. Must be in {1, 5, 10, 50, 100, 500, 1000, 5000}");

    int num_of_mints = 0;
    CBlockIndex* pindex = chainActive[heightStart];

    while (true) {
        num_of_mints += count(pindex->vMintDenominationsInBlock.begin(), pindex->vMintDenominationsInBlock.end(), denom);
        if (pindex->nHeight < heightEnd)
            pindex = chainActive.Next(pindex);
        else
            break;
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("Starting block", heightStart);
    obj.pushKV("Ending block", pindex->nHeight);
    obj.pushKV("Number of "+ std::to_string(d) +"-denom mints", num_of_mints);

    return obj;
}
