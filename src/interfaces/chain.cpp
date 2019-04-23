// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/chain.h>

#include <chain.h>
#include <chainparams.h>
#include <interfaces/handler.h>
#include <interfaces/wallet.h>
#include <net.h>
#include <node/coin.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <policy/settings.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <shutdown.h>
#include <sync.h>
#include <threadsafety.h>
#include <timedata.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <uint256.h>
#include <univalue.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>

#include <memory>
#include <utility>

//!< WISPR
#include <swifttx.h>
#include <netmessagemaker.h>
#include <txdb.h>
#include <net.h>
#include <zwspchain.h>

namespace interfaces {
namespace {

class LockImpl : public Chain::Lock
{
    Optional<int> getHeight() override
    {
        int height = ::chainActive.Height();
        if (height >= 0) {
            return height;
        }
        return nullopt;
    }
    Optional<int> getBlockHeight(const uint256& hash) override
    {
        CBlockIndex* block = LookupBlockIndex(hash);
        if (block && ::chainActive.Contains(block)) {
            return block->nHeight;
        }
        return nullopt;
    }
    int getBlockDepth(const uint256& hash) override
    {
        const Optional<int> tip_height = getHeight();
        const Optional<int> height = getBlockHeight(hash);
        return tip_height && height ? *tip_height - *height + 1 : 0;
    }
    uint256 getBlockHash(int height) override
    {
        CBlockIndex* block = ::chainActive[height];
        assert(block != nullptr);
        return block->GetBlockHash();
    }
    int64_t getBlockTime(int height) override
    {
        CBlockIndex* block = ::chainActive[height];
        assert(block != nullptr);
        return block->GetBlockTime();
    }
    int64_t getBlockMedianTimePast(int height) override
    {
        CBlockIndex* block = ::chainActive[height];
        assert(block != nullptr);
        return block->GetMedianTimePast();
    }
    bool haveBlockOnDisk(int height) override
    {
        CBlockIndex* block = ::chainActive[height];
        return block && ((block->nStatus & BLOCK_HAVE_DATA) != 0) && block->nTx > 0;
    }
    Optional<int> findFirstBlockWithTime(int64_t time, uint256* hash) override
    {
        CBlockIndex* block = ::chainActive.FindEarliestAtLeast(time);
        if (block) {
            if (hash) *hash = block->GetBlockHash();
            return block->nHeight;
        }
        return nullopt;
    }
    Optional<int> findFirstBlockWithTimeAndHeight(int64_t time, int height) override
    {
        // TODO: Could update CChain::FindEarliestAtLeast() to take a height
        // parameter and use it with std::lower_bound() to make this
        // implementation more efficient and allow combining
        // findFirstBlockWithTime and findFirstBlockWithTimeAndHeight into one
        // method.
        for (CBlockIndex* block = ::chainActive[height]; block; block = ::chainActive.Next(block)) {
            if (block->GetBlockTime() >= time) {
                return block->nHeight;
            }
        }
        return nullopt;
    }
    Optional<int> findPruned(int start_height, Optional<int> stop_height) override
    {
        if (::fPruneMode) {
            CBlockIndex* block = stop_height ? ::chainActive[*stop_height] : ::chainActive.Tip();
            while (block && block->nHeight >= start_height) {
                if ((block->nStatus & BLOCK_HAVE_DATA) == 0) {
                    return block->nHeight;
                }
                block = block->pprev;
            }
        }
        return nullopt;
    }
    Optional<int> findFork(const uint256& hash, Optional<int>* height) override
    {
        const CBlockIndex* block = LookupBlockIndex(hash);
        const CBlockIndex* fork = block ? ::chainActive.FindFork(block) : nullptr;
        if (height) {
            if (block) {
                *height = block->nHeight;
            } else {
                height->reset();
            }
        }
        if (fork) {
            return fork->nHeight;
        }
        return nullopt;
    }
    bool isPotentialTip(const uint256& hash) override
    {
        if (::chainActive.Tip()->GetBlockHash() == hash) return true;
        CBlockIndex* block = LookupBlockIndex(hash);
        return block && block->GetAncestor(::chainActive.Height()) == ::chainActive.Tip();
    }
    CBlockLocator getTipLocator() override { return ::chainActive.GetLocator(); }
    Optional<int> findLocatorFork(const CBlockLocator& locator) override
    {
        LockAnnotation lock(::cs_main);
        if (CBlockIndex* fork = FindForkInGlobalIndex(::chainActive, locator)) {
            return fork->nHeight;
        }
        return nullopt;
    }
    bool checkFinalTx(const CTransaction& tx) override
    {
        LockAnnotation lock(::cs_main);
        return CheckFinalTx(tx);
    }
    bool submitToMemoryPool(const CTransactionRef& tx, CAmount absurd_fee, CValidationState& state) override
    {
        LockAnnotation lock(::cs_main);
        return AcceptToMemoryPool(::mempool, state, tx, nullptr /* missing inputs */, nullptr /* txn replaced */,
            false /* bypass limits */, absurd_fee);
    }

    int getTransactionLockSignatures(const uint256& txid) override {
        //compile consessus vote
        std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(txid);
        if (i != mapTxLocks.end()) {
            return (*i).second.CountSignatures();
        }

        return -1;
    };

    bool isTransactionLockTimedOut(const uint256& txid) override {
        //compile consessus vote
        std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(txid);
        if (i != mapTxLocks.end()) {
            return GetTime() > (*i).second.nTimeout;
        }

        return false;
    };

    bool isSporkActive(int nSporkID) override
    {
        return IsSporkActive(nSporkID);
    }

    int64_t getSporkValue(int nSporkID) override
    {
        return GetSporkValue(nSporkID);
    }

    int getIXConfirmations(const uint256& txid) override {
        int sigs = 0;

        std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(txid);
        if (i != mapTxLocks.end()) {
            sigs = (*i).second.CountSignatures();
        }
        if (sigs >= SWIFTTX_SIGNATURES_REQUIRED) {
            return nSwiftTXDepth;
        }

        return 0;
    };
    bool isBlockInIndex(const uint256 hash) override
    {
        CBlockIndex* block = LookupBlockIndex(hash);
        if (block) {
            return true;
        }
        return false;
    };
     bool isTransactionInChain(const uint256& txId, int& nHeightTx, CTransactionRef& tx) override
     {
         return IsTransactionInChain(txId, nHeightTx, tx);
     }
     bool isTransactionInChain(const uint256& txId, int& nHeightTx) override
     {
         return IsTransactionInChain(txId, nHeightTx);
     }
     bool isBlockHashInChain(const uint256& hashBlock) override
     {
         return IsBlockHashInChain(hashBlock);
     }
    bool isSerialInBlockchain(const CBigNum& bnSerial, int& nHeightTx) override
    {
        return IsSerialInBlockchain(bnSerial, nHeightTx);
    }
     bool isSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend) override
    {
         return IsSerialInBlockchain(hashSerial, nHeightTx, txidSpend);
    }
    bool isSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransactionRef& tx) override
    {
        return IsSerialInBlockchain (hashSerial, nHeightTx, txidSpend, tx);
    }
    void sendObfuscationDenominate(std::vector<CTxIn>& vin, std::vector<CTxOut>& vout, CAmount amount, CConnman* connman) override
    {
        return obfuScationPool.SendObfuscationDenominate(vin, vout, amount, connman);
    }
    int getObfuscationEntriesCount() override
    {
        return obfuScationPool.GetEntriesCount();
    }
    int getObfuscationState() override
    {
         return obfuScationPool.GetState();
    }
    int getObfuscationSessionDenom() override
    {
        return obfuScationPool.sessionDenom;
    }
    int getObfuscationDenominations(const std::vector<CTxOut>& vout, bool fSingleRandomDenom) override
    {
         return obfuScationPool.GetDenominations(vout, fSingleRandomDenom);
    }
};

class LockingStateImpl : public LockImpl, public UniqueLock<CCriticalSection>
{
    using UniqueLock::UniqueLock;
};

class NotificationsHandlerImpl : public Handler, CValidationInterface
{
public:
    explicit NotificationsHandlerImpl(Chain& chain, Chain::Notifications& notifications)
        : m_chain(chain), m_notifications(&notifications)
    {
        RegisterValidationInterface(this);
    }
    ~NotificationsHandlerImpl() override { disconnect(); }
    void disconnect() override
    {
        if (m_notifications) {
            m_notifications = nullptr;
            UnregisterValidationInterface(this);
        }
    }
    void TransactionAddedToMempool(const CTransactionRef& tx) override
    {
        m_notifications->TransactionAddedToMempool(tx);
    }
    void TransactionRemovedFromMempool(const CTransactionRef& tx) override
    {
        m_notifications->TransactionRemovedFromMempool(tx);
    }
    void BlockConnected(const std::shared_ptr<const CBlock>& block,
        const CBlockIndex* index,
        const std::vector<CTransactionRef>& tx_conflicted) override
    {
        m_notifications->BlockConnected(*block, tx_conflicted);
    }
    void BlockDisconnected(const std::shared_ptr<const CBlock>& block) override
    {
        m_notifications->BlockDisconnected(*block);
    }
    void UpdatedBlockTip(const CBlockIndex* index, const CBlockIndex* fork_index, bool is_ibd) override
    {
        m_notifications->UpdatedBlockTip();
    }
    void ChainStateFlushed(const CBlockLocator& locator) override { m_notifications->ChainStateFlushed(locator); }

    void UpdatedTransaction(const uint256 &hash) override
    {
        m_notifications->UpdatedTransaction(hash);
    }
    void Inventory(const uint256 &hash) override {
        m_notifications->Inventory(hash);
    }
    Chain& m_chain;
    Chain::Notifications* m_notifications;
};

class RpcHandlerImpl : public Handler
{
public:
    RpcHandlerImpl(const CRPCCommand& command) : m_command(command), m_wrapped_command(&command)
    {
        m_command.actor = [this](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
            if (!m_wrapped_command) return false;
            try {
                return m_wrapped_command->actor(request, result, last_handler);
            } catch (const UniValue& e) {
                // If this is not the last handler and a wallet not found
                // exception was thrown, return false so the next handler can
                // try to handle the request. Otherwise, reraise the exception.
                if (!last_handler) {
                    const UniValue& code = e["code"];
                    if (code.isNum() && code.get_int() == RPC_WALLET_NOT_FOUND) {
                        return false;
                    }
                }
                throw;
            }
        };
        ::tableRPC.appendCommand(m_command.name, &m_command);
    }

    void disconnect() override final
    {
        if (m_wrapped_command) {
            m_wrapped_command = nullptr;
            ::tableRPC.removeCommand(m_command.name, &m_command);
        }
    }

    ~RpcHandlerImpl() override { disconnect(); }

    CRPCCommand m_command;
    const CRPCCommand* m_wrapped_command;
};

class ChainImpl : public Chain
{
public:
    std::unique_ptr<Chain::Lock> lock(bool try_lock) override
    {
        auto result = MakeUnique<LockingStateImpl>(::cs_main, "cs_main", __FILE__, __LINE__, try_lock);
        if (try_lock && result && !*result) return {};
        // std::move necessary on some compilers due to conversion from
        // LockingStateImpl to Lock pointer
        return std::move(result);
    }
    std::unique_ptr<Chain::Lock> assumeLocked() override { return MakeUnique<LockImpl>(); }
    bool findBlock(const uint256& hash, CBlock* block, int64_t* time, int64_t* time_max) override
    {
        CBlockIndex* index;
        {
            LOCK(cs_main);
            index = LookupBlockIndex(hash);
            if (!index) {
                return false;
            }
            if (time) {
                *time = index->GetBlockTime();
            }
            if (time_max) {
                *time_max = index->GetBlockTimeMax();
            }
        }
        if (block && !ReadBlockFromDisk(*block, index, Params().GetConsensus())) {
            block->SetNull();
        }
        return true;
    }
    void findCoins(std::map<COutPoint, Coin>& coins) override { return FindCoins(coins); }
    double guessVerificationProgress(const uint256& block_hash) override
    {
        LOCK(cs_main);
        return GuessVerificationProgress(Params().TxData(), LookupBlockIndex(block_hash));
    }
    RBFTransactionState isRBFOptIn(const CTransaction& tx) override
    {
        LOCK(::mempool.cs);
        return IsRBFOptIn(tx, ::mempool);
    }
    bool hasDescendantsInMempool(const uint256& txid) override
    {
        LOCK(::mempool.cs);
        auto it = ::mempool.GetIter(txid);
        return it && (*it)->GetCountWithDescendants() > 1;
    }
    void relayTransaction(const uint256& txid) override
    {
        CInv inv(MSG_TX, txid);
        g_connman->ForEachNode([&inv](CNode* node) { node->PushInventory(inv); });
    }
    void getTransactionAncestry(const uint256& txid, size_t& ancestors, size_t& descendants) override
    {
        ::mempool.GetTransactionAncestry(txid, ancestors, descendants);
    }
    bool checkChainLimits(const CTransactionRef& tx) override
    {
        LockPoints lp;
        CTxMemPoolEntry entry(tx, 0, 0, 0, false, 0, lp);
        CTxMemPool::setEntries ancestors;
        auto limit_ancestor_count = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        auto limit_ancestor_size = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        auto limit_descendant_count = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        auto limit_descendant_size = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string unused_error_string;
        LOCK(::mempool.cs);
        return ::mempool.CalculateMemPoolAncestors(entry, ancestors, limit_ancestor_count, limit_ancestor_size,
            limit_descendant_count, limit_descendant_size, unused_error_string);
    }
    CFeeRate estimateSmartFee(int num_blocks, bool conservative, FeeCalculation* calc) override
    {
        return ::feeEstimator.estimateSmartFee(num_blocks, calc, conservative);
    }
    unsigned int estimateMaxBlocks() override
    {
        return ::feeEstimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    }
    CFeeRate mempoolMinFee() override
    {
        return ::mempool.GetMinFee(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000);
    }
    CFeeRate relayMinFee() override { return ::minRelayTxFee; }
    CFeeRate relayIncrementalFee() override { return ::incrementalRelayFee; }
    CFeeRate relayDustFee() override { return ::dustRelayFee; }
    CAmount maxTxFee() override { return ::maxTxFee; }
    bool getPruneMode() override { return ::fPruneMode; }
    bool p2pEnabled() override { return g_connman != nullptr; }
    bool isReadyToBroadcast() override { return !::fImporting && !::fReindex && !IsInitialBlockDownload(); }
    bool isInitialBlockDownload() override { return IsInitialBlockDownload(); }
    bool shutdownRequested() override { return ShutdownRequested(); }
    int64_t getAdjustedTime() override { return GetAdjustedTime(); }
    void initMessage(const std::string& message) override { ::uiInterface.InitMessage(message); }
    void initWarning(const std::string& message) override { InitWarning(message); }
    void initError(const std::string& message) override { InitError(message); }
    void loadWallet(std::unique_ptr<Wallet> wallet) override { ::uiInterface.LoadWallet(wallet); }
    void showProgress(const std::string& title, int progress, bool resume_possible) override
    {
        ::uiInterface.ShowProgress(title, progress, resume_possible);
    }
    std::unique_ptr<Handler> handleNotifications(Notifications& notifications) override
    {
        return MakeUnique<NotificationsHandlerImpl>(*this, notifications);
    }
    void waitForNotifications() override { SyncWithValidationInterfaceQueue(); }
    std::unique_ptr<Handler> handleRpc(const CRPCCommand& command) override
    {
        return MakeUnique<RpcHandlerImpl>(command);
    }
    bool rpcEnableDeprecated(const std::string& method) override { return IsDeprecatedRPCEnabled(method); }
    void rpcRunLater(const std::string& name, std::function<void()> fn, int64_t seconds) override
    {
        RPCRunLater(name, std::move(fn), seconds);
    }
    int rpcSerializationFlags() override { return RPCSerializationFlags(); }
    void requestMempoolTransactions(Notifications& notifications) override
    {
        LOCK2(::cs_main, ::mempool.cs);
        for (const CTxMemPoolEntry& entry : ::mempool.mapTx) {
            notifications.TransactionAddedToMempool(entry.GetSharedTx());
        }
    }

    //!< WISPR
    void relayTransactionLock(const uint256& txid, CTransactionRef tx) override
    {
        mapTxLockReq.insert(std::make_pair(txid, (CTransaction) * tx));
        CreateNewLock(((CTransaction) * tx));
//        RelayTransactionLockReq((CTransaction) * tx,  g_connman.get(), true);
        CInv inv(MSG_TXLOCK_REQUEST, tx->GetHash());
        g_connman->ForEachNode([&inv, tx](CNode* pnode)
            {
              if (!(!pnode->fRelayTxes)){
                  g_connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::TXLOCKREQUEST, tx));
              }

               pnode->PushInventory(inv);
            });
    }

    bool readCoinMint(const uint256& hashPubcoin, uint256& hashTx) override
    {
      return zerocoinDB->ReadCoinMint(hashPubcoin, hashTx);
    }
    bool readCoinSpend(const uint256& hashSerial, uint256 &txHash) override
    {
        return zerocoinDB->ReadCoinSpend(hashSerial, txHash);
    }
};
} // namespace

std::unique_ptr<Chain> MakeChain() { return MakeUnique<ChainImpl>(); }

} // namespace interfaces
