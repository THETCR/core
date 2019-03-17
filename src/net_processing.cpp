// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing.h>

#include "addrman.h"
#include <banman.h>
#include "uint256.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "main.h"
#include "merkleblock.h"
#include <netmessagemaker.h>
#include "reverse_iterate.h"
#include "netbase.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "random.h"
#include "tinyformat.h"
#include "txmempool.h"
#include "ui_interface.h"
#include <util/system.h>
#include "util/moneystr.h"
#include "util/strencodings.h"
#include "validationinterface.h"
#include "scheduler.h"
#include "spork.h"
#include "sporkdb.h"
#include "swifttx.h"
#include "obfuscation.h"
#include "masternodeman.h"
#include "masternode-sync.h"
#include "masternode-budget.h"
#include <alert.h>

#include <memory>
#include <algorithm>

#include <boost/thread.hpp>

using namespace std;

#if defined(NDEBUG)
# error "Bitcoin cannot be compiled without assertions."
#endif

struct COrphanTx {
  CTransaction tx;
  NodeId fromPeer;
};

map<uint256, COrphanTx> mapOrphanTransactions GUARDED_BY(cs_main);
map<uint256, set<uint256> > mapOrphanTransactionsByPrev GUARDED_BY(cs_main);
map<uint256, int64_t> mapRejectedBlocks GUARDED_BY(cs_main);
map<uint256, int64_t> mapZerocoinspends GUARDED_BY(cs_main); //txid, time received

//map<uint256, COrphanTx> mapOrphanTransactions GUARDED_BY(cs_main);
//map<COutPoint, set<map<uint256, COrphanTx>::iterator, IteratorComparator>> mapOrphanTransactionsByPrev GUARDED_BY(cs_main);
void EraseOrphansFor(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
///** Increase a node's misbehavior score. */
//void Misbehaving(NodeId nodeid, int howmuch) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
static const uint64_t RANDOMIZER_ID_ADDRESS_RELAY = 0x3cac0035b5866b90ULL; // SHA256("main address relay")[0:8]

/** Average delay between local address broadcasts in seconds. */
static constexpr unsigned int AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24 * 60 * 60;
/** Average delay between peer address broadcasts in seconds. */
static const unsigned int AVG_ADDRESS_BROADCAST_INTERVAL = 30;
/** Average delay between trickled inventory transmissions in seconds.
 *  Blocks and whitelisted receivers bypass this, outbound peers get half this delay. */
static const unsigned int INVENTORY_BROADCAST_INTERVAL = 5;
/** Maximum number of inventory items to send per transmission.
 *  Limits the impact of low-fee transaction floods. */
static constexpr unsigned int INVENTORY_BROADCAST_MAX = 7 * INVENTORY_BROADCAST_INTERVAL;
/** Average delay between feefilter broadcasts in seconds. */
static constexpr unsigned int AVG_FEEFILTER_BROADCAST_INTERVAL = 10 * 60;
/** Maximum feefilter broadcast delay after significant change. */
static constexpr unsigned int MAX_FEEFILTER_CHANGE_DELAY = 5 * 60;
/** How frequently to check for stale tips, in seconds */
static constexpr int64_t STALE_CHECK_INTERVAL = 10 * 60; // 10 minutes
/** How frequently to check for extra outbound peers and disconnect, in seconds */
static constexpr int64_t EXTRA_PEER_CHECK_INTERVAL = 45;

// Internal stuff
namespace
{
/** Number of nodes with fSyncStarted. */
int nSyncStarted GUARDED_BY(cs_main) = 0;

/**
     * Sources of received blocks, to be able to send them reject messages or ban
     * them, if processing happens afterwards. Protected by cs_main.
     */
map<uint256, NodeId> mapBlockSource GUARDED_BY(cs_main);

/**
 * Filter for transactions that were recently rejected by
 * AcceptToMemoryPool. These are not rerequested until the chain tip
 * changes, at which point the entire filter is reset.
 *
 * Without this filter we'd be re-requesting txs from each of our peers,
 * increasing bandwidth consumption considerably. For instance, with 100
 * peers, half of which relay a tx we don't accept, that might be a 50x
 * bandwidth increase. A flooding attacker attempting to roll-over the
 * filter using minimum-sized, 60byte, transactions might manage to send
 * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
 * two minute window to send invs to us.
 *
 * Decreasing the false positive rate is fairly cheap, so we pick one in a
 * million to make it highly unlikely for users to have issues with this
 * filter.
 *
 * Memory used: 1.3 MB
 */
std::unique_ptr<CRollingBloomFilter> recentRejects GUARDED_BY(cs_main);
uint256 hashRecentRejectsChainTip GUARDED_BY(cs_main);
/** Blocks that are in flight, and that are in the queue to be downloaded. Protected by cs_main. */
struct QueuedBlock {
  uint256 hash;
  CBlockIndex* pindex;        //! Optional.
  int64_t nTime;              //! Time of "getdata" request in microseconds.
  int nValidatedQueuedBefore; //! Number of blocks queued with validated headers (globally) at the time this one is requested.
  bool fValidatedHeaders;     //! Whether this block has validated headers at the time of request.
};
    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> > mapBlocksInFlight GUARDED_BY(cs_main);

    /** Stack of nodes which we have set to announce using compact blocks */
    std::list<NodeId> lNodesAnnouncingHeaderAndIDs GUARDED_BY(cs_main);

    /** Number of preferable block download peers. */
    int nPreferredDownload GUARDED_BY(cs_main) = 0;

    /** Number of peers from which we're downloading blocks. */
    int nPeersWithValidatedDownloads GUARDED_BY(cs_main) = 0;

    /** Number of outbound peers with m_chain_sync.m_protect. */
    int g_outbound_peers_with_protect_from_disconnect GUARDED_BY(cs_main) = 0;

    /** When our tip was last updated. */
    std::atomic<int64_t> g_last_tip_update(0);

    /** Relay map */
    typedef std::map<uint256, CTransactionRef> MapRelay;
    MapRelay mapRelay GUARDED_BY(cs_main);
    /** Expiration-time ordered list of (expire time, relay map entry) pairs. */
    std::deque<std::pair<int64_t, MapRelay::iterator>> vRelayExpiration GUARDED_BY(cs_main);

    std::atomic<int64_t> nTimeBestReceived(0); // Used only to inform the wallet of when we last received a block

/** Number of blocks in flight with validated headers. */
int nQueuedValidatedHeaders GUARDED_BY(cs_main) = 0;


struct IteratorComparator
{
  template<typename I>
  bool operator()(const I& a, const I& b)
  {
      return &(*a) < &(*b);
  }
};

} // anon namespace

namespace
{
struct CBlockReject {
  unsigned char chRejectCode;
  std::string strRejectReason;
  uint256 hashBlock;
};

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState {
  //! The peer's address
  CService address;
  //! Whether we have a fully established connection.
  bool fCurrentlyConnected;
  //! Accumulated misbehaviour score for this peer.
  int nMisbehavior;
  //! Whether this peer should be disconnected and banned (unless whitelisted).
  bool fShouldBan;
  //! String name of this peer (debugging/logging purposes).
  std::string name;
  //! List of asynchronously-determined block rejections to notify this peer about.
  std::vector<CBlockReject> rejects;
  //! The best known block we know this peer has announced.
  CBlockIndex* pindexBestKnownBlock;
  //! The hash of the last unknown block this peer has announced.
  uint256 hashLastUnknownBlock;
  //! The last full block we both have.
  CBlockIndex* pindexLastCommonBlock;
  //! Whether we've started headers synchronization with this peer.
  bool fSyncStarted;
  //! Since when we're stalling block download progress (in microseconds), or 0.
  int64_t nStallingSince;
  std::list<QueuedBlock> vBlocksInFlight;
  int nBlocksInFlight;
  //! Whether we consider this a preferred download peer.
  bool fPreferredDownload;

  CNodeState()
  {
      fCurrentlyConnected = false;
      nMisbehavior = 0;
      fShouldBan = false;
      pindexBestKnownBlock = nullptr;
      hashLastUnknownBlock = uint256(0);
      pindexLastCommonBlock = nullptr;
      fSyncStarted = false;
      nStallingSince = 0;
      nBlocksInFlight = 0;
      fPreferredDownload = false;
  }
};

/** Map maintaining per-node state. Requires cs_main. */
map<NodeId, CNodeState> mapNodeState;

// Requires cs_main.
CNodeState* State(NodeId pnode)
{
    map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
        return nullptr;
    return &it->second;
}

int GetHeight()
{
    while (true) {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            MilliSleep(50);
            continue;
        }
        return chainActive.Height();
    }
}

void UpdatePreferredDownload(CNode* node, CNodeState* state)
{
    nPreferredDownload -= state->fPreferredDownload;

    // Whether this node should be marked as a preferred download node.
    state->fPreferredDownload = (!node->fInbound || node->fWhitelisted) && !node->fOneShot && !node->fClient;

    nPreferredDownload += state->fPreferredDownload;
}

static void PushNodeVersion(CNode *pnode, CConnman* connman, int64_t nTime)
{
    ServiceFlags nLocalNodeServices = pnode->GetLocalServices();
    uint64_t nonce = pnode->GetLocalNonce();
    int nNodeStartingHeight = pnode->GetMyStartingHeight();
    NodeId nodeid = pnode->GetId();
    CAddress addr = pnode->addr;

    CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService(), addr.nServices));
    CAddress addrMe = CAddress(CService(), nLocalNodeServices);

    connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, nTime, addrYou, addrMe,
            nonce, strSubVersion, nNodeStartingHeight, ::fRelayTxes));

    if (fLogIPs) {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, us=%s, them=%s, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), addrYou.ToString(), nodeid);
    } else {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, us=%s, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), nodeid);
    }
}

// Requires cs_main.
bool MarkBlockAsReceived(const uint256& hash)
{
    std::map<uint256, pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end()) {
        CNodeState* state = State(itInFlight->second.first);
        nQueuedValidatedHeaders -= itInFlight->second.second->fValidatedHeaders;
        state->vBlocksInFlight.erase(itInFlight->second.second);
        state->nBlocksInFlight--;
        state->nStallingSince = 0;
        mapBlocksInFlight.erase(itInFlight);
        return true;
    }
    return false;
}

// Requires cs_main.
void MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, CBlockIndex* pindex = nullptr)
{
    CNodeState* state = State(nodeid);
    assert(state != nullptr);

    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);

    QueuedBlock newentry = {hash, pindex, GetTimeMicros(), nQueuedValidatedHeaders, pindex != NULL};
    nQueuedValidatedHeaders += newentry.fValidatedHeaders;
    std::list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(), newentry);
    state->nBlocksInFlight++;
    mapBlocksInFlight[hash] = std::make_pair(nodeid, it);
}

/** Check whether the last unknown block a peer advertized is not yet known. */
void ProcessBlockAvailability(NodeId nodeid)
{
    CNodeState* state = State(nodeid);
    assert(state != nullptr);

    if (state->hashLastUnknownBlock != 0) {
        BlockMap::iterator itOld = mapBlockIndex.find(state->hashLastUnknownBlock);
        if (itOld != mapBlockIndex.end() && itOld->second->nChainWork > 0) {
            if (state->pindexBestKnownBlock == NULL || itOld->second->nChainWork >= state->pindexBestKnownBlock->nChainWork)
                state->pindexBestKnownBlock = itOld->second;
            state->hashLastUnknownBlock = uint256(0);
        }
    }
}

/** Update tracking information about which blocks a peer is assumed to have. */
void UpdateBlockAvailability(NodeId nodeid, const uint256& hash)
{
    CNodeState* state = State(nodeid);
    assert(state != nullptr);

    ProcessBlockAvailability(nodeid);

    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end() && it->second->nChainWork > 0) {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == NULL || it->second->nChainWork >= state->pindexBestKnownBlock->nChainWork)
            state->pindexBestKnownBlock = it->second;
    } else {
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-NULL. */
CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb)
{
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

/** Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
 *  at most count entries. */
void FindNextBlocksToDownload(NodeId nodeid, unsigned int count, std::vector<CBlockIndex*>& vBlocks, NodeId& nodeStaller)
{
    if (count == 0)
        return;

    vBlocks.reserve(vBlocks.size() + count);
    CNodeState* state = State(nodeid);
    assert(state != nullptr);

    // Make sure pindexBestKnownBlock is up to date, we'll need it.
    ProcessBlockAvailability(nodeid);

    if (state->pindexBestKnownBlock == NULL || state->pindexBestKnownBlock->nChainWork < chainActive.Tip()->nChainWork) {
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBlock == nullptr) {
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBlock = chainActive[std::min(state->pindexBestKnownBlock->nHeight, chainActive.Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
    // of their current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = LastCommonAncestor(state->pindexLastCommonBlock, state->pindexBestKnownBlock);
    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock)
        return;

    std::vector<CBlockIndex*> vToFetch;
    CBlockIndex* pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the best block we know the peer has, or more than BLOCK_DOWNLOAD_WINDOW + 1 beyond the last
    // linked block we have in common with this peer. The +1 is so we can detect stalling, namely if we would be able to
    // download that next block if the window were 1 larger.
    int nWindowEnd = state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
    int nMaxHeight = std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
    NodeId waitingfor = -1;
    while (pindexWalk->nHeight < nMaxHeight) {
        // Read up to 128 (or more, if more blocks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownBlock) into vToFetch. We fetch 128, because CBlockIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBlocks.size(), 128));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBlock->GetAncestor(pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--) {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBlocks. In the mean time, update
        // pindexLastCommonBlock as long as all ancestors are already downloaded.
        for (CBlockIndex* pindex: vToFetch) {
            if (!pindex->IsValid(BLOCK_VALID_TREE)) {
                // We consider the chain that this peer is on invalid.
                return;
            }
            if (pindex->nStatus & BLOCK_HAVE_DATA) {
                if (pindex->nChainTx)
                    state->pindexLastCommonBlock = pindex;
            } else if (mapBlocksInFlight.count(pindex->GetBlockHash()) == 0) {
                // The block is not already downloaded, and not yet in flight.
                if (pindex->nHeight > nWindowEnd) {
                    // We reached the end of the window.
                    if (vBlocks.size() == 0 && waitingfor != nodeid) {
                        // We aren't able to fetch anything, but we would be if the download window was one larger.
                        nodeStaller = waitingfor;
                    }
                    return;
                }
                vBlocks.push_back(pindex);
                if (vBlocks.size() == count) {
                    return;
                }
            } else if (waitingfor == -1) {
                // This is the first already-in-flight block.
                waitingfor = mapBlocksInFlight[pindex->GetBlockHash()].first;
            }
        }
    }
}

} // anon namespace

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats)
{
    LOCK(cs_main);
    CNodeState* state = State(nodeid);
    if (state == nullptr)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight = state->pindexBestKnownBlock ? state->pindexBestKnownBlock->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock ? state->pindexLastCommonBlock->nHeight : -1;
    for (const QueuedBlock& queue: state->vBlocksInFlight) {
        if (queue.pindex)
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
    }
    return true;
}

//void RegisterNodeSignals(CNodeSignals& nodeSignals)
//{
//    nodeSignals.GetHeight.connect(&GetHeight);
//    nodeSignals.ProcessMessages.connect(&ProcessMessages);
//    nodeSignals.SendMessages.connect(&SendMessages);
//    nodeSignals.InitializeNode.connect(&InitializeNode);
//    nodeSignals.FinalizeNode.connect(&FinalizeNode);
//}
//
//void UnregisterNodeSignals(CNodeSignals& nodeSignals)
//{
//    nodeSignals.GetHeight.disconnect(&GetHeight);
//    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
//    nodeSignals.SendMessages.disconnect(&SendMessages);
//    nodeSignals.InitializeNode.disconnect(&InitializeNode);
//    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
//}

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx, NodeId peer)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    unsigned int sz = GetSerializeSize(tx, CTransaction::CURRENT_VERSION);
    if (sz > 5000) {
        LogPrint(BCLog::MEMPOOL, "ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString());
        return false;
    }

    mapOrphanTransactions[hash].tx = tx;
    mapOrphanTransactions[hash].fromPeer = peer;
    for (const CTxIn& txin: tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    LogPrint(BCLog::MEMPOOL, "stored orphan tx %s (mapsz %u prevsz %u)\n", hash.ToString(),
             mapOrphanTransactions.size(), mapOrphanTransactionsByPrev.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.find(hash);
    if (it == mapOrphanTransactions.end())
        return;
    for (const CTxIn& txin: it->second.tx.vin) {
        map<uint256, set<uint256> >::iterator itPrev = mapOrphanTransactionsByPrev.find(txin.prevout.hash);
        if (itPrev == mapOrphanTransactionsByPrev.end())
            continue;
        itPrev->second.erase(hash);
        if (itPrev->second.empty())
            mapOrphanTransactionsByPrev.erase(itPrev);
    }
    mapOrphanTransactions.erase(it);
}

void EraseOrphansFor(NodeId peer)
{
    int nErased = 0;
    map<uint256, COrphanTx>::iterator iter = mapOrphanTransactions.begin();
    while (iter != mapOrphanTransactions.end()) {
        map<uint256, COrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer) {
            EraseOrphanTx(maybeErase->second.tx.GetHash());
            ++nErased;
        }
    }
    if (nErased > 0) LogPrint(BCLog::MEMPOOL, "Erased %d orphan tx from peer %d\n", nErased, peer);
}


unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans) {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

// Requires cs_main.
void Misbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
        return;

    CNodeState *state = State(pnode);
    if (state == NULL)
        return;

    state->nMisbehavior += howmuch;
    int banscore = gArgs.GetArg("-banscore", DEFAULT_BANSCORE_THRESHOLD);
    if (state->nMisbehavior >= banscore && state->nMisbehavior - howmuch < banscore)
    {
        LogPrintf("%s: %s peer=%d (%d -> %d) BAN THRESHOLD EXCEEDED\n", __func__, state->name, pnode, state->nMisbehavior-howmuch, state->nMisbehavior);
        state->fShouldBan = true;
    } else
        LogPrintf("%s: %s peer=%d (%d -> %d)\n", __func__, state->name, pnode, state->nMisbehavior-howmuch, state->nMisbehavior);
}


//////////////////////////////////////////////////////////////////////////////
//
// blockchain -> download logic notification
//

// TODO: Implement this with the rest of PeerLogicValidation

PeerLogicValidation::PeerLogicValidation(CConnman* connmanIn, BanMan* banman, CScheduler &scheduler, bool enable_bip61)
        : connman(connmanIn), m_banman(banman), m_stale_tip_check_time(0), m_enable_bip61(enable_bip61) {
    // Initialize global variables that cannot be constructed at startup.
    recentRejects.reset(new CRollingBloomFilter(120000, 0.000001));

    const Consensus::Params& consensusParams = Params().GetConsensus();
    // Stale tip checking and peer eviction are on two different timers, but we
    // don't want them to get out of sync due to drift in the scheduler, so we
    // combine them in one function and schedule at the quicker (peer-eviction)
    // timer.
    static_assert(EXTRA_PEER_CHECK_INTERVAL < STALE_CHECK_INTERVAL, "peer eviction timer should be less than stale tip check timer");
    scheduler.scheduleEvery(std::bind(&PeerLogicValidation::CheckForStaleTipAndEvictPeers, this, consensusParams), EXTRA_PEER_CHECK_INTERVAL * 1000);
}

void PeerLogicValidation::InitializeNode(CNode* pnode)
{
    NodeId nodeid = pnode->GetId();
    LOCK(cs_main);
    CNodeState& state = mapNodeState.insert(std::make_pair(nodeid, CNodeState())).first->second;
    state.name = pnode->GetAddrName();
    state.address = pnode->addr;
}

void PeerLogicValidation::FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime)
{
    LOCK(cs_main);
    CNodeState* state = State(nodeid);

    if (state->fSyncStarted)
        nSyncStarted--;

    if (state->nMisbehavior == 0 && state->fCurrentlyConnected) {
        AddressCurrentlyConnected(state->address);
    }

    for (const QueuedBlock& entry: state->vBlocksInFlight)
        mapBlocksInFlight.erase(entry.hash);
    EraseOrphansFor(nodeid);
    nPreferredDownload -= state->fPreferredDownload;

    mapNodeState.erase(nodeid);
}

//void PeerLogicValidation::SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int nPosInBlock) {
//    if (nPosInBlock == CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK)
//        return;
//
//    LOCK(cs_main);
//
//    std::vector<uint256> vOrphanErase;
//    // Which orphan pool entries must we evict?
//    for (size_t j = 0; j < tx.vin.size(); j++) {
//        auto itByPrev = mapOrphanTransactionsByPrev.find(tx.vin[j].prevout.hash);
//        if (itByPrev == mapOrphanTransactionsByPrev.end()) continue;
//        for (auto mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi) {
//            const CTransaction& orphanTx = *mi;
//            const uint256& orphanHash = orphanTx.GetHash();
//            vOrphanErase.push_back(orphanHash);
//        }
//    }
//
//    // Erase orphan transactions include or precluded by this block
//    if (vOrphanErase.size()) {
//        int nErased = 0;
//        for(uint256 &orphanHash: vOrphanErase) {
//            nErased += EraseOrphanTx(orphanHash);
//        }
//        LogPrint(BCLog::MEMPOOL, "Erased %d orphan tx included or conflicted by block\n", nErased);
//    }
//}

/**
 * Update our best height and announce any block hashes which weren't previously
 * in chainActive to our peers.
 */
void PeerLogicValidation::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) {
    const int nNewHeight = pindexNew->nHeight;

    if (!fInitialDownload) {
        // Find the hashes of all blocks that weren't previously in the best chain.
        std::vector<uint256> vHashes;
        const CBlockIndex *pindexToAnnounce = pindexNew;
        while (pindexToAnnounce != pindexFork) {
            vHashes.push_back(pindexToAnnounce->GetBlockHash());
            pindexToAnnounce = pindexToAnnounce->pprev;
            if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE) {
                // Limit announcements in case of a huge reorganization.
                // Rely on the peer's synchronization mechanism in that case.
                break;
            }
        }
        // Relay inventory, but don't relay old inventory during initial block download.
        connman->ForEachNode([nNewHeight, &vHashes](CNode* pnode) {
            if (nNewHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 0)) {
                for (const uint256& hash : reverse_iterate(vHashes)) {
                    pnode->PushBlockHash(hash);
                }
            }
        });
        connman->WakeMessageHandler();
    }
    nTimeBestReceived = GetTime();
}

/**
 * Handle invalid block rejection and consequent peer banning, maintain which
 * peers announce compact blocks.
 */
void PeerLogicValidation::BlockChecked(const CBlock& block, const CValidationState& state) {
    LOCK(cs_main);

    const uint256 hash(block.GetHash());
    std::map<uint256, NodeId>::iterator it = mapBlockSource.find(hash);

    int nDoS = 0;
    if (state.IsInvalid(nDoS)) {
        if (it != mapBlockSource.end() && State(it->second)) {
            CBlockReject reject = {(unsigned char)state.GetRejectCode(), state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), hash};
            State(it->second)->rejects.push_back(reject);
            if (nDoS > 0)
                Misbehaving(it->second, nDoS);
        }
    }
    if (it != mapBlockSource.end())
        mapBlockSource.erase(it);
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

// Note: whenever a protocol update is needed toggle between both implementations (comment out the formerly active one)
//       so we can leave the existing clients untouched (old SPORK will stay on so they don't see even older clients).
//       Those old clients won't react to the changes of the other (new) SPORK because at the time of their implementation
//       it was the one which was commented out
int ActiveProtocol()
{
    // SPORK_14 is used for 70913 (v3.1.0+)
    if (IsSporkActive(SPORK_14_NEW_PROTOCOL_ENFORCEMENT))
        return MIN_PEER_PROTO_VERSION_AFTER_ENFORCEMENT;

    // SPORK_15 was used for 70912 (v3.0.5+), commented out now.
    //if (IsSporkActive(SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2))
    //        return MIN_PEER_PROTO_VERSION_AFTER_ENFORCEMENT;

    return MIN_PEER_PROTO_VERSION_BEFORE_ENFORCEMENT;
}

bool static AlreadyHave(const CInv& inv)
{
    switch (inv.type) {
    case MSG_TX: {
        bool txInMap = false;
        txInMap = mempool.exists(inv.hash);
        return txInMap || mapOrphanTransactions.count(inv.hash) ||
               pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 0)) || // Best effort: only try output 0 and 1
               pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 1));
    }
    case MSG_DSTX:
        return mapObfuscationBroadcastTxes.count(inv.hash);
    case MSG_PUBCOINS:
    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash);
    case MSG_TXLOCK_REQUEST:
        return mapTxLockReq.count(inv.hash) ||
            mapTxLockReqRejected.count(inv.hash);
    case MSG_TXLOCK_VOTE:
        return mapTxLockVote.count(inv.hash);
    case MSG_SPORK:
        return mapSporks.count(inv.hash);
    case MSG_MASTERNODE_WINNER:
        if (masternodePayments.mapMasternodePayeeVotes.count(inv.hash)) {
            masternodeSync.AddedMasternodeWinner(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_VOTE:
        if (budget.mapSeenMasternodeBudgetVotes.count(inv.hash)) {
            masternodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_PROPOSAL:
        if (budget.mapSeenMasternodeBudgetProposals.count(inv.hash)) {
            masternodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_FINALIZED_VOTE:
        if (budget.mapSeenFinalizedBudgetVotes.count(inv.hash)) {
            masternodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_BUDGET_FINALIZED:
        if (budget.mapSeenFinalizedBudgets.count(inv.hash)) {
            masternodeSync.AddedBudgetItem(inv.hash);
            return true;
        }
        return false;
    case MSG_MASTERNODE_ANNOUNCE:
        if (mnodeman.mapSeenMasternodeBroadcast.count(inv.hash)) {
            masternodeSync.AddedMasternodeList(inv.hash);
            return true;
        }
        return false;
    case MSG_MASTERNODE_PING:
        return mnodeman.mapSeenMasternodePing.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}

//void RelayTransaction(const CTransaction& tx)
//{
//    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
//    ss.reserve(10000);
//    ss << tx;
//    RelayTransaction(tx, ss);
//}

void RelayTransaction(const CTransaction& tx, CConnman* connman)
{
    CInv inv(MSG_TX, tx.GetHash());
    {
        int64_t nNow = GetTimeMicros();
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < nNow)
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }
        // Save original serialized message so newer versions are preserved
        auto ret = mapRelay.insert(std::make_pair(tx.GetHash(), std::move(MakeTransactionRef(tx))));
        if (ret.second) {
            vRelayExpiration.push_back(std::make_pair(nNow + 15 * 60 * 1000000, ret.first));
        }
    }
    connman->ForEachNode([&inv, tx](CNode* pnode)
    {
        if (pnode->fRelayTxes){
            if (pnode->pfilter) {
                if (pnode->pfilter->IsRelevantAndUpdate(tx))
                    pnode->PushInventory(inv);
            } else
                pnode->PushInventory(inv);
        }
    });
}

void RelayTransactionLockReq(const CTransaction& tx, CConnman* connman, bool relayToAll)
{
    CInv inv(MSG_TXLOCK_REQUEST, tx.GetHash());
    connman->ForEachNode([connman, &inv, relayToAll, tx](CNode* pnode)
    {
        if (!(!relayToAll && !pnode->fRelayTxes)){
            connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::TXLOCKREQUEST, tx));
        }

        pnode->PushInventory(inv);
    });
}

void RelayInv(CInv& inv, CConnman* connman)
{
    connman->ForEachNode([connman, &inv](CNode* pnode)
    {
        if(!((pnode->nServices == NODE_BLOOM_WITHOUT_MN || pnode->nServices == NODE_BLOOM_LIGHT_ZC) && inv.IsMasterNodeType())){
            if (pnode->nVersion >= ActiveProtocol())
                pnode->PushInventory(inv);
        }
    });
}

//static void RelayAddress(const CAddress& addr, bool fReachable, CConnman& connman)
//{
//    unsigned int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
//
//    // Relay to a limited number of other nodes
//    // Use deterministic randomness to send to the same nodes for 24 hours
//    // at a time so the addrKnowns of the chosen nodes prevent repeats
//    uint64_t hashAddr = addr.GetHash();
//    const CSipHasher hasher = connman.GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY).Write(hashAddr << 32).Write((GetTime() + hashAddr) / (24*60*60));
//    FastRandomContext insecure_rand;
//
//    std::array<std::pair<uint64_t, CNode*>,2> best{{{0, nullptr}, {0, nullptr}}};
//    assert(nRelayNodes <= best.size());
//
//    auto sortfunc = [&best, &hasher, nRelayNodes](CNode* pnode) {
//      if (pnode->nVersion >= CADDR_TIME_VERSION) {
//          uint64_t hashKey = CSipHasher(hasher).Write(pnode->id).Finalize();
//          for (unsigned int i = 0; i < nRelayNodes; i++) {
//              if (hashKey > best[i].first) {
//                  std::copy(best.begin() + i, best.begin() + nRelayNodes - 1, best.begin() + i + 1);
//                  best[i] = std::make_pair(hashKey, pnode);
//                  break;
//              }
//          }
//      }
//    };
//
//    auto pushfunc = [&addr, &best, nRelayNodes, &insecure_rand] {
//      for (unsigned int i = 0; i < nRelayNodes && best[i].first != 0; i++) {
//          best[i].second->PushAddress(addr, insecure_rand);
//      }
//    };
//
//    connman.ForEachNodeThen(std::move(sortfunc), std::move(pushfunc));
//}

void static ProcessGetData(CNode* pfrom, const CChainParams& chainparams, CConnman* connman, const std::atomic<bool>& interruptMsgProc) LOCKS_EXCLUDED(cs_main)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    std::vector<CInv> vNotFound;
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());

    LOCK(cs_main);
    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->fPauseSend)
            break;

        const CInv& inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK) {
                bool send = false;
                BlockMap::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end()) {
                    if (chainActive.Contains(mi->second)) {
                        send = true;
                    } else {
                        // To prevent fingerprinting attacks, only send blocks outside of the active
                        // chain if they are valid, and no more than a max reorg depth than the best header
                        // chain we know about.
                        send = mi->second->IsValid(BLOCK_VALID_SCRIPTS) && (pindexBestHeader != NULL) &&
                            (chainActive.Height() - mi->second->nHeight < Params().MaxReorganizationDepth());
                        if (!send) {
                            LogPrintf("ProcessGetData(): ignoring request from peer=%i for old block that isn't in the main chain\n", pfrom->GetId());
                        }
                    }
                }
                // Don't send not-validated blocks
                if (send && (mi->second->nStatus & BLOCK_HAVE_DATA)) {
                    // Send block from disk
                    CBlock block;
                    if (!ReadBlockFromDisk(block, (*mi).second))
                        assert(!"cannot load block from disk");
                    if (inv.type == MSG_BLOCK)
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::BLOCK, block));
                    else // MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter) {
                            CMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MERKLEBLOCK, merkleBlock));
                            // CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didnt send here -
                            // they must either disconnect and retry or request the full block.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            for (PairType& pair: merkleBlock.vMatchedTxn)
                                if (!pfrom->setInventoryKnown.count(CInv(MSG_TX, pair.second)))
                                    connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::TX, block.vtx[pair.first]));
                        }
                        // else
                        // no response
                    }

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue) {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        std::vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, chainActive.Tip()->GetBlockHash()));
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::INV, vInv));
                        pfrom->hashContinue = 0;
                    }
                }
            } else if (inv.IsKnownType()) {
                // Send stream from relay memory
                bool pushed = false;
                {
                    auto mi = mapRelay.find(inv.hash);
                    if (mi != mapRelay.end()) {
                        connman->PushMessage(pfrom, msgMaker.Make(inv.GetCommand(), (*mi).second));
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_TX) {
                    CTransactionRef ptx = mempool.get(inv.hash);
                    CTransaction tx;
                    if (ptx != nullptr) {
                        tx = *ptx;
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::TX, ss));
                        pushed = true;
                    }
                }

                if(pfrom->GetLocalServices() & NODE_BLOOM_LIGHT_ZC) {
                    if (!pushed && inv.type == MSG_PUBCOINS) {
                        //std::cout << "asking for pubcoins, requested block hash: " << inv.hash.GetHex() << std::endl;

                        bool send = false;
                        BlockMap::iterator mi = mapBlockIndex.find(inv.hash);
                        if (mi != mapBlockIndex.end()) {
                            if (chainActive.Contains(mi->second)) {
                                send = true;
                            } else {
                                // To prevent fingerprinting attacks, only send blocks outside of the active
                                // chain if they are valid, and no more than a max reorg depth than the best header
                                // chain we know about.
                                send = mi->second->IsValid(BLOCK_VALID_SCRIPTS) && (pindexBestHeader != NULL) &&
                                    (chainActive.Height() - mi->second->nHeight < Params().MaxReorganizationDepth());
                                if (!send) {
                                    LogPrintf(
                                        "ProcessGetData(): ignoring request from peer=%i for old block that isn't in the main chain\n",
                                        pfrom->GetId());
                                }
                            }
                        }
                        // Don't send not-validated blocks
                        if (send && (mi->second->nStatus & BLOCK_HAVE_DATA)) {
                            try {
                                std::list<libzerocoin::PublicCoin> pubcoins = GetPubcoinFromBlock((*mi).second);
                                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                                ss.reserve(2000);
                                ss << inv.hash.Get32();
                                ss << pubcoins.size();
                                for (const libzerocoin::PublicCoin &pubcoin : pubcoins) {
                                    ss << pubcoin.getValue();
                                }
                                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::PUBCOINS, ss));
                                pushed = true;
                            } catch (std::exception &e) {
                                PrintExceptionContinue(&e, "ProcessMessages()");
                            }
                        }
                    }
                }

                if (!pushed && inv.type == MSG_TXLOCK_VOTE) {
                    if (mapTxLockVote.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapTxLockVote[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::TXLOCKVOTE, ss));
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TXLOCK_REQUEST) {
                    if (mapTxLockReq.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapTxLockReq[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::TXLOCKREQUEST, ss));
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_SPORK) {
                    if (mapSporks.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapSporks[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::SPORK, ss));
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_MASTERNODE_WINNER) {
                    if (masternodePayments.mapMasternodePayeeVotes.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << masternodePayments.mapMasternodePayeeVotes[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MASTERNODEPAYMENTVOTE, ss));
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_BUDGET_VOTE) {
                    if (budget.mapSeenMasternodeBudgetVotes.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenMasternodeBudgetVotes[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MNBUDGETVOTE, ss));
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_BUDGET_PROPOSAL) {
                    if (budget.mapSeenMasternodeBudgetProposals.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenMasternodeBudgetProposals[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MNBUDGETPROPOSAL, ss));
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_BUDGET_FINALIZED_VOTE) {
                    if (budget.mapSeenFinalizedBudgetVotes.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenFinalizedBudgetVotes[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MNBUDGETFINALVOTE, ss));
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_BUDGET_FINALIZED) {
                    if (budget.mapSeenFinalizedBudgets.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << budget.mapSeenFinalizedBudgets[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MNBUDGETFINAL, ss));
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_MASTERNODE_ANNOUNCE) {
                    if (mnodeman.mapSeenMasternodeBroadcast.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mnodeman.mapSeenMasternodeBroadcast[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MNANNOUNCE, ss));
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_MASTERNODE_PING) {
                    if (mnodeman.mapSeenMasternodePing.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mnodeman.mapSeenMasternodePing[inv.hash];
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::MNPING, ss));
                        pushed = true;
                    }
                }

                if (!pushed && inv.type == MSG_DSTX) {
                    if (mapObfuscationBroadcastTxes.count(inv.hash)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapObfuscationBroadcastTxes[inv.hash].tx << mapObfuscationBroadcastTxes[inv.hash].vin << mapObfuscationBroadcastTxes[inv.hash].vchSig << mapObfuscationBroadcastTxes[inv.hash].sigTime;

                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::DSTX, ss));
                        pushed = true;
                    }
                }


                if (!pushed) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            GetMainSignals().Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::NOTFOUND, vNotFound));
    }
}
//uint32_t GetFetchFlags(CNode* pfrom, CBlockIndex* pprev, const Consensus::Params& chainparams) {
//    uint32_t nFetchFlags = 0;
//    if ((pfrom->GetLocalServices() & NODE_WITNESS) && State(pfrom->GetId())->fHaveWitness) {
//        nFetchFlags |= MSG_WITNESS_FLAG;
//    }
//    return nFetchFlags;
//}

bool fRequestedSporksIDB = false;
bool static ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, int64_t nTimeReceived, const CChainParams& chainparams, CConnman* connman, const std::atomic<bool>& interruptMsgProc, bool enable_bip61)
{
    LogPrint(BCLog::NET, "received: %s (%u bytes) peer=%d\n", SanitizeString(strCommand), vRecv.size(), pfrom->GetId());
    if (gArgs.IsArgSet("-dropmessagestest") && GetRand(gArgs.GetArg("-dropmessagestest", 0)) == 0) {
        LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    if (strCommand == NetMsgType::VERSION) {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0) {
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::REJECT, strCommand, REJECT_DUPLICATE, std::string("Duplicate version message")));
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 1);
            return false;
        }

        // WISPR: We use certain sporks during IBD, so check to see if they are
        // available. If not, ask the first peer connected for them.
        bool fMissingSporks = !pSporkDB->SporkExists(SPORK_14_NEW_PROTOCOL_ENFORCEMENT) &&
            !pSporkDB->SporkExists(SPORK_15_NEW_PROTOCOL_ENFORCEMENT_2) &&
            !pSporkDB->SporkExists(SPORK_16_ZEROCOIN_MAINTENANCE_MODE);

        if (fMissingSporks || !fRequestedSporksIDB){
            LogPrintf("asking peer for sporks\n");
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETSPORKS));
            fRequestedSporksIDB = true;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        int nVersion;
        int nSendVersion;
        uint64_t nNonce = 1;
        uint64_t nServiceInt;
        ServiceFlags nServices;
        std::string strSubVer;
        std::string cleanSubVer;
        int nStartingHeight = -1;
        bool fRelay = true;

        vRecv >> nVersion >> nServiceInt >> nTime >> addrMe;
        nSendVersion = std::min(nVersion, PROTOCOL_VERSION);
        nServices = ServiceFlags(nServiceInt);
        pfrom->nServices = ServiceFlags(nServiceInt);
        if(pfrom->nVersion < ActiveProtocol()){
            LogPrint(BCLog::NET, "peer=%d using obsolete version %i; disconnecting\n", pfrom->GetId(), nVersion);
            connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                                                                              strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION)));
            return false;
        }
        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty()) {
            vRecv >> LIMITED_STRING(pfrom->strSubVer, MAX_SUBVERSION_LENGTH);
            pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
        }
        if (!vRecv.empty())
            vRecv >> nStartingHeight;
        if (!vRecv.empty())
            vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
        else
            pfrom->fRelayTxes = true;

        // Disconnect if we connected to ourself
        if (nNonce == pfrom->GetLocalNonce() && nNonce > 1) {
            LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }
        pfrom->nStartingHeight = nStartingHeight;

        pfrom->SetAddrLocal(addrMe);
        if (pfrom->fInbound && addrMe.IsRoutable()) {
            SeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            PushNodeVersion(pfrom, connman, GetAdjustedTime());

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        // Potentially mark this peer as a preferred download peer.
        UpdatePreferredDownload(pfrom, State(pfrom->GetId()));

        // Change version
        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::VERACK));
        pfrom->SetSendVersion(nSendVersion);
        pfrom->nVersion = nVersion;
        if (!pfrom->fInbound) {
            // Advertise our address
            if (fListen && !IsInitialBlockDownload()) {
                CAddress addr = GetLocalAddress(&pfrom->addr, pfrom->GetLocalServices());
                FastRandomContext insecure_rand;
                if (addr.IsRoutable()) {
                    LogPrintf("ProcessMessages: advertizing address %s\n", addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                } else if (IsPeerAddrLocalGood(pfrom)) {
                    addr.SetIP(pfrom->GetAddrLocal());
                    LogPrintf("ProcessMessages: advertizing address %s\n", addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || connman->GetAddressCount() < 1000) {
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETADDR));
                pfrom->fGetAddr = true;
            }
            connman->MarkAddressGood(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom) {
                std::vector<CAddress> vAddr;
                vAddr.push_back(addrFrom);
                connman->AddNewAddresses(vAddr, addrFrom);
                connman->MarkAddressGood(addrFrom);
            }
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            for (std::pair<const uint256, CAlert> & item: mapAlerts)
                item.second.RelayTo(pfrom, connman);
        }

        pfrom->fSuccessfullyConnected = true;

        std::string remoteAddr;
        if (fLogIPs)
            remoteAddr = ", peeraddr=" + pfrom->addr.ToString();

        LogPrintf("receive version message: %s: version %d, blocks=%d, us=%s, peer=%d%s\n",
                  pfrom->cleanSubVer, pfrom->nVersion,
                  pfrom->nStartingHeight, addrMe.ToString(), pfrom->GetId(),
                  remoteAddr);

        int64_t nTimeOffset = nTime - GetTime();
        pfrom->nTimeOffset = nTimeOffset;
        AddTimeData(pfrom->addr, nTimeOffset);
    }


    else if (pfrom->nVersion == 0) {
        // Must have a version message before anything else
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 1);
        return false;
    }


    else if (strCommand == NetMsgType::VERACK) {
        pfrom->SetRecvVersion(std::min(pfrom->nVersion.load(), PROTOCOL_VERSION));

        // Mark this node as currently connected, so we update its timestamp later.
        if (!pfrom->fInbound) {
            LOCK(cs_main);
            State(pfrom->GetId())->fCurrentlyConnected = true;
        }
    }


    else if (strCommand == NetMsgType::ADDR) {
        std::vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && connman->GetAddressCount() > 1000)
            return true;
        if (vAddr.size() > 1000) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message addr size() = %u", vAddr.size());
        }

        // Store the new addresses
        std::vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        for (CAddress& addr: vAddr) {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable()) {
                // Relay to a limited number of other nodes
                {
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the addrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr << 32) ^ ((GetTime() + hashAddr) / (24 * 60 * 60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    connman->ForEachNode([&](CNode* pnode) {
                        if (!(pnode->nVersion < CADDR_TIME_VERSION)){
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(std::make_pair(hashKey, pnode));
                        }
                    });
                    FastRandomContext insecure_rand;
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr, insecure_rand);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        connman->AddNewAddresses(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }


    else if (strCommand == NetMsgType::INV) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message inv size() = %u", vInv.size());
        }

        LOCK(cs_main);

        std::vector<CInv> vToFetch;

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
            const CInv& inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(inv);
            LogPrint(BCLog::NET, "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom->GetId());

            if (!fAlreadyHave && !fImporting && !fReindex && inv.type != MSG_BLOCK)
                pfrom->AskFor(inv);


            if (inv.type == MSG_BLOCK) {
                UpdateBlockAvailability(pfrom->GetId(), inv.hash);
                if (!fAlreadyHave && !fImporting && !fReindex && !mapBlocksInFlight.count(inv.hash)) {
                    // Add this to the list of blocks to request
                    vToFetch.push_back(inv);
                    LogPrint(BCLog::NET, "getblocks (%d) %s to peer=%d\n", pindexBestHeader->nHeight, inv.hash.ToString(), pfrom->GetId());
                }
            }

            // Track requests for our stuff
            GetMainSignals().Inventory(inv.hash);

            if (pfrom->nSendSize > (SendBufferSize() * 2)) {
                Misbehaving(pfrom->GetId(), 50);
                return error("send buffer size() = %u", pfrom->nSendSize);
            }
        }

        if (!vToFetch.empty())
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
    }


    else if (strCommand == NetMsgType::GETDATA) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message getdata size() = %u", vInv.size());
        }

        if (fDebug || (vInv.size() != 1))
            LogPrint(BCLog::NET, "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom->GetId());

        if ((fDebug && vInv.size() > 0) || (vInv.size() == 1))
            LogPrint(BCLog::NET, "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom->GetId());

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom, chainparams, connman, interruptMsgProc);
    }


    else if (strCommand == NetMsgType::GETBLOCKS) {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = FindForkInGlobalIndex(chainActive, locator);

        // Send the rest of the chain
        if (pindex)
            pindex = chainActive.Next(pindex);
        int nLimit = 500;
        LogPrint(BCLog::NET, "getblocks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop == uint256(0) ? "end" : hashStop.ToString(), nLimit, pfrom->GetId());
        for (; pindex; pindex = chainActive.Next(pindex)) {
            if (pindex->GetBlockHash() == hashStop) {
                LogPrint(BCLog::NET, "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0) {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                LogPrint(BCLog::NET, "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }


    else if (strCommand == NetMsgType::GETHEADERS && Params().HeadersFirstSyncingActive()) {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        if (IsInitialBlockDownload())
            return true;

        CBlockIndex* pindex = nullptr;
        if (locator.IsNull()) {
            // If locator is null, return the hashStop block
            BlockMap::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        } else {
            // Find the last block the caller has in the main chain
            pindex = FindForkInGlobalIndex(chainActive, locator);
            if (pindex)
                pindex = chainActive.Next(pindex);
        }

        // we must use CBlockGetHeader, as CBlockHeaders won't include the 0x00 nTx count at the end
        std::vector<CBlockGetHeader> vHeaders;
        int nLimit = MAX_HEADERS_RESULTS;
        if (fDebug)
            LogPrintf("getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString(), pfrom->GetId());
        for (; pindex; pindex = chainActive.Next(pindex)) {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
    }


    else if (strCommand == NetMsgType::TX || strCommand == NetMsgType::DSTX) {
        std::vector<uint256> vWorkQueue;
        std::vector<uint256> vEraseQueue;
        CTransactionRef ptx;
        //masternode signed transaction
        bool ignoreFees = false;
        CTxIn vin;
        std::vector<unsigned char> vchSig;
        int64_t sigTime = 0;

//        if (strCommand == NetMsgType::TX) {
//            CTransactionRef ptx;
//            vRecv >> ptx;
//            tx = *ptx;
//        } else
//            if (strCommand == NetMsgType::DSTX) {
        //these allow masternodes to publish a limited amount of free transactions
//            vRecv >> tx >> vin >> vchSig >> sigTime;
        if (strCommand == NetMsgType::TX){
            vRecv >> ptx;
        } else if (strCommand == NetMsgType::DSTX){
            vRecv >> ptx >> vin >> vchSig >> sigTime;
        }
        const CTransaction &tx = *ptx;
        if (strCommand == NetMsgType::DSTX){
            CMasternode *pmn = mnodeman.Find(vin);
            if (pmn != nullptr) {
                if (!pmn->allowFreeTx) {
                    //multiple peers can send us a valid masternode transaction
                    if (fDebug) LogPrintf("dstx: Masternode sending too many transactions %s\n", tx.GetHash().ToString());
                    return true;
                }

            std::string strMessage = tx.GetHash().ToString() + std::to_string(sigTime);

            std::string errorMessage = "";
            if (!obfuScationSigner.VerifyMessage(pmn->pubKeyMasternode, vchSig, strMessage, errorMessage)) {
                LogPrintf("dstx: Got bad masternode address signature %s \n", vin.ToString());
                //pfrom->Misbehaving(20);
                return false;
            }

            LogPrintf("dstx: Got Masternode transaction %s\n", tx.GetHash().ToString());

            ignoreFees = true;
            pmn->allowFreeTx = false;

            if (!mapObfuscationBroadcastTxes.count(tx.GetHash())) {
                CObfuscationBroadcastTx dstx;
                dstx.tx = tx;
                dstx.vin = vin;
                dstx.vchSig = vchSig;
                dstx.sigTime = sigTime;

                mapObfuscationBroadcastTxes.insert(std::make_pair(tx.GetHash(), dstx));
            }
          }
        }
        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

        bool fMissingInputs = false;
        bool fMissingZerocoinInputs = false;
        CValidationState state;

        mapAlreadyAskedFor.erase(inv);

        if (!tx.IsZerocoinSpend() && AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs, false, ignoreFees)) {
            mempool.check(pcoinsTip.get());
            RelayTransaction(tx, connman);
            vWorkQueue.push_back(inv.hash);

            LogPrint(BCLog::MEMPOOL, "AcceptToMemoryPool: peer=%d %s : accepted %s (poolsz %u)\n",
                     pfrom->GetId(), pfrom->cleanSubVer,
                     tx.GetHash().ToString(),
                     mempool.mapTx.size());

            // Recursively process any orphan transactions that depended on this one
            set<NodeId> setMisbehaving;
            for(unsigned int i = 0; i < vWorkQueue.size(); i++) {
                map<uint256, set<uint256> >::iterator itByPrev = mapOrphanTransactionsByPrev.find(vWorkQueue[i]);
                if(itByPrev == mapOrphanTransactionsByPrev.end())
                    continue;
                for(set<uint256>::iterator mi = itByPrev->second.begin();
                    mi != itByPrev->second.end();
                    ++mi) {
                    const uint256 &orphanHash = *mi;
                    const CTransaction &orphanTx = mapOrphanTransactions[orphanHash].tx;
                    NodeId fromPeer = mapOrphanTransactions[orphanHash].fromPeer;
                    bool fMissingInputs2 = false;
                    // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
                    // resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
                    // anyone relaying LegitTxX banned)
                    CValidationState stateDummy;


                    if(setMisbehaving.count(fromPeer))
                        continue;
                    if(AcceptToMemoryPool(mempool, stateDummy, orphanTx, true, &fMissingInputs2)) {
                        LogPrint(BCLog::MEMPOOL, "   accepted orphan tx %s\n", orphanHash.ToString());
                        RelayTransaction(orphanTx, connman);
                        vWorkQueue.push_back(orphanHash);
                        vEraseQueue.push_back(orphanHash);
                    } else if(!fMissingInputs2) {
                        int nDos = 0;
                        if(stateDummy.IsInvalid(nDos) && nDos > 0) {
                            // Punish peer that gave us an invalid orphan tx
                            Misbehaving(fromPeer, nDos);
                            setMisbehaving.insert(fromPeer);
                            LogPrint(BCLog::MEMPOOL, "   invalid orphan tx %s\n", orphanHash.ToString());
                        }
                        // Has inputs but not accepted to mempool
                        // Probably non-standard or insufficient fee/priority
                        LogPrint(BCLog::MEMPOOL, "   removed orphan tx %s\n", orphanHash.ToString());
                        vEraseQueue.push_back(orphanHash);
                    }
                    mempool.check(pcoinsTip.get());
                }
            }

            for (uint256 hash: vEraseQueue)EraseOrphanTx(hash);
        } else if (tx.IsZerocoinSpend() && AcceptToMemoryPool(mempool, state, tx, true, &fMissingZerocoinInputs, false, ignoreFees)) {
            //Presstab: ZCoin has a bunch of code commented out here. Is this something that should have more going on?
            //Also there is nothing that handles fMissingZerocoinInputs. Does there need to be?
            RelayTransaction(tx, connman);
            LogPrint(BCLog::MEMPOOL, "AcceptToMemoryPool: Zerocoinspend peer=%d %s : accepted %s (poolsz %u)\n",
                     pfrom->GetId(), pfrom->cleanSubVer,
                     tx.GetHash().ToString(),
                     mempool.mapTx.size());
        } else if (fMissingInputs) {
            AddOrphanTx(tx, pfrom->GetId());

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, gArgs.GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
            unsigned int nEvicted = LimitOrphanTxSize(nMaxOrphanTx);
            if (nEvicted > 0)
                LogPrint(BCLog::MEMPOOL, "mapOrphan overflow, removed %u tx\n", nEvicted);
        } else if (pfrom->fWhitelisted) {
            // Always relay transactions received from whitelisted peers, even
            // if they are already in the mempool (allowing the node to function
            // as a gateway for nodes hidden behind it).

            RelayTransaction(tx, connman);
        }

        if (strCommand == NetMsgType::DSTX) {
            CInv inv(MSG_DSTX, tx.GetHash());
            RelayInv(inv, connman);
        }

        int nDoS = 0;
        if (state.IsInvalid(nDoS)) {
            LogPrint(BCLog::MEMPOOL, "%s from peer=%d %s was not accepted into the memory pool: %s\n", tx.GetHash().ToString(),
                     pfrom->GetId(), pfrom->cleanSubVer,
                     state.GetRejectReason());
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::REJECT, strCommand, state.GetRejectCode(),
                               state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash));
            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);
        }
    }


    else if (strCommand == NetMsgType::HEADERS && Params().HeadersFirstSyncingActive() && !fImporting && !fReindex) // Ignore headers received while importing
    {
        std::vector<CBlockHeader> headers;

        // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("headers message size = %u", nCount);
        }
        headers.resize(nCount);
        for (unsigned int n = 0; n < nCount; n++) {
            vRecv >> headers[n];
            ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
        }

        {
            LOCK(cs_main);

            if (nCount == 0) {
                // Nothing interesting. Stop asking this peers for more headers.
                return true;
            }
            CBlockIndex* pindexLast = nullptr;
            for (const CBlockHeader& header : headers) {
                CValidationState state;
                if (pindexLast != NULL && header.hashPrevBlock != pindexLast->GetBlockHash()) {
                    Misbehaving(pfrom->GetId(), 20);
                    return error("non-continuous headers sequence");
                }
                if (!AcceptBlockHeader(header, state, &pindexLast)) {
                    int nDoS;
                    if (state.IsInvalid(nDoS)) {
                        if (nDoS > 0)
                            Misbehaving(pfrom->GetId(), nDoS);
                        std::string strError = "invalid header received " + header.GetHash().ToString();
                        return error(strError.c_str());
                    }
                }
            }

            if (pindexLast)
                UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());

            if (nCount == MAX_HEADERS_RESULTS && pindexLast) {
                // Headers message had its maximum size; the peer may have more headers.
                // TODO: optimize: if pindexLast is an ancestor of chainActive.Tip or pindexBestHeader, continue
                // from there instead.
                LogPrintf("more getheaders (%d) to end to peer=%d (startheight:%d)\n", pindexLast->nHeight, pfrom->GetId(), pfrom->nStartingHeight);
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexLast), uint256(0)));
            }
        }
    }

    else if (strCommand == NetMsgType::BLOCK && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();
        CInv inv(MSG_BLOCK, hashBlock);
        LogPrint(BCLog::NET, "received block %s peer=%d\n", inv.hash.ToString(), pfrom->GetId());

        //sometimes we will be sent their most recent block and its not the one we want, in that case tell where we are
        if (!mapBlockIndex.count(block.hashPrevBlock)) {
            if (find(pfrom->vBlockRequested.begin(), pfrom->vBlockRequested.end(), hashBlock) != pfrom->vBlockRequested.end()) {
                //we already asked for this block, so lets work backwards and ask for the previous block
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETBLOCKS, chainActive.GetLocator(), block.hashPrevBlock));
                pfrom->vBlockRequested.push_back(block.hashPrevBlock);
            } else {
                //ask to sync to this block
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETBLOCKS, chainActive.GetLocator(), hashBlock));
                pfrom->vBlockRequested.push_back(hashBlock);
            }
        } else {
            pfrom->AddInventoryKnown(inv);
            if (!mapBlockIndex.count(block.GetHash())) {
                // Process all blocks from whitelisted peers, even if not requested,
                // unless we're still syncing with the network.
                // Such an unrequested block may still be processed, subject to the
                // conditions in AcceptBlock().
                bool forceProcessing = pfrom->fWhitelisted && !IsInitialBlockDownload();
                const uint256 hash(block.GetHash());
                {
                    LOCK(cs_main);
                    // Also always process if we requested the block explicitly, as we may
                    // need it even though it is not a candidate for a new best tip.
                    forceProcessing |= MarkBlockAsReceived(hash);
                    // mapBlockSource is only used for sending reject messages and DoS scores,
                    // so the race between here and cs_main in ProcessNewBlock is fine.
                    mapBlockSource.emplace(hash, pfrom->GetId());
                }
                bool fNewBlock = false;
                ProcessNewBlock(chainparams, &block, forceProcessing, NULL, &fNewBlock);
                if (fNewBlock)
                    pfrom->nLastBlockTime = GetTime();
                //disconnect this node if its old protocol version
                if(pfrom->nVersion < ActiveProtocol()){
                    connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                                                                                      strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION)));
                }
            } else {
                LogPrint(BCLog::NET, "%s : Already processed block %s, skipping ProcessNewBlock()\n", __func__, block.GetHash().GetHex());
            }
        }
    }

    else if (strCommand == NetMsgType::ACCVALUE) {
        if(pfrom->GetLocalServices() & NODE_BLOOM_LIGHT_ZC) {
            try {
                int height;
                libzerocoin::CoinDenomination den;
                vRecv >> height;
                vRecv >> den;
                CBigNum bnAccValue = 0;
                //std::cout << "asking for checkpoint value in height: " << height << ", den: " << den << std::endl;
                if (!GetAccumulatorValue(height, den, bnAccValue)) {
                    LogPrint(BCLog::ZWSP, "peer misbehaving for request an invalid acc checkpoint \n", __func__);
                    Misbehaving(pfrom->GetId(), 50);
                } else {
                    //std::cout << "Sending acc value, with checksum: " << GetChecksum(bnAccValue) << " for "
                    //          << bnAccValue.GetDec() << std::endl;
                    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                    ss << bnAccValue;
                    ss << height;
                    connman->PushMessage(pfrom, msgMaker.Make("accvalueresponse", ss));
                }
            } catch (std::exception &e) {
                // TODO: Response with an error?
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
    }

    else if (strCommand == NetMsgType::GENWIT) {
        if(pfrom->GetLocalServices() & NODE_BLOOM_LIGHT_ZC) {
            try {
                CGenWit gen;
                vRecv >> gen;
                gen.setPfrom(pfrom);
                if (gen.isValid(chainActive.Height())) {
                    if (!lightWorker.addWitWork(gen)) {
                        LogPrint(BCLog::ZWSP, "%s : add genwit request failed \n", __func__);
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        // Invalid request only returns the message without a result.
                        ss << gen.getRequestNum();
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::PUBCOINS, ss));
                    }
                } else {
                    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                    // Invalid request only returns the message without a result.
                    ss << gen.getRequestNum();
                    connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::PUBCOINS, ss));
                }
            } catch (std::exception &e) {
                // TODO: Response with an error?
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
    }

        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages.
        // Making users (which are behind NAT and can only make outgoing connections) ignore
        // getaddr message mitigates the attack.
    else if ((strCommand == NetMsgType::GETADDR) && (pfrom->fInbound)) {
        pfrom->vAddrToSend.clear();
        std::vector<CAddress> vAddr = connman->GetAddresses();
        FastRandomContext insecure_rand;
        for (const CAddress& addr: vAddr)
            pfrom->PushAddress(addr, insecure_rand);
    }


    else if (strCommand == NetMsgType::MEMPOOL) {
        LOCK2(cs_main, pfrom->cs_filter);

        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);
        std::vector<CInv> vInv;
        for (uint256& hash: vtxid) {
            CInv inv(MSG_TX, hash);
            CTransactionRef ptx;
            CTransaction tx;
            ptx = mempool.get(hash);
//            bool fInMemPool = mempool.lookup(hash, tx);
            if (ptx == nullptr) continue; // another thread removed since queryHashes, maybe...
            tx = *ptx;
            if ((pfrom->pfilter && pfrom->pfilter->IsRelevantAndUpdate(tx)) ||
                (!pfrom->pfilter))
                vInv.push_back(inv);
            if (vInv.size() == MAX_INV_SZ) {
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::INV, vInv));
                vInv.clear();
            }
        }
        if (vInv.size() > 0)
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::INV, vInv));
    }


    else if (strCommand == NetMsgType::PING) {
        if (pfrom->nVersion > BIP0031_VERSION) {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::PONG, nonce));
        }
    }


    else if (strCommand == NetMsgType::PONG) {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) {
                if (nonce == pfrom->nPingNonceSent) {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere, cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere, cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            LogPrint(BCLog::NET, "pong peer=%d %s: %s, %x expected, %x received, %u bytes\n",
                     pfrom->GetId(),
                     pfrom->cleanSubVer,
                     sProblem,
                     pfrom->nPingNonceSent,
                     nonce,
                     nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
    }


    else if (fAlerts && strCommand == NetMsgType::ALERT) {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0) {
            if (alert.ProcessAlert()) {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    connman->ForEachNode([&](CNode* pnode) {
                            alert.RelayTo(pnode, connman);
                    });
                }
            } else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                LOCK(cs_main);
                Misbehaving(pfrom->GetId(), 10);
            }
        }
    }

    else if (!(pfrom->GetLocalServices() & NODE_BLOOM) &&
        (strCommand == NetMsgType::FILTERLOAD ||
            strCommand == NetMsgType::FILTERADD ||
            strCommand == NetMsgType::FILTERCLEAR)) {
        LogPrintf("bloom message=%s\n", strCommand);
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 100);
    }

    else if (strCommand == NetMsgType::FILTERLOAD) {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints()) {
            // There is no excuse for sending a too-large filter
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
        } else {
            LOCK(pfrom->cs_filter);
            pfrom->pfilter.reset(new CBloomFilter(filter));
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == NetMsgType::FILTERADD) {
        std::vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
                pfrom->pfilter->insert(vData);
            else {
                LOCK(cs_main);
                Misbehaving(pfrom->GetId(), 100);
            }
        }
    }


    else if (strCommand == NetMsgType::FILTERCLEAR) {
        LOCK(pfrom->cs_filter);
        pfrom->pfilter.reset(new CBloomFilter());
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == NetMsgType::REJECT) {
        if (fDebug) {
            try {
                std::string strMsg;
                unsigned char ccode;
                std::string strReason;
                vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode >> LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

                ostringstream ss;
                ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

                if (strMsg == NetMsgType::BLOCK || strMsg == NetMsgType::TX) {
                    uint256 hash;
                    vRecv >> hash;
                    ss << ": hash " << hash.ToString();
                }
                LogPrint(BCLog::NET, "Reject %s\n", SanitizeString(ss.str()));
            } catch (std::ios_base::failure& e) {
                // Avoid feedback loops by preventing reject messages from triggering a new reject message.
                LogPrint(BCLog::NET, "Unparseable reject message received\n");
            }
        }
    } else {
        //probably one the extensions
        obfuScationPool.ProcessMessageObfuscation(pfrom, strCommand, vRecv, connman);
        mnodeman.ProcessMessage(pfrom, strCommand, vRecv, connman);
        budget.ProcessMessage(pfrom, strCommand, vRecv, connman);
        masternodePayments.ProcessMessageMasternodePayments(pfrom, strCommand, vRecv, connman);
        ProcessMessageSwiftTX(pfrom, strCommand, vRecv, connman);
        ProcessSpork(pfrom, strCommand, vRecv, connman);
        masternodeSync.ProcessMessage(pfrom, strCommand, vRecv, connman);
    }


    return true;
}

// requires LOCK(cs_vRecvMsg)
bool PeerLogicValidation::ProcessMessages(CNode* pfrom, std::atomic<bool>& interruptMsgProc)
{
    const CChainParams& chainparams = Params();
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    //if (fDebug)
    //    LogPrintf("ProcessMessages(%u messages)\n", pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom, chainparams, connman, interruptMsgProc);

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return fOk;

    std::list<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    LogPrintf("ProcessMessages(message %u msgsz, %u bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, Params().MessageStart(), CMessageHeader::MESSAGE_START_SIZE) != 0) {
            LogPrintf("PROCESSMESSAGE: INVALID MESSAGESTART %s peer=%d\n", SanitizeString(msg.hdr.GetCommand()), pfrom->GetId());
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid(chainparams.MessageStart())) {
            LogPrintf("PROCESSMESSAGE: ERRORS IN HEADER %s peer=%d\n", SanitizeString(hdr.GetCommand()), pfrom->GetId());
            continue;
        }
        std::string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != *hdr.pchChecksum) {
            LogPrintf("ProcessMessages(%s, %u bytes): CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
                      SanitizeString(strCommand), nMessageSize, nChecksum, hdr.pchChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try {
            fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime, chainparams, connman, interruptMsgProc, false);
            boost::this_thread::interruption_point();
        } catch (std::ios_base::failure& e) {
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::REJECT, strCommand, REJECT_MALFORMED, std::string("error parsing message")));
            if (strstr(e.what(), "end of data")) {
                // Allow exceptions from under-length message on vRecv
                LogPrintf("ProcessMessages(%s, %u bytes): Exception '%s' caught, normally caused by a message being shorter than its stated length\n", SanitizeString(strCommand), nMessageSize, e.what());
            } else if (strstr(e.what(), "size too large")) {
                // Allow exceptions from over-long size
                LogPrintf("ProcessMessages(%s, %u bytes): Exception '%s' caught\n", SanitizeString(strCommand), nMessageSize, e.what());
            } else {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        } catch (boost::thread_interrupted) {
            throw;
        } catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            LogPrintf("ProcessMessage(%s, %u bytes) FAILED peer=%d\n", SanitizeString(strCommand), nMessageSize, pfrom->GetId());

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}

//class CompareInvMempoolOrder
//{
//  CTxMemPool *mp;
//public:
//  CompareInvMempoolOrder(CTxMemPool *_mempool)
//  {
//      mp = _mempool;
//  }
//
//  bool operator()(std::set<uint256>::iterator a, std::set<uint256>::iterator b)
//  {
//      /* As std::make_heap produces a max-heap, we want the entries with the
//       * fewest ancestors/highest fee to sort later. */
//      return mp->CompareDepthAndScore(*b, *a);
//  }
//};

bool PeerLogicValidation::SendMessages(CNode* pto)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    bool fSendTrickle = pto->fWhitelisted;
    {
        // Don't send anything until we get their version message
        if (!pto->fSuccessfullyConnected || pto->fDisconnect)
            return true;

        // If we get here, the outgoing message serialization version is set and can't change.
        const CNetMsgMaker msgMaker(pto->GetSendVersion());

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pto->fPingQueued) {
            // RPC ping request by user
            pingSend = true;
        }
        if (pto->nPingNonceSent == 0 && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros()) {
            // Ping automatically sent as a latency probe & keepalive.
            pingSend = true;
        }
        if (pingSend) {
            uint64_t nonce = 0;
            while (nonce == 0) {
                GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
            }
            pto->fPingQueued = false;
            pto->nPingUsecStart = GetTimeMicros();
            if (pto->nVersion > BIP0031_VERSION) {
                pto->nPingNonceSent = nonce;
                connman->PushMessage(pto, msgMaker.Make(NetMsgType::PING, nonce));
            } else {
                // Peer is too old to support ping command with nonce, pong will never arrive.
                pto->nPingNonceSent = 0;
                connman->PushMessage(pto, msgMaker.Make(NetMsgType::PING));
            }
        }

        TRY_LOCK(cs_main, lockMain); // Acquire cs_main for IsInitialBlockDownload() and CNodeState()
        if (!lockMain)
            return true;

        // Address refresh broadcast
        int64_t nNow = GetTimeMicros();
        if (!IsInitialBlockDownload() && pto->nNextLocalAddrSend < nNow) {
            AdvertiseLocal(pto);
            pto->nNextLocalAddrSend = PoissonNextSend(nNow, AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL);
        }

        //
        // Message: addr
        //
        if (fSendTrickle) {
            std::vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            for (const CAddress& addr: pto->vAddrToSend) {
                if (!pto->addrKnown.contains(addr.GetKey())){
                    pto->addrKnown.insert(addr.GetKey());
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000) {
                        connman->PushMessage(pto, msgMaker.Make(NetMsgType::ADDR, vAddr));
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                connman->PushMessage(pto, msgMaker.Make(NetMsgType::ADDR, vAddr));
        }

        CNodeState& state = *State(pto->GetId());
        int64_t banTime = pto->nVersion < 70914 ? 60*15 : 24*60*60;
        if (state.fShouldBan) {
            if (pto->fWhitelisted)
                LogPrintf("Warning: not punishing whitelisted peer %s!\n", pto->addr.ToString());
            else {
                pto->fDisconnect = true;
                if (pto->addr.IsLocal())
                    LogPrintf("Warning: not banning local peer %s!\n", pto->addr.ToString());
                else {
                    m_banman->Ban(pto->addr, BanReasonNodeMisbehaving, banTime);
                }
            }
            state.fShouldBan = false;
        }

        for (const CBlockReject& reject: state.rejects)
            connman->PushMessage(pto, msgMaker.Make(NetMsgType::REJECT, (std::string) NetMsgType::BLOCK, reject.chRejectCode, reject.strRejectReason, reject.hashBlock));
        state.rejects.clear();

        // Start block sync
        if (pindexBestHeader == nullptr)
            pindexBestHeader = chainActive.Tip();
        bool fFetch = state.fPreferredDownload || (nPreferredDownload == 0 && !pto->fClient && !pto->fOneShot); // Download if this is a nice peer, or we have no nice peers and this one might do.
        if (!state.fSyncStarted && !pto->fClient && fFetch /*&& !fImporting*/ && !fReindex) {
            // Only actively request headers from a single peer, unless we're close to end of initial download.
            if (nSyncStarted == 0 || pindexBestHeader->GetBlockTime() > GetAdjustedTime() - 6 * 60 * 60) { // NOTE: was "close to today" and 24h in Bitcoin
                state.fSyncStarted = true;
                nSyncStarted++;
                //CBlockIndex *pindexStart = pindexBestHeader->pprev ? pindexBestHeader->pprev : pindexBestHeader;
                //LogPrint(BCLog::NET, "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, pto->GetId(, pto->nStartingHeight);
                //connman->PushMessage(pto, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexStart), uint256(0)));
                connman->PushMessage(pto, msgMaker.Make(NetMsgType::GETBLOCKS, chainActive.GetLocator(chainActive.Tip()), uint256(0)));
            }
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            GetMainSignals().Broadcast(nTimeBestReceived);
        }

        //
        // Message: inventory
        //
        std::vector<CInv> vInv;
        std::vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            for (const CInv& inv: pto->vInventoryToSend) {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle) {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    if (fTrickleWait) {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second) {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000) {
                        connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));

        // Detect whether we're stalling
//        int64_t nNow = GetTimeMicros();
        if (!pto->fDisconnect && state.nStallingSince && state.nStallingSince < nNow - 1000000 * BLOCK_STALLING_TIMEOUT) {
            // Stalling only triggers when the block download window cannot move. During normal steady state,
            // the download window should be much larger than the to-be-downloaded set of blocks, so disconnection
            // should only happen during initial block download.
            LogPrintf("Peer=%d is stalling block download, disconnecting\n", pto->GetId());
            pto->fDisconnect = true;
        }
        // In case there is a block that has been in flight from this peer for (2 + 0.5 * N) times the block interval
        // (with N the number of validated blocks that were in flight at the time it was requested), disconnect due to
        // timeout. We compensate for in-flight blocks to prevent killing off peers due to our own downstream link
        // being saturated. We only count validated in-flight blocks so peers can't advertize nonexisting block hashes
        // to unreasonably increase our timeout.

        if (!pto->fDisconnect && state.vBlocksInFlight.size() > 0 && state.vBlocksInFlight.front().nTime < nNow - 500000 * Params().TargetSpacingV2() * (4 + state.vBlocksInFlight.front().nValidatedQueuedBefore)) {
            LogPrintf("Timeout downloading block %s from peer=%d, disconnecting\n", state.vBlocksInFlight.front().hash.ToString(), pto->GetId());
            pto->fDisconnect = true;
        }

        //
        // Message: getdata (blocks)
        //
        std::vector<CInv> vGetData;
        if (!pto->fDisconnect && !pto->fClient && fFetch && state.nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            std::vector<CBlockIndex*> vToDownload;
            NodeId staller = -1;
            FindNextBlocksToDownload(pto->GetId(), MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight, vToDownload, staller);
            for (CBlockIndex* pindex: vToDownload) {
                vGetData.push_back(CInv(MSG_BLOCK, pindex->GetBlockHash()));
                MarkBlockAsInFlight(pto->GetId(), pindex->GetBlockHash(), pindex);
                LogPrintf("Requesting block %s (%d) peer=%d\n", pindex->GetBlockHash().ToString(),
                          pindex->nHeight, pto->GetId());
            }
            if (state.nBlocksInFlight == 0 && staller != -1) {
                if (State(staller)->nStallingSince == 0) {
                    State(staller)->nStallingSince = nNow;
                    LogPrint(BCLog::NET, "Stall started peer=%d\n", staller);
                }
            }
        }

        //
        // Message: getdata (non-blocks)
        //
        while (!pto->fDisconnect && !pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow) {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(inv)) {
                if (fDebug)
                    LogPrint(BCLog::NET, "Requesting %s peer=%d\n", inv.ToString(), pto->GetId());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000) {
                    connman->PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                    vGetData.clear();
                }
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            connman->PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
    }
    return true;
}

class CNetProcessingCleanup
{
public:
  CNetProcessingCleanup() {}
  ~CNetProcessingCleanup() {
      // orphan transactions
      mapOrphanTransactions.clear();
      mapOrphanTransactionsByPrev.clear();
  }
} instance_of_cnetprocessingcleanup;