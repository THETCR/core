// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include "net.h"
#include "validationinterface.h"
#include <consensus/params.h>
#include <sync.h>

extern CCriticalSection cs_main;

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);

/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
/** Default number of orphan+recently-replaced txn to keep around for block reconstruction */
static const unsigned int DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100;
/** Default for BIP61 (sending reject messages) */
static constexpr bool DEFAULT_ENABLE_BIP61{false};

class PeerLogicValidation : public CValidationInterface {
private:
  CConnman* connman;

public:
  PeerLogicValidation(CConnman* connmanIn);
//  PeerLogicValidation(CConnman* connmanIn) : connman(connmanIn) {}

//  virtual void SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int nPosInBlock);
  void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
  void BlockChecked(const CBlock& block, const CValidationState& state) override;
};

struct CNodeStateStats {
  int nMisbehavior;
  int nSyncHeight;
  int nCommonHeight;
  std::vector<int> vHeightInFlight;
};

/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats);
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch);

/** Process protocol messages received from a given node */
bool ProcessMessages(CNode* pfrom);
/**
 * Send queued protocol messages to be sent to a give node.
 *
 * @param[in]   pto             The node which we are sending messages to.
 * @param[in]   fSendTrickle    When true send the trickled data, otherwise trickle the data until true.
 */
bool SendMessages(CNode* pto, bool fSendTrickle);

class CTransaction;
void RelayTransaction(const CTransaction& tx);
void RelayTransaction(const CTransaction& tx, const CDataStream& ss);
void RelayTransactionLockReq(const CTransaction& tx, bool relayToAll = false);
void RelayInv(CInv& inv);

#endif // BITCOIN_NET_PROCESSING_H