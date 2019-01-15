// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TRANSACTIONRECORD_H
#define BITCOIN_QT_TRANSACTIONRECORD_H

#include <amount.h>
#include <uint256.h>

#include <QList>
#include <QString>
#include <utility>

namespace interfaces {
class Node;
class Wallet;
struct WalletTx;
struct WalletTxStatus;
}

/** UI model for transaction status. The transaction status is the part of a transaction that will change over time.
 */
class TransactionStatus
{
public:
    TransactionStatus():
            , sortKey(""), , , , , { }

    enum Status {
        Confirmed,          /**< Have 6 or more confirmations (normal tx) or fully mature (mined tx) **/
        /// Normal (sent/received) transactions
        OpenUntilDate,      /**< Transaction not yet final, waiting for date */
        OpenUntilBlock,     /**< Transaction not yet final, waiting for block */
        Unconfirmed,        /**< Not yet mined into a block **/
        Confirming,         /**< Confirmed, but waiting for the recommended number of confirmations **/
        Conflicted,         /**< Conflicts with other transaction or mempool **/
        Abandoned,          /**< Abandoned from the wallet **/
        /// Generated (mined) transactions
        Immature,           /**< Mined but waiting for maturity */
        NotAccepted         /**< Mined but not accepted */
    };

    /// Transaction counts towards available balance
    bool countsForBalance{false};
    /// Sorting key based on status
    std::string sortKey;

    /** @name Generated (mined) transactions
       @{*/
    int matures_in{0};
    /**@}*/

    /** @name Reported status
       @{*/
    Status status{Unconfirmed};
    qint64 depth{0};
    qint64 open_for{0}; /**< Timestamp if status==OpenUntilDate, otherwise number
                      of additional blocks that need to be mined before
                      finalization */
    /**@}*/

    /** Current number of blocks (to know whether cached status is still valid) */
    int cur_num_blocks{-1};

    bool needsUpdate;
};

/** UI model for a transaction. A core transaction can be represented by multiple UI transactions if it has
    multiple outputs.
 */
class TransactionRecord
{
public:
    enum Type
    {
        Other,
        Generated,
        SendToAddress,
        SendToOther,
        RecvWithAddress,
        RecvFromOther,
        SendToSelf,
        Staked
    };

    /** Number of confirmation recommended for accepting a transaction */
    static const int RecommendedNumConfirmations = 6;

    TransactionRecord():
            hash(), , , address(""), , , , , {
    }

    TransactionRecord(uint256 _hash, qint64 _time):
            hash(std::move(_hash)), time(_time), type(Other), address(""), debit(0), credit(0),
            typeIn('P'), typeOut('P'), idx(0)
    {
    }

    TransactionRecord(uint256 _hash, qint64 _time,
                Type _type, std::string _address,
                const CAmount& _debit, const CAmount& _credit):
            hash(std::move(_hash)), time(_time), type(_type), address(std::move(_address)), debit(_debit), credit(_credit),
            typeIn('P'), typeOut('P'), idx(0)
    {
    }

    /** Decompose CWallet transaction to model transaction records.
     */
    static bool showTransaction();
    static QList<TransactionRecord> decomposeTransaction(const interfaces::WalletTx& wtx);

    /** @name Immutable transaction attributes
      @{*/
    uint256 hash;
    qint64 time{0};
    Type type{Other};
    std::string address;
    CAmount debit{0};
    CAmount credit{0};

    char typeIn{'P'};
    char typeOut{'P'};


    /**@}*/

    /** Subtransaction index, for sort key */
    int idx{0};

    /** Status: can change with block chain update */
    TransactionStatus status;

    /** Whether the transaction was sent/received with a watch-only address */
    bool involvesWatchAddress;

    /** Return the unique identifier for this transaction (part) */
    QString getTxHash() const;

    /** Return the output index of the subtransaction  */
    int getOutputIndex() const;

    /** Update status from core wallet tx.
     */
    void updateStatus(const interfaces::WalletTxStatus& wtx, int numBlocks);


    /** Return whether a status update is needed.
     */
    bool statusUpdateNeeded(int numBlocks) const;
};

#endif // BITCOIN_QT_TRANSACTIONRECORD_H
