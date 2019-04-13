// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <primitives/transaction.h>
#include <consensus/validation.h>

//!< WISPR
#include <consensus/zerocoin_verify.h> // For CheckZerocoinMint && CheckZerocoinSpend

bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs, bool fZerocoinActive, bool fRejectBadUTXO, bool fFakeSerialAttack)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    int nZCSpendCount = 0;
    for (const auto& txout : tx.vout) {
        if (txout.IsEmpty() && !tx.IsCoinBase() && !tx.IsCoinStake())
            return state.DoS(100, error("CheckTransaction(): txout empty for user transaction"));

        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");

        if (fZerocoinActive && txout.IsZerocoinMint()) {
            if(!CheckZerocoinMint(tx.GetHash(), txout, state, true))
                return state.DoS(100, error("CheckTransaction() : invalid zerocoin mint"));
        }
        if (fZerocoinActive && txout.scriptPubKey.IsZerocoinSpend())
            nZCSpendCount++;
    }

    if (fZerocoinActive) {
        if (nZCSpendCount > MAX_ZEROCOINSPENDS_PER_TRANSACTION)
            return state.DoS(100, error("CheckTransaction() : there are more zerocoin spends than are allowed in one transaction"));

        if (tx.IsZerocoinSpend()) {
            //require that a zerocoinspend only has inputs that are zerocoins
            for (const CTxIn& in : tx.vin) {
                if (!in.scriptSig.IsZerocoinSpend())
                    return state.DoS(100,
                                     error("CheckTransaction() : zerocoinspend contains inputs that are not zerocoins"));
            }

            // Do not require signature verification if this is initial sync and a block over 24 hours old
//            bool fVerifySignature = !IsInitialBlockDownload() && (GetTime() - chainActive.Tip()->GetBlockTime() < (60*60*24));
            if (!CheckZerocoinSpend(tx, true, state, fFakeSerialAttack))
                return state.DoS(100, error("CheckTransaction() : invalid zerocoin spend"));
        }
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        std::set<CBigNum> vZerocoinSpendSerials;
        for (const auto& txin : tx.vin)
        {
            if (vInOutPoints.count(txin.prevout))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");


            //duplicate zcspend serials are checked in CheckZerocoinSpend()
            if (!txin.scriptSig.IsZerocoinSpend())
                vInOutPoints.insert(txin.prevout);
        }
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 150)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else if (fZerocoinActive && tx.IsZerocoinSpend())
    {
        if(tx.vin.size() < 1 || static_cast<int>(tx.vin.size()) > MAX_ZEROCOINSPENDS_PER_TRANSACTION)
            return state.DoS(10, error("CheckTransaction() : Zerocoin Spend has more than allowed txin's"), REJECT_INVALID, "bad-zerocoinspend");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull() && (fZerocoinActive && !txin.scriptSig.IsZerocoinSpend()))
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}
