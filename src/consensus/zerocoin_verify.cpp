// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/zerocoin_verify.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <txdb.h>
#include <uint256.h>
#include <zwspchain.h>
#include <validation.h>
#include <util/moneystr.h>
#include <libzerocoin/Coin.h>

using namespace libzerocoin;

bool CheckZerocoinMint(const uint256& txHash, const CTxOut& txout, CValidationState& state, bool fCheckOnly)
{
    PublicCoin pubCoin(Params().Zerocoin_Params(false));
    if(!TxOutToPublicCoin(txout, pubCoin, state))
        return state.DoS(100, error("CheckZerocoinMint(): TxOutToPublicCoin() failed"));

    if (!pubCoin.validate())
        return state.DoS(100, error("CheckZerocoinMint() : PubCoin does not validate"));

    return true;
}

bool CheckZerocoinSpend(const CTransaction& tx, bool fVerifySignature, CValidationState& state, bool fFakeSerialAttack)
{
    //max needed non-mint outputs should be 2 - one for redemption address and a possible 2nd for change
    if (tx.vout.size() > 2) {
        int outs = 0;
        for (const CTxOut& out : tx.vout) {
            if (out.IsZerocoinMint())
                continue;
            outs++;
        }
        if (outs > 2 && !tx.IsCoinStake())
            return state.DoS(100, error("CheckZerocoinSpend(): over two non-mint outputs in a zerocoinspend transaction"));
    }

    //compute the txout hash that is used for the zerocoinspend signatures
    CMutableTransaction txTemp;
    for (const CTxOut& out : tx.vout) {
        txTemp.vout.push_back(out);
    }
    uint256 hashTxOut = txTemp.GetHash();

    bool fValidated = false;
    set<CBigNum> serials;
    std::list<CoinSpend> vSpends;
    CAmount nTotalRedeemed = 0;
    for (const CTxIn& txin : tx.vin) {

        //only check txin that is a zcspend
        if (!txin.scriptSig.IsZerocoinSpend())
            continue;

        CoinSpend newSpend = TxInToZerocoinSpend(txin);
        vSpends.push_back(newSpend);

        //check that the denomination is valid
        if (newSpend.getDenomination() == ZQ_ERROR)
            return state.DoS(100, error("Zerocoinspend does not have the correct denomination"));

        //check that denomination is what it claims to be in nSequence
        if (newSpend.getDenomination() != txin.nSequence)
            return state.DoS(100, error("Zerocoinspend nSequence denomination does not match CoinSpend"));

        //make sure the txout has not changed
        if (newSpend.getTxOutHash() != hashTxOut)
            return state.DoS(100, error("Zerocoinspend does not use the same txout that was used in the SoK"));

        // Skip signature verification during initial block download
        if (fVerifySignature) {
            //see if we have record of the accumulator used in the spend tx
            CBigNum bnAccumulatorValue = 0;
            if (!zerocoinDB->ReadAccumulatorValue(newSpend.getAccumulatorChecksum(), bnAccumulatorValue)) {
                uint32_t nChecksum = newSpend.getAccumulatorChecksum();
                return state.DoS(100, error("%s: Zerocoinspend could not find accumulator associated with checksum %s", __func__, HexStr(BEGIN(nChecksum), END(nChecksum))));
            }

            Accumulator accumulator(Params().Zerocoin_Params(chainActive.Height() < Params().NEW_PROTOCOLS_STARTHEIGHT()),
                                    newSpend.getDenomination(), bnAccumulatorValue);

            //Check that the coin has been accumulated
            if(!newSpend.Verify(accumulator, !fFakeSerialAttack))
                return state.DoS(100, error("CheckZerocoinSpend(): zerocoin spend did not verify"));
        }

        if (serials.count(newSpend.getCoinSerialNumber()))
            return state.DoS(100, error("Zerocoinspend serial is used twice in the same tx"));
        serials.insert(newSpend.getCoinSerialNumber());

        //make sure that there is no over redemption of coins
        nTotalRedeemed += ZerocoinDenominationToAmount(newSpend.getDenomination());
        fValidated = true;
    }

    if (!tx.IsCoinStake() && nTotalRedeemed < tx.GetValueOut()) {
        LogPrintf("redeemed = %s , spend = %s \n", FormatMoney(nTotalRedeemed), FormatMoney(tx.GetValueOut()));
        return state.DoS(100, error("Transaction spend more than was redeemed in zerocoins"));
    }

    return fValidated;
}
