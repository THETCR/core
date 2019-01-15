// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString(), n);
}
std::string COutPoint::ToStringShort() const
{
    return strprintf("%s-%u", hash.ToString().substr(0,64), n);
}
CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    str += strprintf(", hash=%s", GetHash().ToString());
    str += strprintf(", prevPubKey=%s", prevPubKey.ToString());
    str += strprintf(", nSequence=%u", nSequence);
    if (prevout.IsNull()) {
        if (scriptSig.IsZerocoinSpend()){
            str += strprintf(", zerocoinspend %s...", HexStr(scriptSig).substr(0, 25));
        }else{
            str += strprintf(", coinbase %s", HexStr(scriptSig));
        }
    }else {
        str += strprintf(", scriptSig=%s", scriptSig.ToString());
    }
    if (nSequence != SEQUENCE_FINAL) {
        str += strprintf(", nSequence=%u", nSequence);
    }
    if (IsAnonInput())
    {
        str += strprintf(", isAnonInput=%s", "yes");
    };
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
    nRounds = -10;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s, nRounds=%u, hash=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString(), nRounds,
            GetHash().ToString());
}

void CTxOutBase::SetValue(int64_t value)
{
    // convenience function intended for use with CTxOutStandard only
    assert(nVersion == OUTPUT_STANDARD);
    ((CTxOutStandard*) this)->nValue = value;
};

CAmount CTxOutBase::GetValue() const
{
    // convenience function intended for use with CTxOutStandard only
    /*
    switch (nVersion)
    {
        case OUTPUT_STANDARD:
            return ((CTxOutStandard*) this)->nValue;
        case OUTPUT_DATA:
            return 0;
        default:
            assert(false);

    };
    */
    assert(nVersion == OUTPUT_STANDARD);
    return ((CTxOutStandard*) this)->nValue;
};

std::string CTxOutBase::ToString() const
{
    switch (nVersion)
    {
        case OUTPUT_STANDARD:
            {
                auto *so = (CTxOutStandard*)this;
            return strprintf("CTxOutStandard(nValue=%d.%08d, scriptPubKey=%s)", so->nValue / COIN, so->nValue % COIN, HexStr(so->scriptPubKey).substr(0, 30));
            }
        case OUTPUT_DATA:
            {
                auto *dout = (CTxOutData*)this;
            return strprintf("CTxOutData(data=%s)", HexStr(dout->vData).substr(0, 30));
            }
        case OUTPUT_CT:
            {
                auto *cto = (CTxOutCT*)this;
            return strprintf("CTxOutCT(data=%s, scriptPubKey=%s)", HexStr(cto->vData).substr(0, 30), HexStr(cto->scriptPubKey).substr(0, 30));
            }
        case OUTPUT_RINGCT:
            {
                auto *rcto = (CTxOutRingCT*)this;
            return strprintf("CTxOutRingCT(data=%s, pk=%s)", HexStr(rcto->vData).substr(0, 30), HexStr(rcto->pk).substr(0, 30));
            }
        default:
            break;
    };
    return strprintf("CTxOutBase unknown version %d", nVersion);
}

CTxOutStandard::CTxOutStandard(const CAmount& nValueIn, CScript scriptPubKeyIn) : CTxOutBase(OUTPUT_STANDARD)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
};

void DeepCopy(CTxOutBaseRef &to, const CTxOutBaseRef &from)
{
    switch (from->GetType()) {
        case OUTPUT_STANDARD:
            to = MAKE_OUTPUT<CTxOutStandard>();
            *((CTxOutStandard*)to.get()) = *((CTxOutStandard*)from.get());
            break;
        case OUTPUT_CT:
            to = MAKE_OUTPUT<CTxOutCT>();
            *((CTxOutCT*)to.get()) = *((CTxOutCT*)from.get());
            break;
        case OUTPUT_RINGCT:
            to = MAKE_OUTPUT<CTxOutRingCT>();
            *((CTxOutRingCT*)to.get()) = *((CTxOutRingCT*)from.get());
            break;
        case OUTPUT_DATA:
            to = MAKE_OUTPUT<CTxOutData>();
            *((CTxOutData*)to.get()) = *((CTxOutData*)from.get());
            break;
        default:
            break;
    }
    return;
}

std::vector<CTxOutBaseRef> DeepCopy(const std::vector<CTxOutBaseRef> &from)
{
    std::vector<CTxOutBaseRef> vpout;
    vpout.resize(from.size());
    for (size_t i = 0; i < from.size(); ++i) {
        DeepCopy(vpout[i], from[i]);
    }

    return vpout;
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nTime(0), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(tx.vin), vout(tx.vout), vpout{DeepCopy(tx.vpout)}, nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    /*
    if (!HasWitness()) {
        return hash;
    }
    */
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), nTime(0), vin(), vout(), vpout(), nLockTime(0), hash{}, m_witness_hash{} {}
CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(tx.vin), vout(tx.vout), vpout{DeepCopy(tx.vpout)}, nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(std::move(tx.vin)), vout(std::move(tx.vout)), vpout(std::move(tx.vpout)), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
//    printf("%s\n", __func__);
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    for (auto &txout : vpout)
    {
        if (!txout->IsStandardOutput())
            continue;

        CAmount nValue = txout->GetValue();
        nValueOut += txout->GetValue();
        if (!MoneyRange(nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    };

    return nValueOut;
}
double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}
unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, PROTOCOL_VERSION);
    for (auto it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

CAmount CTransaction::GetPlainValueOut(size_t &nStandard, size_t &nCT, size_t &nRingCT) const
{
    // accumulators not cleared here intentionally
    CAmount nValueOut = 0;

    for (const auto &txout : vpout)
    {
        if (txout->IsType(OUTPUT_CT))
        {
            nCT++;
        } else
        if (txout->IsType(OUTPUT_RINGCT))
        {
            nRingCT++;
        };

        if (!txout->IsStandardOutput())
            continue;

        nStandard++;
//        printf("%s: nValue =%lli\n", __func__, txout->GetValue());
        CAmount nValue = txout->GetValue();
        nValueOut += nValue;
        if (!MoneyRange(nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    };
//    printf("%s: nValueOut =%lli\n", __func__, nValueOut);

    return nValueOut;
};

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, nTime=%u, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString(),
        nVersion,
        nTime,
        vin.size(),
        (nVersion & 0x0) < WISPR_TXN_VERSION ? vout.size() : vpout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    for (unsigned int i = 0; i < vpout.size(); i++)
        str += "    " + vpout[i]->ToString() + "\n";
    return str;
}
std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CMutableTransaction(hash=%s, ver=%d, nTime=%u, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
                     GetHash().ToString(),
                     nVersion,
                     nTime,
                     vin.size(),
                     vout.size(),
                     nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}
CAmount CTransaction::GetZerocoinMinted() const
{
    for (const CTxOut& txOut : vout) {
        if(!txOut.scriptPubKey.IsZerocoinMint())
            continue;

        return txOut.nValue;
    }

    return  CAmount(0);
}
CAmount CTransaction::GetZerocoinSpent() const
{
    if(!IsZerocoinSpend())
        return 0;

    CAmount nValueOut = 0;
    for (const CTxIn& txin : vin) {
        if(!txin.scriptSig.IsZerocoinSpend())
            continue;

        nValueOut += txin.nSequence * COIN;
    }

    return nValueOut;
}

int CTransaction::GetZerocoinMintCount() const
{
    int nCount = 0;
    for (const CTxOut& out : vout) {
        if (out.scriptPubKey.IsZerocoinMint())
            nCount++;
    }
    return nCount;
}
CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<unsigned int *>(&nTime) = tx.nTime;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256*>(&hash) = tx.hash;
    return *this;
}
uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}
uint256 CTxIn::GetHash() const {
    return SerializeHash(*this);
}