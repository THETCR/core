// Copyright (c) 2017-2018 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hdwalletdb.h>
#include <wallet/hdwallet.h>

#include <serialize.h>
#include <txdb.h>
#include <primitives/deterministicmint.h>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>
class PackKey
{
public:
    PackKey(std::string s, const CKeyID &keyId, uint32_t nPack)
        : m_prefix(s), m_keyId(keyId), m_nPack(nPack) { };

    std::string m_prefix;
    CKeyID m_keyId;
    uint32_t m_nPack;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(m_prefix);
        READWRITE(m_keyId);
        READWRITE(m_nPack);
    };
};

bool CHDWalletDB::WriteStealthKeyMeta(const CKeyID &keyId, const CStealthKeyMetadata &sxKeyMeta)
{
    return WriteIC(std::make_pair(std::string("sxkm"), keyId), sxKeyMeta, true);
};

bool CHDWalletDB::EraseStealthKeyMeta(const CKeyID &keyId)
{
    return EraseIC(std::make_pair(std::string("sxkm"), keyId));
};


bool CHDWalletDB::WriteStealthAddress(const CStealthAddress &sxAddr)
{
    return WriteIC(std::make_pair(std::string("sxad"), sxAddr.scan_pubkey), sxAddr, true);
};

bool CHDWalletDB::ReadStealthAddress(CStealthAddress& sxAddr)
{
    // Set scan_pubkey before reading
    return m_batch.Read(std::make_pair(std::string("sxad"), sxAddr.scan_pubkey), sxAddr);
};

bool CHDWalletDB::EraseStealthAddress(const CStealthAddress& sxAddr)
{
    return EraseIC(std::make_pair(std::string("sxad"), sxAddr.scan_pubkey));
};


bool CHDWalletDB::ReadNamedExtKeyId(const std::string &name, CKeyID &identifier, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("eknm"), name), identifier, nFlags);
};

bool CHDWalletDB::WriteNamedExtKeyId(const std::string &name, const CKeyID &identifier)
{
    return WriteIC(std::make_pair(std::string("eknm"), name), identifier, true);
};


bool CHDWalletDB::ReadExtKey(const CKeyID &identifier, CStoredExtKey &ek32, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("ek32"), identifier), ek32, nFlags);
};

bool CHDWalletDB::WriteExtKey(const CKeyID &identifier, const CStoredExtKey &ek32)
{
    return WriteIC(std::make_pair(std::string("ek32"), identifier), ek32, true);
};


bool CHDWalletDB::ReadExtAccount(const CKeyID &identifier, CExtKeyAccount &ekAcc, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("eacc"), identifier), ekAcc, nFlags);
};

bool CHDWalletDB::WriteExtAccount(const CKeyID &identifier, const CExtKeyAccount &ekAcc)
{
    return WriteIC(std::make_pair(std::string("eacc"), identifier), ekAcc, true);
};


bool CHDWalletDB::ReadExtKeyPack(const CKeyID &identifier, const uint32_t nPack, std::vector<CEKAKeyPack> &ekPak, uint32_t nFlags)
{
    return m_batch.Read(PackKey("epak", identifier, nPack), ekPak, nFlags);
};

bool CHDWalletDB::WriteExtKeyPack(const CKeyID &identifier, const uint32_t nPack, const std::vector<CEKAKeyPack> &ekPak)
{
    return WriteIC(PackKey("epak", identifier, nPack), ekPak, true);
};


bool CHDWalletDB::ReadExtStealthKeyPack(const CKeyID &identifier, const uint32_t nPack, std::vector<CEKAStealthKeyPack> &aksPak, uint32_t nFlags)
{
    return m_batch.Read(PackKey("espk", identifier, nPack), aksPak, nFlags);
};

bool CHDWalletDB::WriteExtStealthKeyPack(const CKeyID &identifier, const uint32_t nPack, const std::vector<CEKAStealthKeyPack> &aksPak)
{
    return WriteIC(PackKey("espk", identifier, nPack), aksPak, true);
};


bool CHDWalletDB::ReadExtStealthKeyChildPack(const CKeyID &identifier, const uint32_t nPack, std::vector<CEKASCKeyPack> &asckPak, uint32_t nFlags)
{
    return m_batch.Read(PackKey("ecpk", identifier, nPack), asckPak, nFlags);
};

bool CHDWalletDB::WriteExtStealthKeyChildPack(const CKeyID &identifier, const uint32_t nPack, const std::vector<CEKASCKeyPack> &asckPak)
{
    return WriteIC(PackKey("ecpk", identifier, nPack), asckPak, true);
};


bool CHDWalletDB::ReadFlag(const std::string &name, int32_t &nValue, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("flag"), name), nValue, nFlags);
};

bool CHDWalletDB::WriteFlag(const std::string &name, int32_t nValue)
{
    return WriteIC(std::make_pair(std::string("flag"), name), nValue, true);
};


bool CHDWalletDB::ReadExtKeyIndex(uint32_t id, CKeyID &identifier, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("ine"), id), identifier, nFlags);
};

bool CHDWalletDB::WriteExtKeyIndex(uint32_t id, const CKeyID &identifier)
{
    return WriteIC(std::make_pair(std::string("ine"), id), identifier, true);
};


bool CHDWalletDB::ReadStealthAddressIndex(uint32_t id, CStealthAddressIndexed &sxi, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("ins"), id), sxi, nFlags);
};

bool CHDWalletDB::WriteStealthAddressIndex(uint32_t id, const CStealthAddressIndexed &sxi)
{
    return WriteIC(std::make_pair(std::string("ins"), id), sxi, true);
};


bool CHDWalletDB::ReadStealthAddressIndexReverse(const uint160 &hash, uint32_t &id, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("ris"), hash), id, nFlags);
};

bool CHDWalletDB::WriteStealthAddressIndexReverse(const uint160 &hash, uint32_t id)
{
    return WriteIC(std::make_pair(std::string("ris"), hash), id, true);
};


bool CHDWalletDB::ReadStealthAddressLink(const CKeyID &keyId, uint32_t &id, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("lns"), keyId), id, nFlags);
};

bool CHDWalletDB::WriteStealthAddressLink(const CKeyID &keyId, uint32_t id)
{
    return WriteIC(std::make_pair(std::string("lns"), keyId), id, true);
};


bool CHDWalletDB::WriteAddressBookEntry(const std::string &sKey, const CAddressBookData &data)
{
    return WriteIC(std::make_pair(std::string("abe"), sKey), data, true);
};

bool CHDWalletDB::EraseAddressBookEntry(const std::string &sKey)
{
    return EraseIC(std::make_pair(std::string("abe"), sKey));
};


bool CHDWalletDB::ReadVoteTokens(std::vector<CVoteToken> &vVoteTokens, uint32_t nFlags)
{
    return m_batch.Read(std::string("votes"), vVoteTokens, nFlags);
};

bool CHDWalletDB::WriteVoteTokens(const std::vector<CVoteToken> &vVoteTokens)
{
    return WriteIC(std::string("votes"), vVoteTokens, true);
};


bool CHDWalletDB::WriteTxRecord(const uint256 &hash, const CTransactionRecord &rtx)
{
    return WriteIC(std::make_pair(std::string("rtx"), hash), rtx, true);
};

bool CHDWalletDB::EraseTxRecord(const uint256 &hash)
{
    return EraseIC(std::make_pair(std::string("rtx"), hash));
};


bool CHDWalletDB::ReadStoredTx(const uint256 &hash, CStoredTransaction &stx, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("stx"), hash), stx, nFlags);
};

bool CHDWalletDB::WriteStoredTx(const uint256 &hash, const CStoredTransaction &stx)
{
    return WriteIC(std::make_pair(std::string("stx"), hash), stx, true);
};

bool CHDWalletDB::EraseStoredTx(const uint256 &hash)
{
    return EraseIC(std::make_pair(std::string("stx"), hash));
};


bool CHDWalletDB::ReadAnonKeyImage(const CCmpPubKey &ki, COutPoint &op, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("aki"), ki), op, nFlags);
};

bool CHDWalletDB::WriteAnonKeyImage(const CCmpPubKey &ki, const COutPoint &op)
{
    return WriteIC(std::make_pair(std::string("aki"), ki), op, true);
};

bool CHDWalletDB::EraseAnonKeyImage(const CCmpPubKey &ki)
{
    return EraseIC(std::make_pair(std::string("aki"), ki));
};


bool CHDWalletDB::HaveLockedAnonOut(const COutPoint &op, uint32_t nFlags)
{
    char c;
    return m_batch.Read(std::make_pair(std::string("lao"), op), c, nFlags);
}

bool CHDWalletDB::WriteLockedAnonOut(const COutPoint &op)
{
    char c = 't';
    return WriteIC(std::make_pair(std::string("lao"), op), c, true);
};

bool CHDWalletDB::EraseLockedAnonOut(const COutPoint &op)
{
    return EraseIC(std::make_pair(std::string("lao"), op));
};


bool CHDWalletDB::ReadWalletSetting(const std::string &setting, std::string &json, uint32_t nFlags)
{
    return m_batch.Read(std::make_pair(std::string("wset"), setting), json, nFlags);
};

bool CHDWalletDB::WriteWalletSetting(const std::string &setting, const std::string &json)
{
    return WriteIC(std::make_pair(std::string("wset"), setting), json, true);
};

bool CHDWalletDB::EraseWalletSetting(const std::string &setting)
{
    return EraseIC(std::make_pair(std::string("wset"), setting));
};




//!WISPR
bool CHDWalletDB::WriteZerocoinSpendSerialEntry(const CZerocoinSpend& zerocoinSpend)
{
    return m_batch.Write(make_pair(string("zcserial"), zerocoinSpend.GetSerial()), zerocoinSpend, true);
}
bool CHDWalletDB::EraseZerocoinSpendSerialEntry(const CBigNum& serialEntry)
{
    return m_batch.Erase(make_pair(string("zcserial"), serialEntry));
}

bool CHDWalletDB::ReadZerocoinSpendSerialEntry(const CBigNum& bnSerial)
{
    CZerocoinSpend spend;
    return m_batch.Read(make_pair(string("zcserial"), bnSerial), spend);
}

bool CHDWalletDB::WriteDeterministicMint(const CDeterministicMint& dMint)
{
    uint256 hash = dMint.GetPubcoinHash();
    return m_batch.Write(make_pair(string("dzwsp"), hash), dMint, true);
}

bool CHDWalletDB::ReadDeterministicMint(const uint256& hashPubcoin, CDeterministicMint& dMint)
{
    return m_batch.Read(make_pair(string("dzwsp"), hashPubcoin), dMint);
}

bool CHDWalletDB::EraseDeterministicMint(const uint256& hashPubcoin)
{
    return m_batch.Erase(make_pair(string("dzwsp"), hashPubcoin));
}

bool CHDWalletDB::WriteZerocoinMint(const CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << zerocoinMint.GetValue();
    uint256 hash = Hash(ss.begin(), ss.end());

    m_batch.Erase(make_pair(string("zerocoin"), hash));
    return m_batch.Write(make_pair(string("zerocoin"), hash), zerocoinMint, true);
}

bool CHDWalletDB::ReadZerocoinMint(const CBigNum &bnPubCoinValue, CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnPubCoinValue;
    uint256 hash = Hash(ss.begin(), ss.end());

    return ReadZerocoinMint(hash, zerocoinMint);
}

bool CHDWalletDB::ReadZerocoinMint(const uint256& hashPubcoin, CZerocoinMint& mint)
{
    return m_batch.Read(make_pair(string("zerocoin"), hashPubcoin), mint);
}

bool CHDWalletDB::EraseZerocoinMint(const CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << zerocoinMint.GetValue();
    uint256 hash = Hash(ss.begin(), ss.end());

    return m_batch.Erase(make_pair(string("zerocoin"), hash));
}

bool CHDWalletDB::ArchiveMintOrphan(const CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << zerocoinMint.GetValue();
    uint256 hash = Hash(ss.begin(), ss.end());;

    if (!m_batch.Write(make_pair(string("zco"), hash), zerocoinMint)) {
        LogPrintf("%s : failed to database orphaned zerocoin mint\n", __func__);
        return false;
    }

    if (!m_batch.Erase(make_pair(string("zerocoin"), hash))) {
        LogPrintf("%s : failed to erase orphaned zerocoin mint\n", __func__);
        return false;
    }

    return true;
}

bool CHDWalletDB::ArchiveDeterministicOrphan(const CDeterministicMint& dMint)
{
    if (!m_batch.Write(make_pair(string("dzco"), dMint.GetPubcoinHash()), dMint))
        return error("%s: write failed", __func__);

    if (!m_batch.Erase(make_pair(string("dzwsp"), dMint.GetPubcoinHash())))
        return error("%s: failed to erase", __func__);

    return true;
}

bool CHDWalletDB::UnarchiveDeterministicMint(const uint256& hashPubcoin, CDeterministicMint& dMint)
{
    if (!m_batch.Read(make_pair(string("dzco"), hashPubcoin), dMint))
        return error("%s: failed to retrieve deterministic mint from archive", __func__);

    if (!WriteDeterministicMint(dMint))
        return error("%s: failed to write deterministic mint", __func__);

    if (!m_batch.Erase(make_pair(string("dzco"), dMint.GetPubcoinHash())))
        return error("%s : failed to erase archived deterministic mint", __func__);

    return true;
}

bool CHDWalletDB::UnarchiveZerocoinMint(const uint256& hashPubcoin, CZerocoinMint& mint)
{
    if (!m_batch.Read(make_pair(string("zco"), hashPubcoin), mint))
        return error("%s: failed to retrieve zerocoinmint from archive", __func__);

    if (!WriteZerocoinMint(mint))
        return error("%s: failed to write zerocoinmint", __func__);

    uint256 hash = GetPubCoinHash(mint.GetValue());
    if (!m_batch.Erase(make_pair(string("zco"), hash)))
        return error("%s : failed to erase archived zerocoin mint", __func__);

    return true;
}

bool CHDWalletDB::WriteCurrentSeedHash(const uint256& hashSeed)
{
    return m_batch.Write(string("seedhash"), hashSeed);
}

bool CHDWalletDB::ReadCurrentSeedHash(uint256& hashSeed)
{
    return m_batch.Read(string("seedhash"), hashSeed);
}

bool CHDWalletDB::WriteZWSPSeed(const uint256& hashSeed, const vector<unsigned char>& seed)
{
    if (!WriteCurrentSeedHash(hashSeed))
        return error("%s: failed to write current seed hash", __func__);

    return m_batch.Write(make_pair(string("dzs"), hashSeed), seed);
}

bool CHDWalletDB::EraseZWSPSeed()
{
    uint256 hash;
    if(!ReadCurrentSeedHash(hash)){
        return error("Failed to read a current seed hash");
    }
    if(!WriteZWSPSeed(hash, ToByteVector(base_blob<256>(0) << 256))) {
        return error("Failed to write empty seed to wallet");
    }
    if(!WriteCurrentSeedHash(0)) {
        return error("Failed to write empty seedHash");
    }

    return true;
}

bool CHDWalletDB::EraseZWSPSeed_deprecated()
{
    return m_batch.Erase(string("dzs"));
}

bool CHDWalletDB::ReadZWSPSeed(const uint256& hashSeed, vector<unsigned char>& seed)
{
    return m_batch.Read(make_pair(string("dzs"), hashSeed), seed);
}

bool CHDWalletDB::ReadZWSPSeed_deprecated(uint256& seed)
{
    return m_batch.Read(string("dzs"), seed);
}

bool CHDWalletDB::WriteZWSPCount(const uint32_t& nCount)
{
    return m_batch.Write(string("dzc"), nCount);
}

bool CHDWalletDB::ReadZWSPCount(uint32_t& nCount)
{
    return m_batch.Read(string("dzc"), nCount);
}

bool CHDWalletDB::WriteMintPoolPair(const uint256& hashMasterSeed, const uint256& hashPubcoin, const uint32_t& nCount)
{
    return m_batch.Write(make_pair(string("mintpool"), hashPubcoin), make_pair(hashMasterSeed, nCount));
}

//! map with hashMasterSeed as the key, paired with vector of hashPubcoins and their count
std::map<uint256, std::vector<pair<uint256, uint32_t> > > CHDWalletDB::MapMintPool()
{
    std::map<uint256, std::vector<pair<uint256, uint32_t> > > mapPool;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("mintpool"), uint256(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "mintpool")
            break;

        uint256 hashPubcoin;
        ssKey >> hashPubcoin;

        uint256 hashMasterSeed;
        ssValue >> hashMasterSeed;

        uint32_t nCount;
        ssValue >> nCount;

        pair<uint256, uint32_t> pMint;
        pMint.first = hashPubcoin;
        pMint.second = nCount;
        if (mapPool.count(hashMasterSeed)) {
            mapPool.at(hashMasterSeed).emplace_back(pMint);
        } else {
            vector<pair<uint256, uint32_t> > vPairs;
            vPairs.emplace_back(pMint);
            mapPool.insert(make_pair(hashMasterSeed, vPairs));
        }
    }

    pcursor->close();

    return mapPool;
}

std::list<CDeterministicMint> CHDWalletDB::ListDeterministicMints()
{
    std::list<CDeterministicMint> listMints;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("dzwsp"), uint256(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "dzwsp")
            break;

        uint256 hashPubcoin;
        ssKey >> hashPubcoin;

        CDeterministicMint mint;
        ssValue >> mint;

        listMints.emplace_back(mint);
    }

    pcursor->close();
    return listMints;
}

std::list<CZerocoinMint> CHDWalletDB::ListMintedCoins()
{
    std::list<CZerocoinMint> listPubCoin;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    vector<CZerocoinMint> vOverWrite;
    vector<CZerocoinMint> vArchive;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("zerocoin"), uint256(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "zerocoin")
            break;

        uint256 hashPubcoin;
        ssKey >> hashPubcoin;

        CZerocoinMint mint;
        ssValue >> mint;

        listPubCoin.emplace_back(mint);
    }

    pcursor->close();
    return listPubCoin;
}

std::list<CZerocoinSpend> CHDWalletDB::ListSpentCoins()
{
    std::list<CZerocoinSpend> listCoinSpend;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("zcserial"), CBigNum(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "zcserial")
            break;

        CBigNum value;
        ssKey >> value;

        CZerocoinSpend zerocoinSpendItem;
        ssValue >> zerocoinSpendItem;

        listCoinSpend.push_back(zerocoinSpendItem);
    }

    pcursor->close();
    return listCoinSpend;
}

// Just get the Serial Numbers
std::list<CBigNum> CHDWalletDB::ListSpentCoinsSerial()
{
    std::list<CBigNum> listPubCoin;
    std::list<CZerocoinSpend> listCoins = ListSpentCoins();

    for ( auto& coin : listCoins) {
        listPubCoin.push_back(coin.GetSerial());
    }
    return listPubCoin;
}

std::list<CZerocoinMint> CHDWalletDB::ListArchivedZerocoins()
{
    std::list<CZerocoinMint> listMints;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("zco"), CBigNum(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "zco")
            break;

        uint256 value;
        ssKey >> value;

        CZerocoinMint mint;
        ssValue >> mint;

        listMints.push_back(mint);
    }

    pcursor->close();
    return listMints;
}

std::list<CDeterministicMint> CHDWalletDB::ListArchivedDeterministicMints()
{
    std::list<CDeterministicMint> listMints;
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("dzco"), CBigNum(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "dzco")
            break;

        uint256 value;
        ssKey >> value;

        CDeterministicMint dMint;
        ssValue >> dMint;

        listMints.emplace_back(dMint);
    }

    pcursor->close();
    return listMints;
}
