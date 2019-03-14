// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <wallet/walletdb.h>

#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <fs.h>
#include <key_io.h>
#include <protocol.h>
#include <serialize.h>
#include <sync.h>
#include <util/system.h>
#include <util/time.h>
#include <wallet/wallet.h>
#include <primitives/deterministicmint.h>
#include <libzerocoin/bignum.h>

#include <atomic>
#include <string>

#include <boost/thread.hpp>

using namespace std;

static uint64_t nAccountingEntryNumber = 0;

//
// CWalletDB
//

bool WalletBatch::WriteName(const std::string& strAddress, const std::string& strName)
{
    return WriteIC(std::make_pair(std::string("name"), strAddress), strName);
}

bool WalletBatch::EraseName(const std::string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    return EraseIC(std::make_pair(std::string("name"), strAddress));
}

bool WalletBatch::WritePurpose(const std::string& strAddress, const std::string& strPurpose)
{
    return WriteIC(std::make_pair(std::string("purpose"), strAddress), strPurpose);
}

bool WalletBatch::ErasePurpose(const std::string& strAddress)
{
    return EraseIC(std::make_pair(std::string("purpose"), strAddress));
}

bool WalletBatch::WriteTx(const CWalletTx& wtx)
{
    return WriteIC(std::make_pair(std::string("tx"), wtx.GetHash()), wtx);
}

bool WalletBatch::EraseTx(uint256 hash)
{
    return EraseIC(std::make_pair(std::string("tx"), hash));
}

bool WalletBatch::WriteAutoConvertKey(const CBitcoinAddress& btcAddress)
{
    CKeyID keyID;
    if (!btcAddress.GetKeyID(keyID))
        return false;
    return WriteIC(std::make_pair(std::string("automint"), keyID), btcAddress.ToString());
}

void WalletBatch::LoadAutoConvertKeys(std::set<CBitcoinAddress>& setAddresses)
{
    setAddresses.clear();
    Dbc* pcursor = m_batch.GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("automint"), CKeyID());
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
        try {
            ssKey >> strType;
        } catch(...) {
            break;
        }
        if (strType != "automint")
            break;

        CKeyID keyID;
        ssKey >> keyID;

        std::string strAddress;
        ssValue >> strAddress;
        setAddresses.emplace(strAddress);
    }

    pcursor->close();
}


bool WalletBatch::WriteKeyMetadata(const CKeyMetadata& meta, const CPubKey& pubkey, const bool overwrite)
{
    return WriteIC(std::make_pair(std::string("keymeta"), pubkey), meta, overwrite);
}

bool WalletBatch::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, false)) {
        return false;
    }

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return WriteIC(std::make_pair(std::string("key"), vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool WalletBatch::WriteCryptedKey(const CPubKey& vchPubKey,
                                  const std::vector<unsigned char>& vchCryptedSecret,
                                  const CKeyMetadata &keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, true)) {
        return false;
    }

    if (!WriteIC(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false)) {
        return false;
    }
    EraseIC(std::make_pair(std::string("key"), vchPubKey));
    EraseIC(std::make_pair(std::string("wkey"), vchPubKey));
    return true;
}

bool WalletBatch::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    return WriteIC(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool WalletBatch::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
    return WriteIC(std::make_pair(std::string("cscript"), hash), redeemScript, false);
}

bool WalletBatch::WriteWatchOnly(const CScript &dest, const CKeyMetadata& keyMeta)
{
    if (!WriteIC(std::make_pair(std::string("watchmeta"), dest), keyMeta)) {
        return false;
    }
    return WriteIC(std::make_pair(std::string("watchs"), dest), '1');
}

bool WalletBatch::EraseWatchOnly(const CScript &dest)
{
    if (!EraseIC(std::make_pair(std::string("watchmeta"), dest))) {
        return false;
    }
    return EraseIC(std::make_pair(std::string("watchs"), dest));
}

bool WalletBatch::WriteMultiSig(const CScript& dest)
{
    return WriteIC(std::make_pair(std::string("multisig"), dest), '1');
}

bool WalletBatch::EraseMultiSig(const CScript& dest)
{
    return EraseIC(std::make_pair(std::string("multisig"), dest));
}

bool WalletBatch::WriteBestBlock(const CBlockLocator& locator)
{
    WriteIC(std::string("bestblock"), CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan
    return WriteIC(std::string("bestblock_nomerkle"), locator);
}

bool WalletBatch::ReadBestBlock(CBlockLocator& locator)
{
    if (m_batch.Read(std::string("bestblock"), locator) && !locator.vHave.empty()) return true;
    return m_batch.Read(std::string("bestblock_nomerkle"), locator);
}

bool WalletBatch::WriteOrderPosNext(int64_t nOrderPosNext)
{
    return WriteIC(std::string("orderposnext"), nOrderPosNext);
}

// presstab HyperStake
bool WalletBatch::WriteStakeSplitThreshold(uint64_t nStakeSplitThreshold)
{
    return WriteIC(std::string("stakeSplitThreshold"), nStakeSplitThreshold);
}

//presstab HyperStake
bool WalletBatch::WriteMultiSend(std::vector<std::pair<std::string, int> > vMultiSend)
{
    bool ret = true;
    for (unsigned int i = 0; i < vMultiSend.size(); i++) {
        std::pair<std::string, int> pMultiSend;
        pMultiSend = vMultiSend[i];
        if (!WriteIC(std::make_pair(std::string("multisend"), i), pMultiSend, true))
            ret = false;
    }
    return ret;
}
//presstab HyperStake
bool WalletBatch::EraseMultiSend(std::vector<std::pair<std::string, int> > vMultiSend)
{
    bool ret = true;
    for (unsigned int i = 0; i < vMultiSend.size(); i++) {
        std::pair<std::string, int> pMultiSend;
        pMultiSend = vMultiSend[i];
        if (!EraseIC(std::make_pair(std::string("multisend"), i)))
            ret = false;
    }
    return ret;
}
//presstab HyperStake
bool WalletBatch::WriteMSettings(bool fMultiSendStake, bool fMultiSendMasternode, int nLastMultiSendHeight)
{
    std::pair<bool, bool> enabledMS(fMultiSendStake, fMultiSendMasternode);
    std::pair<std::pair<bool, bool>, int> pSettings(enabledMS, nLastMultiSendHeight);

    return WriteIC(std::string("msettingsv2"), pSettings, true);
}
//presstab HyperStake
bool WalletBatch::WriteMSDisabledAddresses(std::vector<std::string> vDisabledAddresses)
{
    bool ret = true;
    for (unsigned int i = 0; i < vDisabledAddresses.size(); i++) {
        if (!WriteIC(std::make_pair(std::string("mdisabled"), i), vDisabledAddresses[i]))
            ret = false;
    }
    return ret;
}
//presstab HyperStake
bool WalletBatch::EraseMSDisabledAddresses(std::vector<std::string> vDisabledAddresses)
{
    bool ret = true;
    for (unsigned int i = 0; i < vDisabledAddresses.size(); i++) {
        if (!EraseIC(std::make_pair(std::string("mdisabled"), i)))
            ret = false;
    }
    return ret;
}
bool WalletBatch::WriteAutoCombineSettings(bool fEnable, CAmount nCombineThreshold)
{
    std::pair<bool, CAmount> pSettings;
    pSettings.first = fEnable;
    pSettings.second = nCombineThreshold;
    return WriteIC(std::string("autocombinesettings"), pSettings, true);
}

bool WalletBatch::WriteDefaultKey(const CPubKey& vchPubKey)
{
    return WriteIC(std::string("defaultkey"), vchPubKey);
}

bool WalletBatch::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return m_batch.Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool WalletBatch::WritePool(int64_t nPool, const CKeyPool& keypool)
{
    return WriteIC(std::make_pair(std::string("pool"), nPool), keypool);
}

bool WalletBatch::ErasePool(int64_t nPool)
{
    return EraseIC(std::make_pair(std::string("pool"), nPool));
}

bool WalletBatch::WriteMinVersion(int nVersion)
{
    return WriteIC(std::string("minversion"), nVersion);
}

bool WalletBatch::ReadAccount(const std::string& strAccount, CAccount& account)
{
    account.SetNull();
    return m_batch.Read(std::make_pair(string("acc"), strAccount), account);
}

bool WalletBatch::WriteAccount(const std::string& strAccount, const CAccount& account)
{
    return WriteIC(std::make_pair(string("acc"), strAccount), account);
}

bool WalletBatch::WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry)
{
    return WriteIC(std::make_pair(std::string("acentry"), std::make_pair(acentry.strAccount, nAccEntryNum)), acentry);
}

bool WalletBatch::WriteAccountingEntry_Backend(const CAccountingEntry& acentry)
{
    return WriteAccountingEntry(++nAccountingEntryNumber, acentry);
}

CAmount WalletBatch::GetAccountCreditDebit(const std::string& strAccount)
{
    std::list<CAccountingEntry> entries;
    ListAccountCreditDebit(strAccount, entries);

    CAmount nCreditDebit = 0;
    for (const CAccountingEntry& entry: entries)
        nCreditDebit += entry.nCreditDebit;

    return nCreditDebit;
}

void WalletBatch::ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries)
{
    bool fAllAccounts = (strAccount == "*");

    Dbc* pcursor = m_batch.GetCursor();
    if (!pcursor)
        throw runtime_error("WalletBatch::ListAccountCreditDebit() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true) {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << std::make_pair(std::string("acentry"), std::make_pair((fAllAccounts ? std::string("") : strAccount), uint64_t(0)));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0) {
            pcursor->close();
            throw runtime_error("WalletBatch::ListAccountCreditDebit() : error scanning DB");
        }

        // Unserialize
        std::string strType;
        ssKey >> strType;
        if (strType != "acentry")
            break;
        CAccountingEntry acentry;
        ssKey >> acentry.strAccount;
        if (!fAllAccounts && acentry.strAccount != strAccount)
            break;

        ssValue >> acentry;
        ssKey >> acentry.nEntryNo;
        entries.push_back(acentry);
    }

    pcursor->close();
}

//DBErrors WalletBatch::ReorderTransactions(CWallet* pwallet)
//{
//    LOCK(pwallet->cs_wallet);
//    // Old wallets didn't have any defined order for transactions
//    // Probably a bad idea to change the output of this
//
//    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
//    typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
//    typedef multimap<int64_t, TxPair> TxItems;
//    TxItems txByTime;
//
//    for (map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
//        CWalletTx* wtx = &((*it).second);
//        txByTime.insert(std::make_pair(wtx->nTimeReceived, TxPair(wtx, (CAccountingEntry*)0)));
//    }
//    std::list<CAccountingEntry> acentries;
//    ListAccountCreditDebit("", acentries);
//    for (CAccountingEntry& entry: acentries) {
//        txByTime.insert(std::make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
//    }
//
//    int64_t& nOrderPosNext = pwallet->nOrderPosNext;
//    nOrderPosNext = 0;
//    std::vector<int64_t> nOrderPosOffsets;
//    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it) {
//        CWalletTx* const pwtx = (*it).second.first;
//        CAccountingEntry* const pacentry = (*it).second.second;
//        int64_t& nOrderPos = (pwtx != 0) ? pwtx->nOrderPos : pacentry->nOrderPos;
//
//        if (nOrderPos == -1) {
//            nOrderPos = nOrderPosNext++;
//            nOrderPosOffsets.push_back(nOrderPos);
//
//            if (pwtx) {
//                if (!WriteTx(pwtx->tx->GetHash(), *pwtx))
//                    return DB_LOAD_FAIL;
//            } else if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
//                return DB_LOAD_FAIL;
//        } else {
//            int64_t nOrderPosOff = 0;
//            for (const int64_t& nOffsetStart: nOrderPosOffsets) {
//                if (nOrderPos >= nOffsetStart)
//                    ++nOrderPosOff;
//            }
//            nOrderPos += nOrderPosOff;
//            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);
//
//            if (!nOrderPosOff)
//                continue;
//
//            // Since we're changing the order, write it back
//            if (pwtx) {
//                if (!WriteTx(pwtx->tx->GetHash(), *pwtx))
//                    return DB_LOAD_FAIL;
//            } else if (!WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
//                return DB_LOAD_FAIL;
//        }
//    }
//    WriteOrderPosNext(nOrderPosNext);
//
//    return DB_LOAD_OK;
//}

class CWalletScanState {
public:
    unsigned int nKeys{0};
    unsigned int nCKeys{0};
    unsigned int nWatchKeys{0};
    unsigned int nKeyMeta{0};
    unsigned int m_unknown_records{0};
    bool fIsEncrypted{false};
    bool fAnyUnordered{false};
    int nFileVersion{0};
    std::vector<uint256> vWalletUpgrade;

    CWalletScanState() {
    }
};

static bool ReadKeyValue(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue,
             CWalletScanState &wss, std::string& strType, std::string& strErr) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    try {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        if (strType == "name")
        {
            std::string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[DecodeDestination(strAddress)].name;
        }
        else if (strType == "purpose")
        {
            std::string strAddress;
            ssKey >> strAddress;
            ssValue >> pwallet->mapAddressBook[DecodeDestination(strAddress)].purpose;
        }
        else if (strType == "tx")
        {
            uint256 hash;
            ssKey >> hash;
            CWalletTx wtx(nullptr /* pwallet */, MakeTransactionRef());
            ssValue >> wtx;
            CValidationState state;
            if (!(CheckTransaction(*wtx.tx, false, false, state) && (wtx.GetHash() == hash) && state.IsValid()))
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!ssValue.empty())
                {
                    char fTmp;
                    char fUnused;
                    std::string unused_string;
                    ssValue >> fTmp >> fUnused >> unused_string;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d %s",
                                       wtx.fTimeReceivedIsTxTime, fTmp, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            pwallet->LoadToWallet(wtx);
        }
        else if (strType == "watchs")
        {
            wss.nWatchKeys++;
            CScript script;
            ssKey >> script;
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
                pwallet->LoadWatchOnly(script);
        }
        else if (strType == "key" || strType == "wkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            if (strType == "key")
            {
                wss.nKeys++;
                ssValue >> pkey;
            } else {
                CWalletKey wkey;
                ssValue >> wkey;
                pkey = wkey.vchPrivKey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
            // using EC operations as a checksum.
            // Newer wallets store keys as "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch (...) {}

            bool fSkipCheck = false;

            if (!hash.IsNull())
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        }
        else if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == "ckey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            std::vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "keymeta")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;
            pwallet->LoadKeyMetadata(vchPubKey.GetID(), keyMeta);
        }
        else if (strType == "watchmeta")
        {
            CScript script;
            ssKey >> script;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;
            pwallet->LoadScriptMetadata(CScriptID(script), keyMeta);
        }
        else if (strType == "defaultkey")
        {
            // We don't want or need the default key, but if there is one set,
            // we want to make sure that it is valid so that we can detect corruption
            CPubKey vchPubKey;
            ssValue >> vchPubKey;
            if (!vchPubKey.IsValid()) {
                strErr = "Error reading wallet database: Default Key corrupt";
                return false;
            }
        }
        else if (strType == "pool")
        {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;

            pwallet->LoadKeyPool(nIndex, keypool);
        }
        else if (strType == "version")
        {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        }
        else if (strType == "cscript")
        {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> script;
            if (!pwallet->LoadCScript(script))
            {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        }
        else if (strType == "orderposnext")
        {
            ssValue >> pwallet->nOrderPosNext;
        }
        else if (strType == "destdata")
        {
            std::string strAddress, strKey, strValue;
            ssKey >> strAddress;
            ssKey >> strKey;
            ssValue >> strValue;
            pwallet->LoadDestData(DecodeDestination(strAddress), strKey, strValue);
        }
        else if (strType == "hdchain")
        {
            CHDChain chain;
            ssValue >> chain;
            pwallet->SetHDChain(chain, true);
        } else if (strType == "flags") {
            uint64_t flags;
            ssValue >> flags;
            if (!pwallet->SetWalletFlags(flags, true)) {
                strErr = "Error reading wallet database: Unknown non-tolerable wallet flags found";
                return false;
            }
        } else if (strType != "bestblock" && strType != "bestblock_nomerkle" &&
                   strType != "minversion" && strType != "acentry") {
            wss.m_unknown_records++;
        }
    } catch (...)
    {
        return false;
    }
    return true;
}

bool WalletBatch::IsKeyType(const std::string& strType)
{
    return (strType== "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey");
}

DBErrors WalletBatch::LoadWallet(CWallet* pwallet)
{
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DBErrors::LOAD_OK;

    LOCK(pwallet->cs_wallet);
    try {
        int nMinVersion = 0;
        if (m_batch.Read((std::string)"minversion", nMinVersion))
        {
            if (nMinVersion > FEATURE_LATEST)
                return DBErrors::TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = m_batch.GetCursor();
        if (!pcursor)
        {
            pwallet->WalletLogPrintf("Error getting wallet database cursor\n");
            return DBErrors::CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                pwallet->WalletLogPrintf("Error reading next record from wallet database\n");
                return DBErrors::CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            std::string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType) || strType == "defaultkey") {
                    result = DBErrors::CORRUPT;
                } else if(strType == "flags") {
                    // reading the wallet flags can only fail if unknown flags are present
                    result = DBErrors::TOO_NEW;
                } else {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == "tx")
                        // Rescan if there is a bad transaction record:
                        gArgs.SoftSetBoolArg("-rescan", true);
                }
            }
            if (!strErr.empty())
                pwallet->WalletLogPrintf("%s\n", strErr);
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DBErrors::CORRUPT;
    }

    if (fNoncriticalErrors && result == DBErrors::LOAD_OK)
        result = DBErrors::NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DBErrors::LOAD_OK)
        return result;

    pwallet->WalletLogPrintf("nFileVersion = %d\n", wss.nFileVersion);

    pwallet->WalletLogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total. Unknown wallet records: %u\n",
                             wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys, wss.m_unknown_records);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys + wss.nWatchKeys) != wss.nKeyMeta)
        pwallet->UpdateTimeFirstKey(1);

    for (const uint256& hash : wss.vWalletUpgrade)
        WriteTx(pwallet->mapWallet.at(hash));

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
        return DBErrors::NEED_REWRITE;

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
        result = pwallet->ReorderTransactions();

    // Upgrade all of the wallet keymetadata to have the hd master key id
    // This operation is not atomic, but if it fails, updated entries are still backwards compatible with older software
    try {
        pwallet->UpgradeKeyMetadata();
    } catch (...) {
        result = DBErrors::CORRUPT;
    }

    return result;
}

DBErrors WalletBatch::FindWalletTx(std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx)
{
    DBErrors result = DBErrors::LOAD_OK;

    try {
        int nMinVersion = 0;
        if (m_batch.Read((std::string)"minversion", nMinVersion))
        {
            if (nMinVersion > FEATURE_LATEST)
                return DBErrors::TOO_NEW;
        }

        // Get cursor
        Dbc* pcursor = m_batch.GetCursor();
        if (!pcursor)
        {
            LogPrintf("Error getting wallet database cursor\n");
            return DBErrors::CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                LogPrintf("Error reading next record from wallet database\n");
                return DBErrors::CORRUPT;
            }

            std::string strType;
            ssKey >> strType;
            if (strType == "tx") {
                uint256 hash;
                ssKey >> hash;

                CWalletTx wtx(nullptr /* pwallet */, MakeTransactionRef());
                ssValue >> wtx;

                vTxHash.push_back(hash);
                vWtx.push_back(wtx);
            }
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted&) {
        throw;
    }
    catch (...) {
        result = DBErrors::CORRUPT;
    }

    return result;
}

DBErrors WalletBatch::ZapSelectTx(std::vector<uint256>& vTxHashIn, std::vector<uint256>& vTxHashOut)
{
    // build list of wallet TXs and hashes
    std::vector<uint256> vTxHash;
    std::vector<CWalletTx> vWtx;
    DBErrors err = FindWalletTx(vTxHash, vWtx);
    if (err != DBErrors::LOAD_OK) {
        return err;
    }

    std::sort(vTxHash.begin(), vTxHash.end());
    std::sort(vTxHashIn.begin(), vTxHashIn.end());

    // erase each matching wallet TX
    bool delerror = false;
    std::vector<uint256>::iterator it = vTxHashIn.begin();
    for (const uint256& hash : vTxHash) {
        while (it < vTxHashIn.end() && (*it) < hash) {
            it++;
        }
        if (it == vTxHashIn.end()) {
            break;
        }
        else if ((*it) == hash) {
            if(!EraseTx(hash)) {
                LogPrint(BCLog::DB, "Transaction was found for deletion but returned database error: %s\n", hash.GetHex());
                delerror = true;
            }
            vTxHashOut.push_back(hash);
        }
    }

    if (delerror) {
        return DBErrors::CORRUPT;
    }
    return DBErrors::LOAD_OK;
}

DBErrors WalletBatch::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    // build list of wallet TXs
    std::vector<uint256> vTxHash;
    DBErrors err = FindWalletTx(vTxHash, vWtx);
    if (err != DBErrors::LOAD_OK)
        return err;

    // erase each wallet TX
    for (const uint256& hash : vTxHash) {
        if (!EraseTx(hash))
            return DBErrors::CORRUPT;
    }

    return DBErrors::LOAD_OK;
}

void MaybeCompactWalletDB()
{
    static std::atomic<bool> fOneThread(false);
    if (fOneThread.exchange(true)) {
        return;
    }
    if (!gArgs.GetBoolArg("-flushwallet", DEFAULT_FLUSHWALLET)) {
        return;
    }

    for (const std::shared_ptr<CWallet>& pwallet : GetWallets()) {
        WalletDatabase& dbh = pwallet->GetDBHandle();

        unsigned int nUpdateCounter = dbh.nUpdateCounter;

        if (dbh.nLastSeen != nUpdateCounter) {
            dbh.nLastSeen = nUpdateCounter;
            dbh.nLastWalletUpdate = GetTime();
        }

        if (dbh.nLastFlushed != nUpdateCounter && GetTime() - dbh.nLastWalletUpdate >= 2) {
            if (BerkeleyBatch::PeriodicFlush(dbh)) {
                dbh.nLastFlushed = nUpdateCounter;
            }
        }
    }

    fOneThread = false;
}

//void ThreadFlushWalletDB(const std::string& strFile)
//{
//    // Make this thread recognisable as the wallet flushing thread
//    RenameThread("wispr-wallet");
//
//    static bool fOneThread;
//    if (fOneThread)
//        return;
//    fOneThread = true;
//    if (!gArgs.GetBoolArg("-flushwallet", true))
//        return;
//
//    unsigned int nLastSeen = nWalletDBUpdated;
//    unsigned int nLastFlushed = nWalletDBUpdated;
//    int64_t nLastWalletUpdate = GetTime();
//    while (true) {
//        MilliSleep(500);
//
//        if (nLastSeen != nWalletDBUpdated) {
//            nLastSeen = nWalletDBUpdated;
//            nLastWalletUpdate = GetTime();
//        }
//
//        if (nLastFlushed != nWalletDBUpdated && GetTime() - nLastWalletUpdate >= 2) {
//            TRY_LOCK(bitdb.cs_db, lockDb);
//            if (lockDb) {
//                // Don't do this if any databases are in use
//                int nRefCount = 0;
//                map<string, int>::iterator mi = bitdb.mapFileUseCount.begin();
//                while (mi != bitdb.mapFileUseCount.end()) {
//                    nRefCount += (*mi).second;
//                    mi++;
//                }
//
//                if (nRefCount == 0) {
//                    boost::this_thread::interruption_point();
//                    map<string, int>::iterator mi = bitdb.mapFileUseCount.find(strFile);
//                    if (mi != bitdb.mapFileUseCount.end()) {
//                        LogPrint(BCLog::DB, "Flushing wallet.dat\n");
//                        nLastFlushed = nWalletDBUpdated;
//                        int64_t nStart = GetTimeMillis();
//
//                        // Flush wallet.dat so it's self contained
//                        bitdb.CloseDb(strFile);
//                        bitdb.CheckpointLSN(strFile);
//
//                        bitdb.mapFileUseCount.erase(mi++);
//                        LogPrint(BCLog::DB, "Flushed wallet.dat %dms\n", GetTimeMillis() - nStart);
//                    }
//                }
//            }
//        }
//    }
//}

//void NotifyBacked(const CWallet& wallet, bool fSuccess, std::string strMessage)
//{
//    LogPrint(BCLog::NONE, strMessage.data());
//    wallet.NotifyWalletBacked(fSuccess, strMessage);
//}
//
//bool BackupWallet(const CWallet& wallet, const fs::path& strDest, bool fEnableCustom)
//{
//    fs::path pathCustom;
//    fs::path pathWithFile;
//    if (!wallet.fFileBacked) {
//        return false;
//    } else if(fEnableCustom) {
//        pathWithFile = gArgs.GetArg("-backuppath", "");
//        if(!pathWithFile.empty()) {
//            if(!pathWithFile.has_extension()) {
//                pathCustom = pathWithFile;
//                pathWithFile /= wallet.GetUniqueWalletBackupName(false);
//            } else {
//                pathCustom = pathWithFile.parent_path();
//            }
//            try {
//                fs::create_directories(pathCustom);
//            } catch(const fs::filesystem_error& e) {
//                NotifyBacked(wallet, false, strprintf("%s\n", e.what()));
//                pathCustom = "";
//            }
//        }
//    }
//
//    while (true) {
//        {
//            LOCK(bitdb.cs_db);
//            if (!bitdb.mapFileUseCount.count(wallet.strWalletFile) || bitdb.mapFileUseCount[wallet.strWalletFile] == 0) {
//                // Flush log data to the dat file
//                bitdb.CloseDb(wallet.strWalletFile);
//                bitdb.CheckpointLSN(wallet.strWalletFile);
//                bitdb.mapFileUseCount.erase(wallet.strWalletFile);
//
//                // Copy wallet.dat
//                fs::path pathDest(strDest);
//                fs::path pathSrc = GetDataDir() / wallet.strWalletFile;
//                if (is_directory(pathDest)) {
//                    if(!exists(pathDest)) create_directory(pathDest);
//                    pathDest /= wallet.strWalletFile;
//                }
//                bool defaultPath = AttemptBackupWallet(wallet, pathSrc.string(), pathDest.string());
//
//                if(defaultPath && !pathCustom.empty()) {
//                    int nThreshold = gArgs.GetArg("-custombackupthreshold", DEFAULT_CUSTOMBACKUPTHRESHOLD);
//                    if (nThreshold > 0) {
//
//                        typedef std::multimap<std::time_t, fs::path> folder_set_t;
//                        folder_set_t folderSet;
//                        fs::directory_iterator end_iter;
//
//                        pathCustom.make_preferred();
//                        // Build map of backup files for current(!) wallet sorted by last write time
//
//                        fs::path currentFile;
//                        for (fs::directory_iterator dir_iter(pathCustom); dir_iter != end_iter; ++dir_iter) {
//                            // Only check regular files
//                            if (fs::is_regular_file(dir_iter->status())) {
//                                currentFile = dir_iter->path().filename();
//                                // Only add the backups for the current wallet, e.g. wallet.dat.*
//                                if (dir_iter->path().stem().string() == wallet.strWalletFile) {
//                                    folderSet.insert(folder_set_t::value_type(fs::last_write_time(dir_iter->path()), *dir_iter));
//                                }
//                            }
//                        }
//
//                        int counter = 0; //TODO: add seconds to avoid naming conflicts
//                        for (auto entry : folderSet) {
//                            counter++;
//                            if(entry.second == pathWithFile) {
//                                pathWithFile += "(1)";
//                            }
//                        }
//
//                        if (counter >= nThreshold) {
//                            std::time_t oldestBackup = 0;
//                            for(auto entry : folderSet) {
//                                if(oldestBackup == 0 || entry.first < oldestBackup) {
//                                    oldestBackup = entry.first;
//                                }
//                            }
//
//                            try {
//                                auto entry = folderSet.find(oldestBackup);
//                                if (entry != folderSet.end()) {
//                                    fs::remove(entry->second);
//                                    LogPrintf("Old backup deleted: %s\n", (*entry).second);
//                                }
//                            } catch (fs::filesystem_error& error) {
//                                std::string strMessage = strprintf("Failed to delete backup %s\n", error.what());
//                                LogPrint(BCLog::NONE, strMessage.data());
//                                NotifyBacked(wallet, false, strMessage);
//                            }
//                        }
//                    }
//                    AttemptBackupWallet(wallet, pathSrc.string(), pathWithFile.string());
//                }
//
//                return defaultPath;
//            }
//        }
//        MilliSleep(100);
//    }
//    return false;
//}
//
//bool AttemptBackupWallet(const CWallet& wallet, const fs::path& pathSrc, const fs::path& pathDest)
//{
//    bool retStatus;
//    std::string strMessage;
//    try {
//        if (fs::equivalent(pathSrc, pathDest)) {
//            LogPrintf("cannot backup to wallet source file %s\n", pathDest.string());
//            return false;
//        }
//#if BOOST_VERSION >= 105800 /* BOOST_LIB_VERSION 1_58 */
//        fs::copy_file(pathSrc.c_str(), pathDest, fs::copy_option::overwrite_if_exists);
//#else
//        std::ifstream src(pathSrc.c_str(),  std::ios::binary | std::ios::in);
//        std::ofstream dst(pathDest.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
//        dst << src.rdbuf();
//        dst.flush();
//        src.close();
//        dst.close();
//#endif
//        strMessage = strprintf("copied wallet.dat to %s\n", pathDest.string());
//        LogPrint(BCLog::NONE, strMessage.data());
//        retStatus = true;
//    } catch (const fs::filesystem_error& e) {
//        retStatus = false;
//        strMessage = strprintf("%s\n", e.what());
//        LogPrint(BCLog::NONE, strMessage.data());
//    }
//    NotifyBacked(wallet, retStatus, strMessage);
//    return retStatus;
//}

//
// Try to (very carefully!) recover wallet file if there is a problem.
//
bool WalletBatch::Recover(const fs::path& wallet_path, void *callbackDataIn, bool (*recoverKVcallback)(void* callbackData, CDataStream ssKey, CDataStream ssValue), std::string& out_backup_filename)
{
    return BerkeleyBatch::Recover(wallet_path, callbackDataIn, recoverKVcallback, out_backup_filename);
}

bool WalletBatch::Recover(const fs::path& wallet_path, std::string& out_backup_filename)
{
    // recover without a key filter callback
    // results in recovering all record types
    return WalletBatch::Recover(wallet_path, nullptr, nullptr, out_backup_filename);
}

bool WalletBatch::RecoverKeysOnlyFilter(void *callbackData, CDataStream ssKey, CDataStream ssValue)
{
    CWallet *dummyWallet = reinterpret_cast<CWallet*>(callbackData);
    CWalletScanState dummyWss;
    std::string strType, strErr;
    bool fReadOK;
    {
        // Required in LoadKeyMetadata():
        LOCK(dummyWallet->cs_wallet);
        fReadOK = ReadKeyValue(dummyWallet, ssKey, ssValue,
                               dummyWss, strType, strErr);
    }
    if (!IsKeyType(strType) && strType != "hdchain")
        return false;
    if (!fReadOK)
    {
        LogPrintf("WARNING: WalletBatch::Recover skipping %s: %s\n", strType, strErr);
        return false;
    }

    return true;
}

bool WalletBatch::VerifyEnvironment(const fs::path& wallet_path, std::string& errorStr)
{
    return BerkeleyBatch::VerifyEnvironment(wallet_path, errorStr);
}

bool WalletBatch::VerifyDatabaseFile(const fs::path& wallet_path, std::string& warningStr, std::string& errorStr)
{
    return BerkeleyBatch::VerifyDatabaseFile(wallet_path, warningStr, errorStr, WalletBatch::Recover);
}

bool WalletBatch::WriteDestData(const std::string &address, const std::string &key, const std::string &value)
{
    return WriteIC(std::make_pair(std::string("destdata"), std::make_pair(address, key)), value);
}

bool WalletBatch::EraseDestData(const std::string &address, const std::string &key)
{
    return EraseIC(std::make_pair(std::string("destdata"), std::make_pair(address, key)));
}

bool WalletBatch::WriteHDChain(const CHDChain& chain)
{
    return WriteIC(std::string("hdchain"), chain);
}

bool WalletBatch::WriteWalletFlags(const uint64_t flags)
{
    return WriteIC(std::string("flags"), flags);
}

bool WalletBatch::TxnBegin()
{
    return m_batch.TxnBegin();
}

bool WalletBatch::TxnCommit()
{
    return m_batch.TxnCommit();
}

bool WalletBatch::TxnAbort()
{
    return m_batch.TxnAbort();
}

bool WalletBatch::ReadVersion(int& nVersion)
{
    return m_batch.ReadVersion(nVersion);
}

bool WalletBatch::WriteVersion(int nVersion)
{
    return m_batch.WriteVersion(nVersion);
}

bool WalletBatch::WriteZerocoinSpendSerialEntry(const CZerocoinSpend& zerocoinSpend)
{
    return WriteIC(std::make_pair(string("zcserial"), zerocoinSpend.GetSerial()), zerocoinSpend, true);
}
bool WalletBatch::EraseZerocoinSpendSerialEntry(const CBigNum& serialEntry)
{
    return EraseIC(std::make_pair(string("zcserial"), serialEntry));
}

bool WalletBatch::ReadZerocoinSpendSerialEntry(const CBigNum& bnSerial)
{
    CZerocoinSpend spend;
    return m_batch.Read(std::make_pair(string("zcserial"), bnSerial), spend);
}

bool WalletBatch::WriteDeterministicMint(const CDeterministicMint& dMint)
{
    uint256 hash = dMint.GetPubcoinHash();
    return WriteIC(std::make_pair(string("dzwsp"), hash), dMint, true);
}

bool WalletBatch::ReadDeterministicMint(const uint256& hashPubcoin, CDeterministicMint& dMint)
{
    return m_batch.Read(std::make_pair(string("dzwsp"), hashPubcoin), dMint);
}

bool WalletBatch::EraseDeterministicMint(const uint256& hashPubcoin)
{
    return EraseIC(std::make_pair(string("dzwsp"), hashPubcoin));
}

bool WalletBatch::WriteZerocoinMint(const CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << zerocoinMint.GetValue();
    uint256 hash = Hash(ss.begin(), ss.end());

    EraseIC(std::make_pair(string("zerocoin"), hash));
    return WriteIC(std::make_pair(string("zerocoin"), hash), zerocoinMint, true);
}

bool WalletBatch::ReadZerocoinMint(const CBigNum &bnPubCoinValue, CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnPubCoinValue;
    uint256 hash = Hash(ss.begin(), ss.end());

    return ReadZerocoinMint(hash, zerocoinMint);
}

bool WalletBatch::ReadZerocoinMint(const uint256& hashPubcoin, CZerocoinMint& mint)
{
    return m_batch.Read(std::make_pair(string("zerocoin"), hashPubcoin), mint);
}

bool WalletBatch::EraseZerocoinMint(const CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << zerocoinMint.GetValue();
    uint256 hash = Hash(ss.begin(), ss.end());

    return EraseIC(std::make_pair(string("zerocoin"), hash));
}

bool WalletBatch::ArchiveMintOrphan(const CZerocoinMint& zerocoinMint)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << zerocoinMint.GetValue();
    uint256 hash = Hash(ss.begin(), ss.end());;

    if (!WriteIC(std::make_pair(string("zco"), hash), zerocoinMint)) {
        LogPrintf("%s : failed to database orphaned zerocoin mint\n", __func__);
        return false;
    }

    if (!EraseIC(std::make_pair(string("zerocoin"), hash))) {
        LogPrintf("%s : failed to erase orphaned zerocoin mint\n", __func__);
        return false;
    }

    return true;
}

bool WalletBatch::ArchiveDeterministicOrphan(const CDeterministicMint& dMint)
{
    if (!WriteIC(std::make_pair(string("dzco"), dMint.GetPubcoinHash()), dMint))
        return error("%s: write failed", __func__);

    if (!EraseIC(std::make_pair(string("dzwsp"), dMint.GetPubcoinHash())))
        return error("%s: failed to erase", __func__);

    return true;
}

bool WalletBatch::UnarchiveDeterministicMint(const uint256& hashPubcoin, CDeterministicMint& dMint)
{
    if (!m_batch.Read(std::make_pair(string("dzco"), hashPubcoin), dMint))
        return error("%s: failed to retrieve deterministic mint from archive", __func__);

    if (!WriteDeterministicMint(dMint))
        return error("%s: failed to write deterministic mint", __func__);

    if (!EraseIC(std::make_pair(string("dzco"), dMint.GetPubcoinHash())))
        return error("%s : failed to erase archived deterministic mint", __func__);

    return true;
}

bool WalletBatch::UnarchiveZerocoinMint(const uint256& hashPubcoin, CZerocoinMint& mint)
{
    if (!m_batch.Read(std::make_pair(string("zco"), hashPubcoin), mint))
        return error("%s: failed to retrieve zerocoinmint from archive", __func__);

    if (!WriteZerocoinMint(mint))
        return error("%s: failed to write zerocoinmint", __func__);

    uint256 hash = GetPubCoinHash(mint.GetValue());
    if (!EraseIC(std::make_pair(string("zco"), hash)))
        return error("%s : failed to erase archived zerocoin mint", __func__);

    return true;
}

bool WalletBatch::WriteCurrentSeedHash(const uint256& hashSeed)
{
    return WriteIC(string("seedhash"), hashSeed);
}

bool WalletBatch::ReadCurrentSeedHash(uint256& hashSeed)
{
    return m_batch.Read(string("seedhash"), hashSeed);
}

bool WalletBatch::WriteZWSPSeed(const uint256& hashSeed, const std::vector<unsigned char>& seed)
{
    if (!WriteCurrentSeedHash(hashSeed))
        return error("%s: failed to write current seed hash", __func__);

    return WriteIC(std::make_pair(string("dzs"), hashSeed), seed);
}

bool WalletBatch::EraseZWSPSeed()
{
    uint256 hash;
    if(!ReadCurrentSeedHash(hash)){
        return error("Failed to read a current seed hash");
    }
    if(!WriteZWSPSeed(hash, ToByteVector(base_uint<256>(0) << 256))) {
        return error("Failed to write empty seed to wallet");
    }
    if(!WriteCurrentSeedHash(0)) {
        return error("Failed to write empty seedHash");
    }

    return true;
}

bool WalletBatch::EraseZWSPSeed_deprecated()
{
    return EraseIC(string("dzs"));
}

bool WalletBatch::ReadZWSPSeed(const uint256& hashSeed, std::vector<unsigned char>& seed)
{
    return m_batch.Read(std::make_pair(string("dzs"), hashSeed), seed);
}

bool WalletBatch::ReadZWSPSeed_deprecated(uint256& seed)
{
    return m_batch.Read(string("dzs"), seed);
}

bool WalletBatch::WriteZWSPCount(const uint32_t& nCount)
{
    return WriteIC(string("dzc"), nCount);
}

bool WalletBatch::ReadZWSPCount(uint32_t& nCount)
{
    return m_batch.Read(string("dzc"), nCount);
}

bool WalletBatch::WriteMintPoolPair(const uint256& hashMasterSeed, const uint256& hashPubcoin, const uint32_t& nCount)
{
    return WriteIC(std::make_pair(string("mintpool"), hashPubcoin), make_pair(hashMasterSeed, nCount));
}

//! map with hashMasterSeed as the key, paired with vector of hashPubcoins and their count
std::map<uint256, std::vector<std::pair<uint256, uint32_t> > > WalletBatch::MapMintPool()
{
    std::map<uint256, std::vector<std::pair<uint256, uint32_t> > > mapPool;
    Dbc* pcursor = m_batch.GetCursor();
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
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
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
            std::vector<std::pair<uint256, uint32_t> > vPairs;
            vPairs.emplace_back(pMint);
            mapPool.insert(std::make_pair(hashMasterSeed, vPairs));
        }
    }

    pcursor->close();

    return mapPool;
}

std::list<CDeterministicMint> WalletBatch::ListDeterministicMints()
{
    std::list<CDeterministicMint> listMints;
    Dbc* pcursor = m_batch.GetCursor();
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
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
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

std::list<CZerocoinMint> WalletBatch::ListMintedCoins()
{
    std::list<CZerocoinMint> listPubCoin;
    Dbc* pcursor = m_batch.GetCursor();
    if (!pcursor)
        throw runtime_error(std::string(__func__)+" : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    std::vector<CZerocoinMint> vOverWrite;
    std::vector<CZerocoinMint> vArchive;
    for (;;)
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("zerocoin"), uint256(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
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

std::list<CZerocoinSpend> WalletBatch::ListSpentCoins()
{
    std::list<CZerocoinSpend> listCoinSpend;
    Dbc* pcursor = m_batch.GetCursor();
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
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
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
std::list<CBigNum> WalletBatch::ListSpentCoinsSerial()
{
    std::list<CBigNum> listPubCoin;
    std::list<CZerocoinSpend> listCoins = ListSpentCoins();

    for ( auto& coin : listCoins) {
        listPubCoin.push_back(coin.GetSerial());
    }
    return listPubCoin;
}

std::list<CZerocoinMint> WalletBatch::ListArchivedZerocoins()
{
    std::list<CZerocoinMint> listMints;
    Dbc* pcursor = m_batch.GetCursor();
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
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
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

std::list<CDeterministicMint> WalletBatch::ListArchivedDeterministicMints()
{
    std::list<CDeterministicMint> listMints;
    Dbc* pcursor = m_batch.GetCursor();
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
        int ret = m_batch.ReadAtCursor(pcursor, ssKey, ssValue);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
        {
            pcursor->close();
            throw runtime_error(std::string(__func__)+" : error scanning DB");
        }

        // Unserialize
        std::string strType;
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
