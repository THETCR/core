// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <accumulators.h>
#include <checkpoints.h>
#include <chain.h>
#include <wallet/coincontrol.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <fs.h>
#include <interfaces/chain.h>
#include <interfaces/wallet.h>
#include <kernel.h>
#include <key.h>
#include <key_io.h>
#include <keystore.h>
#include <main.h>
#include <masternode-budget.h>
#include <net.h>
#include <net_processing.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/sign.h>
#include <shutdown.h>
#include <spork.h>
#include <stakeinput.h>
#include <swifttx.h>
#include <timedata.h>
#include <txmempool.h>
#include <util/bip32.h>
#include <util/moneystr.h>
#include <wallet/fees.h>
#include <zwspchain.h>

#include <denomination_functions.h>
#include <libzerocoin/bignum.h>
#include <libzerocoin/Denominations.h>
#include <wallet/zwspwallet.h>
#include <primitives/deterministicmint.h>
#include <algorithm>
#include <assert.h>
#include <future>

#include <wallet/zwspwallet.h>
#include <wallet/zwsptracker.h>

#include <boost/algorithm/string/replace.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;
CWallet* pwalletMain = nullptr;
CzWSPWallet* zwalletMain = nullptr;
/**
 * Settings
 */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;
unsigned int nTxConfirmTarget = 1;
bool bSpendZeroConfChange = true;
bool bdisableSystemnotifications = false; // Those bubbles can be annoying and slow down the UI when you get lots of trx
bool fSendFreeTransactions = false;
bool fPayAtLeastCustomFee = true;
int64_t nStartupTime = GetTime(); //!< Client startup time for use with automint

/**
 * Fees smaller than this (in uwsp) are considered zero fee (for transaction creation)
 * We are ~100 times smaller then bitcoin now (2015-06-23), set minTxFee 10 times higher
 * so it's still 10 times lower comparing to bitcoin.
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(10000);

static const size_t OUTPUT_GROUP_MAX_ENTRIES = 10;

static CCriticalSection cs_wallets;
static std::vector<std::shared_ptr<CWallet>> vpwallets GUARDED_BY(cs_wallets);

bool AddWallet(const std::shared_ptr<CWallet>& wallet)
{
    LOCK(cs_wallets);
    assert(wallet);
    std::vector<std::shared_ptr<CWallet>>::const_iterator i = std::find(vpwallets.begin(), vpwallets.end(), wallet);
    if (i != vpwallets.end()) return false;
    vpwallets.push_back(wallet);
    return true;
}

bool RemoveWallet(const std::shared_ptr<CWallet>& wallet)
{
    LOCK(cs_wallets);
    assert(wallet);
    std::vector<std::shared_ptr<CWallet>>::iterator i = std::find(vpwallets.begin(), vpwallets.end(), wallet);
    if (i == vpwallets.end()) return false;
    vpwallets.erase(i);
    return true;
}

bool HasWallets()
{
    LOCK(cs_wallets);
    return !vpwallets.empty();
}

std::vector<std::shared_ptr<CWallet>> GetWallets()
{
    LOCK(cs_wallets);
    return vpwallets;
}

std::shared_ptr<CWallet> GetWallet(const std::string& name)
{
    LOCK(cs_wallets);
    for (const std::shared_ptr<CWallet>& wallet : vpwallets) {
        if (wallet->GetName() == name) return wallet;
    }
    return nullptr;
}

static Mutex g_wallet_release_mutex;
static std::condition_variable g_wallet_release_cv;
static std::set<CWallet*> g_unloading_wallet_set;

// Custom deleter for shared_ptr<CWallet>.
static void ReleaseWallet(CWallet* wallet)
{
    // Unregister and delete the wallet right after BlockUntilSyncedToCurrentChain
    // so that it's in sync with the current chainstate.
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->BlockUntilSyncedToCurrentChain();
    wallet->Flush();
    UnregisterValidationInterface(wallet);
    delete wallet;
    // Wallet is now released, notify UnloadWallet, if any.
    {
        LOCK(g_wallet_release_mutex);
        if (g_unloading_wallet_set.erase(wallet) == 0) {
            // UnloadWallet was not called for this wallet, all done.
            return;
        }
    }
    g_wallet_release_cv.notify_all();
}

void UnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    // Mark wallet for unloading.
    CWallet* pwallet = wallet.get();
    {
        LOCK(g_wallet_release_mutex);
        auto it = g_unloading_wallet_set.insert(pwallet);
        assert(it.second);
    }
    // The wallet can be in use so it's not possible to explicitly unload here.
    // Notify the unload intent so that all remaining shared pointers are
    // released.
    pwallet->NotifyUnload();
    // Time to ditch our shared_ptr and wait for ReleaseWallet call.
    wallet.reset();
    {
        WAIT_LOCK(g_wallet_release_mutex, lock);
        while (g_unloading_wallet_set.count(pwallet) == 1) {
            g_wallet_release_cv.wait(lock);
        }
    }
}

std::shared_ptr<CWallet> LoadWallet(interfaces::Chain& chain, const WalletLocation& location, std::string& error, std::string& warning)
{
    if (!CWallet::Verify(chain, location, false, error, warning)) {
        error = "Wallet file verification failed: " + error;
        return nullptr;
    }

    std::shared_ptr<CWallet> wallet = CWallet::CreateWalletFromFile(chain, location);
    if (!wallet) {
        error = "Wallet loading failed.";
        return nullptr;
    }
    AddWallet(wallet);
    wallet->postInitProcess();
    return wallet;
}

std::shared_ptr<CWallet> LoadWallet(interfaces::Chain& chain, const std::string& name, std::string& error, std::string& warning)
{
    return LoadWallet(chain, WalletLocation(name), error, warning);
}

const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly {
    bool operator()(const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t1,
        const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", tx->tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->tx->vout[i].nValue));
}

std::vector<CKeyID> GetAffectedKeys(const CScript& spk, const SigningProvider& provider)
{
    std::vector<CScript> dummy;
    FlatSigningProvider out;
    InferDescriptor(spk, provider)->Expand(0, DUMMY_SIGNING_PROVIDER, dummy, out);
    std::vector<CKeyID> ret;
    for (const auto& entry : out.pubkeys) {
        ret.push_back(entry.first);
    }
    return ret;
}

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return nullptr;
    return &(it->second);
}

CPubKey CWallet::GenerateNewKey(WalletBatch &batch, bool internal)
{
    assert(!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    assert(!IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // use HD key derivation if HD was enabled during wallet creation and a seed is present
    if (IsHDEnabled()) {
        DeriveNewChildKey(batch, metadata, secret, (CanSupportFeature(FEATURE_HD_SPLIT) ? internal : false));
    } else {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed) {
        SetMinVersion(FEATURE_COMPRPUBKEY);
    }

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    UpdateTimeFirstKey(nCreationTime);

    if (!AddKeyPubKeyWithDB(batch, secret, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": AddKey failed");
    }
    return pubkey;
}

CBitcoinAddress CWallet::GenerateNewAutoMintKey()
{
    CBitcoinAddress btcAddress;
    WalletBatch batch(*database);
    CKeyID keyID = GenerateNewKey(batch).GetID();
    btcAddress.Set(keyID);
    batch.WriteAutoConvertKey(btcAddress);
    SetAddressBook(keyID, "automint-address", "receive");
    setAutoConvertAddresses.emplace(btcAddress);
    return btcAddress;
}

void CWallet::DeriveNewChildKey(WalletBatch &batch, CKeyMetadata& metadata, CKey& secret, bool internal)
{
    // for now we use a fixed keypath scheme of m/0'/0'/k
    CKey seed;                     //seed (256bit)
    CExtKey masterKey;             //hd master key
    CExtKey accountKey;            //key at m/0'
    CExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
    CExtKey childKey;              //key at m/0'/0'/<n>'

    // try to get the seed
    if (!GetKey(hdChain.seed_id, seed))
        throw std::runtime_error(std::string(__func__) + ": seed not found");

    masterKey.SetSeed(seed.begin(), seed.size());

    // derive m/0'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

    // derive m/0'/0' (external chain) OR m/0'/1' (internal chain)
    assert(internal ? CanSupportFeature(FEATURE_HD_SPLIT) : true);
    accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT+(internal ? 1 : 0));

    // derive child key at next index, skip keys already known to the wallet
    do {
        // always derive hardened keys
        // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
        // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
        if (internal) {
            chainChildKey.Derive(childKey, hdChain.nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/1'/" + std::to_string(hdChain.nInternalChainCounter) + "'";
            metadata.key_origin.path.push_back(0 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(1 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(hdChain.nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            hdChain.nInternalChainCounter++;
        }
        else {
            chainChildKey.Derive(childKey, hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/0'/" + std::to_string(hdChain.nExternalChainCounter) + "'";
            metadata.key_origin.path.push_back(0 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(0 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            hdChain.nExternalChainCounter++;
        }
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secret = childKey.key;
    metadata.hd_seed_id = hdChain.seed_id;
    CKeyID master_id = masterKey.key.GetPubKey().GetID();
    std::copy(master_id.begin(), master_id.begin() + 4, metadata.key_origin.fingerprint);
    metadata.has_key_origin = true;
    // update the chain model in the database
    if (!batch.WriteHDChain(hdChain))
        throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
}

bool CWallet::AddKeyPubKeyWithDB(WalletBatch &batch, const CKey& secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata

    // Make sure we aren't adding private keys to private key disabled wallets
    assert(!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // CCryptoKeyStore has no concept of wallet databases, but calls AddCryptedKey
    // which is overridden below.  To avoid flushes, the database handle is
    // tunneled through to it.
    bool needsDB = !encrypted_batch;
    if (needsDB) {
        encrypted_batch = &batch;
    }
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey)) {
        if (needsDB) encrypted_batch = nullptr;
        return false;
    }
    if (needsDB) encrypted_batch = nullptr;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }

    if (!IsCrypted()) {
        return batch.WriteKey(pubkey,
                              secret.GetPrivKey(),
                              mapKeyMetadata[pubkey.GetID()]);
    }
    UnsetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    return true;
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    WalletBatch batch(*database);
    return CWallet::AddKeyPubKeyWithDB(batch, secret, pubkey);
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_wallet);
        if (encrypted_batch)
            return encrypted_batch->WriteCryptedKey(vchPubKey,
                                                    vchCryptedSecret,
                                                    mapKeyMetadata[vchPubKey.GetID()]);
        else
            return WalletBatch(*database).WriteCryptedKey(vchPubKey,
                                                          vchCryptedSecret,
                                                          mapKeyMetadata[vchPubKey.GetID()]);
    }
}

void CWallet::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    UpdateTimeFirstKey(meta.nCreateTime);
    mapKeyMetadata[keyID] = meta;
}

void CWallet::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // m_script_metadata
    UpdateTimeFirstKey(meta.nCreateTime);
    m_script_metadata[script_id] = meta;
}

// Writes a keymetadata for a public key. overwrite specifies whether to overwrite an existing metadata for that key if there exists one.
bool CWallet::WriteKeyMetadata(const CKeyMetadata& meta, const CPubKey& pubkey, const bool overwrite)
{
    return WalletBatch(*database).WriteKeyMetadata(meta, pubkey, overwrite);
}

void CWallet::UpgradeKeyMetadata()
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (IsLocked() || IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
        return;
    }

    std::unique_ptr<WalletBatch> batch = MakeUnique<WalletBatch>(*database);
    size_t cnt = 0;
    for (auto& meta_pair : mapKeyMetadata) {
        CKeyMetadata& meta = meta_pair.second;
        if (!meta.hd_seed_id.IsNull() && !meta.has_key_origin && meta.hdKeypath != "s") { // If the hdKeypath is "s", that's the seed and it doesn't have a key origin
            CKey key;
            GetKey(meta.hd_seed_id, key);
            CExtKey masterKey;
            masterKey.SetSeed(key.begin(), key.size());
            // Add to map
            CKeyID master_id = masterKey.key.GetPubKey().GetID();
            std::copy(master_id.begin(), master_id.begin() + 4, meta.key_origin.fingerprint);
            if (!ParseHDKeypath(meta.hdKeypath, meta.key_origin.path)) {
                throw std::runtime_error("Invalid stored hdKeypath");
            }
            meta.has_key_origin = true;
            if (meta.nVersion < CKeyMetadata::VERSION_WITH_KEY_ORIGIN) {
                meta.nVersion = CKeyMetadata::VERSION_WITH_KEY_ORIGIN;
            }

            // Write meta to wallet
            CPubKey pubkey;
            if (GetPubKey(meta_pair.first, pubkey)) {
                batch->WriteKeyMetadata(meta, pubkey, true);
                if (++cnt % 1000 == 0) {
                    // avoid creating overlarge in-memory batches in case the wallet contains large amounts of keys
                    batch.reset(new WalletBatch(*database));
                }
            }
        }
    }
    batch.reset(); //write before setting the flag
    SetWalletFlag(WALLET_FLAG_KEY_ORIGIN_METADATA);
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

/**
 * Update wallet first key creation time. This should be called whenever keys
 * are added to the wallet, with the oldest key creation time.
 */
void CWallet::UpdateTimeFirstKey(int64_t nCreateTime)
{
    AssertLockHeld(cs_wallet);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (WalletBatch(*database).WriteCScript(Hash160(redeemScript), redeemScript)) {
        UnsetWalletFlag(WALLET_FLAG_BLANK_WALLET);
        return true;
    }
    return false;
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(CScriptID(redeemScript));
        WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript& dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    const CKeyMetadata& meta = m_script_metadata[CScriptID(dest)];
    UpdateTimeFirstKey(meta.nCreateTime);
    NotifyWatchonlyChanged(true);
    if (WalletBatch(*database).WriteWatchOnly(dest, meta)) {
        UnsetWalletFlag(WALLET_FLAG_BLANK_WALLET);
        return true;
    }
    return false;
}

bool CWallet::AddWatchOnly(const CScript& dest, int64_t nCreateTime)
{
    m_script_metadata[CScriptID(dest)].nCreateTime = nCreateTime;
    return AddWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (!WalletBatch(*database).EraseWatchOnly(dest))
        return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::AddMultiSig(const CScript& dest)
{
    if (!CCryptoKeyStore::AddMultiSig(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information
    NotifyMultiSigChanged(true);
    if (!fFileBacked)
        return true;
    return WalletBatch(*database).WriteMultiSig(dest);
}

bool CWallet::RemoveMultiSig(const CScript& dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveMultiSig(dest))
        return false;
    if (!HaveMultiSig())
        NotifyMultiSigChanged(false);
    if (fFileBacked)
        if (!WalletBatch(*database).EraseMultiSig(dest))
            return false;

    return true;
}

bool CWallet::LoadMultiSig(const CScript& dest)
{
    return CCryptoKeyStore::AddMultiSig(dest);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase, bool accept_no_keys, bool anonymizeOnly)
{
    CCrypter crypter;
    CKeyingMaterial _vMasterKey;

    {
        LOCK(cs_wallet);
        for (const MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(_vMasterKey, accept_no_keys)) {
                // Now that we've unlocked, upgrade the key metadata
                fWalletUnlockAnonymizeOnly = anonymizeOnly;
                UpgradeKeyMetadata();
                return true;
            }
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial _vMasterKey;
        for (MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(_vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime))));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime)))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                WalletLogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(_vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                WalletBatch(*database).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::ChainStateFlushed(const CBlockLocator& loc)
{
    WalletBatch batch(*database);
    batch.WriteBestBlock(loc);
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    WalletBatch batch(*database);
    batch.WriteBestBlock(loc);
}

void CWallet::SetMinVersion(enum WalletFeature nVersion, WalletBatch* batch_in, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
        nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    {
        WalletBatch* batch = batch_in ? batch_in : new WalletBatch(*database);
        if (nWalletVersion > 40000)
            batch->WriteMinVersion(nWalletVersion);
        if (!batch_in)
            delete batch;
    }
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

std::set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

bool CWallet::HasWalletSpend(const uint256& txid) const
{
    AssertLockHeld(cs_wallet);
    auto iter = mapTxSpends.lower_bound(COutPoint(txid, 0));
    return (iter != mapTxSpends.end() && iter->first.hash == txid);
}

void CWallet::Flush(bool shutdown)
{
    database->Flush(shutdown);
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const CWalletTx* wtx = &mapWallet.at(it->second);
        if (wtx->nOrderPos < nMinOrderPos) {
            nMinOrderPos = wtx->nOrderPos;
            copyFrom = wtx;
        }
    }

    if (!copyFrom) {
        return;
    }

    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet.at(hash);
        if (copyFrom == copyTo) continue;
        assert(copyFrom && "Oldest wallet transaction in range assumed to have been found.");
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(interfaces::Chain::Lock& locked_chain, const uint256& hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = mit->second.GetDepthInMainChain(locked_chain);
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));

    setLockedCoins.erase(outpoint);

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const uint256& wtxid)
{
    auto it = mapWallet.find(wtxid);
    assert(it != mapWallet.end());
    CWalletTx& thisTx = it->second;
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : thisTx.tx->vin)
        AddToSpends(txin.prevout, wtxid);
}

bool CWallet::GetMasternodeVinAndKeys(CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet, std::string strTxHash, std::string strOutputIndex)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    std::vector<COutput> vPossibleCoins;
    AvailableCoins(vPossibleCoins, true, NULL, false, ONLY_125000);
    if (vPossibleCoins.empty()) {
        LogPrintf("CWallet::GetMasternodeVinAndKeys -- Could not locate any valid masternode vin\n");
        return false;
    }

    if (strTxHash.empty()) // No output specified, select the first one
        return GetVinAndKeysFromOutput(vPossibleCoins[0], txinRet, pubKeyRet, keyRet);

    // Find specific vin
    uint256 txHash = uint256S(strTxHash);

    int nOutputIndex;
    try {
        nOutputIndex = std::stoi(strOutputIndex.c_str());
    } catch (const std::exception& e) {
        LogPrintf("%s: %s on strOutputIndex\n", __func__, e.what());
        return false;
    }

    for (COutput& out: vPossibleCoins)
        if (out.tx->tx->GetHash() == txHash && out.i == nOutputIndex) // found it!
            return GetVinAndKeysFromOutput(out, txinRet, pubKeyRet, keyRet);

    LogPrintf("CWallet::GetMasternodeVinAndKeys -- Could not locate specified masternode vin\n");
    return false;
}

bool CWallet::GetVinAndKeysFromOutput(COutput out, CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;

    txinRet = CTxIn(out.tx->tx->GetHash(), out.i);
    pubScript = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    CKeyID keyID;
    if (!address2.GetKeyID(keyID)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Address does not refer to a key\n");
        return false;
    }

    if (!GetKey(keyID, keyRet)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Private key for address is not known\n");
        return false;
    }

    pubKeyRet = keyRet.GetPubKey();
    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial _vMasterKey;

    _vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(&_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = static_cast<unsigned int>(2500000 / ((double)(GetTimeMillis() - nStartTime)));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + static_cast<unsigned int>(kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime)))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    WalletLogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        assert(!encrypted_batch);
        encrypted_batch = new WalletBatch(*database);
        if (!encrypted_batch->TxnBegin()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            return false;
        }
        encrypted_batch->WriteMasterKey(nMasterKeyMaxID, kMasterKey);

        if (!EncryptKeys(_vMasterKey))
        {
            encrypted_batch->TxnAbort();
            delete encrypted_batch;
            encrypted_batch = nullptr;
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, encrypted_batch, true);

        if (!encrypted_batch->TxnCommit()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            // We now have keys encrypted in memory, but not on disk...
            // die to avoid confusion and let the user reload the unencrypted wallet.
            assert(false);
        }

        delete encrypted_batch;
        encrypted_batch = nullptr;

        Lock();
        Unlock(strWalletPassphrase);

        // if we are using HD, replace the HD seed with a new one
        if (IsHDEnabled()) {
            SetHDSeed(GenerateNewSeed());
        }

        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        database->Rewrite();

        // BDB seems to have a bad habit of writing old data into
        // slack space in .dat files; that is bad if the old data is
        // unencrypted private keys. So:
        database->ReloadDbEnv();

    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    WalletBatch batch(*database);

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx into a sorted-by-time multimap.
    typedef std::multimap<int64_t, CWalletTx*> TxItems;
    TxItems txByTime;

    for (auto& entry : mapWallet)
    {
        CWalletTx* wtx = &entry.second;
        txByTime.insert(std::make_pair(wtx->nTimeReceived, wtx));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second;
        int64_t& nOrderPos = pwtx->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
    }
    batch.WriteOrderPosNext(nOrderPosNext);

    return DBErrors::LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(WalletBatch *batch)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (batch) {
        batch->WriteOrderPosNext(nOrderPosNext);
    } else {
        WalletBatch(*database).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (std::pair<const uint256, CWalletTx> & item: mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::MarkReplaced(const uint256& originalHash, const uint256& newHash)
{
    LOCK(cs_wallet);

    auto mi = mapWallet.find(originalHash);

    // There is a bug if MarkReplaced is not called on an existing wallet transaction.
    assert(mi != mapWallet.end());

    CWalletTx& wtx = (*mi).second;

    // Ensure for now that we're not overwriting data
    assert(wtx.mapValue.count("replaced_by_txid") == 0);

    wtx.mapValue["replaced_by_txid"] = newHash.ToString();

    WalletBatch batch(*database, "r+");

    bool success = true;
    if (!batch.WriteTx(wtx)) {
        WalletLogPrintf("%s: Updating batch tx %s failed\n", __func__, wtx.GetHash().ToString());
        success = false;
    }

    NotifyTransactionChanged(this, originalHash, CT_UPDATED);

    return success;
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn, bool fFlushOnClose)
{
    LOCK(cs_wallet);

    WalletBatch batch(*database, "r+", fFlushOnClose);

    uint256 hash = wtxIn.GetHash();

    // Inserts only if not already there, returns tx inserted or tx found
    std::pair<std::map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(std::make_pair(hash, wtxIn));
    CWalletTx& wtx = (*ret.first).second;
    wtx.BindWallet(this);
    bool fInsertedNew = ret.second;
    if (fInsertedNew) {
        wtx.nTimeReceived = chain().getAdjustedTime();
        wtx.nOrderPos = IncOrderPosNext(&batch);
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
        wtx.nTimeSmart = ComputeTimeSmart(wtx);
        AddToSpends(hash);
    }

    bool fUpdated = false;
    if (!fInsertedNew)
    {
        // Merge
        if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock)
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        // If no longer abandoned, update
        if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned())
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex))
        {
            wtx.nIndex = wtxIn.nIndex;
            fUpdated = true;
        }
        if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
        {
            wtx.fFromMe = wtxIn.fFromMe;
            fUpdated = true;
        }
        // If we have a witness-stripped version of this transaction, and we
        // see a new version with a witness, then we must be upgrading a pre-segwit
        // wallet.  Store the new version of the transaction with the witness,
        // as the stripped-version must be invalid.
        // TODO: Store all versions of the transaction, instead of just one.
        if (wtxIn.tx->HasWitness() && !wtx.tx->HasWitness()) {
            wtx.SetTx(wtxIn.tx);
            fUpdated = true;
        }
    }

    //// debug print
    WalletLogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

    // Write to disk
    if (fInsertedNew || fUpdated)
        if (!batch.WriteTx(wtx))
            return false;

    // Break debit/credit balance caches:
    wtx.MarkDirty();

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = gArgs.GetArg("-walletnotify", "");

    if (!strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
        std::thread t(runCommand, strCmd);
        t.detach(); // thread runs free
    }

    return true;
}

void CWallet::LoadToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    const auto& ins = mapWallet.emplace(hash, wtxIn);
    CWalletTx& wtx = ins.first->second;
    wtx.BindWallet(this);
    if (/* insertion took place */ ins.second) {
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
    }
    AddToSpends(hash);
    for (const CTxIn& txin : wtx.tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            CWalletTx& prevtx = it->second;
            if (prevtx.nIndex == -1 && !prevtx.hashUnset()) {
                MarkConflicted(prevtx.hashBlock, wtx.GetHash());
            }
        }
    }
}

/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const uint256& block_hash, int posInBlock, bool fUpdate)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);

        if (!block_hash.IsNull()) {
            for (const CTxIn& txin : tx.vin) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        WalletLogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), block_hash.ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(block_hash, range.first->second);
                    }
                    range.first++;
                }
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            /* Check if any keys in the wallet keypool that were supposed to be unused
             * have appeared in a new transaction. If so, remove those keys from the keypool.
             * This can happen when restoring an old wallet backup that does not contain
             * the mostly recently created transactions from newer versions of the wallet.
             */

            // loop though all outputs
            for (const CTxOut& txout: tx.vout) {
                // extract addresses and check if they match with an unused keypool key
                for (const auto& keyid : GetAffectedKeys(txout.scriptPubKey, *this)) {
                    std::map<CKeyID, int64_t>::const_iterator mi = m_pool_key_to_index.find(keyid);
                    if (mi != m_pool_key_to_index.end()) {
                        WalletLogPrintf("%s: Detected a used keypool key, mark all keypool key up to this key as used\n", __func__);
                        MarkReserveKeysAsUsed(mi->second);

                        if (!TopUpKeyPool()) {
                            WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
                        }
                    }
                }
            }

            CWalletTx wtx(this, ptx);

            // Get merkle branch if transaction was found in a block
            if (!block_hash.IsNull())
                wtx.SetMerkleBranch(block_hash, posInBlock);

            return AddToWallet(wtx, false);
        }
    }
    return false;
}

bool CWallet::TransactionCanBeAbandoned(const uint256& hashTx) const
{
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && wtx->GetDepthInMainChain(*locked_chain) == 0 && !wtx->InMempool();
}

void CWallet::MarkInputsDirty(const CTransactionRef& tx)
{
    for (const CTxIn& txin : tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            it->second.MarkDirty();
        }
    }
}

bool CWallet::AbandonTransaction(interfaces::Chain::Lock& locked_chain, const uint256& hashTx)
{
    auto locked_chain_recursive = chain().lock();  // Temporary. Removed in upcoming lock cleanup
    LOCK(cs_wallet);

    WalletBatch batch(*database, "r+");

    std::set<uint256> todo;
    std::set<uint256> done;

    // Can't mark abandoned if confirmed or in mempool
    auto it = mapWallet.find(hashTx);
    assert(it != mapWallet.end());
    CWalletTx& origtx = it->second;
    if (origtx.GetDepthInMainChain(locked_chain) != 0 || origtx.InMempool()) {
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;
        int currentconfirm = wtx.GetDepthInMainChain(locked_chain);
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned()) {
            // If the orig tx was not in block/mempool, none of its spends can be in mempool
            assert(!wtx.InMempool());
            wtx.nIndex = -1;
            wtx.setAbandoned();
            wtx.MarkDirty();
            batch.WriteTx(wtx);
            NotifyTransactionChanged(this, wtx.GetHash(), CT_UPDATED);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                if (!done.count(iter->second)) {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            MarkInputsDirty(wtx.tx);
        }
    }

    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, const uint256& hashTx)
{
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);

    int conflictconfirms = -locked_chain->getBlockDepth(hashBlock);
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    WalletBatch batch(*database, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;
        int currentconfirm = wtx.GetDepthInMainChain(*locked_chain);
        if (conflictconfirms < currentconfirm) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            batch.WriteTx(wtx);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                if (!done.count(iter->second)) {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            MarkInputsDirty(wtx.tx);
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef& ptx, const uint256& block_hash, int posInBlock, bool update_tx) {
    if (!AddToWalletIfInvolvingMe(ptx, block_hash, posInBlock, update_tx))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    MarkInputsDirty(ptx);
}

void CWallet::TransactionAddedToMempool(const CTransactionRef& ptx) {
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);
    SyncTransaction(ptx, {} /* block hash */, 0 /* position in block */);

    auto it = mapWallet.find(ptx->GetHash());
    if (it != mapWallet.end()) {
        it->second.fInMempool = true;
    }
}

void CWallet::TransactionRemovedFromMempool(const CTransactionRef &ptx) {
    LOCK(cs_wallet);
    auto it = mapWallet.find(ptx->GetHash());
    if (it != mapWallet.end()) {
        it->second.fInMempool = false;
    }
}

void CWallet::BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex *pindex, const std::vector<CTransactionRef>& vtxConflicted) {
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);
    // TODO: Temporarily ensure that mempool removals are notified before
    // connected transactions.  This shouldn't matter, but the abandoned
    // state of transactions in our wallet is currently cleared when we
    // receive another notification and there is a race condition where
    // notification of a connected conflict might cause an outside process
    // to abandon a transaction and then have it inadvertently cleared by
    // the notification that the conflicted transaction was evicted.

    for (const CTransactionRef& ptx : vtxConflicted) {
        SyncTransaction(ptx, {} /* block hash */, 0 /* position in block */);
        TransactionRemovedFromMempool(ptx);
    }
    for (size_t i = 0; i < pblock->vtx.size(); i++) {
        SyncTransaction(pblock->vtx[i], pindex->GetBlockHash(), i);
        TransactionRemovedFromMempool(pblock->vtx[i]);
    }

    m_last_block_processed = pindex->GetBlockHash();
}

void CWallet::BlockDisconnected(const std::shared_ptr<const CBlock>& pblock) {
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);

    for (const CTransactionRef& ptx : pblock->vtx) {
        SyncTransaction(ptx, {} /* block hash */, 0 /* position in block */);
    }
}



void CWallet::BlockUntilSyncedToCurrentChain() {
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs_wallet);

    {
        // Skip the queue-draining stuff if we know we're caught up with
        // chainActive.Tip()...
        // We could also take cs_wallet here, and call m_last_block_processed
        // protected by cs_wallet instead of cs_main, but as long as we need
        // cs_main here anyway, it's easier to just call it cs_main-protected.
        auto locked_chain = chain().lock();

        if (!m_last_block_processed.IsNull() && locked_chain->isPotentialTip(m_last_block_processed)) {
            return;
        }
    }

    // ...otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).
    SyncWithValidationInterfaceQueue();
}

// TODO: Last copy from here.
isminetype CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                return IsMine(prev.tx->vout[txin.prevout.n]);
        }
    }
    return ISMINE_NO;
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    return ::IsMine(*this, txout.scriptPubKey);
}

CAmount CWallet::GetCredit(const CTxOut& txout, const isminefilter& filter) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    return IsChange(txout.scriptPubKey);
}

bool CWallet::IsChange(const CScript& script) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, script))
    {
        CTxDestination address;
        if (!ExtractDestination(script, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut& txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    for (const CTxOut& txout : tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const
{
    LOCK(cs_wallet);

    for (const CTxIn& txin : tx.vin)
    {
        auto mi = mapWallet.find(txin.prevout.hash);
        if (mi == mapWallet.end())
            return false; // any unknown inputs can't be from us

        const CWalletTx& prev = (*mi).second;

        if (txin.prevout.n >= prev.tx->vout.size())
            return false; // invalid input!

        if (!(IsMine(prev.tx->vout[txin.prevout.n]) & filter))
            return false;
    }
    return true;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction& tx) const
{
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

CPubKey CWallet::GenerateNewSeed()
{
    assert(!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    CKey key;
    key.MakeNewKey(true);
    return DeriveNewSeed(key);
}

CPubKey CWallet::DeriveNewSeed(const CKey& key)
{
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the seed
    CPubKey seed = key.GetPubKey();
    assert(key.VerifyPubKey(seed));

    // set the hd keypath to "s" -> Seed, refers the seed to itself
    metadata.hdKeypath     = "s";
    metadata.has_key_origin = false;
    metadata.hd_seed_id = seed.GetID();

    {
        LOCK(cs_wallet);

        // mem store the metadata
        mapKeyMetadata[seed.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, seed))
            throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");
    }

    return seed;
}

void CWallet::SetHDSeed(const CPubKey& seed)
{
    LOCK(cs_wallet);
    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.nVersion = CanSupportFeature(FEATURE_HD_SPLIT) ? CHDChain::VERSION_HD_CHAIN_SPLIT : CHDChain::VERSION_HD_BASE;
    newHdChain.seed_id = seed.GetID();
    SetHDChain(newHdChain, false);
    NotifyCanGetAddressesChanged();
    UnsetWalletFlag(WALLET_FLAG_BLANK_WALLET);
}

void CWallet::SetHDChain(const CHDChain& chain, bool memonly)
{
    LOCK(cs_wallet);
    if (!memonly && !WalletBatch(*database).WriteHDChain(chain))
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");

    hdChain = chain;
}

bool CWallet::IsHDEnabled() const
{
    return !hdChain.seed_id.IsNull();
}

bool CWallet::CanGenerateKeys()
{
    // A wallet can generate keys if it has an HD seed (IsHDEnabled) or it is a non-HD wallet (pre FEATURE_HD)
    LOCK(cs_wallet);
    return IsHDEnabled() || !CanSupportFeature(FEATURE_HD);
}

bool CWallet::CanGetAddresses(bool internal)
{
    LOCK(cs_wallet);
    // Check if the keypool has keys
    bool keypool_has_keys;
    if (internal && CanSupportFeature(FEATURE_HD_SPLIT)) {
        keypool_has_keys = setInternalKeyPool.size() > 0;
    } else {
        keypool_has_keys = KeypoolCountExternalKeys() > 0;
    }
    // If the keypool doesn't have keys, check if we can generate them
    if (!keypool_has_keys) {
        return CanGenerateKeys();
    }
    return keypool_has_keys;
}

void CWallet::SetWalletFlag(uint64_t flags)
{
    LOCK(cs_wallet);
    m_wallet_flags |= flags;
    if (!WalletBatch(*database).WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetWalletFlag(uint64_t flag)
{
    LOCK(cs_wallet);
    m_wallet_flags &= ~flag;
    if (!WalletBatch(*database).WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

bool CWallet::IsWalletFlagSet(uint64_t flag)
{
    return (m_wallet_flags & flag);
}

bool CWallet::SetWalletFlags(uint64_t overwriteFlags, bool memonly)
{
    LOCK(cs_wallet);
    m_wallet_flags = overwriteFlags;
    if (((overwriteFlags & g_known_wallet_flags) >> 32) ^ (overwriteFlags >> 32)) {
        // contains unknown non-tolerable wallet flags
        return false;
    }
    if (!memonly && !WalletBatch(*database).WriteWalletFlags(m_wallet_flags)) {
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
    }

    return true;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

// Helper for producing a max-sized low-S low-R signature (eg 71 bytes)
// or a max-sized low-S signature (e.g. 72 bytes) if use_max_sig is true
bool CWallet::DummySignInput(CTxIn &tx_in, const CTxOut &txout, bool use_max_sig) const
{
    // Fill in dummy signatures for fee calculation.
    const CScript& scriptPubKey = txout.scriptPubKey;
    SignatureData sigdata;

    if (!ProduceSignature(*this, use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR, scriptPubKey, sigdata)) {
        return false;
    }
    UpdateInput(tx_in, sigdata);
    return true;
}

// Helper for producing a bunch of max-sized low-S low-R signatures (eg 71 bytes)
bool CWallet::DummySignTx(CMutableTransaction &txNew, const std::vector<CTxOut> &txouts, bool use_max_sig) const
{
    // Fill in dummy signatures for fee calculation.
    int nIn = 0;
    for (const auto& txout : txouts)
    {
        if (!DummySignInput(txNew.vin[nIn], txout, use_max_sig)) {
            return false;
        }

        nIn++;
    }
    return true;
}

int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CWallet *wallet, bool use_max_sig)
{
    std::vector<CTxOut> txouts;
    // Look up the inputs.  We should have already checked that this transaction
    // IsAllFromMe(ISMINE_SPENDABLE), so every input should already be in our
    // wallet, with a valid index into the vout array, and the ability to sign.
    for (const CTxIn& input : tx.vin) {
        const auto mi = wallet->mapWallet.find(input.prevout.hash);
        if (mi == wallet->mapWallet.end()) {
            return -1;
        }
        assert(input.prevout.n < mi->second.tx->vout.size());
        txouts.emplace_back(mi->second.tx->vout[input.prevout.n]);
    }
    return CalculateMaximumSignedTxSize(tx, wallet, txouts, use_max_sig);
}

// txouts needs to be in the order of tx.vin
int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CWallet *wallet, const std::vector<CTxOut>& txouts, bool use_max_sig)
{
    CMutableTransaction txNew(tx);
    if (!wallet->DummySignTx(txNew, txouts, use_max_sig)) {
        // This should never happen, because IsAllFromMe(ISMINE_SPENDABLE)
        // implies that we can sign for every input.
        return -1;
    }
    return GetVirtualTransactionSize(CTransaction(txNew));
}

int CalculateMaximumSignedInputSize(const CTxOut& txout, const CWallet* wallet, bool use_max_sig)
{
    CMutableTransaction txn;
    txn.vin.push_back(CTxIn(COutPoint()));
    if (!wallet->DummySignInput(txn.vin[0], txout, use_max_sig)) {
        return -1;
    }
    return GetVirtualTransactionInputSize(txn.vin[0]);
}

void CWalletTx::GetAmounts(std::list<COutputEntry>& listReceived,
                           std::list<COutputEntry>& listSent, CAmount& nFee, const isminefilter& filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = tx->GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < tx->vout.size(); ++i)
    {
        const CTxOut& txout = tx->vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter) && !IsZerocoinSpend())
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (txout.scriptPubKey.IsZerocoinMint()) {
            address = CNoDestination();
        } else if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            pwallet->WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                                     this->GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

/**
 * Scan active chain for relevant transactions after importing keys. This should
 * be called whenever new keys are added to the wallet, with the oldest key
 * creation time.
 *
 * @return Earliest timestamp that could be successfully scanned from. Timestamp
 * returned will be higher than startTime if relevant blocks could not be read.
 */
int64_t CWallet::RescanFromTime(int64_t startTime, const WalletRescanReserver& reserver, bool update)
{
    // Find starting block. May be null if nCreateTime is greater than the
    // highest blockchain timestamp, in which case there is nothing that needs
    // to be scanned.
    uint256 start_block;
    {
        auto locked_chain = chain().lock();
        const Optional<int> start_height = locked_chain->findFirstBlockWithTime(startTime - TIMESTAMP_WINDOW, &start_block);
        const Optional<int> tip_height = locked_chain->getHeight();
        WalletLogPrintf("%s: Rescanning last %i blocks\n", __func__, tip_height && start_height ? *tip_height - *start_height + 1 : 0);
    }

    if (!start_block.IsNull()) {
        // TODO: this should take into account failure by ScanResult::USER_ABORT
        ScanResult result = ScanForWalletTransactions(start_block, {} /* stop_block */, reserver, update);
        if (result.status == ScanResult::FAILURE) {
            int64_t time_max;
            if (!chain().findBlock(result.last_failed_block, nullptr /* block */, nullptr /* time */, &time_max)) {
                throw std::logic_error("ScanForWalletTransactions returned invalid block hash");
            }
            return time_max + TIMESTAMP_WINDOW + 1;
        }
    }
    return startTime;
}

/**
 * Scan the block chain (starting in start_block) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 *
 * @param[in] start_block Scan starting block. If block is not on the active
 *                        chain, the scan will return SUCCESS immediately.
 * @param[in] stop_block  Scan ending block. If block is not on the active
 *                        chain, the scan will continue until it reaches the
 *                        chain tip.
 *
 * @return ScanResult returning scan information and indicating success or
 *         failure. Return status will be set to SUCCESS if scan was
 *         successful. FAILURE if a complete rescan was not possible (due to
 *         pruning or corruption). USER_ABORT if the rescan was aborted before
 *         it could complete.
 *
 * @pre Caller needs to make sure start_block (and the optional stop_block) are on
 * the main chain after to the addition of any new keys you want to detect
 * transactions for.
 */
CWallet::ScanResult CWallet::ScanForWalletTransactions(const uint256& start_block, const uint256& stop_block, const WalletRescanReserver& reserver, bool fUpdate)
{
    int64_t nNow = GetTime();
    bool fCheckZWSP = gArgs.GetBoolArg("-zapwallettxes", false);
    if (fCheckZWSP)
        zwspTracker->Init();
    assert(reserver.isReserved());

    uint256 block_hash = start_block;
    ScanResult result;

    WalletLogPrintf("Rescan started from block %s...\n", start_block.ToString());

    {
        fAbortRescan = false;
        ShowProgress(strprintf("%s " + _("Rescanning..."), GetDisplayName()), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        uint256 tip_hash;
        // The way the 'block_height' is initialized is just a workaround for the gcc bug #47679 since version 4.6.0.
        Optional<int> block_height = MakeOptional(false, int());
        double progress_begin;
        double progress_end;
        {
            auto locked_chain = chain().lock();
            if (Optional<int> tip_height = locked_chain->getHeight()) {
                tip_hash = locked_chain->getBlockHash(*tip_height);
            }
            block_height = locked_chain->getBlockHeight(block_hash);
            progress_begin = chain().guessVerificationProgress(block_hash);
            progress_end = chain().guessVerificationProgress(stop_block.IsNull() ? tip_hash : stop_block);
        }
        double progress_current = progress_begin;
        set<uint256> setAddedToWallet;
        while (block_height && !fAbortRescan && !ShutdownRequested()) {
            if (*block_height % 100 == 0 && progress_end - progress_begin > 0.0) {
                ShowProgress(strprintf("%s " + _("Rescanning..."), GetDisplayName()), std::max(1, std::min(99, (int)((progress_current - progress_begin) / (progress_end - progress_begin) * 100))));
            }
            if (GetTime() >= nNow + 60) {
                nNow = GetTime();
                WalletLogPrintf("Still rescanning. At block %d. Progress=%f\n", *block_height, progress_current);
            }

            CBlock block;
            if (chain().findBlock(block_hash, &block) && !block.IsNull()) {
                auto locked_chain = chain().lock();
                LOCK(cs_wallet);
                if (!locked_chain->getBlockHeight(block_hash)) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    // TODO: This should return success instead of failure, see
                    // https://github.com/bitcoin/bitcoin/pull/14711#issuecomment-458342518
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    SyncTransaction(block.vtx[posInBlock], block_hash, posInBlock, fUpdate);
                }
                // scan succeeded, record block as most recent successfully scanned
                result.last_scanned_block = block_hash;
                result.last_scanned_height = *block_height;

                //If this is a zapwallettx, need to readd zwsp
                if (fCheckZWSP && block_height >= Params().NEW_PROTOCOLS_STARTHEIGHT()) {
                    std::list<CZerocoinMint> listMints;
                    BlockToZerocoinMintList(block, listMints, true);

                    for (auto& m : listMints) {
                        if (IsMyMint(m.GetValue())) {
                            LogPrint(BCLog::ZERO, "%s: found mint\n", __func__);
                            pwalletMain->UpdateMint(m.GetValue(), block_height.get(), m.GetTxHash(), m.GetDenomination());

                            // Add the transaction to the wallet
                            size_t posInBlock = 0;
                            for (;posInBlock < block.vtx.size(); ++posInBlock) {
                                CTransactionRef tx = block.vtx[posInBlock];
                                uint256 txid = tx->GetHash();
                                if (setAddedToWallet.count(txid) || mapWallet.count(txid))
                                    continue;
                                if (txid == m.GetTxHash()) {
                                    CWalletTx wtx(pwalletMain, tx);
                                    wtx.nTimeReceived = block.GetBlockTime();
                                    wtx.SetMerkleBranch(block_hash, posInBlock);
                                    pwalletMain->AddToWallet(wtx);
                                    setAddedToWallet.insert(txid);
                                }
                            }

                            //Check if the mint was ever spent
                            int nHeightSpend = 0;
                            uint256 txidSpend;
                            CTransaction txSpend;
                            if (IsSerialInBlockchain(GetSerialHash(m.GetSerialNumber()), nHeightSpend, txidSpend, txSpend)) {
                                if (setAddedToWallet.count(txidSpend) || mapWallet.count(txidSpend))
                                    continue;

                                CWalletTx wtx(pwalletMain, txSpend);
                                CBlockIndex* pindexSpend = chainActive[nHeightSpend];
                                CBlock blockSpend;
                                if (ReadBlockFromDisk(blockSpend, pindexSpend))
                                    wtx.SetMerkleBranch(block_hash, posInBlock);

                                wtx.nTimeReceived = pindexSpend->nTime;
                                pwalletMain->AddToWallet(wtx);
                                setAddedToWallet.emplace(txidSpend);
                            }
                        }
                    }
                }
            } else {
                // could not scan block, keep scanning but record this block as the most recent failure
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
            }
            if (block_hash == stop_block) {
                break;
            }
            {
                auto locked_chain = chain().lock();
                Optional<int> tip_height = locked_chain->getHeight();
                if (!tip_height || *tip_height <= block_height || !locked_chain->getBlockHeight(block_hash)) {
                    // break successfully when rescan has reached the tip, or
                    // previous block is no longer on the chain due to a reorg
                    break;
                }

                // increment block and verification progress
                block_hash = locked_chain->getBlockHash(++*block_height);
                progress_current = chain().guessVerificationProgress(block_hash);

                // handle updated tip hash
                const uint256 prev_tip_hash = tip_hash;
                tip_hash = locked_chain->getBlockHash(*tip_height);
                if (stop_block.IsNull() && prev_tip_hash != tip_hash) {
                    // in case the tip has changed, update progress max
                    progress_end = chain().guessVerificationProgress(tip_hash);
                }
            }
        }
        ShowProgress(strprintf("%s " + _("Rescanning..."), GetDisplayName()), 100); // hide progress dialog in GUI
        if (block_height && fAbortRescan) {
            WalletLogPrintf("Rescan aborted at block %d. Progress=%f\n", *block_height, progress_current);
            result.status = ScanResult::USER_ABORT;
        } else if (block_height && ShutdownRequested()) {
            WalletLogPrintf("Rescan interrupted by shutdown request at block %d. Progress=%f\n", *block_height, progress_current);
            result.status = ScanResult::USER_ABORT;
        }
    }
    return result;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);
    std::map<int64_t, CWalletTx*> mapSorted;

    // Sort pending wallet transactions based on their initial wallet insertion order
    for (std::pair<const uint256, CWalletTx>& item : mapWallet)
    {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain(*locked_chain);

        if (!wtx.IsCoinBase() && !wtx.tx->IsCoinStake() && (nDepth == 0 && !wtx.isAbandoned())) {
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
        }
    }

    // Try to add wallet transactions to memory pool
    for (const std::pair<const int64_t, CWalletTx*>& item : mapSorted) {
        CWalletTx& wtx = *(item.second);
        CValidationState state;
        wtx.AcceptToMemoryPool(*locked_chain, state);
    }
}

bool CWalletTx::RelayWalletTransaction(interfaces::Chain::Lock& locked_chain, std::string strCommand)
{
    // TODO: Check function calls.
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase() && !isAbandoned() && GetDepthInMainChain(locked_chain) == 0)
    {
        CValidationState state;
        /* GetDepthInMainChain already catches known conflicts. */
        if (InMempool() || AcceptToMemoryPool(locked_chain, state)) {
            pwallet->WalletLogPrintf("Relaying wtx %s\n", GetHash().ToString());
            if (strCommand == NetMsgType::TXLOCKREQUEST) {
                mapTxLockReq.insert(std::make_pair(GetHash(), (CTransaction) * tx));
                CreateNewLock(((CTransaction) * tx));
                RelayTransactionLockReq((CTransaction) * tx,  g_connman.get(), true);
            } else {
                RelayTransaction((CTransaction) * tx, g_connman.get());
            }
            if (pwallet->chain().p2pEnabled()) {
                pwallet->chain().relayTransaction(GetHash());
                return true;
            }
        }
    }
    return false;
}

std::set<uint256> CWalletTx::GetConflicts() const
{
    std::set<uint256> result;
    if (pwallet != nullptr)
    {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (tx->vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*tx, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*tx, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(interfaces::Chain::Lock& locked_chain, const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsImmatureCoinBase(locked_chain))
        return 0;

    CAmount credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(interfaces::Chain::Lock& locked_chain, bool fUseCache) const
{
    if ((IsImmatureCoinBase(locked_chain) || tx->IsCoinStake()) && GetBlocksToMaturity(locked_chain) > 0 && IsInMainChain(locked_chain)) {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(interfaces::Chain::Lock& locked_chain, bool fUseCache, const isminefilter& filter) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsImmatureCoinBase(locked_chain))
        return 0;

    CAmount* cache = nullptr;
    bool* cache_used = nullptr;

    if (filter == ISMINE_SPENDABLE) {
        cache = &nAvailableCreditCached;
        cache_used = &fAvailableCreditCached;
    } else if (filter == ISMINE_WATCH_ONLY) {
        cache = &nAvailableWatchCreditCached;
        cache_used = &fAvailableWatchCreditCached;
    }

    if (fUseCache && cache_used && *cache_used) {
        return *cache;
    }

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(locked_chain, hashTx, i))
        {
            const CTxOut &txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, filter);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + " : value out of range");
        }
    }

    if (cache) {
        *cache = nCredit;
        assert(cache_used);
        *cache_used = true;
    }
    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(interfaces::Chain::Lock& locked_chain, const bool fUseCache) const
{
    if (IsImmatureCoinBase(locked_chain) && IsInMainChain(locked_chain)) {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*tx);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const
{
    return fInMempool;
}

bool CWalletTx::IsTrusted(interfaces::Chain::Lock& locked_chain) const
{
    // Quick answer in most cases
    if (!locked_chain.checkFinalTx(*tx)) {
        return false;
    }
    int nDepth = GetDepthInMainChain(locked_chain);
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!pwallet->m_spend_zero_conf_change || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!InMempool())
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : tx->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == nullptr)
            return false;
        const CTxOut& parentOut = parent->tx->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

bool CWalletTx::IsEquivalentTo(const CWalletTx& _tx) const
{
    CMutableTransaction tx1 {*this->tx};
    CMutableTransaction tx2 {*_tx.tx};
    for (auto& txin : tx1.vin) txin.scriptSig = CScript();
    for (auto& txin : tx2.vin) txin.scriptSig = CScript();
    return CTransaction(tx1) == CTransaction(tx2);
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(interfaces::Chain::Lock& locked_chain, int64_t nTime)
{
    std::vector<uint256> result;

    LOCK(cs_wallet);

    // Sort them in chronological order
    std::multimap<unsigned int, CWalletTx*> mapSorted;
    for (std::pair<const uint256, CWalletTx>& item : mapWallet)
    {
        CWalletTx& wtx = item.second;
        // Don't rebroadcast if newer than nTime:
        if (wtx.nTimeReceived > nTime)
            continue;
        mapSorted.insert(std::make_pair(wtx.nTimeReceived, &wtx));
    }
    for (const std::pair<const unsigned int, CWalletTx*>& item : mapSorted)
    {
        CWalletTx& wtx = *item.second;
        if (wtx.RelayWalletTransaction(locked_chain)) {
            result.push_back(wtx.GetHash());
        }
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    auto locked_chain = chain().assumeLocked();  // Temporary. Removed in upcoming lock cleanup
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(*locked_chain, nBestBlockTime-5*60);
    if (!relayed.empty())
        WalletLogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance(const isminefilter& filter, const int min_depth) const
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (pcoin->IsTrusted(*locked_chain) && pcoin->GetDepthInMainChain(*locked_chain) >= min_depth) {
                nTotal += pcoin->GetAvailableCredit(*locked_chain, true, filter);
            }
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (!pcoin->IsTrusted(*locked_chain) && pcoin->GetDepthInMainChain(*locked_chain) == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableCredit(*locked_chain);
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            nTotal += pcoin->GetImmatureCredit(*locked_chain);
        }
    }
    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (!pcoin->IsTrusted(*locked_chain) && pcoin->GetDepthInMainChain(*locked_chain) == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableCredit(*locked_chain, true, ISMINE_WATCH_ONLY);
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit(*locked_chain);
        }
    }
    return nTotal;
}

// Calculate total balance in a different way from GetBalance. The biggest
// difference is that GetBalance sums up all unspent TxOuts paying to the
// wallet, while this sums up both spent and unspent TxOuts paying to the
// wallet, and then subtracts the values of TxIns spending from the wallet. This
// also has fewer restrictions on which unconfirmed transactions are considered
// trusted.
CAmount CWallet::GetLegacyBalance(const isminefilter& filter, int minDepth) const
{
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);

    CAmount balance = 0;
    for (const auto& entry : mapWallet) {
        const CWalletTx& wtx = entry.second;
        const int depth = wtx.GetDepthInMainChain(*locked_chain);
        if (depth < 0 || !locked_chain->checkFinalTx(*wtx.tx) || wtx.IsImmatureCoinBase(*locked_chain)) {
            continue;
        }

        // Loop through tx outputs and add incoming payments. For outgoing txs,
        // treat change outputs specially, as part of the amount debited.
        CAmount debit = wtx.GetDebit(filter);
        const bool outgoing = debit > 0;
        for (const CTxOut& out : wtx.tx->vout) {
            if (outgoing && IsChange(out)) {
                debit -= out.nValue;
            } else if (IsMine(out) & filter && depth >= minDepth) {
                balance += out.nValue;
            }
        }

        // For outgoing txs, subtract amount debited.
        if (outgoing) {
            balance -= debit;
        }
    }

    return balance;
}

CAmount CWallet::GetAvailableBalance(const CCoinControl* coinControl) const
{
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);

    CAmount balance = 0;
    std::vector<COutput> vCoins;
    AvailableCoins(*locked_chain, vCoins, true, coinControl);
    for (const COutput& out : vCoins) {
        if (out.fSpendable) {
            balance += out.tx->tx->vout[out.i].nValue;
        }
    }
    return balance;
}

void CWallet::AvailableCoins(interfaces::Chain::Lock& locked_chain, std::vector<COutput> &vCoins, bool fOnlySafe, const CCoinControl *coinControl, const CAmount &nMinimumAmount, const CAmount &nMaximumAmount, const CAmount &nMinimumSumAmount, const uint64_t nMaximumCount, const int nMinDepth, const int nMaxDepth) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    vCoins.clear();
    CAmount nTotal = 0;

    for (const auto& entry : mapWallet)
    {
        const uint256& wtxid = entry.first;
        const CWalletTx* pcoin = &entry.second;

        if (!locked_chain.checkFinalTx(*pcoin->tx)) {
            continue;
        }

        if (pcoin->IsImmatureCoinBase(locked_chain))
            continue;

        int nDepth = pcoin->GetDepthInMainChain(locked_chain);
        if (nDepth < 0)
            continue;

        // We should not consider coins which aren't at least in our mempool
        // It's possible for these to be conflicted via ancestors which we may never be able to detect
        if (nDepth == 0 && !pcoin->InMempool())
            continue;

        bool safeTx = pcoin->IsTrusted(locked_chain);

        // We should not consider coins from transactions that are replacing
        // other transactions.
        //
        // Example: There is a transaction A which is replaced by bumpfee
        // transaction B. In this case, we want to prevent creation of
        // a transaction B' which spends an output of B.
        //
        // Reason: If transaction A were initially confirmed, transactions B
        // and B' would no longer be valid, so the user would have to create
        // a new transaction C to replace B'. However, in the case of a
        // one-block reorg, transactions B' and C might BOTH be accepted,
        // when the user only wanted one of them. Specifically, there could
        // be a 1-block reorg away from the chain where transactions A and C
        // were accepted to another chain where B, B', and C were all
        // accepted.
        if (nDepth == 0 && pcoin->mapValue.count("replaces_txid")) {
            safeTx = false;
        }

        // Similarly, we should not consider coins from transactions that
        // have been replaced. In the example above, we would want to prevent
        // creation of a transaction A' spending an output of A, because if
        // transaction B were initially confirmed, conflicting with A and
        // A', we wouldn't want to the user to create a transaction D
        // intending to replace A', but potentially resulting in a scenario
        // where A, A', and D could all be accepted (instead of just B and
        // D, or just A and A' like the user would want).
        if (nDepth == 0 && pcoin->mapValue.count("replaced_by_txid")) {
            safeTx = false;
        }

        if (fOnlySafe && !safeTx) {
            continue;
        }

        if (nDepth < nMinDepth || nDepth > nMaxDepth)
            continue;

        for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
            if (pcoin->tx->vout[i].nValue < nMinimumAmount || pcoin->tx->vout[i].nValue > nMaximumAmount)
                continue;

            if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(entry.first, i)))
                continue;

            if (IsLockedCoin(entry.first, i))
                continue;

            if (IsSpent(locked_chain, wtxid, i))
                continue;

            isminetype mine = IsMine(pcoin->tx->vout[i]);

            if (mine == ISMINE_NO) {
                continue;
            }

            bool solvable = IsSolvable(*this, pcoin->tx->vout[i].scriptPubKey);
            bool spendable = ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (((mine & ISMINE_WATCH_ONLY) != ISMINE_NO) && (coinControl && coinControl->fAllowWatchOnly && solvable));

            vCoins.push_back(COutput(pcoin, i, nDepth, spendable, solvable, safeTx, (coinControl && coinControl->fAllowWatchOnly)));

            // Checks the sum amount of all UTXO's.
            if (nMinimumSumAmount != MAX_MONEY) {
                nTotal += pcoin->tx->vout[i].nValue;

                if (nTotal >= nMinimumSumAmount) {
                    return;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                return;
            }
        }
    }
}

std::map<CTxDestination, std::vector<COutput>> CWallet::ListCoins(interfaces::Chain::Lock& locked_chain) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    std::map<CTxDestination, std::vector<COutput>> result;
    std::vector<COutput> availableCoins;

    AvailableCoins(locked_chain, availableCoins);

    for (const COutput& coin : availableCoins) {
        CTxDestination address;
        if (coin.fSpendable &&
            ExtractDestination(FindNonChangeParentOutput(*coin.tx->tx, coin.i).scriptPubKey, address)) {
            result[address].emplace_back(std::move(coin));
        }
    }

    std::vector<COutPoint> lockedCoins;
    ListLockedCoins(lockedCoins);
    for (const COutPoint& output : lockedCoins) {
        auto it = mapWallet.find(output.hash);
        if (it != mapWallet.end()) {
            int depth = it->second.GetDepthInMainChain(locked_chain);
            if (depth >= 0 && output.n < it->second.tx->vout.size() &&
                IsMine(it->second.tx->vout[output.n]) == ISMINE_SPENDABLE) {
                CTxDestination address;
                if (ExtractDestination(FindNonChangeParentOutput(*it->second.tx, output.n).scriptPubKey, address)) {
                    result[address].emplace_back(
                            &it->second, output.n, depth, true /* spendable */, true /* solvable */, false /* safe */);
                }
            }
        }
    }

    return result;
}

const CTxOut& CWallet::FindNonChangeParentOutput(const CTransaction& tx, int output) const
{
    const CTransaction* ptx = &tx;
    int n = output;
    while (IsChange(ptx->vout[n]) && ptx->vin.size() > 0) {
        const COutPoint& prevout = ptx->vin[0].prevout;
        auto it = mapWallet.find(prevout.hash);
        if (it == mapWallet.end() || it->second.tx->vout.size() <= prevout.n ||
            !IsMine(it->second.tx->vout[prevout.n])) {
            break;
        }
        ptx = it->second.tx.get();
        n = prevout.n;
    }
    return ptx->vout[n];
}

bool CWallet::SelectCoinsMinConf(const CAmount& nTargetValue, const CoinEligibilityFilter& eligibility_filter, std::vector<OutputGroup> groups,
                                 std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet, const CoinSelectionParams& coin_selection_params, bool& bnb_used) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    std::vector<OutputGroup> utxo_pool;
    if (coin_selection_params.use_bnb) {
        // Get long term estimate
        FeeCalculation feeCalc;
        CCoinControl temp;
        temp.m_confirm_target = 1008;
        CFeeRate long_term_feerate = GetMinimumFeeRate(*this, temp, &feeCalc);

        // Calculate cost of change
        CAmount cost_of_change = GetDiscardRate(*this).GetFee(coin_selection_params.change_spend_size) + coin_selection_params.effective_fee.GetFee(coin_selection_params.change_output_size);

        // Filter by the min conf specs and add to utxo_pool and calculate effective value
        for (OutputGroup& group : groups) {
            if (!group.EligibleForSpending(eligibility_filter)) continue;

            group.fee = 0;
            group.long_term_fee = 0;
            group.effective_value = 0;
            for (auto it = group.m_outputs.begin(); it != group.m_outputs.end(); ) {
                const CInputCoin& coin = *it;
                CAmount effective_value = coin.txout.nValue - (coin.m_input_bytes < 0 ? 0 : coin_selection_params.effective_fee.GetFee(coin.m_input_bytes));
                // Only include outputs that are positive effective value (i.e. not dust)
                if (effective_value > 0) {
                    group.fee += coin.m_input_bytes < 0 ? 0 : coin_selection_params.effective_fee.GetFee(coin.m_input_bytes);
                    group.long_term_fee += coin.m_input_bytes < 0 ? 0 : long_term_feerate.GetFee(coin.m_input_bytes);
                    group.effective_value += effective_value;
                    ++it;
                } else {
                    it = group.Discard(coin);
                }
            }
            if (group.effective_value > 0) utxo_pool.push_back(group);
        }
        // Calculate the fees for things that aren't inputs
        CAmount not_input_fees = coin_selection_params.effective_fee.GetFee(coin_selection_params.tx_noinputs_size);
        bnb_used = true;
        return SelectCoinsBnB(utxo_pool, nTargetValue, cost_of_change, setCoinsRet, nValueRet, not_input_fees);
    } else {
        // Filter by the min conf specs and add to utxo_pool
        for (const OutputGroup& group : groups) {
            if (!group.EligibleForSpending(eligibility_filter)) continue;
            utxo_pool.push_back(group);
        }
        bnb_used = false;
        return KnapsackSolver(nTargetValue, utxo_pool, setCoinsRet, nValueRet);
    }
}

bool CWallet::SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet, const CCoinControl& coin_control, CoinSelectionParams& coin_selection_params, bool& bnb_used) const
{
    std::vector<COutput> vCoins(vAvailableCoins);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coin_control.HasSelected() && !coin_control.fAllowOtherInputs)
    {
        // We didn't use BnB here, so set it to false.
        bnb_used = false;

        for (const COutput& out : vCoins)
        {
            if (!out.fSpendable)
                continue;
            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.insert(out.GetInputCoin());
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    std::set<CInputCoin> setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    coin_control.ListSelected(vPresetInputs);
    for (const COutPoint& outpoint : vPresetInputs)
    {
        // For now, don't use BnB if preset inputs are selected. TODO: Enable this later
        bnb_used = false;
        coin_selection_params.use_bnb = false;

        std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->tx->vout.size() <= outpoint.n)
                return false;
            // Just to calculate the marginal byte size
            nValueFromPresetInputs += pcoin->tx->vout[outpoint.n].nValue;
            setPresetCoins.insert(CInputCoin(pcoin->tx, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (std::vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coin_control.HasSelected();)
    {
        if (setPresetCoins.count(it->GetInputCoin()))
            it = vCoins.erase(it);
        else
            ++it;
    }

    // form groups from remaining coins; note that preset coins will not
    // automatically have their associated (same address) coins included
    if (coin_control.m_avoid_partial_spends && vCoins.size() > OUTPUT_GROUP_MAX_ENTRIES) {
        // Cases where we have 11+ outputs all pointing to the same destination may result in
        // privacy leaks as they will potentially be deterministically sorted. We solve that by
        // explicitly shuffling the outputs before processing
        Shuffle(vCoins.begin(), vCoins.end(), FastRandomContext());
    }
    std::vector<OutputGroup> groups = GroupOutputs(vCoins, !coin_control.m_avoid_partial_spends);

    size_t max_ancestors = (size_t)std::max<int64_t>(1, gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT));
    size_t max_descendants = (size_t)std::max<int64_t>(1, gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT));
    bool fRejectLongChains = gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    bool res = nTargetValue <= nValueFromPresetInputs ||
               SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(1, 6, 0), groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used) ||
               SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(1, 1, 0), groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used) ||
               (m_spend_zero_conf_change && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, 2), groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used)) ||
               (m_spend_zero_conf_change && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, std::min((size_t)4, max_ancestors/3), std::min((size_t)4, max_descendants/3)), groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used)) ||
               (m_spend_zero_conf_change && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, max_ancestors/2, max_descendants/2), groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used)) ||
               (m_spend_zero_conf_change && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, max_ancestors-1, max_descendants-1), groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used)) ||
               (m_spend_zero_conf_change && !fRejectLongChains && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, CoinEligibilityFilter(0, 1, std::numeric_limits<uint64_t>::max()), groups, setCoinsRet, nValueRet, coin_selection_params, bnb_used));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    util::insert(setCoinsRet, setPresetCoins);

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CWallet::SignTransaction(CMutableTransaction &tx)
{
    AssertLockHeld(cs_wallet); // mapWallet

    // sign the new tx
    int nIn = 0;
    for (auto& input : tx.vin) {
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(input.prevout.hash);
        if(mi == mapWallet.end() || input.prevout.n >= mi->second.tx->vout.size()) {
            return false;
        }
        const CScript& scriptPubKey = mi->second.tx->vout[input.prevout.n].scriptPubKey;
        const CAmount& amount = mi->second.tx->vout[input.prevout.n].nValue;
        SignatureData sigdata;
        if (!ProduceSignature(*this, MutableTransactionSignatureCreator(&tx, nIn, amount, SIGHASH_ALL), scriptPubKey, sigdata)) {
            return false;
        }
        UpdateInput(input, sigdata);
        nIn++;
    }
    return true;
}

bool CWallet::FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosInOut, std::string& strFailReason, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, CCoinControl coinControl)
{
    std::vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector.
    for (size_t idx = 0; idx < tx.vout.size(); idx++) {
        const CTxOut& txOut = tx.vout[idx];
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, setSubtractFeeFromOutputs.count(idx) == 1};
        vecSend.push_back(recipient);
    }

    coinControl.fAllowOtherInputs = true;

    for (const CTxIn& txin : tx.vin) {
        coinControl.Select(txin.prevout);
    }

    // Acquire the locks to prevent races to the new locked unspents between the
    // CreateTransaction call and LockCoin calls (when lockUnspents is true).
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);

    CReserveKey reservekey(this);
    CTransactionRef tx_new;
    if (!CreateTransaction(*locked_chain, vecSend, tx_new, reservekey, nFeeRet, nChangePosInOut, strFailReason, coinControl, false)) {
        return false;
    }

    if (nChangePosInOut != -1) {
        tx.vout.insert(tx.vout.begin() + nChangePosInOut, tx_new->vout[nChangePosInOut]);
        // We don't have the normal Create/Commit cycle, and don't want to risk
        // reusing change, so just remove the key from the keypool here.
        reservekey.KeepKey();
    }

    // Copy output sizes from new transaction; they may have had the fee
    // subtracted from them.
    for (unsigned int idx = 0; idx < tx.vout.size(); idx++) {
        tx.vout[idx].nValue = tx_new->vout[idx].nValue;
    }

    // Add new txins while keeping original txin scriptSig/order.
    for (const CTxIn& txin : tx_new->vin) {
        if (!coinControl.IsSelected(txin.prevout)) {
            tx.vin.push_back(txin);

            if (lockUnspents) {
                LockCoin(txin.prevout);
            }
        }
    }

    return true;
}

static bool IsCurrentForAntiFeeSniping(interfaces::Chain::Lock& locked_chain)
{
    if (IsInitialBlockDownload()) {
        return false;
    }
    constexpr int64_t MAX_ANTI_FEE_SNIPING_TIP_AGE = 8 * 60 * 60; // in seconds
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - MAX_ANTI_FEE_SNIPING_TIP_AGE)) {
        return false;
    }
    return true;
}

/**
 * Return a height-based locktime for new transactions (uses the height of the
 * current chain tip unless we are not synced with the current chain
 */
static uint32_t GetLocktimeForNewTransaction(interfaces::Chain::Lock& locked_chain)
{
    uint32_t const height = locked_chain.getHeight().get_value_or(-1);
    uint32_t locktime;
    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    if (IsCurrentForAntiFeeSniping(locked_chain)) {
        locktime = height;

        // Secondly occasionally randomly pick a nLockTime even further back, so
        // that transactions that are delayed after signing for whatever reason,
        // e.g. high-latency mix networks and some CoinJoin implementations, have
        // better privacy.
        if (GetRandInt(10) == 0)
            locktime = std::max(0, (int)locktime - GetRandInt(100));
    } else {
        // If our chain is lagging behind, we can't discourage fee sniping nor help
        // the privacy of high-latency transactions. To avoid leaking a potentially
        // unique "nLockTime fingerprint", set nLockTime to a constant.
        locktime = 0;
    }
    assert(locktime <= height);
    assert(locktime < LOCKTIME_THRESHOLD);
    return locktime;
}

OutputType CWallet::TransactionChangeType(OutputType change_type, const std::vector<CRecipient>& vecSend)
{
    // If -changetype is specified, always use that change type.
    if (change_type != OutputType::CHANGE_AUTO) {
        return change_type;
    }

    // if m_default_address_type is legacy, use legacy address as change (even
    // if some of the outputs are P2WPKH or P2WSH).
    if (m_default_address_type == OutputType::LEGACY) {
        return OutputType::LEGACY;
    }

    // if any destination is P2WPKH or P2WSH, use P2WPKH for the change
    // output.
    for (const auto& recipient : vecSend) {
        // Check if any destination contains a witness program:
        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;
        if (recipient.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            return OutputType::BECH32;
        }
    }

    // else use m_default_address_type for change
    return m_default_address_type;
}

bool CWallet::CreateTransaction(interfaces::Chain::Lock& locked_chain, const std::vector<CRecipient>& vecSend, CTransactionRef& tx, CReserveKey& reservekey, CAmount& nFeeRet,
                                int& nChangePosInOut, std::string& strFailReason, const CCoinControl& coin_control, bool sign)
{
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    for (const auto& recipient : vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must not be negative");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty())
    {
        strFailReason = _("Transaction must have at least one recipient");
        return false;
    }

    CMutableTransaction txNew;

    txNew.nLockTime = GetLocktimeForNewTransaction(locked_chain);

    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    int nBytes;
    {
        std::set<CInputCoin> setCoins;
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);
        {
            std::vector<COutput> vAvailableCoins;
            AvailableCoins(*locked_chain, vAvailableCoins, true, &coin_control);
            CoinSelectionParams coin_selection_params; // Parameters for coin selection, init with dummy

            // Create change script that will be used if we need change
            // TODO: pass in scriptChange instead of reservekey so
            // change transaction isn't always pay-to-bitcoin-address
            CScript scriptChange;

            // coin control: send change to custom address
            if (!boost::get<CNoDestination>(&coin_control.destChange)) {
                scriptChange = GetScriptForDestination(coin_control.destChange);
            } else { // no coin control: send change to newly generated address
                // Note: We use a new key here to keep it from being obvious which side is the change.
                //  The drawback is that by not reusing a previous key, the change may be lost if a
                //  backup is restored, if the backup doesn't have the new private key for the change.
                //  If we reused the old key, it would be possible to add code to look for and
                //  rediscover unknown transactions that were written with keys of ours to recover
                //  post-backup change.

                // Reserve a new key pair from key pool
                if (!CanGetAddresses(true)) {
                    strFailReason = _("Can't generate a change-address key. No keys in the internal keypool and can't generate any keys.");
                    return false;
                }
                CPubKey vchPubKey;
                bool ret;
                ret = reservekey.GetReservedKey(vchPubKey, true);
                if (!ret)
                {
                    strFailReason = _("Keypool ran out, please call keypoolrefill first");
                    return false;
                }

                const OutputType change_type = TransactionChangeType(coin_control.m_change_type ? *coin_control.m_change_type : m_default_change_type, vecSend);

                LearnRelatedScripts(vchPubKey, change_type);
                scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
            }
            CTxOut change_prototype_txout(0, scriptChange);
            coin_selection_params.change_output_size = GetSerializeSize(change_prototype_txout);

            CFeeRate discard_rate = GetDiscardRate(*this);

            // Get the fee rate to use effective values in coin selection
            CFeeRate nFeeRateNeeded = GetMinimumFeeRate(*this, coin_control, &feeCalc);

            nFeeRet = 0;
            bool pick_new_inputs = true;
            CAmount nValueIn = 0;

            // BnB selector is the only selector used when this is true.
            // That should only happen on the first pass through the loop.
            coin_selection_params.use_bnb = nSubtractFeeFromAmount == 0; // If we are doing subtract fee from recipient, then don't use BnB
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;

                // vouts to the payees
                coin_selection_params.tx_noinputs_size = 11; // Static vsize overhead + outputs vsize. 4 nVersion, 4 nLocktime, 1 input count, 1 output count, 1 witness overhead (dummy, flag, stack size)
                for (const auto& recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        assert(nSubtractFeeFromAmount != 0);
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }
                    // Include the fee cost for outputs. Note this is only used for BnB right now
                    coin_selection_params.tx_noinputs_size += ::GetSerializeSize(txout, PROTOCOL_VERSION);

                    if (IsDust(txout, ::dustRelayFee))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                bool bnb_used;
                if (pick_new_inputs) {
                    nValueIn = 0;
                    setCoins.clear();
                    int change_spend_size = CalculateMaximumSignedInputSize(change_prototype_txout, this);
                    // If the wallet doesn't know how to sign change output, assume p2sh-p2wpkh
                    // as lower-bound to allow BnB to do it's thing
                    if (change_spend_size == -1) {
                        coin_selection_params.change_spend_size = DUMMY_NESTED_P2WPKH_INPUT_SIZE;
                    } else {
                        coin_selection_params.change_spend_size = (size_t)change_spend_size;
                    }
                    coin_selection_params.effective_fee = nFeeRateNeeded;
                    if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, coin_control, coin_selection_params, bnb_used))
                    {
                        // If BnB was used, it was the first pass. No longer the first pass and continue loop with knapsack.
                        if (bnb_used) {
                            coin_selection_params.use_bnb = false;
                            continue;
                        }
                        else {
                            strFailReason = _("Insufficient funds");
                            return false;
                        }
                    }
                } else {
                    bnb_used = false;
                }

                const CAmount nChange = nValueIn - nValueToSelect;
                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    CTxOut newTxOut(nChange, scriptChange);

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    // The nChange when BnB is used is always going to go to fees.
                    if (IsDust(newTxOut, discard_rate) || bnb_used)
                    {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                    }
                    else
                    {
                        if (nChangePosInOut == -1)
                        {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size()+1);
                        }
                        else if ((unsigned int)nChangePosInOut > txNew.vout.size())
                        {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        std::vector<CTxOut>::iterator position = txNew.vout.begin()+nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                    }
                } else {
                    nChangePosInOut = -1;
                }

                // Dummy fill vin for maximum size estimation
                //
                for (const auto& coin : setCoins) {
                    txNew.vin.push_back(CTxIn(coin.outpoint,CScript()));
                }

                nBytes = CalculateMaximumSignedTxSize(CTransaction(txNew), this, coin_control.fAllowWatchOnly);
                if (nBytes < 0) {
                    strFailReason = _("Signing transaction failed");
                    return false;
                }

                nFeeNeeded = GetMinimumFee(*this, nBytes, coin_control, &feeCalc);
                if (feeCalc.reason == FeeReason::FALLBACK && !m_allow_fallback_fee) {
                    // eventually allow a fallback fee
                    strFailReason = _("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.");
                    return false;
                }

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded) {
                    // Reduce fee to only the needed amount if possible. This
                    // prevents potential overpayment in fees if the coins
                    // selected to meet nFeeNeeded result in a transaction that
                    // requires less fee than the prior iteration.

                    // If we have no change and a big enough excess fee, then
                    // try to construct transaction again only without picking
                    // new inputs. We now know we only need the smaller fee
                    // (because of reduced tx size) and so we should add a
                    // change output. Only try this once.
                    if (nChangePosInOut == -1 && nSubtractFeeFromAmount == 0 && pick_new_inputs) {
                        unsigned int tx_size_with_change = nBytes + coin_selection_params.change_output_size + 2; // Add 2 as a buffer in case increasing # of outputs changes compact size
                        CAmount fee_needed_with_change = GetMinimumFee(*this, tx_size_with_change, coin_control, nullptr);
                        CAmount minimum_value_for_change = GetDustThreshold(change_prototype_txout, discard_rate);
                        if (nFeeRet >= fee_needed_with_change + minimum_value_for_change) {
                            pick_new_inputs = false;
                            nFeeRet = fee_needed_with_change;
                            continue;
                        }
                    }

                    // If we have change output already, just increase it
                    if (nFeeRet > nFeeNeeded && nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                        CAmount extraFeePaid = nFeeRet - nFeeNeeded;
                        std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                        change_position->nValue += extraFeePaid;
                        nFeeRet -= extraFeePaid;
                    }
                    break; // Done, enough fee included.
                }
                else if (!pick_new_inputs) {
                    // This shouldn't happen, we should have had enough excess
                    // fee to pay for the new output and still meet nFeeNeeded
                    // Or we should have just subtracted fee from recipients and
                    // nFeeNeeded should not have changed
                    strFailReason = _("Transaction fee and change calculation failed");
                    return false;
                }

                // Try to reduce change to include necessary fee
                if (nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                    CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;
                    std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                    // Only reduce change if remaining amount is still a large enough output.
                    if (change_position->nValue >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                        change_position->nValue -= additionalFeeNeeded;
                        nFeeRet += additionalFeeNeeded;
                        break; // Done, able to increase fee from change
                    }
                }

                // If subtracting fee from recipients, we now know what fee we
                // need to subtract, we have no reason to reselect inputs
                if (nSubtractFeeFromAmount > 0) {
                    pick_new_inputs = false;
                }

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                coin_selection_params.use_bnb = false;
                continue;
            }
        }

        if (nChangePosInOut == -1) reservekey.ReturnKey(); // Return any reserved key if we don't have change

        // Shuffle selected coins and fill in final vin
        txNew.vin.clear();
        std::vector<CInputCoin> selected_coins(setCoins.begin(), setCoins.end());
        Shuffle(selected_coins.begin(), selected_coins.end(), FastRandomContext());

        // Note how the sequence number is set to non-maxint so that
        // the nLockTime set above actually works.
        //
        // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
        // we use the highest possible value in that range (maxint-2)
        // to avoid conflicting with other possible uses of nSequence,
        // and in the spirit of "smallest possible change from prior
        // behavior."
        const uint32_t nSequence = coin_control.m_signal_bip125_rbf.get_value_or(m_signal_rbf) ? MAX_BIP125_RBF_SEQUENCE : (CTxIn::SEQUENCE_FINAL - 1);
        for (const auto& coin : selected_coins) {
            txNew.vin.push_back(CTxIn(coin.outpoint, CScript(), nSequence));
        }

        if (sign)
        {
            int nIn = 0;
            for (const auto& coin : selected_coins)
            {
                const CScript& scriptPubKey = coin.txout.scriptPubKey;
                SignatureData sigdata;

                if (!ProduceSignature(*this, MutableTransactionSignatureCreator(&txNew, nIn, coin.txout.nValue, SIGHASH_ALL), scriptPubKey, sigdata))
                {
                    strFailReason = _("Signing transaction failed");
                    return false;
                } else {
                    UpdateInput(txNew.vin.at(nIn), sigdata);
                }

                nIn++;
            }
        }

        // Return the constructed transaction data.
        tx = MakeTransactionRef(std::move(txNew));

        // Limit size
        if (GetTransactionWeight(*tx) > MAX_STANDARD_TX_WEIGHT)
        {
            strFailReason = _("Transaction too large");
            return false;
        }
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        if (!chain().checkChainLimits(tx)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }

    WalletLogPrintf("Fee Calculation: Fee:%d Bytes:%u Needed:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
                    nFeeRet, nBytes, nFeeNeeded, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
                    feeCalc.est.pass.start, feeCalc.est.pass.end,
                    100 * feeCalc.est.pass.withinTarget / (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool),
                    feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
                    feeCalc.est.fail.start, feeCalc.est.fail.end,
                    100 * feeCalc.est.fail.withinTarget / (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool),
                    feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm, CReserveKey& reservekey, CValidationState& state)
{
    {
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);

        CWalletTx wtxNew(this, std::move(tx));
        wtxNew.mapValue = std::move(mapValue);
        wtxNew.vOrderForm = std::move(orderForm);
        wtxNew.fTimeReceivedIsTxTime = true;
        wtxNew.fFromMe = true;

        WalletLogPrintf("CommitTransaction:\n%s", wtxNew.tx->ToString()); /* Continued */
        {
            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            for (const CTxIn& txin : wtxNew.tx->vin)
            {
                CWalletTx &coin = mapWallet.at(txin.prevout.hash);
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }
        }

        // Get the inserted-CWalletTx from mapWallet so that the
        // fInMempool flag is cached properly
        CWalletTx& wtx = mapWallet.at(wtxNew.GetHash());

        if (fBroadcastTransactions)
        {
            // Broadcast
            if (!wtx.AcceptToMemoryPool(*locked_chain, state)) {
                WalletLogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", FormatStateMessage(state));
                // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
            } else {
                wtx.RelayWalletTransaction(*locked_chain);
            }
        }
    }
    return true;
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    auto locked_chain = chain().lock();
    LOCK(cs_wallet);

    fFirstRunRet = false;
    DBErrors nLoadWalletRet = WalletBatch(*database,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DBErrors::NEED_REWRITE)
    {
        if (database->Rewrite("\x04pool"))
        {
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    {
        LOCK(cs_KeyStore);
        // This wallet is in its first run if all of these are empty
        fFirstRunRet = mapKeys.empty() && mapCryptedKeys.empty() && mapWatchKeys.empty() && setWatchOnly.empty() && mapScripts.empty()
                       && !IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET);
    }

    if (nLoadWalletRet != DBErrors::LOAD_OK)
        return nLoadWalletRet;

    return DBErrors::LOAD_OK;
}

DBErrors CWallet::ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut)
{
    AssertLockHeld(cs_wallet); // mapWallet
    DBErrors nZapSelectTxRet = WalletBatch(*database,"cr+").ZapSelectTx(vHashIn, vHashOut);
    for (uint256 hash : vHashOut) {
        const auto& it = mapWallet.find(hash);
        wtxOrdered.erase(it->second.m_it_wtxOrdered);
        mapWallet.erase(it);
    }

    if (nZapSelectTxRet == DBErrors::NEED_REWRITE)
    {
        if (database->Rewrite("\x04pool"))
        {
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapSelectTxRet != DBErrors::LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DBErrors::LOAD_OK;

}

DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    DBErrors nZapWalletTxRet = WalletBatch(*database,"cr+").ZapWalletTx(vWtx);
    if (nZapWalletTxRet == DBErrors::NEED_REWRITE)
    {
        if (database->Rewrite("\x04pool"))
        {
            LOCK(cs_wallet);
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DBErrors::LOAD_OK)
        return nZapWalletTxRet;

    return DBErrors::LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& strPurpose)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet);
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW) );
    if (!strPurpose.empty() && !WalletBatch(*database).WritePurpose(EncodeDestination(address), strPurpose))
        return false;
    return WalletBatch(*database).WriteName(EncodeDestination(address), strName);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet);

        // Delete destdata tuples associated with address
        std::string strAddress = EncodeDestination(address);
        for (const std::pair<const std::string, std::string> &item : mapAddressBook[address].destdata)
        {
            WalletBatch(*database).EraseDestData(strAddress, item.first);
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    WalletBatch(*database).ErasePurpose(EncodeDestination(address));
    return WalletBatch(*database).EraseName(EncodeDestination(address));
}

const std::string& CWallet::GetLabelName(const CScript& scriptPubKey) const
{
    CTxDestination address;
    if (ExtractDestination(scriptPubKey, address) && !scriptPubKey.IsUnspendable()) {
        auto mi = mapAddressBook.find(address);
        if (mi != mapAddressBook.end()) {
            return mi->second.name;
        }
    }
    // A scriptPubKey that doesn't have an entry in the address book is
    // associated with the default label ("").
    const static std::string DEFAULT_LABEL_NAME;
    return DEFAULT_LABEL_NAME;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    if (IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return false;
    }
    {
        LOCK(cs_wallet);
        WalletBatch batch(*database);

        for (const int64_t nIndex : setInternalKeyPool) {
            batch.ErasePool(nIndex);
        }
        setInternalKeyPool.clear();

        for (const int64_t nIndex : setExternalKeyPool) {
            batch.ErasePool(nIndex);
        }
        setExternalKeyPool.clear();

        for (const int64_t nIndex : set_pre_split_keypool) {
            batch.ErasePool(nIndex);
        }
        set_pre_split_keypool.clear();

        m_pool_key_to_index.clear();

        if (!TopUpKeyPool()) {
            return false;
        }
        WalletLogPrintf("CWallet::NewKeyPool rewrote keypool\n");
    }
    return true;
}

size_t CWallet::KeypoolCountExternalKeys()
{
    AssertLockHeld(cs_wallet); // setExternalKeyPool
    return setExternalKeyPool.size() + set_pre_split_keypool.size();
}

void CWallet::LoadKeyPool(int64_t nIndex, const CKeyPool &keypool)
{
    AssertLockHeld(cs_wallet);
    if (keypool.m_pre_split) {
        set_pre_split_keypool.insert(nIndex);
    } else if (keypool.fInternal) {
        setInternalKeyPool.insert(nIndex);
    } else {
        setExternalKeyPool.insert(nIndex);
    }
    m_max_keypool_index = std::max(m_max_keypool_index, nIndex);
    m_pool_key_to_index[keypool.vchPubKey.GetID()] = nIndex;

    // If no metadata exists yet, create a default with the pool key's
    // creation time. Note that this may be overwritten by actually
    // stored metadata for that key later, which is fine.
    CKeyID keyid = keypool.vchPubKey.GetID();
    if (mapKeyMetadata.count(keyid) == 0)
        mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    if (!CanGenerateKeys()) {
        return false;
    }
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = std::max(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);

        // count amount of available keys (internal, external)
        // make sure the keypool of external and internal keys fits the user selected target (-keypool)
        int64_t missingExternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setExternalKeyPool.size(), (int64_t) 0);
        int64_t missingInternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setInternalKeyPool.size(), (int64_t) 0);

        if (!IsHDEnabled() || !CanSupportFeature(FEATURE_HD_SPLIT))
        {
            // don't create extra internal keys
            missingInternal = 0;
        }
        bool internal = false;
        WalletBatch batch(*database);
        for (int64_t i = missingInternal + missingExternal; i--;)
        {
            if (i < missingInternal) {
                internal = true;
            }

            CPubKey pubkey(GenerateNewKey(batch, internal));
            AddKeypoolPubkeyWithDB(pubkey, internal, batch);
        }
        if (missingInternal + missingExternal > 0) {
            WalletLogPrintf("keypool added %d keys (%d internal), size=%u (%u internal)\n", missingInternal + missingExternal, missingInternal, setInternalKeyPool.size() + setExternalKeyPool.size() + set_pre_split_keypool.size(), setInternalKeyPool.size());
        }
    }
    NotifyCanGetAddressesChanged();
    return true;
}

void CWallet::AddKeypoolPubkey(const CPubKey& pubkey, const bool internal)
{
    WalletBatch batch(*database);
    AddKeypoolPubkeyWithDB(pubkey, internal, batch);
    NotifyCanGetAddressesChanged();
}

void CWallet::AddKeypoolPubkeyWithDB(const CPubKey& pubkey, const bool internal, WalletBatch& batch)
{
    LOCK(cs_wallet);
    assert(m_max_keypool_index < std::numeric_limits<int64_t>::max()); // How in the hell did you use so many keys?
    int64_t index = ++m_max_keypool_index;
    if (!batch.WritePool(index, CKeyPool(pubkey, internal))) {
        throw std::runtime_error(std::string(__func__) + ": writing imported pubkey failed");
    }
    if (internal) {
        setInternalKeyPool.insert(index);
    } else {
        setExternalKeyPool.insert(index);
    }
    m_pool_key_to_index[pubkey.GetID()] = index;
}

bool CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fRequestedInternal)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        bool fReturningInternal = fRequestedInternal;
        fReturningInternal &= (IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT)) || IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        bool use_split_keypool = set_pre_split_keypool.empty();
        std::set<int64_t>& setKeyPool = use_split_keypool ? (fReturningInternal ? setInternalKeyPool : setExternalKeyPool) : set_pre_split_keypool;

        // Get the oldest key
        if (setKeyPool.empty()) {
            return false;
        }

        WalletBatch batch(*database);

        auto it = setKeyPool.begin();
        nIndex = *it;
        setKeyPool.erase(it);
        if (!batch.ReadPool(nIndex, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read failed");
        }
        CPubKey pk;
        if (!GetPubKey(keypool.vchPubKey.GetID(), pk)) {
            throw std::runtime_error(std::string(__func__) + ": unknown key in key pool");
        }
        // If the key was pre-split keypool, we don't care about what type it is
        if (use_split_keypool && keypool.fInternal != fReturningInternal) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry misclassified");
        }
        if (!keypool.vchPubKey.IsValid()) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry invalid");
        }

        m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        WalletLogPrintf("keypool reserve %d\n", nIndex);
    }
    NotifyCanGetAddressesChanged();
    return true;
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    WalletBatch batch(*database);
    batch.ErasePool(nIndex);
    WalletLogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex, bool fInternal, const CPubKey& pubkey)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        if (fInternal) {
            setInternalKeyPool.insert(nIndex);
        } else if (!set_pre_split_keypool.empty()) {
            set_pre_split_keypool.insert(nIndex);
        } else {
            setExternalKeyPool.insert(nIndex);
        }
        m_pool_key_to_index[pubkey.GetID()] = nIndex;
        NotifyCanGetAddressesChanged();
    }
    WalletLogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool internal)
{
    if (!CanGetAddresses(internal)) {
        return false;
    }

    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        int64_t nIndex;
        if (!ReserveKeyFromKeyPool(nIndex, keypool, internal) && !IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            if (IsLocked()) return false;
            WalletBatch batch(*database);
            result = GenerateNewKey(batch, internal);
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

static int64_t GetOldestKeyTimeInPool(const std::set<int64_t>& setKeyPool, WalletBatch& batch) {
    if (setKeyPool.empty()) {
        return GetTime();
    }

    CKeyPool keypool;
    int64_t nIndex = *(setKeyPool.begin());
    if (!batch.ReadPool(nIndex, keypool)) {
        throw std::runtime_error(std::string(__func__) + ": read oldest key in keypool failed");
    }
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    LOCK(cs_wallet);

    WalletBatch batch(*database);

    // load oldest key from keypool, get time and return
    int64_t oldestKey = GetOldestKeyTimeInPool(setExternalKeyPool, batch);
    if (IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT)) {
        oldestKey = std::max(GetOldestKeyTimeInPool(setInternalKeyPool, batch), oldestKey);
        if (!set_pre_split_keypool.empty()) {
            oldestKey = std::max(GetOldestKeyTimeInPool(set_pre_split_keypool, batch), oldestKey);
        }
    }

    return oldestKey;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances(interfaces::Chain::Lock& locked_chain)
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        for (const auto& walletEntry : mapWallet)
        {
            const CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsTrusted(locked_chain))
                continue;

            if (pcoin->IsImmatureCoinBase(locked_chain))
                continue;

            int nDepth = pcoin->GetDepthInMainChain(locked_chain);
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->tx->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(locked_chain, walletEntry.first, i) ? 0 : pcoin->tx->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : mapWallet)
    {
        const CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->tx->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (const CTxIn& txin : pcoin->tx->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet.at(txin.prevout.hash).tx->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
                for (const CTxOut& txout : pcoin->tx->vout)
                    if (IsChange(txout))
                    {
                        CTxDestination txoutAddr;
                        if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                            continue;
                        grouping.insert(txoutAddr);
                    }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : pcoin->tx->vout)
            if (IsMine(txout))
            {
                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (std::set<CTxDestination> _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (const CTxDestination& address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (const CTxDestination& element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (const std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CWallet::GetLabelAddresses(const std::string& label) const
{
    LOCK(cs_wallet);
    std::set<CTxDestination> result;
    for (const std::pair<const CTxDestination, CAddressBookData>& item : mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == label)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey, bool internal)
{
    if (!pwallet->CanGetAddresses(internal)) {
        return false;
    }

    if (nIndex == -1)
    {
        CKeyPool keypool;
        if (!pwallet->ReserveKeyFromKeyPool(nIndex, keypool, internal)) {
            return false;
        }
        vchPubKey = keypool.vchPubKey;
        fInternal = keypool.fInternal;
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1) {
        pwallet->ReturnKey(nIndex, fInternal, vchPubKey);
    }
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::MarkReserveKeysAsUsed(int64_t keypool_id)
{
    AssertLockHeld(cs_wallet);
    bool internal = setInternalKeyPool.count(keypool_id);
    if (!internal) assert(setExternalKeyPool.count(keypool_id) || set_pre_split_keypool.count(keypool_id));
    std::set<int64_t> *setKeyPool = internal ? &setInternalKeyPool : (set_pre_split_keypool.empty() ? &setExternalKeyPool : &set_pre_split_keypool);
    auto it = setKeyPool->begin();

    WalletBatch batch(*database);
    while (it != std::end(*setKeyPool)) {
        const int64_t& index = *(it);
        if (index > keypool_id) break; // set*KeyPool is ordered

        CKeyPool keypool;
        if (batch.ReadPool(index, keypool)) { //TODO: This should be unnecessary
            m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        }
        LearnAllRelatedScripts(keypool.vchPubKey);
        batch.ErasePool(index);
        WalletLogPrintf("keypool index %d removed\n", index);
        it = setKeyPool->erase(it);
    }
}

void CWallet::LockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

void CWallet::GetKeyBirthTimes(interfaces::Chain::Lock& locked_chain, std::map<CTxDestination, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (const auto& entry : mapKeyMetadata) {
        if (entry.second.nCreateTime) {
            mapKeyBirth[entry.first] = entry.second.nCreateTime;
        }
    }

    // map in which we'll infer heights of other keys
    const Optional<int> tip_height = locked_chain.getHeight();
    const int max_height = tip_height && *tip_height > 144 ? *tip_height - 144 : 0; // the tip can be reorganized; use a 144-block safety margin
    std::map<CKeyID, int> mapKeyFirstBlock;
    for (const CKeyID &keyid : GetKeys()) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = max_height;
    }

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    for (const auto& entry : mapWallet) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = entry.second;
        if (Optional<int> height = locked_chain.getBlockHeight(wtx.hashBlock)) {
            // ... which are already in a block
            for (const CTxOut &txout : wtx.tx->vout) {
                // iterate over all their outputs
                for (const auto &keyid : GetAffectedKeys(txout.scriptPubKey, *this)) {
                    // ... and all their affected keys
                    std::map<CKeyID, int>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && *height < rit->second)
                        rit->second = *height;
                }
            }
        }
    }

    // Extract block timestamps for those keys
    for (const auto& entry : mapKeyFirstBlock)
        mapKeyBirth[entry.first] = locked_chain.getBlockTime(entry.second) - TIMESTAMP_WINDOW; // block times can be 2h off
}

/**
 * Compute smart timestamp for a transaction being added to the wallet.
 *
 * Logic:
 * - If sending a transaction, assign its timestamp to the current time.
 * - If receiving a transaction outside a block, assign its timestamp to the
 *   current time.
 * - If receiving a block with a future timestamp, assign all its (not already
 *   known) transactions' timestamps to the current time.
 * - If receiving a block with a past timestamp, before the most recent known
 *   transaction (that we care about), assign all its (not already known)
 *   transactions' timestamps to the same timestamp as that most-recent-known
 *   transaction.
 * - If receiving a block with a past timestamp, but after the most recent known
 *   transaction, assign all its (not already known) transactions' timestamps to
 *   the block time.
 *
 * For more information see CWalletTx::nTimeSmart,
 * https://bitcointalk.org/?topic=54527, or
 * https://github.com/bitcoin/bitcoin/pull/1393.
 */
unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx) const
{
    unsigned int nTimeSmart = wtx.nTimeReceived;
    if (!wtx.hashUnset()) {
        int64_t blocktime;
        if (chain().findBlock(wtx.hashBlock, nullptr /* block */, &blocktime)) {
            int64_t latestNow = wtx.nTimeReceived;
            int64_t latestEntry = 0;

            // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
            int64_t latestTolerated = latestNow + 300;
            const TxItems& txOrdered = wtxOrdered;
            for (auto it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                CWalletTx* const pwtx = it->second;
                if (pwtx == &wtx) {
                    continue;
                }
                int64_t nSmartTime;
                nSmartTime = pwtx->nTimeSmart;
                if (!nSmartTime) {
                    nSmartTime = pwtx->nTimeReceived;
                }
                if (nSmartTime <= latestTolerated) {
                    latestEntry = nSmartTime;
                    if (nSmartTime > latestNow) {
                        latestNow = nSmartTime;
                    }
                    break;
                }
            }

            nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
        } else {
            WalletLogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), wtx.hashBlock.ToString());
        }
    }
    return nTimeSmart;
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return WalletBatch(*database).WriteDestData(EncodeDestination(dest), key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    return WalletBatch(*database).EraseDestData(EncodeDestination(dest), key);
}

void CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if(i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if(j != i->second.destdata.end())
        {
            if(value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

std::vector<std::string> CWallet::GetDestValues(const std::string& prefix) const
{
    std::vector<std::string> values;
    for (const auto& address : mapAddressBook) {
        for (const auto& data : address.second.destdata) {
            if (!data.first.compare(0, prefix.size(), prefix)) {
                values.emplace_back(data.second);
            }
        }
    }
    return values;
}

void CWallet::MarkPreSplitKeys()
{
    WalletBatch batch(*database);
    for (auto it = setExternalKeyPool.begin(); it != setExternalKeyPool.end();) {
        int64_t index = *it;
        CKeyPool keypool;
        if (!batch.ReadPool(index, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read keypool entry failed");
        }
        keypool.m_pre_split = true;
        if (!batch.WritePool(index, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": writing modified keypool entry failed");
        }
        set_pre_split_keypool.insert(index);
        it = setExternalKeyPool.erase(it);
    }
}

bool CWallet::Verify(interfaces::Chain& chain, const WalletLocation& location, bool salvage_wallet, std::string& error_string, std::string& warning_string)
{
    // Do some checking on wallet path. It should be either a:
    //
    // 1. Path where a directory can be created.
    // 2. Path to an existing directory.
    // 3. Path to a symlink to a directory.
    // 4. For backwards compatibility, the name of a data file in -walletdir.
    LOCK(cs_wallets);
    const fs::path& wallet_path = location.GetPath();
    fs::file_type path_type = fs::symlink_status(wallet_path).type();
    if (!(path_type == fs::file_not_found || path_type == fs::directory_file ||
          (path_type == fs::symlink_file && fs::is_directory(wallet_path)) ||
          (path_type == fs::regular_file && fs::path(location.GetName()).filename() == location.GetName()))) {
        error_string = strprintf(
                "Invalid -wallet path '%s'. -wallet path should point to a directory where wallet.dat and "
                "database/log.?????????? files can be stored, a location where such a directory could be created, "
                "or (for backwards compatibility) the name of an existing data file in -walletdir (%s)",
                location.GetName(), GetWalletDir());
        return false;
    }

    // Make sure that the wallet path doesn't clash with an existing wallet path
    if (IsWalletLoaded(wallet_path)) {
        error_string = strprintf("Error loading wallet %s. Duplicate -wallet filename specified.", location.GetName());
        return false;
    }

    // Keep same database environment instance across Verify/Recover calls below.
    std::unique_ptr<WalletDatabase> database = WalletDatabase::Create(wallet_path);

    try {
        if (!WalletBatch::VerifyEnvironment(wallet_path, error_string)) {
            return false;
        }
    } catch (const fs::filesystem_error& e) {
        error_string = strprintf("Error loading wallet %s. %s", location.GetName(), fsbridge::get_filesystem_error_message(e));
        return false;
    }

    if (salvage_wallet) {
        // Recover readable keypairs:
        CWallet dummyWallet(chain, WalletLocation(), WalletDatabase::CreateDummy());
        std::string backup_filename;
        if (!WalletBatch::Recover(wallet_path, (void *)&dummyWallet, WalletBatch::RecoverKeysOnlyFilter, backup_filename)) {
            return false;
        }
    }

    return WalletBatch::VerifyDatabaseFile(wallet_path, warning_string, error_string);
}

std::shared_ptr<CWallet> CWallet::CreateWalletFromFile(interfaces::Chain& chain, const WalletLocation& location, uint64_t wallet_creation_flags)
{
    const std::string& walletFile = location.GetName();

    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector<CWalletTx> vWtx;

    if (gArgs.GetBoolArg("-zapwallettxes", false)) {
        chain.initMessage(_("Zapping all transactions from wallet..."));

        std::unique_ptr<CWallet> tempWallet = MakeUnique<CWallet>(chain, location, WalletDatabase::Create(location.GetPath()));
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DBErrors::LOAD_OK) {
            chain.initError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return nullptr;
        }
    }

    chain.initMessage(_("Loading wallet..."));

    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    // TODO: Can't use std::make_shared because we need a custom deleter but
    // should be possible to use std::allocate_shared.
    std::shared_ptr<CWallet> walletInstance(new CWallet(chain, location, WalletDatabase::Create(location.GetPath())), ReleaseWallet);
    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DBErrors::LOAD_OK)
    {
        if (nLoadWalletRet == DBErrors::CORRUPT) {
            chain.initError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NONCRITICAL_ERROR)
        {
            chain.initWarning(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                          " or address book entries might be missing or incorrect."),
                                        walletFile));
        }
        else if (nLoadWalletRet == DBErrors::TOO_NEW) {
            chain.initError(strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, _(PACKAGE_NAME)));
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NEED_REWRITE)
        {
            chain.initError(strprintf(_("Wallet needed to be rewritten: restart %s to complete"), _(PACKAGE_NAME)));
            return nullptr;
        }
        else {
            chain.initError(strprintf(_("Error loading %s"), walletFile));
            return nullptr;
        }
    }

    int prev_version = walletInstance->nWalletVersion;
    if (gArgs.GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = gArgs.GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            walletInstance->WalletLogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = FEATURE_LATEST;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            walletInstance->WalletLogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < walletInstance->GetVersion())
        {
            chain.initError(_("Cannot downgrade wallet"));
            return nullptr;
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }

    // Upgrade to HD if explicit upgrade
    if (gArgs.GetBoolArg("-upgradewallet", false)) {
        LOCK(walletInstance->cs_wallet);

        // Do not upgrade versions to any version between HD_SPLIT and FEATURE_PRE_SPLIT_KEYPOOL unless already supporting HD_SPLIT
        int max_version = walletInstance->nWalletVersion;
        if (!walletInstance->CanSupportFeature(FEATURE_HD_SPLIT) && max_version >=FEATURE_HD_SPLIT && max_version < FEATURE_PRE_SPLIT_KEYPOOL) {
            chain.initError(_("Cannot upgrade a non HD split wallet without upgrading to support pre split keypool. Please use -upgradewallet=169900 or -upgradewallet with no version specified."));
            return nullptr;
        }

        bool hd_upgrade = false;
        bool split_upgrade = false;
        if (walletInstance->CanSupportFeature(FEATURE_HD) && !walletInstance->IsHDEnabled()) {
            walletInstance->WalletLogPrintf("Upgrading wallet to HD\n");
            walletInstance->SetMinVersion(FEATURE_HD);

            // generate a new master key
            CPubKey masterPubKey = walletInstance->GenerateNewSeed();
            walletInstance->SetHDSeed(masterPubKey);
            hd_upgrade = true;
        }
        // Upgrade to HD chain split if necessary
        if (walletInstance->CanSupportFeature(FEATURE_HD_SPLIT)) {
            walletInstance->WalletLogPrintf("Upgrading wallet to use HD chain split\n");
            walletInstance->SetMinVersion(FEATURE_PRE_SPLIT_KEYPOOL);
            split_upgrade = FEATURE_HD_SPLIT > prev_version;
        }
        // Mark all keys currently in the keypool as pre-split
        if (split_upgrade) {
            walletInstance->MarkPreSplitKeys();
        }
        // Regenerate the keypool if upgraded to HD
        if (hd_upgrade) {
            if (!walletInstance->TopUpKeyPool()) {
                chain.initError(_("Unable to generate keys"));
                return nullptr;
            }
        }
    }

    if (fFirstRun)
    {
        // ensure this wallet.dat can only be opened by clients supporting HD with chain split and expects no default key
        walletInstance->SetMinVersion(FEATURE_LATEST);

        if ((wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            //selective allow to set flags
            walletInstance->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        } else if (wallet_creation_flags & WALLET_FLAG_BLANK_WALLET) {
            walletInstance->SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
        } else {
            // generate a new seed
            CPubKey seed = walletInstance->GenerateNewSeed();
            walletInstance->SetHDSeed(seed);
        } // Otherwise, do not generate a new seed

        // Top up the keypool
        if (walletInstance->CanGenerateKeys() && !walletInstance->TopUpKeyPool()) {
            chain.initError(_("Unable to generate initial keys"));
            return nullptr;
        }

        auto locked_chain = chain.assumeLocked();  // Temporary. Removed in upcoming lock cleanup
        walletInstance->ChainStateFlushed(locked_chain->getTipLocator());
    } else if (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS) {
        // Make it impossible to disable private keys after creation
        chain.initError(strprintf(_("Error loading %s: Private keys can only be disabled during creation"), walletFile));
        return NULL;
    } else if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        LOCK(walletInstance->cs_KeyStore);
        if (!walletInstance->mapKeys.empty() || !walletInstance->mapCryptedKeys.empty()) {
            chain.initWarning(strprintf(_("Warning: Private keys detected in wallet {%s} with disabled private keys"), walletFile));
        }
    }

    if (!gArgs.GetArg("-addresstype", "").empty() && !ParseOutputType(gArgs.GetArg("-addresstype", ""), walletInstance->m_default_address_type)) {
        chain.initError(strprintf("Unknown address type '%s'", gArgs.GetArg("-addresstype", "")));
        return nullptr;
    }

    if (!gArgs.GetArg("-changetype", "").empty() && !ParseOutputType(gArgs.GetArg("-changetype", ""), walletInstance->m_default_change_type)) {
        chain.initError(strprintf("Unknown change type '%s'", gArgs.GetArg("-changetype", "")));
        return nullptr;
    }

    if (gArgs.IsArgSet("-mintxfee")) {
        CAmount n = 0;
        if (!ParseMoney(gArgs.GetArg("-mintxfee", ""), n) || 0 == n) {
            chain.initError(AmountErrMsg("mintxfee", gArgs.GetArg("-mintxfee", "")));
            return nullptr;
        }
        if (n > HIGH_TX_FEE_PER_KB) {
            chain.initWarning(AmountHighWarn("-mintxfee") + " " +
                              _("This is the minimum transaction fee you pay on every transaction."));
        }
        walletInstance->m_min_fee = CFeeRate(n);
    }

    walletInstance->m_allow_fallback_fee = Params().IsFallbackFeeEnabled();
    if (gArgs.IsArgSet("-fallbackfee")) {
        CAmount nFeePerK = 0;
        if (!ParseMoney(gArgs.GetArg("-fallbackfee", ""), nFeePerK)) {
            chain.initError(strprintf(_("Invalid amount for -fallbackfee=<amount>: '%s'"), gArgs.GetArg("-fallbackfee", "")));
            return nullptr;
        }
        if (nFeePerK > HIGH_TX_FEE_PER_KB) {
            chain.initWarning(AmountHighWarn("-fallbackfee") + " " +
                              _("This is the transaction fee you may pay when fee estimates are not available."));
        }
        walletInstance->m_fallback_fee = CFeeRate(nFeePerK);
        walletInstance->m_allow_fallback_fee = nFeePerK != 0; //disable fallback fee in case value was set to 0, enable if non-null value
    }
    if (gArgs.IsArgSet("-discardfee")) {
        CAmount nFeePerK = 0;
        if (!ParseMoney(gArgs.GetArg("-discardfee", ""), nFeePerK)) {
            chain.initError(strprintf(_("Invalid amount for -discardfee=<amount>: '%s'"), gArgs.GetArg("-discardfee", "")));
            return nullptr;
        }
        if (nFeePerK > HIGH_TX_FEE_PER_KB) {
            chain.initWarning(AmountHighWarn("-discardfee") + " " +
                              _("This is the transaction fee you may discard if change is smaller than dust at this level"));
        }
        walletInstance->m_discard_rate = CFeeRate(nFeePerK);
    }
    if (gArgs.IsArgSet("-paytxfee")) {
        CAmount nFeePerK = 0;
        if (!ParseMoney(gArgs.GetArg("-paytxfee", ""), nFeePerK)) {
            chain.initError(AmountErrMsg("paytxfee", gArgs.GetArg("-paytxfee", "")));
            return nullptr;
        }
        if (nFeePerK > HIGH_TX_FEE_PER_KB) {
            chain.initWarning(AmountHighWarn("-paytxfee") + " " +
                              _("This is the transaction fee you will pay if you send a transaction."));
        }
        walletInstance->m_pay_tx_fee = CFeeRate(nFeePerK, 1000);
        if (walletInstance->m_pay_tx_fee < ::minRelayTxFee) {
            chain.initError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s' (must be at least %s)"),
                                      gArgs.GetArg("-paytxfee", ""), ::minRelayTxFee.ToString()));
            return nullptr;
        }
    }
    walletInstance->m_confirm_target = gArgs.GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    walletInstance->m_spend_zero_conf_change = gArgs.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    walletInstance->m_signal_rbf = gArgs.GetBoolArg("-walletrbf", DEFAULT_WALLET_RBF);

    walletInstance->WalletLogPrintf("Wallet completed loading in %15dms\n", GetTimeMillis() - nStart);

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    auto locked_chain = chain.lock();
    LOCK(walletInstance->cs_wallet);

    int rescan_height = 0;
    if (!gArgs.GetBoolArg("-rescan", false))
    {
        WalletBatch batch(*walletInstance->database);
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator)) {
            if (const Optional<int> fork_height = locked_chain->findLocatorFork(locator)) {
                rescan_height = *fork_height;
            }
        }
    }

    const Optional<int> tip_height = locked_chain->getHeight();
    if (tip_height) {
        walletInstance->m_last_block_processed = locked_chain->getBlockHash(*tip_height);
    } else {
        walletInstance->m_last_block_processed.SetNull();
    }

    if (tip_height && *tip_height != rescan_height)
    {
        //We can't rescan beyond non-pruned blocks, stop and throw an error
        //this might happen if a user uses an old wallet within a pruned node
        // or if he ran -disablewallet for a longer time, then decided to re-enable
        if (chain.getPruneMode()) {
            int block_height = *tip_height;
            while (block_height > 0 && locked_chain->haveBlockOnDisk(block_height - 1) && rescan_height != block_height) {
                --block_height;
            }

            if (rescan_height != block_height) {
                chain.initError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
                return nullptr;
            }
        }

        chain.initMessage(_("Rescanning..."));
        walletInstance->WalletLogPrintf("Rescanning last %i blocks (from block %i)...\n", *tip_height - rescan_height, rescan_height);

        // No need to read and scan block if block was created before
        // our wallet birthday (as adjusted for block time variability)
        if (walletInstance->nTimeFirstKey) {
            if (Optional<int> first_block = locked_chain->findFirstBlockWithTimeAndHeight(walletInstance->nTimeFirstKey - TIMESTAMP_WINDOW, rescan_height)) {
                rescan_height = *first_block;
            }
        }

        nStart = GetTimeMillis();
        {
            WalletRescanReserver reserver(walletInstance.get());
            if (!reserver.reserve() || (ScanResult::SUCCESS != walletInstance->ScanForWalletTransactions(locked_chain->getBlockHash(rescan_height), {} /* stop block */, reserver, true /* update */).status)) {
                chain.initError(_("Failed to rescan the wallet during initialization"));
                return nullptr;
            }
        }
        walletInstance->WalletLogPrintf("Rescan completed in %15dms\n", GetTimeMillis() - nStart);
        walletInstance->ChainStateFlushed(locked_chain->getTipLocator());
        walletInstance->database->IncrementUpdateCounter();

        // Restore wallet transaction metadata after -zapwallettxes=1
        if (gArgs.GetBoolArg("-zapwallettxes", false) && gArgs.GetArg("-zapwallettxes", "1") != "2")
        {
            WalletBatch batch(*walletInstance->database);

            for (const CWalletTx& wtxOld : vWtx)
            {
                uint256 hash = wtxOld.GetHash();
                std::map<uint256, CWalletTx>::iterator mi = walletInstance->mapWallet.find(hash);
                if (mi != walletInstance->mapWallet.end())
                {
                    const CWalletTx* copyFrom = &wtxOld;
                    CWalletTx* copyTo = &mi->second;
                    copyTo->mapValue = copyFrom->mapValue;
                    copyTo->vOrderForm = copyFrom->vOrderForm;
                    copyTo->nTimeReceived = copyFrom->nTimeReceived;
                    copyTo->nTimeSmart = copyFrom->nTimeSmart;
                    copyTo->fFromMe = copyFrom->fFromMe;
                    copyTo->nOrderPos = copyFrom->nOrderPos;
                    batch.WriteTx(*copyTo);
                }
            }
        }
    }

    chain.loadWallet(interfaces::MakeWallet(walletInstance));

    // Register with the validation interface. It's ok to do this after rescan since we're still holding cs_main.
    RegisterValidationInterface(walletInstance.get());

    walletInstance->SetBroadcastTransactions(gArgs.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    {
        walletInstance->WalletLogPrintf("setKeyPool.size() = %u\n",      walletInstance->GetKeyPoolSize());
        walletInstance->WalletLogPrintf("mapWallet.size() = %u\n",       walletInstance->mapWallet.size());
        walletInstance->WalletLogPrintf("mapAddressBook.size() = %u\n",  walletInstance->mapAddressBook.size());
    }

    return walletInstance;
}

void CWallet::postInitProcess()
{
    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ReacceptWalletTransactions();
}

bool CWallet::BackupWallet(const std::string& strDest)
{
    return database->Backup(strDest);
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
    fInternal = false;
    m_pre_split = false;
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
    fInternal = internalIn;
    m_pre_split = false;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

void CMerkleTx::SetMerkleBranch(const uint256& block_hash, int posInBlock)
{
    // Update the tx's hashBlock
    hashBlock = block_hash;

    // set the position of the transaction in the block
    nIndex = posInBlock;
}

int CMerkleTx::GetDepthInMainChain(interfaces::Chain::Lock& locked_chain, bool enableIX) const
{
    if (hashUnset())
        return 0;

    AssertLockHeld(cs_main);

    int nResult = locked_chain.getBlockDepth(hashBlock) * (nIndex == -1 ? -1 : 1);
    if (enableIX) {
        if (nResult < 6) {
            int signatures = GetTransactionLockSignatures();
            if (signatures >= SWIFTTX_SIGNATURES_REQUIRED) {
                return nSwiftTXDepth + nResult;
            }
        }
    }
    return nResult;
}

int CMerkleTx::GetBlocksToMaturity(interfaces::Chain::Lock& locked_chain) const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    int chain_depth = GetDepthInMainChain(locked_chain);
    assert(chain_depth >= 0); // coinbase tx should not be conflicted
    return std::max(0, (COINBASE_MATURITY+1) - chain_depth);
}

bool CMerkleTx::IsImmatureCoinBase(interfaces::Chain::Lock& locked_chain) const
{
    // note GetBlocksToMaturity is 0 for non-coinbase tx
    return GetBlocksToMaturity(locked_chain) > 0;
}

bool CWalletTx::AcceptToMemoryPool(interfaces::Chain::Lock& locked_chain, CValidationState& state)
{
    // We must set fInMempool here - while it will be re-set to true by the
    // entered-mempool callback, if we did not there would be a race where a
    // user could call sendmoney in a loop and hit spurious out of funds errors
    // because we think that this newly generated transaction's change is
    // unavailable as we're not yet aware that it is in the mempool.
    bool ret = locked_chain.submitToMemoryPool(tx, pwallet->chain().maxTxFee(), state);
    fInMempool |= ret;
    return ret;
}

void CWallet::LearnRelatedScripts(const CPubKey& key, OutputType type)
{
    if (key.IsCompressed() && (type == OutputType::P2SH_SEGWIT || type == OutputType::BECH32)) {
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        // Make sure the resulting program is solvable.
        assert(IsSolvable(*this, witprog));
        AddCScript(witprog);
    }
}

void CWallet::LearnAllRelatedScripts(const CPubKey& key)
{
    // OutputType::P2SH_SEGWIT always adds all necessary scripts for all types.
    LearnRelatedScripts(key, OutputType::P2SH_SEGWIT);
}

std::vector<OutputGroup> CWallet::GroupOutputs(const std::vector<COutput>& outputs, bool single_coin) const {
    std::vector<OutputGroup> groups;
    std::map<CTxDestination, OutputGroup> gmap;
    CTxDestination dst;
    for (const auto& output : outputs) {
        if (output.fSpendable) {
            CInputCoin input_coin = output.GetInputCoin();

            size_t ancestors, descendants;
            chain().getTransactionAncestry(output.tx->GetHash(), ancestors, descendants);
            if (!single_coin && ExtractDestination(output.tx->tx->vout[output.i].scriptPubKey, dst)) {
                // Limit output groups to no more than 10 entries, to protect
                // against inadvertently creating a too-large transaction
                // when using -avoidpartialspends
                if (gmap[dst].m_outputs.size() >= OUTPUT_GROUP_MAX_ENTRIES) {
                    groups.push_back(gmap[dst]);
                    gmap.erase(dst);
                }
                gmap[dst].Insert(input_coin, output.nDepth, output.tx->IsFromMe(ISMINE_ALL), ancestors, descendants);
            } else {
                groups.emplace_back(input_coin, output.nDepth, output.tx->IsFromMe(ISMINE_ALL), ancestors, descendants);
            }
        }
    }
    if (!single_coin) {
        for (const auto& it : gmap) groups.push_back(it.second);
    }
    return groups;
}

bool CWallet::GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const
{
    CKeyMetadata meta;
    {
        LOCK(cs_wallet);
        auto it = mapKeyMetadata.find(keyID);
        if (it != mapKeyMetadata.end()) {
            meta = it->second;
        }
    }
    if (meta.has_key_origin) {
        std::copy(meta.key_origin.fingerprint, meta.key_origin.fingerprint + 4, info.fingerprint);
        info.path = meta.key_origin.path;
    } else { // Single pubkeys get the master fingerprint of themselves
        std::copy(keyID.begin(), keyID.begin() + 4, info.fingerprint);
    }
    return true;
}

bool CWallet::AddKeyOrigin(const CPubKey& pubkey, const KeyOriginInfo& info)
{
    LOCK(cs_wallet);
    std::copy(info.fingerprint, info.fingerprint + 4, mapKeyMetadata[pubkey.GetID()].key_origin.fingerprint);
    mapKeyMetadata[pubkey.GetID()].key_origin.path = info.path;
    mapKeyMetadata[pubkey.GetID()].has_key_origin = true;
    mapKeyMetadata[pubkey.GetID()].hdKeypath = WriteHDKeypath(info.path);
    return WriteKeyMetadata(mapKeyMetadata[pubkey.GetID()], pubkey, true);
}

// TODO: Erase from here
void CWallet::EraseFromWallet(const uint256& hash)
{
    if (!fFileBacked)
        return;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            WalletBatch(*database).EraseTx(hash);
    }
    return;
}

bool CWallet::IsUsed(const CBitcoinAddress address) const
{
    LOCK(cs_wallet);
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!::IsMine(*this, scriptPubKey)) {
        return false;
    }

    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
        const CWalletTx& wtx = (*it).second;
        if (wtx.tx->IsCoinBase()) {
            continue;
        }
        for (const CTxOut& txout : wtx.tx->vout) {
            if (txout.scriptPubKey == scriptPubKey)
                return true;
        }
    }
    return false;
}

bool CWallet::IsMyZerocoinSpend(const CBigNum& bnSerial) const
{
    return zwspTracker->HasSerial(bnSerial);
}

// Recursively determine the rounds of a given input (How deep is the Obfuscation chain for a given input)
int CWallet::GetRealInputObfuscationRounds(CTxIn in, int rounds) const
{
    static std::map<uint256, CMutableTransaction> mDenomWtxes;

    if (rounds >= 16) return 15; // 16 rounds max

    uint256 hash = in.prevout.hash;
    unsigned int nout = in.prevout.n;

    const CWalletTx* wtx = GetWalletTx(hash);
    if (wtx != nullptr) {
        std::map<uint256, CMutableTransaction>::const_iterator mdwi = mDenomWtxes.find(hash);
        // not known yet, let's add it
        if (mdwi == mDenomWtxes.end()) {
            LogPrint(BCLog::OBFUSCATION, "GetInputObfuscationRounds INSERTING %s\n", hash.ToString());
            mDenomWtxes[hash] = CMutableTransaction(*wtx->tx);
        }
        // found and it's not an initial value, just return it
        else if (mDenomWtxes[hash].vout[nout].nRounds != -10) {
            return mDenomWtxes[hash].vout[nout].nRounds;
        }


        // bounds check
        if (nout >= wtx->tx->vout.size()) {
            // should never actually hit this
            LogPrint(BCLog::OBFUSCATION, "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, -4);
            return -4;
        }

        if (pwalletMain->IsCollateralAmount(wtx->tx->vout[nout].nValue)) {
            mDenomWtxes[hash].vout[nout].nRounds = -3;
            LogPrint(BCLog::OBFUSCATION, "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        //make sure the final output is non-denominate
        if (/*rounds == 0 && */ !IsDenominatedAmount(wtx->tx->vout[nout].nValue)) //NOT DENOM
        {
            mDenomWtxes[hash].vout[nout].nRounds = -2;
            LogPrint(BCLog::OBFUSCATION, "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        bool fAllDenoms = true;
        for (CTxOut out: wtx->tx->vout) {
            fAllDenoms = fAllDenoms && IsDenominatedAmount(out.nValue);
        }
        // this one is denominated but there is another non-denominated output found in the same tx
        if (!fAllDenoms) {
            mDenomWtxes[hash].vout[nout].nRounds = 0;
            LogPrint(BCLog::OBFUSCATION, "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        int nShortest = -10; // an initial value, should be no way to get this by calculations
        bool fDenomFound = false;
        // only denoms here so let's look up
        for (CTxIn in2: wtx->tx->vin) {
            if (IsMine(in2)) {
                int n = GetRealInputObfuscationRounds(in2, rounds + 1);
                // denom found, find the shortest chain or initially assign nShortest with the first found value
                if (n >= 0 && (n < nShortest || nShortest == -10)) {
                    nShortest = n;
                    fDenomFound = true;
                }
            }
        }
        mDenomWtxes[hash].vout[nout].nRounds = fDenomFound ? (nShortest >= 15 ? 16 : nShortest + 1) // good, we a +1 to the shortest one but only 16 rounds max allowed
                                                             :
                                                             0; // too bad, we are the fist one in that chain
        LogPrint(BCLog::OBFUSCATION, "GetInputObfuscationRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
        return mDenomWtxes[hash].vout[nout].nRounds;
    }

    return rounds - 1;
}

// respect current settings
int CWallet::GetInputObfuscationRounds(CTxIn in) const
{
    LOCK(cs_wallet);
    int realObfuscationRounds = GetRealInputObfuscationRounds(in, 0);
    return realObfuscationRounds > nZeromintPercentage ? nZeromintPercentage : realObfuscationRounds;
}

bool CWallet::IsDenominated(const CTxIn& txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end()) {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size()) return IsDenominatedAmount(prev.tx->vout[txin.prevout.n].nValue);
        }
    }
    return false;
}

bool CWallet::IsDenominated(const CTransaction& tx) const
{
    /*
        Return false if ANY inputs are non-denom
    */
    bool ret = true;
    for (const CTxIn& txin: tx.vin) {
        if (!IsDenominated(txin)) {
            ret = false;
        }
    }
    return ret;
}


bool CWallet::IsDenominatedAmount(CAmount nInputAmount) const
{
    for (CAmount d: obfuScationDenominations)
        if (nInputAmount == d)
            return true;
    return false;
}

int64_t CWalletTx::GetComputedTxTime(interfaces::Chain::Lock& locked_chain) const
{
    LOCK(cs_main);
    if (tx->IsZerocoinSpend() || tx->IsZerocoinMint()) {
        if (IsInMainChain(locked_chain))
            return mapBlockIndex.at(hashBlock)->GetBlockTime();
        else
            return nTimeReceived;
    }
    return GetTxTime();
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (tx->IsCoinBase()) {
            // Generated block
            if (hashBlock != 0) {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        } else {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(tx->GetHash());
            if (mi != pwallet->mapRequestCount.end()) {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0) {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

CAmount CWalletTx::GetAnonymizableCredit(interfaces::Chain::Lock& locked_chain, bool fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (tx->IsCoinBase() && GetBlocksToMaturity(locked_chain) > 0)
        return 0;

    if (fUseCache && fAnonymizableCreditCached)
        return nAnonymizableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];
        const CTxIn vin = CTxIn(hashTx, i);

        if (pwallet->IsSpent(locked_chain, hashTx, i) || pwallet->IsLockedCoin(hashTx, i)) continue;
        if (fMasterNode && tx->vout[i].nValue == 125000 * COIN) continue; // do not count MN-like outputs

        const int rounds = pwallet->GetInputObfuscationRounds(vin);
        if (rounds >= -2 && rounds < nZeromintPercentage) {
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAnonamizableCredit() : value out of range");
        }
    }

    nAnonymizableCreditCached = nCredit;
    fAnonymizableCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetAnonymizedCredit(interfaces::Chain::Lock& locked_chain, bool fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (tx->IsCoinBase() && GetBlocksToMaturity(locked_chain) > 0)
        return 0;

    if (fUseCache && fAnonymizedCreditCached)
        return nAnonymizedCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];
        const CTxIn vin = CTxIn(hashTx, i);

        if (pwallet->IsSpent(locked_chain, hashTx, i) || !pwallet->IsDenominated(vin)) continue;

        const int rounds = pwallet->GetInputObfuscationRounds(vin);
        if (rounds >= nZeromintPercentage) {
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAnonymizedCredit() : value out of range");
        }
    }

    nAnonymizedCreditCached = nCredit;
    fAnonymizedCreditCached = true;
    return nCredit;
}

// Return sum of unlocked coins
CAmount CWalletTx::GetUnlockedCredit(interfaces::Chain::Lock& locked_chain) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (tx->IsCoinBase() && GetBlocksToMaturity(locked_chain) > 0)
        return 0;

    CAmount nCredit = 0;
    uint256 hashTx = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];

        if (pwallet->IsSpent(locked_chain, hashTx, i) || pwallet->IsLockedCoin(hashTx, i)) continue;
        if (fMasterNode && tx->vout[i].nValue == 125000 * COIN) continue; // do not count MN-like outputs

        nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
        if (!MoneyRange(nCredit))
            throw std::runtime_error("CWalletTx::GetUnlockedCredit() : value out of range");
    }

    return nCredit;
}

    // Return sum of unlocked coins
CAmount CWalletTx::GetLockedCredit(interfaces::Chain::Lock& locked_chain) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (tx->IsCoinBase() && GetBlocksToMaturity(locked_chain) > 0)
        return 0;

    CAmount nCredit = 0;
    uint256 hashTx = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];

        // Skip spent coins
        if (pwallet->IsSpent(locked_chain, hashTx, i)) continue;

        // Add locked coins
        if (pwallet->IsLockedCoin(hashTx, i)) {
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
        }

        // Add masternode collaterals which are handled likc locked coins
        else if (fMasterNode && tx->vout[i].nValue == 125000 * COIN) {
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
        }

        if (!MoneyRange(nCredit))
            throw std::runtime_error("CWalletTx::GetLockedCredit() : value out of range");
    }

    return nCredit;
}

CAmount CWalletTx::GetDenominatedCredit(interfaces::Chain::Lock& locked_chain, bool unconfirmed, bool fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (tx->IsCoinBase() && GetBlocksToMaturity(locked_chain) > 0)
        return 0;

    int nDepth = GetDepthInMainChain(locked_chain, false);
    if (nDepth < 0) return 0;

    bool isUnconfirmed = !CheckFinalTx(*tx) || (!IsTrusted(locked_chain) && nDepth == 0);
    if (unconfirmed != isUnconfirmed) return 0;

    if (fUseCache) {
        if (unconfirmed && fDenomUnconfCreditCached)
            return nDenomUnconfCreditCached;
        else if (!unconfirmed && fDenomConfCreditCached)
            return nDenomConfCreditCached;
    }

    CAmount nCredit = 0;
    uint256 hashTx = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];

        if (pwallet->IsSpent(locked_chain, hashTx, i) || !pwallet->IsDenominatedAmount(tx->vout[i].nValue)) continue;

        nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
        if (!MoneyRange(nCredit))
            throw std::runtime_error("CWalletTx::GetDenominatedCredit() : value out of range");
    }

    if (unconfirmed) {
        nDenomUnconfCreditCached = nCredit;
        fDenomUnconfCreditCached = true;
    } else {
        nDenomConfCreditCached = nCredit;
        fDenomConfCreditCached = true;
    }
    return nCredit;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(interfaces::Chain::Lock& locked_chain, const bool& fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (tx->IsCoinBase() && GetBlocksToMaturity(locked_chain) > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        if (!pwallet->IsSpent(locked_chain, tx->GetHash(), i)) {
            const CTxOut& txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetLockedWatchOnlyCredit(interfaces::Chain::Lock& locked_chain) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (tx->IsCoinBase() && GetBlocksToMaturity(locked_chain) > 0)
        return 0;

    CAmount nCredit = 0;
    uint256 hashTx = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut& txout = tx->vout[i];

        // Skip spent coins
        if (pwallet->IsSpent(locked_chain, hashTx, i)) continue;

        // Add locked coins
        if (pwallet->IsLockedCoin(hashTx, i)) {
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
        }

        // Add masternode collaterals which are handled likc locked coins
        else if (fMasterNode && tx->vout[i].nValue == 125000 * COIN) {
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
        }

        if (!MoneyRange(nCredit))
            throw std::runtime_error("CWalletTx::GetLockedCredit() : value out of range");
    }

    return nCredit;
}

void CWalletTx::GetAccountAmounts(const std::string& strAccount, CAmount& nReceived, CAmount& nSent, CAmount& nFee, const isminefilter& filter) const
{
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, filter);

    if (strAccount == strFromAccount) {
        for (const COutputEntry& s: listSent)
            nSent += s.amount;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        for (const COutputEntry& r: listReceived) {
            if (pwallet->mapAddressBook.count(r.destination)) {
                map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second.name == strAccount)
                    nReceived += r.amount;
            } else if (strAccount.empty()) {
                nReceived += r.amount;
            }
        }
    }
}


bool CWalletTx::WriteToDisk()
{
    return WalletBatch(pwalletMain->GetDBHandle()).WriteTx(*this);
}

/** @} */ // end of mapWallet


/** @defgroup Actions
 *
 * @{
 */

std::map<libzerocoin::CoinDenomination, int> mapMintMaturity;
int nLastMaturityCheck = 0;
CAmount CWallet::GetZerocoinBalance(bool fMatureOnly) const
{
    if (fMatureOnly) {
        if (chainActive.Height() > nLastMaturityCheck)
            mapMintMaturity = GetMintMaturityHeight();
        nLastMaturityCheck = chainActive.Height();

        CAmount nBalance = 0;
        std::vector<CMintMeta> vMints = zwspTracker->GetMints(true);
        for (auto meta : vMints) {
            if (meta.nHeight >= mapMintMaturity.at(meta.denom) || meta.nHeight >= chainActive.Height() || meta.nHeight == 0)
                continue;
            nBalance += libzerocoin::ZerocoinDenominationToAmount(meta.denom);
        }
        return nBalance;
    }

    return zwspTracker->GetBalance(false, false);
}

CAmount CWallet::GetImmatureZerocoinBalance() const
{
    return GetZerocoinBalance(false) - GetZerocoinBalance(true) - GetUnconfirmedZerocoinBalance();
}

CAmount CWallet::GetUnconfirmedZerocoinBalance() const
{
    return zwspTracker->GetUnconfirmedBalance();
}

CAmount CWallet::GetUnlockedCoins() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted(*locked_chain) && pcoin->GetDepthInMainChain(*locked_chain) > 0)
                nTotal += pcoin->GetUnlockedCredit(*locked_chain);
        }
    }

    return nTotal;
}

CAmount CWallet::GetLockedCoins() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted(*locked_chain) && pcoin->GetDepthInMainChain(*locked_chain) > 0)
                nTotal += pcoin->GetLockedCredit(*locked_chain);
        }
    }

    return nTotal;
}

// Get a Map pairing the Denominations with the amount of Zerocoin for each Denomination
std::map<libzerocoin::CoinDenomination, CAmount> CWallet::GetMyZerocoinDistribution() const
{
    std::map<libzerocoin::CoinDenomination, CAmount> spread;
    for (const auto& denom : libzerocoin::zerocoinDenomList)
        spread.insert(std::pair<libzerocoin::CoinDenomination, CAmount>(denom, 0));
    {
        LOCK(cs_wallet);
        set<CMintMeta> setMints = zwspTracker->ListMints(true, true, true);
        for (auto& mint : setMints)
            spread.at(mint.denom)++;
    }
    return spread;
}


CAmount CWallet::GetAnonymizableBalance() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted(*locked_chain))
                nTotal += pcoin->GetAnonymizableCredit(*locked_chain);
        }
    }

    return nTotal;
}

CAmount CWallet::GetAnonymizedBalance() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            if (pcoin->IsTrusted(*locked_chain))
                nTotal += pcoin->GetAnonymizedCredit(*locked_chain);
        }
    }

    return nTotal;
}

// Note: calculated including unconfirmed,
// that's ok as long as we use it for informational purposes only
double CWallet::GetAverageAnonymizedRounds() const
{
    if (fLiteMode) return 0;

    double fTotal = 0;
    double fCount = 0;

    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            uint256 hash = (*it).first;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                CTxIn vin = CTxIn(hash, i);

                if (IsSpent(*locked_chain, hash, i) || IsMine(pcoin->tx->vout[i]) != ISMINE_SPENDABLE || !IsDenominated(vin)) continue;

                int rounds = GetInputObfuscationRounds(vin);
                fTotal += (float)rounds;
                fCount += 1;
            }
        }
    }

    if (fCount == 0) return 0;

    return fTotal / fCount;
}

// Note: calculated including unconfirmed,
// that's ok as long as we use it for informational purposes only
CAmount CWallet::GetNormalizedAnonymizedBalance() const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;

    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            uint256 hash = (*it).first;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                CTxIn vin = CTxIn(hash, i);

                if (IsSpent(*locked_chain, hash, i) || IsMine(pcoin->tx->vout[i]) != ISMINE_SPENDABLE || !IsDenominated(vin)) continue;
                if (pcoin->GetDepthInMainChain(*locked_chain) < 0) continue;

                int rounds = GetInputObfuscationRounds(vin);
                nTotal += pcoin->tx->vout[i].nValue * rounds / nZeromintPercentage;
            }
        }
    }

    return nTotal;
}

CAmount CWallet::GetDenominatedBalance(bool unconfirmed) const
{
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;

            nTotal += pcoin->GetDenominatedCredit(*locked_chain, unconfirmed);
        }
    }

    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted(*locked_chain))
                nTotal += pcoin->GetAvailableWatchOnlyCredit(*locked_chain);
        }
    }

    return nTotal;
}

CAmount CWallet::GetLockedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted(*locked_chain) && pcoin->GetDepthInMainChain(*locked_chain) > 0)
                nTotal += pcoin->GetLockedWatchOnlyCredit(*locked_chain);
        }
    }
    return nTotal;
}

/**
 * populate vCoins with vector of available COutputs.
 */
void CWallet::AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl* coinControl, bool fIncludeZeroValue, AvailableCoinsType nCoinType, bool fUseIX, int nWatchonlyConfig) const
{
    vCoins.clear();

    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            if (!CheckFinalTx(*pcoin->tx))
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted(*locked_chain))
                continue;

            if ((pcoin->tx->IsCoinBase() || pcoin->tx->IsCoinStake()) && pcoin->GetBlocksToMaturity(*locked_chain) > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain(*locked_chain, false);
            // do not use IX for inputs that have less then 6 blockchain confirmations
            if (fUseIX && nDepth < 6)
                continue;

            // We should not consider coins which aren't at least in our mempool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (nDepth == 0 && !pcoin->InMempool())
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                bool found = false;
                if (nCoinType == ONLY_DENOMINATED) {
                    found = IsDenominatedAmount(pcoin->tx->vout[i].nValue);
                } else if (nCoinType == ONLY_NOT10000IFMN) {
                    found = !(fMasterNode && pcoin->tx->vout[i].nValue == 125000 * COIN);
                } else if (nCoinType == ONLY_NONDENOMINATED_NOT10000IFMN) {
                    if (IsCollateralAmount(pcoin->tx->vout[i].nValue)) continue; // do not use collateral amounts
                    found = !IsDenominatedAmount(pcoin->tx->vout[i].nValue);
                    if (found && fMasterNode) found = pcoin->tx->vout[i].nValue != 125000 * COIN; // do not use Hot MN funds
                } else if (nCoinType == ONLY_125000) {
                    found = pcoin->tx->vout[i].nValue == 125000 * COIN;
                } else {
                    found = true;
                }
                if (!found) continue;

                if (nCoinType == STAKABLE_COINS) {
                    if (pcoin->tx->vout[i].IsZerocoinMint())
                        continue;
                }

                isminetype mine = IsMine(pcoin->tx->vout[i]);
                if (IsSpent(*locked_chain, wtxid, i))
                    continue;
                if (mine == ISMINE_NO)
                    continue;

                if ((mine == ISMINE_MULTISIG || mine == ISMINE_SPENDABLE) && nWatchonlyConfig == 2)
                    continue;

                if (mine == ISMINE_WATCH_ONLY && nWatchonlyConfig == 1)
                    continue;

                if (IsLockedCoin((*it).first, i) && nCoinType != ONLY_125000)
                    continue;
                if (pcoin->tx->vout[i].nValue <= 0 && !fIncludeZeroValue)
                    continue;
                if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected((*it).first, i))
                    continue;

                bool fIsSpendable = false;
                if ((mine & ISMINE_SPENDABLE) != ISMINE_NO)
                    fIsSpendable = true;
                if ((mine & ISMINE_MULTISIG) != ISMINE_NO)
                    fIsSpendable = true;

                bool solvable = IsSolvable(*this, pcoin->tx->vout[i].scriptPubKey);
                bool safeTx = pcoin->IsTrusted(*locked_chain);

                vCoins.emplace_back(COutput(pcoin, i, nDepth, fIsSpendable, solvable, safeTx));
            }
        }
    }
}

map<CBitcoinAddress, std::vector<COutput> > CWallet::AvailableCoinsByAddress(bool fConfirmed, CAmount maxCoinValue)
{
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, fConfirmed);

    map<CBitcoinAddress, std::vector<COutput> > mapCoins;
    for (COutput out: vCoins) {
        if (maxCoinValue > 0 && out.tx->tx->vout[out.i].nValue > maxCoinValue)
            continue;

        CTxDestination address;
        if (!ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, address))
            continue;

        mapCoins[CBitcoinAddress(address)].push_back(out);
    }

    return mapCoins;
}

static void ApproximateBestSubset(std::vector<std::pair<CAmount, pair<const CWalletTx*, unsigned int> > > vValue, const CAmount& nTotalLower, const CAmount& nTargetValue, std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++) {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++) {
            for (unsigned int i = 0; i < vValue.size(); i++) {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand() & 1 : !vfIncluded[i]) {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue) {
                        fReachedTarget = true;
                        if (nTotal < nBest) {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}


// TODO: find appropriate place for this sort function
// move denoms down
bool less_then_denom(const COutput& out1, const COutput& out2)
{
    const CWalletTx* pcoin1 = out1.tx;
    const CWalletTx* pcoin2 = out2.tx;

    bool found1 = false;
    bool found2 = false;
    for (CAmount d: obfuScationDenominations) // loop through predefined denoms
    {
        if (pcoin1->tx->vout[out1.i].nValue == d) found1 = true;
        if (pcoin2->tx->vout[out2.i].nValue == d) found2 = true;
    }
    return (!found1 && found2);
}

bool CWallet::SelectStakeCoins(std::list<std::unique_ptr<CStakeInput> >& listInputs, CAmount nTargetAmount)
{
    auto locked_chain = chain().lock();
    LOCK(cs_main);
    //Add WSP
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, NULL, false, STAKABLE_COINS);
    CAmount nAmountSelected = 0;
    if (gArgs.GetBoolArg("-wspstake", true)) {
        for (const COutput &out : vCoins) {
            //make sure not to outrun target amount
            if (nAmountSelected + out.tx->tx->vout[out.i].nValue > nTargetAmount)
                continue;

            //if zerocoinspend, then use the block time
            int64_t nTxTime = out.tx->GetTxTime();
            if (out.tx->tx->IsZerocoinSpend()) {
                if (!out.tx->IsInMainChain(*locked_chain))
                    continue;
                nTxTime = mapBlockIndex.at(out.tx->hashBlock)->GetBlockTime();
            }

            //check for min age
            if (GetAdjustedTime() - nTxTime < GetStakeMinAge())
                continue;

            //check that it is matured
            if (out.nDepth < (out.tx->tx->IsCoinStake() ? Params().COINBASE_MATURITY() : 10))
                continue;

            //add to our stake set
            nAmountSelected += out.tx->tx->vout[out.i].nValue;

            std::unique_ptr<CWspStake> input(new CWspStake());
            input->SetInput((CTransaction) *out.tx->tx, out.i);
            listInputs.emplace_back(std::move(input));
        }
    }

    //zWSP
    if (gArgs.GetBoolArg("-zwspstake", true) && chainActive.Height() > Params().NEW_PROTOCOLS_STARTHEIGHT() && !IsSporkActive(SPORK_16_ZEROCOIN_MAINTENANCE_MODE)) {
        //Only update zWSP set once per update interval
        bool fUpdate = false;
        static int64_t nTimeLastUpdate = 0;
        if (GetAdjustedTime() - nTimeLastUpdate > nStakeSetUpdateTime) {
            fUpdate = true;
            nTimeLastUpdate = GetAdjustedTime();
        }

        set<CMintMeta> setMints = zwspTracker->ListMints(true, true, fUpdate);
        for (auto meta : setMints) {
            if (meta.hashStake == 0) {
                CZerocoinMint mint;
                if (GetMint(meta.hashSerial, mint)) {
                    uint256 hashStake = mint.GetSerialNumber().getuint256();
                    hashStake = Hash(hashStake.begin(), hashStake.end());
                    meta.hashStake = hashStake;
                    zwspTracker->UpdateState(meta);
                }
            }
            if (meta.nVersion < CZerocoinMint::STAKABLE_VERSION)
                continue;
            if (meta.nHeight < chainActive.Height() - Params().Zerocoin_RequiredStakeDepth()) {
                std::unique_ptr<CZWspStake> input(new CZWspStake(meta.denom, meta.hashStake));
                listInputs.emplace_back(std::move(input));
            }
        }
    }

    return true;
}

bool CWallet::MintableCoins()
{
    auto locked_chain = chain().lock();
    LOCK(cs_main);
    CAmount nBalance = GetBalance();
    CAmount nZwspBalance = GetZerocoinBalance(false);

    // Regular WSP
    if (nBalance > 0) {
        if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
            return error("%s : invalid reserve balance amount", __func__);
        if (nBalance <= nReserveBalance)
            return false;

        std::vector<COutput> vCoins;
        AvailableCoins(vCoins, true);

        for (const COutput& out : vCoins) {
            int64_t nTxTime = out.tx->GetTxTime();
            if (out.tx->tx->IsZerocoinSpend()) {
                if (!out.tx->IsInMainChain(*locked_chain))
                    continue;
                nTxTime = mapBlockIndex.at(out.tx->hashBlock)->GetBlockTime();
            }

            if (GetAdjustedTime() - nTxTime > GetStakeMinAge())
                return true;
        }
    }

    // zWSP
    if (nZwspBalance > 0) {
        set<CMintMeta> setMints = zwspTracker->ListMints(true, true, true);
        for (auto mint : setMints) {
            if (mint.nVersion < CZerocoinMint::STAKABLE_VERSION)
                continue;
            if (mint.nHeight > chainActive.Height() - Params().Zerocoin_RequiredStakeDepth())
                continue;
           return true;
        }
    }

    return false;
}

bool CWallet::SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<CAmount, pair<const CWalletTx*, unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    std::vector<std::pair<CAmount, pair<const CWalletTx*, unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    // move denoms down on the list
    sort(vCoins.begin(), vCoins.end(), less_then_denom);

    // try to find nondenom first to prevent unneeded spending of mixed coins
    for (unsigned int tryDenom = 0; tryDenom < 2; tryDenom++) {
        if (fDebug) LogPrint(BCLog::SELECTCOINS, "tryDenom: %d\n", tryDenom);
        vValue.clear();
        nTotalLower = 0;
        for (const COutput& output: vCoins) {
            if (!output.fSpendable)
                continue;

            const CWalletTx* pcoin = output.tx;

            //            if (fDebug) LogPrint(BCLog::SELECTCOINS, "value %s confirms %d\n", FormatMoney(pcoin->tx->vout[output.i].nValue), output.nDepth);
            if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
                continue;

            int i = output.i;
            CAmount n = pcoin->tx->vout[i].nValue;
            if (tryDenom == 0 && IsDenominatedAmount(n)) continue; // we don't want denom values on first run

            pair<CAmount, pair<const CWalletTx*, unsigned int> > coin = make_pair(n, make_pair(pcoin, i));

            if (n == nTargetValue) {
                setCoinsRet.insert(coin.second);
                nValueRet += coin.first;
                return true;
            } else if (n < nTargetValue + CENT) {
                vValue.push_back(coin);
                nTotalLower += n;
            } else if (n < coinLowestLarger.first) {
                coinLowestLarger = coin;
            }
        }

        if (nTotalLower == nTargetValue) {
            for (unsigned int i = 0; i < vValue.size(); ++i) {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }
            return true;
        }

        if (nTotalLower < nTargetValue) {
            if (coinLowestLarger.second.first == NULL) // there is no input larger than nTargetValue
            {
                if (tryDenom == 0)
                    // we didn't look at denom yet, let's do it
                    continue;
                else
                    // we looked at everything possible and didn't find anything, no luck
                    return false;
            }
            setCoinsRet.insert(coinLowestLarger.second);
            nValueRet += coinLowestLarger.first;
            return true;
        }

        // nTotalLower > nTargetValue
        break;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest)) {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    } else {
        std::string s = "CWallet::SelectCoinsMinConf best subset: ";
        for (unsigned int i = 0; i < vValue.size(); i++) {
            if (vfBest[i]) {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
                s += FormatMoney(vValue[i].first) + " ";
            }
        }
        LogPrintf("%s - total %s\n", s, FormatMoney(nBest));
    }

    return true;
}

bool CWallet::SelectCoins(const CAmount& nTargetValue, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX) const
{
    // Note: this function should never be used for "always free" tx types like dstx

    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl, false, coin_type, useIX);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected()) {
        for (const COutput& out: vCoins) {
            if (!out.fSpendable)
                continue;

            if (coin_type == ONLY_DENOMINATED) {
                CTxIn vin = CTxIn(out.tx->tx->GetHash(), out.i);
                int rounds = GetInputObfuscationRounds(vin);
                // make sure it's actually anonymized
                if (rounds < nZeromintPercentage) continue;
            }

            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.insert(std::make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    //if we're doing only denominated, we need to round up to the nearest .1 WSP
    if (coin_type == ONLY_DENOMINATED) {
        // Make outputs by looping through denominations, from large to small
        for (CAmount v: obfuScationDenominations) {
            for (const COutput& out: vCoins) {
                if (out.tx->tx->vout[out.i].nValue == v                                               //make sure it's the denom we're looking for
                    && nValueRet + out.tx->tx->vout[out.i].nValue < nTargetValue + (0.1 * COIN) + 100 //round the amount up to .1 WSP over
                    ) {
                    CTxIn vin = CTxIn(out.tx->tx->GetHash(), out.i);
                    int rounds = GetInputObfuscationRounds(vin);
                    // make sure it's actually anonymized
                    if (rounds < nZeromintPercentage) continue;
                    nValueRet += out.tx->tx->vout[out.i].nValue;
                    setCoinsRet.insert(std::make_pair(out.tx, out.i));
                }
            }
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet)));
}

struct CompareByPriority {
    bool operator()(const COutput& t1,
        const COutput& t2) const
    {
        return t1.Priority() > t2.Priority();
    }
};

bool CWallet::SelectCoinsByDenominations(int nDenom, CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& vCoinsRet, std::vector<COutput>& vCoinsRet2, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax)
{
    vCoinsRet.clear();
    nValueRet = 0;

    vCoinsRet2.clear();
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, NULL, false, ONLY_DENOMINATED);

    std::random_shuffle(vCoins.rbegin(), vCoins.rend());

    //keep track of each denomination that we have
    bool fFound10000 = false;
    bool fFound1000 = false;
    bool fFound100 = false;
    bool fFound10 = false;
    bool fFound1 = false;
    bool fFoundDot1 = false;

    //Check to see if any of the denomination are off, in that case mark them as fulfilled
    if (!(nDenom & (1 << 0))) fFound10000 = true;
    if (!(nDenom & (1 << 1))) fFound1000 = true;
    if (!(nDenom & (1 << 2))) fFound100 = true;
    if (!(nDenom & (1 << 3))) fFound10 = true;
    if (!(nDenom & (1 << 4))) fFound1 = true;
    if (!(nDenom & (1 << 5))) fFoundDot1 = true;

    for (const COutput& out: vCoins) {
        // masternode-like input should not be selected by AvailableCoins now anyway
        //if(out.tx->tx->vout[out.i].nValue == 10000*COIN) continue;
        if (nValueRet + out.tx->tx->vout[out.i].nValue <= nValueMax) {
            bool fAccepted = false;

            // Function returns as follows:
            //
            // bit 0 - 10000 WSP+1 ( bit on if present )
            // bit 1 - 1000 WSP+1
            // bit 2 - 100 WSP+1
            // bit 3 - 10 WSP+1
            // bit 4 - 1 WSP+1
            // bit 5 - .1 WSP+1

            CTxIn vin = CTxIn(out.tx->tx->GetHash(), out.i);

            int rounds = GetInputObfuscationRounds(vin);
            if (rounds >= nObfuscationRoundsMax) continue;
            if (rounds < nObfuscationRoundsMin) continue;

            if (fFound10000 && fFound1000 && fFound100 && fFound10 && fFound1 && fFoundDot1) { //if fulfilled
                //we can return this for submission
                if (nValueRet >= nValueMin) {
                    //random reduce the max amount we'll submit for anonymity
                    nValueMax -= (rand() % (nValueMax / 5));
                    //on average use 50% of the inputs or less
                    int r = (rand() % (int)vCoins.size());
                    if ((int)vCoinsRet.size() > r) return true;
                }
                //Denomination criterion has been met, we can take any matching denominations
                if ((nDenom & (1 << 0)) && out.tx->tx->vout[out.i].nValue == ((10000 * COIN) + 10000000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 1)) && out.tx->tx->vout[out.i].nValue == ((1000 * COIN) + 1000000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 2)) && out.tx->tx->vout[out.i].nValue == ((100 * COIN) + 100000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 3)) && out.tx->tx->vout[out.i].nValue == ((10 * COIN) + 10000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 4)) && out.tx->tx->vout[out.i].nValue == ((1 * COIN) + 1000)) {
                    fAccepted = true;
                } else if ((nDenom & (1 << 5)) && out.tx->tx->vout[out.i].nValue == ((.1 * COIN) + 100)) {
                    fAccepted = true;
                }
            } else {
                //Criterion has not been satisfied, we will only take 1 of each until it is.
                if ((nDenom & (1 << 0)) && out.tx->tx->vout[out.i].nValue == ((10000 * COIN) + 10000000)) {
                    fAccepted = true;
                    fFound10000 = true;
                } else if ((nDenom & (1 << 1)) && out.tx->tx->vout[out.i].nValue == ((1000 * COIN) + 1000000)) {
                    fAccepted = true;
                    fFound1000 = true;
                } else if ((nDenom & (1 << 2)) && out.tx->tx->vout[out.i].nValue == ((100 * COIN) + 100000)) {
                    fAccepted = true;
                    fFound100 = true;
                } else if ((nDenom & (1 << 3)) && out.tx->tx->vout[out.i].nValue == ((10 * COIN) + 10000)) {
                    fAccepted = true;
                    fFound10 = true;
                } else if ((nDenom & (1 << 4)) && out.tx->tx->vout[out.i].nValue == ((1 * COIN) + 1000)) {
                    fAccepted = true;
                    fFound1 = true;
                } else if ((nDenom & (1 << 5)) && out.tx->tx->vout[out.i].nValue == ((.1 * COIN) + 100)) {
                    fAccepted = true;
                    fFoundDot1 = true;
                }
            }
            if (!fAccepted) continue;

            vin.prevPubKey = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += out.tx->tx->vout[out.i].nValue;
            vCoinsRet.push_back(vin);
            vCoinsRet2.push_back(out);
        }
    }

    return (nValueRet >= nValueMin && fFound10000 && fFound1000 && fFound100 && fFound10 && fFound1 && fFoundDot1);
}

bool CWallet::SelectCoinsDark(CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax) const
{
    CCoinControl* coinControl = nullptr;

    setCoinsRet.clear();
    nValueRet = 0;

    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl, false, nObfuscationRoundsMin < 0 ? ONLY_NONDENOMINATED_NOT10000IFMN : ONLY_DENOMINATED);

    set<pair<const CWalletTx*, unsigned int> > setCoinsRet2;

    //order the array so largest nondenom are first, then denominations, then very small inputs.
    sort(vCoins.rbegin(), vCoins.rend(), CompareByPriority());

    for (const COutput& out: vCoins) {
        //do not allow inputs less than 1 CENT
        if (out.tx->tx->vout[out.i].nValue < CENT) continue;
        //do not allow collaterals to be selected
        if (IsCollateralAmount(out.tx->tx->vout[out.i].nValue)) continue;
        if (fMasterNode && out.tx->tx->vout[out.i].nValue == 125000 * COIN) continue; //masternode input

        if (nValueRet + out.tx->tx->vout[out.i].nValue <= nValueMax) {
            CTxIn vin = CTxIn(out.tx->tx->GetHash(), out.i);

            int rounds = GetInputObfuscationRounds(vin);
            if (rounds >= nObfuscationRoundsMax) continue;
            if (rounds < nObfuscationRoundsMin) continue;

            vin.prevPubKey = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.push_back(vin);
            setCoinsRet2.insert(std::make_pair(out.tx, out.i));
        }
    }

    // if it's more than min, we're good to return
    if (nValueRet >= nValueMin) return true;

    return false;
}

bool CWallet::SelectCoinsCollateral(std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet) const
{
    std::vector<COutput> vCoins;

    //LogPrintf(" selecting coins for collateral\n");
    AvailableCoins(vCoins);

    //LogPrintf("found coins %d\n", (int)vCoins.size());

    set<pair<const CWalletTx*, unsigned int> > setCoinsRet2;

    for (const COutput& out: vCoins) {
        // collateral inputs will always be a multiple of DARSEND_COLLATERAL, up to five
        if (IsCollateralAmount(out.tx->tx->vout[out.i].nValue)) {
            CTxIn vin = CTxIn(out.tx->tx->GetHash(), out.i);

            vin.prevPubKey = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.push_back(vin);
            setCoinsRet2.insert(std::make_pair(out.tx, out.i));
            return true;
        }
    }

    return false;
}

int CWallet::CountInputsWithAmount(CAmount nInputAmount)
{
    CAmount nTotal = 0;
    {
        auto locked_chain = chain().lock();
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted(*locked_chain)) {
                int nDepth = pcoin->GetDepthInMainChain(*locked_chain, false);

                for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                    bool solvable = IsSolvable(*this, pcoin->tx->vout[i].scriptPubKey);
                    bool safeTx = pcoin->IsTrusted(*locked_chain);

                    COutput out = COutput(pcoin, i, nDepth, true, solvable, safeTx);
                    CTxIn vin = CTxIn(out.tx->tx->GetHash(), out.i);

                    if (out.tx->tx->vout[out.i].nValue != nInputAmount) continue;
                    if (!IsDenominatedAmount(pcoin->tx->vout[i].nValue)) continue;
                    if (IsSpent(*locked_chain, out.tx->tx->GetHash(), i) || IsMine(pcoin->tx->vout[i]) != ISMINE_SPENDABLE || !IsDenominated(vin)) continue;

                    nTotal++;
                }
            }
        }
    }

    return nTotal;
}

bool CWallet::HasCollateralInputs(bool fOnlyConfirmed) const
{
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, fOnlyConfirmed);

    int nFound = 0;
    for (const COutput& out: vCoins)
        if (IsCollateralAmount(out.tx->tx->vout[out.i].nValue)) nFound++;

    return nFound > 0;
}

bool CWallet::IsCollateralAmount(CAmount nInputAmount) const
{
    return nInputAmount != 0 && nInputAmount % OBFUSCATION_COLLATERAL == 0 && nInputAmount < OBFUSCATION_COLLATERAL * 5 && nInputAmount > OBFUSCATION_COLLATERAL;
}

bool CWallet::CreateCollateralTransaction(CMutableTransaction& txCollateral, std::string& strReason)
{
    /*
        To doublespend a collateral transaction, it will require a fee higher than this. So there's
        still a significant cost.
    */
    CAmount nFeeRet = 1 * COIN;

    txCollateral.vin.clear();
    txCollateral.vout.clear();

    CReserveKey reservekey(this);
    CAmount nValueIn2 = 0;
    std::vector<CTxIn> vCoinsCollateral;

    if (!SelectCoinsCollateral(vCoinsCollateral, nValueIn2)) {
        strReason = "Error: Obfuscation requires a collateral transaction and could not locate an acceptable input!";
        return false;
    }

    // make our change address
    CScript scriptChange;
    CPubKey vchPubKey;
    assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
    scriptChange = GetScriptForDestination(vchPubKey.GetID());
    reservekey.KeepKey();

    for (CTxIn v: vCoinsCollateral)
        txCollateral.vin.push_back(v);

    if (nValueIn2 - OBFUSCATION_COLLATERAL - nFeeRet > 0) {
        //pay collateral charge in fees
        CTxOut vout3 = CTxOut(nValueIn2 - OBFUSCATION_COLLATERAL, scriptChange);
        txCollateral.vout.push_back(vout3);
    }

    int vinNumber = 0;
    for (CTxIn v: txCollateral.vin) {
        const CTxOut& txout = txCollateral.vout[v.prevout.n];
        if (!SignSignature(*this, v.prevPubKey, txCollateral, vinNumber, txout.nValue, int(SIGHASH_ALL | SIGHASH_ANYONECANPAY))) {
            for (CTxIn v: vCoinsCollateral)
                UnlockCoin(v.prevout);

            strReason = "CObfuscationPool::Sign - Unable to sign collateral transaction! \n";
            return false;
        }
        vinNumber++;
    }

    return true;
}

bool CWallet::GetBudgetSystemCollateralTX(CWalletTx& tx, uint256 hash, bool useIX)
{
    // make our change address
    CReserveKey reservekey(pwalletMain);

    CScript scriptChange;
    scriptChange << OP_RETURN << ToByteVector(hash);

    CAmount nFeeRet = 0;
    std::string strFail = "";
    std::vector<std::pair<CScript, CAmount> > vecSend;
    vecSend.push_back(std::make_pair(scriptChange, BUDGET_FEE_TX_OLD)); // Old 50 WSP collateral

    CCoinControl* coinControl = nullptr;
    bool success = CreateTransaction(vecSend, tx, reservekey, nFeeRet, strFail, coinControl, ALL_COINS, useIX, (CAmount)0);
    if (!success) {
        LogPrintf("GetBudgetSystemCollateralTX: Error - %s\n", strFail);
        return false;
    }

    return true;
}

bool CWallet::GetBudgetFinalizationCollateralTX(CWalletTx& tx, uint256 hash, bool useIX)
{
    // make our change address
    CReserveKey reservekey(pwalletMain);

    CScript scriptChange;
    scriptChange << OP_RETURN << ToByteVector(hash);

    CAmount nFeeRet = 0;
    std::string strFail = "";
    std::vector<std::pair<CScript, CAmount> > vecSend;
    vecSend.push_back(std::make_pair(scriptChange, BUDGET_FEE_TX)); // New 5 WSP collateral

    CCoinControl* coinControl = nullptr;
    bool success = CreateTransaction(vecSend, tx, reservekey, nFeeRet, strFail, coinControl, ALL_COINS, useIX, (CAmount)0);
    if (!success) {
        LogPrintf("GetBudgetSystemCollateralTX: Error - %s\n", strFail);
        return false;
    }

    return true;
}

bool CWallet::ConvertList(std::vector<CTxIn> vCoins, std::vector<CAmount>& vecAmounts)
{
    for (CTxIn i: vCoins) {
        if (mapWallet.count(i.prevout.hash)) {
            CWalletTx& wtx = mapWallet[i.prevout.hash];
            if (i.prevout.n < wtx.tx->vout.size()) {
                vecAmounts.push_back(wtx.tx->vout[i.prevout.n].nValue);
            }
        } else {
            LogPrintf("ConvertList -- Couldn't find transaction\n");
        }
    }
    return true;
}

bool CWallet::CreateTransaction(const std::vector<std::pair<CScript, CAmount> >& vecSend,
    CWalletTx& wtxNew,
    CReserveKey& reservekey,
    CAmount& nFeeRet,
    std::string& strFailReason,
    const CCoinControl* coinControl,
    AvailableCoinsType coin_type,
    bool useIX,
    CAmount nFeePay)
{
    if (useIX && nFeePay < CENT) nFeePay = CENT;

    CAmount nValue = 0;

    for (const std::pair<CScript, CAmount> & s: vecSend) {
        if (nValue < 0) {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;

    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        {
            nFeeRet = 0;
            if (nFeePay > 0) nFeeRet = nFeePay;
            while (true) {
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;

                CAmount nTotalValue = nValue + nFeeRet;
                double dPriority = 0;

                // vouts to the payees
                if (coinControl && !coinControl->fSplitBlock) {
                    for (const std::pair<CScript, CAmount> & s: vecSend) {
                        CTxOut txout(s.second, s.first);
                        if (IsDust(txout, ::minRelayTxFee)) {
                            strFailReason = _("Transaction amount too small");
                            return false;
                        }
                        txNew.vout.push_back(txout);
                    }
                } else //UTXO Splitter Transaction
                {
                    int nSplitBlock;

                    if (coinControl)
                        nSplitBlock = coinControl->nSplitBlock;
                    else
                        nSplitBlock = 1;

                    for (const std::pair<CScript, CAmount> & s: vecSend) {
                        for (int i = 0; i < nSplitBlock; i++) {
                            if (i == nSplitBlock - 1) {
                                uint64_t nRemainder = s.second % nSplitBlock;
                                txNew.vout.push_back(CTxOut((s.second / nSplitBlock) + nRemainder, s.first));
                            } else
                                txNew.vout.push_back(CTxOut(s.second / nSplitBlock, s.first));
                        }
                    }
                }

                // Choose coins to use
                set<pair<const CWalletTx*, unsigned int> > setCoins;
                CAmount nValueIn = 0;

                if (!SelectCoins(nTotalValue, setCoins, nValueIn, coinControl, coin_type, useIX)) {
                    if (coin_type == ALL_COINS) {
                        strFailReason = _("Insufficient funds.");
                    } else if (coin_type == ONLY_NOT10000IFMN) {
                        strFailReason = _("Unable to locate enough funds for this transaction that are not equal 10000 WSP.");
                    } else if (coin_type == ONLY_NONDENOMINATED_NOT10000IFMN) {
                        strFailReason = _("Unable to locate enough Obfuscation non-denominated funds for this transaction that are not equal 10000 WSP.");
                    } else {
                        strFailReason = _("Unable to locate enough Obfuscation denominated funds for this transaction.");
                        strFailReason += " " + _("Obfuscation uses exact denominated amounts to send funds, you might simply need to anonymize some more coins.");
                    }

                    if (useIX) {
                        strFailReason += " " + _("SwiftX requires inputs with at least 6 confirmations, you might need to wait a few minutes and try again.");
                    }

                    return false;
                }


                for (std::pair<const CWalletTx*, unsigned int> pcoin: setCoins) {
                    CAmount nCredit = pcoin.first->tx->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain(*locked_chain);
                    if (age != 0)
                        age += 1;
                    dPriority += (double)nCredit * age;
                }

                CAmount nChange = nValueIn - nValue - nFeeRet;

                //over pay for denominated transactions
                if (coin_type == ONLY_DENOMINATED) {
                    nFeeRet += nChange;
                    nChange = 0;
                    wtxNew.mapValue["DS"] = "1";
                }

                if (nChange > 0) {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-wispr-address
                    CScript scriptChange;
                    bool combineChange = false;

                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange)) {
                        scriptChange = GetScriptForDestination(coinControl->destChange);

                        std::vector<CTxOut>::iterator it = txNew.vout.begin();
                        while (it != txNew.vout.end()) {
                            if (scriptChange == it->scriptPubKey) {
                                it->nValue += nChange;
                                nChange = 0;
                                reservekey.ReturnKey();
                                combineChange = true;
                                break;
                            }
                            ++it;
                        }
                    }

                    // no coin control: send change to newly generated address
                    else {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey);
                        assert(ret); // should never fail, as we just unlocked

                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                    }

                    if (!combineChange) {
                        CTxOut newTxOut(nChange, scriptChange);

                        // Never create dust outputs; if we would, just
                        // add the dust to the fee.
                        if (IsDust(newTxOut, ::minRelayTxFee)) {
                            nFeeRet += nChange;
                            nChange = 0;
                            reservekey.ReturnKey();
                        } else {
                            // Insert change txn at random position:
                            std::vector<CTxOut>::iterator position = txNew.vout.begin() + GetRandInt(txNew.vout.size() + 1);
                            txNew.vout.insert(position, newTxOut);
                        }
                    }
                } else
                    reservekey.ReturnKey();

                // Fill vin
                for (const std::pair<const CWalletTx*, unsigned int> & coin: setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->tx->GetHash(), coin.second));

                // Sign
                int nIn = 0;
                for (const std::pair<const CWalletTx*, unsigned int>& coin : setCoins) {
                    if (!SignSignature(*this, coin.first->tx->vout[nIn].scriptPubKey, txNew, nIn, coin.first->tx->vout[nIn].nValue, SIGHASH_ALL)) {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                    nIn++;
                }
                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransactionRef*>(&wtxNew.tx) = MakeTransactionRef(std::move(txNew));

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, PROTOCOL_VERSION);
                if (nBytes >= MAX_STANDARD_TX_SIZE) {
                    strFailReason = _("Transaction too large");
                    return false;
                }
                dPriority = wtxNew.tx->ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE) {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = ::feeEstimator.estimatePriority(nTxConfirmTarget);
                    // Not enough mempool history to estimate: use hard-coded AllowFree.
                    if (dPriorityNeeded <= 0 && AllowFree(dPriority))
                        break;

                    // Small enough, and priority high enough, to send for free
                    if (dPriorityNeeded > 0 && dPriority >= dPriorityNeeded)
                        break;
                }
                FeeCalculation feeCalc;
                CAmount nFeeNeeded =  max(nFeePay, GetMinimumFee(*this, nBytes, *coinControl, &feeCalc));
//                CAmount nFeeNeeded = max(nFeePay, GetMinimumFee(nBytes, nTxConfirmTarget, mempool));

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes)) {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded) // Done, enough fee included
                    break;

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }
    return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, const CAmount& nValue, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX, CAmount nFeePay)
{
    std::vector<std::pair<CScript, CAmount> > vecSend;
    vecSend.push_back(std::make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, strFailReason, coinControl, coin_type, useIX, nFeePay);
}

// ppcoin: create coin stake transaction
bool CWallet::CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, unsigned int& nTxNewTime)
{
    // The following split & combine thresholds are important to security
    // Should not be adjusted if you don't understand the consequences
    //int64_t nCombineThreshold = 0;
    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    CAmount nBalance = GetBalance();

    if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
        return error("CreateCoinStake : invalid reserve balance amount");

    if (nBalance > 0 && nBalance <= nReserveBalance)
        return false;

    // Get the list of stakable inputs
    std::list<std::unique_ptr<CStakeInput> > listInputs;
    if (!SelectStakeCoins(listInputs, nBalance - nReserveBalance))
        return false;

    if (listInputs.empty())
        return false;

    if (GetAdjustedTime() - chainActive.Tip()->GetBlockTime() < 60)
        MilliSleep(10000);

    CAmount nCredit;
    CScript scriptPubKeyKernel;
    bool fKernelFound = false;
    for (std::unique_ptr<CStakeInput>& stakeInput : listInputs) {
        nCredit = 0;
        // Make sure the wallet is unlocked and shutdown hasn't been requested
        if (IsLocked() || ShutdownRequested())
            return false;

        //make sure that enough time has elapsed between
        CBlockIndex* pindex = stakeInput->GetIndexFrom();
        if (!pindex || pindex->nHeight < 1) {
            LogPrintf("*** no pindexfrom\n");
            continue;
        }

        // Read block header
        CBlockHeader block = pindex->GetBlockHeader();
        uint256 hashProofOfStake = 0;
        nTxNewTime = GetAdjustedTime();

        //iterates each utxo inside of CheckStakeKernelHash()
        if (Stake(stakeInput.get(), nBits, block.GetBlockTime(), nTxNewTime, hashProofOfStake)) {
            LOCK(cs_main);
            //Double check that this will pass time requirements
            if (nTxNewTime <= chainActive.Tip()->GetMedianTimePast()) {
                LogPrintf("CreateCoinStake() : kernel found, but it is too far in the past \n");
                continue;
            }

            // Found a kernel
            LogPrintf("CreateCoinStake : kernel found\n");
            nCredit += stakeInput->GetValue();

            // Calculate reward
            CAmount nReward;
            nReward = GetBlockValue(chainActive.Height() + 1);
            nCredit += nReward;

            // Create the output transaction(s)
            std::vector<CTxOut> vout;
            if (!stakeInput->CreateTxOuts(this, vout, nCredit)) {
                LogPrintf("%s : failed to get scriptPubKey\n", __func__);
                continue;
            }
            txNew.vout.insert(txNew.vout.end(), vout.begin(), vout.end());

            CAmount nMinFee = 0;
            if (!stakeInput->IsZWSP()) {
                // Set output amount
                if (txNew.vout.size() == 3) {
                    txNew.vout[1].nValue = ((nCredit - nMinFee) / 2 / CENT) * CENT;
                    txNew.vout[2].nValue = nCredit - nMinFee - txNew.vout[1].nValue;
                } else
                    txNew.vout[1].nValue = nCredit - nMinFee;
            }

            // Limit size
            unsigned int nBytes = ::GetSerializeSize(txNew, PROTOCOL_VERSION);
            if (nBytes >= DEFAULT_BLOCK_MAX_SIZE / 5)
                return error("CreateCoinStake : exceeded coinstake size limit");

            //Masternode payment
            FillBlockPayee(txNew, nMinFee, true, stakeInput->IsZWSP());

            uint256 hashTxOut = txNew.GetHash();
            CTxIn in;
            if (!stakeInput->CreateTxIn(this, in, hashTxOut)) {
                LogPrintf("%s : failed to create TxIn\n", __func__);
                txNew.vin.clear();
                txNew.vout.clear();
                continue;
            }
            txNew.vin.emplace_back(in);

            //Mark mints as spent
            if (stakeInput->IsZWSP()) {
                CZWspStake* z = (CZWspStake*)stakeInput.get();
                if (!z->MarkSpent(this, txNew.GetHash()))
                    return error("%s: failed to mark mint as used\n", __func__);
            }

            fKernelFound = true;
            break;
        }
        if (fKernelFound)
            break; // if kernel is found stop searching
    }
    if (!fKernelFound)
        return false;

    // Sign for WSP
    int nIn = 0;
    if (!txNew.vin[0].scriptSig.IsZerocoinSpend()) {
        for (CTxIn txIn : txNew.vin) {
            const CWalletTx *wtx = GetWalletTx(txIn.prevout.hash);
            if (!SignSignature(*this, wtx->tx->vout[nIn].scriptPubKey, txNew, nIn, wtx->tx->vout[nIn].nValue, SIGHASH_ALL))
                return error("CreateCoinStake : failed to sign coinstake");
            nIn++;
        }
    } else {
        //Update the mint database with tx hash and height
        for (const CTxOut& out : txNew.vout) {
            if (!out.IsZerocoinMint())
                continue;

            libzerocoin::PublicCoin pubcoin(Params().Zerocoin_Params(false));
            CValidationState state;
            if (!TxOutToPublicCoin(out, pubcoin, state))
                return error("%s: extracting pubcoin from txout failed", __func__);

            uint256 hashPubcoin = GetPubCoinHash(pubcoin.getValue());
            if (!zwspTracker->HasPubcoinHash(hashPubcoin))
                return error("%s: could not find pubcoinhash %s in tracker", __func__, hashPubcoin.GetHex());

            CMintMeta meta = zwspTracker->GetMetaFromPubcoin(hashPubcoin);
            meta.txid = txNew.GetHash();
            meta.nHeight = chainActive.Height() + 1;
            if (!zwspTracker->UpdateState(meta))
                return error("%s: failed to update metadata in tracker", __func__);
        }
    }

    // Successfully generated coinstake
    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, std::string strCommand)
{
    {
        auto locked_chain = chain().lock();
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitTransaction:\n%s", wtxNew.tx->ToString());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            WalletBatch* pwalletdb = fFileBacked ? new WalletBatch(*database, "r") : nullptr;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            if (!wtxNew.tx->IsZerocoinSpend()) {
                set<uint256> updated_hahes;
                for (const CTxIn& txin: wtxNew.tx->vin) {
                    // notify only once
                    if (updated_hahes.find(txin.prevout.hash) != updated_hahes.end()) continue;

                    CWalletTx& coin = mapWallet[txin.prevout.hash];
                    coin.BindWallet(this);
                    NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
                    updated_hahes.insert(txin.prevout.hash);
                }
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.tx->GetHash()] = 0;

        // Broadcast
        CValidationState state;
        if (!wtxNew.AcceptToMemoryPool(*locked_chain, state)) {
            // This must not fail. The transaction has already been signed and recorded.
            LogPrintf("CommitTransaction() : Error: Transaction not valid\n");
            return false;
        }
        wtxNew.RelayWalletTransaction(strCommand);
    }
    return true;
}

//bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry, WalletBatch & pwalletdb)
//{
//    if (!pwalletdb.WriteAccountingEntry_Backend(acentry))
//        return false;
//
//    laccentries.push_back(acentry);
//    CAccountingEntry & entry = laccentries.back();
//    wtxOrdered.insert(std::make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
//    wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
//
//    return true;
//}

//CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool)
//{
//    // payTxFee is user-set "I want to pay this much"
//    CAmount nFeeNeeded = payTxFee.GetFee(nTxBytes);
//    // user selected total at least (default=true)
//    if (fPayAtLeastCustomFee && nFeeNeeded > 0 && nFeeNeeded < payTxFee.GetFeePerK())
//        nFeeNeeded = payTxFee.GetFeePerK();
//    // User didn't set: use -txconfirmtarget to estimate...
//    if (nFeeNeeded == 0)
//        nFeeNeeded = pool.estimateFee(nConfirmTarget).GetFee(nTxBytes);
//    // ... unless we don't have enough mempool data, in which case fall
//    // back to a hard-coded fee
//    if (nFeeNeeded == 0)
//        nFeeNeeded = minTxFee.GetFee(nTxBytes);
//    // prevent user from paying a non-sense fee (like 1 satoshi): 0 < fee < minRelayFee
//    if (nFeeNeeded < ::minRelayTxFee.GetFee(nTxBytes))
//        nFeeNeeded = ::minRelayTxFee.GetFee(nTxBytes);
//    // But always obey the maximum
//    if (nFeeNeeded > maxTxFee)
//        nFeeNeeded = maxTxFee;
//    return nFeeNeeded;
//}

CAmount CWallet::GetTotalValue(std::vector<CTxIn> vCoins)
{
    CAmount nTotalValue = 0;
    CWalletTx wtx;
    for (CTxIn i: vCoins) {
        if (mapWallet.count(i.prevout.hash)) {
            CWalletTx& wtx = mapWallet[i.prevout.hash];
            if (i.prevout.n < wtx.tx->vout.size()) {
                nTotalValue += wtx.tx->vout[i.prevout.n].nValue;
            }
        } else {
            LogPrintf("GetTotalValue -- Couldn't find transaction\n");
        }
    }
    return nTotalValue;
}

string CWallet::PrepareObfuscationDenominate(int minRounds, int maxRounds)
{
    if (IsLocked())
        return _("Error: Wallet locked, unable to create transaction!");

    if (obfuScationPool.GetState() != POOL_STATUS_ERROR && obfuScationPool.GetState() != POOL_STATUS_SUCCESS)
        if (obfuScationPool.GetEntriesCount() > 0)
            return _("Error: You already have pending entries in the Obfuscation pool");

    // ** find the coins we'll use
    std::vector<CTxIn> vCoins;
    std::vector<CTxIn> vCoinsResult;
    std::vector<COutput> vCoins2;
    CAmount nValueIn = 0;
    CReserveKey reservekey(this);

    /*
        Select the coins we'll use

        if minRounds >= 0 it means only denominated inputs are going in and coming out
    */
    if (minRounds >= 0) {
        if (!SelectCoinsByDenominations(obfuScationPool.sessionDenom, 0.1 * COIN, OBFUSCATION_POOL_MAX, vCoins, vCoins2, nValueIn, minRounds, maxRounds))
            return _("Error: Can't select current denominated inputs");
    }

    LogPrintf("PrepareObfuscationDenominate - preparing obfuscation denominate . Got: %d \n", nValueIn);

    {
        LOCK(cs_wallet);
        for (CTxIn v: vCoins)
            LockCoin(v.prevout);
    }

    CAmount nValueLeft = nValueIn;
    std::vector<CTxOut> vOut;

    /*
        TODO: Front load with needed denominations (e.g. .1, 1 )
    */

    // Make outputs by looping through denominations: try to add every needed denomination, repeat up to 5-10 times.
    // This way we can be pretty sure that it should have at least one of each needed denomination.
    // NOTE: No need to randomize order of inputs because they were
    // initially shuffled in CWallet::SelectCoinsByDenominations already.
    int nStep = 0;
    int nStepsMax = 5 + GetRandInt(5);
    while (nStep < nStepsMax) {
        for (CAmount v: obfuScationDenominations) {
            // only use the ones that are approved
            bool fAccepted = false;
            if ((obfuScationPool.sessionDenom & (1 << 0)) && v == ((10000 * COIN) + 10000000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 1)) && v == ((1000 * COIN) + 1000000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 2)) && v == ((100 * COIN) + 100000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 3)) && v == ((10 * COIN) + 10000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 4)) && v == ((1 * COIN) + 1000)) {
                fAccepted = true;
            } else if ((obfuScationPool.sessionDenom & (1 << 5)) && v == ((.1 * COIN) + 100)) {
                fAccepted = true;
            }
            if (!fAccepted) continue;

            // try to add it
            if (nValueLeft - v >= 0) {
                // Note: this relies on a fact that both vectors MUST have same size
                std::vector<CTxIn>::iterator it = vCoins.begin();
                std::vector<COutput>::iterator it2 = vCoins2.begin();
                while (it2 != vCoins2.end()) {
                    // we have matching inputs
                    if ((*it2).tx->tx->vout[(*it2).i].nValue == v) {
                        // add new input in resulting vector
                        vCoinsResult.push_back(*it);
                        // remove corresponting items from initial vectors
                        vCoins.erase(it);
                        vCoins2.erase(it2);

                        CScript scriptChange;
                        CPubKey vchPubKey;
                        // use a unique change address
                        assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                        reservekey.KeepKey();

                        // add new output
                        CTxOut o(v, scriptChange);
                        vOut.push_back(o);

                        // subtract denomination amount
                        nValueLeft -= v;

                        break;
                    }
                    ++it;
                    ++it2;
                }
            }
        }

        nStep++;

        if (nValueLeft == 0) break;
    }

    {
        // unlock unused coins
        LOCK(cs_wallet);
        for (CTxIn v: vCoins)
            UnlockCoin(v.prevout);
    }

    if (obfuScationPool.GetDenominations(vOut) != obfuScationPool.sessionDenom) {
        // unlock used coins on failure
        LOCK(cs_wallet);
        for (CTxIn v: vCoinsResult)
            UnlockCoin(v.prevout);
        return "Error: can't make current denominated outputs";
    }

    // randomize the output order
    std::random_shuffle(vOut.begin(), vOut.end());

    // We also do not care about full amount as long as we have right denominations, just pass what we found
    obfuScationPool.SendObfuscationDenominate(vCoinsResult, vOut, nValueIn - nValueLeft, g_connman.get());

    return "";
}

bool CWallet::SetDefaultKey(const CPubKey& vchPubKey)
{
    if (fFileBacked) {
        if (!WalletBatch(*database).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */

set<CTxDestination> CWallet::GetAccountAddresses(string strAccount) const
{
    LOCK(cs_wallet);
    set<CTxDestination> result;
    for (const std::pair<CTxDestination, CAddressBookData> & item: mapAddressBook) {
        const CTxDestination& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

//bool CWallet::UpdatedTransaction(const uint256& hashTx)
//{
//    {
//        LOCK(cs_wallet);
//        // Only notify UI if this transaction is in this wallet
//        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
//        if (mi != mapWallet.end()) {
//            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
//            return true;
//        }
//    }
//    return false;
//}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void>
{
private:
    const CKeyStore& keystore;
    std::vector<CKeyID>& vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore& keystoreIn, std::vector<CKeyID>& vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript& script)
    {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            for (const CTxDestination& dest: vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID& keyId)
    {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID& scriptId)
    {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }
    void operator()(const WitnessV0ScriptHash &none) {}
    void operator()(const WitnessUnknown &none) {}

    void operator()(const CNoDestination& none) {}
};

void CWallet::InitAutoConvertAddresses()
{
    WalletBatch walletdb(*database);
    walletdb.LoadAutoConvertKeys(setAutoConvertAddresses);
}

void CWallet::AutoZeromintForAddress()
{
    auto locked_chain = chain().lock();
    std::map<CTxDestination, CAmount> mapBalances = GetAddressBalances(*locked_chain);
    std::map<CBitcoinAddress, std::vector<COutput> > mapAddressCoins = AvailableCoinsByAddress(true);

    for (auto address : setAutoConvertAddresses) {
        CTxDestination dest = address.Get();

        if (!mapBalances.count(dest) || !mapAddressCoins.count(address))
            continue;

        CAmount nBalance = mapBalances.at(dest);
        if (nBalance <= libzerocoin::ZQ_ONE*COIN)
            continue;

        CAmount nMintAmount = nBalance;
        CAmount nChange = nMintAmount % COIN;
        if (nChange == 0)
            nChange = (99*CENT);
        nMintAmount -= nChange;

        CAmount nSelected = 0;
        std::unique_ptr<CCoinControl> coinControl(new CCoinControl());
        for (auto out : mapAddressCoins.at(address)) {
            COutPoint outPoint(out.tx->tx->GetHash(), out.i);
            coinControl->Select(outPoint);
            nSelected += out.tx->tx->vout[out.i].nValue;
        }

        CreateAutoMintTransaction(nMintAmount, coinControl.get());
    }
}

void CWallet::CreateAutoMintTransaction(const CAmount& nMintAmount, CCoinControl* coinControl)
{
    if (nMintAmount > 0){
        CWalletTx wtx;
        std::vector<CDeterministicMint> vDMints;
        LogPrintf("%s: autominting request amount %s\n", __func__, FormatMoney(nMintAmount));
        std::string strError = pwalletMain->MintZerocoin(nMintAmount, wtx, vDMints, coinControl);

        // Return if something went wrong during minting
        if (strError != ""){
            LogPrintf("CWallet::AutoZeromint(): auto minting failed with error: %s\n", strError);
            return;
        }
        CAmount nZerocoinBalance = GetZerocoinBalance(false);
        CAmount nBalance = GetUnlockedCoins();
        CAmount dPercentage = 100 * (double)nZerocoinBalance / (double)(nZerocoinBalance + nBalance);
        LogPrintf("CWallet::AutoZeromint() @ block %ld: successfully minted %ld zWSP. Current percentage of zWSP: %lf%%\n",
                  chainActive.Tip()->nHeight, nMintAmount, dPercentage);
        // Re-adjust startup time to delay next Automint for 5 minutes
        nStartupTime = GetAdjustedTime();
    }
    else {
        LogPrintf("CWallet::AutoZeromint(): Nothing minted because either not enough funds available or the requested denomination size (%d) is not yet reached.\n", nPreferredDenom);
    }
}

// CWallet::AutoZeromint() gets called with each new incoming block
void CWallet::AutoZeromint()
{
    // Don't bother Autominting if Zerocoin Protocol isn't active
    if (GetAdjustedTime() > GetSporkValue(SPORK_16_ZEROCOIN_MAINTENANCE_MODE)) return;

    // Wait until blockchain + masternodes are fully synced and wallet is unlocked.
    if (IsInitialBlockDownload() || IsLocked()){
        // Re-adjust startup time in case syncing needs a long time.
        nStartupTime = GetAdjustedTime();
        return;
    }

    // After sync wait even more to reduce load when wallet was just started
    int64_t nWaitTime = GetAdjustedTime() - nStartupTime;
    if (nWaitTime < AUTOMINT_DELAY){
        LogPrint(BCLog::ZERO, "CWallet::AutoZeromint(): time since sync-completion or last Automint (%ld sec) < default waiting time (%ld sec). Waiting again...\n", nWaitTime, AUTOMINT_DELAY);
        return;
    }

    // Process Auto Convert Addresses First
    if (fEnableAutoConvert)
        AutoZeromintForAddress();

    if (!fEnableZeromint)
        return;

    CAmount nZerocoinBalance = GetZerocoinBalance(false); //false includes both pending and mature zerocoins. Need total balance for this so nothing is overminted.
    CAmount nBalance = GetUnlockedCoins(); // We only consider unlocked coins, this also excludes masternode-vins
                                           // from being accidentally minted
    CAmount nMintAmount = 0;
    CAmount nToMintAmount = 0;

    // zWSP are integers > 0, so we can't mint 10% of 9 WSP
    if (nBalance < 10){
        LogPrint(BCLog::ZERO, "CWallet::AutoZeromint(): available balance (%ld) too small for minting zWSP\n", nBalance);
        return;
    }

    // Percentage of zWSP we already have
    double dPercentage = 100 * (double)nZerocoinBalance / (double)(nZerocoinBalance + nBalance);

    // Check if minting is actually needed
    if(dPercentage >= nZeromintPercentage){
        LogPrint(BCLog::ZERO, "CWallet::AutoZeromint() @block %ld: percentage of existing zWSP (%lf%%) already >= configured percentage (%d%%). No minting needed...\n",
                  chainActive.Tip()->nHeight, dPercentage, nZeromintPercentage);
        return;
    }

    // zWSP amount needed for the target percentage
    nToMintAmount = ((nZerocoinBalance + nBalance) * nZeromintPercentage / 100);

    // zWSP amount missing from target (must be minted)
    nToMintAmount = (nToMintAmount - nZerocoinBalance) / COIN;

    // Use the biggest denomination smaller than the needed zWSP We'll only mint exact denomination to make minting faster.
    // Exception: for big amounts use 6666 (6666 = 1*5000 + 1*1000 + 1*500 + 1*100 + 1*50 + 1*10 + 1*5 + 1) to create all
    // possible denominations to avoid having 5000 denominations only.
    // If a preferred denomination is used (means nPreferredDenom != 0) do nothing until we have enough WSP to mint this denomination

    if (nPreferredDenom > 0){
        if (nToMintAmount >= nPreferredDenom)
            nToMintAmount = nPreferredDenom;  // Enough coins => mint preferred denomination
        else
            nToMintAmount = 0;                // Not enough coins => do nothing and wait for more coins
    }

    if (nToMintAmount >= ZQ_6666){
        nMintAmount = ZQ_6666;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_FIVE_THOUSAND){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_FIVE_THOUSAND;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_ONE_THOUSAND){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_ONE_THOUSAND;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_FIVE_HUNDRED){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_FIVE_HUNDRED;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_ONE_HUNDRED){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_ONE_HUNDRED;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_FIFTY){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_FIFTY;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_TEN){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_TEN;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_FIVE){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_FIVE;
    } else if (nToMintAmount >= libzerocoin::CoinDenomination::ZQ_ONE){
        nMintAmount = libzerocoin::CoinDenomination::ZQ_ONE;
    } else {
        nMintAmount = 0;
    }

    CreateAutoMintTransaction(nMintAmount*COIN);
}

void CWallet::AutoCombineDust()
{
    auto locked_chain = chain().lock();
    LOCK2(cs_main, cs_wallet);
    if (chainActive.Tip()->nTime < (GetAdjustedTime() - 300) || IsLocked()) {
        return;
    }

    map<CBitcoinAddress, std::vector<COutput> > mapCoinsByAddress = AvailableCoinsByAddress(true, nAutoCombineThreshold * COIN);

    //coins are sectioned by address. This combination code only wants to combine inputs that belong to the same address
    for (map<CBitcoinAddress, std::vector<COutput> >::iterator it = mapCoinsByAddress.begin(); it != mapCoinsByAddress.end(); it++) {
        std::vector<COutput> vCoins, vRewardCoins;
        bool maxSize = false;
        vCoins = it->second;

        // We don't want the tx to be refused for being too large
        // we use 50 bytes as a base tx size (2 output: 2*34 + overhead: 10 -> 90 to be certain)
        unsigned int txSizeEstimate = 90;

        //find masternode rewards that need to be combined
        CCoinControl* coinControl = new CCoinControl();
        CAmount nTotalRewardsValue = 0;
        for (const COutput& out: vCoins) {
            if (!out.fSpendable)
                continue;
            //no coins should get this far if they dont have proper maturity, this is double checking
            if (out.tx->tx->IsCoinStake() && out.tx->GetDepthInMainChain(*locked_chain) < Params().COINBASE_MATURITY() + 1)
                continue;

            COutPoint outpt(out.tx->tx->GetHash(), out.i);
            coinControl->Select(outpt);
            vRewardCoins.push_back(out);
            nTotalRewardsValue += out.Value();

            // Combine to the threshold and not way above
            if (nTotalRewardsValue > nAutoCombineThreshold * COIN)
                break;

            // Around 180 bytes per input. We use 190 to be certain
            txSizeEstimate += 190;
            if (txSizeEstimate >= MAX_STANDARD_TX_SIZE - 200) {
                maxSize = true;
                break;
            }
        }

        //if no inputs found then return
        if (!coinControl->HasSelected())
            continue;

        //we cannot combine one coin with itself
        if (vRewardCoins.size() <= 1)
            continue;

        std::vector<std::pair<CScript, CAmount> > vecSend;
        CScript scriptPubKey = GetScriptForDestination(it->first.Get());
        vecSend.push_back(std::make_pair(scriptPubKey, nTotalRewardsValue));

        //Send change to same address
        CTxDestination destMyAddress;
        if (!ExtractDestination(scriptPubKey, destMyAddress)) {
            LogPrintf("AutoCombineDust: failed to extract destination\n");
            continue;
        }
        coinControl->destChange = destMyAddress;

        // Create the transaction and commit it to the network
        CWalletTx wtx;
        CReserveKey keyChange(this); // this change address does not end up being used, because change is returned with coin control switch
        std::string strErr;
        CAmount nFeeRet = 0;

        // 10% safety margin to avoid "Insufficient funds" errors
        vecSend[0].second = nTotalRewardsValue - (nTotalRewardsValue / 10);

        if (!CreateTransaction(vecSend, wtx, keyChange, nFeeRet, strErr, coinControl, ALL_COINS, false, CAmount(0))) {
            LogPrintf("AutoCombineDust createtransaction failed, reason: %s\n", strErr);
            continue;
        }

        //we don't combine below the threshold unless the fees are 0 to avoid paying fees over fees over fees
        if (!maxSize && nTotalRewardsValue < nAutoCombineThreshold * COIN && nFeeRet > 0)
            continue;

        if (!CommitTransaction(wtx, keyChange)) {
            LogPrintf("AutoCombineDust transaction commit failed\n");
            continue;
        }

        LogPrintf("AutoCombineDust sent transaction\n");

        delete coinControl;
    }
}

bool CWallet::MultiSend()
{
    auto locked_chain = chain().lock();
    LOCK2(cs_main, cs_wallet);
    // Stop the old blocks from sending multisends
    if (chainActive.Tip()->nTime < (GetAdjustedTime() - 300) || IsLocked()) {
        return false;
    }

    if (chainActive.Tip()->nHeight <= nLastMultiSendHeight) {
        LogPrintf("Multisend: lastmultisendheight is higher than current best height\n");
        return false;
    }

    std::vector<COutput> vCoins;
    AvailableCoins(vCoins);
    bool stakeSent = false;
    bool mnSent = false;
    for (const COutput& out : vCoins) {

        //need output with precise confirm count - this is how we identify which is the output to send
        if (out.tx->GetDepthInMainChain(*locked_chain) != Params().COINBASE_MATURITY() + 1)
            continue;

        COutPoint outpoint(out.tx->tx->GetHash(), out.i);
        bool sendMSonMNReward = fMultiSendMasternodeReward && outpoint.IsMasternodeReward(*out.tx->tx);
        bool sendMSOnStake = fMultiSendStake && out.tx->tx->IsCoinStake() && !sendMSonMNReward; //output is either mnreward or stake reward, not both

        if (!(sendMSOnStake || sendMSonMNReward))
            continue;

        CTxDestination destMyAddress;
        if (!ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, destMyAddress)) {
            LogPrintf("Multisend: failed to extract destination\n");
            continue;
        }

        //Disabled Addresses won't send MultiSend transactions
        if (vDisabledAddresses.size() > 0) {
            for (unsigned int i = 0; i < vDisabledAddresses.size(); i++) {
                if (vDisabledAddresses[i] == CBitcoinAddress(destMyAddress).ToString()) {
                    LogPrintf("Multisend: disabled address preventing multisend\n");
                    return false;
                }
            }
        }

        // create new coin control, populate it with the selected utxo, create sending vector
        CCoinControl cControl;
        COutPoint outpt(out.tx->tx->GetHash(), out.i);
        cControl.Select(outpt);
        cControl.destChange = destMyAddress;

        CWalletTx wtx;
        CReserveKey keyChange(this); // this change address does not end up being used, because change is returned with coin control switch
        CAmount nFeeRet = 0;
        std::vector<std::pair<CScript, CAmount> > vecSend;

        // loop through multisend vector and add amounts and addresses to the sending vector
        const isminefilter filter = ISMINE_SPENDABLE;
        CAmount nAmount = 0;
        for (unsigned int i = 0; i < vMultiSend.size(); i++) {
            // MultiSend vector is a pair of 1)Address as a std::string 2) Percent of stake to send as an int
            nAmount = ((out.tx->GetCredit(*locked_chain, filter) - out.tx->GetDebit(filter)) * vMultiSend[i].second) / 100;
            CBitcoinAddress strAddSend(vMultiSend[i].first);
            CScript scriptPubKey;
            scriptPubKey = GetScriptForDestination(strAddSend.Get());
            vecSend.push_back(std::make_pair(scriptPubKey, nAmount));
        }

        //get the fee amount
        CWalletTx wtxdummy;
        std::string strErr;
        CreateTransaction(vecSend, wtxdummy, keyChange, nFeeRet, strErr, &cControl, ALL_COINS, false, CAmount(0));
        CAmount nLastSendAmount = vecSend[vecSend.size() - 1].second;
        if (nLastSendAmount < nFeeRet + 500) {
            LogPrintf("%s: fee of %d is too large to insert into last output\n", __func__, nFeeRet + 500);
            return false;
        }
        vecSend[vecSend.size() - 1].second = nLastSendAmount - nFeeRet - 500;

        // Create the transaction and commit it to the network
        if (!CreateTransaction(vecSend, wtx, keyChange, nFeeRet, strErr, &cControl, ALL_COINS, false, CAmount(0))) {
            LogPrintf("MultiSend createtransaction failed\n");
            return false;
        }

        if (!CommitTransaction(wtx, keyChange)) {
            LogPrintf("MultiSend transaction commit failed\n");
            return false;
        } else
            fMultiSendNotify = true;

        //write nLastMultiSendHeight to DB
        WalletBatch walletdb(*database);
        nLastMultiSendHeight = chainActive.Tip()->nHeight;
        if (!walletdb.WriteMSettings(fMultiSendStake, fMultiSendMasternodeReward, nLastMultiSendHeight))
            LogPrintf("Failed to write MultiSend setting to DB\n");

        LogPrintf("MultiSend successfully sent\n");

        //set which MultiSend triggered
        if (sendMSOnStake)
            stakeSent = true;
        else
            mnSent = true;

        //stop iterating if we have sent out all the MultiSend(s)
        if ((stakeSent && mnSent) || (stakeSent && !fMultiSendMasternodeReward) || (mnSent && !fMultiSendStake))
            return true;
    }

    return true;
}

int CMerkleTx::GetDepthInMainChainINTERNAL(const CBlockIndex*& pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;
    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;


    pindexRet = pindex;
    return chainActive.Height() - pindex->nHeight + 1;
}


bool CWalletTx::AcceptToMemoryPool(bool fLimitFree, bool fRejectInsaneFee, bool ignoreFees)
{
    CValidationState state;
    bool fAccepted = ::AcceptToMemoryPool(mempool, state, *tx, fLimitFree, NULL, fRejectInsaneFee, ignoreFees);
    if (!fAccepted)
        LogPrintf("%s : %s\n", __func__, state.GetRejectReason());
    return fAccepted;
}

int CMerkleTx::GetTransactionLockSignatures() const
{
    if (fLargeWorkForkFound || fLargeWorkInvalidChainFound) return -2;
    if (!IsSporkActive(SPORK_2_SWIFTTX)) return -3;
    if (!fEnableSwiftTX) return -1;

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(tx->GetHash());
    if (i != mapTxLocks.end()) {
        return (*i).second.CountSignatures();
    }

    return -1;
}

bool CMerkleTx::IsTransactionLockTimedOut() const
{
    if (!fEnableSwiftTX) return 0;

    //compile consessus vote
    std::map<uint256, CTransactionLock>::iterator i = mapTxLocks.find(tx->GetHash());
    if (i != mapTxLocks.end()) {
        return GetTime() > (*i).second.nTimeout;
    }

    return false;
}

// Given a set of inputs, find the public key that contributes the most coins to the input set
CScript GetLargestContributor(set<pair<const CWalletTx*, unsigned int> >& setCoins)
{
    map<CScript, CAmount> mapScriptsOut;
    for (const std::pair<const CWalletTx*, unsigned int>& coin : setCoins) {
        CTxOut out = coin.first->tx->vout[coin.second];
        mapScriptsOut[out.scriptPubKey] += out.nValue;
    }

    CScript scriptLargest;
    CAmount nLargestContributor = 0;
    for (auto it : mapScriptsOut) {
        if (it.second > nLargestContributor) {
            scriptLargest = it.first;
            nLargestContributor = it.second;
        }
    }

    return scriptLargest;
}

bool CWallet::GetZerocoinKey(const CBigNum& bnSerial, CKey& key)
{
    WalletBatch walletdb(*database);
    CZerocoinMint mint;
    if (!GetMint(GetSerialHash(bnSerial), mint))
        return error("%s: could not find serial %s in walletdb!", __func__, bnSerial.GetHex());

    return mint.GetKeyPair(key);
}

bool CWallet::CreateZWSPOutPut(libzerocoin::CoinDenomination denomination, CTxOut& outMint, CDeterministicMint& dMint)
{
    // mint a new coin (create Pedersen Commitment) and extract PublicCoin that is shareable from it
    libzerocoin::PrivateCoin coin(Params().Zerocoin_Params(false), denomination, false);
    zwalletMain->GenerateDeterministicZWSP(denomination, coin, dMint);

    libzerocoin::PublicCoin pubCoin = coin.getPublicCoin();

    // Validate
    if(!pubCoin.validate())
        return error("%s: newly created pubcoin is not valid", __func__);

    zwalletMain->UpdateCount();

    CScript scriptSerializedCoin = CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();
    outMint = CTxOut(libzerocoin::ZerocoinDenominationToAmount(denomination), scriptSerializedCoin);

    return true;
}

bool CWallet::CreateZerocoinMintTransaction(const CAmount nValue, CMutableTransaction& txNew, std::vector<CDeterministicMint>& vDMints, CReserveKey* reservekey, int64_t& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl, const bool isZCSpendChange)
{
    if (IsLocked()) {
        strFailReason = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("SpendZerocoin() : %s", strFailReason.c_str());
        return false;
    }

    //add multiple mints that will fit the amount requested as closely as possible
    CAmount nMintingValue = 0;
    CAmount nValueRemaining = 0;
    while (true) {
        //mint a coin with the closest denomination to what is being requested
        nFeeRet = max(static_cast<int>(txNew.vout.size()), 1) * Params().Zerocoin_MintFee();
        nValueRemaining = nValue - nMintingValue - (isZCSpendChange ? nFeeRet : 0);

        // if this is change of a zerocoinspend, then we can't mint all change, at least something must be given as a fee
        if (isZCSpendChange && nValueRemaining <= 1 * COIN)
            break;

        libzerocoin::CoinDenomination denomination = libzerocoin::AmountToClosestDenomination(nValueRemaining, nValueRemaining);
        if (denomination == libzerocoin::ZQ_ERROR)
            break;

        CAmount nValueNewMint = libzerocoin::ZerocoinDenominationToAmount(denomination);
        nMintingValue += nValueNewMint;

        CTxOut outMint;
        CDeterministicMint dMint;
        if (!CreateZWSPOutPut(denomination, outMint, dMint)) {
            strFailReason = strprintf("%s: failed to create new zwsp output", __func__);
            return error(strFailReason.c_str());
        }
        txNew.vout.push_back(outMint);

        //store as CZerocoinMint for later use
        LogPrint(BCLog::ZERO, "%s: new mint %s\n", __func__, dMint.ToString());
        vDMints.emplace_back(dMint);
    }

    // calculate fee
    CAmount nFee = Params().Zerocoin_MintFee() * txNew.vout.size();

    // no ability to select more coins if this is a ZCSpend change mint
    CAmount nTotalValue = (isZCSpendChange ? nValue : (nValue + nFee));

    // check for a zerocoinspend that mints the change
    CAmount nValueIn = 0;
    set<pair<const CWalletTx*, unsigned int> > setCoins;
    if (isZCSpendChange) {
        nValueIn = nValue;
    } else {
        // select UTXO's to use
        if (!SelectCoins(nTotalValue, setCoins, nValueIn, coinControl)) {
            strFailReason = _("Insufficient or insufficient confirmed funds, you might need to wait a few minutes and try again.");
            return false;
        }

        // Fill vin
        for (const std::pair<const CWalletTx*, unsigned int>& coin : setCoins)
            txNew.vin.push_back(CTxIn(coin.first->tx->GetHash(), coin.second));
    }

    //any change that is less than 0.0100000 will be ignored and given as an extra fee
    //also assume that a zerocoinspend that is minting the change will not have any change that goes to Wsp
    CAmount nChange = nValueIn - nTotalValue; // Fee already accounted for in nTotalValue
    if (nChange > 1 * CENT && !isZCSpendChange) {
        // Fill a vout to ourself using the largest contributing address
        CScript scriptChange = GetLargestContributor(setCoins);

        //add to the transaction
        CTxOut outChange(nChange, scriptChange);
        txNew.vout.push_back(outChange);
    } else {
        if (reservekey)
            reservekey->ReturnKey();
    }

    // Sign if these are wispr outputs - NOTE that zWSP outputs are signed later in SoK
    if (!isZCSpendChange) {
        int nIn = 0;
        for (const std::pair<const CWalletTx*, unsigned int>& coin : setCoins) {
            if (!SignSignature(*this, coin.first->tx->vout[nIn].scriptPubKey, txNew, nIn, coin.first->tx->vout[nIn].nValue, SIGHASH_ALL)) {
                strFailReason = _("Signing transaction failed");
                return false;
            }
            nIn++;
        }
    }

    return true;
}

bool CWallet::MintToTxIn(CZerocoinMint zerocoinSelected, int nSecurityLevel, const uint256& hashTxOut, CTxIn& newTxIn,
                         CZerocoinSpendReceipt& receipt, libzerocoin::SpendType spendType, CBlockIndex* pindexCheckpoint)
{
    // Default error status if not changed below
    receipt.SetStatus(_("Transaction Mint Started"), ZWSP_TXMINT_GENERAL);
    libzerocoin::ZerocoinParams* paramsAccumulator = Params().Zerocoin_Params(false);

    bool isV1Coin = libzerocoin::ExtractVersionFromSerial(zerocoinSelected.GetSerialNumber()) < libzerocoin::PrivateCoin::PUBKEY_VERSION;
    libzerocoin::ZerocoinParams* paramsCoin = Params().Zerocoin_Params(isV1Coin);
    //LogPrintf("%s: *** using v1 coin params=%b, using v1 acc params=%b\n", __func__, isV1Coin, chainActive.Height() < Params().NEW_PROTOCOLS_STARTHEIGHT());

    // 2. Get pubcoin from the private coin
    libzerocoin::CoinDenomination denomination = zerocoinSelected.GetDenomination();
    libzerocoin::PublicCoin pubCoinSelected(paramsCoin, zerocoinSelected.GetValue(), denomination);
    //LogPrintf("%s : selected mint %s\n pubcoinhash=%s\n", __func__, zerocoinSelected.ToString(), GetPubCoinHash(zerocoinSelected.GetValue()).GetHex());
    if (!pubCoinSelected.validate()) {
        receipt.SetStatus(_("The selected mint coin is an invalid coin"), ZWSP_INVALID_COIN);
        return false;
    }

    // 3. Compute Accumulator and Witness
    libzerocoin::Accumulator accumulator(paramsAccumulator, pubCoinSelected.getDenomination());
    libzerocoin::AccumulatorWitness witness(paramsAccumulator, accumulator, pubCoinSelected);
    std::string strFailReason = "";
    int nMintsAdded = 0;
    if (!GenerateAccumulatorWitness(pubCoinSelected, accumulator, witness, nSecurityLevel, nMintsAdded, strFailReason, pindexCheckpoint)) {
        receipt.SetStatus(_("Try to spend with a higher security level to include more coins"), ZWSP_FAILED_ACCUMULATOR_INITIALIZATION);
        return error("%s : %s", __func__, receipt.GetStatusMessage());
    }

    // Construct the CoinSpend object. This acts like a signature on the transaction.
    libzerocoin::PrivateCoin privateCoin(paramsCoin, denomination, false);
    privateCoin.setPublicCoin(pubCoinSelected);
    privateCoin.setRandomness(zerocoinSelected.GetRandomness());
    privateCoin.setSerialNumber(zerocoinSelected.GetSerialNumber());

    //Version 2 zerocoins have a privkey associated with them
    uint8_t nVersion = zerocoinSelected.GetVersion();
    privateCoin.setVersion(zerocoinSelected.GetVersion());
    LogPrintf("%s: privatecoin version=%d\n", __func__, privateCoin.getVersion());
    if (nVersion >= libzerocoin::PrivateCoin::PUBKEY_VERSION) {
        CKey key;
        if (!zerocoinSelected.GetKeyPair(key))
            return error("%s: failed to set zWSP privkey mint version=%d", __func__, nVersion);

        privateCoin.setPrivKey(key.GetPrivKey());
    }


    uint32_t nChecksum = GetChecksum(accumulator.getValue());
    CBigNum bnValue;
    if (!GetAccumulatorValueFromChecksum(nChecksum, false, bnValue) || bnValue == 0)
        return error("%s: could not find checksum used for spend\n", __func__);

    try {
        libzerocoin::CoinSpend spend(paramsCoin, paramsAccumulator, privateCoin, accumulator, nChecksum, witness, hashTxOut,
                                     spendType);
        LogPrintf("%s\n", spend.ToString());

        if (!spend.Verify(accumulator)) {
            receipt.SetStatus(_("The new spend coin transaction did not verify"), ZWSP_INVALID_WITNESS);
            //return false;
            LogPrintf("** spend.verify failed, trying with different params\n");

            libzerocoin::CoinSpend spend2(Params().Zerocoin_Params(true), paramsAccumulator, privateCoin, accumulator,
                                          nChecksum, witness, hashTxOut, libzerocoin::SpendType::SPEND);
            LogPrintf("*** spend2 valid=%d\n", spend2.Verify(accumulator));
            return false;
        }

        // Deserialize the CoinSpend intro a fresh object
        CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
        serializedCoinSpend << spend;
        std::vector<unsigned char> data(serializedCoinSpend.begin(), serializedCoinSpend.end());

        //Add the coin spend into a WISPR transaction
        newTxIn.scriptSig = CScript() << OP_ZEROCOINSPEND << data.size();
        newTxIn.scriptSig.insert(newTxIn.scriptSig.end(), data.begin(), data.end());
        newTxIn.prevout.SetNull();

        //use nSequence as a shorthand lookup of denomination
        //NOTE that this should never be used in place of checking the value in the final blockchain acceptance/verification
        //of the transaction
        newTxIn.nSequence = denomination;

        CDataStream serializedCoinSpendChecking(SER_NETWORK, PROTOCOL_VERSION);
        try {
            serializedCoinSpendChecking << spend;
        } catch (...) {
            receipt.SetStatus(_("Failed to deserialize"), ZWSP_BAD_SERIALIZATION);
            return false;
        }

        libzerocoin::CoinSpend newSpendChecking(paramsCoin, paramsAccumulator, serializedCoinSpendChecking);
        if (!newSpendChecking.Verify(accumulator)) {
            receipt.SetStatus(_("The transaction did not verify"), ZWSP_BAD_SERIALIZATION);
            return false;
        }

        if (IsSerialKnown(spend.getCoinSerialNumber())) {
            //Tried to spend an already spent zWSP
            receipt.SetStatus(_("The coin spend has been used"), ZWSP_SPENT_USED_ZWSP);

            uint256 hashSerial = GetSerialHash(spend.getCoinSerialNumber());
            if (!zwspTracker->HasSerialHash(hashSerial))
                return error("%s: serialhash %s not found in tracker", __func__, hashSerial.GetHex());

            CMintMeta meta = zwspTracker->Get(hashSerial);
            meta.isUsed = true;
            if (!zwspTracker->UpdateState(meta))
                LogPrintf("%s: failed to write zerocoinmint\n", __func__);

            pwalletMain->NotifyZerocoinChanged(pwalletMain, zerocoinSelected.GetValue().GetHex(), "Used", CT_UPDATED);
            return false;
        }

        uint32_t nAccumulatorChecksum = GetChecksum(accumulator.getValue());
        CZerocoinSpend zcSpend(spend.getCoinSerialNumber(), 0, zerocoinSelected.GetValue(), zerocoinSelected.GetDenomination(), nAccumulatorChecksum);
        zcSpend.SetMintCount(nMintsAdded);
        receipt.AddSpend(zcSpend);
    } catch (const std::exception&) {
        receipt.SetStatus(_("CoinSpend: Accumulator witness does not verify"), ZWSP_INVALID_WITNESS);
        return false;
    }

    receipt.SetStatus(_("Spend Valid"), ZWSP_SPEND_OKAY); // Everything okay

    return true;
}

bool CWallet::CreateZerocoinSpendTransaction(CAmount nValue, int nSecurityLevel, CWalletTx& wtxNew, CReserveKey& reserveKey, CZerocoinSpendReceipt& receipt, std::vector<CZerocoinMint>& vSelectedMints, std::vector<CDeterministicMint>& vNewMints, bool fMintChange,  bool fMinimizeChange, CBitcoinAddress* address)
{
    // Check available funds
    int nStatus = ZWSP_TRX_FUNDS_PROBLEMS;
    if (nValue > GetZerocoinBalance(true)) {
        receipt.SetStatus(_("You don't have enough Zerocoins in your wallet"), nStatus);
        return false;
    }

    if (nValue < 1) {
        receipt.SetStatus(_("Value is below the smallest available denomination (= 1) of zWSP"), nStatus);
        return false;
    }

    // Create transaction
    nStatus = ZWSP_TRX_CREATE;

    // If not already given pre-selected mints, then select mints from the wallet
    WalletBatch walletdb(pwalletMain->GetDBHandle());
    set<CMintMeta> setMints;
    CAmount nValueSelected = 0;
    int nCoinsReturned = 0; // Number of coins returned in change from function below (for debug)
    int nNeededSpends = 0;  // Number of spends which would be needed if selection failed
    const int nMaxSpends = Params().Zerocoin_MaxSpendsPerTransaction(); // Maximum possible spends for one zWSP transaction
    std::vector<CMintMeta> vMintsToFetch;
    if (vSelectedMints.empty()) {
        setMints = zwspTracker->ListMints(true, true, true); // need to find mints to spend
        if(setMints.empty()) {
            receipt.SetStatus(_("Failed to find Zerocoins in wallet.dat"), nStatus);
            return false;
        }

        // If the input value is not an int, then we want the selection algorithm to round up to the next highest int
        double dValue = static_cast<double>(nValue) / static_cast<double>(COIN);
        bool fWholeNumber = floor(dValue) == dValue;
        CAmount nValueToSelect = nValue;
        if(!fWholeNumber)
            nValueToSelect = static_cast<CAmount>(ceil(dValue) * COIN);

        // Select the zWSP mints to use in this spend
        std::map<libzerocoin::CoinDenomination, CAmount> DenomMap = GetMyZerocoinDistribution();
        std::list<CMintMeta> listMints(setMints.begin(), setMints.end());
        vMintsToFetch = SelectMintsFromList(nValueToSelect, nValueSelected, nMaxSpends, fMinimizeChange,
                                             nCoinsReturned, listMints, DenomMap, nNeededSpends);
        for (auto& meta : vMintsToFetch) {
            CZerocoinMint mint;
            if (!GetMint(meta.hashSerial, mint))
                return error("%s: failed to fetch hashSerial %s", __func__, meta.hashSerial.GetHex());
            vSelectedMints.emplace_back(mint);
        }
    } else {
        unsigned int mintsCount = 0;
        for (const CZerocoinMint& mint : vSelectedMints) {
            if (nValueSelected < nValue) {
                nValueSelected += ZerocoinDenominationToAmount(mint.GetDenomination());
                mintsCount ++;
            }
            else
                break;
        }
        if (mintsCount < vSelectedMints.size()) {
            vSelectedMints.resize(mintsCount);
        }
    }

    int nArchived = 0;
    for (CZerocoinMint mint : vSelectedMints) {
        // see if this serial has already been spent
        int nHeightSpend;
        if (IsSerialInBlockchain(mint.GetSerialNumber(), nHeightSpend)) {
            receipt.SetStatus(_("Trying to spend an already spent serial #, try again."), nStatus);
            uint256 hashSerial = GetSerialHash(mint.GetSerialNumber());
            if (!zwspTracker->HasSerialHash(hashSerial))
                return error("%s: tracker does not have serialhash %s", __func__, hashSerial.GetHex());

            CMintMeta meta = zwspTracker->Get(hashSerial);
            meta.isUsed = true;
            zwspTracker->UpdateState(meta);

            return false;
        }

        //check that this mint made it into the blockchain
        CTransaction txMint;
        uint256 hashBlock;
        bool fArchive = false;
        if (!GetTransaction(mint.GetTxHash(), txMint, hashBlock)) {
            receipt.SetStatus(_("Unable to find transaction containing mint"), nStatus);
            fArchive = true;
        } else if (mapBlockIndex.count(hashBlock) < 1) {
            receipt.SetStatus(_("Mint did not make it into blockchain"), nStatus);
            fArchive = true;
        }

        // archive this mint as an orphan
        if (fArchive) {
            //walletdb.ArchiveMintOrphan(mint);
            //nArchived++;
            //todo
        }
    }
    if (nArchived)
        return false;

    if (vSelectedMints.empty()) {
        if(nNeededSpends > 0){
            // Too much spends needed, so abuse nStatus to report back the number of needed spends
            receipt.SetStatus(_("Too many spends needed"), nStatus, nNeededSpends);
        }
        else {
            receipt.SetStatus(_("Failed to select a zerocoin"), nStatus);
        }
        return false;
    }

    for (const auto& mint : vSelectedMints) {
        if (mint.GetVersion() < libzerocoin::PrivateCoin::PUBKEY_VERSION) {
            if (nSecurityLevel < 100) {
                nStatus = ZWSP_SPEND_V1_SEC_LEVEL;
                receipt.SetStatus(_("Version 1 zWSP require a security level of 100 to successfully spend."), nStatus);
                return false;
            }
        }
    }

    if ((static_cast<int>(vSelectedMints.size()) > Params().Zerocoin_MaxSpendsPerTransaction())) {
        receipt.SetStatus(_("Failed to find coin set amongst held coins with less than maxNumber of Spends"), nStatus);
        return false;
    }

    // Create change if needed
    nStatus = ZWSP_TRX_CHANGE;

    CMutableTransaction txNew;
    wtxNew.BindWallet(this);
    {
        LOCK2(cs_main, cs_wallet);
        {
            txNew.vin.clear();
            txNew.vout.clear();

            //if there is an address to send to then use it, if not generate a new address to send to
            CScript scriptZerocoinSpend;
            CScript scriptChange;
            CAmount nChange = nValueSelected - nValue;

            if (nChange < 0) {
                receipt.SetStatus(_("Selected coins value is less than payment target"), nStatus);
                return false;
            }

            if (nChange > 0 && !address) {
                receipt.SetStatus(_("Need address because change is not exact"), nStatus);
                return false;
            }

            if (address) {
                scriptZerocoinSpend = GetScriptForDestination(address->Get());
                if (nChange) {
                    // Reserve a new key pair from key pool
                    CPubKey vchPubKey;
                    assert(reserveKey.GetReservedKey(vchPubKey)); // should never fail
                    scriptChange = GetScriptForDestination(vchPubKey.GetID());
                }
            } else {
                // Reserve a new key pair from key pool
                CPubKey vchPubKey;
                assert(reserveKey.GetReservedKey(vchPubKey)); // should never fail
                scriptZerocoinSpend = GetScriptForDestination(vchPubKey.GetID());
            }

            //add change output if we are spending too much (only applies to spending multiple at once)
            if (nChange) {
                //mint change as zerocoins
                if (fMintChange) {
                    CAmount nFeeRet = 0;
                    std::string strFailReason = "";
                    if (!CreateZerocoinMintTransaction(nChange, txNew, vNewMints, &reserveKey, nFeeRet, strFailReason, NULL, true)) {
                        receipt.SetStatus(_("Failed to create mint"), nStatus);
                        return false;
                    }
                } else {
                    CTxOut txOutChange(nValueSelected - nValue, scriptChange);
                    txNew.vout.push_back(txOutChange);
                }
            }

            //add output to wispr address to the transaction (the actual primary spend taking place)
            CTxOut txOutZerocoinSpend(nValue, scriptZerocoinSpend);
            txNew.vout.push_back(txOutZerocoinSpend);

            //hash with only the output info in it to be used in Signature of Knowledge
            uint256 hashTxOut = txNew.GetHash();

            //add all of the mints to the transaction as inputs
            for (CZerocoinMint mint : vSelectedMints) {
                CTxIn newTxIn;
                if (!MintToTxIn(mint, nSecurityLevel, hashTxOut, newTxIn, receipt, libzerocoin::SpendType::SPEND)) {
                    return false;
                }
                txNew.vin.push_back(newTxIn);
            }

            // Limit size
            unsigned int nBytes = ::GetSerializeSize(txNew, PROTOCOL_VERSION);
            if (nBytes >= MAX_ZEROCOIN_TX_SIZE) {
                receipt.SetStatus(_("In rare cases, a spend with 7 coins exceeds our maximum allowable transaction size, please retry spend using 6 or less coins"), ZWSP_TX_TOO_LARGE);
                return false;
            }

            //now that all inputs have been added, add full tx hash to zerocoinspend records and write to db
            uint256 txHash = txNew.GetHash();
            for (CZerocoinSpend spend : receipt.GetSpends()) {
                spend.SetTxHash(txHash);

                if (!WalletBatch(*database).WriteZerocoinSpendSerialEntry(spend)) {
                    receipt.SetStatus(_("Failed to write coin serial number into wallet"), nStatus);
                }
            }

            //turn the finalized transaction into a wallet transaction
            wtxNew = CWalletTx(this, txNew);
            wtxNew.fFromMe = true;
            wtxNew.fTimeReceivedIsTxTime = true;
            wtxNew.nTimeReceived = GetAdjustedTime();
        }
    }

    receipt.SetStatus(_("Transaction Created"), ZWSP_SPEND_OKAY); // Everything okay

    return true;
}

string CWallet::ResetMintZerocoin()
{
    long updates = 0;
    long deletions = 0;
    WalletBatch walletdb(pwalletMain->GetDBHandle());

    set<CMintMeta> setMints = zwspTracker->ListMints(false, false, true);
    std::vector<CMintMeta> vMintsToFind(setMints.begin(), setMints.end());
    std::vector<CMintMeta> vMintsMissing;
    std::vector<CMintMeta> vMintsToUpdate;

    // search all of our available data for these mints
    FindMints(vMintsToFind, vMintsToUpdate, vMintsMissing);

    // Update the meta data of mints that were marked for updating
    for (CMintMeta meta : vMintsToUpdate) {
        updates++;
        zwspTracker->UpdateState(meta);
    }

    // Delete any mints that were unable to be located on the blockchain
    for (CMintMeta mint : vMintsMissing) {
        deletions++;
        if (!zwspTracker->Archive(mint))
            LogPrintf("%s: failed to archive mint\n", __func__);
    }

    NotifyzWSPReset();

    std::string strResult = _("ResetMintZerocoin finished: ") + to_string(updates) + _(" mints updated, ") + to_string(deletions) + _(" mints deleted\n");
    return strResult;
}

string CWallet::ResetSpentZerocoin()
{
    long removed = 0;
    WalletBatch walletdb(pwalletMain->GetDBHandle());

    set<CMintMeta> setMints = zwspTracker->ListMints(false, false, true);
    std::list<CZerocoinSpend> listSpends = walletdb.ListSpentCoins();
    std::list<CZerocoinSpend> listUnconfirmedSpends;

    for (CZerocoinSpend spend : listSpends) {
        CTransaction tx;
        uint256 hashBlock = 0;
        if (!GetTransaction(spend.GetTxHash(), tx, hashBlock)) {
            listUnconfirmedSpends.push_back(spend);
            continue;
        }

        //no confirmations
        if (hashBlock == 0)
            listUnconfirmedSpends.push_back(spend);
    }

    for (CZerocoinSpend spend : listUnconfirmedSpends) {
        for (CMintMeta meta : setMints) {
            if (meta.hashSerial == GetSerialHash(spend.GetSerial())) {
                removed++;
                meta.isUsed = false;
                zwspTracker->UpdateState(meta);
                walletdb.EraseZerocoinSpendSerialEntry(spend.GetSerial());
                continue;
            }
        }
    }

    NotifyzWSPReset();

    std::string strResult = _("ResetSpentZerocoin finished: ") + to_string(removed) + _(" unconfirmed transactions removed\n");
    return strResult;
}

bool IsMintInChain(const uint256& hashPubcoin, uint256& txid, int& nHeight)
{
    if (!IsPubcoinInBlockchain(hashPubcoin, txid))
        return false;

    uint256 hashBlock;
    CTransaction tx;
    if (!GetTransaction(txid, tx, hashBlock))
        return false;

    if (!mapBlockIndex.count(hashBlock) || !chainActive.Contains(mapBlockIndex.at(hashBlock)))
        return false;

    nHeight = mapBlockIndex.at(hashBlock)->nHeight;
    return true;
}

void CWallet::ReconsiderZerocoins(std::list<CZerocoinMint>& listMintsRestored, std::list<CDeterministicMint>& listDMintsRestored)
{
    WalletBatch walletdb(pwalletMain->GetDBHandle());
    std::list<CZerocoinMint> listMints = walletdb.ListArchivedZerocoins();
    std::list<CDeterministicMint> listDMints = walletdb.ListArchivedDeterministicMints();

    if (listMints.empty() && listDMints.empty())
        return;

    for (CZerocoinMint mint : listMints) {
        uint256 txid;
        int nHeight;
        uint256 hashPubcoin = GetPubCoinHash(mint.GetValue());
        if (!IsMintInChain(hashPubcoin, txid, nHeight))
            continue;

        mint.SetTxHash(txid);
        mint.SetHeight(nHeight);
        mint.SetUsed(IsSerialInBlockchain(mint.GetSerialNumber(), nHeight));

        if (!zwspTracker->UnArchive(hashPubcoin, false)) {
            LogPrintf("%s : failed to unarchive mint %s\n", __func__, mint.GetValue().GetHex());
        } else {
            zwspTracker->UpdateZerocoinMint(mint);
        }
        listMintsRestored.emplace_back(mint);
    }

    for (CDeterministicMint dMint : listDMints) {
        uint256 txid;
        int nHeight;
        if (!IsMintInChain(dMint.GetPubcoinHash(), txid, nHeight))
            continue;

        dMint.SetTxHash(txid);
        dMint.SetHeight(nHeight);
        uint256 txidSpend;
        dMint.SetUsed(IsSerialInBlockchain(dMint.GetSerialHash(), nHeight, txidSpend));

        if (!zwspTracker->UnArchive(dMint.GetPubcoinHash(), true)) {
            LogPrintf("%s : failed to unarchive deterministic mint %s\n", __func__, dMint.GetPubcoinHash().GetHex());
        } else {
            zwspTracker->Add(dMint, true);
        }
        listDMintsRestored.emplace_back(dMint);
    }
}

string CWallet::GetUniqueWalletBackupName(bool fzwspAuto) const
{
    std::stringstream ssDateTime;
    std::string strWalletBackupName = strprintf("%s", DateTimeStrFormat(".%Y-%m-%d-%H-%M", GetTime()));
    ssDateTime << strWalletBackupName;

    return strprintf("wallet%s.dat%s", fzwspAuto ? "-autozwspbackup" : "", DateTimeStrFormat(".%Y-%m-%d-%H-%M", GetTime()));
}

void CWallet::ZWspBackupWallet()
{
    fs::path backupDir = GetDataDir() / "backups";
    fs::path backupPath;
    std::string strNewBackupName;

    for (int i = 0; i < 10; i++) {
        strNewBackupName = strprintf("wallet-autozwspbackup-%d.dat", i);
        backupPath = backupDir / strNewBackupName;

        if (fs::exists(backupPath)) {
            //Keep up to 10 backups
            if (i <= 8) {
                //If the next file backup exists and is newer, then iterate
                fs::path nextBackupPath = backupDir / strprintf("wallet-autozwspbackup-%d.dat", i + 1);
                if (fs::exists(nextBackupPath)) {
                    time_t timeThis = fs::last_write_time(backupPath);
                    time_t timeNext = fs::last_write_time(nextBackupPath);
                    if (timeThis > timeNext) {
                        //The next backup is created before this backup was
                        //The next backup is the correct path to use
                        backupPath = nextBackupPath;
                        break;
                    }
                }
                //Iterate to the next filename/number
                continue;
            }
            //reset to 0 because name with 9 already used
            strNewBackupName = strprintf("wallet-autozwspbackup-%d.dat", 0);
            backupPath = backupDir / strNewBackupName;
            break;
        }
        //This filename is fresh, break here and backup
        break;
    }

    BackupWallet(backupPath.string());

    if(!gArgs.GetArg("-zwspbackuppath", "").empty()) {
        fs::path customPath(gArgs.GetArg("-zwspbackuppath", ""));
        fs::create_directories(customPath);

        if(!customPath.has_extension()) {
            customPath /= GetUniqueWalletBackupName(true);
        }

        BackupWallet(customPath.string());
    }

}

string CWallet::MintZerocoinFromOutPoint(CAmount nValue, CWalletTx& wtxNew, std::vector<CDeterministicMint>& vDMints, const std::vector<COutPoint> vOutpts)
{
    CCoinControl* coinControl = new CCoinControl();
    for (const COutPoint& outpt : vOutpts) {
        coinControl->Select(outpt);
    }
    if (!coinControl->HasSelected()){
        std::string strError = _("Error: No valid utxo!");
        LogPrintf("MintZerocoin() : %s", strError.c_str());
        return strError;
    }
    std::string strError = MintZerocoin(nValue, wtxNew, vDMints, coinControl);
    delete coinControl;
    return strError;
}

string CWallet::MintZerocoin(CAmount nValue, CWalletTx& wtxNew, std::vector<CDeterministicMint>& vDMints, const CCoinControl* coinControl)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");

    CAmount nBalance = GetBalance();
    if (nValue + Params().Zerocoin_MintFee() > nBalance) {
        LogPrintf("%s: balance=%s fee=%s nValue=%s\n", __func__, FormatMoney(nBalance), FormatMoney(Params().Zerocoin_MintFee()), FormatMoney(nValue));
        return _("Insufficient funds");
    }

    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked()) {
        std::string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintZerocoin() : %s", strError.c_str());
        return strError;
    }

    std::string strError;
    CMutableTransaction txNew;
    if (!CreateZerocoinMintTransaction(nValue, txNew, vDMints, &reservekey, nFeeRequired, strError, coinControl)) {
        if (nValue + nFeeRequired > GetBalance())
            return strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"), FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    wtxNew = CWalletTx(this, txNew);
    wtxNew.fFromMe = true;
    wtxNew.fTimeReceivedIsTxTime = true;

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, PROTOCOL_VERSION);
    if (nBytes >= MAX_ZEROCOIN_TX_SIZE) {
        return _("Error: The transaction is larger than the maximum allowed transaction size!");
    }

    //commit the transaction to the network
    if (!CommitTransaction(wtxNew, reservekey)) {
        return _("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    } else {
        //update mints with full transaction hash and then database them
        WalletBatch walletdb(pwalletMain->GetDBHandle());
        for (CDeterministicMint dMint : vDMints) {
            dMint.SetTxHash(wtxNew.tx->GetHash());
            zwspTracker->Add(dMint, true);
        }
    }

    //Create a backup of the wallet
    if (fBackupMints)
        ZWspBackupWallet();

    return "";
}

bool CWallet::SpendZerocoin(CAmount nAmount, int nSecurityLevel, CWalletTx& wtxNew, CZerocoinSpendReceipt& receipt, std::vector<CZerocoinMint>& vMintsSelected, bool fMintChange, bool fMinimizeChange, CBitcoinAddress* addressTo)
{
    // Default: assume something goes wrong. Depending on the problem this gets more specific below
    int nStatus = ZWSP_SPEND_ERROR;

    if (IsLocked()) {
        receipt.SetStatus("Error: Wallet locked, unable to create transaction!", ZWSP_WALLET_LOCKED);
        return false;
    }

    CReserveKey reserveKey(this);
    std::vector<CDeterministicMint> vNewMints;
    if (!CreateZerocoinSpendTransaction(nAmount, nSecurityLevel, wtxNew, reserveKey, receipt, vMintsSelected, vNewMints, fMintChange, fMinimizeChange, addressTo)) {
        return false;
    }

    if (fMintChange && fBackupMints)
        ZWspBackupWallet();

    WalletBatch walletdb(pwalletMain->GetDBHandle());
    if (!CommitTransaction(wtxNew, reserveKey)) {
        LogPrintf("%s: failed to commit\n", __func__);
        nStatus = ZWSP_COMMIT_FAILED;

        //reset all mints
        for (CZerocoinMint mint : vMintsSelected) {
            uint256 hashPubcoin = GetPubCoinHash(mint.GetValue());
            zwspTracker->SetPubcoinNotUsed(hashPubcoin);
            pwalletMain->NotifyZerocoinChanged(pwalletMain, mint.GetValue().GetHex(), "New", CT_UPDATED);
        }

        //erase spends
        for (CZerocoinSpend spend : receipt.GetSpends()) {
            if (!walletdb.EraseZerocoinSpendSerialEntry(spend.GetSerial())) {
                receipt.SetStatus("Error: It cannot delete coin serial number in wallet", ZWSP_ERASE_SPENDS_FAILED);
            }

            //Remove from public zerocoinDB
            RemoveSerialFromDB(spend.GetSerial());
        }

        // erase new mints
        for (auto& dMint : vNewMints) {
            if (!walletdb.EraseDeterministicMint(dMint.GetPubcoinHash())) {
                receipt.SetStatus("Error: Unable to cannot delete zerocoin mint in wallet", ZWSP_ERASE_NEW_MINTS_FAILED);
            }
        }

        receipt.SetStatus("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.", nStatus);
        return false;
    }

    //Set spent mints as used
    uint256 txidSpend = wtxNew.tx->GetHash();
    for (CZerocoinMint mint : vMintsSelected) {
        uint256 hashPubcoin = GetPubCoinHash(mint.GetValue());
        zwspTracker->SetPubcoinUsed(hashPubcoin, txidSpend);

        CMintMeta metaCheck = zwspTracker->GetMetaFromPubcoin(hashPubcoin);
        if (!metaCheck.isUsed) {
            receipt.SetStatus("Error, the mint did not get marked as used", nStatus);
            return false;
        }
    }

    // write new Mints to db
    for (auto& dMint : vNewMints) {
        dMint.SetTxHash(txidSpend);
        zwspTracker->Add(dMint, true);
    }

    receipt.SetStatus("Spend Successful", ZWSP_SPEND_OKAY);  // When we reach this point spending zWSP was successful

    return true;
}

bool CWallet::GetMintFromStakeHash(const uint256& hashStake, CZerocoinMint& mint)
{
    CMintMeta meta;
    if (!zwspTracker->GetMetaFromStakeHash(hashStake, meta))
        return error("%s: failed to find meta associated with hashStake", __func__);
    return GetMint(meta.hashSerial, mint);
}

bool CWallet::GetMint(const uint256& hashSerial, CZerocoinMint& mint)
{
    if (!zwspTracker->HasSerialHash(hashSerial))
        return error("%s: serialhash %s is not in tracker", __func__, hashSerial.GetHex());

    WalletBatch walletdb(*database);
    CMintMeta meta = zwspTracker->Get(hashSerial);
    if (meta.isDeterministic) {
        CDeterministicMint dMint;
        if (!walletdb.ReadDeterministicMint(meta.hashPubcoin, dMint))
            return error("%s: failed to read deterministic mint", __func__);
        if (!zwalletMain->RegenerateMint(dMint, mint))
            return error("%s: failed to generate mint", __func__);

        return true;
    } else if (!walletdb.ReadZerocoinMint(meta.hashPubcoin, mint)) {
        return error("%s: failed to read zerocoinmint from database", __func__);
    }

    return true;
}


bool CWallet::IsMyMint(const CBigNum& bnValue) const
{
    if (zwspTracker->HasPubcoin(bnValue))
        return true;

    return zwalletMain->IsInMintPool(bnValue);
}

bool CWallet::UpdateMint(const CBigNum& bnValue, const int& nHeight, const uint256& txid, const libzerocoin::CoinDenomination& denom)
{
    uint256 hashValue = GetPubCoinHash(bnValue);
    CZerocoinMint mint;
    if (zwspTracker->HasPubcoinHash(hashValue)) {
        CMintMeta meta = zwspTracker->GetMetaFromPubcoin(hashValue);
        meta.nHeight = nHeight;
        meta.txid = txid;
        return zwspTracker->UpdateState(meta);
    } else {
        //Check if this mint is one that is in our mintpool (a potential future mint from our deterministic generation)
        if (zwalletMain->IsInMintPool(bnValue)) {
            if (zwalletMain->SetMintSeen(bnValue, nHeight, txid, denom))
                return true;
        }
    }

    return false;
}

//! Primarily for the scenario that a mint was confirmed and added to the chain and then that block orphaned
bool CWallet::SetMintUnspent(const CBigNum& bnSerial)
{
    uint256 hashSerial = GetSerialHash(bnSerial);
    if (!zwspTracker->HasSerialHash(hashSerial))
        return error("%s: did not find mint", __func__);

    CMintMeta meta = zwspTracker->Get(hashSerial);
    zwspTracker->SetPubcoinNotUsed(meta.hashPubcoin);
    return true;
}

bool CWallet::DatabaseMint(CDeterministicMint& dMint)
{
    WalletBatch batch(*database);
    zwspTracker->Add(dMint, true);
    return true;
}

//!WISPR
void CWallet::setZWallet(CzWSPWallet* zwallet)
{
    zwalletMain = zwallet;
    zwspTracker = std::unique_ptr<CzWSPTracker>(new CzWSPTracker(strWalletFile, m_chain, m_location, WalletDatabase::Create(m_location.GetPath())));
}
