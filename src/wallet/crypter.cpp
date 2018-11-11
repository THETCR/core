// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/crypter.h>

#include <crypto/aes.h>
#include <crypto/sha512.h>
#include <script/script.h>
#include <script/standard.h>
#include <util.h>

#include <string>
#include <vector>

#include <init.h>
#include <uint256.h>

#include <boost/foreach.hpp>
#include <openssl/evp.h>
#include <wallet/hdwallet.h>
#include <wallet/hdwalletdb.h>

int CCrypter::BytesToKeySHA512AES(const std::vector<unsigned char>& chSalt, const SecureString& strKeyData, int count, unsigned char *key,unsigned char *iv) const
{
    // This mimics the behavior of openssl's EVP_BytesToKey with an aes256cbc
    // cipher and sha512 message digest. Because sha512's output size (64b) is
    // greater than the aes256 block size (16b) + aes256 key size (32b),
    // there's no need to process more than once (D_0).

    if(!count || !key || !iv)
        return 0;

    unsigned char buf[CSHA512::OUTPUT_SIZE];
    CSHA512 di;

    di.Write((const unsigned char*)strKeyData.c_str(), strKeyData.size());
    di.Write(chSalt.data(), chSalt.size());
    di.Finalize(buf);

    for(int i = 0; i != count - 1; i++)
        di.Reset().Write(buf, sizeof(buf)).Finalize(buf);

    memcpy(key, buf, WALLET_CRYPTO_KEY_SIZE);
    memcpy(iv, buf + WALLET_CRYPTO_KEY_SIZE, WALLET_CRYPTO_IV_SIZE);
    memory_cleanse(buf, sizeof(buf));
    return WALLET_CRYPTO_KEY_SIZE;
}

bool CCrypter::SetKeyFromPassphrase(const SecureString& strKeyData, const std::vector<unsigned char>& chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
    if (nDerivationMethod == 0)
        i = BytesToKeySHA512AES(chSalt, strKeyData, nRounds, vchKey.data(), vchIV.data());

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(vchKey.data(), vchKey.size());
        memory_cleanse(vchIV.data(), vchIV.size());
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial& chNewKey, const std::vector<unsigned char>& chNewIV)
{
    if (chNewKey.size() != WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != WALLET_CRYPTO_IV_SIZE)
        return false;

    memcpy(vchKey.data(), chNewKey.data(), chNewKey.size());
    memcpy(vchIV.data(), chNewIV.data(), chNewIV.size());

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char> &vchCiphertext) const
{
    if (!fKeySet)
        return false;

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCKSIZE bytes
    vchCiphertext.resize(vchPlaintext.size() + AES_BLOCKSIZE);

    AES256CBCEncrypt enc(vchKey.data(), vchIV.data(), true);
    size_t nLen = enc.Encrypt(&vchPlaintext[0], vchPlaintext.size(), vchCiphertext.data());
    if(nLen < vchPlaintext.size())
        return false;
    vchCiphertext.resize(nLen);

    return true;
}

bool CCrypter::Decrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext) const
{
    if (!fKeySet)
        return false;

    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = vchCiphertext.size();

    vchPlaintext.resize(nLen);

    AES256CBCDecrypt dec(vchKey.data(), vchIV.data(), true);
    nLen = dec.Decrypt(vchCiphertext.data(), vchCiphertext.size(), &vchPlaintext[0]);
    if(nLen == 0)
        return false;
    vchPlaintext.resize(nLen);
    return true;
}


bool EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial &vchPlaintext, const uint256& nIV, std::vector<unsigned char> &vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(chIV.data(), &nIV, WALLET_CRYPTO_IV_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt(*((const CKeyingMaterial*)&vchPlaintext), vchCiphertext);
}

bool DecryptSecret(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCiphertext, const uint256& nIV, CKeyingMaterial& vchPlaintext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(chIV.data(), &nIV, WALLET_CRYPTO_IV_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}

static bool DecryptKey(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCryptedSecret, const CPubKey& vchPubKey, CKey& key)
{
    CKeyingMaterial vchSecret;
    if(!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
        return false;

    if (vchSecret.size() != 32)
        return false;

    key.Set(vchSecret.begin(), vchSecret.end(), vchPubKey.IsCompressed());
    return key.VerifyPubKey(vchPubKey);
}

bool CCryptoKeyStore::SetCrypted()
{
    LOCK(cs_KeyStore);
    if (fUseCrypto)
        return true;
    if (!mapKeys.empty())
        return false;
    fUseCrypto = true;
    return true;
}

//bool CCryptoKeyStore::IsLocked() const
//{
//    if (!IsCrypted()) {
//        return false;
//    }
//    LOCK(cs_KeyStore);
//    return vMasterKey.empty();
//}
// This function should be used in a different combinations to determine
// if CCryptoKeyStore is fully locked so that no operations requiring access
// to private keys are possible:
//      IsLocked(true)
// or if CCryptoKeyStore's private keys are available for mixing only:
//      !IsLocked(true) && IsLocked()
// or if they are available for everything:
//      !IsLocked()
bool CCryptoKeyStore::IsLocked(bool fForMixing) const
{
    if (!IsCrypted())
        return false;
    bool result;
    {
        LOCK(cs_KeyStore);
        result = vMasterKey.empty();
    }
    // fForMixing   fOnlyMixingAllowed  return
    // ---------------------------------------
    // true         true                result
    // true         false               result
    // false        true                true
    // false        false               result

    if(!fForMixing && fOnlyMixingAllowed) return true;

    return result;
}
bool CCryptoKeyStore::Lock()
{
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
    }

    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;
        bool keyPass = false;
        bool keyFail = false;

        size_t nTries = 0;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;

            if (vchCryptedSecret.size() == 0) // unexpanded key received on stealth address
                continue;

            nTries++;
            CKey key;
            if (!DecryptKey(vMasterKeyIn, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            assert(false);
        }
        if (keyFail || (!keyPass && nTries > 0))
            return false;
        vMasterKey = vMasterKeyIn;
        fDecryptionThoroughlyChecked = true;
    }
    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::AddKeyPubKey(key, pubkey);
    }

    if (IsLocked()) {
        return false;
    }

    std::vector<unsigned char> vchCryptedSecret;
    CKeyingMaterial vchSecret(key.begin(), key.end());
    if (!EncryptSecret(vMasterKey, vchSecret, pubkey.GetHash(), vchCryptedSecret)) {
        return false;
    }

    if (!AddCryptedKey(pubkey, vchCryptedSecret)) {
        return false;
    }
    return true;
}

bool CCryptoKeyStore::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    if (!SetCrypted()) {
        return false;
    }

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

isminetype CCryptoKeyStore::IsMine(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::IsMine(address);
    }
    if (mapCryptedKeys.count(address) > 0)
        return ISMINE_SPENDABLE;
    if (mapWatchKeys.count(address) > 0)
        return ISMINE_WATCH_ONLY_;
    return ISMINE_NO;
};

bool CCryptoKeyStore::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::HaveKey(address);
    }
    return mapCryptedKeys.count(address) > 0;
}

bool CCryptoKeyStore::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return DecryptKey(vMasterKey, vchCryptedSecret, vchPubKey, keyOut);
    }
    return false;
}

bool CCryptoKeyStore::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted())
        return CBasicKeyStore::GetPubKey(address, vchPubKeyOut);

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return CBasicKeyStore::GetPubKey(address, vchPubKeyOut);
}

std::set<CKeyID> CCryptoKeyStore::GetKeys() const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return CBasicKeyStore::GetKeys();
    }
    std::set<CKeyID> set_address;
    for (const auto& mi : mapCryptedKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

bool CCryptoKeyStore::EncryptKeys(CKeyingMaterial& vMasterKeyIn)
{
    LOCK(cs_KeyStore);
    if (!mapCryptedKeys.empty() || IsCrypted())
        return false;

    fUseCrypto = true;
    for (KeyMap::value_type& mKey : mapKeys)
    {
        const CKey &key = mKey.second;
        CPubKey vchPubKey = key.GetPubKey();
        CKeyingMaterial vchSecret(key.begin(), key.end());
        std::vector<unsigned char> vchCryptedSecret;
        if (!EncryptSecret(vMasterKeyIn, vchSecret, vchPubKey.GetHash(), vchCryptedSecret))
            return false;
        if (!AddCryptedKey(vchPubKey, vchCryptedSecret))
            return false;
    }
    mapKeys.clear();
    return true;
}
bool CCryptoKeyStore::AddDeterministicSeed(CHDWallet *pwallet, const uint256& seed)
{
    CHDWalletDB db(pwallet->strWalletFile);
    string strErr;
    uint256 hashSeed = Hash(seed.begin(), seed.end());

    if(IsCrypted()) {
        if (!IsLocked()) { //if we have password

            CKeyingMaterial kmSeed(seed.begin(), seed.end());
            vector<unsigned char> vchSeedSecret;


            //attempt encrypt
            if (EncryptSecret(vMasterKey, kmSeed, hashSeed, vchSeedSecret)) {
                //write to wallet with hashSeed as unique key
                if (db.WriteZWSPSeed(hashSeed, vchSeedSecret)) {
                    return true;
                }
            }
            strErr = "encrypt seed";
        }
        strErr = "save since wallet is locked";
    } else { //wallet not encrypted
        if (db.WriteZWSPSeed(hashSeed, ToByteVector(seed))) {
            return true;
        }
        strErr = "save zwspseed to wallet";
    }
    //the use case for this is no password set seed, mint dzWSP,

    return error("s%: Failed to %s\n", __func__, strErr);
}

bool CCryptoKeyStore::GetDeterministicSeed(CHDWallet *pwallet, const uint256& hashSeed, uint256& seedOut)
{

    CHDWalletDB db(pwallet->strWalletFile);
    string strErr;
    if (IsCrypted()) {
        if(!IsLocked()) { //if we have password

            vector<unsigned char> vchCryptedSeed;
            //read encrypted seed
            if (db.ReadZWSPSeed(hashSeed, vchCryptedSeed)) {
                uint256 seedRetrieved = uint256(ReverseEndianString(HexStr(vchCryptedSeed)));
                //this checks if the hash of the seed we just read matches the hash given, meaning it is not encrypted
                //the use case for this is when not crypted, seed is set, then password set, the seed not yet crypted in memory
                if(hashSeed == Hash(seedRetrieved.begin(), seedRetrieved.end())) {
                    seedOut = seedRetrieved;
                    return true;
                }

                CKeyingMaterial kmSeed;
                //attempt decrypt
                if (DecryptSecret(vMasterKey, vchCryptedSeed, hashSeed, kmSeed)) {
                    seedOut = uint256(ReverseEndianString(HexStr(kmSeed)));
                    return true;
                }
                strErr = "decrypt seed";
            } else { strErr = "read seed from wallet"; }
        } else { strErr = "read seed; wallet is locked"; }
    } else {
        vector<unsigned char> vchSeed;
        // wallet not crypted
        if (db.ReadZWSPSeed(hashSeed, vchSeed)) {
            seedOut = uint256(ReverseEndianString(HexStr(vchSeed)));
            return true;
        }
        strErr = "read seed from wallet";
    }

    return error("%s: Failed to %s\n", __func__, strErr);


//    return error("Failed to decrypt deterministic seed %s", IsLocked() ? "Wallet is locked!" : "");
}