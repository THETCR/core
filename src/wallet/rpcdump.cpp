// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bip38.h"
#include "main.h"
#include <key_io.h>
#include "rpc/server.h"
#include <rpc/util.h>
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include <util/bip32.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/wallet.h>
#include <script/descriptor.h>

#include <fstream>
#include <secp256k1.h>
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <openssl/aes.h>
#include <openssl/sha.h>

#include <univalue.h>

using namespace std;

void EnsureWalletIsUnlocked(bool fAllowAnonOnly);

std::string static EncodeDumpTime(int64_t nTime)
{
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64_t static DecodeDumpTime(const std::string& str)
{
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time())
        return 0;
    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string& str)
{
    std::stringstream ret;
    for (unsigned char c: str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string& str)
{
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos + 2 < str.length()) {
            c = (((str[pos + 1] >> 6) * 9 + ((str[pos + 1] - '0') & 15)) << 4) |
                ((str[pos + 2] >> 6) * 9 + ((str[pos + 2] - '0') & 15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

static bool GetWalletAddressesForKey(CWallet* const pwallet, const CKeyID& keyid, std::string& strAddr, std::string& strLabel) EXCLUSIVE_LOCKS_REQUIRED(pwalletMain->cs_wallet)
{
    bool fLabelFound = false;
    CKey key;
    pwalletMain->GetKey(keyid, key);
    for (const auto& dest : GetAllDestinationsForKey(key.GetPubKey())) {
        if (pwalletMain->mapAddressBook.count(dest)) {
            if (!strAddr.empty()) {
                strAddr += ",";
            }
            strAddr += EncodeDestination(dest);
            strLabel = EncodeDumpString(pwalletMain->mapAddressBook[dest].name);
            fLabelFound = true;
        }
    }
    if (!fLabelFound) {
        strAddr = EncodeDestination(GetDestinationForKey(key.GetPubKey(), pwalletMain->m_default_address_type));
    }
    return fLabelFound;
}

static const int64_t TIMESTAMP_MIN = 0;

static void RescanWallet(CWallet& wallet, const WalletRescanReserver& reserver, int64_t time_begin = TIMESTAMP_MIN, bool update = true)
{
    int64_t scanned_time = wallet.RescanFromTime(time_begin, reserver, update);
    if (wallet.IsAbortingRescan()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted by user.");
    } else if (scanned_time > time_begin) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan was unable to fully rescan the blockchain. Some transactions may be missing.");
    }
}

UniValue importprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                RPCHelpMan{"importprivkey",
                           "\nAdds a private key (as returned by dumpprivkey) to your wallet. Requires a new wallet backup.\n"
                           "Hint: use importmulti to import more than one private key.\n"
                           "\nNote: This call can take over an hour to complete if rescan is true, during that time, other rpc calls\n"
                           "may report that the imported key exists but related transactions are still missing, leading to temporarily incorrect/bogus balances and unspent outputs until rescan completes.\n",
                           {
                                   {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key (see dumpprivkey)"},
                                   {"label", RPCArg::Type::STR, /* default */ "current label if address exists, otherwise \"\"", "An optional label"},
                                   {"rescan", RPCArg::Type::BOOL, /* default */ "true", "Rescan the wallet for transactions"},
                           },
                           RPCResults{},
                           RPCExamples{
                                   "\nDump a private key\n"
                                   + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
                                   "\nImport the private key with rescan\n"
                                   + HelpExampleCli("importprivkey", "\"mykey\"") +
                                   "\nImport using a label and without rescan\n"
                                   + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
                                   "\nImport using default blank label and without rescan\n"
                                   + HelpExampleCli("importprivkey", "\"mykey\" \"\" false") +
                                   "\nAs a JSON-RPC call\n"
                                   + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
                           },
                }.ToString());

    if (pwalletMain->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot import private keys to a wallet with private keys disabled");
    }

    WalletRescanReserver reserver(pwalletMain);
    bool fRescan = true;
    {
        auto locked_chain = pwalletMain->chain().lock();
        LOCK(pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked(pwalletMain);

        std::string strSecret = request.params[0].get_str();
        std::string strLabel = "";
        if (!request.params[1].isNull())
            strLabel = request.params[1].get_str();

        // Whether to perform rescan after import
        if (!request.params[2].isNull())
            fRescan = request.params[2].get_bool();

        if (fRescan && pwalletMain->chain().getPruneMode()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");
        }

        if (fRescan && !reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
        }

        CKey key = DecodeSecret(strSecret);
        if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID vchAddress = pubkey.GetID();
        {
            pwalletMain->MarkDirty();

            // We don't know which corresponding address will be used;
            // label all new addresses, and label existing addresses if a
            // label was passed.
            for (const auto& dest : GetAllDestinationsForKey(pubkey)) {
                if (!request.params[1].isNull() || pwalletMain->mapAddressBook.count(dest) == 0) {
                    pwalletMain->SetAddressBook(dest, strLabel, "receive");
                }
            }

            // Don't throw error in case a key is already there
            if (pwalletMain->HaveKey(vchAddress)) {
                return NullUniValue;
            }

            // whenever a key is imported, we need to scan the whole chain
            pwalletMain->UpdateTimeFirstKey(1);
            pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1;

            if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
            }
            pwalletMain->LearnAllRelatedScripts(pubkey);
        }
    }
    if (fRescan) {
        RescanWallet(*pwalletMain, reserver);
    }

    return NullUniValue;
}

static void ImportAddress(CWallet*, const CTxDestination& dest, const std::string& strLabel);
static void ImportScript(CWallet* const pwallet, const CScript& script, const std::string& strLabel, bool isRedeemScript) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    if (!isRedeemScript && ::IsMine(*pwallet, script) == ISMINE_SPENDABLE) {
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");
    }

    pwallet->MarkDirty();

    if (!pwallet->HaveWatchOnly(script) && !pwallet->AddWatchOnly(script, 0 /* nCreateTime */)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");
    }

    if (isRedeemScript) {
        const CScriptID id(script);
        if (!pwallet->HaveCScript(id) && !pwallet->AddCScript(script)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding p2sh redeemScript to wallet");
        }
        ImportAddress(pwallet, id, strLabel);
    } else {
        CTxDestination destination;
        if (ExtractDestination(script, destination)) {
            pwallet->SetAddressBook(destination, strLabel, "receive");
        }
    }
}

static void ImportAddress(CWallet* const pwallet, const CTxDestination& dest, const std::string& strLabel) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    CScript script = GetScriptForDestination(dest);
    ImportScript(pwallet, script, strLabel, false);
    // add to address book or update label
    if (IsValidDestination(dest))
        pwallet->SetAddressBook(dest, strLabel, "receive");
}

UniValue importaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
        throw std::runtime_error(
                RPCHelpMan{"importaddress",
                           "\nAdds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend. Requires a new wallet backup.\n"
                           "\nNote: This call can take over an hour to complete if rescan is true, during that time, other rpc calls\n"
                           "may report that the imported address exists but related transactions are still missing, leading to temporarily incorrect/bogus balances and unspent outputs until rescan completes.\n"
                           "If you have the full public key, you should call importpubkey instead of this.\n"
                           "\nNote: If you import a non-standard raw script in hex form, outputs sending to it will be treated\n"
                           "as change, and not show up in many RPCs.\n",
                           {
                                   {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Bitcoin address (or hex-encoded script)"},
                                   {"label", RPCArg::Type::STR, /* default */ "\"\"", "An optional label"},
                                   {"rescan", RPCArg::Type::BOOL, /* default */ "true", "Rescan the wallet for transactions"},
                                   {"p2sh", RPCArg::Type::BOOL, /* default */ "false", "Add the P2SH version of the script as well"},
                           },
                           RPCResults{},
                           RPCExamples{
                                   "\nImport an address with rescan\n"
                                   + HelpExampleCli("importaddress", "\"myaddress\"") +
                                   "\nImport using a label without rescan\n"
                                   + HelpExampleCli("importaddress", "\"myaddress\" \"testing\" false") +
                                   "\nAs a JSON-RPC call\n"
                                   + HelpExampleRpc("importaddress", "\"myaddress\", \"testing\", false")
                           },
                }.ToString());


    std::string strLabel;
    if (!request.params[1].isNull())
        strLabel = request.params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (!request.params[2].isNull())
        fRescan = request.params[2].get_bool();

    if (fRescan && pwalletMain->chain().getPruneMode()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Rescan is disabled in pruned mode");
    }

    WalletRescanReserver reserver(pwalletMain);
    if (fRescan && !reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    // Whether to import a p2sh version, too
    bool fP2SH = false;
    if (!request.params[3].isNull())
        fP2SH = request.params[3].get_bool();

    {
        auto locked_chain = pwalletMain->chain().lock();
        LOCK(pwalletMain->cs_wallet);

        CTxDestination dest = DecodeDestination(request.params[0].get_str());
        if (IsValidDestination(dest)) {
            if (fP2SH) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot use the p2sh flag with an address - use a script instead");
            }
            ImportAddress(pwalletMain, dest, strLabel);
        } else if (IsHex(request.params[0].get_str())) {
            std::vector<unsigned char> data(ParseHex(request.params[0].get_str()));
            ImportScript(pwalletMain, CScript(data.begin(), data.end()), strLabel, fP2SH);
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");
        }
    }
    if (fRescan)
    {
        RescanWallet(*pwalletMain, reserver);
        pwalletMain->ReacceptWalletTransactions();
    }

    return NullUniValue;
}

UniValue importwallet(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                RPCHelpMan{"importwallet",
                           "\nImports keys from a wallet dump file (see dumpwallet). Requires a new wallet backup to include imported keys.\n",
                           {
                                   {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet file"},
                           },
                           RPCResults{},
                           RPCExamples{
                                   "\nDump the wallet\n"
                                   + HelpExampleCli("dumpwallet", "\"test\"") +
                                   "\nImport the wallet\n"
                                   + HelpExampleCli("importwallet", "\"test\"") +
                                   "\nImport using the json rpc call\n"
                                   + HelpExampleRpc("importwallet", "\"test\"")
                           },
                }.ToString());

    if (pwalletMain->chain().getPruneMode()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled in pruned mode");
    }

    WalletRescanReserver reserver(pwalletMain);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int64_t nTimeBegin = 0;
    bool fGood = true;
    {
        auto locked_chain = pwalletMain->chain().lock();
        LOCK(pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked(pwalletMain);

        fsbridge::ifstream file;
        file.open(request.params[0].get_str(), std::ios::in | std::ios::ate);
        if (!file.is_open()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");
        }
        Optional<int> tip_height = locked_chain->getHeight();
        nTimeBegin = tip_height ? locked_chain->getBlockTime(*tip_height) : 0;

        int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
        file.seekg(0, file.beg);

        // Use uiInterface.ShowProgress instead of pwallet.ShowProgress because pwallet.ShowProgress has a cancel button tied to AbortRescan which
        // we don't want for this progress bar showing the import progress. uiInterface.ShowProgress does not have a cancel button.
        uiInterface.ShowProgress(strprintf("%s " + _("Importing..."), pwalletMain->GetDisplayName()), 0); // show progress dialog in GUI
        std::vector<std::tuple<CKey, int64_t, bool, std::string>> keys;
        std::vector<std::pair<CScript, int64_t>> scripts;
        while (file.good()) {
            uiInterface.ShowProgress("", std::max(1, std::min(50, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
            std::string line;
            std::getline(file, line);
            if (line.empty() || line[0] == '#')
                continue;

            std::vector<std::string> vstr;
            boost::split(vstr, line, boost::is_any_of(" "));
            if (vstr.size() < 2)
                continue;
            CKey key = DecodeSecret(vstr[0]);
            if (key.IsValid()) {
                int64_t nTime = DecodeDumpTime(vstr[1]);
                std::string strLabel;
                bool fLabel = true;
                for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
                    if (vstr[nStr].front() == '#')
                        break;
                    if (vstr[nStr] == "change=1")
                        fLabel = false;
                    if (vstr[nStr] == "reserve=1")
                        fLabel = false;
                    if (vstr[nStr].substr(0,6) == "label=") {
                        strLabel = DecodeDumpString(vstr[nStr].substr(6));
                        fLabel = true;
                    }
                }
                keys.push_back(std::make_tuple(key, nTime, fLabel, strLabel));
            } else if(IsHex(vstr[0])) {
                std::vector<unsigned char> vData(ParseHex(vstr[0]));
                CScript script = CScript(vData.begin(), vData.end());
                int64_t birth_time = DecodeDumpTime(vstr[1]);
                scripts.push_back(std::pair<CScript, int64_t>(script, birth_time));
            }
        }
        file.close();
        // We now know whether we are importing private keys, so we can error if private keys are disabled
        if (keys.size() > 0 && pwalletMain->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            uiInterface.ShowProgress("", 100); // hide progress dialog in GUI
            throw JSONRPCError(RPC_WALLET_ERROR, "Importing wallets is disabled when private keys are disabled");
        }
        double total = (double)(keys.size() + scripts.size());
        double progress = 0;
        for (const auto& key_tuple : keys) {
            uiInterface.ShowProgress("", std::max(50, std::min(75, (int)((progress / total) * 100) + 50)));
            const CKey& key = std::get<0>(key_tuple);
            int64_t time = std::get<1>(key_tuple);
            bool has_label = std::get<2>(key_tuple);
            std::string label = std::get<3>(key_tuple);

            CPubKey pubkey = key.GetPubKey();
            assert(key.VerifyPubKey(pubkey));
            CKeyID keyid = pubkey.GetID();
            if (pwalletMain->HaveKey(keyid)) {
                pwalletMain->WalletLogPrintf("Skipping import of %s (key already present)\n", EncodeDestination(keyid));
                continue;
            }
            pwalletMain->WalletLogPrintf("Importing %s...\n", EncodeDestination(keyid));
            if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
                fGood = false;
                continue;
            }
            pwalletMain->mapKeyMetadata[keyid].nCreateTime = time;
            if (has_label)
                pwalletMain->SetAddressBook(keyid, label, "receive");
            nTimeBegin = std::min(nTimeBegin, time);
            progress++;
        }
        for (const auto& script_pair : scripts) {
            uiInterface.ShowProgress("", std::max(50, std::min(75, (int)((progress / total) * 100) + 50)));
            const CScript& script = script_pair.first;
            int64_t time = script_pair.second;
            CScriptID id(script);
            if (pwalletMain->HaveCScript(id)) {
                pwalletMain->WalletLogPrintf("Skipping import of %s (script already present)\n", HexStr(script));
                continue;
            }
            if(!pwalletMain->AddCScript(script)) {
                pwalletMain->WalletLogPrintf("Error importing script %s\n", HexStr(script));
                fGood = false;
                continue;
            }
            if (time > 0) {
                pwalletMain->m_script_metadata[id].nCreateTime = time;
                nTimeBegin = std::min(nTimeBegin, time);
            }
            progress++;
        }
        uiInterface.ShowProgress("", 100); // hide progress dialog in GUI
        pwalletMain->UpdateTimeFirstKey(nTimeBegin);
    }
    uiInterface.ShowProgress("", 100); // hide progress dialog in GUI
    RescanWallet(*pwalletMain, reserver, nTimeBegin, false /* update */);
    pwalletMain->MarkDirty();

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys/scripts to wallet");

    return NullUniValue;
}

UniValue dumpprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "dumpprivkey \"wispraddress\"\n"
            "\nReveals the private key corresponding to 'wispraddress'.\n"
            "Then the importprivkey can be used with this output\n" +
            HelpRequiringPassphrase() + "\n"

            "\nArguments:\n"
            "1. \"wispraddress\"   (string, required) The wispr address for the private key\n"

            "\nResult:\n"
            "\"key\"                (string) The private key\n"

            "\nExamples:\n" +
            HelpExampleCli("dumpprivkey", "\"myaddress\"") + HelpExampleCli("importprivkey", "\"mykey\"") + HelpExampleRpc("dumpprivkey", "\"myaddress\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    std::string strAddress = request.params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid WISPR address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret).ToString();
}


UniValue dumpwallet(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                RPCHelpMan{"dumpwallet",
                           "\nDumps all wallet keys in a human-readable format to a server-side file. This does not allow overwriting existing files.\n"
                           "Imported scripts are included in the dumpfile, but corresponding BIP173 addresses, etc. may not be added automatically by importwallet.\n"
                           "Note that if your wallet contains keys which are not derived from your HD seed (e.g. imported keys), these are not covered by\n"
                           "only backing up the seed itself, and must be backed up too (e.g. ensure you back up the whole dumpfile).\n",
                           {
                                   {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The filename with path (either absolute or relative to bitcoind)"},
                           },
                           RPCResult{
                                   "{                           (json object)\n"
                                   "  \"filename\" : {        (string) The filename with full absolute path\n"
                                   "}\n"
                           },
                           RPCExamples{
                                   HelpExampleCli("dumpwallet", "\"test\"")
                                   + HelpExampleRpc("dumpwallet", "\"test\"")
                           },
                }.ToString());

    auto locked_chain = pwalletMain->chain().lock();
    LOCK(pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked(pwalletMain);

    fs::path filepath = request.params[0].get_str();
    filepath = fs::absolute(filepath);

    /* Prevent arbitrary files from being overwritten. There have been reports
     * that users have overwritten wallet files this way:
     * https://github.com/bitcoin/bitcoin/issues/9934
     * It may also avoid other security issues.
     */
    if (fs::exists(filepath)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, filepath.string() + " already exists. If you are sure this is what you want, move it out of the way first");
    }

    fsbridge::ofstream file;
    file.open(filepath);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CTxDestination, int64_t> mapKeyBirth;
    const std::map<CKeyID, int64_t>& mapKeyPool = pwalletMain->GetAllReserveKeys();
    pwalletMain->GetKeyBirthTimes(*locked_chain, mapKeyBirth);

    std::set<CScriptID> scripts = pwalletMain->GetCScripts();
    // TODO: include scripts in GetKeyBirthTimes() output instead of separate

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (const auto& entry : mapKeyBirth) {
        if (const CKeyID* keyID = boost::get<CKeyID>(&entry.first)) { // set and test
            vKeyBirth.push_back(std::make_pair(entry.second, *keyID));
        }
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    file << strprintf("# Wallet dump created by Bitcoin %s\n", CLIENT_BUILD);
    file << strprintf("# * Created on %s\n", FormatISO8601DateTime(GetTime()));
    const Optional<int> tip_height = locked_chain->getHeight();
    file << strprintf("# * Best block at time of backup was %i (%s),\n", tip_height.get_value_or(-1), tip_height ? locked_chain->getBlockHash(*tip_height).ToString() : "(missing block hash)");
    file << strprintf("#   mined on %s\n", tip_height ? FormatISO8601DateTime(locked_chain->getBlockTime(*tip_height)) : "(missing block time)");
    file << "\n";

    // add the base58check encoded extended master if the wallet uses HD
    CKeyID seed_id = pwalletMain->GetHDChain().seed_id;
    if (!seed_id.IsNull())
    {
        CKey seed;
        if (pwalletMain->GetKey(seed_id, seed)) {
            CExtKey masterKey;
            masterKey.SetSeed(seed.begin(), seed.size());

            file << "# extended private masterkey: " << EncodeExtKey(masterKey) << "\n\n";
        }
    }
    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = FormatISO8601DateTime(it->first);
        std::string strAddr;
        std::string strLabel;
        CKey key;
        if (pwalletMain->GetKey(keyid, key)) {
            file << strprintf("%s %s ", EncodeSecret(key), strTime);
            if (GetWalletAddressesForKey(pwalletMain, keyid, strAddr, strLabel)) {
                file << strprintf("label=%s", strLabel);
            } else if (keyid == seed_id) {
                file << "hdseed=1";
            } else if (mapKeyPool.count(keyid)) {
                file << "reserve=1";
            } else if (pwalletMain->mapKeyMetadata[keyid].hdKeypath == "s") {
                file << "inactivehdseed=1";
            } else {
                file << "change=1";
            }
            file << strprintf(" # addr=%s%s\n", strAddr, (pwalletMain->mapKeyMetadata[keyid].has_key_origin ? " hdkeypath="+WriteHDKeypath(pwalletMain->mapKeyMetadata[keyid].key_origin.path) : ""));
        }
    }
    file << "\n";
    for (const CScriptID &scriptid : scripts) {
        CScript script;
        std::string create_time = "0";
        std::string address = EncodeDestination(scriptid);
        // get birth times for scripts with metadata
        auto it = pwalletMain->m_script_metadata.find(scriptid);
        if (it != pwalletMain->m_script_metadata.end()) {
            create_time = FormatISO8601DateTime(it->second.nCreateTime);
        }
        if(pwalletMain->GetCScript(scriptid, script)) {
            file << strprintf("%s %s script=1", HexStr(script.begin(), script.end()), create_time);
            file << strprintf(" # addr=%s\n", address);
        }
    }
    file << "\n";
    file << "# End of dump\n";
    file.close();

    UniValue reply(UniValue::VOBJ);
    reply.pushKV("filename", filepath.string());

    return reply;
}

UniValue bip38encrypt(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "bip38encrypt \"wispraddress\" \"passphrase\"\n"
            "\nEncrypts a private key corresponding to 'wispraddress'.\n" +
            HelpRequiringPassphrase() + "\n"

            "\nArguments:\n"
            "1. \"wispraddress\"   (string, required) The wispr address for the private key (you must hold the key already)\n"
            "2. \"passphrase\"   (string, required) The passphrase you want the private key to be encrypted with - Valid special chars: !#$%&'()*+,-./:;<=>?`{|}~ \n"

            "\nResult:\n"
            "\"key\"                (string) The encrypted private key\n"

            "\nExamples:\n" +
            HelpExampleCli("bip38encrypt", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" \"mypasphrase\"") +
            HelpExampleRpc("bip38encrypt", "\"DMJRSsuU9zfyrvxVaAEFQqK4MxZg6vgeS6\" \"mypasphrase\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    std::string strAddress = request.params[0].get_str();
    std::string strPassphrase = request.params[1].get_str();

    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid WISPR address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    uint256 privKey = vchSecret.GetPrivKey_256();
    std::string encryptedOut = BIP38_Encrypt(strAddress, strPassphrase, privKey, vchSecret.IsCompressed());

    UniValue result(UniValue::VOBJ);
    result.pushKV("Addess", strAddress);
    result.pushKV("Encrypted Key", encryptedOut);

    return result;
}

UniValue bip38decrypt(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "bip38decrypt \"wispraddress\" \"passphrase\"\n"
            "\nDecrypts and then imports password protected private key.\n" +
            HelpRequiringPassphrase() + "\n"

            "\nArguments:\n"
            "1. \"encryptedkey\"   (string, required) The encrypted private key\n"
            "2. \"passphrase\"   (string, required) The passphrase you want the private key to be encrypted with\n"

            "\nResult:\n"
            "\"key\"                (string) The decrypted private key\n"

            "\nExamples:\n" +
            HelpExampleCli("bip38decrypt", "\"encryptedkey\" \"mypassphrase\"") +
            HelpExampleRpc("bip38decrypt", "\"encryptedkey\" \"mypassphrase\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    /** Collect private key and passphrase **/
    std::string strKey = request.params[0].get_str();
    std::string strPassphrase = request.params[1].get_str();

    uint256 privKey;
    bool fCompressed;
    if (!BIP38_Decrypt(strPassphrase, strKey, privKey, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed To Decrypt");

    UniValue result(UniValue::VOBJ);
    result.pushKV("privatekey", HexStr(privKey));

    CKey key;
    key.Set(privKey.begin(), privKey.end(), fCompressed);

    if (!key.IsValid())
        throw JSONRPCError(RPC_WALLET_ERROR, "Private Key Not Valid");

    CPubKey pubkey = key.GetPubKey();
    pubkey.IsCompressed();
    assert(key.VerifyPubKey(pubkey));
    result.pushKV("Address", CBitcoinAddress(pubkey.GetID()).ToString());
    CKeyID vchAddress = pubkey.GetID();
    WalletRescanReserver reserver(pwalletMain);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }
    {
        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBook(vchAddress, "", "receive");

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress))
            throw JSONRPCError(RPC_WALLET_ERROR, "Key already held by wallet");

        pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!pwalletMain->AddKeyPubKey(key, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        // whenever a key is imported, we need to scan the whole chain
        pwalletMain->UpdateTimeFirstKey(1); // 0 would be considered 'no value'
//        pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
        RescanWallet(*pwalletMain, reserver);
    }

    return result;
}
