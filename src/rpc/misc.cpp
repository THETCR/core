// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <core_io.h>
#include <crypto/ripemd160.h>
#include <key_io.h>
#include <validation.h>
#include <httpserver.h>
#include <net.h>
#include <netbase.h>
#include <outputtype.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <timedata.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <warnings.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#endif

#include <stdint.h>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <univalue.h>

//!WISPR
#include <masternode-sync.h>
#include <spork.h>


/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "\nReturns an object containing various state info.\n"

            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total wispr balance of the wallet (excluding zerocoins)\n"
            "  \"zerocoinbalance\": xxxxxxx, (numeric) the total zerocoin balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"moneysupply\" : \"supply\"       (numeric) The money supply when this block was added to the blockchain\n"
            "  \"zWSPsupply\" :\n"
            "  {\n"
            "     \"1\" : n,            (numeric) supply of 1 zWSP denomination\n"
            "     \"5\" : n,            (numeric) supply of 5 zWSP denomination\n"
            "     \"10\" : n,           (numeric) supply of 10 zWSP denomination\n"
            "     \"50\" : n,           (numeric) supply of 50 zWSP denomination\n"
            "     \"100\" : n,          (numeric) supply of 100 zWSP denomination\n"
            "     \"500\" : n,          (numeric) supply of 500 zWSP denomination\n"
            "     \"1000\" : n,         (numeric) supply of 1000 zWSP denomination\n"
            "     \"5000\" : n,         (numeric) supply of 5000 zWSP denomination\n"
            "     \"total\" : n,        (numeric) The total supply of all zWSP denominations\n"
            "  }\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in wispr/kb\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in wispr/kb\n"
            "  \"staking status\": true|false,  (boolean) if the wallet is staking or not\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getinfo", "") + HelpExampleRpc("getinfo", ""));

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    std::string services;
    for (int i = 0; i < 8; i++) {
        uint64_t check = 1 << i;
        if (g_connman->GetLocalServices() & check) {
            switch (check) {
                case NODE_NETWORK:
                    services+= "NETWORK/";
                    break;
                case NODE_BLOOM:
                    services+= "BLOOM/";
                    break;
                case NODE_BLOOM_WITHOUT_MN:
                case NODE_BLOOM_LIGHT_ZC:
                    services+= "BLOOM_ZC/";
                    break;
                default:
                    services+= "UNKNOWN/";
            }
        }
    }

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", CLIENT_VERSION);
    obj.pushKV("protocolversion", PROTOCOL_VERSION);
    obj.pushKV("services", services);
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.pushKV("walletversion", pwalletMain->GetVersion());
        obj.pushKV("balance", ValueFromAmount(pwalletMain->GetBalance()));
        obj.pushKV("zerocoinbalance", ValueFromAmount(pwalletMain->GetZerocoinBalance(true)));
    }
#endif
    obj.pushKV("blocks", (int)chainActive.Height());
    obj.pushKV("timeoffset", GetTimeOffset());
    obj.pushKV("connections", (int)vNodes.size());
    obj.pushKV("proxy", (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string()));
    obj.pushKV("difficulty", (double)GetDifficulty(chainActive.Tip()));
    obj.pushKV("testnet", Params().TestnetToBeDeprecatedFieldRPC());

    // During inital block verification chainActive.Tip() might be not yet initialized
    if (chainActive.Tip() == nullptr) {
        obj.pushKV("status", "Blockchain information not yet available");
        return obj;
    }

    obj.pushKV("moneysupply",ValueFromAmount(chainActive.Tip()->nMoneySupply));
    UniValue zwspObj(UniValue::VOBJ);
    for (auto denom : libzerocoin::zerocoinDenomList) {
        zwspObj.pushKV(to_string(denom), ValueFromAmount(chainActive.Tip()->mapZerocoinSupply.at(denom) * (denom*COIN)));
    }
    zwspObj.pushKV("total", ValueFromAmount(chainActive.Tip()->GetZerocoinSupply()));
    obj.pushKV("zWSPsupply", zwspObj);

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.pushKV("keypoololdest", pwalletMain->GetOldestKeyPoolTime());
        obj.pushKV("keypoolsize", (int)pwalletMain->GetKeyPoolSize());
    }
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.pushKV("unlocked_until", pwalletMain->nRelockTime);
    obj.pushKV("paytxfee", ValueFromAmount(payTxFee.GetFeePerK()));
#endif
    obj.pushKV("relayfee", ValueFromAmount(::minRelayTxFee.GetFeePerK()));
    bool nStaking = false;
    if (mapHashedBlocks.count(chainActive.Tip()->nHeight))
        nStaking = true;
    else if (mapHashedBlocks.count(chainActive.Tip()->nHeight - 1) && nLastCoinStakeSearchInterval)
        nStaking = true;
    obj.pushKV("staking status", (nStaking ? "Staking Active" : "Staking Not Active"));
    obj.pushKV("errors", GetWarnings("statusbar"));
    return obj;
}

static UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            RPCHelpMan{"validateaddress",
                "\nReturn information about the given bitcoin address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to validate"},
                },
                RPCResult{
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\",        (string) The bitcoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex-encoded scriptPubKey generated by the address\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"iswitness\" : true|false,     (boolean) If the address is a witness address\n"
            "  \"witness_version\" : version   (numeric, optional) The version number of the witness program\n"
            "  \"witness_program\" : \"hex\"     (string, optional) The hex value of the witness program\n"
            "}\n"
                },
                RPCExamples{
                    HelpExampleCli("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("validateaddress", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
                },
            }.ToString());

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    bool isValid = IsValidDestination(dest);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("isvalid", isValid);
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

        UniValue detail = DescribeAddress(dest);
        ret.pushKVs(detail);
    }
    return ret;
}

/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(const UniValue& params)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)",
                keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++) {
        const std::string& ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: WISPR address and we have full public key:
        CBitcoinAddress address(ks);
        if (pwalletMain && address.IsValid()) {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key", ks));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s", ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: " + ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
            if (IsHex(ks)) {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: " + ks);
            pubkeys[i] = vchPubKey;
        } else {
            throw runtime_error(" Invalid public key: " + ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
            strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE));

    return result;
}

static UniValue createmultisig(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
    {
        std::string msg =
            RPCHelpMan{"createmultisig",
                "\nCreates a multi-signature address with n signature of m keys required.\n"
                "It returns a json object with the address and redeemScript.\n",
                {
                    {"nrequired", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of required signatures out of the n keys."},
                    {"keys", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array of hex-encoded public keys.",
                        {
                            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The hex-encoded public key"},
                        }},
                    {"address_type", RPCArg::Type::STR, /* default */ "legacy", "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                },
                RPCResult{
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"
                },
                RPCExamples{
            "\nCreate a multisig address from 2 public keys\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"")
                },
            }.ToString();
        throw std::runtime_error(msg);
    }

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); ++i) {
        if (IsHex(keys[i].get_str()) && (keys[i].get_str().length() == 66 || keys[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys[i].get_str()));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid public key: %s\n.", keys[i].get_str()));
        }
    }

    // Get the output type
    OutputType output_type = OutputType::LEGACY;
    if (!request.params[2].isNull()) {
        if (!ParseOutputType(request.params[2].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[2].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    const CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    CBasicKeyStore keystore;
    const CTxDestination dest = AddAndGetDestinationForScript(keystore, inner, output_type);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));

    return result;
}

UniValue getdescriptorinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"getdescriptorinfo",
            {"\nAnalyses a descriptor.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
            },
            RPCResult{
            "{\n"
            "  \"descriptor\" : \"desc\",         (string) The descriptor in canonical form, without private keys\n"
            "  \"isrange\" : true|false,        (boolean) Whether the descriptor is ranged\n"
            "  \"issolvable\" : true|false,     (boolean) Whether the descriptor is solvable\n"
            "  \"hasprivatekeys\" : true|false, (boolean) Whether the input descriptor contained at least one private key\n"
            "}\n"
            },
            RPCExamples{
                "Analyse a descriptor\n" +
                HelpExampleCli("getdescriptorinfo", "\"wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)\"")
            }}.ToString()
        );
    }

    RPCTypeCheck(request.params, {UniValue::VSTR});

    FlatSigningProvider provider;
    auto desc = Parse(request.params[0].get_str(), provider);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor"));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("descriptor", desc->ToString());
    result.pushKV("isrange", desc->IsRange());
    result.pushKV("issolvable", desc->IsSolvable());
    result.pushKV("hasprivatekeys", provider.keys.size() > 0);
    return result;
}

UniValue deriveaddresses(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.empty() || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"deriveaddresses",
            {"\nDerives one or more addresses corresponding to an output descriptor.\n"
            "Examples of output descriptors are:\n"
            "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
            "    wpkh(<pubkey>)                       Native segwit P2PKH outputs for the given pubkey\n"
            "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
            "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
            "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
            "or more path elements separated by \"/\", where \"h\" represents a hardened child key.\n"
            "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
                {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED_NAMED_ARG, "If a ranged descriptor is used, this specifies the end or the range (in [begin,end] notation) to derive."},
            },
            RPCResult{
                "[ address ] (array) the derived addresses\n"
            },
            RPCExamples{
                "First three native segwit receive addresses\n" +
                HelpExampleCli("deriveaddresses", "\"wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#trd0mf0l\" \"[0,2]\"")
            }}.ToString()
        );
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValueType()}); // Range argument is checked later
    const std::string desc_str = request.params[0].get_str();

    int64_t range_begin = 0;
    int64_t range_end = 0;

    if (request.params.size() >= 2 && !request.params[1].isNull()) {
        auto range = ParseRange(request.params[1]);
        if (range.first < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should be greater or equal than 0");
        }
        if ((range.second >> 31) != 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "End of range is too high");
        }
        if (range.second >= range.first + 1000000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Range is too large");
        }
        range_begin = range.first;
        range_end = range.second;
    }

    FlatSigningProvider provider;
    auto desc = Parse(desc_str, provider, /* require_checksum = */ true);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor"));
    }

    if (!desc->IsRange() && request.params.size() > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
    }

    if (desc->IsRange() && request.params.size() == 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range must be specified for a ranged descriptor");
    }

    UniValue addresses(UniValue::VARR);

    for (int i = range_begin; i <= range_end; ++i) {
        std::vector<CScript> scripts;
        if (!desc->Expand(i, provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys"));
        }

        for (const CScript &script : scripts) {
            CTxDestination dest;
            if (!ExtractDestination(script, dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Descriptor does not have a corresponding address"));
            }

            addresses.push_back(EncodeDestination(dest));
        }
    }

    // This should not be possible, but an assert seems overkill:
    if (addresses.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unexpected empty result");
    }

    return addresses;
}

static UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            RPCHelpMan{"verifymessage",
                "\nVerify a signed message\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to use for the signature."},
                    {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature provided by the signer in base 64 encoding (see signmessage)."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
                },
                RPCResult{
            "true|false   (boolean) If the signature is verified or not.\n"
                },
                RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
                },
            }.ToString());

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    CTxDestination destination = DecodeDestination(strAddress);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&destination);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == *keyID);
}

static UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            RPCHelpMan{"signmessagewithprivkey",
                "\nSign a message with the private key of an address\n",
                {
                    {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key to sign the message with."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
                },
                RPCResult{
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
                },
                RPCExamples{
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
                },
            }.ToString());

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CKey key = DecodeSecret(strPrivkey);
    if (!key.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

static UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            RPCHelpMan{"setmocktime",
                "\nSet the local time to given timestamp (-regtest only)\n",
                {
                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."},
                },
                RPCResults{},
                RPCExamples{""},
            }.ToString()
        );

    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("setmocktime for regression testing (-regtest mode) only");

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("used", uint64_t(stats.used));
    obj.pushKV("free", uint64_t(stats.free));
    obj.pushKV("total", uint64_t(stats.total));
    obj.pushKV("locked", uint64_t(stats.locked));
    obj.pushKV("chunks_used", uint64_t(stats.chunks_used));
    obj.pushKV("chunks_free", uint64_t(stats.chunks_free));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

static UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            RPCHelpMan{"getmemoryinfo",
                "Returns an object containing information about memory usage.\n",
                {
                    {"mode", RPCArg::Type::STR, /* default */ "\"stats\"", "determines what kind of information is returned.\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+)."},
                },
                {
                    RPCResult{"mode \"stats\"",
            "{\n"
            "  \"locked\": {               (json object) Information about locked memory manager\n"
            "    \"used\": xxxxx,          (numeric) Number of bytes used\n"
            "    \"free\": xxxxx,          (numeric) Number of bytes available in current arenas\n"
            "    \"total\": xxxxxxx,       (numeric) Total number of bytes managed\n"
            "    \"locked\": xxxxxx,       (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n"
            "    \"chunks_used\": xxxxx,   (numeric) Number allocated chunks\n"
            "    \"chunks_free\": xxxxx,   (numeric) Number unused chunks\n"
            "  }\n"
            "}\n"
                    },
                    RPCResult{"mode \"mallocinfo\"",
            "\"<malloc version=\"1\">...\"\n"
                    },
                },
                RPCExamples{
                    HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
                },
            }.ToString());

    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("locked", RPCLockedMemoryInfo());
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
}

static void EnableOrDisableLogCategories(UniValue cats, bool enable) {
    cats = cats.get_array();
    for (unsigned int i = 0; i < cats.size(); ++i) {
        std::string cat = cats[i].get_str();

        bool success;
        if (enable) {
            success = LogInstance().EnableCategory(cat);
        } else {
            success = LogInstance().DisableCategory(cat);
        }

        if (!success) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
    }
}

UniValue logging(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"logging",
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + ListLogCategories() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            "  - \"none\", \"0\" : even if other logging categories are specified, ignore all of them.\n"
            ,
                {
                    {"include", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "A json array of categories to add debug logging",
                        {
                            {"include_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                    {"exclude", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "A json array of categories to remove debug logging",
                        {
                            {"exclude_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                },
                RPCResult{
            "{                   (json object where keys are the logging categories, and values indicates its status\n"
            "  \"category\": true|false,  (bool) if being debug logged or not. false:inactive, true:active\n"
            "  ...\n"
            "}\n"
                },
                RPCExamples{
                    HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], [\"libevent\"]")
                },
            }.ToString());
    }

    uint32_t original_log_categories = LogInstance().GetCategoryMask();
    if (request.params[0].isArray()) {
        EnableOrDisableLogCategories(request.params[0], true);
    }
    if (request.params[1].isArray()) {
        EnableOrDisableLogCategories(request.params[1], false);
    }
    uint32_t updated_log_categories = LogInstance().GetCategoryMask();
    uint32_t changed_log_categories = original_log_categories ^ updated_log_categories;

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    if (changed_log_categories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(LogInstance().WillLogCategory(BCLog::LIBEVENT))) {
            LogInstance().DisableCategory(BCLog::LIBEVENT);
            if (changed_log_categories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    std::vector<CLogCategoryActive> vLogCatActive = ListActiveLogCategories();
    for (const auto& logCatActive : vLogCatActive) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
}

static UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            RPCHelpMan{"echo|echojson ...",
                "\nSimply echo back the input arguments. This command is for testing.\n"
                "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in "
                "bitcoin-cli and the GUI. There is no server-side difference.",
                {},
                RPCResults{},
                RPCExamples{""},
            }.ToString()
        );

    return request.params;
}

//!WISPR
UniValue mnsync(const JSONRPCRequest& request)
{
    std::string strMode;
    if (request.params.size() == 1)
        strMode = request.params[0].get_str();

    if (request.fHelp || request.params.size() != 1 || (strMode != "status" && strMode != "reset")) {
        throw runtime_error(
            "mnsync \"status|reset\"\n"
            "\nReturns the sync status or resets sync.\n"

            "\nArguments:\n"
            "1. \"mode\"    (string, required) either 'status' or 'reset'\n"

            "\nResult ('status' mode):\n"
            "{\n"
            "  \"IsBlockchainSynced\": true|false,    (boolean) 'true' if blockchain is synced\n"
            "  \"lastMasternodeList\": xxxx,        (numeric) Timestamp of last MN list message\n"
            "  \"lastMasternodeWinner\": xxxx,      (numeric) Timestamp of last MN winner message\n"
            "  \"lastBudgetItem\": xxxx,            (numeric) Timestamp of last MN budget message\n"
            "  \"lastFailure\": xxxx,           (numeric) Timestamp of last failed sync\n"
            "  \"nCountFailures\": n,           (numeric) Number of failed syncs (total)\n"
            "  \"sumMasternodeList\": n,        (numeric) Number of MN list messages (total)\n"
            "  \"sumMasternodeWinner\": n,      (numeric) Number of MN winner messages (total)\n"
            "  \"sumBudgetItemProp\": n,        (numeric) Number of MN budget messages (total)\n"
            "  \"sumBudgetItemFin\": n,         (numeric) Number of MN budget finalization messages (total)\n"
            "  \"countMasternodeList\": n,      (numeric) Number of MN list messages (local)\n"
            "  \"countMasternodeWinner\": n,    (numeric) Number of MN winner messages (local)\n"
            "  \"countBudgetItemProp\": n,      (numeric) Number of MN budget messages (local)\n"
            "  \"countBudgetItemFin\": n,       (numeric) Number of MN budget finalization messages (local)\n"
            "  \"RequestedMasternodeAssets\": n, (numeric) Status code of last sync phase\n"
            "  \"RequestedMasternodeAttempt\": n, (numeric) Status code of last sync attempt\n"
            "}\n"

            "\nResult ('reset' mode):\n"
            "\"status\"     (string) 'success'\n"

            "\nExamples:\n" +
            HelpExampleCli("mnsync", "\"status\"") + HelpExampleRpc("mnsync", "\"status\""));
    }

    if (strMode == "status") {
        UniValue obj(UniValue::VOBJ);

        obj.pushKV("IsBlockchainSynced", masternodeSync.IsBlockchainSynced());
        obj.pushKV("lastMasternodeList", masternodeSync.lastMasternodeList);
        obj.pushKV("lastMasternodeWinner", masternodeSync.lastMasternodeWinner);
        obj.pushKV("lastBudgetItem", masternodeSync.lastBudgetItem);
        obj.pushKV("lastFailure", masternodeSync.lastFailure);
        obj.pushKV("nCountFailures", masternodeSync.nCountFailures);
        obj.pushKV("sumMasternodeList", masternodeSync.sumMasternodeList);
        obj.pushKV("sumMasternodeWinner", masternodeSync.sumMasternodeWinner);
        obj.pushKV("sumBudgetItemProp", masternodeSync.sumBudgetItemProp);
        obj.pushKV("sumBudgetItemFin", masternodeSync.sumBudgetItemFin);
        obj.pushKV("countMasternodeList", masternodeSync.countMasternodeList);
        obj.pushKV("countMasternodeWinner", masternodeSync.countMasternodeWinner);
        obj.pushKV("countBudgetItemProp", masternodeSync.countBudgetItemProp);
        obj.pushKV("countBudgetItemFin", masternodeSync.countBudgetItemFin);
        obj.pushKV("RequestedMasternodeAssets", masternodeSync.RequestedMasternodeAssets);
        obj.pushKV("RequestedMasternodeAttempt", masternodeSync.RequestedMasternodeAttempt);

        return obj;
    }

    if (strMode == "reset") {
        masternodeSync.Reset();
        return "success";
    }
    return "failure";
}

/*
    Used for updating/reading spork settings on the network
*/
UniValue spork(const JSONRPCRequest& request)
{
    if (request.params.size() == 1 && request.params[0].get_str() == "show") {
        UniValue ret(UniValue::VOBJ);
        for (int nSporkID = SPORK_START; nSporkID <= SPORK_END; nSporkID++) {
            if (sporkManager.GetSporkNameByID(nSporkID) != "Unknown")
                ret.pushKV(sporkManager.GetSporkNameByID(nSporkID), GetSporkValue(nSporkID));
        }
        return ret;
    } else if (request.params.size() == 1 && request.params[0].get_str() == "active") {
        UniValue ret(UniValue::VOBJ);
        for (int nSporkID = SPORK_START; nSporkID <= SPORK_END; nSporkID++) {
            if (sporkManager.GetSporkNameByID(nSporkID) != "Unknown")
                ret.pushKV(sporkManager.GetSporkNameByID(nSporkID), IsSporkActive(nSporkID));
        }
        return ret;
    } else if (request.params.size() == 2) {
        int nSporkID = sporkManager.GetSporkIDByName(request.params[0].get_str());
        if (nSporkID == -1) {
            return "Invalid spork name";
        }

        // SPORK VALUE
        int64_t nValue = request.params[1].get_int64();

        //broadcast new spork
        if (sporkManager.UpdateSpork(nSporkID, nValue)) {
            return "success";
        } else {
            return "failure";
        }
    }

    throw runtime_error(
        "spork \"name\" ( value )\n"
        "\nReturn spork values or their active state.\n"

        "\nArguments:\n"
        "1. \"name\"        (string, required)  \"show\" to show values, \"active\" to show active state.\n"
        "                       When set up as a spork signer, the name of the spork can be used to update it's value.\n"
        "2. value           (numeric, required when updating a spork) The new value for the spork.\n"

        "\nResult (show):\n"
        "{\n"
        "  \"spork_name\": nnn      (key/value) Key is the spork name, value is it's current value.\n"
        "  ,...\n"
        "}\n"

        "\nResult (active):\n"
        "{\n"
        "  \"spork_name\": true|false      (key/value) Key is the spork name, value is a boolean for it's active state.\n"
        "  ,...\n"
        "}\n"

        "\nResult (name):\n"
        " \"success|failure\"       (string) Wither or not the update succeeded.\n"

        "\nExamples:\n" +
        HelpExampleCli("spork", "show") + HelpExampleRpc("spork", "show"));
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getmemoryinfo",          &getmemoryinfo,          {"mode"} },
    { "control",            "logging",                &logging,                {"include", "exclude"}},
    { "util",               "validateaddress",        &validateaddress,        {"address"} },
    { "util",               "createmultisig",         &createmultisig,         {"nrequired","keys","address_type"} },
    { "util",               "deriveaddresses",        &deriveaddresses,        {"descriptor", "range"} },
    { "util",               "getdescriptorinfo",      &getdescriptorinfo,      {"descriptor"} },
    { "util",               "verifymessage",          &verifymessage,          {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, {"privkey","message"} },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            {"timestamp"}},
    { "hidden",             "echo",                   &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},

    //!WISPR
    {"wispr", "mnsync", &mnsync,{}},
    {"wispr", "spork", &spork,{}},
};
// clang-format on

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
