// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/client.h>
#include <rpc/protocol.h>
#include <util/system.h>

#include <set>
#include <stdint.h>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
};

// clang-format off
/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    { "setmocktime", 0, "timestamp" },
    { "generatetoaddress", 0, "nblocks" },
    { "generatetoaddress", 2, "maxtries" },
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 4, "subtractfeefromamount" },
    { "sendtoaddress", 5 , "replaceable" },
    { "sendtoaddress", 6 , "conf_target" },
    { "settxfee", 0, "amount" },
    { "sethdseed", 0, "newkeypool" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbylabel", 1, "minconf" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbylabel", 0, "minconf" },
    { "listreceivedbylabel", 1, "include_empty" },
    { "listreceivedbylabel", 2, "include_watchonly" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getblockhash", 0, "height" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitforblock", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "walletpassphrase", 1, "timeout" },
    { "getblocktemplate", 0, "template_request" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 4, "subtractfeefrom" },
    { "sendmany", 5 , "replaceable" },
    { "sendmany", 6 , "conf_target" },
    { "deriveaddresses", 1, "range" },
    { "scantxoutset", 1, "scanobjects" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "listunspent", 4, "query_options" },
    { "getblock", 1, "verbosity" },
    { "getblock", 1, "verbose" },
    { "getblockheader", 1, "verbose" },
    { "getchaintxstats", 0, "nblocks" },
    { "gettransaction", 1, "include_watchonly" },
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "createrawtransaction", 3, "replaceable" },
    { "decoderawtransaction", 1, "iswitness" },
    { "signrawtransactionwithkey", 1, "privkeys" },
    { "signrawtransactionwithkey", 2, "prevtxs" },
    { "signrawtransactionwithwallet", 1, "prevtxs" },
    { "sendrawtransaction", 1, "allowhighfees" },
    { "sendrawtransaction", 1, "maxfeerate" },
    { "testmempoolaccept", 0, "rawtxs" },
    { "testmempoolaccept", 1, "allowhighfees" },
    { "testmempoolaccept", 1, "maxfeerate" },
    { "combinerawtransaction", 0, "txs" },
    { "fundrawtransaction", 1, "options" },
    { "fundrawtransaction", 2, "iswitness" },
    { "walletcreatefundedpsbt", 0, "inputs" },
    { "walletcreatefundedpsbt", 1, "outputs" },
    { "walletcreatefundedpsbt", 2, "locktime" },
    { "walletcreatefundedpsbt", 3, "options" },
    { "walletcreatefundedpsbt", 4, "bip32derivs" },
    { "walletprocesspsbt", 1, "sign" },
    { "walletprocesspsbt", 3, "bip32derivs" },
    { "createpsbt", 0, "inputs" },
    { "createpsbt", 1, "outputs" },
    { "createpsbt", 2, "locktime" },
    { "createpsbt", 3, "replaceable" },
    { "combinepsbt", 0, "txs"},
    { "joinpsbts", 0, "txs"},
    { "finalizepsbt", 1, "extract"},
    { "converttopsbt", 1, "permitsigdata"},
    { "converttopsbt", 2, "iswitness"},
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "importprivkey", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importpubkey", 2, "rescan" },
    { "importmulti", 0, "requests" },
    { "importmulti", 1, "options" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "getblockstats", 0, "hash_or_height" },
    { "getblockstats", 1, "stats" },
    { "pruneblockchain", 0, "height" },
    { "keypoolrefill", 0, "newsize" },
    { "getrawmempool", 0, "verbose" },
    { "estimatesmartfee", 0, "conf_target" },
    { "estimaterawfee", 0, "conf_target" },
    { "estimaterawfee", 1, "threshold" },
    { "prioritisetransaction", 1, "dummy" },
    { "prioritisetransaction", 2, "fee_delta" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setnetworkactive", 0, "state" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },
    { "bumpfee", 1, "options" },
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "disconnectnode", 1, "nodeid" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
    { "rescanblockchain", 0, "start_height"},
    { "rescanblockchain", 1, "stop_height"},
    { "createwallet", 1, "disable_private_keys"},
    { "createwallet", 2, "blank"},
    { "getnodeaddresses", 0, "count"},
    { "stop", 0, "wait" },

    //!WISPR
    //TODO fix params
    { "sendrawtransaction", 2, "instantsend" },
    { "sendrawtransaction", 3, "bypasslimits" },

    {"getaddednodeinfo", 0, "dns"},
    {"setgenerate", 0, "generate"},
    {"setgenerate", 1, "genproclimit"},
    {"sendtoaddressix", 1, "amount"},
    { "move", 2, "amount" },
    { "move", 3, "minconf" },
    { "sendfrom", 2, "amount" },
    { "sendfrom", 3, "minconf" },
    { "listaccounts", 0, "minconf" },
    { "listaccounts", 1, "addlockconf" },
    { "walletpassphrase", 2, "mixingonly" },
    { "estimatefee", 0, "nblocks" },
    { "estimatepriority", 0, "nblocks" },
    { "spork", 1, "value" },
    {"mnbudget", 3, ""},
    {"mnbudget", 4, ""},
    {"mnbudget", 6, ""},
    {"mnbudget", 8, ""},
    {"preparebudget", 2, "payment-count"},
    {"preparebudget", 3, "block-start"},
    {"preparebudget", 5, "monthly-payment"},
    {"submitbudget", 4, "payment-count"},
    {"submitbudget", 5, "block-start"},
    {"submitbudget", 7, "monthly-payment"},
    // disabled until removal of the legacy 'masternode' command
    //{"startmasternode", 1},
    {"mnvoteraw", 1, ""},
    {"mnvoteraw", 4, ""},
    {"reservebalance", 0, "reserve"},
    {"reservebalance", 1, "amount"},
    {"setstakesplitthreshold", 0, "value"},
    {"autocombinerewards", 0, "enable"},
    {"autocombinerewards", 1, "threshold"},
    {"getzerocoinbalance", 0, ""},
    {"listmintedzerocoins", 0, "fVerbose"},
    {"listmintedzerocoins", 1, "fMatureOnly"},
    {"listspentzerocoins", 0, ""},
    {"listzerocoinamounts", 0, ""},
    {"mintzerocoin", 0, "amount"},
    {"mintzerocoin", 1, "utxos"},
    {"spendzerocoin", 0, "amount"},
    {"spendzerocoin", 1, "mintchange"},
    {"spendzerocoin", 2, "minimizechange"},
    {"spendzerocoinmints", 0, "mints_list"},
    {"importzerocoins", 0, "importdata"},
    {"exportzerocoins", 0, "include_spent"},
    {"exportzerocoins", 1, "denomination"},
    {"resetmintzerocoin", 0, "fullscan"},
    {"getspentzerocoinamount", 1, "index"},
    {"generatemintlist", 0, "count"},
    {"generatemintlist", 1, "range"},
    {"searchdzwsp", 0, "count"},
    {"searchdzwsp", 1, "range"},
    {"searchdzwsp", 2, "threads"},
    {"getaccumulatorvalues", 0, "height"},
    {"getaccumulatorwitness",2, "coinDenomination"},
    {"getmintsvalues", 2, ""},
    {"enableautomintaddress", 0, "enable"},
    {"getmintsinblocks", 0, "height"},
    {"getmintsinblocks", 1, "range"},
    {"getmintsinblocks", 2, "coinDenomination"},
    {"getfeeinfo", 0, "blocks"},
    {"getserials", 0, "starting_height"},
    {"getserials", 1, "range"},
    {"getserials", 2, "fVerbose"}
};
// clang-format on

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
    bool convert(const std::string& method, const std::string& name) {
        return (membersByName.count(std::make_pair(method, name)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
        membersByName.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                            vRPCConvertParams[i].paramName));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw std::runtime_error(std::string("Error parsing JSON:")+strVal);
    return jVal[0];
}

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);

    for (const std::string &s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string::npos) {
            throw(std::runtime_error("No '=' in named argument '"+s+"', this needs to be present for every argument (even if it is empty)"));
        }

        std::string name = s.substr(0, pos);
        std::string value = s.substr(pos+1);

        if (!rpcCvtTable.convert(strMethod, name)) {
            // insert string value directly
            params.pushKV(name, value);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.pushKV(name, ParseNonRFCJSONValue(value));
        }
    }

    return params;
}
