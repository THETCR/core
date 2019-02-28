// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
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
    std::string methodName; //! method whose params want conversion
    int paramIdx;           //! 0-based idx of param to convert
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
    { "stop", 0, "wait" },
    { "setmocktime", 0, "timestamp" },
    {"getaddednodeinfo", 0, "dns"},
    {"setgenerate", 0, "generate"},
    {"setgenerate", 1, "genproclimit"},
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "sendtoaddress", 1, "amount" },
    {"sendtoaddressix", 1, "amount"},
    { "settxfee", 0, "amount" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaccount", 1, "minconf" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "addlockconf" },
    { "listreceivedbyaddress", 2, "include_empty" },
    { "listreceivedbyaccount", 0, "minconf" },
    { "listreceivedbyaccount", 1, "addlockconf" },
    { "listreceivedbyaccount", 2, "include_empty" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "addlockconf" },
    { "getblockhash", 0, "height" },
    { "move", 2, "amount" },
    { "move", 3, "minconf" },
    { "sendfrom", 2, "amount" },
    { "sendfrom", 3, "minconf" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "listaccounts", 0, "minconf" },
    { "listaccounts", 1, "addlockconf" },
    { "walletpassphrase", 1, "timeout" },
    { "walletpassphrase", 2, "mixingonly" },
    { "getblocktemplate", 0, "template_request" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "getblock", 1, "verbosity" },
    { "getblockheader", 1, "verbose" },
    { "gettransaction", 1, "include_watchonly" },
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "signrawtransaction", 1, "prevtxs" },
    { "signrawtransaction", 2, "privkeys" },
    { "sendrawtransaction", 1, "allowhighfees" },
    { "sendrawtransaction", 2, "instantsend" },
    { "sendrawtransaction", 3, "bypasslimits" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "importprivkey", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "keypoolrefill", 0, "newsize" },
    { "getrawmempool", 0, "verbose" },
    { "estimatefee", 0, "nblocks" },
    { "estimatepriority", 0, "nblocks" },
    { "prioritisetransaction", 1, "priority_delta" },
    { "prioritisetransaction", 2, "fee_delta" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
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
        {"spendzerocoin", 3, "securitylevel"},
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
        {"getfeeinfo", 0, "blocks"}
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
