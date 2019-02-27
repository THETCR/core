// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>

#include "base58.h"
#include <fs.h>
#include <key_io.h>
#include <random.h>
#include <rpc/util.h>
#include <shutdown.h>
#include <sync.h>
#include <ui_interface.h>
#include <util/strencodings.h>
#include <util/system.h>
#ifdef ENABLE_WALLET
#include <wallet/db.h>
#include <wallet/wallet.h>
#endif

#include <boost/signals2/signal.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include <memory> // for unique_ptr
#include <unordered_map>

static CCriticalSection cs_rpcWarmup;
static std::atomic<bool> g_rpc_running{false};
static bool fRPCInWarmup GUARDED_BY(cs_rpcWarmup) = true;
static std::string rpcWarmupStatus GUARDED_BY(cs_rpcWarmup) = "RPC server started";
/* Timer-creating functions */
static RPCTimerInterface* timerInterface = nullptr;

/* Map of name to timer. */
static std::map<std::string, std::unique_ptr<RPCTimerBase> > deadlineTimers;

struct RPCCommandExecutionInfo
{
    std::string method;
    int64_t start;
};

struct RPCServerInfo
{
    Mutex mutex;
    std::list<RPCCommandExecutionInfo> active_commands GUARDED_BY(mutex);
};

static RPCServerInfo g_rpc_server_info;

struct RPCCommandExecution
{
    std::list<RPCCommandExecutionInfo>::iterator it;
    explicit RPCCommandExecution(const std::string& method)
    {
        LOCK(g_rpc_server_info.mutex);
        it = g_rpc_server_info.active_commands.insert(g_rpc_server_info.active_commands.end(), {method, GetTimeMicros()});
    }
    ~RPCCommandExecution()
    {
        LOCK(g_rpc_server_info.mutex);
        g_rpc_server_info.active_commands.erase(it);
    }
};

static struct CRPCSignals
{
    boost::signals2::signal<void ()> Started;
    boost::signals2::signal<void ()> Stopped;
    boost::signals2::signal<void (const CRPCCommand&)> PreCommand;
    boost::signals2::signal<void (const CRPCCommand&)> PostCommand;
} g_rpcSignals;

void RPCServer::OnStarted(std::function<void ()> slot)
{
    g_rpcSignals.Started.connect(slot);
}

void RPCServer::OnStopped(std::function<void ()> slot)
{
    g_rpcSignals.Stopped.connect(slot);
}

void RPCServer::OnPreCommand(std::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PreCommand.connect(boost::bind(slot, _1));
}

void RPCServer::OnPostCommand(std::function<void (const CRPCCommand&)> slot)
{
    g_rpcSignals.PostCommand.connect(boost::bind(slot, _1));
}

void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValueType>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    for (const UniValueType& t : typesExpected) {
        if (params.size() <= i)
            break;

        const UniValue& v = params[i];
        if (!(fAllowNull && v.isNull())) {
            RPCTypeCheckArgument(v, t);
        }
        i++;
    }
}

void RPCTypeCheckArgument(const UniValue& value, const UniValueType& typeExpected)
{
    if (!typeExpected.typeAny && value.type() != typeExpected.type) {
        throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Expected type %s, got %s", uvTypeName(typeExpected.type), uvTypeName(value.type())));
    }
}

void RPCTypeCheckObj(const UniValue& o,
                     const std::map<std::string, UniValueType>& typesExpected,
                     bool fAllowNull,
                     bool fStrict)
{
    for (const auto& t : typesExpected) {
        const UniValue& v = find_value(o, t.first);
        if (!fAllowNull && v.isNull())
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first));

        if (!(t.second.typeAny || v.type() == t.second.type || (fAllowNull && v.isNull()))) {
            std::string err = strprintf("Expected type %s for %s, got %s",
                                        uvTypeName(t.second.type), t.first, uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }

    if (fStrict)
    {
        for (const std::string& k : o.getKeys())
        {
            if (typesExpected.count(k) == 0)
            {
                std::string err = strprintf("Unexpected key %s", k);
                throw JSONRPCError(RPC_TYPE_ERROR, err);
            }
        }
    }
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount AmountFromValue(const UniValue& value)
{
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

uint256 ParseHashV(const UniValue& v, std::string strName)
{
    std::string strHex(v.get_str());
    if (64 != strHex.length())
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be of length %d (not %d, for '%s')", strName, 64, strHex.length(), strHex));
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return uint256S(strHex);
}

uint256 ParseHashO(const UniValue& o, std::string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}
std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

int ParseInt(const UniValue& o, std::string strKey)
{
    const UniValue& v = find_value(o, strKey);
    if (v.isNum())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, " + strKey + "is not an int");

    return v.get_int();
}

bool ParseBool(const UniValue& o, std::string strKey)
{
    const UniValue& v = find_value(o, strKey);
    if (v.isBool())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, " + strKey + "is not a bool");

    return v.get_bool();
}

std::string CRPCTable::help(const std::string& strCommand, const JSONRPCRequest& helpreq) const
{
    std::string strRet;
    std::string category;
    std::set<rpcfn_type> setDone;
    std::vector<std::pair<std::string, const CRPCCommand*> > vCommands;

    for (const auto& entry : mapCommands)
        vCommands.push_back(make_pair(entry.second->category + entry.first, entry.second));
    sort(vCommands.begin(), vCommands.end());

    JSONRPCRequest jreq(helpreq);
    jreq.fHelp = true;
    jreq.params = UniValue();

    for (const std::pair<std::string, const CRPCCommand*>& command : vCommands)
    {
        const CRPCCommand *pcmd = command.second;
        std::string strMethod = pcmd->name;
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand)
            continue;
        jreq.strMethod = strMethod;
        try
        {
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(jreq);
        }
        catch (const std::exception& e)
        {
            // Help text is returned in an exception
            std::string strHelp = std::string(e.what());
            if (strCommand == "")
            {
                if (strHelp.find('\n') != std::string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category)
                {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    strRet += "== " + Capitalize(category) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand);
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

UniValue help(const JSONRPCRequest& jsonRequest)
{
    if (jsonRequest.fHelp || jsonRequest.params.size() > 1)
        throw std::runtime_error(
                RPCHelpMan{"help",
                           "\nList all commands, or get help for a specified command.\n",
                           {
                                   {"command", RPCArg::Type::STR, /* default */ "all commands", "The command to get help on"},
                           },
                           RPCResult{
                                   "\"text\"     (string) The help text\n"
                           },
                           RPCExamples{""},
                }.ToString()
        );

    std::string strCommand;
    if (jsonRequest.params.size() > 0)
        strCommand = jsonRequest.params[0].get_str();

    return tableRPC.help(strCommand, jsonRequest);
}


UniValue stop(const JSONRPCRequest& jsonRequest)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    // Also accept the hidden 'wait' integer argument (milliseconds)
    // For instance, 'stop 1000' makes the call wait 1 second before returning
    // to the client (intended for testing)
    if (jsonRequest.fHelp || jsonRequest.params.size() > 1)
        throw std::runtime_error(
                RPCHelpMan{"stop",
                           "\nStop Wispr server.",
                           {},
                           RPCResults{},
                           RPCExamples{""},
                }.ToString());
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client.
    StartShutdown();
    if (jsonRequest.params[0].isNum()) {
        MilliSleep(jsonRequest.params[0].get_int());
    }
    return "Bitcoin server stopping";
}

static UniValue uptime(const JSONRPCRequest& jsonRequest)
{
    if (jsonRequest.fHelp || jsonRequest.params.size() > 0)
        throw std::runtime_error(
                RPCHelpMan{"uptime",
                           "\nReturns the total uptime of the server.\n",
                           {},
                           RPCResult{
                                   "ttt        (numeric) The number of seconds that the server has been running\n"
                           },
                           RPCExamples{
                                   HelpExampleCli("uptime", "")
                                   + HelpExampleRpc("uptime", "")
                           },
                }.ToString());

    return GetTime() - GetStartupTime();
}

static UniValue getrpcinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                RPCHelpMan{"getrpcinfo",
                           "\nReturns details of the RPC server.\n",
                           {},
                           RPCResults{},
                           RPCExamples{""},
                }.ToString()
        );
    }

    LOCK(g_rpc_server_info.mutex);
    UniValue active_commands(UniValue::VARR);
    for (const RPCCommandExecutionInfo& info : g_rpc_server_info.active_commands) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("method", info.method);
        entry.pushKV("duration", GetTimeMicros() - info.start);
        active_commands.push_back(entry);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("active_commands", active_commands);

    return result;
}


/**
 * Call Table
 */
static const CRPCCommand vRPCCommands[] =
    {
        //  category              name                      actor (function)         okSafeMode threadSafe reqWallet
        //  --------------------- ------------------------  -----------------------  ---------- ---------- ---------
        /* Overall control/query calls */
        {"control", "getinfo", &getinfo, true, false, false}, /* uses wallet if enabled */
        {"control", "help", &help, true, true, false},
        {"control", "stop", &stop, true, true, false},

        /* P2P networking */
        {"network", "getnetworkinfo", &getnetworkinfo, true, false, false},
        {"network", "addnode", &addnode, true, true, false},
        {"network", "disconnectnode", &disconnectnode, true, true, false},
        {"network", "getaddednodeinfo", &getaddednodeinfo, true, true, false},
        {"network", "getconnectioncount", &getconnectioncount, true, false, false},
        {"network", "getnettotals", &getnettotals, true, true, false},
        {"network", "getpeerinfo", &getpeerinfo, true, false, false},
        {"network", "ping", &ping, true, false, false},
        {"network", "setban", &setban, true, false, false},
        {"network", "listbanned", &listbanned, true, false, false},
        {"network", "clearbanned", &clearbanned, true, false, false},

        /* Block chain and UTXO */
        {"blockchain", "findserial", &findserial, true, false, false},
        {"blockchain", "getaccumulatorvalues", &getaccumulatorvalues, true, false, false},
        {"blockchain", "getaccumulatorwitness", &getaccumulatorwitness, true, false, false},
        {"blockchain", "getmintsinblocks", &getmintsinblocks, true, false, false},
        {"blockchain", "getblockchaininfo", &getblockchaininfo, true, false, false},
        {"blockchain", "getbestblockhash", &getbestblockhash, true, false, false},
        {"blockchain", "getblockcount", &getblockcount, true, false, false},
        {"blockchain", "getblock", &getblock, true, false, false},
        {"blockchain", "getblockhash", &getblockhash, true, false, false},
        {"blockchain", "getblockheader", &getblockheader, false, false, false},
        {"blockchain", "getchaintips", &getchaintips, true, false, false},
        {"blockchain", "getdifficulty", &getdifficulty, true, false, false},
        {"blockchain", "getfeeinfo", &getfeeinfo, true, false, false},
        {"blockchain", "getmempoolinfo", &getmempoolinfo, true, true, false},
        {"blockchain", "getrawmempool", &getrawmempool, true, false, false},
        {"blockchain", "gettxout", &gettxout, true, false, false},
        {"blockchain", "gettxoutsetinfo", &gettxoutsetinfo, true, false, false},
        {"blockchain", "invalidateblock", &invalidateblock, true, true, false},
        {"blockchain", "reconsiderblock", &reconsiderblock, true, true, false},
        {"blockchain", "verifychain", &verifychain, true, false, false},

        /* Mining */
        {"mining", "getblocktemplate", &getblocktemplate, true, false, false},
        {"mining", "getmininginfo", &getmininginfo, true, false, false},
        {"mining", "getnetworkhashps", &getnetworkhashps, true, false, false},
        {"mining", "prioritisetransaction", &prioritisetransaction, true, false, false},
        {"mining", "submitblock", &submitblock, true, true, false},
        {"mining", "reservebalance", &reservebalance, true, true, false},

#ifdef ENABLE_WALLET
        /* Coin generation */
        {"generating", "getgenerate", &getgenerate, true, false, false},
        {"generating", "gethashespersec", &gethashespersec, true, false, false},
        {"generating", "setgenerate", &setgenerate, true, true, false},
#endif

        /* Raw transactions */
        {"rawtransactions", "createrawtransaction", &createrawtransaction, true, false, false},
        {"rawtransactions", "decoderawtransaction", &decoderawtransaction, true, false, false},
        {"rawtransactions", "decodescript", &decodescript, true, false, false},
        {"rawtransactions", "getrawtransaction", &getrawtransaction, true, false, false},
        {"rawtransactions", "sendrawtransaction", &sendrawtransaction, false, false, false},
        {"rawtransactions", "signrawtransaction", &signrawtransaction, false, false, false}, /* uses wallet if enabled */

        /* Utility functions */
        {"util", "createmultisig", &createmultisig, true, true, false},
        {"util", "validateaddress", &validateaddress, true, false, false}, /* uses wallet if enabled */
        {"util", "verifymessage", &verifymessage, true, false, false},
        {"util", "estimatefee", &estimatefee, true, true, false},
        {"util", "estimatepriority", &estimatepriority, true, true, false},

        /* Not shown in help */
        {"hidden", "invalidateblock", &invalidateblock, true, true, false},
        {"hidden", "reconsiderblock", &reconsiderblock, true, true, false},
        {"hidden", "setmocktime", &setmocktime, true, false, false},

        /* WISPR features */
        {"wispr", "masternode", &masternode, true, true, false},
        {"wispr", "listmasternodes", &listmasternodes, true, true, false},
        {"wispr", "getmasternodecount", &getmasternodecount, true, true, false},
        {"wispr", "masternodeconnect", &masternodeconnect, true, true, false},
        {"wispr", "createmasternodebroadcast", &createmasternodebroadcast, true, true, false},
        {"wispr", "decodemasternodebroadcast", &decodemasternodebroadcast, true, true, false},
        {"wispr", "relaymasternodebroadcast", &relaymasternodebroadcast, true, true, false},
        {"wispr", "masternodecurrent", &masternodecurrent, true, true, false},
        {"wispr", "masternodedebug", &masternodedebug, true, true, false},
        {"wispr", "startmasternode", &startmasternode, true, true, false},
        {"wispr", "createmasternodekey", &createmasternodekey, true, true, false},
        {"wispr", "getmasternodeoutputs", &getmasternodeoutputs, true, true, false},
        {"wispr", "listmasternodeconf", &listmasternodeconf, true, true, false},
        {"wispr", "getmasternodestatus", &getmasternodestatus, true, true, false},
        {"wispr", "getmasternodewinners", &getmasternodewinners, true, true, false},
        {"wispr", "getmasternodescores", &getmasternodescores, true, true, false},
        {"wispr", "mnbudget", &mnbudget, true, true, false},
        {"wispr", "preparebudget", &preparebudget, true, true, false},
        {"wispr", "submitbudget", &submitbudget, true, true, false},
        {"wispr", "mnbudgetvote", &mnbudgetvote, true, true, false},
        {"wispr", "getbudgetvotes", &getbudgetvotes, true, true, false},
        {"wispr", "getnextsuperblock", &getnextsuperblock, true, true, false},
        {"wispr", "getbudgetprojection", &getbudgetprojection, true, true, false},
        {"wispr", "getbudgetinfo", &getbudgetinfo, true, true, false},
        {"wispr", "mnbudgetrawvote", &mnbudgetrawvote, true, true, false},
        {"wispr", "mnfinalbudget", &mnfinalbudget, true, true, false},
        {"wispr", "checkbudgets", &checkbudgets, true, true, false},
        {"wispr", "mnsync", &mnsync, true, true, false},
        {"wispr", "spork", &spork, true, true, false},
        {"wispr", "getpoolinfo", &getpoolinfo, true, true, false},

#ifdef ENABLE_WALLET
        /* Wallet */
        {"wallet", "addmultisigaddress", &addmultisigaddress, true, false, true},
        {"wallet", "autocombinerewards", &autocombinerewards, false, false, true},
        {"wallet", "backupwallet", &backupwallet, true, false, true},
        {"wallet", "enableautomintaddress", &enableautomintaddress, true, false, true},
        {"wallet", "createautomintaddress", &createautomintaddress, true, false, true},
        {"wallet", "dumpprivkey", &dumpprivkey, true, false, true},
        {"wallet", "dumpwallet", &dumpwallet, true, false, true},
        {"wallet", "bip38encrypt", &bip38encrypt, true, false, true},
        {"wallet", "bip38decrypt", &bip38decrypt, true, false, true},
        {"wallet", "encryptwallet", &encryptwallet, true, false, true},
        {"wallet", "getaccountaddress", &getaccountaddress, true, false, true},
        {"wallet", "getaccount", &getaccount, true, false, true},
        {"wallet", "getaddressesbyaccount", &getaddressesbyaccount, true, false, true},
        {"wallet", "getbalance", &getbalance, false, false, true},
        {"wallet", "getnewaddress", &getnewaddress, true, false, true},
        {"wallet", "getrawchangeaddress", &getrawchangeaddress, true, false, true},
        {"wallet", "getreceivedbyaccount", &getreceivedbyaccount, false, false, true},
        {"wallet", "getreceivedbyaddress", &getreceivedbyaddress, false, false, true},
        {"wallet", "getstakingstatus", &getstakingstatus, false, false, true},
        {"wallet", "getstakesplitthreshold", &getstakesplitthreshold, false, false, true},
        {"wallet", "gettransaction", &gettransaction, false, false, true},
        {"wallet", "getunconfirmedbalance", &getunconfirmedbalance, false, false, true},
        {"wallet", "getwalletinfo", &getwalletinfo, false, false, true},
        {"wallet", "importprivkey", &importprivkey, true, false, true},
        {"wallet", "importwallet", &importwallet, true, false, true},
        {"wallet", "importaddress", &importaddress, true, false, true},
        {"wallet", "keypoolrefill", &keypoolrefill, true, false, true},
        {"wallet", "listaccounts", &listaccounts, false, false, true},
        {"wallet", "listaddressgroupings", &listaddressgroupings, false, false, true},
        {"wallet", "listlockunspent", &listlockunspent, false, false, true},
        {"wallet", "listreceivedbyaccount", &listreceivedbyaccount, false, false, true},
        {"wallet", "listreceivedbyaddress", &listreceivedbyaddress, false, false, true},
        {"wallet", "listsinceblock", &listsinceblock, false, false, true},
        {"wallet", "listtransactions", &listtransactions, false, false, true},
        {"wallet", "listunspent", &listunspent, false, false, true},
        {"wallet", "lockunspent", &lockunspent, true, false, true},
        {"wallet", "move", &movecmd, false, false, true},
        {"wallet", "multisend", &multisend, false, false, true},
        {"wallet", "sendfrom", &sendfrom, false, false, true},
        {"wallet", "sendmany", &sendmany, false, false, true},
        {"wallet", "sendtoaddress", &sendtoaddress, false, false, true},
        {"wallet", "sendtoaddressix", &sendtoaddressix, false, false, true},
        {"wallet", "setaccount", &setaccount, true, false, true},
        {"wallet", "setstakesplitthreshold", &setstakesplitthreshold, false, false, true},
        {"wallet", "settxfee", &settxfee, true, false, true},
        {"wallet", "signmessage", &signmessage, true, false, true},
        {"wallet", "walletlock", &walletlock, true, false, true},
        {"wallet", "walletpassphrasechange", &walletpassphrasechange, true, false, true},
        {"wallet", "walletpassphrase", &walletpassphrase, true, false, true},

        {"zerocoin", "getzerocoinbalance", &getzerocoinbalance, false, false, true},
        {"zerocoin", "listmintedzerocoins", &listmintedzerocoins, false, false, true},
        {"zerocoin", "listspentzerocoins", &listspentzerocoins, false, false, true},
        {"zerocoin", "listzerocoinamounts", &listzerocoinamounts, false, false, true},
        {"zerocoin", "mintzerocoin", &mintzerocoin, false, false, true},
        {"zerocoin", "spendzerocoin", &spendzerocoin, false, false, true},
        {"zerocoin", "spendzerocoinmints", &spendzerocoinmints, false, false, true},
        {"zerocoin", "resetmintzerocoin", &resetmintzerocoin, false, false, true},
        {"zerocoin", "resetspentzerocoin", &resetspentzerocoin, false, false, true},
        {"zerocoin", "getarchivedzerocoin", &getarchivedzerocoin, false, false, true},
        {"zerocoin", "importzerocoins", &importzerocoins, false, false, true},
        {"zerocoin", "exportzerocoins", &exportzerocoins, false, false, true},
        {"zerocoin", "reconsiderzerocoins", &reconsiderzerocoins, false, false, true},
        {"zerocoin", "getspentzerocoinamount", &getspentzerocoinamount, false, false, false},
        {"zerocoin", "getzwspseed", &getzwspseed, false, false, true},
        {"zerocoin", "setzwspseed", &setzwspseed, false, false, true},
        {"zerocoin", "generatemintlist", &generatemintlist, false, false, true},
        {"zerocoin", "searchdzwsp", &searchdzwsp, false, false, true},
        {"zerocoin", "dzwspstate", &dzwspstate, false, false, true}

#endif // ENABLE_WALLET
};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](const std::string &name) const
{
    std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return nullptr;
    return (*it).second;
}

bool CRPCTable::appendCommand(const std::string& name, const CRPCCommand* pcmd)
{
    if (IsRPCRunning())
        return false;

    // don't allow overwriting for now
    std::map<std::string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it != mapCommands.end())
        return false;

    mapCommands[name] = pcmd;
    return true;
}

void StartRPC()
{
    LogPrint(BCLog::RPC, "Starting RPC\n");
    g_rpc_running = true;
    g_rpcSignals.Started();
}

void InterruptRPC()
{
    LogPrint(BCLog::RPC, "Interrupting RPC\n");
    // Interrupt e.g. running longpolls
    g_rpc_running = false;
}

void StopRPC()
{
    LogPrint(BCLog::RPC, "Stopping RPC\n");
    deadlineTimers.clear();
    DeleteAuthCookie();
    g_rpcSignals.Stopped();
}

bool IsRPCRunning()
{
    return g_rpc_running;
}

void SetRPCWarmupStatus(const std::string& newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool RPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

void JSONRPCRequest::parse(const UniValue& valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    UniValue valMethod = find_value(request, "method");
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (fLogIPs)
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s user=%s peeraddr=%s\n", SanitizeString(strMethod),
                 this->authUser, this->peerAddr);
    else
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s user=%s\n", SanitizeString(strMethod), this->authUser);

    // Parse params
    UniValue valParams = find_value(request, "params");
    if (valParams.isArray() || valParams.isObject())
        params = valParams;
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
}

bool IsDeprecatedRPCEnabled(const std::string& method)
{
    const std::vector<std::string> enabled_methods = gArgs.GetArgs("-deprecatedrpc");

    return find(enabled_methods.begin(), enabled_methods.end(), method) != enabled_methods.end();
}

static UniValue JSONRPCExecOne(JSONRPCRequest jreq, const UniValue& req)
{
    UniValue rpc_result(UniValue::VOBJ);

    try {
        jreq.parse(req);

        UniValue result = tableRPC.execute(jreq);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id);
    }
    catch (const UniValue& objError)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id);
    }
    catch (const std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

std::string JSONRPCExecBatch(const JSONRPCRequest& jreq, const UniValue& vReq)
{
    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(jreq, vReq[reqIdx]));

    return ret.write() + "\n";
}
/**
 * Process named arguments into a vector of positional arguments, based on the
 * passed-in specification for the RPC call's arguments.
 */
static inline JSONRPCRequest transformNamedArguments(const JSONRPCRequest& in, const std::vector<std::string>& argNames)
{
    JSONRPCRequest out = in;
    out.params = UniValue(UniValue::VARR);
    // Build a map of parameters, and remove ones that have been processed, so that we can throw a focused error if
    // there is an unknown one.
    const std::vector<std::string>& keys = in.params.getKeys();
    const std::vector<UniValue>& values = in.params.getValues();
    std::unordered_map<std::string, const UniValue*> argsIn;
    for (size_t i=0; i<keys.size(); ++i) {
        argsIn[keys[i]] = &values[i];
    }
    // Process expected parameters.
    int hole = 0;
    for (const std::string &argNamePattern: argNames) {
        std::vector<std::string> vargNames;
        boost::algorithm::split(vargNames, argNamePattern, boost::algorithm::is_any_of("|"));
        auto fr = argsIn.end();
        for (const std::string & argName : vargNames) {
            fr = argsIn.find(argName);
            if (fr != argsIn.end()) {
                break;
            }
        }
        if (fr != argsIn.end()) {
            for (int i = 0; i < hole; ++i) {
                // Fill hole between specified parameters with JSON nulls,
                // but not at the end (for backwards compatibility with calls
                // that act based on number of specified parameters).
                out.params.push_back(UniValue());
            }
            hole = 0;
            out.params.push_back(*fr->second);
            argsIn.erase(fr);
        } else {
            hole += 1;
        }
    }
    // If there are still arguments in the argsIn map, this is an error.
    if (!argsIn.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown named parameter " + argsIn.begin()->first);
    }
    // Return request with named arguments transformed to positional arguments
    return out;
}
UniValue CRPCTable::execute(const JSONRPCRequest &request) const
{
    // Return immediately if in warmup
    {
        LOCK(cs_rpcWarmup);
        if (fRPCInWarmup)
            throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    }

    // Find method
    const CRPCCommand *pcmd = tableRPC[request.strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    try
    {
        RPCCommandExecution execution(request.strMethod);
        // Execute, convert arguments to array if necessary
        if (request.params.isObject()) {
            return pcmd->actor(transformNamedArguments(request, pcmd->argNames));
        } else {
            return pcmd->actor(request);
        }
    }
    catch (const std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}

std::vector<std::string> CRPCTable::listCommands() const
{
    std::vector<std::string> commandList;
    for (const auto& i : mapCommands) commandList.emplace_back(i.first);
    return commandList;
}

std::string HelpExampleCli(string methodname, std::string args)
{
    return "> wispr-cli " + methodname + " " + args + "\n";
}

std::string HelpExampleRpc(const std::string& methodname, const std::string& args)
{
    return "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
           "\"method\": \"" + methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:17001/\n";
}

void RPCSetTimerInterfaceIfUnset(RPCTimerInterface *iface)
{
    if (!timerInterface)
        timerInterface = iface;
}

void RPCSetTimerInterface(RPCTimerInterface *iface)
{
    timerInterface = iface;
}

void RPCUnsetTimerInterface(RPCTimerInterface *iface)
{
    if (timerInterface == iface)
        timerInterface = nullptr;
}

void RPCRunLater(const std::string& name, std::function<void()> func, int64_t nSeconds)
{
    if (!timerInterface)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No timer handler registered for RPC");
    deadlineTimers.erase(name);
    LogPrint(BCLog::RPC, "queue run of timer %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());
    deadlineTimers.emplace(name, std::unique_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds*1000)));
}

int RPCSerializationFlags()
{
    int flag = 0;
    if (gArgs.GetArg("-rpcserialversion", DEFAULT_RPC_SERIALIZE_VERSION) == 0)
        flag |= SERIALIZE_TRANSACTION_NO_WITNESS;
    return flag;
}

CRPCTable tableRPC;
