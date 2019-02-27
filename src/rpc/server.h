// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPCSERVER_H
#define BITCOIN_RPCSERVER_H

#include <amount.h>
#include <primitives/zerocoin.h>
#include <rpc/protocol.h>
#include <uint256.h>

#include <list>
#include <map>
#include <stdint.h>
#include <string>

#include <univalue.h>

static const unsigned int DEFAULT_RPC_SERIALIZE_VERSION = 1;

class CRPCCommand;

namespace RPCServer
{
    void OnStarted(std::function<void ()> slot);
    void OnStopped(std::function<void ()> slot);
    void OnPreCommand(std::function<void (const CRPCCommand&)> slot);
    void OnPostCommand(std::function<void (const CRPCCommand&)> slot);
}

class CBlockIndex;

/** Wrapper for UniValue::VType, which includes typeAny:
 * Used to denote don't care type. */
struct UniValueType {
    UniValueType(UniValue::VType _type) : typeAny(false), type(_type) {}
    UniValueType() : typeAny(true) {}
    bool typeAny;
    UniValue::VType type;
};

class JSONRPCRequest
{
public:
    UniValue id;
    std::string strMethod;
    UniValue params;
    bool fHelp;
    std::string URI;
    std::string authUser;
    std::string peerAddr;

    JSONRPCRequest() : id(NullUniValue), params(NullUniValue), fHelp(false) {}
    void parse(const UniValue& valRequest);
};


/** Query whether RPC is running */
bool IsRPCRunning();

/**
 * Set the RPC warmup status.  When this is done, all RPC calls will error out
 * immediately with RPC_IN_WARMUP.
 */
void SetRPCWarmupStatus(const std::string& newStatus);
/* Mark warmup as done.  RPC calls will be processed from now on.  */
void SetRPCWarmupFinished();

/* returns the current warmup state.  */
bool RPCIsInWarmup(std::string *outStatus);

/**
 * Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
 * the right number of arguments are passed, just that any passed are the correct type.
 */
void RPCTypeCheck(const UniValue& params,
                  const std::list<UniValueType>& typesExpected, bool fAllowNull=false);

/**
 * Type-check one argument; throws JSONRPCError if wrong type given.
 */
void RPCTypeCheckArgument(const UniValue& value, const UniValueType& typeExpected);

/*
  Check for expected keys/value types in an Object.
*/
void RPCTypeCheckObj(const UniValue& o,
                     const std::map<std::string, UniValueType>& typesExpected,
                     bool fAllowNull = false,
                     bool fStrict = false);

/** Opaque base class for timers returned by NewTimerFunc.
 * This provides no methods at the moment, but makes sure that delete
 * cleans up the whole state.
 */
class RPCTimerBase
{
public:
    virtual ~RPCTimerBase() {}
};

/**
 * RPC timer "driver".
 */
class RPCTimerInterface
{
public:
    virtual ~RPCTimerInterface() {}
    /** Implementation name */
    virtual const char *Name() = 0;
    /** Factory function for timers.
     * RPC will call the function to create a timer that will call func in *millis* milliseconds.
     * @note As the RPC mechanism is backend-neutral, it can use different implementations of timers.
     * This is needed to cope with the case in which there is no HTTP server, but
     * only GUI RPC console, and to break the dependency of pcserver on httprpc.
     */
    virtual RPCTimerBase* NewTimer(std::function<void()>& func, int64_t millis) = 0;
};

/** Set the factory function for timers */
void RPCSetTimerInterface(RPCTimerInterface *iface);
/** Set the factory function for timer, but only, if unset */
void RPCSetTimerInterfaceIfUnset(RPCTimerInterface *iface);
/** Unset factory function for timers */
void RPCUnsetTimerInterface(RPCTimerInterface *iface);

/**
 * Run func nSeconds from now.
 * Overrides previous timer <name> (if any).
 */
void RPCRunLater(const std::string& name, std::function<void()> func, int64_t nSeconds);

typedef UniValue(*rpcfn_type)(const JSONRPCRequest& jsonRequest);

class CRPCCommand
{
public:
    std::string category;
    std::string name;
    rpcfn_type actor;
    std::vector<std::string> argNames;
};

/**
 * WISPR RPC command dispatcher.
 */
class CRPCTable
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands;
public:
    CRPCTable();
    const CRPCCommand* operator[](const std::string& name) const;
    std::string help(const std::string& name, const JSONRPCRequest& helpreq) const;

    /**
     * Execute a method.
     * @param request The JSONRPCRequest to execute
     * @returns Result of the call.
     * @throws an exception (UniValue) when an error happens.
     */
    UniValue execute(const JSONRPCRequest &request) const;

    /**
    * Returns a list of registered commands
    * @returns List of registered commands.
    */
    std::vector<std::string> listCommands() const;


    /**
     * Appends a CRPCCommand to the dispatch table.
     *
     * Returns false if RPC server is already running (dump concurrency protection).
     *
     * Commands cannot be overwritten (returns false).
     *
     * Commands with different method names but the same callback function will
     * be considered aliases, and only the first registered method name will
     * show up in the help text command listing. Aliased commands do not have
     * to have the same behavior. Server and client code can distinguish
     * between calls based on method name, and aliased commands can also
     * register different names, types, and numbers of parameters.
     */
    bool appendCommand(const std::string& name, const CRPCCommand* pcmd);
};

bool IsDeprecatedRPCEnabled(const std::string& method);

extern CRPCTable tableRPC;

/**
 * Utilities: convert hex-encoded Values
 * (throws error if not hex).
 */
extern uint256 ParseHashV(const UniValue& v, std::string strName);
extern uint256 ParseHashO(const UniValue& o, std::string strKey);
extern std::vector<unsigned char> ParseHexV(const UniValue& v, std::string strName);
extern std::vector<unsigned char> ParseHexO(const UniValue& o, std::string strKey);
extern int ParseInt(const UniValue& o, std::string strKey);
extern bool ParseBool(const UniValue& o, std::string strKey);

extern int64_t nWalletUnlockTime;
extern CAmount AmountFromValue(const UniValue& value);
extern double GetDifficulty(const CBlockIndex* blockindex = nullptr);
extern std::string HelpRequiringPassphrase();
extern std::string HelpExampleCli(const std::string& methodname, const std::string& args);
extern std::string HelpExampleRpc(const std::string& methodname, const std::string& args);

extern void EnsureWalletIsUnlocked(bool fAllowAnonOnly = false);
extern UniValue DoZwspSpend(const CAmount nAmount, bool fMintChange, bool fMinimizeChange, const int nSecurityLevel, std::vector<CZerocoinMint>& vMintsSelected, std::string address_str);

extern UniValue getconnectioncount(const JSONRPCRequest& request); // in rpc/net.cpp
extern UniValue getpeerinfo(const JSONRPCRequest& request);
extern UniValue ping(const JSONRPCRequest& request);
extern UniValue addnode(const JSONRPCRequest& request);
extern UniValue disconnectnode(const JSONRPCRequest& request);
extern UniValue getaddednodeinfo(const JSONRPCRequest& request);
extern UniValue getnettotals(const JSONRPCRequest& request);
extern UniValue setban(const JSONRPCRequest& request);
extern UniValue listbanned(const JSONRPCRequest& request);
extern UniValue clearbanned(const JSONRPCRequest& request);

extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue bip38encrypt(const JSONRPCRequest& request);
extern UniValue bip38decrypt(const JSONRPCRequest& request);

extern UniValue getgenerate(const JSONRPCRequest& request); // in rpc/mining.cpp
extern UniValue setgenerate(const JSONRPCRequest& request);
extern UniValue getnetworkhashps(const JSONRPCRequest& request);
extern UniValue gethashespersec(const JSONRPCRequest& request);
extern UniValue getmininginfo(const JSONRPCRequest& request);
extern UniValue prioritisetransaction(const JSONRPCRequest& request);
extern UniValue getblocktemplate(const JSONRPCRequest& request);
extern UniValue submitblock(const JSONRPCRequest& request);
extern UniValue estimatefee(const JSONRPCRequest& request);
extern UniValue estimatepriority(const JSONRPCRequest& request);

extern UniValue getnewaddress(const JSONRPCRequest& request); // in rpcwallet.cpp
extern UniValue getaccountaddress(const JSONRPCRequest& request);
extern UniValue getrawchangeaddress(const JSONRPCRequest& request);
extern UniValue setaccount(const JSONRPCRequest& request);
extern UniValue getaccount(const JSONRPCRequest& request);
extern UniValue getaddressesbyaccount(const JSONRPCRequest& request);
extern UniValue sendtoaddress(const JSONRPCRequest& request);
extern UniValue sendtoaddressix(const JSONRPCRequest& request);
extern UniValue signmessage(const JSONRPCRequest& request);
extern UniValue getreceivedbyaddress(const JSONRPCRequest& request);
extern UniValue getreceivedbyaccount(const JSONRPCRequest& request);
extern UniValue getbalance(const JSONRPCRequest& request);
extern UniValue getunconfirmedbalance(const JSONRPCRequest& request);
extern UniValue movecmd(const JSONRPCRequest& request);
extern UniValue sendfrom(const JSONRPCRequest& request);
extern UniValue sendmany(const JSONRPCRequest& request);
extern UniValue addmultisigaddress(const JSONRPCRequest& request);
extern UniValue listreceivedbyaddress(const JSONRPCRequest& request);
extern UniValue listreceivedbyaccount(const JSONRPCRequest& request);
extern UniValue listtransactions(const JSONRPCRequest& request);
extern UniValue listaddressgroupings(const JSONRPCRequest& request);
extern UniValue listaccounts(const JSONRPCRequest& request);
extern UniValue listsinceblock(const JSONRPCRequest& request);
extern UniValue gettransaction(const JSONRPCRequest& request);
extern UniValue backupwallet(const JSONRPCRequest& request);
extern UniValue keypoolrefill(const JSONRPCRequest& request);
extern UniValue walletpassphrase(const JSONRPCRequest& request);
extern UniValue walletpassphrasechange(const JSONRPCRequest& request);
extern UniValue walletlock(const JSONRPCRequest& request);
extern UniValue encryptwallet(const JSONRPCRequest& request);
extern UniValue getwalletinfo(const JSONRPCRequest& request);
extern UniValue getblockchaininfo(const JSONRPCRequest& request);
extern UniValue getnetworkinfo(const JSONRPCRequest& request);
extern UniValue reservebalance(const JSONRPCRequest& request);
extern UniValue setstakesplitthreshold(const JSONRPCRequest& request);
extern UniValue getstakesplitthreshold(const JSONRPCRequest& request);
extern UniValue multisend(const JSONRPCRequest& request);
extern UniValue autocombinerewards(const JSONRPCRequest& request);
extern UniValue getzerocoinbalance(const JSONRPCRequest& request);
extern UniValue listmintedzerocoins(const JSONRPCRequest& request);
extern UniValue listspentzerocoins(const JSONRPCRequest& request);
extern UniValue listzerocoinamounts(const JSONRPCRequest& request);
extern UniValue mintzerocoin(const JSONRPCRequest& request);
extern UniValue spendzerocoin(const JSONRPCRequest& request);
extern UniValue spendzerocoinmints(const JSONRPCRequest& request);
extern UniValue resetmintzerocoin(const JSONRPCRequest& request);
extern UniValue resetspentzerocoin(const JSONRPCRequest& request);
extern UniValue getarchivedzerocoin(const JSONRPCRequest& request);
extern UniValue importzerocoins(const JSONRPCRequest& request);
extern UniValue exportzerocoins(const JSONRPCRequest& request);
extern UniValue reconsiderzerocoins(const JSONRPCRequest& request);
extern UniValue getspentzerocoinamount(const JSONRPCRequest& request);
extern UniValue setzwspseed(const JSONRPCRequest& request);
extern UniValue getzwspseed(const JSONRPCRequest& request);
extern UniValue generatemintlist(const JSONRPCRequest& request);
extern UniValue searchdzwsp(const JSONRPCRequest& request);
extern UniValue dzwspstate(const JSONRPCRequest& request);
extern UniValue enableautomintaddress(const JSONRPCRequest& request);
extern UniValue createautomintaddress(const JSONRPCRequest& request);

extern UniValue getrawtransaction(const JSONRPCRequest& request); // in rpc/rawtransaction.cpp
extern UniValue listunspent(const JSONRPCRequest& request);
extern UniValue lockunspent(const JSONRPCRequest& request);
extern UniValue listlockunspent(const JSONRPCRequest& request);
extern UniValue createrawtransaction(const JSONRPCRequest& request);
extern UniValue decoderawtransaction(const JSONRPCRequest& request);
extern UniValue decodescript(const JSONRPCRequest& request);
extern UniValue signrawtransaction(const JSONRPCRequest& request);
extern UniValue sendrawtransaction(const JSONRPCRequest& request);

extern UniValue findserial(const JSONRPCRequest& request); // in rpc/blockchain.cpp
extern UniValue getblockcount(const JSONRPCRequest& request);
extern UniValue getbestblockhash(const JSONRPCRequest& request);
extern UniValue getdifficulty(const JSONRPCRequest& request);
extern UniValue settxfee(const JSONRPCRequest& request);
extern UniValue getmempoolinfo(const JSONRPCRequest& request);
extern UniValue getrawmempool(const JSONRPCRequest& request);
extern UniValue getblockhash(const JSONRPCRequest& request);
extern UniValue getblock(const JSONRPCRequest& request);
extern UniValue getblockheader(const JSONRPCRequest& request);
extern UniValue getfeeinfo(const JSONRPCRequest& request);
extern UniValue gettxoutsetinfo(const JSONRPCRequest& request);
extern UniValue gettxout(const JSONRPCRequest& request);
extern UniValue verifychain(const JSONRPCRequest& request);
extern UniValue getchaintips(const JSONRPCRequest& request);
extern UniValue invalidateblock(const JSONRPCRequest& request);
extern UniValue reconsiderblock(const JSONRPCRequest& request);
extern UniValue getaccumulatorvalues(const JSONRPCRequest& request);
extern UniValue getaccumulatorwitness(const JSONRPCRequest& request);
extern UniValue getmintsinblocks(const JSONRPCRequest& request);

extern UniValue getpoolinfo(const JSONRPCRequest& request); // in rpc/masternode.cpp
extern UniValue masternode(const JSONRPCRequest& request);
extern UniValue listmasternodes(const JSONRPCRequest& request);
extern UniValue getmasternodecount(const JSONRPCRequest& request);
extern UniValue createmasternodebroadcast(const JSONRPCRequest& request);
extern UniValue decodemasternodebroadcast(const JSONRPCRequest& request);
extern UniValue relaymasternodebroadcast(const JSONRPCRequest& request);
extern UniValue masternodeconnect(const JSONRPCRequest& request);
extern UniValue masternodecurrent(const JSONRPCRequest& request);
extern UniValue masternodedebug(const JSONRPCRequest& request);
extern UniValue startmasternode(const JSONRPCRequest& request);
extern UniValue createmasternodekey(const JSONRPCRequest& request);
extern UniValue getmasternodeoutputs(const JSONRPCRequest& request);
extern UniValue listmasternodeconf(const JSONRPCRequest& request);
extern UniValue getmasternodestatus(const JSONRPCRequest& request);
extern UniValue getmasternodewinners(const JSONRPCRequest& request);
extern UniValue getmasternodescores(const JSONRPCRequest& request);

extern UniValue mnbudget(const JSONRPCRequest& request); // in rpc/budget.cpp
extern UniValue preparebudget(const JSONRPCRequest& request);
extern UniValue submitbudget(const JSONRPCRequest& request);
extern UniValue mnbudgetvote(const JSONRPCRequest& request);
extern UniValue getbudgetvotes(const JSONRPCRequest& request);
extern UniValue getnextsuperblock(const JSONRPCRequest& request);
extern UniValue getbudgetprojection(const JSONRPCRequest& request);
extern UniValue getbudgetinfo(const JSONRPCRequest& request);
extern UniValue mnbudgetrawvote(const JSONRPCRequest& request);
extern UniValue mnfinalbudget(const JSONRPCRequest& request);
extern UniValue checkbudgets(const JSONRPCRequest& request);

extern UniValue getinfo(const JSONRPCRequest& request); // in rpc/misc.cpp
extern UniValue mnsync(const JSONRPCRequest& request);
extern UniValue spork(const JSONRPCRequest& request);
extern UniValue validateaddress(const JSONRPCRequest& request);
extern UniValue createmultisig(const JSONRPCRequest& request);
extern UniValue verifymessage(const JSONRPCRequest& request);
extern UniValue setmocktime(const JSONRPCRequest& request);
extern UniValue getstakingstatus(const JSONRPCRequest& request);

void StartRPC();
void InterruptRPC();
void StopRPC();
std::string JSONRPCExecBatch(const JSONRPCRequest& jreq, const UniValue& vReq);
// Retrieves any serialization flags requested in command line argument
int RPCSerializationFlags();
#endif // BITCOIN_RPCSERVER_H
