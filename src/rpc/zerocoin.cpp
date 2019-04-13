// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>

#include <chainparams.h>
#include <validation.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <zwspchain.h>
#include <masternode-sync.h>
#include <util/moneystr.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <univalue.h>

UniValue getspentzerocoinamount(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "getspentzerocoinamount hexstring index\n"
            "\nReturns value of spent zerocoin output designated by transaction hash and input index.\n"

            "\nArguments:\n"
            "1. hash          (hexstring) Transaction hash\n"
            "2. index         (int) Input index\n"

            "\nResult:\n"
            "\"value\"        (int) Spent output value, -1 if error\n"

            "\nExamples:\n" +
            HelpExampleCli("getspentzerocoinamount", "78021ebf92a80dfccef1413067f1222e37535399797cce029bb40ad981131706 0"));

    LOCK(cs_main);

    uint256 txHash = ParseHashV(request.params[0], "parameter 1");
    int inputIndex = request.params[1].get_int();
    if (inputIndex < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter for transaction input");

    CTransactionRef tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(txHash, tx, Params().GetConsensus(), hashBlock))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    if (inputIndex >= (int)tx->vin.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter for transaction input");

    const CTxIn& input = tx->vin[inputIndex];
    if (!input.scriptSig.IsZerocoinSpend())
        return -1;

    libzerocoin::CoinSpend spend = TxInToZerocoinSpend(input);
    CAmount nValue = libzerocoin::ZerocoinDenominationToAmount(spend.getDenomination());
    return FormatMoney(nValue);
}

UniValue listmintedzerocoins(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "listmintedzerocoins (fVerbose) (fMatureOnly)\n"
            "\nList all zWSP mints in the wallet.\n" +
            HelpRequiringPassphrase(pwallet) + "\n"

                                               "\nArguments:\n"
                                               "1. fVerbose      (boolean, optional, default=false) Output mints metadata.\n"
                                               "2. fMatureOnly      (boolean, optional, default=false) List only mature mints. (Set only if fVerbose is specified)\n"

                                               "\nResult (with fVerbose=false):\n"
                                               "[\n"
                                               "  \"xxx\"      (string) Pubcoin in hex format.\n"
                                               "  ,...\n"
                                               "]\n"

                                               "\nResult (with fVerbose=true):\n"
                                               "[\n"
                                               "  {\n"
                                               "    \"serial hash\": \"xxx\",   (string) Mint serial hash in hex format.\n"
                                               "    \"version\": n,   (numeric) Zerocoin version number.\n"
                                               "    \"zWSP ID\": \"xxx\",   (string) Pubcoin in hex format.\n"
                                               "    \"denomination\": n,   (numeric) Coin denomination.\n"
                                               "    \"confirmations\": n   (numeric) Number of confirmations.\n"
                                               "  }\n"
                                               "  ,..."
                                               "]\n"

                                               "\nExamples:\n" +
            HelpExampleCli("listmintedzerocoins", "") + HelpExampleRpc("listmintedzerocoins", "") +
            HelpExampleCli("listmintedzerocoins", "true") + HelpExampleRpc("listmintedzerocoins", "true") +
            HelpExampleCli("listmintedzerocoins", "true true") + HelpExampleRpc("listmintedzerocoins", "true, true"));

    bool fVerbose = (request.params.size() > 0) ? request.params[0].get_bool() : false;
    bool fMatureOnly = (request.params.size() > 1) ? request.params[1].get_bool() : false;

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet, true);

    WalletBatch walletdb(pwallet->GetDBHandle());
    set<CMintMeta> setMints = pwallet->zwspTracker->ListMints(true, fMatureOnly, true);

    int nBestHeight = chainActive.Height();

    UniValue jsonList(UniValue::VARR);
    if (fVerbose) {
        for (const CMintMeta& m : setMints) {
            // Construct mint object
            UniValue objMint(UniValue::VOBJ);
            objMint.pushKV("serial hash", m.hashSerial.GetHex());  // Serial hah
            objMint.pushKV("version", m.nVersion);                 // Zerocoin versin
            objMint.pushKV("zWSP ID", m.hashPubcoin.GetHex());     // PubCon
            int denom = libzerocoin::ZerocoinDenominationToInt(m.denom);
            objMint.pushKV("denomination", denom);                 // Denominatin
            int nConfirmations = (m.nHeight && nBestHeight > m.nHeight) ? nBestHeight - m.nHeight : 0;
            objMint.pushKV("confirmations", nConfirmations);       // Confirmatios
            // Push back mint object
            jsonList.push_back(objMint);
        }
    } else {
        for (const CMintMeta& m : setMints)
            // Push back PubCoin
            jsonList.push_back(m.hashPubcoin.GetHex());
    }
    return jsonList;
}

UniValue resetmintzerocoin(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "resetmintzerocoin ( fullscan )\n"
            "\nScan the blockchain for all of the zerocoins that are held in the wallet.dat.\n"
            "Update any meta-data that is incorrect. Archive any mints that are not able to be found.\n" +
            HelpRequiringPassphrase(pwallet) + "\n"

                                               "\nArguments:\n"
                                               "1. fullscan          (boolean, optional) Rescan each block of the blockchain.\n"
                                               "                               WARNING - may take 30+ minutes!\n"

                                               "\nResult:\n"
                                               "{\n"
                                               "  \"updated\": [       (array) JSON array of updated mints.\n"
                                               "    \"xxx\"            (string) Hex encoded mint.\n"
                                               "    ,...\n"
                                               "  ],\n"
                                               "  \"archived\": [      (array) JSON array of archived mints.\n"
                                               "    \"xxx\"            (string) Hex encoded mint.\n"
                                               "    ,...\n"
                                               "  ]\n"
                                               "}\n"

                                               "\nExamples:\n" +
            HelpExampleCli("resetmintzerocoin", "true") + HelpExampleRpc("resetmintzerocoin", "true"));

    LOCK(pwallet->cs_wallet);

    WalletBatch walletdb(pwallet->GetDBHandle());
    CzWSPTracker* zwspTracker = pwallet->zwspTracker.get();
    set<CMintMeta> setMints = zwspTracker->ListMints(false, false, true);
    std::vector<CMintMeta> vMintsToFind(setMints.begin(), setMints.end());
    std::vector<CMintMeta> vMintsMissing;
    std::vector<CMintMeta> vMintsToUpdate;

    // search all of our available data for these mints
    FindMints(vMintsToFind, vMintsToUpdate, vMintsMissing);

    // update the meta data of mints that were marked for updating
    UniValue arrUpdated(UniValue::VARR);
    for (CMintMeta meta : vMintsToUpdate) {
        zwspTracker->UpdateState(meta);
        arrUpdated.push_back(meta.hashPubcoin.GetHex());
    }

    // delete any mints that were unable to be located on the blockchain
    UniValue arrDeleted(UniValue::VARR);
    for (CMintMeta mint : vMintsMissing) {
        zwspTracker->Archive(mint);
        arrDeleted.push_back(mint.hashPubcoin.GetHex());
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("updated", arrUpdated);
    obj.pushKV("archived", arrDeleted);
    return obj;
}

UniValue resetspentzerocoin(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "resetspentzerocoin\n"
            "\nScan the blockchain for all of the zerocoins that are held in the wallet.dat.\n"
            "Reset mints that are considered spent that did not make it into the blockchain.\n"

            "\nResult:\n"
            "{\n"
            "  \"restored\": [        (array) JSON array of restored objects.\n"
            "    {\n"
            "      \"serial\": \"xxx\"  (string) Serial in hex format.\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("resetspentzerocoin", "") + HelpExampleRpc("resetspentzerocoin", ""));

    LOCK(pwallet->cs_wallet);

    WalletBatch walletdb(pwallet->GetDBHandle());
    CzWSPTracker* zwspTracker = pwallet->zwspTracker.get();
    set<CMintMeta> setMints = zwspTracker->ListMints(false, false, false);
    std::list<CZerocoinSpend> listSpends = walletdb.ListSpentCoins();
    std::list<CZerocoinSpend> listUnconfirmedSpends;

    for (CZerocoinSpend spend : listSpends) {
        CTransactionRef tx;
        uint256 hashBlock = 0;
        if (!GetTransaction(spend.GetTxHash(), tx, Params().GetConsensus(), hashBlock)) {
            listUnconfirmedSpends.push_back(spend);
            continue;
        }

        //no confirmations
        if (hashBlock == 0)
            listUnconfirmedSpends.push_back(spend);
    }

    UniValue objRet(UniValue::VOBJ);
    UniValue arrRestored(UniValue::VARR);
    for (CZerocoinSpend spend : listUnconfirmedSpends) {
        for (auto& meta : setMints) {
            if (meta.hashSerial == GetSerialHash(spend.GetSerial())) {
                zwspTracker->SetPubcoinNotUsed(meta.hashPubcoin);
                walletdb.EraseZerocoinSpendSerialEntry(spend.GetSerial());
                RemoveSerialFromDB(spend.GetSerial());
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("serial", spend.GetSerial().GetHex());
                arrRestored.push_back(obj);
                continue;
            }
        }
    }

    objRet.pushKV("restored", arrRestored);
    return objRet;
}

UniValue getstakingstatus(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getstakingstatus\n"
            "\nReturns an object containing various staking information.\n"

            "\nResult:\n"
            "{\n"
            "  \"validtime\": true|false,          (boolean) if the chain tip is within staking phases\n"
            "  \"haveconnections\": true|false,    (boolean) if network connections are present\n"
            "  \"walletunlocked\": true|false,     (boolean) if the wallet is unlocked\n"
            "  \"mintablecoins\": true|false,      (boolean) if the wallet has mintable coins\n"
            "  \"enoughcoins\": true|false,        (boolean) if available coins are greater than reserve balance\n"
            "  \"mnsync\": true|false,             (boolean) if masternode data is synced\n"
            "  \"staking status\": true|false,     (boolean) if the wallet is staking or not\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getstakingstatus", "") + HelpExampleRpc("getstakingstatus", ""));

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    uint32_t const tip_height = locked_chain->getHeight().get_value_or(0);
    int64_t const tip_time = locked_chain->getBlockTime(tip_height);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("validtime", tip_time > 1471482000);
    obj.pushKV("haveconnections", g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) != 0);
    if (pwallet) {
        obj.pushKV("walletunlocked", !pwallet->IsLocked());
        obj.pushKV("mintablecoins", pwallet->MintableCoins());
        obj.pushKV("enoughcoins", nReserveBalance <= pwallet->GetBalance().m_mine_trusted);
    }
    obj.pushKV("mnsync", masternodeSync.IsSynced());

    bool nStaking = false;
    if (mapHashedBlocks.count(tip_height))
        nStaking = true;
    else if (mapHashedBlocks.count(tip_height - 1) && nLastCoinStakeSearchInterval)
        nStaking = true;
    obj.pushKV("staking status", nStaking);

    return obj;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    {"wallet", "getstakingstatus", &getstakingstatus, {}},
    {"zerocoin", "getspentzerocoinamount", &getspentzerocoinamount, {}},
    {"zerocoin", "listmintedzerocoins", &listmintedzerocoins, {}},
    {"zerocoin", "resetmintzerocoin", &resetmintzerocoin, {}},
    {"zerocoin", "resetspentzerocoin", &resetspentzerocoin, {}},
};
// clang-format on

void RegisterZerocoinRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
