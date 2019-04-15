// Copyright (c) 2017-2018 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/miner.h>

#include <kernel.h>
#include <miner.h>
#include <chainparams.h>
#include <util/moneystr.h>

#include <fs.h>
#include <sync.h>
#include <net.h>
#include <validation.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <crypto/sha256.h>

#include <wallet/wallet.h>

#include <blocksignature.h>
#include <masternode-sync.h>
#include <zwspchain.h>
#include <stdint.h>

typedef CWallet* CWalletRef;
std::vector<StakeThread*> vStakeThreads;

void StakeThread::condWaitFor(int ms)
{
    std::unique_lock<std::mutex> lock(mtxMinerProc);
    fWakeMinerProc = false;
    condMinerProc.wait_for(lock, std::chrono::milliseconds(ms), [this] { return this->fWakeMinerProc; });
};

std::atomic<bool> fStopMinerProc(false);
std::atomic<bool> fTryToSync(false);
std::atomic<bool> fIsStaking(false);


int nMinStakeInterval = 0;  // min stake interval in seconds
int nMinerSleep = 500;
std::atomic<int64_t> nTimeLastStake(0);

extern double GetDifficulty(const CBlockIndex* blockindex = nullptr);

//double GetPoSKernelPS()
//{
//    LOCK(cs_main);
//
//    CBlockIndex *pindex = chainActive.Tip();
//    CBlockIndex *pindexPrevStake = nullptr;
//
//    int nBestHeight = pindex->nHeight;
//
//    int nPoSInterval = 72; // blocks sampled
//    double dStakeKernelsTriedAvg = 0;
//    int nStakesHandled = 0, nStakesTime = 0;
//
//    while (pindex && nStakesHandled < nPoSInterval) {
//        if (pindex->IsProofOfStake()) {
//            if (pindexPrevStake) {
//                dStakeKernelsTriedAvg += GetDifficulty(pindexPrevStake) * 4294967296.0;
//                nStakesTime += pindexPrevStake->nTime - pindex->nTime;
//                nStakesHandled++;
//            }
//            pindexPrevStake = pindex;
//        }
//        pindex = pindex->pprev;
//    }
//
//    double result = 0;
//
//    if (nStakesTime) {
//        result = dStakeKernelsTriedAvg / nStakesTime;
//    }
//
//    //if (IsProtocolV2(nBestHeight))
//        result *= Params().GetStakeTimestampMask(nBestHeight) + 1;
//
//    return result;
//}

bool CheckStake(CBlock *pblock, CWallet& wallet)
{
    uint256 proofHash, hashTarget;
    uint256 hashBlock = pblock->GetHash();

    if (!pblock->IsProofOfStake()) {
        return error("%s: %s is not a proof-of-stake block.", __func__, hashBlock.GetHex());
    }

    // Verify hash target and signature of coinstake tx
    {
        LOCK(cs_main);

        BlockMap::const_iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
        if (mi == mapBlockIndex.end()) {
            return error("%s: %s prev block not found: %s.", __func__, hashBlock.GetHex(), pblock->hashPrevBlock.GetHex());
        }

        if (!chainActive.Contains(mi->second)) {
            return error("%s: %s prev block not in active chain: %s.", __func__, hashBlock.GetHex(), pblock->hashPrevBlock.GetHex());
        }

        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash()) { // hashbestchain
            return error("%s: Generated block is stale.", __func__);
        }
    }

    // debug print
    LogPrintf("CheckStake(): New proof-of-stake block found  \n  hash: %s \nproofhash: %s  \ntarget: %s\n", hashBlock.GetHex(), proofHash.GetHex(), hashTarget.GetHex());
    if (LogAcceptCategory(BCLog::POS)) {
        LogPrintf("block %s\n", pblock->ToString());
        LogPrintf("out %s\n", FormatMoney(pblock->vtx[0]->GetValueOut()));
    }

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr)) {
        if (pblock->IsZerocoinStake()){
            wallet.zwspTracker->RemovePending(pblock->vtx[1]->GetHash());
        }
        return error("%s: Block not accepted.", __func__);
    }

    return true;
};

//bool ImportOutputs(CBlockTemplate *pblocktemplate, int nHeight)
//{
//    LogPrint(BCLog::POS, "%s, nHeight %d\n", __func__, nHeight);
//
//    CBlock *pblock = &pblocktemplate->block;
//    if (pblock->vtx.size() < 1) {
//        return error("%s: Malformed block.", __func__);
//    }
//
//    fs::path fPath = GetDataDir() / "genesisOutputs.txt";
//
//    if (!fs::exists(fPath)) {
//        return error("%s: File not found 'genesisOutputs.txt'.", __func__);
//    }
//
//    const int nMaxOutputsPerTxn = 80;
//    FILE *fp;
//    errno = 0;
//    if (!(fp = fopen(fPath.string().c_str(), "rb"))) {
//        return error("%s - Can't open file, strerror: %s.", __func__, strerror(errno));
//    }
//
//    CMutableTransaction txn;
//    txn.nVersion = CTransaction::CURRENT_VERSION;
//    txn.nLockTime = 0;
//    txn.vin.push_back(CTxIn()); // null prevout
//
//    // scriptsig len must be > 2
//    const char *s = "import";
//    txn.vin[0].scriptSig = CScript() << std::vector<unsigned char>((const unsigned char*)s, (const unsigned char*)s + strlen(s));
//
//    int nOutput = 0, nAdded = 0;
//    char cLine[512];
//    char *pAddress, *pAmount;
//
//    while (fgets(cLine, 512, fp)) {
//        cLine[511] = '\0'; // safety
//        size_t len = strlen(cLine);
//        while (isspace(cLine[len-1]) && len>0) {
//            cLine[len-1] = '\0', len--;
//        }
//
//        if (!(pAddress = strtok(cLine, ","))
//            || !(pAmount = strtok(nullptr, ","))) {
//            continue;
//        }
//
//        nOutput++;
//        if (nOutput <= nMaxOutputsPerTxn * (nHeight-1)) {
//            continue;
//        }
//
//        uint64_t amount;
//        if (!ParseUInt64(std::string(pAmount), &amount) || !MoneyRange(amount)) {
//            LogPrintf("Warning: %s - Skipping invalid amount: %s, %s\n", __func__, pAmount, strerror(errno));
//            continue;
//        }
//
//        std::string addrStr(pAddress);
//        CTxDestination destination = DecodeDestination(addrStr);
//
//        CKeyID id;
//        const CKeyID *keyID = boost::get<CKeyID>(&destination);
//        if (!IsValidDestination(destination)
//            || !keyID) {
//            LogPrintf("Warning: %s - Skipping invalid address: %s\n", __func__, pAddress);
//            continue;
//        }
//
//        CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(id) << OP_EQUALVERIFY << OP_CHECKSIG;
//        CTxOut txout = CTxOut();
//        txout.nValue = amount;
//        txout.scriptPubKey = script;
//        txn.vout.push_back(txout);
//
//        nAdded++;
//        if (nAdded >= nMaxOutputsPerTxn) {
//            break;
//        }
//    }
//
//    fclose(fp);
//
//    uint256 hash = txn.GetHash();
//    if (!Params().CheckImportCoinbase(nHeight, hash)) {
//        return error("%s - Incorrect outputs hash.", __func__);
//    }
//
//    pblock->vtx.insert(pblock->vtx.begin()+1, MakeTransactionRef(txn));
//
//    return true;
//};

void StartThreadStakeMiner()
{
    nMinStakeInterval = gArgs.GetArg("-minstakeinterval", 0);
    nMinerSleep = gArgs.GetArg("-minersleep", 500);

    if (!gArgs.GetBoolArg("-staking", true)) {
        LogPrintf("Staking disabled\n");
    } else {
        auto vpwallets = GetWallets();
        size_t nWallets = vpwallets.size();

        if (nWallets < 1) {
            return;
        }
        size_t nThreads = std::min(nWallets, (size_t)gArgs.GetArg("-stakingthreads", 1));

        size_t nPerThread = nWallets / nThreads;
        for (size_t i = 0; i < nThreads; ++i) {
            size_t nStart = nPerThread * i;
            size_t nEnd = (i == nThreads-1) ? nWallets : nPerThread * (i+1);
            StakeThread *t = new StakeThread();
            vStakeThreads.push_back(t);
            GetWallet(vpwallets[i]->GetName())->nStakeThread = i;
            t->sName = strprintf("miner%d", i);
            t->thread = std::thread(&TraceThread<std::function<void()> >, t->sName.c_str(), std::function<void()>(std::bind(&ThreadStakeMiner, i, vpwallets, nStart, nEnd)));
        }
    }

    fStopMinerProc = false;
};

void StopThreadStakeMiner()
{
    if (vStakeThreads.size() < 1 // no thread created
        || fStopMinerProc) {
        return;
    }
    LogPrint(BCLog::POS, "StopThreadStakeMiner\n");
    fStopMinerProc = true;

    for (auto t : vStakeThreads) {
        {
            std::lock_guard<std::mutex> lock(t->mtxMinerProc);
            t->fWakeMinerProc = true;
        }
        t->condMinerProc.notify_all();
        t->thread.join();
        delete t;
    }
    vStakeThreads.clear();
};

void WakeThreadStakeMiner(CWallet *pwallet)
{
    // Call when chain is synced, wallet unlocked or balance changed
    LOCK(pwallet->cs_wallet);
    LogPrint(BCLog::POS, "WakeThreadStakeMiner thread %d\n", pwallet->nStakeThread);

    if (pwallet->nStakeThread >= vStakeThreads.size()) {
        return; // stake unit test
    }
    StakeThread *t = vStakeThreads[pwallet->nStakeThread];
    pwallet->nLastCoinStakeSearchTime = 0;
    {
        std::lock_guard<std::mutex> lock(t->mtxMinerProc);
        t->fWakeMinerProc = true;
    }

    t->condMinerProc.notify_all();
};

bool ThreadStakeMinerStopped()
{
    return fStopMinerProc;
}

static inline void condWaitFor(size_t nThreadID, int ms)
{
    assert(vStakeThreads.size() > nThreadID);
    StakeThread *t = vStakeThreads[nThreadID];
    t->condWaitFor(ms);
};

bool fGenerateBitcoins = false;
bool fMintableCoins = false;
int nMintableLastCheck = 0;

void ThreadStakeMiner(size_t nThreadID, std::vector<std::shared_ptr<CWallet>> &vpwallets, size_t nStart, size_t nEnd)
{
    LogPrintf("Starting staking thread %d, %d wallet%s.\n", nThreadID, nEnd - nStart, (nEnd - nStart) > 1 ? "s" : "");

    int nBestHeight; // TODO: set from new block signal?
    int64_t nBestTime;

    if (!gArgs.GetBoolArg("-staking", true)) {
        LogPrint(BCLog::POS, "%s: -staking is false.\n", __func__);
        return;
    }

    CScript coinbaseScript;
    while (!fStopMinerProc) {
        if (fReindex || fImporting) {
            fIsStaking = false;
            LogPrint(BCLog::POS, "%s: Block import/reindex.\n", __func__);
            condWaitFor(nThreadID, 30000);
            continue;
        }

        int num_nodes;
        {
            LOCK(cs_main);
            nBestHeight = chainActive.Height();
            nBestTime = chainActive.Tip()->nTime;
            num_nodes = g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL);
        }

        if (fTryToSync) {
            fTryToSync = false;
        }

        if (num_nodes == 0 || IsInitialBlockDownload()) {
            fIsStaking = false;
            fTryToSync = true;
            LogPrint(BCLog::POS, "%s: IsInitialBlockDownload\n", __func__);
            condWaitFor(nThreadID, 2000);
            continue;
        }
        if(!masternodeSync.IsSynced()) {
            fIsStaking = false;
            LogPrint(BCLog::POS, "%s: masternodes arent's synced\n", __func__);
            condWaitFor(nThreadID, nMinerSleep * 4);
            continue;
        }

        if (nMinStakeInterval > 0 && nTimeLastStake + (int64_t)nMinStakeInterval > GetTime()) {
            LogPrint(BCLog::POS, "%s: Rate limited to 1 / %d seconds.\n", __func__, nMinStakeInterval);
            condWaitFor(nThreadID, nMinStakeInterval * 500); // nMinStakeInterval / 2 seconds
            continue;
        }

        int64_t nTime = GetAdjustedTime();
        int64_t nSearchTime = nTime;
        if (nSearchTime <= nBestTime) {
            if (nTime < nBestTime) {
                LogPrint(BCLog::POS, "%s: Can't stake before last block time.\n", __func__);
                condWaitFor(nThreadID, std::min(1000 + (nBestTime - nTime) * 1000, (int64_t)30000));
                continue;
            }

            int64_t nNextSearch = nSearchTime + 60;
            condWaitFor(nThreadID, std::min(nMinerSleep + (nNextSearch - nTime) * 1000, (int64_t)10000));
            continue;
        }

        std::unique_ptr<CBlockTemplate> pblocktemplate;

        size_t nWaitFor = 60000;
        CAmount reserve_balance;
        //TODO IMPLEMENT OUR POS ALGORITHM
        for (size_t i = nStart; i < nEnd; ++i) {
            auto pwallet = vpwallets[i].get();
            CReserveKey reservekey(pwallet);
            fMintableCoins = pwallet->MintableCoins();
            unsigned int nExtraNonce = 0;

            if (!pwallet->fStakingEnabled) {
                pwallet->m_is_staking = CWallet::NOT_STAKING_DISABLED;
                continue;
            }

            {
                LOCK(pwallet->cs_wallet);
                if (!pwallet->chain().isReadyToBroadcast()) {
                    fIsStaking = false;
                    LogPrint(BCLog::POS, "%s: not ready to broadcast\n", __func__);
                    condWaitFor(nThreadID, nMinerSleep * 4);
                    continue;
                }
                if (nSearchTime <= pwallet->nLastCoinStakeSearchTime) {
                    nWaitFor = std::min(nWaitFor, (size_t)nMinerSleep);
                    continue;
                }

                if (pwallet->nStakeLimitHeight && nBestHeight >= pwallet->nStakeLimitHeight) {
                    pwallet->m_is_staking = CWallet::NOT_STAKING_LIMITED;
                    nWaitFor = std::min(nWaitFor, (size_t)30000);
                    continue;
                }

                if (pwallet->IsLocked()) {
                    pwallet->m_is_staking = CWallet::NOT_STAKING_LOCKED;
                    nWaitFor = std::min(nWaitFor, (size_t)30000);
                    continue;
                }
                reserve_balance = pwallet->nReserveBalance;
            }
            if(!fMintableCoins) {
                fIsStaking = false;
                LogPrint(BCLog::POS, "%s: no mintalbe coins found\n", __func__);
                condWaitFor(nThreadID, nMinerSleep * 4);
                continue;
            }
            CAmount balance = pwallet->GetBalance().m_mine_trusted;

            if (balance <= reserve_balance) {
                LOCK(pwallet->cs_wallet);
                pwallet->m_is_staking = CWallet::NOT_STAKING_BALANCE;
                nWaitFor = std::min(nWaitFor, (size_t)60000);
                pwallet->nLastCoinStakeSearchTime = nSearchTime + 60;
                LogPrint(BCLog::POS, "%s: Wallet %d, low balance.\n", __func__, i);
                continue;
            }

            CBlockIndex* pindexPrev = chainActive.Tip();
            if (!pindexPrev)
                continue;

            if (!pblocktemplate.get()) {
                CPubKey pubkey;
                if (!reservekey.GetReservedKey(pubkey)){
                    continue;
                }

                coinbaseScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
                pblocktemplate = BlockAssembler(Params()).CreateNewPoSBlock(coinbaseScript, pwallet, true);
                if (!pblocktemplate.get()) {
                    fIsStaking = false;
                    nWaitFor = std::min(nWaitFor, (size_t)nMinerSleep);
                    LogPrint(BCLog::POS, "%s: Couldn't create new block.\n", __func__);
                    continue;
                }
            }

            pwallet->m_is_staking = CWallet::IS_STAKING;

            nWaitFor = nMinerSleep;
            fIsStaking = true;
            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            //Stake miner main
            LogPrintf("CPUMiner : proof-of-stake block found %s \n", pblock->GetHash().ToString().c_str());
            if (pblock->IsZerocoinStake()) {
                //Find the key associated with the zerocoin that is being staked
                libzerocoin::CoinSpend spend = TxInToZerocoinSpend(pblock->vtx[1]->vin[0]);
                CBigNum bnSerial = spend.getCoinSerialNumber();
                CKey key;
                if (!pwallet->GetZerocoinKey(bnSerial, key)) {
                    LogPrintf("%s: failed to find zWSP with serial %s, unable to sign block\n", __func__, bnSerial.GetHex());
                    continue;
                }

                //Sign block with the zWSP key
                if (!SignBlockWithKey(*pblock, key)) {
                    LogPrintf("BitcoinMiner(): Signing new block with zWSP key failed \n");
                    continue;
                }
            } else if (!SignBlock(*pblock, *pwallet)) {
                LogPrintf("BitcoinMiner(): Signing new block with UTXO key failed \n");
                continue;
            }
            if (CheckStake(pblock, *pwallet)) {
                nTimeLastStake = GetTime();
                break;
            }
            int nRequiredDepth = std::min((int)(10 - 1), (int)(nBestHeight / 2));
            LOCK(pwallet->cs_wallet);
            if (pwallet->m_greatest_txn_depth < nRequiredDepth - 4) {
                pwallet->m_is_staking = CWallet::NOT_STAKING_DEPTH;
                size_t nSleep = (nRequiredDepth - pwallet->m_greatest_txn_depth) / 4;
                nWaitFor = std::min(nWaitFor, (size_t)(nSleep * 1000));
                pwallet->nLastCoinStakeSearchTime = nSearchTime + nSleep;
                LogPrint(BCLog::POS, "%s: Wallet %d, no outputs with required depth, sleeping for %ds.\n", __func__, i, nSleep);
                continue;
            }
        }

        condWaitFor(nThreadID, nWaitFor);
    }
};

//static CBlock* FillPoSData(CBlock* pblock, CWallet* pwallet){
//    pblock->nTime = GetAdjustedTime();
//    CBlockIndex* pindexPrev = chainActive.Tip();
//    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
//    CMutableTransaction txCoinStake;
//    int64_t nSearchTime = pblock->nTime; // search to current time
//    bool fStakeFound = false;
//    if (nSearchTime >= nLastCoinStakeSearchTime) {
//        unsigned int nTxNewTime = 0;
//        if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime - nLastCoinStakeSearchTime, txCoinStake, nTxNewTime)) {
//            pblock->nTime = nTxNewTime;
//            pblock->vtx[0]->vout[0].SetEmpty();
//            pblock->vtx.push_back(MakeTransactionRef(std::move(CTransaction(txCoinStake))));
//            fStakeFound = true;
//        }
//        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
//        nLastCoinStakeSearchTime = nSearchTime;
//    }
//
//    if (!fStakeFound)
//        return nullptr;
//
//    CValidationState state;
//    if (!TestBlockValidity(state, Params(), *pblock, pindexPrev, false, false)) {
//        LogPrintf("CreateNewBlock() : TestBlockValidity failed\n");
//        return nullptr;
//    }
//
//    return pblock;
//}