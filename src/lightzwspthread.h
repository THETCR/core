//
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

#ifndef PIVX_LIGHTZWSPTHREAD_H
#define PIVX_LIGHTZWSPTHREAD_H

#include <atomic>
#include "genwit.h"
#include "accumulators.h"
#include "concurrentqueue.h"
#include "chainparams.h"

extern CChain chainActive;
// Max amount of computation for a single request
const int COMP_MAX_AMOUNT = 60 * 24 * 60;


/****** Thread ********/

class CLightWorker{

private:

    concurrentqueue<CGenWit> requestsQueue;
    std::atomic<bool> isWorkerRunning;
    std::thread threadIns;

public:

    CLightWorker() {
        isWorkerRunning = false;
    }

    enum ERROR_CODES {
        NOT_ENOUGH_MINTS = 0,
        NON_DETERMINED = 1
    };

    bool addWitWork(CGenWit wit) {
        if (!isWorkerRunning) {
            LogPrintf("%s not running trying to add wit work \n", "pivx-light-thread");
            return false;
        }
        requestsQueue.push(wit);
        return true;
    }

    void StartLightZwspThread() {
        LogPrintf("%s thread start\n", "pivx-light-thread");
        threadIns = std::thread(std::bind(&CLightWorker::ThreadLightZWSPSimplified, this));
//        threadIns = boost::thread(boost::bind(&CLightWorker::ThreadLightZWSPSimplified, this));
    }

    void StopLightZwspThread() {
        threadIns.join();
        LogPrintf("%s thread interrupted\n", "pivx-light-thread");
    }

private:

    void ThreadLightZWSPSimplified();

    void rejectWork(CGenWit& wit, int blockHeight, uint32_t errorNumber);

};

#endif //PIVX_LIGHTZWSPTHREAD_H
