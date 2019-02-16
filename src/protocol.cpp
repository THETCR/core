// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2017-2018 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"

#include "chainparams.h"
#include <util/system.h>
#include "util/strencodings.h"

#ifndef WIN32
#include <arpa/inet.h>
#endif

namespace NetMsgType {
const char *VERSION="version";
const char *VERACK="verack";
const char *ADDR="addr";
const char *INV="inv";
const char *GETDATA="getdata";
const char *MERKLEBLOCK="merkleblock";
const char *GETBLOCKS="getblocks";
const char *GETHEADERS="getheaders";
const char *TX="tx";
const char *HEADERS="headers";
const char *BLOCK="block";
const char *GETADDR="getaddr";
const char *MEMPOOL="mempool";
const char *PING="ping";
const char *PONG="pong";
const char *ALERT="alert";
const char *NOTFOUND="notfound";
const char *FILTERLOAD="filterload";
const char *FILTERADD="filteradd";
const char *FILTERCLEAR="filterclear";
const char *REJECT="reject";
const char *SENDHEADERS="sendheaders";
const char *SENDCMPCT="sendcmpct";
const char *CMPCTBLOCK="cmpctblock";
const char *GETBLOCKTXN="getblocktxn";
const char *BLOCKTXN="blocktxn";
// Dash message types
const char *TXLOCKREQUEST="ix";
const char *TXLOCKVOTE="txlvote";
const char *SPORK="spork";
const char *GETSPORKS="getsporks";
const char *MASTERNODEPAYMENTVOTE="mnw";
const char *MASTERNODEPAYMENTBLOCK="mnwb";
const char *MASTERNODEPAYMENTSYNC="mnget";
const char *MNBUDGETSYNC="mnvs"; // deprecated since 12.1
const char *MNBUDGETVOTE="mvote"; // deprecated since 12.1
const char *MNBUDGETPROPOSAL="mprop"; // deprecated since 12.1
const char *MNBUDGETFINAL="fbs"; // deprecated since 12.1
const char *MNBUDGETFINALVOTE="fbvote"; // deprecated since 12.1
const char *MNQUORUM="mn quorum"; // not implemented
const char *MNANNOUNCE="mnb";
const char *MNPING="mnp";
const char *DSACCEPT="dsa";
const char *DSVIN="dsi";
const char *DSFINALTX="dsf";
const char *DSSIGNFINALTX="dss";
const char *DSCOMPLETE="dsc";
const char *DSSTATUSUPDATE="dssu";
const char *DSTX="dstx";
const char *DSQUEUE="dsq";
const char *DSEG="dseg";
const char *SYNCSTATUSCOUNT="ssc";
const char *MNGOVERNANCESYNC="govsync";
const char *MNGOVERNANCEOBJECT="govobj";
const char *MNGOVERNANCEOBJECTVOTE="govobjvote";
const char *MNVERIFY="mnv";
const char *PUBCOINS="pubcoins";
const char *GENWIT="genwit";
const char *ACCVALUE="accvalue";
};

static const char* ppszTypeName[] =
    {
        "ERROR", // Should never occur
        NetMsgType::TX,
        NetMsgType::BLOCK,
        "filtered block", // Should never occur
        // Dash message types
        // NOTE: include non-implmented here, we must keep this list in sync with enum in protocol.h
        NetMsgType::TXLOCKREQUEST,
        NetMsgType::TXLOCKVOTE,
        NetMsgType::SPORK,
        NetMsgType::MASTERNODEPAYMENTVOTE,
        NetMsgType::MASTERNODEPAYMENTBLOCK, // reusing, was MNSCANERROR previousely, was NOT used in 12.0, we need this for inv
        NetMsgType::MNBUDGETVOTE, // deprecated since 12.1
        NetMsgType::MNBUDGETPROPOSAL, // deprecated since 12.1
        NetMsgType::MNBUDGETFINAL, // deprecated since 12.1
        NetMsgType::MNBUDGETFINALVOTE, // deprecated since 12.1
        NetMsgType::MNQUORUM, // not implemented
        NetMsgType::MNANNOUNCE,
        NetMsgType::MNPING,
        NetMsgType::DSTX,
        NetMsgType::MNGOVERNANCEOBJECT,
        NetMsgType::MNGOVERNANCEOBJECTVOTE,
        NetMsgType::MNVERIFY,
        "compact block", // Should never occur
        NetMsgType::PUBCOINS,
        NetMsgType::GENWIT,
        NetMsgType::ACCVALUE
    };

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {
    NetMsgType::VERSION,
    NetMsgType::VERACK,
    NetMsgType::ADDR,
    NetMsgType::INV,
    NetMsgType::GETDATA,
    NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS,
    NetMsgType::GETHEADERS,
    NetMsgType::TX,
    NetMsgType::HEADERS,
    NetMsgType::BLOCK,
    NetMsgType::GETADDR,
    NetMsgType::MEMPOOL,
    NetMsgType::PING,
    NetMsgType::PONG,
    NetMsgType::ALERT,
    NetMsgType::NOTFOUND,
    NetMsgType::FILTERLOAD,
    NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR,
    NetMsgType::REJECT,
    NetMsgType::SENDCMPCT,
    NetMsgType::CMPCTBLOCK,
    NetMsgType::GETBLOCKTXN,
    NetMsgType::BLOCKTXN,
    // Dash message types
    // NOTE: do NOT include non-implmented here, we want them to be "Unknown command" in ProcessMessage()
    NetMsgType::TXLOCKREQUEST,
    NetMsgType::TXLOCKVOTE,
    NetMsgType::SPORK,
    NetMsgType::GETSPORKS,
    NetMsgType::MASTERNODEPAYMENTVOTE,
    NetMsgType::MASTERNODEPAYMENTBLOCK, // there is no message for this, only inventory
    NetMsgType::MASTERNODEPAYMENTSYNC,
    NetMsgType::MNBUDGETSYNC, // deprecated since 12.1
    NetMsgType::MNBUDGETVOTE, // deprecated since 12.1
    NetMsgType::MNBUDGETPROPOSAL, // deprecated since 12.1
    NetMsgType::MNBUDGETFINAL, // deprecated since 12.1
    NetMsgType::MNBUDGETFINALVOTE, // deprecated since 12.1
    NetMsgType::MNQUORUM, // not implemented
    NetMsgType::MNANNOUNCE,
    NetMsgType::MNPING,
    NetMsgType::DSACCEPT,
    NetMsgType::DSVIN,
    NetMsgType::DSFINALTX,
    NetMsgType::DSSIGNFINALTX,
    NetMsgType::DSCOMPLETE,
    NetMsgType::DSSTATUSUPDATE,
    NetMsgType::DSTX,
    NetMsgType::DSQUEUE,
    NetMsgType::DSEG,
    NetMsgType::SYNCSTATUSCOUNT,
    NetMsgType::MNGOVERNANCESYNC,
    NetMsgType::MNGOVERNANCEOBJECT,
    NetMsgType::MNGOVERNANCEOBJECTVOTE,
    NetMsgType::MNVERIFY,
    NetMsgType::PUBCOINS,
    NetMsgType::GENWIT,
    NetMsgType::ACCVALUE
};

const static std::vector<std::string> allNetMessageTypesVec(allNetMessageTypes, allNetMessageTypes+ARRAYLEN(allNetMessageTypes));

CMessageHeader::CMessageHeader()
{
    memcpy(pchMessageStart, Params().MessageStart(), MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    nMessageSize = -1;
    nChecksum = 0;
}

CMessageHeader::CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, Params().MessageStart(), MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    nChecksum = 0;
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsValid() const
{
    // Check start string
    if (memcmp(pchMessageStart, Params().MessageStart(), MESSAGE_START_SIZE) != 0)
        return false;

    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++) {
        if (*p1 == 0) {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        } else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE) {
        LogPrintf("CMessageHeader::IsValid() : (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand(), nMessageSize);
        return false;
    }

    return true;
}


CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, ServiceFlags nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NETWORK;
    nTime = 100000000;
}

CInv::CInv()
{
    type = 0;
    hash = 0;
}

CInv::CInv(int typeIn, const uint256& hashIn)
{
    type = typeIn;
    hash = hashIn;
}

CInv::CInv(const std::string& strType, const uint256& hashIn)
{
    unsigned int i;
    for (i = 1; i < ARRAYLEN(ppszTypeName); i++) {
        if (strType == ppszTypeName[i]) {
            type = i;
            break;
        }
    }
    if (i == ARRAYLEN(ppszTypeName))
        LogPrint("net", "CInv::CInv(string, uint256) : unknown type '%s'", strType);
    hash = hashIn;
}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

bool CInv::IsKnownType() const
{
    return (type >= 1 && type < (int)ARRAYLEN(ppszTypeName));
}

bool CInv::IsMasterNodeType() const{
 	return (type >= 6);
}

const char* CInv::GetCommand() const
{
    if (!IsKnownType()) {
        LogPrint("net", "CInv::GetCommand() : type=%d unknown type", type);
        return "UNKNOWN";
    }

    return ppszTypeName[type];
}

std::string CInv::ToString() const
{
    return strprintf("%s %s", GetCommand(), hash.ToString());
}

const std::vector<std::string> &getAllNetMessageTypes()
{
    return allNetMessageTypesVec;
}