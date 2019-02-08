// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2016-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef BITCOIN_PROTOCOL_H
#define BITCOIN_PROTOCOL_H

#include "netbase.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <stdint.h>
#include <string>

#define MESSAGE_START_SIZE 4

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];
    CMessageHeader();
    CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(nChecksum);
    }

    // TODO: make private (improves encapsulation)
public:
    enum {
        COMMAND_SIZE = 12,
        MESSAGE_SIZE_SIZE = sizeof(int),
        CHECKSUM_SIZE = sizeof(int),

        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
        HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
    };
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;
    unsigned int nChecksum;
};

/**
 * Bitcoin protocol message types. When adding new message types, don't forget
 * to update allNetMessageTypes in protocol.cpp.
 */
namespace NetMsgType {

/**
 * The version message provides information about the transmitting node to the
 * receiving node at the beginning of a connection.
 * @see https://bitcoin.org/en/developer-reference#version
 */
extern const char *VERSION;
/**
 * The verack message acknowledges a previously-received version message,
 * informing the connecting node that it can begin to send other messages.
 * @see https://bitcoin.org/en/developer-reference#verack
 */
extern const char *VERACK;
/**
 * The addr (IP address) message relays connection information for peers on the
 * network.
 * @see https://bitcoin.org/en/developer-reference#addr
 */
extern const char *ADDR;
/**
 * The inv message (inventory message) transmits one or more inventories of
 * objects known to the transmitting peer.
 * @see https://bitcoin.org/en/developer-reference#inv
 */
extern const char *INV;
/**
 * The getdata message requests one or more data objects from another node.
 * @see https://bitcoin.org/en/developer-reference#getdata
 */
extern const char *GETDATA;
/**
 * The merkleblock message is a reply to a getdata message which requested a
 * block using the inventory type MSG_MERKLEBLOCK.
 * @since protocol version 70001 as described by BIP37.
 * @see https://bitcoin.org/en/developer-reference#merkleblock
 */
extern const char *MERKLEBLOCK;
/**
 * The getblocks message requests an inv message that provides block header
 * hashes starting from a particular point in the block chain.
 * @see https://bitcoin.org/en/developer-reference#getblocks
 */
extern const char *GETBLOCKS;
/**
 * The getheaders message requests a headers message that provides block
 * headers starting from a particular point in the block chain.
 * @since protocol version 31800.
 * @see https://bitcoin.org/en/developer-reference#getheaders
 */
extern const char *GETHEADERS;
/**
 * The tx message transmits a single transaction.
 * @see https://bitcoin.org/en/developer-reference#tx
 */
extern const char *TX;
/**
 * The headers message sends one or more block headers to a node which
 * previously requested certain headers with a getheaders message.
 * @since protocol version 31800.
 * @see https://bitcoin.org/en/developer-reference#headers
 */
extern const char *HEADERS;
/**
 * The block message transmits a single serialized block.
 * @see https://bitcoin.org/en/developer-reference#block
 */
extern const char *BLOCK;
/**
 * The getaddr message requests an addr message from the receiving node,
 * preferably one with lots of IP addresses of other receiving nodes.
 * @see https://bitcoin.org/en/developer-reference#getaddr
 */
extern const char *GETADDR;
/**
 * The mempool message requests the TXIDs of transactions that the receiving
 * node has verified as valid but which have not yet appeared in a block.
 * @since protocol version 60002.
 * @see https://bitcoin.org/en/developer-reference#mempool
 */
extern const char *MEMPOOL;
/**
 * The ping message is sent periodically to help confirm that the receiving
 * peer is still connected.
 * @see https://bitcoin.org/en/developer-reference#ping
 */
extern const char *PING;
/**
 * The pong message replies to a ping message, proving to the pinging node that
 * the ponging node is still alive.
 * @since protocol version 60001 as described by BIP31.
 * @see https://bitcoin.org/en/developer-reference#pong
 */
extern const char *PONG;
/**
 * The alert message warns nodes of problems that may affect them or the rest
 * of the network.
 * @since protocol version 311.
 * @see https://bitcoin.org/en/developer-reference#alert
 */
extern const char *ALERT;
/**
 * The notfound message is a reply to a getdata message which requested an
 * object the receiving node does not have available for relay.
 * @ince protocol version 70001.
 * @see https://bitcoin.org/en/developer-reference#notfound
 */
extern const char *NOTFOUND;
/**
 * The filterload message tells the receiving peer to filter all relayed
 * transactions and requested merkle blocks through the provided filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterload
 */
extern const char *FILTERLOAD;
/**
 * The filteradd message tells the receiving peer to add a single element to a
 * previously-set bloom filter, such as a new public key.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filteradd
 */
extern const char *FILTERADD;
/**
 * The filterclear message tells the receiving peer to remove a previously-set
 * bloom filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterclear
 */
extern const char *FILTERCLEAR;
/**
 * The reject message informs the receiving node that one of its previous
 * messages has been rejected.
 * @since protocol version 70002 as described by BIP61.
 * @see https://bitcoin.org/en/developer-reference#reject
 */
extern const char *REJECT;
/**
 * Indicates that a node prefers to receive new block announcements via a
 * "headers" message rather than an "inv".
 * @since protocol version 70012 as described by BIP130.
 * @see https://bitcoin.org/en/developer-reference#sendheaders
 */
extern const char *SENDHEADERS;
/**
 * Contains a 1-byte bool and 8-byte LE version number.
 * Indicates that a node is willing to provide blocks via "cmpctblock" messages.
 * May indicate that a node prefers to receive new block announcements via a
 * "cmpctblock" message rather than an "inv", depending on message contents.
 * @since protocol version 70209 as described by BIP 152
 */
extern const char *SENDCMPCT;
/**
 * Contains a CBlockHeaderAndShortTxIDs object - providing a header and
 * list of "short txids".
 * @since protocol version 70209 as described by BIP 152
 */
extern const char *CMPCTBLOCK;
/**
 * Contains a BlockTransactionsRequest
 * Peer should respond with "blocktxn" message.
 * @since protocol version 70209 as described by BIP 152
 */
extern const char *GETBLOCKTXN;
/**
 * Contains a BlockTransactions.
 * Sent in response to a "getblocktxn" message.
 * @since protocol version 70209 as described by BIP 152
 */
extern const char *BLOCKTXN;
// Dash message types
// NOTE: do NOT declare non-implmented here, we don't want them to be exposed to the outside
// TODO: add description
extern const char *TXLOCKREQUEST;
extern const char *TXLOCKVOTE;
extern const char *SPORK;
extern const char *GETSPORKS;
extern const char *MASTERNODEPAYMENTVOTE;
extern const char *MASTERNODEPAYMENTBLOCK;
extern const char *MASTERNODEPAYMENTSYNC;
extern const char *MNBUDGETSYNC; // deprecated since 12.1
extern const char *MNBUDGETVOTE; // deprecated since 12.1
extern const char *MNBUDGETPROPOSAL; // deprecated since 12.1
extern const char *MNBUDGETFINAL; // deprecated since 12.1
extern const char *MNBUDGETFINALVOTE; // deprecated since 12.1
extern const char *MNQUORUM; // not implemented
extern const char *MNANNOUNCE;
extern const char *MNPING;
extern const char *DSACCEPT;
extern const char *DSVIN;
extern const char *DSFINALTX;
extern const char *DSSIGNFINALTX;
extern const char *DSCOMPLETE;
extern const char *DSSTATUSUPDATE;
extern const char *DSTX;
extern const char *DSQUEUE;
extern const char *DSEG;
extern const char *SYNCSTATUSCOUNT;
extern const char *MNGOVERNANCESYNC;
extern const char *MNGOVERNANCEOBJECT;
extern const char *MNGOVERNANCEOBJECTVOTE;
extern const char *MNVERIFY;
extern const char *PUBCOINS;
extern const char *GENWIT;
extern const char *ACCVALUE;
};

/* Get a vector of all valid message types (see above) */
const std::vector<std::string> &getAllNetMessageTypes();

/** nServices flags */
enum ServiceFlags : uint64_t {
  // Nothing
      NODE_NONE = 0,
  // NODE_NETWORK means that the node is capable of serving the block chain. It is currently
  // set by all Bitcoin Core nodes, and is unset by SPV clients or other peers that just want
  // network services but don't provide them.
      NODE_NETWORK = (1 << 0),
  // NODE_GETUTXO means the node is capable of responding to the getutxo protocol request.
  // Bitcoin Core does not support this but a patch set called Bitcoin XT does.
  // See BIP 64 for details on how this is implemented.
      NODE_GETUTXO = (1 << 1),
  // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
  // Bitcoin Core nodes used to support this by default, without advertising this bit,
  // but no longer do as of protocol version 70011 (= NO_BLOOM_VERSION)
      NODE_BLOOM = (1 << 2),
  // Indicates that a node can be asked for blocks and transactions including
  // witness data.
      NODE_WITNESS = (1 << 3),
  // NODE_XTHIN means the node supports Xtreme Thinblocks
  // If this is turned off then the node will not service nor make xthin requests
      NODE_XTHIN = (1 << 6),
  // NODE_BLOOM_WITHOUT_MN means the node has the same features as NODE_BLOOM with the only difference
  // that the node doens't want to receive master nodes messages. (the 1<<3 was not picked as constant because on bitcoin 0.14 is witness and we want that update here )
      NODE_BLOOM_WITHOUT_MN = (1 << 4),
  // NODE_BLOOM_LIGHT_ZC means the node has the same feature as NODE_BLOOM_WITHOUT_MN with the addition of
  // support for the light zerocoin protocol.
      NODE_BLOOM_LIGHT_ZC = (1 << 5),
  // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
  // isn't getting used, or one not being used much, and notify the
  // bitcoin-development mailing list. Remember that service bits are just
  // unauthenticated advertisements, so your code must be robust against
  // collisions and other cases where nodes may be advertising a service they
  // do not actually support. Other service bits should be allocated via the
  // BIP process.
};


/** Old nServices flags */
//enum {
//    NODE_NETWORK = (1 << 0),
//
//    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
//    // Bitcoin Core nodes used to support this by default, without advertising this bit,
//    // but no longer do as of protocol version 70011 (= NO_BLOOM_VERSION)
//    NODE_BLOOM = (1 << 2),
//
//	// NODE_BLOOM_WITHOUT_MN means the node has the same features as NODE_BLOOM with the only difference
//	// that the node doens't want to receive master nodes messages. (the 1<<3 was not picked as constant because on bitcoin 0.14 is witness and we want that update here )
//
//    NODE_BLOOM_WITHOUT_MN = (1 << 5),
//
//
//    // NODE_BLOOM_LIGHT_ZC means the node has the same feature as NODE_BLOOM_WITHOUT_MN with the addition of
//    // support for the light zerocoin protocol.
//    NODE_BLOOM_LIGHT_ZC = (1 << 6),
//
//    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
//    // isn't getting used, or one not being used much, and notify the
//    // bitcoin-development mailing list. Remember that service bits are just
//    // unauthenticated advertisements, so your code must be robust against
//    // collisions and other cases where nodes may be advertising a service they
//    // do not actually support. Other service bits should be allocated via the
//    // BIP process.
//};

/** A CService with information about it as peer */
class CAddress : public CService
{
public:
    CAddress();
    explicit CAddress(CService ipIn, uint64_t nServicesIn = NODE_NETWORK);

    void Init();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (ser_action.ForRead())
            Init();
        if (nType & SER_DISK)
            READWRITE(nVersion);
        if ((nType & SER_DISK) ||
            (nVersion >= CADDR_TIME_VERSION && !(nType & SER_GETHASH)))
            READWRITE(nTime);
        READWRITE(nServices);
        READWRITE(*(CService*)this);
    }

    // TODO: make private (improves encapsulation)
public:
    uint64_t nServices;

    // disk and network only
    unsigned int nTime;
};

/** inv message data */
class CInv
{
public:
    CInv();
    CInv(int typeIn, const uint256& hashIn);
    CInv(const std::string& strType, const uint256& hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(type);
        READWRITE(hash);
    }

    friend bool operator<(const CInv& a, const CInv& b);

    bool IsKnownType() const;
    bool IsMasterNodeType() const;
    const char* GetCommand() const;
    std::string ToString() const;

    // TODO: make private (improves encapsulation)
public:
    int type;
    uint256 hash;
};

enum {
    MSG_TX = 1,
    MSG_BLOCK,
    // Nodes may always request a MSG_FILTERED_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK,
    MSG_TXLOCK_REQUEST,
    MSG_TXLOCK_VOTE,
    MSG_SPORK,
    MSG_MASTERNODE_WINNER,
    MSG_MASTERNODE_SCANNING_ERROR,
    MSG_BUDGET_VOTE,
    MSG_BUDGET_PROPOSAL,
    MSG_BUDGET_FINALIZED,
    MSG_BUDGET_FINALIZED_VOTE,
    MSG_MASTERNODE_QUORUM,
    MSG_MASTERNODE_ANNOUNCE,
    MSG_MASTERNODE_PING,
    MSG_DSTX,
    MSG_PUBCOINS,
    MSG_GENWIT,
    MSG_ACC_VALUE
};

#endif // BITCOIN_PROTOCOL_H
