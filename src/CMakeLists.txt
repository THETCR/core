# Copyright (c) 2017 The Bitcoin developers

cmake_minimum_required(VERSION 3.13.1)
project(WISPR)

set(CMAKE_CXX_STANDARD 11)

# Default visibility is hidden on all targets.
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

option(BUILD_BITCOIN_WALLET "Activate the wallet functionality" ON)
option(BUILD_BITCOIN_ZMQ "Activate the ZeroMQ functionalities" ON)
option(BUILD_BITCOIN_SEEDER "Build wispr-seeder" OFF)
option(BUILD_BITCOIN_CLI "Build wispr-cli" ON)
option(BUILD_BITCOIN_TX "Build wispr-tx" ON)
option(BUILD_BITCOIN_QT "Build wispr-qt" ON)

# Ensure that WINDRES_PREPROC is enabled when using windres.
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	list(APPEND CMAKE_RC_FLAGS "-DWINDRES_PREPROC")
endif()

# Enable warning
include(AddCompilerFlags)

add_c_compiler_flag(-Wnested-externs -Wstrict-prototypes)
add_compiler_flag(
	-Wall
	-Wextra
	-Wformat
	-Wvla
	-Wformat-security
	-Wcast-align
	-Wunused-parameter
	# FIXME: Activating this flag cause cmake to fail on leveldb.
	# -Wthread-safety-analysis
	-Wshadow
)

option(EXTRA_WARNINGS "Enable extra warnings" OFF)
if(EXTRA_WARNINGS)
	add_cxx_compiler_flag(-Wsuggest-override)
else()
	add_compiler_flag(-Wno-unused-parameter)
endif()

#set the bitcoin headers
set(WISPR_CORE_H
		addrdb.h
		masternode/activemasternode.h
		zerocoin/accumulators.h
		zerocoin/accumulatorcheckpoints.h
		zerocoin/accumulatorcheckpoints.json.h
		zerocoin/accumulatormap.h
		rctindex.h
		addrman.h
		attributes.h
		base58.h
		bech32.h
		bloom.h
		blockencodings.h
		blockfilter.h
		cachemap.h
		cachemultimap.h
		chain.h
		chainparams.h
		chainparamsbase.h
		chainparamsseeds.h
		chainparamsimport.h
		checkpoints.h
		checkqueue.h
		clientversion.h
		coins.h
		compat.h
		compat/byteswap.h
		compat/endian.h
		compat/sanity.h
		compressor.h
		consensus/consensus.h
		consensus/tx_verify.h
		primitives/block.h
		primitives/deterministicmint.h
		primitives/transaction.h
		primitives/zerocoin.h
		core_io.h
		core_memusage.h
		cuckoocache.h
		obfuscation/denomination_functions.h
		obfuscation/privatesend.h
		obfuscation/privatesend-client.h
		obfuscation/privatesend-server.h
		obfuscation/privatesend-util.h
		dsnotificationinterface.h
		governance/governance.h
		governance/governance-classes.h
		governance/governance-exceptions.h
		governance/governance-object.h
		governance/governance-validators.h
		governance/governance-vote.h
		governance/governance-votedb.h
		flat-database.h
		fs.h
		httprpc.h
		httpserver.h
		index/base.h
		index/txindex.h
		indirectmap.h
		init.h
		invalid.h
		invalid_outpoints.json.h
		invalid_serials.json.h
		pos/kernel.h
		instantx.h
		anon.h
		blind.h
		interfaces/chain.h
		interfaces/handler.h
		interfaces/node.h
		interfaces/wallet.h
		key.h
		keepass.h
		key/stealth.h
		key/extkey.h
		key/mnemonic.h
		unilib/uninorms.h
		unilib/utf8.h
		key/types.h
		key/keyutil.h
		key/wordlists/chinese_simplified.h
		key/wordlists/chinese_traditional.h
		key/wordlists/english.h
		key/wordlists/french.h
		key/wordlists/japanese.h
		key/wordlists/spanish.h
		key/wordlists/italian.h
		key/wordlists/korean.h
		key_io.h
		keystore.h
		dbwrapper.h
		limitedmap.h
		logging.h
		masternode/masternode.h
		masternode/masternode-payments.h
		masternode/masternode-sync.h
		masternode/masternodeman.h
		masternode/masternodeconfig.h
		memusage.h
		merkleblock.h
		messagesigner.h
		miner.h
		zerocoin/mintpool.h
		net.h
		net_processing.h
		netaddress.h
		netbase.h
		netfulfilledman.h
		netmessagemaker.h
		noui.h
		outputtype.h
		policy/feerate.h
		policy/fees.h
		policy/policy.h
		policy/rbf.h
		pow.h
		pos/kernel.h
		pos/miner.h
		protocol.h
		random.h
		reverse_iterator.h
		reverselock.h
		rpc/blockchain.h
		rpc/client.h
		rpc/mining.h
		rpc/protocol.h
		rpc/server.h
		rpc/rpcutil.h
		rpc/rawtransaction.h
		rpc/register.h
		rpc/util.h
		scheduler.h
		script/descriptor.h
		script/ismine.h
		script/sigcache.h
		script/sign.h
		script/standard.h
		shutdown.h
		streams.h
		smsg/db.h
		smsg/crypter.h
		smsg/net.h
		smsg/smessage.h
		smsg/rpcsmessage.h
		spork/spork.h
		spork/sporkdb.h
		wallet/stakeinput.h
		support/allocators/secure.h
		support/allocators/zeroafterfree.h
		support/cleanse.h
		support/events.h
		support/lockedpool.h
		sync.h
		threadsafety.h
		threadinterrupt.h
		timedata.h
		torcontrol.h
		txdb.h
		txmempool.h
		ui_interface.h
		undo.h
		util/bytevectorhash.h
		util/system.h
		util/memory.h
		util/moneystr.h
		util/time.h
		validation.h
		validationinterface.h
		versionbits.h
		versionbitsinfo.h
		walletinitinterface.h
		wallet/coincontrol.h
		wallet/crypter.h
		wallet/db.h
		wallet/feebumper.h
		wallet/fees.h
		wallet/rpcwallet.h
		wallet/wallet.h
		wallet/walletdb.h
		wallet/rpchdwallet.h
		wallet/hdwalletdb.h
		wallet/hdwallet.h
		wallet/walletutil.h
		wallet/coinselection.h
		zerocoin/zwspchain.h
		zerocoin/zwsptracker.h
		zerocoin/zwspwallet.h
		warnings.h
		zmq/zmqabstractnotifier.h
		zmq/zmqconfig.h
		zmq/zmqnotificationinterface.h
		zmq/zmqpublishnotifier.h
		zmq/zmqrpc.h
		usbdevice/usbdevice.h
		usbdevice/rpcusbdevice.h
		insight/addressindex.h
		insight/spentindex.h
		insight/timestampindex.h
		insight/csindex.h
		insight/insight.h
		insight/rpc.h)


# Create a target for OpenSSL
include(BrewHelper)
find_brew_prefix(OPENSSL_ROOT_DIR openssl)
find_package(OpenSSL REQUIRED)

# libtool style configure
add_subdirectory(config)

# libraries
add_subdirectory(crypto)
add_subdirectory(libzerocoin)
add_subdirectory(smsg)
add_subdirectory(usbdevice)
add_subdirectory(leveldb)
add_subdirectory(secp256k1)
add_subdirectory(univalue)
add_subdirectory(util)

# Boost packages
set(BOOST_PACKAGES_REQUIRED chrono filesystem program_options system thread test)

function(prepend var prefix)
	set(listVar "")
	foreach(f ${ARGN})
		list(APPEND listVar "${prefix}${f}")
	endforeach(f)
	set(${var} "${listVar}" PARENT_SCOPE)
endfunction(prepend)

prepend(BOOST_LIBRARIES "Boost::" ${BOOST_PACKAGES_REQUIRED})

find_package(Boost 1.68 REQUIRED ${BOOST_PACKAGES_REQUIRED})
target_link_libraries(util univalue crypto ${BOOST_LIBRARIES})

# Make sure boost uses std::atomic (it doesn't before 1.63)
target_compile_definitions(util PUBLIC BOOST_SP_USE_STD_ATOMIC BOOST_AC_USE_STD_ATOMIC)

# More completely unrelated features shared by all executables.
# Because nothing says this is different from util than "common"
add_library(common
		base58.cpp
		bech32.cpp
		chainparams.cpp
		coins.cpp
		compressor.cpp
		core_read.cpp
		core_write.cpp
		primitives/block.cpp
		primitives/deterministicmint.cpp
		primitives/transaction.cpp
		primitives/zerocoin.cpp
		anon.cpp
		blind.cpp
		key.cpp
		key/keyutil.cpp
		key/extkey.cpp
		key/stealth.cpp
		smsg/crypter.cpp
		key/mnemonic.cpp
		unilib/uninorms.cpp
		unilib/utf8.cpp
		key_io.cpp
		keystore.cpp
		netaddress.cpp
		netbase.cpp
		policy/feerate.cpp
		protocol.cpp
		scheduler.cpp
		script/descriptor.cpp
		script/ismine.cpp
		script/sign.cpp
		script/standard.cpp
		spork/spork.cpp
		spork/sporkdb.cpp
		versionbitsinfo.cpp
		warnings.cpp
		zerocoin/accumulators.cpp
		zerocoin/accumulatorcheckpoints.cpp
		zerocoin/accumulatormap.cpp
		${WISPR_CORE_H}
		)

target_link_libraries(common util secp256k1)

# libbitcoinconsensus
add_library(bitcoinconsensus
		amount.h
		arith_uint256.cpp
		arith_uint256.h
		consensus/merkle.cpp
		consensus/merkle.h
		consensus/params.h
		consensus/validation.h
		hash.cpp
		hash.h
		invalid.cpp
		invalid.h
		prevector.h
		primitives/block.cpp
		primitives/block.h
		primitives/transaction.cpp
		primitives/transaction.h
		primitives/deterministicmint.cpp
		primitives/deterministicmint.h
		primitives/zerocoin.cpp
		primitives/zerocoin.h
		pubkey.cpp
		pubkey.h
		script/wisprconsensus.cpp
		script/interpreter.cpp
		script/interpreter.h
		script/script.cpp
		script/script.h
		script/script_error.cpp
		script/script_error.h
		spork/spork.cpp
		spork/spork.h
		serialize.h
		span.h
		tinyformat.h
		uint256.cpp
		uint256.h
		util/strencodings.cpp
		util/strencodings.h
		version.h
)

target_link_libraries(bitcoinconsensus common)

# Bitcoin server facilities
add_library(server
		masternode/activemasternode.cpp
		addrman.cpp
		addrdb.cpp
		bloom.cpp
		blockencodings.cpp
		blockfilter.cpp
		chain.cpp
		checkpoints.cpp
		dsnotificationinterface.cpp
		consensus/tx_verify.cpp
		httprpc.cpp
		httpserver.cpp
		index/base.cpp
		index/txindex.cpp
		interfaces/chain.cpp
		interfaces/handler.cpp
		interfaces/node.cpp
		init.cpp
		instantx.cpp
		dbwrapper.cpp
		governance/governance.cpp
		governance/governance-classes.cpp
		governance/governance-object.cpp
		governance/governance-validators.cpp
		governance/governance-vote.cpp
		governance/governance-votedb.cpp
		masternode/masternode.cpp
		masternode/masternode-payments.cpp
		masternode/masternode-sync.cpp
		masternode/masternodeconfig.cpp
		masternode/masternodeman.cpp
		merkleblock.cpp
		messagesigner.cpp
		miner.cpp
		net.cpp
		netfulfilledman.cpp
		net_processing.cpp
		noui.cpp
		outputtype.cpp
		policy/fees.cpp
		policy/policy.cpp
		policy/rbf.cpp
		pow.cpp
		obfuscation/privatesend.cpp
		obfuscation/privatesend-server.cpp
		pos/kernel.cpp
		rest.cpp
		rpc/anon.cpp
		rpc/mnemonic.cpp
		rpc/blockchain.cpp
		rpc/masternode.cpp
		rpc/governance.cpp
		rpc/mining.cpp
		rpc/misc.cpp
		rpc/net.cpp
		rpc/rawtransaction.cpp
		rpc/server.cpp
		rpc/client.cpp
		rpc/rpcutil.cpp
		rpc/util.cpp
		script/sigcache.cpp
		shutdown.cpp
		spork/spork.cpp
		spork/sporkdb.cpp
		timedata.cpp
		torcontrol.cpp
		txdb.cpp
		txmempool.cpp
		ui_interface.cpp
		validation.cpp
		validationinterface.cpp
		zerocoin/zwspchain.cpp
		versionbits.cpp
		insight/insight.cpp
		insight/rpc.cpp
		${WISPR_CORE_H}
		)

# This require libevent
find_package(Event REQUIRED)

target_include_directories(server PRIVATE leveldb/helpers/memenv)

target_link_libraries(server
	Event
	bitcoinconsensus
	leveldb
	memenv
)

# Test suite.
add_subdirectory(test)

# Benchmark suite.
add_subdirectory(bench)

# Wallet
if(BUILD_BITCOIN_WALLET)
	add_subdirectory(wallet)
	target_link_libraries(server wallet)
endif()

# ZeroMQ
if(BUILD_BITCOIN_ZMQ)
	add_subdirectory(zmq)
	target_link_libraries(server zmq)
endif()

# RPC client support
add_library(rpcclient rpc/client.cpp)
target_link_libraries(rpcclient univalue util)

# wispr-seeder
#if(BUILD_BITCOIN_SEEDER)
#	add_subdirectory(seeder)
#endif()

# wispr-cli
if(BUILD_BITCOIN_CLI)
	add_executable(wispr-cli wispr-cli.cpp)
	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		target_sources(wispr-cli PRIVATE wispr-cli-res.rc)
	endif()

	target_link_libraries(wispr-cli common rpcclient Event)
endif()

# wispr-tx
if(BUILD_BITCOIN_TX)
	add_executable(wispr-tx wispr-tx.cpp)
	if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		target_sources(wispr-tx PRIVATE wispr-tx-res.rc)
	endif()

	target_link_libraries(wispr-tx univalue common libzerocoin util bitcoinconsensus crypto secp256k1)
endif()

# wisprd
add_executable(wisprd wisprd.cpp)
target_link_libraries(wisprd server common univalue libzerocoin util wallet zmq bitcoinconsensus crypto leveldb secp256k1 smsg usbdevice)
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	target_sources(wisprd PRIVATE wisprd-res.rc)
endif()

# Bitcoin-qt
if(BUILD_BITCOIN_QT)
	add_subdirectory(qt)
endif()
