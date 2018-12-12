# Copyright (c) 2017 The Bitcoin developers

project(wallet)

# Add Berkeley DB dependency.
find_package(BerkeleyDB REQUIRED)

# Add event dependency. This is only required for evhttp_uridecode
# in rpcwallet.cpp so it may be worth considering using an alternative.
find_package(Event REQUIRED)

add_library(wallet
		../interfaces/wallet.cpp
		../script/ismine.cpp
		../keepass.cpp
		../obfuscation/denomination_functions.cpp
		../obfuscation/privatesend-client.cpp
		../obfuscation/privatesend-util.cpp
		coincontrol.cpp
		crypter.cpp
		db.cpp
		feebumper.cpp
		fees.cpp
		init.cpp
		rpcdump.cpp
		rpcwallet.cpp
		wallet.cpp
		walletdb.cpp
		hdwallet.cpp
		hdwalletdb.cpp
		rpchdwallet.cpp
		../primitives/deterministicmint.cpp
		../primitives/zerocoin.cpp
		../zerocoin/mintpool.cpp
		../zerocoin/zwspwallet.cpp
		../zerocoin/zwsptracker.cpp
		stakeinput.cpp
		../blind.cpp
		../key/stealth.cpp
		../pos/miner.cpp
		../pos/kernel.cpp
		../policy/rbf.cpp
		walletutil.cpp
		coinselection.cpp
		${WISPR_CORE_H}
		)

target_link_libraries(wallet util univalue Event ${BDBXX_LIBRARY})

target_include_directories(wallet PUBLIC ${BDBXX_INCLUDE_DIR})
