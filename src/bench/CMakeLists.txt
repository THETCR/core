# Copyright (c) 2018 The Bitcoin developers

project(wispr-bench)

include_directories(.)

add_executable(wispr-bench
	EXCLUDE_FROM_ALL
		bench_bitcoin.cpp
		bench.cpp
		block_assemble.cpp
		checkblock.cpp
		checkqueue.cpp
		examples.cpp
		rollingbloom.cpp
		crypto_hash.cpp
		ccoins_caching.cpp
		gcs_filter.cpp
		merkle_root.cpp
		mempool_eviction.cpp
		verify_script.cpp
		base58.cpp
		bech32.cpp
		lockedpool.cpp
		prevector.cpp
		blind.cpp
		mlsag.cpp
)

target_link_libraries(wispr-bench common bitcoinconsensus server)

add_custom_target(bench-bitcoin
	COMMAND
		./wispr-bench
	DEPENDS
		wispr-bench
)
