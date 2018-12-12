# Copyright (c) 2018 The Bitcoin developers

project(test_wispr-qt)

include(TestSuite)
create_test_suite(wispr-qt)
add_dependencies(check check-wispr-qt)

add_test_to_suite(wispr-qt test_wispr-qt
	addressbooktests.cpp
	compattests.cpp
	util.cpp
	rpcnestedtests.cpp
	test_main.cpp
	uritests.cpp
	
	# Test framework
	../../test/test_wispr.cpp
	../../test/util_tests.cpp
)

target_link_libraries(test_wispr-qt wispr-qt-base Qt5::Test)

# Wallet
if(BUILD_BITCOIN_WALLET)
	# Add wallet functionality to test_wispr-qt
	target_sources(test_wispr-qt
		PRIVATE
			paymentservertests.cpp
			wallettests.cpp
	)

	target_link_libraries(test_wispr-qt wallet)
endif()
