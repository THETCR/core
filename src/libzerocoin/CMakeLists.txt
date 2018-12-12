# Copyright (c) 2018 The Wispr developers

project(libzerocoin)

# Add GMP dependency.
find_package(GMP REQUIRED)

add_library(libzerocoin
        Accumulator.cpp
        AccumulatorProofOfKnowledge.cpp
        Coin.cpp
        Denominations.cpp
        CoinSpend.cpp
        Commitment.cpp
        ParamGeneration.cpp
        Params.cpp
        SerialNumberSignatureOfKnowledge.cpp
        )

target_link_libraries(libzerocoin GMP)

target_include_directories(libzerocoin PUBLIC ${GMP_INCLUDE_DIR})
