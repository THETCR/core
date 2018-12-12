# Copyright (c) 2018 The Wispr developers

project(smsg)


add_library(smsg
        ../lz4/lz4.h
        ../lz4/lz4.c
        ../xxhash/xxhash.h
        ../xxhash/xxhash.c
        ../interfaces/handler.cpp
        crypter.cpp
        keystore.h
        keystore.cpp
        db.cpp
        smessage.cpp
        rpcsmessage.cpp
        )

target_link_libraries(smsg)

target_include_directories(smsg PUBLIC)
