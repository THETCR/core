# Copyright (c) 2017 The Bitcoin developers

cmake_minimum_required(VERSION 3.13.1)
project(WISPR)

# Add path for custom modules
set(CMAKE_MODULE_PATH
        ${CMAKE_MODULE_PATH}
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules
        )

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
set(OPENSSL_ROOT_DIR D:/Development/Libraries/CPP/openssl)
set(OPENSSL_INCLUDE_DIR D:/Development/Libraries/CPP/openssl/include)
set(EVENT_LIBRARY D:/Development/Libraries/CPP/libevent/libevent.lib)
set(EVENT_INCLUDE_DIR D:/Development/Libraries/CPP/libevent/include)
set(BDB_LIBRARY D:/Development/Libraries/CPP/bdb/lib/libdb48.lib)
set(BDB_INCLUDE_DIR D:/Development/Libraries/CPP/bdb/include)
set(BDBXX_LIBRARY D:/Development/Libraries/CPP/bdb/lib/libdb48d.lib)
set(ZMQ_LIBRARY D:/Development/Libraries/CPP/ZeroMQ 4.0.4/lib/libzmq-v120-mt-4_0_4.lib)
set(ZMQ_INCLUDE_DIR D:/Development/Libraries/CPP/ZeroMQ 4.0.4/include)
set(SHLWAPI_INCLUDE_DIR D:/Development/Compilers/C++/win/include)
set(GMP_INCLUDE_DIR D:/Development/Compilers/C++/win/include)
set(GMP_LIBRARY D:/Development/Compilers/C++/win/lib64/libgmp.dll.a)
set(GMPXX_LIBRARY D:/Development/Compilers/C++/win/lib64/libgmpxx.dll.a)
set(Protobuf_LIBRARIES D:/Development/Libraries/CPP/protoc/lib/libprotobuf.lib)
set(Protobuf_INCLUDE_DIR D:/Development/Libraries/CPP/protoc/include)
set(Protobuf_PROTOC_EXECUTABLE D:/Development/Libraries/CPP/protoc/bin/protoc.exe)
set(CMAKE_PREFIX_PATH D:/Development/Libraries/CPP/Qt/5.9.6/mingw53_32)

set(Boost_NO_SYSTEM_PATHS true)
#set(Boost_USE_STATIC_LIBS OFF CACHE BOOL "use static libraries from Boost")
set(Boost_USE_MULTITHREADED ON)
set(Boost_INCLUDE_DIR D:/Development/Libraries/CPP/boost)
set(Boost_LIBRARY_DIR D:/Development/Libraries/CPP/boost/lib)
# Make contrib script accessible.
set(CONTRIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/contrib)

# If ccache is available, then use it.
find_program(CCACHE ccache)
if(CCACHE)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ${CCACHE})
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ${CCACHE})
endif(CCACHE)

# Add the magic taret check and check-all
add_custom_target(check-all)
add_custom_target(check)

add_subdirectory(src)
add_subdirectory(test)