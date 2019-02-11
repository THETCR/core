# This CMakeLists.txt is not meant to actually work!
# It only serves as a dummy project to make CLion work properly when it comes to symbol resolution and all the nice
# features dependent on that. Building must still be done on the command line using the automake build chain
# If you load this project in CLion and would like to run/debug executables, make sure to remove the "Build" entry from
# the run/debug configuration as otherwise CLion will try to build this project with cmake, failing horribly.
# You'll also have to manually change the executable in the configuration to the correct path of the already built executable

cmake_minimum_required(VERSION 3.13.2)
project(WISPR)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
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

#Code completion CLION

#Libraries to link to. The :: is for convenience
set(QT_LIBRARIES Qt5::Core Qt5::Widgets Qt5::Gui Qt5::Test Qt5::Network)
find_package(Qt5 COMPONENTS Core Widgets UiPlugin Network Gui Test CONFIG REQUIRED )

include_directories(
        src
        src/leveldb/include
        src/secp256k1/include
        src/univalue/include
        ${Boost_INCLUDE_DIR}
)

add_definitions(
        -DENABLE_WALLET=1
)

qt5_wrap_ui(UI_GENERATED_HEADERS
        qt/forms/addressbookpage.ui
        qt/forms/askpassphrasedialog.ui
        qt/forms/coincontroldialog.ui
        qt/forms/darksendconfig.ui
        qt/forms/editaddressdialog.ui
        qt/forms/helpmessagedialog.ui
        qt/forms/intro.ui
        qt/forms/modaloverlay.ui
        qt/forms/masternodelist.ui
        qt/forms/openuridialog.ui
        qt/forms/optionsdialog.ui
        qt/forms/overviewpage.ui
        qt/forms/receivecoinsdialog.ui
        qt/forms/receiverequestdialog.ui
        qt/forms/debugwindow.ui
        qt/forms/sendcoinsdialog.ui
        qt/forms/sendcoinsentry.ui
        qt/forms/signverifymessagedialog.ui
        qt/forms/transactiondescdialog.ui
        qt/forms/coldstakingdialog.ui
        qt/forms/mnemonicdialog.ui
        qt/forms/zwspcontroldialog.ui
        )
file(GLOB SOURCE_FILES
        src/compat/*.cpp
        src/compat/*.h
        src/consensus/*.cpp
        src/consensus/*.h
        src/crypto/*.c
        src/crypto/*.h
        src/crypto/*.cpp
        src/key/*.cpp
        src/key/*.h
        src/leveldb/db/*.cc
        src/leveldb/db/*.h
        src/leveldb/include/*.h
        src/libzerocoin/*.h
        src/libzerocoin/*.cpp
        src/policy/*.cpp
        src/policy/*.h
        src/primitives/*.cpp
        src/primitives/*.h
        src/qt/*.cpp
        src/qt/*.h
        src/qt/test/*.cpp
        src/qt/test/*.h
        src/rpc/*.cpp
        src/rpc/*.h
        src/script/*.cpp
        src/script/*.h
        src/secp256k1/include/*.h
        src/secp256k1/src/*.cpp
        src/secp256k1/src/*.h
        src/support/*.cpp
        src/support/*.h
        src/test/*.cpp
        src/test/*.h
        src/univalue/include/*.h
        src/univalue/lib/*.cpp
        src/univalue/lib/*.h
        src/zmq/*.cpp
        src/zmq/*.h
        src/*.cpp
        src/*.h
        src/evo/*.h
        src/evo/*.cpp
        # Handle ui files
        ${UI_GENERATED_HEADERS}
        )

add_executable(WISPR ${SOURCE_FILES})
target_link_libraries(WISPR ${QT_LIBRARIES} ${Boost_LIBRARIES} ${Protobuf_LIBRARIES} Event zmq GMP)
