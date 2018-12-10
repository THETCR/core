# This CMakeLists.txt is not meant to actually work!
# It only serves as a dummy project to make CLion work properly when it comes to symbol resolution and all the nice
# features dependent on that. Building must still be done on the command line using the automake build chain
# If you load this project in CLion and would like to run/debug executables, make sure to remove the "Build" entry from
# the run/debug configuration as otherwise CLion will try to build this project with cmake, failing horribly.
# You'll also have to manually change the executable in the configuration to the correct path of the already built executable

cmake_minimum_required(VERSION 3.13.1)
project(core)

set(CMAKE_CXX_STANDARD 11)
#set_property(GLOBAL PROPERTY AUTOGEN_TARGETS_FOLDER src/qt/forms)
set(CMAKE_AUTOUIC_SEARCH_PATHS src/qt/forms)

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed
set(CMAKE_AUTOMOC ON)
# Create code from a list of Qt designer ui files
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(Boost_NO_SYSTEM_PATHS true)
#set(Boost_USE_STATIC_LIBS OFF CACHE BOOL "use static libraries from Boost")
set(Boost_USE_MULTITHREADED ON)
set(Boost_INCLUDE_DIR D:/Development/Libraries/CPP/boost)
set(Boost_LIBRARY_DIR D:/Development/Libraries/CPP/boost/lib)
find_package(Boost COMPONENTS chrono filesystem program_options system thread test REQUIRED)

#set(QT_PATH D:/Development/Libraries/CPP/Qt/5.9.6/mingw53_32)
#Qt5 paths
#Qt5 library path
#set(QT5_LIB_DIR ${QT_PATH}/lib/cmake)
##Qt5 individual libraries
#set(QT5_CORE ${QT_LIB_DIR}/Qt5Core)
#set(QT5_WIDGETS ${QT_LIB_DIR}/Qt5Widgets)
#set(QT5_GUI ${QT_LIB_DIR}/Qt5Gui)
#set(QT5_NETWORK ${QT_LIB_DIR}/Qt5Network)
#set(QT5_TEST ${QT_LIB_DIR}/Qt5Test)
#set(Qt5_INCLUDE_DIR D:/Development/Libraries/CPP/Qt/5.9.6/mingw53_32/include)
#set(Qt5_LIBRARY_DIR D:/Development/Libraries/CPP/Qt/5.9.6/mingw53_32/lib)
find_package(Qt5 COMPONENTS Core Widgets UiPlugin Network Gui Test CONFIG REQUIRED )
#Libraries to link to. The :: is for convenience
set(QT_LIBRARIES Qt5::Core Qt5::Widgets Qt5::Gui Qt5::Test Qt5::Network)
#Libraries required. Probably the same as above minus the '::'. find_package() will be called on these
#set(QT_LIBRARIES_REQUIRED Qt5Core Qt5Widgets Qt5Gui Qt5Test Qt5Network)
#set(HW_GUI_DIR ${CMAKE_CURRENT_SOURCE_DIR} src/qt/forms)
#set(HW_MOC_DIR ${CMAKE_CURRENT_SOURCE_DIR} src/qt)

#find packages
#foreach(QT_LIBRARIES_REQUIRED ${QT_LIBRARIES_REQUIRED})
#    find_package(${QT_LIBRARIES_REQUIRED} CONFIG REQUIRED)
#endforeach()
if (WIN32)
    # disable autolinking in boost
    add_definitions( -DBOOST_ALL_NO_LIB )

    # force all boost libraries to dynamic link (we already disabled
    # autolinking, so I don't know why we need this, but we do!)
    add_definitions( -DBOOST_ALL_DYN_LINK )
endif()
include_directories(
        src
        src/leveldb/include
        src/univalue/include
        ${Boost_INCLUDE_DIR}
)

add_definitions(
        -DENABLE_WALLET=1
)
file(GLOB SOURCE_FILES
        src/bench/*.cpp
        src/bench/*.h
        src/compat/*.cpp
        src/compat/*.h
        src/consensus/*.h
        src/consensus/*.cpp
        src/crypto/*.c
        src/crypto/*.h
        src/crypto/*.cpp
        src/governance/*.h
        src/governance/*.cpp
        src/key/*.h
        src/key/*.cpp
        src/insight/*.h
        src/insight/*.cpp
        src/index/*.h
        src/index/*.cpp
        src/interfaces/*.h
        src/interfaces/*.cpp
        src/lz4/*.h
        src/lz4/*.cpp
        src/masternode/*.h
        src/masternode/*.cpp
        src/leveldb/db/*.cc
        src/leveldb/db/*.h
        src/leveldb/include/*.h
        src/obfuscation/*.h
        src/obfuscation/*.cpp
        src/libzerocoin/*.h
        src/libzerocoin/*.cpp
        src/policy/*.cpp
        src/policy/*.h
        src/primitives/*.cpp
        src/primitives/*.h
        src/pos/*.cpp
        src/pos/*.h
        src/qt/test/*.cpp
        src/qt/test/*.h
        src/qt/forms/*.ui
        src/qt/*.qrc
        src/qt/*.cpp
        src/qt/*.h
        src/qt/res/*.rc
        src/script/*.cpp
        src/script/*.h
        src/spork/*.cpp
        src/spork/*.h
        src/secp256k1/include/*.h
        src/smsg/*.h
        src/smsg/*.cpp
        src/support/*.h
        src/support/*.cpp
        src/test/*.cpp
        src/test/*.h
        src/unilib/*.h
        src/unilib/*.cpp
        src/univalue/include/*.h
        src/univalue/lib/*.cpp
        src/univalue/lib/*.h
        src/usbdevice/*.h
        src/usbdevice/*.cpp
        src/wallet/test/*.cpp
        src/wallet/*.cpp
        src/wallet/*.h
        src/zerocoin/*.cpp
        src/zerocoin/*.h
        src/zmq/*.cpp
        src/zmq/*.h
        src/util/*.cpp
        src/util/*.h
        src/*.cpp
        src/*.h
        src/*.rc
        src/evo/*.h
        src/evo/*.cpp
        src/rpc/*.cpp
        src/rpc/*.h
        )

#add_library(configwin ${UI_HEADERS} ${UI_MOC})
#qt5_use_modules(configwin Widgets)
add_executable(wispr WIN32 ${SOURCE_FILES})
target_link_libraries(wispr ${QT_LIBRARIES} ${Boost_LIBRARIES})
#qt5_use_modules(wispr Core Gui Widgets Network Test)