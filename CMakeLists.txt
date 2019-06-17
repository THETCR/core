# Copyright (c) 2017 The Bitcoin developers

cmake_minimum_required(VERSION 3.13.2)
project(WISPR-Particl)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
#set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add path for custom modules
set(CMAKE_MODULE_PATH
        ${CMAKE_MODULE_PATH}
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules
        )

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)


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


#Code completion CLION

#Libraries to link to. The :: is for convenience
set(QT_LIBRARIES Qt5::Core Qt5::Widgets Qt5::Gui Qt5::Test Qt5::Network)

include_directories(
        src
        src/leveldb/include
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
        src/qt/*.qrc
        src/qt/*.cpp
        src/qt/*.h
        src/qt/locale/*.ts
        src/qt/res/css/*.css
        src/qt/res/icons/*.png
        src/qt/res/icons/*.ico
        src/qt/res/icons/*.icns
        src/qt/res/images/*.png
        src/qt/res/movies/*.png
        src/qt/res/src/*.svg
        src/qt/res/*.rc
        src/qt/forms/*.ui
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
        # Handle ui files
        ${UI_GENERATED_HEADERS}
        )
find_package(Qt5 COMPONENTS Core Widgets UiPlugin Network Gui Test CONFIG REQUIRED )
add_executable(WISPR-Particl ${SOURCE_FILES})
target_link_libraries(WISPR-Particl ${QT_LIBRARIES} ${Boost_LIBRARIES} ${Protobuf_LIBRARIES} Event zmq GMP)