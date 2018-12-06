# This CMakeLists.txt is not meant to actually work!
# It only serves as a dummy project to make CLion work properly when it comes to symbol resolution and all the nice
# features dependent on that. Building must still be done on the command line using the automake build chain
# If you load this project in CLion and would like to run/debug executables, make sure to remove the "Build" entry from
# the run/debug configuration as otherwise CLion will try to build this project with cmake, failing horribly.
# You'll also have to manually change the executable in the configuration to the correct path of the already built executable

cmake_minimum_required(VERSION 3.7)
project(core)

set(CMAKE_CXX_STANDARD 11)
set(Boost_NO_SYSTEM_PATHS true)
set(Boost_USE_STATIC_LIBS OFF CACHE BOOL "use static libraries from Boost")
set(Boost_USE_MULTITHREADED ON)
set(Boost_INCLUDE_DIR D:/Development/Libraries/CPP/boost)
set(Boost_LIBRARY_DIR D:/Development/Libraries/CPP/boost/lib)
find_package(Boost COMPONENTS chrono filesystem program_options system thread test REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(QT_PATH D:/Development/Libraries/CPP/Qt/5.9.6/mingw53_32)
#Qt5 paths
#Qt5 library path
set(QT5_LIB_DIR ${QT_PATH}/lib/cmake)
#Qt5 individual libraries
set(QT5_CORE ${QT_LIB_DIR}/Qt5Core)
set(QT5_WIDGETS ${QT_LIB_DIR}/Qt5Widgets)
set(QT5_GUI ${QT_LIB_DIR}/Qt5Gui)
#set(Qt5_INCLUDE_DIR D:/Development/Libraries/CPP/Qt/5.9.6/mingw53_32/include)
#set(Qt5_LIBRARY_DIR D:/Development/Libraries/CPP/Qt/5.9.6/mingw53_32/lib)
#find_package( Qt5 COMPONENTS Core Widgets UiPlugin Network Gui Test REQUIRED )
#Libraries to link to. The :: is for convenience
set(QT_LIBRARIES Qt5::Core Qt5::Widgets Qt5::Gui Qt5::Test Qt5::Network)
#Libraries required. Probably the same as above minus the '::'. find_package() will be called on these
set(QT_LIBRARIES_REQUIRED Qt5Core Qt5Widgets Qt5Gui Qt5Test Qt5Network)

#find packages
foreach(QT_LIBRARIES_REQUIRED ${QT_LIBRARIES_REQUIRED})
    find_package( ${QT_LIBRARIES_REQUIRED} REQUIRED )
endforeach()
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
        ${Qt5_INCLUDE_DIR}
)
qt5_wrap_ui(src/qt/forms/ui_addressbookpage.h addressbookpage.ui)
qt5_wrap_ui(src/qt/forms/ui_askpassphrasedialog.h askpassphrasedialog.ui)
qt5_wrap_ui(src/qt/forms/ui_bip38tooldialog.h bip38tooldialog.ui)
qt5_wrap_ui(src/qt/forms/ui_blockexplorer.h blockexplorer.ui)
qt5_wrap_ui(src/qt/forms/ui_coincontroldialog.h coincontroldialog.ui)
qt5_wrap_ui(src/qt/forms/ui_coldstakingdialog.h coldstakingdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_darksendconfig.h darksendconfig.ui)
qt5_wrap_ui(src/qt/forms/ui_debugwindow.h debugwindow.ui)
qt5_wrap_ui(src/qt/forms/ui_editaddressdialog.h editaddressdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_helpmessagedialog.h helpmessagedialog.ui)
qt5_wrap_ui(src/qt/forms/ui_intro.h intro.ui)
qt5_wrap_ui(src/qt/forms/ui_masternodelist.h masternodelist.ui)
qt5_wrap_ui(src/qt/forms/ui_mnemonicdialog.h mnemonicdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_modaloverlay.h modaloverlay.ui)
qt5_wrap_ui(src/qt/forms/ui_multisenddialog.h multisenddialog.ui)
qt5_wrap_ui(src/qt/forms/ui_multisigdialog.ui multisigdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_obfuscationconfig.h obfuscationconfig.ui)
qt5_wrap_ui(src/qt/forms/ui_openuridialog.h openuridialog.ui)
qt5_wrap_ui(src/qt/forms/ui_optionsdialog.h optionsdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_overviewpage.h overviewpage.ui)
qt5_wrap_ui(src/qt/forms/ui_privacydialog.h privacydialog.ui)
qt5_wrap_ui(src/qt/forms/ui_qrdialog.h qrdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_receivecoinsdialog.h receivecoinsdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_receiverequestdialog.h receiverequestdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_rpcconsole.h rpcconsole.ui)
qt5_wrap_ui(src/qt/forms/ui_sendcoinsdialog.h sendcoinsdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_sendcoinsentry.h sendcoinsentry.ui)
qt5_wrap_ui(src/qt/forms/ui_signverifymessagedialog.h signverifymessagedialog.ui)
qt5_wrap_ui(src/qt/forms/ui_tradingdialog.h tradingdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_transactiondescdialog.h transactiondescdialog.ui)
qt5_wrap_ui(src/qt/forms/ui_zwspcontroldialog.h zwspcontroldialog.ui)
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
        src/qt/*.cpp
        src/qt/*.h
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
        src/evo/*.h
        src/evo/*.cpp
        src/rpc/*.cpp
        src/rpc/*.h
        )

add_executable(wispr ${SOURCE_FILES})
target_link_libraries(wispr ${QT_LIBRARIES} ${Boost_LIBRARIES})