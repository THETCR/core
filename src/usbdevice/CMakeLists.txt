# Copyright (c) 2018 The Wispr developers

project(usbdevice)

# Do protobuf codegen
find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTOBUF_SOURCES PROTOBUF_HEADERS trezor/messages.proto trezor/messages-bitcoin.proto trezor/messages-common.proto trezor/messages-management.proto)

add_library(usbdevice
        usbwrapper.cpp
        usbwrapper.h
        ledger/btchipApdu.h
        ledger/ledgerLayer.h
        ledger/ledgerLayer.c
        ledger/dongleCommHidHidapi.h
        ledger/dongleCommHidHidapi.c
        usbdevice.cpp
        debugdevice.h
        debugdevice.cpp
        ledgerdevice.h
        ledgerdevice.cpp
        trezor/messages.proto
        trezor/messages-common.proto
        trezor/messages-management.proto
        trezor/messages-bitcoin.proto
        trezordevice.h
        trezordevice.cpp
        rpcusbdevice.cpp
        # Protobuf codegen
        ${PROTOBUF_HEADERS}
        ${PROTOBUF_SOURCES}
        )

target_link_libraries(usbdevice)

target_include_directories(usbdevice PUBLIC)
