# Copyright (c) 2018 The Wispr developers

project(usbdevice)

# Do protobuf codegen
find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTOBUF_SOURCES PROTOBUF_HEADERS trezor/messages.proto trezor/messages-bitcoin.proto trezor/messages-common.proto trezor/messages-management.proto)

add_library(usbdevice
        usbwrapper.cpp
        ledger/ledgerLayer.c
        ledger/dongleCommHidHidapi.c
        usbdevice.cpp
        debugdevice.cpp
        ledgerdevice.cpp
        trezor/messages.proto
        trezor/messages-common.proto
        trezor/messages-management.proto
        trezor/messages-bitcoin.proto
        trezordevice.cpp
        rpcusbdevice.cpp
        # Protobuf codegen
        ${PROTOBUF_HEADERS}
        ${PROTOBUF_SOURCES}
        )

target_link_libraries(usbdevice)

target_include_directories(usbdevice PUBLIC)
