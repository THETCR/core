project(util)

# Various completely unrelated features shared by all executables.
add_library(util
        ../support/lockedpool.cpp
        ../chainparamsbase.cpp
        ../clientversion.cpp
        ../compat/glibc_sanity.cpp
        ../compat/glibcxx_sanity.cpp
        ../compat/strnlen.cpp
        ../fs.cpp
        ../logging.cpp
        ../random.cpp
        ../rpc/protocol.cpp
        ../support/cleanse.cpp
        ../sync.cpp
        ../threadinterrupt.cpp
        bytevectorhash.cpp
        system.cpp
        moneystr.cpp
        strencodings.cpp
        time.cpp
        )

target_compile_definitions(util PUBLIC HAVE_CONFIG_H)
target_include_directories(util
        PUBLIC
        .
        # To access the config.
        ${CMAKE_CURRENT_BINARY_DIR}
        )

# Target specific configs
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    #	set(Boost_USE_STATIC_LIBS ON)
    set(Boost_THREADAPI win32)

    find_package(SHLWAPI REQUIRED)
    target_link_libraries(util ${SHLWAPI_LIBRARY})
    target_include_directories(util PUBLIC ${SHLWAPI_INCLUDE_DIR})

    find_library(WS2_32_LIBRARY NAMES ws2_32)
    target_link_libraries(util ${WS2_32_LIBRARY})

    target_compile_definitions(util PUBLIC BOOST_THREAD_USE_LIB)
endif()
