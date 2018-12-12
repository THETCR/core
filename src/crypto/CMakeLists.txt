# Copyright (c) 2017 The Bitcoin developers

project(crypto)

# The library
add_library(crypto
		aes.cpp
		aes.h
		chacha20.h
		chacha20.cpp
		common.h
		hmac_sha256.cpp
		hmac_sha256.h
		hmac_sha512.cpp
		hmac_sha512.h
		ripemd160.cpp
		ripemd160.h
		scrypt.cpp
		scrypt.h
		sha1.cpp
		sha1.h
		sha256.cpp
		sha256.h
		sha512.cpp
		sha512.h
		siphash.cpp
		siphash.h
)

target_include_directories(crypto
	PRIVATE
		..
	PUBLIC
		# To access the config.
		${CMAKE_CURRENT_BINARY_DIR}/..
)

target_compile_definitions(crypto PUBLIC HAVE_CONFIG_H)

# Use assembly is specified
option(CRYPTO_USE_ASM "Use assembly version of crypto primitives" ON)
if(CRYPTO_USE_ASM)
	target_compile_definitions(crypto PRIVATE USE_ASM)
endif()

# Dependencies
target_link_libraries(crypto OpenSSL::Crypto)
