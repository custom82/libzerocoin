cmake_minimum_required(VERSION 3.10)
project(libzerocoin LANGUAGES CXX)

set(ZEROCOIN_VERSION_MAJOR 0)
set(ZEROCOIN_VERSION_MINOR 1)
set(ZEROCOIN_VERSION_PATCH 0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 3.0 REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Aggiungi Accumulator.cpp
set(ZEROCOIN_SOURCES
    src/bignum.cpp
    src/Params.cpp
    src/Accumulator.cpp
)

add_library(zerocoin ${ZEROCOIN_SOURCES})
target_link_libraries(zerocoin PRIVATE OpenSSL::Crypto)
target_compile_definitions(zerocoin PRIVATE -DOPENSSL_API_COMPAT=30000)
target_compile_options(zerocoin PRIVATE -w)
EOF
