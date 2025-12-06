cmake_minimum_required(VERSION 3.10)
project(libzerocoin LANGUAGES CXX)

# Versione
set(ZEROCOIN_VERSION_MAJOR 0)
set(ZEROCOIN_VERSION_MINOR 1)
set(ZEROCOIN_VERSION_PATCH 0)

# C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Trova OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# Include
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# SOLO file base che sappiamo funzionare
set(ZEROCOIN_SOURCES
    src/bignum.cpp
    src/Params.cpp
)

# Crea libreria
add_library(zerocoin ${ZEROCOIN_SOURCES})

# Link con OpenSSL
target_link_libraries(zerocoin PRIVATE OpenSSL::Crypto)

# Definisci per OpenSSL 3.x
target_compile_definitions(zerocoin PRIVATE -DOPENSSL_API_COMPAT=30000)

# Disabilita warning per ora
target_compile_options(zerocoin PRIVATE -w)
