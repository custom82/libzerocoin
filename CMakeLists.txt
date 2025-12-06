cmake_minimum_required(VERSION 3.10)
project(libzerocoin)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSL 3.x
find_package(OpenSSL 3.0 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Lista file sorgente (basata sul repository)
set(LIBZEROCOIN_SOURCES
    Accumulator.cpp
    AccumulatorProofOfKnowledge.cpp
    Coin.cpp
    CoinSpend.cpp
    Commitment.cpp
    CommitmentProofOfKnowledge.cpp
    ParamGeneration.cpp
    SerialNumberSignatureOfKnowledge.cpp
    Zerocoin.cpp
    bitcoin_bignum/bignum.cpp
)

# Verifica quali file esistono
foreach(file ${LIBZEROCOIN_SOURCES})
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file})
        message(WARNING "File ${file} non trovato, rimuovo dalla lista")
        list(REMOVE_ITEM LIBZEROCOIN_SOURCES ${file})
    endif()
endforeach()

# Aggiungi libreria
add_library(libzerocoin ${LIBZEROCOIN_SOURCES})

# Link con OpenSSL
target_link_libraries(libzerocoin OpenSSL::Crypto OpenSSL::SSL)

# Flags compilazione
if(MSVC)
    target_compile_definitions(libzerocoin PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _SCL_SECURE_NO_WARNINGS
    )
    target_compile_options(libzerocoin PRIVATE /W3)
else()
    target_compile_options(libzerocoin PRIVATE
        -Wall
        -Wextra
        -Wno-deprecated-declarations
        -Wno-unused-parameter
    )
endif()

# Installazione
install(TARGETS libzerocoin DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION include/libzerocoin
    FILES_MATCHING PATTERN "*.h"
)
