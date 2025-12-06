cmake_minimum_required(VERSION 3.10)
project(libzerocoin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL 3.x
find_package(OpenSSL 3.0 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Source files for libzerocoin
set(LIBZEROCOIN_SOURCES
    bitcoin_bignum/bignum.cpp
    Accumulator.cpp
    AccumulatorProofOfKnowledge.cpp
    Coin.cpp
    CoinSpend.cpp
    Commitment.cpp
    CommitmentProofOfKnowledge.cpp
    ParamGeneration.cpp
    Params.cpp
    SerialNumberSignatureOfKnowledge.cpp
    Zerocoin.cpp
)

# Add library
add_library(libzerocoin ${LIBZEROCOIN_SOURCES})

# Link with OpenSSL
target_link_libraries(libzerocoin
    OpenSSL::Crypto
    OpenSSL::SSL
)

# Compiler flags
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

# Install
install(TARGETS libzerocoin DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} DESTINATION include/libzerocoin FILES_MATCHING PATTERN "*.h")
