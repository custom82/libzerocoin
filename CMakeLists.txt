cmake_minimum_required(VERSION 3.10)
project(zerocoin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/bitcoin_bignum
    ${OPENSSL_INCLUDE_DIR}
)

add_library(zerocoin SHARED
    Accumulator.cpp
    AccumulatorProofOfKnowledge.cpp
    Coin.cpp
    CoinSpend.cpp
    Commitment.cpp
    ParamGeneration.cpp
    SerialNumberSignatureOfKnowledge.cpp
    bitcoin_bignum/bignum.cpp
)

target_link_libraries(zerocoin
    ${OPENSSL_CRYPTO_LIBRARY}
)
