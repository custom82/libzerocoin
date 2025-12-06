# Dopo cmake_minimum_required e project, aggiungi:

# Versione della libreria
set(ZEROCOIN_VERSION_MAJOR 0)
set(ZEROCOIN_VERSION_MINOR 1)
set(ZEROCOIN_VERSION_PATCH 0)

# Opzioni di build
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_TESTS "Build tests" OFF)

# Configura C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/bitcoin_bignum
)

# Source files
set(ZEROCOIN_SOURCES
    src/Accumulator.cpp
    src/AccumulatorProofOfKnowledge.cpp
    src/Coin.cpp
    src/CoinSpend.cpp
    src/Commitment.cpp
    # src/CommitmentProofOfKnowledge.cpp  # COMMENTATO - file non esiste
    src/ParamGeneration.cpp
    src/Params.cpp
    src/SerialNumberSignatureOfKnowledge.cpp
    src/Zerocoin.cpp
    bitcoin_bignum/bignum.cpp
)

# Headers for installation
set(ZEROCOIN_HEADERS
    include/libzerocoin/Accumulator.h
    include/libzerocoin/AccumulatorProofOfKnowledge.h
    include/libzerocoin/Coin.h
    include/libzerocoin/CoinSpend.h
    include/libzerocoin/Commitment.h
    include/libzerocoin/CommitmentProofOfKnowledge.h
    include/libzerocoin/ParamGeneration.h
    include/libzerocoin/Params.h
    include/libzerocoin/SerialNumberSignatureOfKnowledge.h
    include/libzerocoin/Zerocoin.h
    bitcoin_bignum/bignum.h
    bitcoin_bignum/serialize.h
    bitcoin_bignum/util.h
)

# Aggiungi se uint256.h esiste
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/libzerocoin/uint256.h")
    list(APPEND ZEROCOIN_HEADERS include/libzerocoin/uint256.h)
endif()

# Crea la libreria
add_library(zerocoin ${ZEROCOIN_SOURCES})
target_link_libraries(zerocoin OpenSSL::Crypto)

# Installa la libreria
install(TARGETS zerocoin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Installa gli headers
install(FILES ${ZEROCOIN_HEADERS}
    DESTINATION include/libzerocoin
)
