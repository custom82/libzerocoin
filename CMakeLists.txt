cmake_minimum_required(VERSION 3.10)
project(libzerocoin LANGUAGES CXX)

# Versione
set(ZEROCOIN_VERSION_MAJOR 0)
set(ZEROCOIN_VERSION_MINOR 1)
set(ZEROCOIN_VERSION_PATCH 0)

# Opzioni
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_TESTS "Build tests" OFF)

# C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Warning (mantieni compatibilità)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wno-deprecated-declarations)
endif()

# Trova OpenSSL 3.0 o superiore
find_package(OpenSSL 3.0 REQUIRED)

# Directory di include
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# File sorgenti - BASATO SULLA TUA STRUTTURA REALE
set(ZEROCOIN_SOURCES
    src/Accumulator.cpp
    src/AccumulatorProofOfKnowledge.cpp
    src/Coin.cpp
    src/CoinSpend.cpp
    src/Commitment.cpp
    # CommitmentProofOfKnowledge.cpp NON ESISTE in src/ - è solo header
    src/ParamGeneration.cpp
    src/Params.cpp
    src/SerialNumberSignatureOfKnowledge.cpp
    # Zerocoin.cpp NON ESISTE in src/ - solo Tutorial.cpp e Tests.cpp
    src/bignum.cpp                    # Il vecchio bitcoin_bignum/bignum.cpp
    src/hash.cpp
    src/SpendMetaData.cpp
)

# File header per installazione
set(ZEROCOIN_HEADERS
    include/Accumulator.h
    include/AccumulatorProofOfKnowledge.h
    include/AccumulatorWitness.h
    include/bignum.h
    include/Bignum.h
    include/CBigNum.h
    include/Coin.h
    include/CoinSpend.h
    include/Commitment.h
    include/CommitmentProofOfKnowledge.h
    include/ParamGeneration.h
    include/Params.h
    include/serialize.h
    include/SerialNumberSignatureOfKnowledge.h
    include/SpendMetaData.h
    include/uint256.h
    include/Zerocoin.h
    include/zerocoin_types.h
)

# Verifica se i file esistono
foreach(source IN LISTS ZEROCOIN_SOURCES)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
        message(STATUS "Not found (will skip): ${source}")
        list(REMOVE_ITEM ZEROCOIN_SOURCES ${source})
    endif()
endforeach()

message(STATUS "Sources to build: ${ZEROCOIN_SOURCES}")

# Crea la libreria
add_library(zerocoin ${ZEROCOIN_SOURCES})

# Proprietà della libreria
set_target_properties(zerocoin PROPERTIES
    VERSION ${ZEROCOIN_VERSION_MAJOR}.${ZEROCOIN_VERSION_MINOR}.${ZEROCOIN_VERSION_PATCH}
    SOVERSION ${ZEROCOIN_VERSION_MAJOR}
)

# Link con OpenSSL (versione 3.x)
target_link_libraries(zerocoin PRIVATE OpenSSL::Crypto)

# Include directories
target_include_directories(zerocoin PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Definisci per OpenSSL 3.x compatibilità
target_compile_definitions(zerocoin PRIVATE
    -DOPENSSL_API_COMPAT=30000
)

# Test (opzionale)
if(BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/Tests.cpp")
    add_executable(zerocoin_tests src/Tests.cpp)
    target_link_libraries(zerocoin_tests zerocoin)
    add_test(NAME zerocoin_tests COMMAND zerocoin_tests)
endif()

# Installazione
install(TARGETS zerocoin
    EXPORT zerocoin-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# Installa tutti gli header
install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# File pkg-config
configure_file(libzerocoin.pc.in libzerocoin.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libzerocoin.pc
    DESTINATION lib/pkgconfig
)

# Configurazione per CMake
install(EXPORT zerocoin-targets
    FILE zerocoin-config.cmake
    NAMESPACE zerocoin::
    DESTINATION lib/cmake/zerocoin
)
