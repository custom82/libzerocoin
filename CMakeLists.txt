cmake_minimum_required(VERSION 3.10)

# Nome del progetto e versioni
project(libzerocoin VERSION 1.0 LANGUAGES CXX)

# Impostazioni di compilazione
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Definisci la variabile di compilazione per la libreria
set(LIBZEROCOIN_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(LIBZEROCOIN_SRC_DIR ${CMAKE_SOURCE_DIR}/src)

# Aggiungi le cartelle di inclusione
include_directories(
    ${LIBZEROCOIN_INCLUDE_DIR}
    ${LIBZEROCOIN_SRC_DIR}
)

# Aggiungi i file di origine
set(SRC_FILES
    ${LIBZEROCOIN_SRC_DIR}/Accumulator.cpp
    ${LIBZEROCOIN_SRC_DIR}/AccumulatorProofOfKnowledge.cpp
    ${LIBZEROCOIN_SRC_DIR}/Coin.cpp
    ${LIBZEROCOIN_SRC_DIR}/CoinSpend.cpp
    ${LIBZEROCOIN_SRC_DIR}/Commitment.cpp
    ${LIBZEROCOIN_SRC_DIR}/ParamGeneration.cpp
    ${LIBZEROCOIN_SRC_DIR}/SerialNumberSignatureOfKnowledge.cpp
    ${LIBZEROCOIN_SRC_DIR}/bignum.cpp
    ${LIBZEROCOIN_SRC_DIR}/hash.cpp
    ${LIBZEROCOIN_SRC_DIR}/paramgen.cpp
    ${LIBZEROCOIN_SRC_DIR}/Tests.cpp
    ${LIBZEROCOIN_SRC_DIR}/Tutorial.cpp
)

# Aggiungi i file di header
set(HEADER_FILES
    ${LIBZEROCOIN_INCLUDE_DIR}/Accumulator.h
    ${LIBZEROCOIN_INCLUDE_DIR}/AccumulatorProofOfKnowledge.h
    ${LIBZEROCOIN_INCLUDE_DIR}/Coin.h
    ${LIBZEROCOIN_INCLUDE_DIR}/CoinSpend.h
    ${LIBZEROCOIN_INCLUDE_DIR}/Commitment.h
    ${LIBZEROCOIN_INCLUDE_DIR}/CommitmentProofOfKnowledge.h
    ${LIBZEROCOIN_INCLUDE_DIR}/ParamGeneration.h
    ${LIBZEROCOIN_INCLUDE_DIR}/SerialNumberSignatureOfKnowledge.h
    ${LIBZEROCOIN_INCLUDE_DIR}/bignum.h
    ${LIBZEROCOIN_INCLUDE_DIR}/hash.h
    ${LIBZEROCOIN_INCLUDE_DIR}/serialize.h
    ${LIBZEROCOIN_INCLUDE_DIR}/serialize_stub.h
    ${LIBZEROCOIN_INCLUDE_DIR}/uint256.h
    ${LIBZEROCOIN_INCLUDE_DIR}/Zerocoin.h
)

# Definisci la libreria da creare
add_library(zerocoin STATIC ${SRC_FILES} ${HEADER_FILES})

# Opzioni di linkaggio (se necessarie)
# Esempio: link a OpenSSL o altre librerie
# target_link_libraries(zerocoin PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Genera un file .pc per pkg-config
configure_file(${CMAKE_SOURCE_DIR}/libzerocoin.pc.in ${CMAKE_BINARY_DIR}/libzerocoin.pc @ONLY)

# Crea una configurazione per i test (se presenti)
# aggiungere opzioni per i test in caso siano necessari
# enable_testing()
# add_subdirectory(tests)
