# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(libzerocoin VERSION 2.0.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Trova OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Lista file sorgente - verifica quali esistono
set(POSSIBLE_SOURCES
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

# Filtra solo i file che esistono
set(LIBZEROCOIN_SOURCES)
foreach(src ${POSSIBLE_SOURCES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${src})
        list(APPEND LIBZEROCOIN_SOURCES ${src})
        message(STATUS "Found source: ${src}")
    else()
        message(WARNING "Source file not found: ${src}")
    endif()
endforeach()

# Verifica che abbiamo almeno alcuni file
list(LENGTH LIBZEROCOIN_SOURCES NUM_SOURCES)
if(NUM_SOURCES EQUAL 0)
    message(FATAL_ERROR "No source files found!")
endif()

# Crea la libreria
add_library(zerocoin ${LIBZEROCOIN_SOURCES})

# Link con OpenSSL
target_link_libraries(zerocoin ${OPENSSL_LIBRARIES})

# Flags di compilazione
if(MSVC)
    target_compile_options(zerocoin PRIVATE /W3)
else()
    target_compile_options(zerocoin PRIVATE
        -Wall
        -Wextra
        -Wno-deprecated-declarations
        -Wno-unused-parameter
    )
endif()

# Installa la libreria
install(TARGETS zerocoin
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Installa gli header
file(GLOB HEADER_FILES "*.h" "bitcoin_bignum/*.h")
install(FILES ${HEADER_FILES}
    DESTINATION include/libzerocoin
)

# Crea file pkg-config
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/libzerocoin.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/libzerocoin.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libzerocoin.pc
    DESTINATION lib/pkgconfig
)
