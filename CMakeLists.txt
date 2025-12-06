cmake_minimum_required(VERSION 3.16)
project(libzerocoin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Silenzia il warning di Boost
cmake_policy(SET CMP0167 NEW)

# Trova dipendenze
find_package(OpenSSL 3.0 REQUIRED)
find_package(Boost 1.88 REQUIRED COMPONENTS system filesystem)

# Directory sorgente e header
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(INCLUDE_DIR ${SOURCE_DIR}/include)

# File sorgente esistenti nel tuo repo - VERIFICA CHE ESISTANO
set(ZEROCOIN_SOURCES
    ${SOURCE_DIR}/src/libzerocoin.cpp
)

# Verifica quali file esistono realmente
foreach(file ${ZEROCOIN_SOURCES})
    if(NOT EXISTS "${file}")
        message(WARNING "File non trovato: ${file}")
        list(REMOVE_ITEM ZEROCOIN_SOURCES ${file})
    endif()
endforeach()

message(STATUS "File sorgente trovati: ${ZEROCOIN_SOURCES}")

# Crea la libreria
add_library(zerocoin SHARED ${ZEROCOIN_SOURCES})

# Directory di inclusione
target_include_directories(zerocoin
    PUBLIC
        $<BUILD_INTERFACE:${INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${SOURCE_DIR}/src
)

# Link con librerie
target_link_libraries(zerocoin
    PRIVATE OpenSSL::Crypto
    PRIVATE Boost::system
    PRIVATE Boost::filesystem
)

# Definizioni di compilazione per OpenSSL 3.5
target_compile_definitions(zerocoin PRIVATE
    OPENSSL_API_COMPAT=30000
    OPENSSL_NO_DEPRECATED
    _GLIBCXX_USE_CXX11_ABI=1
)

# Flags di compilazione
target_compile_options(zerocoin PRIVATE
    -Wall
    -Wextra
    -Wno-deprecated-declarations
)

# Installazione
install(TARGETS zerocoin
    EXPORT zerocoin-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Installa header
install(DIRECTORY ${INCLUDE_DIR}/ DESTINATION include/libzerocoin)

# Pacchetto pkg-config (opzionale)
configure_file(
    ${SOURCE_DIR}/libzerocoin.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/libzerocoin.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libzerocoin.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Test opzionale
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    add_executable(zerocoin_test ${SOURCE_DIR}/src/Tests.cpp)
    target_link_libraries(zerocoin_test zerocoin)
    add_test(NAME zerocoin_test COMMAND zerocoin_test)
endif()
