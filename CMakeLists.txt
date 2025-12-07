cmake_minimum_required(VERSION 3.16)
project(libzerocoin
    VERSION 1.0.0
    DESCRIPTION "Zerocoin cryptographic library"
    LANGUAGES CXX
)

# Policy settings
cmake_policy(SET CMP0167 NEW)

# Trova le dipendenze
find_package(OpenSSL 3.0 REQUIRED)
find_package(Boost 1.75 REQUIRED COMPONENTS serialization)

# Configurazione delle opzioni del compilatore
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wno-deprecated-declarations
    )
endif()

# Opzione per la libreria condivisa
option(BUILD_SHARED_LIBS "Build shared library" ON)

# Condizionale per scegliere la libreria statica o condivisa
if(BUILD_SHARED_LIBS)
    add_library(zerocoin SHARED
        src/libzerocoin.cpp
    )
else()
    add_library(zerocoin STATIC
        src/libzerocoin.cpp
    )
endif()

# Imposta esplicitamente il nome dell'output per la libreria come libzerocoin
set_target_properties(zerocoin PROPERTIES
    OUTPUT_NAME "zerocoin"  # Genererà libzerocoin.so (per SHARED) o libzerocoin.a (per STATIC)
    PREFIX "lib"  # Aggiungi il prefisso 'lib' su Linux
)

# Inclusione delle directory
target_include_directories(zerocoin PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link delle librerie necessarie
target_link_libraries(zerocoin
    OpenSSL::Crypto
    Boost::serialization
)

# Imposta versione e altre proprietà
set_target_properties(zerocoin PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# Configura la generazione del pacchetto TGZ
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
include(CPack)
