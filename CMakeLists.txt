cmake_minimum_required(VERSION 3.16)
project(libzerocoin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find OpenSSL 3.0 or newer
find_package(OpenSSL 3.0 REQUIRED)

# Find Boost 1.88 or newer
find_package(Boost 1.88 REQUIRED COMPONENTS system filesystem)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# List ALL source files that actually exist in your repo
set(LIBZEROCOIN_SOURCES
    src/Accumulator.cpp
    src/AccumulatorProofOfKnowledge.cpp
    src/Coin.cpp
    src/CoinSpend.cpp
    src/Commitment.cpp
    src/hash.cpp
    src/bignum.cpp
    src/ParamGeneration.cpp
    src/Params.cpp
    src/SerialNumberSignatureOfKnowledge.cpp
    src/SpendMetaData.cpp
    src/Zerocoin.cpp
    src/zerocoin_types.cpp
)

# Check which files actually exist
foreach(src_file ${LIBZEROCOIN_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src_file}")
        message(WARNING "Source file ${src_file} not found!")
        list(REMOVE_ITEM LIBZEROCOIN_SOURCES ${src_file})
    endif()
endforeach()

message(STATUS "Found source files: ${LIBZEROCOIN_SOURCES}")

# Create shared library
add_library(zerocoin SHARED ${LIBZEROCOIN_SOURCES})

# Set properties
set_target_properties(zerocoin PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# Link libraries
target_link_libraries(zerocoin
    PRIVATE OpenSSL::Crypto
    PRIVATE Boost::system
    PRIVATE Boost::filesystem
)

# Compile definitions for OpenSSL 3.5 compatibility
target_compile_definitions(zerocoin PRIVATE
    OPENSSL_API_COMPAT=30000
    OPENSSL_NO_DEPRECATED
)

# Include directories for the library
target_include_directories(zerocoin
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Installation
install(TARGETS zerocoin
    EXPORT zerocoin-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install headers
install(DIRECTORY include/ DESTINATION include/libzerocoin)
