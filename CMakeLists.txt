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

# Source files
set(SOURCES
    src/Accumulator.cpp
    src/AccumulatorProofOfKnowledge.cpp
    src/Coin.cpp
    src/CoinSpend.cpp
    src/Commitment.cpp
    src/ParamGeneration.cpp
    src/Params.cpp
    src/Proof.cpp
    src/SerialNumberSignatureOfKnowledge.cpp
    src/hash.cpp
    src/bignum.cpp
)

# Header files
set(HEADERS
    include/Accumulator.h
    include/AccumulatorProofOfKnowledge.h
    include/Coin.h
    include/CoinSpend.h
    include/Commitment.h
    include/ParamGeneration.h
    include/Params.h
    include/Proof.h
    include/SerialNumberSignatureOfKnowledge.h
    include/Zerocoin.h
    include/bignum.h
    include/hash.h
    include/serialize.h
)

# Create shared library
add_library(zerocoin SHARED ${SOURCES})

# Set properties
set_target_properties(zerocoin PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${HEADERS}"
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

# Installation
install(TARGETS zerocoin
    EXPORT zerocoin-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/libzerocoin
)

# Install headers
install(DIRECTORY include/ DESTINATION include/libzerocoin)

# Create and install CMake package
install(EXPORT zerocoin-targets
    FILE zerocoin-config.cmake
    NAMESPACE libzerocoin::
    DESTINATION lib/cmake/zerocoin
)

# Create test executable
if(BUILD_TESTING)
    add_executable(zerocoin_test tests/test_basic.cpp)
    target_link_libraries(zerocoin_test zerocoin)

    add_test(NAME zerocoin_test COMMAND zerocoin_test)
endif()
