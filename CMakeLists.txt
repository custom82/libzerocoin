cmake_minimum_required(VERSION 3.16)
project(libzerocoin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find dependencies
find_package(OpenSSL 3.0 REQUIRED)
find_package(Boost 1.88 REQUIRED COMPONENTS system filesystem)

# Source files - ONLY those that actually exist
set(ZEROCOIN_SOURCES
    src/Accumulator.cpp
    src/Coin.cpp
    src/CoinSpend.cpp
    src/Commitment.cpp
    src/hash.cpp
    src/bignum.cpp
    src/ParamGeneration.cpp
    src/Params.cpp
    src/SpendMetaData.cpp
    src/Zerocoin.cpp
)

# Optional files - only include if they exist
foreach(optional_file
    src/AccumulatorProofOfKnowledge.cpp
    src/SerialNumberSignatureOfKnowledge.cpp
    src/zerocoin_types.cpp
)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${optional_file}")
        list(APPEND ZEROCOIN_SOURCES ${optional_file})
        message(STATUS "Including optional file: ${optional_file}")
    else()
        message(STATUS "Skipping missing file: ${optional_file}")
    endif()
endforeach()

message(STATUS "Building with ${ZEROCOIN_SOURCES}")

# Create library
add_library(zerocoin SHARED ${ZEROCOIN_SOURCES})

# Include directories
target_include_directories(zerocoin
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link libraries
target_link_libraries(zerocoin
    PRIVATE OpenSSL::Crypto
    PRIVATE Boost::system
    PRIVATE Boost::filesystem
)

# Compile definitions
target_compile_definitions(zerocoin PRIVATE
    OPENSSL_API_COMPAT=30000
    OPENSSL_NO_DEPRECATED
)

# Installation
install(TARGETS zerocoin
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)
