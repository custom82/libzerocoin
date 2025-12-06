cmake_minimum_required(VERSION 3.16)
project(libzerocoin
    VERSION 1.0.0
    DESCRIPTION "Zerocoin cryptographic library"
    LANGUAGES CXX
)

# Policy settings
cmake_policy(SET CMP0167 NEW)

# Find dependencies
find_package(OpenSSL 3.0 REQUIRED)
find_package(Boost 1.75 REQUIRED COMPONENTS serialization)

# Configure compiler options
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

# Shared library option
option(BUILD_SHARED_LIBS "Build shared library" ON)

# Library target
add_library(libzerocoin
    src/libzerocoin.cpp
)

target_include_directories(libzerocoin PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(libzerocoin
    OpenSSL::Crypto
    Boost::serialization
)

# Set version and properties
set_target_properties(libzerocoin PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
