cmake_minimum_required(VERSION 3.16)
project(libzerocoin VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find dependencies
find_package(OpenSSL 3.0 REQUIRED)
find_package(Boost 1.88 REQUIRED COMPONENTS system filesystem)

# Single source file library
add_library(zerocoin SHARED libzerocoin.cpp)

# Include directory
target_include_directories(zerocoin
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

# Link libraries
target_link_libraries(zerocoin
    PRIVATE OpenSSL::Crypto
    PRIVATE Boost::system
    PRIVATE Boost::filesystem
)

# Compile definitions for OpenSSL 3.5
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

install(FILES libzerocoin.h DESTINATION include)
