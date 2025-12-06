cmake_minimum_required(VERSION 3.16)
project(libzerocoin VERSION 2.0.0 LANGUAGES CXX)

# FORZA C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Flag moderni
add_compile_options(-std=c++20)
add_compile_options(-Wall -Wextra -Wpedantic)

# Trova dipendenze
find_package(OpenSSL 3.0 REQUIRED)
find_package(Boost 1.75 REQUIRED COMPONENTS serialization)

# Configura output
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Target principale
add_library(libzerocoin STATIC
    src/libzerocoin.cpp
)

target_include_directories(libzerocoin PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(libzerocoin PUBLIC
    OpenSSL::Crypto
    Boost::serialization
)

# Test
if(BUILD_TESTS)
    enable_testing()
    add_executable(zerocoin_test tests/test_main.cpp)
    target_link_libraries(zerocoin_test libzerocoin)
    add_test(NAME zerocoin_test COMMAND zerocoin_test)
endif()

# Install
install(TARGETS libzerocoin
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)
