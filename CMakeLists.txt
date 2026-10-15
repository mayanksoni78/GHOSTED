cmake_minimum_required(VERSION 3.16)
project(GhostDisk VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
if (MSVC)
    add_compile_options(/W4 /EHsc)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Core library for Member 1 modules (and future modules)
add_library(ghostdisk_core
    src/fs_scanner.cpp
    src/directory_scanner.cpp
)

target_include_directories(ghostdisk_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Test executable
enable_testing()
add_executable(test_scanners tests/test_scanners.cpp)
target_link_libraries(test_scanners PRIVATE ghostdisk_core)
add_test(NAME TestScanners COMMAND test_scanners)
