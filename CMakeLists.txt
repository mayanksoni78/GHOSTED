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

# Core library for Member 1, 2, 3 and 4 modules
add_library(ghostdisk_core
    src/fs_scanner.cpp
    src/directory_scanner.cpp
    src/proc_inspector.cpp
    src/discrepancy_analyzer.cpp
    src/finding_analyzer.cpp
    src/verification_service.cpp
    src/recovery_coordinator.cpp
)

target_include_directories(ghostdisk_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Test executables
enable_testing()

add_executable(test_scanners tests/test_scanners.cpp)
target_link_libraries(test_scanners PRIVATE ghostdisk_core)
add_test(NAME TestScanners COMMAND test_scanners)

add_executable(test_proc_inspector tests/test_proc_inspector.cpp)
target_link_libraries(test_proc_inspector PRIVATE ghostdisk_core)
add_test(NAME TestProcInspector COMMAND test_proc_inspector)

add_executable(test_analyzer tests/test_analyzer.cpp)
target_link_libraries(test_analyzer PRIVATE ghostdisk_core)
add_test(NAME TestAnalyzer COMMAND test_analyzer)

add_executable(test_recovery tests/test_recovery.cpp)
target_link_libraries(test_recovery PRIVATE ghostdisk_core)
add_test(NAME TestRecovery COMMAND test_recovery)

# Standalone CLI application for Linux diagnostics
add_executable(ghostdisk_cli src/cli_main.cpp)
target_link_libraries(ghostdisk_cli PRIVATE ghostdisk_core)
