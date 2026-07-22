cmake_minimum_required(VERSION 3.20)
project(CodeSkeptic VERSION 0.4.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Homebrew LLVM (macOS ARM). On Linux the system LLVM is found;
# if needed, -DCMAKE_PREFIX_PATH=/usr/lib/llvm-20 can be passed (LLVM 18 still works).
if(APPLE AND NOT DEFINED CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH "/opt/homebrew/opt/llvm")
endif()

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "LLVM version: ${LLVM_VERSION}")
message(STATUS "Clang include dirs: ${CLANG_INCLUDE_DIRS}")

add_subdirectory(src)

enable_testing()
add_subdirectory(tests)
