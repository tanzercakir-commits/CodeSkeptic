cmake_minimum_required(VERSION 3.20)
project(CodeSkeptic VERSION 0.4.7 LANGUAGES C CXX)

# Release identity is evidence. A build from an exact v<project-version> tag
# carries the release version; every other checkout is visibly a development
# build and includes its source commit when git is available. This prevents
# months of post-release main changes from still claiming to be the old binary.
set(CODESKEPTIC_VERSION_OVERRIDE "" CACHE STRING
    "Explicit version identity for source archives/reproducible packagers")
if(CODESKEPTIC_VERSION_OVERRIDE)
    set(CODESKEPTIC_VERSION_STRING "${CODESKEPTIC_VERSION_OVERRIDE}")
else()
    execute_process(
        COMMAND git describe --tags --exact-match HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE CODESKEPTIC_TAG_RESULT
        OUTPUT_VARIABLE CODESKEPTIC_EXACT_TAG
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(CODESKEPTIC_TAG_RESULT EQUAL 0 AND
       CODESKEPTIC_EXACT_TAG STREQUAL "v${PROJECT_VERSION}")
        set(CODESKEPTIC_VERSION_STRING "${PROJECT_VERSION}")
    else()
        math(EXPR CODESKEPTIC_NEXT_PATCH "${PROJECT_VERSION_PATCH} + 1")
        set(CODESKEPTIC_VERSION_STRING
            "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${CODESKEPTIC_NEXT_PATCH}-dev")
        execute_process(
            COMMAND git rev-parse --short=12 HEAD
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            RESULT_VARIABLE CODESKEPTIC_SHA_RESULT
            OUTPUT_VARIABLE CODESKEPTIC_GIT_SHA
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(CODESKEPTIC_SHA_RESULT EQUAL 0)
            string(APPEND CODESKEPTIC_VERSION_STRING "+g${CODESKEPTIC_GIT_SHA}")
            execute_process(
                COMMAND git diff --quiet --ignore-submodules HEAD
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                RESULT_VARIABLE CODESKEPTIC_DIRTY_RESULT
                ERROR_QUIET
            )
            if(NOT CODESKEPTIC_DIRTY_RESULT EQUAL 0)
                string(APPEND CODESKEPTIC_VERSION_STRING ".dirty")
            endif()
        endif()
    endif()
endif()
message(STATUS "CodeSkeptic identity: ${CODESKEPTIC_VERSION_STRING}")

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

# OFF for artifact builds (Docker image): the tests FetchContent
# googletest, which needs git + network — a hermetic image build
# shouldn't. CI and dev builds keep the default ON.
option(CODESKEPTIC_BUILD_TESTS "Build unit tests" ON)
if(CODESKEPTIC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
