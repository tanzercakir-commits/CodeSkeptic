cmake_minimum_required(VERSION 3.20)
project(CodeSkeptic VERSION 0.4.8 LANGUAGES C CXX)

# Release identity is evidence. A build from an exact v<project-version> tag
# carries the release version; every other checkout is visibly a development
# build and includes its source commit when git is available. This prevents
# months of post-release main changes from still claiming to be the old binary.
set(CODESKEPTIC_VERSION_OVERRIDE "" CACHE STRING
    "Explicit version identity for source archives/reproducible packagers")
if(CODESKEPTIC_VERSION_OVERRIDE)
    set(CODESKEPTIC_VERSION_STRING "${CODESKEPTIC_VERSION_OVERRIDE}")
elseif(DEFINED ENV{CODESKEPTIC_VERSION_OVERRIDE} AND
       NOT "$ENV{CODESKEPTIC_VERSION_OVERRIDE}" STREQUAL "")
    set(CODESKEPTIC_VERSION_STRING "$ENV{CODESKEPTIC_VERSION_OVERRIDE}")
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

# OFF for artifact builds (Docker image): the tests FetchContent
# googletest, which needs git + network — a hermetic image build
# shouldn't. CI and dev builds keep the default ON.
option(CODESKEPTIC_BUILD_TESTS "Build unit tests" ON)
option(CODESKEPTIC_BUILD_FUZZERS
       "Build deterministic libFuzzer parser targets" OFF)
set(CODESKEPTIC_SANITIZER "none" CACHE STRING
    "Runtime instrumentation profile: none, address, undefined, or thread")
set_property(CACHE CODESKEPTIC_SANITIZER PROPERTY STRINGS
             none address undefined thread)
set(CODESKEPTIC_SANITIZER_PROFILES none address undefined thread)
list(FIND CODESKEPTIC_SANITIZER_PROFILES
     "${CODESKEPTIC_SANITIZER}" CODESKEPTIC_SANITIZER_INDEX)
if(CODESKEPTIC_SANITIZER_INDEX EQUAL -1)
    message(FATAL_ERROR
        "unsupported CODESKEPTIC_SANITIZER: ${CODESKEPTIC_SANITIZER}")
endif()
if(NOT CODESKEPTIC_SANITIZER STREQUAL "none" AND
   NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
        "CodeSkeptic sanitizer profiles require Clang or AppleClang")
endif()

# One interface target makes the runtime part of every CodeSkeptic consumer:
# production CLI, unit tests, and each dedicated libFuzzer executable. A
# static library cannot prove a sanitizer runtime by compile flags alone; the
# final executable must carry the matching link option too.
add_library(codeskeptic_sanitizer_flags INTERFACE)
set(CODESKEPTIC_SANITIZER_FLAGS "")
if(NOT CODESKEPTIC_SANITIZER STREQUAL "none")
    list(APPEND CODESKEPTIC_SANITIZER_FLAGS
         "-fsanitize=${CODESKEPTIC_SANITIZER}"
         "-fno-omit-frame-pointer")
    if(CODESKEPTIC_SANITIZER STREQUAL "undefined")
        list(APPEND CODESKEPTIC_SANITIZER_FLAGS
             "-fno-sanitize-recover=undefined")
    endif()
    target_compile_options(codeskeptic_sanitizer_flags INTERFACE
                           ${CODESKEPTIC_SANITIZER_FLAGS})
    target_link_options(codeskeptic_sanitizer_flags INTERFACE
                        ${CODESKEPTIC_SANITIZER_FLAGS})
endif()

if(CODESKEPTIC_BUILD_FUZZERS AND CODESKEPTIC_BUILD_TESTS)
    message(FATAL_ERROR
        "Fuzzer builds are dedicated: set CODESKEPTIC_BUILD_TESTS=OFF")
endif()
if(CODESKEPTIC_BUILD_FUZZERS AND
   NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "CodeSkeptic fuzz targets require Clang/libFuzzer")
endif()
if(APPLE)
    if(NOT CMAKE_OSX_SYSROOT)
        execute_process(
            COMMAND xcrun --show-sdk-path
            OUTPUT_VARIABLE CODESKEPTIC_APPLE_SDK
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE CODESKEPTIC_APPLE_SDK_RESULT
        )
        if(NOT CODESKEPTIC_APPLE_SDK_RESULT EQUAL 0 OR
           NOT CODESKEPTIC_APPLE_SDK)
            message(FATAL_ERROR
                "macOS builds require an Xcode SDK sysroot")
        endif()
        set(CMAKE_OSX_SYSROOT "${CODESKEPTIC_APPLE_SDK}" CACHE PATH
            "Xcode SDK used by macOS builds" FORCE)
    endif()
endif()

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

# Tiny, dependency-free child-side half of the resource-supervision
# handshake. Keeping it separate lets the dedicated probe use the exact
# production handshake without linking the Clang-heavy analyzer core. Define
# it after LLVM discovery so LLVM's selected MSVC CRT model is inherited by
# both this library and its later executable consumers.
add_library(codeskeptic_resource_worker_control STATIC
    src/core/ResourceWorkerControl.cpp)
target_include_directories(codeskeptic_resource_worker_control
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(codeskeptic_resource_worker_control
    PUBLIC codeskeptic_sanitizer_flags)

message(STATUS "LLVM version: ${LLVM_VERSION}")
message(STATUS "Clang include dirs: ${CLANG_INCLUDE_DIRS}")

if(APPLE)
    # Homebrew LLVM's imported dependency targets publish the SDK's root C
    # include directory as a consumer include. Clang already reaches it via
    # -isysroot; publishing it explicitly places C headers before libc++ and
    # breaks libc++'s include_next wrappers. Remove only that redundant root
    # include from the imported targets, leaving their link locations intact.
    set(CODESKEPTIC_LLVM_SDK_INCLUDE "${CMAKE_OSX_SYSROOT}/usr/include")
    foreach(CODESKEPTIC_LLVM_DEP IN ITEMS
            FFI::ffi FFI::ffi_static LibEdit::LibEdit ZLIB::ZLIB)
        if(TARGET ${CODESKEPTIC_LLVM_DEP})
            get_target_property(CODESKEPTIC_LLVM_DEP_INCLUDES
                ${CODESKEPTIC_LLVM_DEP} INTERFACE_INCLUDE_DIRECTORIES)
            if(CODESKEPTIC_LLVM_DEP_INCLUDES)
                list(REMOVE_ITEM CODESKEPTIC_LLVM_DEP_INCLUDES
                    "${CODESKEPTIC_LLVM_SDK_INCLUDE}")
                set_property(TARGET ${CODESKEPTIC_LLVM_DEP} PROPERTY
                    INTERFACE_INCLUDE_DIRECTORIES
                    "${CODESKEPTIC_LLVM_DEP_INCLUDES}")
            endif()
        endif()
    endforeach()
endif()

add_subdirectory(src)
if(CODESKEPTIC_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()

if(CODESKEPTIC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(APPLE)
    # FetchContent's test dependency discovery can revisit SDK-backed
    # imported packages after the first cleanup above. Re-apply the exact
    # property normalization after every subdirectory has been configured;
    # CMake evaluates the transitive interface at generation time.
    foreach(CODESKEPTIC_LLVM_DEP IN ITEMS
            FFI::ffi FFI::ffi_static LibEdit::LibEdit ZLIB::ZLIB)
        if(TARGET ${CODESKEPTIC_LLVM_DEP})
            get_target_property(CODESKEPTIC_LLVM_DEP_INCLUDES
                ${CODESKEPTIC_LLVM_DEP} INTERFACE_INCLUDE_DIRECTORIES)
            if(CODESKEPTIC_LLVM_DEP_INCLUDES)
                list(REMOVE_ITEM CODESKEPTIC_LLVM_DEP_INCLUDES
                    "${CODESKEPTIC_LLVM_SDK_INCLUDE}")
                set_property(TARGET ${CODESKEPTIC_LLVM_DEP} PROPERTY
                    INTERFACE_INCLUDE_DIRECTORIES
                    "${CODESKEPTIC_LLVM_DEP_INCLUDES}")
            endif()
        endif()
    endforeach()
endif()
