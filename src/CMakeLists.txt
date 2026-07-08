add_library(zerodefect_core STATIC
    core/Messages.cpp
    source_manager/SourceManager.cpp
    engine/RuleEngine.cpp
    reporter/ConsoleReporter.cpp
    reporter/JsonReporter.cpp
    config/Config.cpp
    analyzer/StaticAnalyzer.cpp
    rules/UninitPointerRule_Ex.cpp
    rules/MemoryLeakRule_Ex.cpp
    rules/DivByZeroRule.cpp
)

add_executable(zerodefect main.cpp)
target_link_libraries(zerodefect PRIVATE zerodefect_core)

target_include_directories(zerodefect_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(zerodefect_core SYSTEM
    PUBLIC ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS}
)

target_compile_definitions(zerodefect_core
    PUBLIC ${LLVM_DEFINITIONS}
)

# Clang resource dir (stddef.h, stdarg.h gibi intrinsic header'lar için)
execute_process(
    COMMAND ${LLVM_TOOLS_BINARY_DIR}/clang -print-resource-dir
    OUTPUT_VARIABLE CLANG_RESOURCE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(CLANG_RESOURCE_DIR)
    target_compile_definitions(zerodefect_core PRIVATE
        CLANG_RESOURCE_DIR="${CLANG_RESOURCE_DIR}"
    )
    message(STATUS "Clang resource dir: ${CLANG_RESOURCE_DIR}")
endif()

# macOS SDK sysroot (string.h, stdlib.h vb. için)
if(APPLE)
    execute_process(
        COMMAND xcrun --show-sdk-path
        OUTPUT_VARIABLE MACOS_SDK_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(MACOS_SDK_PATH)
        target_compile_definitions(zerodefect_core PRIVATE
            MACOS_SDK_PATH="${MACOS_SDK_PATH}"
        )
        message(STATUS "macOS SDK path: ${MACOS_SDK_PATH}")
    endif()
endif()

if(NOT LLVM_ENABLE_RTTI)
    target_compile_options(zerodefect_core PUBLIC -fno-rtti)
endif()

target_link_libraries(zerodefect_core
    PUBLIC
        clangTooling
        clangFrontend
        clangAST
        clangBasic
        clangSerialization
        clangDriver
        clangParse
        clangSema
        clangAnalysis
        clangEdit
        clangLex
        clangASTMatchers
        LLVMSupport
)
