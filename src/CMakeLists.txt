add_library(codeskeptic_core STATIC
    core/Messages.cpp
    core/FunctionFilter.cpp
    source_manager/SourceManager.cpp
    source_manager/ResourceDir.cpp
    engine/AllocFunctions.cpp
    engine/CfgCache.cpp
    engine/FatalCalls.cpp
    engine/ImmutableFlags.cpp
    engine/RuleEngine.cpp
    engine/SummaryDiff.cpp
    engine/FunctionSummary.cpp
    engine/PathFacts.cpp
    engine/Interval.cpp
    engine/IntervalEval.cpp
    engine/ExtentMap.cpp
    engine/ParamIntervals.cpp
    engine/CoverageReport.cpp
    engine/AssumptionMode.cpp
    reporter/ConsoleReporter.cpp
    reporter/HtmlReporter.cpp
    reporter/JsonReporter.cpp
    reporter/SarifReporter.cpp
    config/Config.cpp
    analyzer/StaticAnalyzer.cpp
    analyzer/SuppressionFilter.cpp
    analyzer/Baseline.cpp
    server/McpServer.cpp
    rules/UninitPointerRule_Ex.cpp
    rules/MemoryLeakRule_Ex.cpp
    rules/DivByZeroRule.cpp
    rules/IntOverflowRule.cpp
    rules/BoundsRule.cpp
    rules/AssumptionRule.cpp
    rules/NullDerefRule.cpp
    rules/ContractRule.cpp
    rules/PolicyRule.cpp
    contracts/ContractParser.cpp
    contracts/ContractInfo.cpp
    contracts/GuardContracts.cpp
    contracts/Policy.cpp
    contracts/Sidecar.cpp
)

add_executable(codeskeptic main.cpp)
target_link_libraries(codeskeptic PRIVATE codeskeptic_core)

# Relocatable-tarball rpath: distro LLVM packages link the clang libs
# against a shared libLLVM.so; the release layout bundles it in ../lib
# next to the binary (package_release.sh). Harmless for dev builds —
# an rpath entry that matches nothing is simply skipped.
if(APPLE)
    target_link_options(codeskeptic PRIVATE
        "-Wl,-rpath,@executable_path/../lib")
elseif(NOT WIN32)
    # --disable-new-dtags => DT_RPATH (not RUNPATH): unlike RUNPATH,
    # DT_RPATH applies transitively, so bundled libLLVM.so's own deps
    # (libedit, libxml2, ...) are also resolved from ../lib.
    target_link_options(codeskeptic PRIVATE
        "-Wl,-rpath,$ORIGIN/../lib" "-Wl,--disable-new-dtags")
endif()
# (Windows has no rpath: DLLs resolve from the exe's own directory.)

target_include_directories(codeskeptic_core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(codeskeptic_core SYSTEM
    PUBLIC ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS}
)

target_compile_definitions(codeskeptic_core
    PUBLIC ${LLVM_DEFINITIONS}
    # Single source of truth for the version: project(VERSION ...) above
    PUBLIC CODESKEPTIC_VERSION="${PROJECT_VERSION}"
)

# Clang resource dir (for intrinsic headers such as stddef.h, stdarg.h)
execute_process(
    COMMAND ${LLVM_TOOLS_BINARY_DIR}/clang${CMAKE_EXECUTABLE_SUFFIX} -print-resource-dir
    OUTPUT_VARIABLE CLANG_RESOURCE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(CLANG_RESOURCE_DIR)
    target_compile_definitions(codeskeptic_core PRIVATE
        CLANG_RESOURCE_DIR="${CLANG_RESOURCE_DIR}"
    )
    message(STATUS "Clang resource dir: ${CLANG_RESOURCE_DIR}")
endif()

# macOS SDK sysroot (for string.h, stdlib.h, etc.)
if(APPLE)
    execute_process(
        COMMAND xcrun --show-sdk-path
        OUTPUT_VARIABLE MACOS_SDK_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(MACOS_SDK_PATH)
        target_compile_definitions(codeskeptic_core PRIVATE
            MACOS_SDK_PATH="${MACOS_SDK_PATH}"
        )
        message(STATUS "macOS SDK path: ${MACOS_SDK_PATH}")
    endif()
endif()

if(NOT LLVM_ENABLE_RTTI)
    # MSVC spells "no RTTI" as /GR- (docs/windows-support.md §2)
    if(MSVC)
        target_compile_options(codeskeptic_core PUBLIC /GR-)
    else()
        target_compile_options(codeskeptic_core PUBLIC -fno-rtti)
    endif()
endif()

if(MSVC)
    # The Clang-header-heavy TUs overflow MSVC's default COFF section
    # limit; PUBLIC so test TUs (which include the same headers via
    # TestHelper) inherit it (docs/windows-support.md §2).
    target_compile_options(codeskeptic_core PUBLIC /bigobj)
endif()

target_link_libraries(codeskeptic_core
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
