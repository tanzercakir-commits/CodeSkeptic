add_library(zerodefect_core STATIC
    source_manager/SourceManager.cpp
    engine/RuleEngine.cpp
    reporter/ConsoleReporter.cpp
    reporter/JsonReporter.cpp
    config/Config.cpp
    analyzer/StaticAnalyzer.cpp
    rules/UninitPointerRule.cpp
    rules/MemoryLeakRule.cpp
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
