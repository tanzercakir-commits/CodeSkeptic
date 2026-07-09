include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(zerodefect_tests
    TestHelper.cpp
    DiagnosticTest.cpp
    UninitPointerRuleExTest.cpp
    MemoryLeakRuleExTest.cpp
    DivByZeroRuleTest.cpp
    NullDerefRuleTest.cpp
    SarifReporterTest.cpp
    SuppressionFilterTest.cpp
    BaselineTest.cpp
    StressEdgeCaseTest.cpp
    FunctionFilterTest.cpp
    McpServerTest.cpp
    InterproceduralTest.cpp
)

target_include_directories(zerodefect_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(zerodefect_tests
    PRIVATE
        zerodefect_core
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(zerodefect_tests)
