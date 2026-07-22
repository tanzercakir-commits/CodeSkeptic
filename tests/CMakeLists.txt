include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(codeskeptic_tests
    TestHelper.cpp
    DiagnosticTest.cpp
    UninitPointerRuleExTest.cpp
    MemoryLeakRuleExTest.cpp
    DivByZeroRuleTest.cpp
    IntOverflowRuleTest.cpp
    BoundsRuleTest.cpp
    NullDerefRuleTest.cpp
    SarifReporterTest.cpp
    HtmlReporterTest.cpp
    CfgCacheTest.cpp
    IntervalTest.cpp
    IntervalAnalysisTest.cpp
    ParamIntervalsTest.cpp
    CoverageReportTest.cpp
    AssumptionRuleTest.cpp
    FatalCallsTest.cpp
    SummaryDiffTest.cpp
    SuppressionFilterTest.cpp
    BaselineTest.cpp
    DisjunctsV2bTest.cpp
    ContractTest.cpp
    StressEdgeCaseTest.cpp
    FunctionFilterTest.cpp
    ReportPathsTest.cpp
    BrokenTuTest.cpp
    McpServerTest.cpp
    InterproceduralTest.cpp
    ResourceDirTest.cpp
)

target_include_directories(codeskeptic_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(codeskeptic_tests
    PRIVATE
        codeskeptic_core
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(codeskeptic_tests)

# End-to-end diff-review flow (scripts/review_diff.sh + review_report.py):
# hermetic git-repo fixture driven with the real binary. Pins the delta
# semantics (Baseline-v2 key parity / shift-immunity, rename map, gate
# ladder). Needs git + python3 — present locally and on the CI runner.
add_test(NAME ReviewDiffFlow
         COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/test_review_diff.sh
                 $<TARGET_FILE:codeskeptic>)
