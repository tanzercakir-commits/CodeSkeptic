include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
# MSVC: googletest defaults to the static CRT (/MT) while this project
# uses CMake's default /MD — mixing them is a hard link error (LNK2038).
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(codeskeptic_tests
    TestHelper.cpp
    DiagnosticTest.cpp
    AnalysisResultTest.cpp
    CapabilitiesTest.cpp
    FindingFingerprintTest.cpp
    ConfigTest.cpp
    SourceManagerTest.cpp
    VerdictIntegrityTest.cpp
    JsonReporterTest.cpp
    UninitPointerRuleExTest.cpp
    UninitScalarRuleTest.cpp
    MemoryLeakRuleExTest.cpp
    FdResourceRuleTest.cpp
    DivByZeroRuleTest.cpp
    IntOverflowRuleTest.cpp
    SignConversionRuleTest.cpp
    AllocSizeOverflowRuleTest.cpp
    BoundsRuleTest.cpp
    NullDerefRuleTest.cpp
    AssertRecoveryTest.cpp
    SarifReporterTest.cpp
    HtmlReporterTest.cpp
    CfgCacheTest.cpp
    IntervalTest.cpp
    IntervalAnalysisTest.cpp
    ImmutableFlagsTest.cpp
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
    MacSdkPathTest.cpp
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
add_dependencies(codeskeptic_tests codeskeptic_corpus_inputs)

include(GoogleTest)
gtest_discover_tests(codeskeptic_tests)

# Cross-host status/review automation is Python-only and deliberately runs on
# every platform. In particular, its synthetic Windows compile-command paths
# pin bugs that the POSIX-only end-to-end review fixture cannot exercise.
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME CompilationDatabaseCliContract
         COMMAND ${Python3_EXECUTABLE} -B
                 ${CMAKE_CURRENT_SOURCE_DIR}/CompilationDatabaseCliTest.py
                 $<TARGET_FILE:codeskeptic>)
set_tests_properties(CompilationDatabaseCliContract PROPERTIES
    ENVIRONMENT "CODESKEPTIC_CORPUS_COMPILER=${LLVM_TOOLS_BINARY_DIR}/clang${CMAKE_EXECUTABLE_SUFFIX}")
if(UNIX)
    add_test(NAME ProjectQueueContract
             COMMAND ${Python3_EXECUTABLE} -B
                     ${CMAKE_CURRENT_SOURCE_DIR}/test_project_queue.py)
endif()
add_test(NAME StatusAutomationContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/StatusAutomationTest.py)
add_test(NAME RealworldCampaignContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/RealworldCampaignTest.py)
add_test(NAME StressMatrixContract
         COMMAND ${Python3_EXECUTABLE} -B
                 ${CMAKE_CURRENT_SOURCE_DIR}/StressMatrixTest.py)
add_test(NAME StressMatrixCorpus
         COMMAND ${Python3_EXECUTABLE} -B
                 ${CMAKE_SOURCE_DIR}/scripts/run_stress_matrix.py
                 $<TARGET_FILE:codeskeptic>)
set_tests_properties(StressMatrixContract PROPERTIES TIMEOUT 60)
set_tests_properties(StressMatrixCorpus PROPERTIES TIMEOUT 120 LABELS "stress")
add_test(NAME ReviewInputContract
         COMMAND ${Python3_EXECUTABLE} -B
                 ${CMAKE_CURRENT_SOURCE_DIR}/ReviewInputTest.py
                 $<TARGET_FILE:codeskeptic>)
set_tests_properties(ReviewInputContract PROPERTIES TIMEOUT 180)

# End-to-end diff-review flow (scripts/review_diff.sh + review_report.py):
# hermetic git-repo fixture driven with the real binary. Pins the delta
# semantics (Baseline-v2 key parity / shift-immunity, rename map, gate
# ladder). Needs git + python3 — present locally and on the CI runner.
#
# Not on native Windows: the auxiliary harness is bash+python by design
# (docs/windows-support.md §6) and its path/exit-code assumptions are
# POSIX. The 620 C++ unit tests above are the portable floor; this
# flow stays pinned by the Linux/macOS lanes.
if(NOT WIN32)
    add_test(NAME ActionArgsParser
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/ActionArgsTest.py)
    add_test(NAME ReleaseWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/ReleaseWorkflowTest.py)
    add_test(NAME DockerWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/DockerWorkflowTest.py)
    add_test(NAME CapabilitiesCliContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/CapabilitiesCliTest.py
                     $<TARGET_FILE:codeskeptic>)
    add_test(NAME OutputParityCliContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/OutputParityCliTest.py
                     $<TARGET_FILE:codeskeptic>)
    add_test(NAME MeasurementLabContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/MeasurementLabTest.py)
    add_test(NAME MeasurementWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/MeasurementWorkflowTest.py)
    add_test(NAME ReviewDiffFlow
             COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/test_review_diff.sh
                     $<TARGET_FILE:codeskeptic>)
endif()
