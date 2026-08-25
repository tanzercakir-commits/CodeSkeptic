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
    AnalysisCoordinatorTest.cpp
    WorkerProtocolTest.cpp
    UnitEvidenceStoreTest.cpp
    BudgetedAnalysisTest.cpp
    CapabilitiesTest.cpp
    FindingFingerprintTest.cpp
    ConfigTest.cpp
    VerdictIntegrityTest.cpp
    JsonReporterTest.cpp
    UninitPointerRuleExTest.cpp
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
    ResourceSupervisorTest.cpp
)

add_executable(codeskeptic_resource_probe resource_budget_probe.cpp)
target_link_libraries(codeskeptic_resource_probe PRIVATE
                      codeskeptic_resource_worker_control)
add_executable(codeskeptic_budget_worker_probe budget_worker_probe.cpp)
target_link_libraries(codeskeptic_budget_worker_probe PRIVATE
                      codeskeptic_core)
add_dependencies(codeskeptic_tests codeskeptic
                 codeskeptic_resource_probe
                 codeskeptic_budget_worker_probe)
target_compile_definitions(codeskeptic_tests PRIVATE
    CODESKEPTIC_BINARY="$<TARGET_FILE:codeskeptic>"
    CODESKEPTIC_RESOURCE_PROBE="$<TARGET_FILE:codeskeptic_resource_probe>"
    CODESKEPTIC_BUDGET_WORKER_PROBE="$<TARGET_FILE:codeskeptic_budget_worker_probe>")

target_include_directories(codeskeptic_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(codeskeptic_tests
    PRIVATE
        codeskeptic_core
        GTest::gtest_main
)

# Runtime tripwires prove that the selected sanitizer is linked and active.
# They are intentionally not CTest cases: the matrix runner executes the one
# matching the profile and requires its diagnostic/non-zero exit as evidence.
if(CODESKEPTIC_SANITIZER STREQUAL "address")
    add_executable(codeskeptic_sanitizer_tripwire
                   sanitizer/AddressTripwire.cpp)
    target_link_libraries(codeskeptic_sanitizer_tripwire PRIVATE
                          codeskeptic_sanitizer_flags)
elseif(CODESKEPTIC_SANITIZER STREQUAL "undefined")
    add_executable(codeskeptic_sanitizer_tripwire
                   sanitizer/UndefinedTripwire.cpp)
    target_link_libraries(codeskeptic_sanitizer_tripwire PRIVATE
                          codeskeptic_sanitizer_flags)
endif()

include(GoogleTest)
gtest_discover_tests(codeskeptic_tests)

# Cross-host status/review automation is Python-only and deliberately runs on
# every platform. In particular, its synthetic Windows compile-command paths
# pin bugs that the POSIX-only end-to-end review fixture cannot exercise.
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME StatusAutomationContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/StatusAutomationTest.py)
add_test(NAME RealworldCampaignContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/RealworldCampaignTest.py)
add_test(NAME StabilityFaultInjectionContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/StabilityFaultInjectionTest.py)
add_test(NAME HostedStatusWorkflowContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/HostedStatusWorkflowTest.py)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME DeterminismCalibrationImportContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/DeterminismCalibrationImportTest.py)
    add_test(NAME StabilityEvidenceExportContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/StabilityEvidenceExportTest.py)
    add_test(NAME StabilityCgroupAuthorityContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/StabilityCgroupAuthorityTest.py)
    add_test(NAME StabilityHostRecoveryContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/StabilityHostRecoveryTest.py)
    add_test(NAME StabilityHostContaminationContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/StabilityHostContaminationTest.py)
    add_test(NAME StabilityCampaignContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/StabilityCampaignTest.py)
    add_test(NAME StabilityWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/StabilityWorkflowTest.py)
    add_test(NAME StabilityStagingProducerContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/StabilityStagingProducerTest.py)
    add_test(NAME HostedExactHeadReceiptContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/HostedExactHeadReceiptTest.py)
    add_test(NAME HostedCaptureContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/HostedCaptureTest.py)
    add_test(NAME RealworldMirrorAuthorityProducerContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/RealworldMirrorAuthorityProducerTest.py)
endif()
add_test(NAME Phase83QualificationContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/Phase83QualificationTest.py)
add_test(NAME UpstreamValidationContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/UpstreamValidationTest.py)
add_test(NAME UpstreamCandidateManifestContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/UpstreamCandidateManifestTest.py)
add_test(NAME UpstreamCandidateEvidenceContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/UpstreamCandidateEvidenceTest.py)
add_test(NAME FuzzingContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/FuzzingContractTest.py)
add_test(NAME SanitizerContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/SanitizerContractTest.py)
add_test(NAME StressMatrixContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/StressMatrixTest.py
                 $<TARGET_FILE:codeskeptic>)
add_test(NAME ResourceBudgetWorkflowContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/ResourceBudgetWorkflowTest.py)
add_test(NAME QualityFloorReceiptContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/QualityFloorReceiptTest.py)
add_test(NAME QualityFloorCampaignContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/QualityFloorCampaignTest.py)
add_test(NAME QualityFloorEvidenceContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/QualityFloorEvidenceTest.py)
add_test(NAME AnalyzerBuildAuthorityContract
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_CURRENT_SOURCE_DIR}/AnalyzerBuildAuthorityTest.py)

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
    add_test(NAME MeasurementLabContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/MeasurementLabTest.py)
    add_test(NAME MeasurementWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/MeasurementWorkflowTest.py)
    add_test(NAME JulietEvaluationContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/JulietEvaluationTest.py)
    add_test(NAME ThesisWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/ThesisWorkflowTest.py)
    add_test(NAME CorpusWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/CorpusWorkflowTest.py)
    add_test(NAME DeterminismQualificationContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/DeterminismQualificationTest.py)
    add_test(NAME DeterminismWorkflowContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/DeterminismWorkflowTest.py)
    add_test(NAME DeterminismConfirmationEvidenceContract
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/DeterminismConfirmationEvidenceTest.py)
    add_test(NAME ReviewDiffFlow
             COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/test_review_diff.sh
                     $<TARGET_FILE:codeskeptic>)
endif()

# Contract tests repeatedly import repository scripts while later authority
# tests hash the exact source tree.  Keep the suite observational: no test may
# leave Python bytecode inside the source tree and thereby perturb a later
# manifest or staging check.  Applying the environment to every test defined
# in this directory also covers shell contracts that invoke Python children.
get_property(CODESKEPTIC_DIRECTORY_TESTS DIRECTORY PROPERTY TESTS)
set_tests_properties(
    ${CODESKEPTIC_DIRECTORY_TESTS}
    PROPERTIES ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1"
)
