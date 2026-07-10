// Summary diff: contract change classification. Invariants: (1) losing
// or changing a strong claim is WEAKENED (callers affected -> exit 1),
// (2) gaining a strong claim is STRENGTHENED, a directionless drift is
// CHANGED, (3) identical harvests yield zero records, (4) a corrupt
// file exits 2.

#include "engine/SummaryDiff.h"

#include <fstream>
#include <sstream>
#include <gtest/gtest.h>

using namespace zerodefect;
using RN = SummaryRegistry::ReturnNullness;
using RZ = SummaryRegistry::ReturnZeroness;
using PE = SummaryRegistry::ParamEffect;

namespace {

std::string writeFile(const std::string& name, const std::string& body) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream f(path);
    f << body;
    return path;
}

SummaryRegistry::FunctionSummary makeSum(RN rn, RZ rz,
                                         std::vector<PE> params = {}) {
    SummaryRegistry::FunctionSummary s;
    s.returnNullness = rn;
    s.returnZeroness = rz;
    s.params = std::move(params);
    return s;
}

} // anonymous namespace

TEST(SummaryDiffTest, StrongClaimLost_Weakened) {
    SummaryMap oldMap{{"find/1", makeSum(RN::NeverNull, RZ::Unknown)}};
    SummaryMap newMap{{"find/1", makeSum(RN::MaybeNull, RZ::Unknown)}};
    auto result = diffSummaries(oldMap, newMap);
    ASSERT_EQ(result.weakened, 1u);
    EXPECT_EQ(result.changes[0].kind, ChangeKind::Weakened);
    EXPECT_NE(result.changes[0].detail.find("NeverNull -> MaybeNull"),
              std::string::npos);
}

TEST(SummaryDiffTest, ParamStrongClaimChanged_Weakened) {
    // Frees -> Stores: double-free detection is lost, callers must be
    // re-examined
    SummaryMap oldMap{{"my_free/1",
                       makeSum(RN::Unknown, RZ::Unknown, {PE::Frees})}};
    SummaryMap newMap{{"my_free/1",
                       makeSum(RN::Unknown, RZ::Unknown, {PE::Stores})}};
    auto result = diffSummaries(oldMap, newMap);
    ASSERT_EQ(result.weakened, 1u);
    EXPECT_NE(result.changes[0].detail.find("param#0: Frees -> Stores"),
              std::string::npos);
}

TEST(SummaryDiffTest, StrongClaimGained_Strengthened) {
    SummaryMap oldMap{{"five/0", makeSum(RN::Unknown, RZ::Unknown)}};
    SummaryMap newMap{{"five/0", makeSum(RN::Unknown, RZ::NeverZero)}};
    auto result = diffSummaries(oldMap, newMap);
    EXPECT_EQ(result.weakened, 0u);
    ASSERT_EQ(result.strengthened, 1u);
    EXPECT_EQ(result.changes[0].kind, ChangeKind::Strengthened);
}

TEST(SummaryDiffTest, DirectionlessDrift_Changed) {
    SummaryMap oldMap{{"g/1", makeSum(RN::Unknown, RZ::Unknown)}};
    SummaryMap newMap{{"g/1", makeSum(RN::MaybeNull, RZ::Unknown)}};
    auto result = diffSummaries(oldMap, newMap);
    EXPECT_EQ(result.weakened, 0u);
    EXPECT_EQ(result.changed, 1u);
}

TEST(SummaryDiffTest, AddedRemoved_AndWeakenedFirst) {
    SummaryMap oldMap{
        {"gone/0", makeSum(RN::Unknown, RZ::Unknown)},
        {"weak/0", makeSum(RN::NeverNull, RZ::Unknown)},
    };
    SummaryMap newMap{
        {"weak/0", makeSum(RN::Unknown, RZ::Unknown)},
        {"fresh/0", makeSum(RN::Unknown, RZ::Unknown)},
    };
    auto result = diffSummaries(oldMap, newMap);
    EXPECT_EQ(result.added, 1u);
    EXPECT_EQ(result.removed, 1u);
    ASSERT_EQ(result.weakened, 1u);
    // Weakened entries come FIRST in the list (report readability)
    EXPECT_EQ(result.changes[0].kind, ChangeKind::Weakened);
}

TEST(SummaryDiffTest, IdenticalHarvests_NoChanges) {
    SummaryMap same{{"f/1", makeSum(RN::NeverNull, RZ::Unknown,
                                    {PE::ReadsOnly})}};
    auto result = diffSummaries(same, same);
    EXPECT_TRUE(result.changes.empty());
}

TEST(SummaryDiffTest, ReportEndToEnd_ExitCodes) {
    auto oldPath = writeFile("sd_old.txt",
        "zerodefect-summaries v2\n"
        "find/1\tN\t-\tU\n");
    auto newPathWeak = writeFile("sd_new_weak.txt",
        "zerodefect-summaries v2\n"
        "find/1\tM\t-\tU\n");
    auto newPathSame = writeFile("sd_new_same.txt",
        "zerodefect-summaries v2\n"
        "find/1\tN\t-\tU\n");

    std::ostringstream out;
    EXPECT_EQ(reportSummaryDiff(oldPath, newPathWeak, out), 1);
    EXPECT_NE(out.str().find("SUMMARY_DIFF WEAKENED find/1"),
              std::string::npos);
    EXPECT_NE(out.str().find("re-checked"), std::string::npos);

    std::ostringstream out2;
    EXPECT_EQ(reportSummaryDiff(oldPath, newPathSame, out2), 0);

    std::ostringstream out3;
    EXPECT_EQ(reportSummaryDiff("/no/such.txt", newPathSame, out3), 2);
}
