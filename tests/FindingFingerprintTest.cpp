#include "core/FindingFingerprint.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace codeskeptic;

namespace {

fs::path writeSource(const fs::path &root, const std::string &content) {
  const fs::path path = root / "project" / "src" / "sample.cpp";
  fs::create_directories(path.parent_path());
  std::ofstream output(path);
  output << content;
  return path;
}

Diagnostic diagnosticAt(const fs::path &path, unsigned line) {
  Diagnostic diagnostic;
  diagnostic.severity = Severity::Warning;
  diagnostic.file = path.string();
  diagnostic.line = line;
  diagnostic.column = 9;
  diagnostic.rule_id = "null-deref";
  diagnostic.function = "sample";
  diagnostic.message = "Possible null dereference: 'p' may be null";
  return diagnostic;
}

} // namespace

TEST(FindingFingerprintTest, StableAcrossCheckoutRootsLineShiftsAndFormatting) {
  const fs::path first_root =
      fs::path(::testing::TempDir()) / "fingerprint-root-a";
  const fs::path second_root =
      fs::path(::testing::TempDir()) / "fingerprint-root-b";
  const fs::path first =
      writeSource(first_root, "int sample(int* p) {\n    return *p;\n}\n");
  const fs::path second = writeSource(
      second_root, "// shifted\n\nint sample(int* p) {\n\treturn  * p;\n}\n");

  Diagnostic left = diagnosticAt(first, 2);
  Diagnostic right = diagnosticAt(second, 4);
  right.column = 2;
  right.severity = Severity::Error;
  right.message = "Definite dereference of a null pointer";

  const std::string fingerprint = findingFingerprint(left);
  EXPECT_EQ(fingerprint, findingFingerprint(right));
  EXPECT_EQ(fingerprint.rfind("csf1-", 0), 0u);
  EXPECT_EQ(fingerprint.size(), 21u);
}

TEST(FindingFingerprintTest, SemanticInputsChangeIdentity) {
  const fs::path root = fs::path(::testing::TempDir()) / "fingerprint-semantic";
  const fs::path source =
      writeSource(root, "int sample(int* p) {\n    return *p;\n}\n");
  Diagnostic original = diagnosticAt(source, 2);
  const std::string expected = findingFingerprint(original);

  Diagnostic changed = original;
  changed.rule_id = "bounds";
  EXPECT_NE(expected, findingFingerprint(changed));
  changed = original;
  changed.function = "other";
  EXPECT_NE(expected, findingFingerprint(changed));
  writeSource(root, "int sample(int* p) {\n    return p[1];\n}\n");
  EXPECT_NE(expected, findingFingerprint(original));
}

TEST(FindingFingerprintTest, AssignmentPopulatesEveryFinding) {
  DiagnosticList diagnostics(2);
  diagnostics[0].rule_id = "contract";
  diagnostics[0].message = "first";
  diagnostics[1].rule_id = "policy";
  diagnostics[1].message = "second";

  assignFindingFingerprints(diagnostics);

  EXPECT_EQ(diagnostics[0].fingerprint.rfind("csf1-", 0), 0u);
  EXPECT_EQ(diagnostics[1].fingerprint.rfind("csf1-", 0), 0u);
  EXPECT_NE(diagnostics[0].fingerprint, diagnostics[1].fingerprint);
}
