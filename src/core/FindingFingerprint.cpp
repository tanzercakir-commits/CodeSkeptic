#include "core/FindingFingerprint.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string_view>
#include <utility>
#include <filesystem>
#include <set>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/SourceManager.h>

namespace codeskeptic {

namespace {

constexpr std::size_t kPortablePathComponents = 3;

std::string portablePathTail(std::string path) {
  std::replace(path.begin(), path.end(), '\\', '/');

  std::vector<std::string_view> components;
  std::size_t begin = 0;
  while (begin < path.size()) {
    const std::size_t end = path.find('/', begin);
    const std::size_t length =
        (end == std::string::npos ? path.size() : end) - begin;
    if (length > 0)
      components.emplace_back(path.data() + begin, length);
    if (end == std::string::npos)
      break;
    begin = end + 1;
  }

  const std::size_t first = components.size() > kPortablePathComponents
                                ? components.size() - kPortablePathComponents
                                : 0;
  std::string result;
  for (std::size_t index = first; index < components.size(); ++index) {
    if (!result.empty())
      result += '/';
    result.append(components[index]);
  }
  return result;
}

std::string withoutFormattingWhitespace(std::string_view value) {
  std::string normalized;
  normalized.reserve(value.size());
  bool in_single_quote = false;
  bool in_double_quote = false;
  bool escaped = false;
  for (const unsigned char byte : value) {
    const char character = static_cast<char>(byte);
    const bool formatting_whitespace = character == ' ' || character == '\t' ||
                                       character == '\r' || character == '\n' ||
                                       character == '\v' || character == '\f';
    if (!in_single_quote && !in_double_quote && formatting_whitespace)
      continue;
    normalized += character;
    if (escaped) {
      escaped = false;
      continue;
    }
    if ((in_single_quote || in_double_quote) && character == '\\') {
      escaped = true;
      continue;
    }
    if (!in_double_quote && character == '\'')
      in_single_quote = !in_single_quote;
    else if (!in_single_quote && character == '"')
      in_double_quote = !in_double_quote;
  }
  return normalized;
}

std::string fnv1a64Hex(std::string_view value) {
  std::uint64_t hash = 14695981039346656037ull;
  for (const unsigned char byte : value) {
    hash ^= byte;
    hash *= 1099511628211ull;
  }
  char buffer[17];
  std::snprintf(buffer, sizeof(buffer), "%016llx",
                static_cast<unsigned long long>(hash));
  return buffer;
}

const std::string &
sourceLine(std::map<std::string, std::vector<std::string>> &cache,
           const std::string &path, unsigned line) {
  static const std::string empty;
  auto iterator = cache.find(path);
  if (iterator == cache.end()) {
    std::vector<std::string> lines;
    std::ifstream input(path);
    std::string current;
    while (std::getline(input, current))
      lines.push_back(std::move(current));
    iterator = cache.emplace(path, std::move(lines)).first;
  }
  if (line == 0 || line > iterator->second.size())
    return empty;
  return iterator->second[line - 1];
}

} // namespace

std::string
FindingFingerprintContext::fingerprint(const Diagnostic &diagnostic) {
  const std::string payload =
      "csf1\n" + diagnostic.rule_id + "\n" + portablePathTail(diagnostic.file) +
      "\n" + diagnostic.function + "\n" +
      withoutFormattingWhitespace(
          sourceLine(source_lines_, diagnostic.file, diagnostic.line));
  return "csf1-" + fnv1a64Hex(payload);
}

std::string findingFingerprint(const Diagnostic &diagnostic) {
  FindingFingerprintContext context;
  return context.fingerprint(diagnostic);
}

void assignFindingFingerprints(DiagnosticList &diagnostics) {
  FindingFingerprintContext context;
  for (auto &diagnostic : diagnostics)
    diagnostic.fingerprint = context.fingerprint(diagnostic);
}

void bindBaselineFunctions(clang::ASTContext &context, DiagnosticList &diagnostics) {
  if (diagnostics.empty()) return;
  struct Candidate {
    const clang::FunctionDecl *canonical;
    std::string file, signature;
    std::pair<unsigned, unsigned> begin, end;
  };
  struct Visitor : clang::RecursiveASTVisitor<Visitor> {
    clang::ASTContext &context;
    std::map<std::string, std::vector<Candidate>> candidates;
    explicit Visitor(clang::ASTContext &ctx, const DiagnosticList &findings)
        : context(ctx) {
      for (const auto &finding : findings)
        if (!finding.function.empty()) candidates.try_emplace(finding.function);
    }
    bool VisitFunctionDecl(clang::FunctionDecl *function) {
      const auto name = function->getQualifiedNameAsString();
      auto slot = candidates.find(name);
      if (slot == candidates.end() || !function->doesThisDeclarationHaveABody()) return true;
      const auto *body = function->getBody();
      auto begin = function->getBeginLoc(), end = body->getEndLoc();
      // Template constraints, macro-generated and dependent ownership require
      // more evidence than a canonical ordinary function type. Leave unbound.
      bool bindable = function->getTemplatedKind() == clang::FunctionDecl::TK_NonTemplate &&
                      !function->isDependentContext();
      if (const auto *method = llvm::dyn_cast<clang::CXXMethodDecl>(function))
        bindable = bindable && !method->getParent()->isLambda() &&
                   !method->getParent()->getDescribedClassTemplate();
      auto &source = context.getSourceManager();
      if (begin.isInvalid() || end.isInvalid() || begin.isMacroID() || end.isMacroID()) return true;
      if (source.getFileID(begin) != source.getFileID(end)) return true;
      std::error_code error;
      const auto file = std::filesystem::weakly_canonical(source.getFilename(begin).str(), error);
      if (error || source.getFilename(begin).empty()) return true;
      clang::PrintingPolicy policy(context.getLangOpts());
      const auto signature = bindable
          ? "csb-fn1:" + function->getType().getCanonicalType().getAsString(policy)
          : std::string{};
      slot->second.push_back({function->getCanonicalDecl(), file.string(), signature,
          {source.getSpellingLineNumber(begin), source.getSpellingColumnNumber(begin)},
          {source.getSpellingLineNumber(end), source.getSpellingColumnNumber(end)}});
      return true;
    }
  } visitor(context, diagnostics);
  visitor.TraverseDecl(context.getTranslationUnitDecl());
  for (auto &finding : diagnostics) {
    finding.baseline_function.clear();
    if (!finding.line || !finding.column) continue;
    const auto found = visitor.candidates.find(finding.function);
    if (found == visitor.candidates.end()) continue;
    std::error_code error;
    const auto path = std::filesystem::weakly_canonical(finding.file, error).string();
    if (error) continue;
    const std::pair<unsigned, unsigned> position{finding.line, finding.column};
    const Candidate *owner = nullptr;
    bool ambiguous = false;
    for (const auto &candidate : found->second) {
      if (candidate.file != path || position < candidate.begin || position > candidate.end) continue;
      if (owner && (owner->canonical != candidate.canonical || owner->signature != candidate.signature))
        ambiguous = true;
      owner = &candidate;
    }
    if (owner && !ambiguous) finding.baseline_function = owner->signature;
  }
}

} // namespace codeskeptic
