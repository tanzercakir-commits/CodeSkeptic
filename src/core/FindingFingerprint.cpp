#include "core/FindingFingerprint.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string_view>
#include <utility>

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

} // namespace codeskeptic
