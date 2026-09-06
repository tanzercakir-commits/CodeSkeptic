#ifndef CODESKEPTIC_MODEL_INPUT_H
#define CODESKEPTIC_MODEL_INPUT_H

#include <array>
#include <filesystem>
#include <fstream>
#include <string>

namespace codeskeptic::model_input {

// Apply to a private input buffer, never published model state. Byte limits
// count the original file, including CRLF. Bare CR and binary NUL are invalid.
inline bool normalizeText(std::string& text, size_t maxBytes) {
    if (text.size() > maxBytes) return false;
    size_t dest = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\0') return false;
        if (text[i] == '\r') {
            if (i + 1 == text.size() || text[i + 1] != '\n') return false;
            continue;
        }
        text[dest++] = text[i];
    }
    text.resize(dest);
    return true;
}

// Reject non-regular inputs before opening (in particular FIFOs/devices).
// Recheck bytes actually read, rather than trusting a possibly stale size.
// This is not an atomic filesystem snapshot against concurrent replacement.
inline bool readTextFile(const std::string& path, size_t maxBytes,
                         std::string& out) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) return false;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > maxBytes) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::string text;
    std::array<char, 8192> chunk;
    for (;;) {
        in.read(chunk.data(), chunk.size());
        const auto count = static_cast<size_t>(in.gcount());
        if (count > maxBytes - text.size()) return false;
        text.append(chunk.data(), count);
        if (in.bad() || (in.fail() && !in.eof())) return false;
        if (in.eof()) break;
    }
    if (!normalizeText(text, maxBytes)) return false;
    out.swap(text);
    return true;
}

} // namespace codeskeptic::model_input

#endif
