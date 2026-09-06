#ifndef CODESKEPTIC_REPORTER_REPORT_ENCODING_H
#define CODESKEPTIC_REPORTER_REPORT_ENCODING_H

#include "reporter/Coverage.h"
#include <string>

namespace codeskeptic {

// JSON string contents, shared by all finding serializers. Path callers use
// coveragePathIdentity first so invalid UTF-8 never aliases another filename.
inline std::string escapeJson(const std::string& value) {
    static constexpr char hex[] = "0123456789abcdef";
    const std::string text = llvm::json::isUTF8(value) ? value : llvm::json::fixUTF8(value);
    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[c >> 4];
                    out += hex[c & 15];
                } else out += static_cast<char>(c);
        }
    }
    return out;
}

} // namespace codeskeptic
#endif
