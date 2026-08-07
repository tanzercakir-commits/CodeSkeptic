#include "core/Capabilities.h"

#include <ostream>

#ifndef CODESKEPTIC_VERSION
#define CODESKEPTIC_VERSION "0.0.0-dev"
#endif

namespace codeskeptic {

void writeCapabilities(std::ostream& out, bool json) {
    if (!json) {
        out << "CodeSkeptic " << CODESKEPTIC_VERSION << "\n"
            << "languages: C, C++\n"
            << "outputs: console, json, sarif-2.1.0, html\n"
            << "frontends: cli, mcp\n"
            << "verdict-exit-codes: 0=clean, 1=findings, 2=unavailable\n"
            << "rules: uninit-ptr, memory-leak, double-free, use-after-free, "
               "resource-leak, div-by-zero, null-deref, bounds, int-overflow, "
               "sign-conversion, alloc-size-overflow, assumption, contract, "
               "policy\n";
        return;
    }

    out << "{\n"
        << "  \"schema_version\": 1,\n"
        << "  \"product\": \"CodeSkeptic\",\n"
        << "  \"version\": \"" << CODESKEPTIC_VERSION << "\",\n"
        << "  \"languages\": [\"c\", \"cpp\"],\n"
        << "  \"frontends\": [\"cli\", \"mcp\"],\n"
        << "  \"outputs\": [\"console\", \"json\", \"sarif-2.1.0\", \"html\"],\n"
        << "  \"modes\": [\"whole-program\", \"incremental-summaries\", "
           "\"baseline\", \"function-scope\", \"line-scope\"],\n"
        << "  \"verdict\": {\"0\": \"clean\", \"1\": \"findings\", "
           "\"2\": \"unavailable\"},\n"
        << "  \"rules\": [\"uninit-ptr\", \"memory-leak\", \"double-free\", "
           "\"use-after-free\", \"resource-leak\", \"div-by-zero\", "
           "\"null-deref\", \"bounds\", \"int-overflow\", "
           "\"sign-conversion\", \"alloc-size-overflow\", \"assumption\", "
           "\"contract\", \"policy\"]\n"
        << "}\n";
}

} // namespace codeskeptic
