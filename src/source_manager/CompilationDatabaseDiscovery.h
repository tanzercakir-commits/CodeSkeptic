#ifndef CODESKEPTIC_COMPILATION_DATABASE_DISCOVERY_H
#define CODESKEPTIC_COMPILATION_DATABASE_DISCOVERY_H

#include <clang/Tooling/CompilationDatabase.h>

#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

namespace codeskeptic {
class Config;

// An owned, already-loaded selection: the doctor and analyzer consume the
// same resolution, never a report followed by a second, different lookup.
struct CompilationDatabaseSelection {
    bool ready = false;
    bool synthetic = false;
    std::string reason;
    std::string selection;
    std::string source;
    std::string database;
    std::vector<std::string> candidates;
    std::vector<std::string> files;
    std::size_t entries = 0;
    std::size_t matching_entries = 0;
    std::unique_ptr<clang::tooling::CompilationDatabase> commands;
};

CompilationDatabaseSelection discoverCompilationDatabase(const Config& config);
void writeCompilationDoctor(const CompilationDatabaseSelection& result,
                            std::ostream& output);
} // namespace codeskeptic

#endif
