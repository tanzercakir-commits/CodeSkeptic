// Corpus harness only: materialize LLVM's historical missing-command recipes
// as explicit inputs. Product discovery remains strict and never interpolates.
#include "config/Config.h"
#include "source_manager/CompilationDatabaseDiscovery.h"

#include <clang/Tooling/CompilationDatabase.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>

namespace {
namespace fs = std::filesystem;

bool inside(const fs::path& path, const fs::path& root) {
    const auto relative = path.lexically_relative(root);
    return !relative.empty() && *relative.begin() != "..";
}

llvm::json::Object row(const clang::tooling::CompileCommand& command) {
    // Response expansion can introduce non-UTF8 bytes even when the original
    // JSON and source identity are valid. LLVM JSON asserts on such strings.
    for (const auto* value : {&command.Directory, &command.Filename,
                              &command.Output, &command.Heuristic}) {
        if (!llvm::json::isUTF8(*value))
            throw std::runtime_error("expanded compilation command is not UTF-8");
    }
    llvm::json::Array arguments;
    for (const auto& argument : command.CommandLine) {
        if (!llvm::json::isUTF8(argument))
            throw std::runtime_error("expanded compilation argument is not UTF-8");
        arguments.push_back(argument);
    }
    return llvm::json::Object{{"directory", command.Directory}, {"file", command.Filename},
                              {"arguments", std::move(arguments)}, {"output", command.Output}};
}

void write(const fs::path& path, const std::string& bytes) {
    std::ofstream stream(path, std::ios::binary);
    stream.exceptions(std::ios::badbit | std::ios::failbit);
    stream << bytes << '\n';
    stream.close();
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: codeskeptic_corpus_inputs <original-db> <source-root> "
                     "<original-anchor-source> <new-output-directory>\n";
        return 2;
    }
    try {
        const auto database = fs::canonical(argv[1]);
        const auto root = fs::canonical(argv[2]);
        const auto anchor = fs::canonical(argv[3]);
        const auto output = fs::weakly_canonical(fs::absolute(argv[4]));
        for (const auto* path : {&database, &root, &anchor, &output}) {
            if (!llvm::json::isUTF8(path->string()))
                throw std::runtime_error("corpus path identity is not UTF-8");
        }
        if (!fs::is_directory(root) || !inside(anchor, root) ||
            inside(database, root) || inside(output, root) || fs::exists(output))
            throw std::runtime_error("corpus requires an in-tree anchor, external build/output and fresh output");

        codeskeptic::Config config;
        config.setSourcePath(anchor.string());
        config.setBuildPath(database.string());
        auto selected = codeskeptic::discoverCompilationDatabase(config);
        if (!selected.ready || selected.synthetic || !selected.commands)
            throw std::runtime_error("original database rejected: " + selected.reason);

        // Discovery validates every original row and freezes response expansion,
        // not just the anchor's commands. Use that same owned snapshot below;
        // never reread the original database to obtain an unchecked proxy.
        llvm::json::Array originals;
        for (const auto& command : selected.commands->getAllCompileCommands()) {
            if (!fs::is_directory(command.Directory))
                throw std::runtime_error("original command working directory is missing: " + command.Directory);
            originals.push_back(row(command));
        }
        auto recipes = clang::tooling::inferMissingCompileCommands(std::move(selected.commands));

        // Match directory discovery's full source surface. The original build
        // and prepared output are required outside it; no generated CMake TUs
        // enter the manifest. Deliberately broken corpus fixtures remain in it.
        std::set<std::string> files;
        for (auto it = fs::recursive_directory_iterator(root);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_directory() && it->path().filename() == ".git") {
                it.disable_recursion_pending();
                continue;
            }
            const auto ext = it->path().extension().string();
            if (it->is_regular_file() &&
                (ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx")) {
                const auto name = fs::canonical(it->path()).string();
                if (!llvm::json::isUTF8(name))
                    throw std::runtime_error("corpus source identity is not UTF-8");
                files.insert(name);
            }
        }
        if (files.empty()) throw std::runtime_error("corpus source manifest is empty");
        llvm::json::Array prepared, provenance;
        std::size_t inferred = 0;
        for (const auto& file : files) {
            const auto commands = recipes->getCompileCommands(file);
            if (commands.empty()) throw std::runtime_error("no LLVM recipe for corpus source: " + file);
            llvm::json::Array variants;
            for (const auto& command : commands) {
                prepared.push_back(row(command));
                auto evidence = row(command);
                evidence["heuristic"] = command.Heuristic;
                variants.push_back(std::move(evidence));
            }
            const bool isInferred = !commands.front().Heuristic.empty();
            inferred += isInferred;
            provenance.push_back(llvm::json::Object{
                {"file", file}, {"inferred", isInferred}, {"commands", std::move(variants)}});
        }
        const auto count = prepared.size();
        const auto databaseBytes = llvm::formatv("{0:2}", llvm::json::Value(std::move(prepared))).str();
        const auto provenanceBytes = llvm::formatv("{0:2}", llvm::json::Value(llvm::json::Object{
            {"schema", "codeskeptic-corpus-inputs/v1"}, {"llvm_version", LLVM_VERSION_STRING},
            {"original_database", selected.database}, {"source_root", root.string()},
            {"original_commands", std::move(originals)}, {"sources", std::move(provenance)}})).str();

        // No output is published until all originals and all requested recipes
        // are available. Fresh directories avoid confusing stale evidence with
        // the current run; failure always prevents the harness from scanning.
        if (!fs::create_directory(output)) throw std::runtime_error("cannot create fresh corpus output");
        write(output / "provenance.json", provenanceBytes);
        write(output / "compile_commands.json", databaseBytes);
        std::cout << "CORPUS_INPUTS sources=" << files.size() << " commands=" << count
                  << " inferred_sources=" << inferred << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[corpus-inputs] " << error.what() << '\n';
        return 2;
    }
}
