#include "rules/PolicyRule.h"

#include "contracts/ContractParser.h"
#include "contracts/Policy.h"
#include "core/Messages.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RawCommentList.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/SourceManager.h>

#include <map>
#include <set>
#include <string>

using namespace clang;
using namespace clang::ast_matchers;

namespace codeskeptic {

namespace {

struct FilePolicies {
    bool noAbsolutePaths = false;
    bool machineProposedOnly = false;  // activated only by cs:ai lines
};

} // anonymous namespace

void PolicyRule::check(ASTContext& ctx, DiagnosticList& results) {
    const SourceManager& sm = ctx.getSourceManager();

    // Files worth inspecting: the main file plus every file declaring
    // a function (headers). System headers never participate.
    std::set<FileID> files = {sm.getMainFileID()};
    for (const auto& m :
         match(functionDecl().bind("f"), ctx)) {
        const auto* func = m.getNodeAs<FunctionDecl>("f");
        if (!func) continue;
        SourceLocation loc = sm.getExpansionLoc(func->getLocation());
        if (loc.isValid() && !sm.isInSystemHeader(loc))
            files.insert(sm.getFileID(loc));
    }

    // Per-file activation from `cs:policy` comment lines. Any such
    // line anywhere in a file scopes the policy to that whole file
    // (§2.3 — file comments are the local addition mechanism; the
    // project-wide mechanism is the idiom profile).
    std::map<FileID, FilePolicies> active;
    const bool profileActive =
        profilePolicies().count("no-absolute-paths") > 0;

    for (FileID fid : files) {
        const auto* comments = ctx.Comments.getCommentsInFile(fid);
        if (!comments) continue;
        for (const auto& [offset, comment] : *comments) {
            const std::string text = comment->getRawText(sm).str();
            if (text.find("cs:") == std::string::npos) continue;
            ParsedContracts parsed = parseContractComment(text);
            for (const auto& clause : parsed.clauses) {
                if (clause.kind != ContractClauseKind::Policy) continue;
                const unsigned commentLine =
                    sm.getSpellingLineNumber(comment->getBeginLoc());
                if (!isKnownPolicy(clause.policyName)) {
                    Diagnostic diag;
                    diag.file = sm.getFilename(comment->getBeginLoc()).str();
                    diag.line = commentLine +
                                (clause.line > 0 ? clause.line - 1 : 0);
                    diag.column = 1;
                    diag.rule_id = "contract-syntax";
                    diag.severity = Severity::Error;
                    diag.message =
                        msg(MsgId::PolicyUnknownName, clause.policyName);
                    results.push_back(std::move(diag));
                    continue;
                }
                if (clause.policyName == "no-absolute-paths") {
                    auto& fp = active[fid];
                    if (fp.noAbsolutePaths)
                        fp.machineProposedOnly =
                            fp.machineProposedOnly && clause.machineProposed;
                    else
                        fp.machineProposedOnly = clause.machineProposed;
                    fp.noAbsolutePaths = true;
                }
            }
        }
    }

    if (!profileActive && active.empty()) return;

    // The pattern scan: string literals that look like hard-coded
    // absolute paths. Literals born from macro expansions are skipped
    // (__FILE__, assert paths) — a deliberate FN direction, noted in
    // the tests.
    for (const auto& m :
         match(stringLiteral().bind("lit"), ctx)) {
        const auto* lit = m.getNodeAs<StringLiteral>("lit");
        if (!lit || !(lit->isOrdinary() || lit->isUTF8())) continue;
        SourceLocation begin = lit->getBeginLoc();
        if (begin.isInvalid() || begin.isMacroID()) continue;
        SourceLocation loc = sm.getExpansionLoc(begin);
        if (sm.isInSystemHeader(loc)) continue;

        FileID fid = sm.getFileID(loc);
        bool fileActive = false;
        bool aiOnly = false;
        auto it = active.find(fid);
        if (it != active.end() && it->second.noAbsolutePaths) {
            fileActive = true;
            aiOnly = it->second.machineProposedOnly;
        }
        if (!profileActive && !fileActive) continue;

        const std::string text = lit->getString().str();
        if (!looksLikeAbsolutePath(text)) continue;

        std::string shown = text.size() > 48
                                ? text.substr(0, 45) + "..."
                                : text;
        Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = sm.getSpellingLineNumber(loc);
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "policy";
        // Profile activation or a bare cs:policy line is declared
        // intent -> error; activation only via cs:ai -> warning.
        diag.severity = (!profileActive && aiOnly) ? Severity::Warning
                                                   : Severity::Error;
        diag.message = msg(MsgId::PolicyAbsolutePath, "\"" + shown + "\"");
        results.push_back(std::move(diag));
    }
}

} // namespace codeskeptic
