#include "engine/AssertGuards.h"

#include "engine/CfgCache.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <optional>

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/StmtCXX.h>
#include <clang/Analysis/CFG.h>
#include <clang/Basic/SourceLocation.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Lex/MacroArgs.h>
#include <clang/Lex/MacroInfo.h>
#include <clang/Lex/PPCallbacks.h>
#include <clang/Lex/Preprocessor.h>

namespace codeskeptic {

namespace {

// --- Configuration state -------------------------------------------

bool g_enabled = true;
std::set<std::string>& extraNames() {
    static std::set<std::string> names;
    return names;
}

// --- Per-TU record list --------------------------------------------
//
// One entry per assert-like macro expansion whose condition the
// preprocessor threw away. Deliberate global state, in the same spirit
// as CfgCache / FatalCalls: the analyzer is single-threaded per TU
// (SourceManager runs the whole pipeline on ONE worker thread), and
// the list is reset by installAssertRecovery at the start of every TU.
struct VanishedAssert {
    clang::SourceLocation begin;  // the macro name token
    clang::SourceLocation end;    // the closing paren
    std::vector<std::string> names;  // variables asserted non-null
};

std::vector<VanishedAssert>& records() {
    static std::vector<VanishedAssert> recs;
    return recs;
}

// Staleness fence. SourceLocations are only meaningful against the
// SourceManager that minted them. The MCP warm-AST path never calls
// installAssertRecovery, so without this fence a cached AST could be
// analyzed against another TU's leftover records — locations that
// resolve to arbitrary offsets in an unrelated file. Recording the
// owning SourceManager makes that structurally impossible: a mismatch
// means "no records", not "wrong records".
const clang::SourceManager* g_recordOwner = nullptr;

// --- Token shape parsing -------------------------------------------

bool isIdentifierSpelling(const std::string& s) {
    if (s.empty()) return false;
    if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_'))
        return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
            return false;
    return true;
}

// The spellings that mean "the null pointer" in the shapes we accept.
// `0` is here because C code writes `p != 0`; the subject side is
// still required to be a plain identifier, so this cannot swallow an
// integer comparison into the pointer domain (the resolver rejects
// non-pointer variables anyway).
bool isNullSpelling(const std::string& s) {
    return s == "NULL" || s == "nullptr" || s == "0" || s == "0L" ||
           s == "0UL" || s == "0u" || s == "0U" || s == "__null";
}

// Matches a NULL POINTER CONSTANT starting at toks[i], returning the
// index just past it. The grammar is deliberately tiny:
//
//     nullconst := NULLSPELL
//                | '(' nullconst ')'                 // ((void*)0)
//                | '(' typename+ '*'+ ')' nullconst  // (void*)0
//
// The cast form is not a nicety: `NULL` is itself a macro, and code
// that spells it out — or that a header already expanded — arrives
// here as `( void * ) 0`. Every accepted form is a null pointer
// constant by the language rules, so collapsing it to one NULL token
// adds no assumption. A cast of anything OTHER than a null constant
// (`(void*)q`) does not match and rejects the record, as it must.
std::optional<size_t> matchNullConstant(const std::vector<std::string>& toks,
                                        size_t i, unsigned depth) {
    if (depth > 4 || i >= toks.size()) return std::nullopt;
    if (isNullSpelling(toks[i])) return i + 1;
    if (toks[i] != "(") return std::nullopt;

    size_t j = i + 1;
    unsigned nest = 1;
    for (; j < toks.size(); ++j) {
        if (toks[j] == "(") ++nest;
        else if (toks[j] == ")" && --nest == 0) break;
    }
    if (j >= toks.size()) return std::nullopt;  // unbalanced

    // Cast form: only type-name words, then one or more `*`.
    bool sawStar = false, castOk = (j > i + 1);
    for (size_t k = i + 1; k < j && castOk; ++k) {
        if (toks[k] == "*") { sawStar = true; continue; }
        if (sawStar || !isIdentifierSpelling(toks[k])) castOk = false;
    }
    if (castOk && sawStar)
        if (auto after = matchNullConstant(toks, j + 1, depth + 1))
            return after;

    // Parenthesized form.
    if (auto inner = matchNullConstant(toks, i + 1, depth + 1))
        if (*inner == j) return j + 1;

    return std::nullopt;
}

// One conjunct -> the variable it proves non-null, or nullopt when the
// shape is out of v1 scope. The token filter is a WHITELIST: anything
// that is not `!=`, an identifier, or part of a null constant drops
// this conjunct. `->`, `*`, `!`, `?`, calls and arithmetic all land
// here and are dropped by construction rather than by an ever-growing
// list of exclusions.
std::optional<std::string> parseConjunct(const std::vector<std::string>& raw) {
    std::vector<std::string> t;
    for (size_t i = 0; i < raw.size();) {
        if (auto next = matchNullConstant(raw, i, 0)) {
            t.push_back("NULL");
            i = *next;
            continue;
        }
        if (raw[i] != "!=" && !isIdentifierSpelling(raw[i]))
            return std::nullopt;
        t.push_back(raw[i]);
        ++i;
    }
    if (t.size() == 1)
        return t[0] == "NULL" ? std::nullopt : std::optional<std::string>(t[0]);
    if (t.size() == 3 && t[1] == "!=") {
        if (t[0] != "NULL" && t[2] == "NULL") return t[0];
        if (t[2] != "NULL" && t[0] == "NULL") return t[2];
        // `a != b` between two variables says nothing about either
        // one's nullness.
    }
    return std::nullopt;
}

// Splits on TOP-LEVEL `&&`. `A && B` entails both conjuncts, so an
// unparseable conjunct may be dropped on its own — `assert(p != NULL
// && n > 0)` still proves p, which matters because that is how real
// code is written. But the entailment only holds with no `||` ABOVE
// the conjunction: `p || q && r` does not prove r. A top-level `||`
// therefore vetoes the whole record; one nested inside parentheses is
// harmless, because the conjunct containing it is unparseable anyway.
std::optional<std::vector<std::vector<std::string>>>
splitConjuncts(const std::vector<std::string>& toks) {
    std::vector<std::vector<std::string>> parts(1);
    int depth = 0;
    for (const auto& t : toks) {
        if (t == "(") {
            ++depth;
        } else if (t == ")") {
            if (--depth < 0) return std::nullopt;
        } else if (depth == 0 && t == "||") {
            return std::nullopt;
        } else if (depth == 0 && t == "&&") {
            parts.emplace_back();
            continue;
        }
        parts.back().push_back(t);
    }
    if (depth != 0) return std::nullopt;
    return parts;
}

// Parses the argument token spellings into the set of variable names
// the assertion proves non-null. Returns nullopt when nothing in the
// shape is usable — the caller then records nothing at all.
std::optional<std::vector<std::string>>
parseAssertShape(const std::vector<std::string>& toks) {
    if (toks.empty()) return std::nullopt;
    auto parts = splitConjuncts(toks);
    if (!parts) return std::nullopt;

    std::vector<std::string> out;
    for (const auto& part : *parts)
        if (auto name = parseConjunct(part)) out.push_back(*name);
    if (out.empty()) return std::nullopt;
    return out;
}

// --- The preprocessor hook ------------------------------------------

// True when the macro body never mentions its first parameter, i.e.
// the expansion DISCARDS the condition. This is the gate that
// separates "compiled out" from "live": a live assert expands to code
// containing the condition, the AST keeps it, and the ordinary CFG
// edge already narrows it (AR.1). Only the discarded ones are
// invisible, and only those are recovered here.
bool bodyDiscardsCondition(const clang::MacroInfo* mi) {
    if (!mi || !mi->isFunctionLike()) return false;
    // EXACTLY one parameter, never variadic. A multi-argument assert
    // states a RELATION between its arguments, and argument 0 read on
    // its own is not that relation — it is a different claim, often the
    // OPPOSITE one. `ASSERT_EQ(p, NULL)` asserts that p IS null; taking
    // `p` alone as the condition would record "p is non-null" and
    // silently retire the true finding. Same for gtest's ASSERT_LT(p,q)
    // and message-first shapes like ASSERT_MSG(msg, cond). Only the
    // one-argument form has an argument that IS the condition.
    if (mi->getNumParams() != 1 || mi->isVariadic()) return false;
    const clang::IdentifierInfo* param = *mi->param_begin();
    if (!param) return false;
    for (const clang::Token& t : mi->tokens())
        if (t.getIdentifierInfo() == param) return false;
    return true;
}

class AssertPPCallbacks : public clang::PPCallbacks {
public:
    explicit AssertPPCallbacks(clang::Preprocessor& pp) : pp_(pp) {}

    void MacroExpands(const clang::Token& nameTok,
                      const clang::MacroDefinition& md,
                      clang::SourceRange range,
                      const clang::MacroArgs* args) override {
        if (!g_enabled || !args) return;

        const clang::IdentifierInfo* ii = nameTok.getIdentifierInfo();
        if (!ii) return;
        if (!isAssertMacroName(ii->getName().str())) return;

        if (!bodyDiscardsCondition(md.getMacroInfo())) return;

        // An assert nested inside another macro expansion has no
        // honest file position to attach to (v1 scope).
        if (range.getBegin().isInvalid() || range.getBegin().isMacroID() ||
            range.getEnd().isInvalid() || range.getEnd().isMacroID())
            return;

        const clang::Token* tok = args->getUnexpArgument(0);
        if (!tok) return;
        std::vector<std::string> spellings;
        for (; tok->isNot(clang::tok::eof); ++tok) {
            if (spellings.size() > 16) return;  // out of v1 shape range
            spellings.push_back(pp_.getSpelling(*tok));
        }

        auto names = parseAssertShape(spellings);
        if (!names) return;

        records().push_back({range.getBegin(), range.getEnd(),
                             std::move(*names)});
    }

private:
    clang::Preprocessor& pp_;
};

// --- Attachment ------------------------------------------------------

// Offset of a location within `fid`, or nullopt when it belongs to a
// different file (an included header, a macro from elsewhere).
std::optional<unsigned> offsetIn(const clang::SourceManager& sm,
                                 clang::FileID fid,
                                 clang::SourceLocation loc) {
    if (loc.isInvalid()) return std::nullopt;
    auto [f, off] = sm.getDecomposedExpansionLoc(loc);
    if (f != fid) return std::nullopt;
    return off;
}

// A jump into the middle of a block would let control reach a
// statement WITHOUT passing the assert. Labels, computed gotos and EH
// handlers are the ways that happens in C/C++ outside of switch (which
// is handled per-block below); a function containing any of them gives
// up all of its recovered guards.
bool hasJumpHazard(const clang::Stmt* s) {
    if (!s) return false;
    if (llvm::isa<clang::LabelStmt>(s) ||
        llvm::isa<clang::IndirectGotoStmt>(s) ||
        llvm::isa<clang::AddrLabelExpr>(s) ||
        llvm::isa<clang::CXXTryStmt>(s))
        return true;
    for (const clang::Stmt* c : s->children())
        if (hasJumpHazard(c)) return true;
    return false;
}

bool containsSwitchCase(const clang::Stmt* s) {
    if (!s) return false;
    if (llvm::isa<clang::SwitchCase>(s)) return true;
    for (const clang::Stmt* c : s->children())
        if (containsSwitchCase(c)) return true;
    return false;
}

// Innermost CompoundStmt whose source range contains `off`. DFS
// assigns on the way down, so the deepest container wins.
const clang::CompoundStmt* innermostCompound(const clang::Stmt* body,
                                             const clang::SourceManager& sm,
                                             clang::FileID fid, unsigned off) {
    const clang::CompoundStmt* best = nullptr;
    std::function<void(const clang::Stmt*)> walk = [&](const clang::Stmt* s) {
        if (!s) return;
        if (const auto* cs = llvm::dyn_cast<clang::CompoundStmt>(s)) {
            auto b = offsetIn(sm, fid, cs->getBeginLoc());
            auto e = offsetIn(sm, fid, cs->getEndLoc());
            if (b && e && *b <= off && off <= *e) best = cs;
        }
        for (const clang::Stmt* c : s->children()) walk(c);
    };
    walk(body);
    return best;
}

// Name -> declaration, for the function's parameters and locals. A
// name declared more than once (shadowing in a nested scope) is
// AMBIGUOUS at token level and maps to nullptr: the recovered token
// `p` cannot be resolved to one of two `p`s, so nothing is claimed.
std::unordered_map<std::string, const clang::VarDecl*>
collectVarsByName(const clang::FunctionDecl* func) {
    std::unordered_map<std::string, const clang::VarDecl*> byName;
    std::set<std::string> seen;
    auto add = [&](const clang::VarDecl* vd) {
        if (!vd || !vd->getIdentifier()) return;
        std::string n = vd->getName().str();
        if (!seen.insert(n).second) {
            byName[n] = nullptr;  // ambiguous
            return;
        }
        byName[n] = vd;
    };
    for (const clang::ParmVarDecl* p : func->parameters()) add(p);
    std::function<void(const clang::Stmt*)> walk = [&](const clang::Stmt* s) {
        if (!s) return;
        if (const auto* ds = llvm::dyn_cast<clang::DeclStmt>(s))
            for (const clang::Decl* d : ds->decls())
                add(llvm::dyn_cast<clang::VarDecl>(d));
        for (const clang::Stmt* c : s->children()) walk(c);
    };
    walk(func->getBody());
    return byName;
}

// The statement a guard fires on: the FIRST CFG element, in evaluation
// order, that lies inside `next`'s source range. Scanning each block in
// element order and then tie-breaking across blocks by source position
// picks the earliest-evaluated element rather than the
// lexically-outermost one — `int y = *p;` must narrow before `*p`, not
// before the DeclStmt that wraps it.
const clang::Stmt* firstElementIn(clang::CFG* cfg,
                                  const clang::SourceManager& sm,
                                  clang::FileID fid, unsigned lo,
                                  unsigned hi) {
    const clang::Stmt* best = nullptr;
    unsigned bestOff = 0;
    for (const clang::CFGBlock* block : *cfg) {
        if (!block) continue;
        for (const clang::CFGElement& elem : *block) {
            auto cfgStmt = elem.getAs<clang::CFGStmt>();
            if (!cfgStmt) continue;
            const clang::Stmt* stmt = cfgStmt->getStmt();
            if (!stmt) continue;
            auto off = offsetIn(sm, fid, stmt->getBeginLoc());
            if (!off || *off < lo || *off > hi) continue;
            if (!best || *off < bestOff) {
                best = stmt;
                bestOff = *off;
            }
            break;  // first in-range element of THIS block only
        }
    }
    return best;
}

bool isLoopStmt(const clang::Stmt* s) {
    return llvm::isa<clang::WhileStmt>(s) || llvm::isa<clang::DoStmt>(s) ||
           llvm::isa<clang::ForStmt>(s) ||
           llvm::isa<clang::CXXForRangeStmt>(s);
}

// Gate 4's placement question, asked of the object it is actually about.
//
// The guard never fires on `next`. It fires on the CFG element that
// firstElementIn() picks out of `next`, so testing the CLASS of `next`
// tests the wrong object: anything standing between the two — a
// `#pragma clang loop` (which wraps the loop in an AttributedStmt), a
// bare `{ ... }`, nested blocks — leaves the class check satisfied while
// the guard still lands on a loop condition. That reopened the exact
// false negative the rejection exists to prevent, one pair of braces
// apart, and the whole first battery passed over it because every case
// in it writes the loop directly after the assert.
//
// Returns whether `target` was located in the subtree at all — an
// unlocatable target is dropped, the standing rule of this gate — and
// reports the OUTERMOST loop the walk descended through to reach it
// (null when the path is loop-free). The outermost loop suffices for
// the write question below: everything between its entry and the
// target, inner loops included, sits inside its subtree.
bool locateTarget(const clang::Stmt* root, const clang::Stmt* target,
                  const clang::Stmt*& outermostLoop) {
    outermostLoop = nullptr;
    if (!root || !target) return false;
    bool reached = false;
    const clang::Stmt* found = nullptr;
    std::function<void(const clang::Stmt*, const clang::Stmt*)> walk =
        [&](const clang::Stmt* s, const clang::Stmt* outer) {
            if (!s || reached) return;
            // Evaluated BEFORE the identity test, so a target that IS
            // the loop counts as inside it: its own back edge re-fires
            // a guard attached to it.
            const clang::Stmt* now = outer;
            if (!now && isLoopStmt(s)) now = s;
            if (s == target) {
                reached = true;
                found = now;
                return;
            }
            for (const clang::Stmt* c : s->children()) walk(c, now);
        };
    walk(root, nullptr);
    outermostLoop = found;
    return reached;
}

// Can `stmt` change which object `vd` points to (or hand that ability
// to code we cannot see)? Asked of the loop a guard would sit inside:
// re-firing assert(p != NULL) on the back edge is harmless while p is
// the SAME p on every iteration, and unsound the moment the body can
// rebind it. Conservative on purpose — a maybe is a yes:
//
//   - plain or compound assignment with vd as the left-hand side
//     (p = q, p += n); a member store through vd (p->a = n) is a READ
//     of vd and does not count,
//   - ++/-- on vd (pointer arithmetic rebinds),
//   - &vd anywhere — the address escapes, anyone may store through it,
//   - vd bound to a non-const lvalue reference parameter: the C++
//     shape that rebinds with no & in the source. By-value and
//     const-ref uses cannot rebind and do not count. A call whose
//     parameter types cannot be seen is treated as able to rebind,
//   - vd appearing anywhere under an asm statement.
bool writesVar(const clang::Stmt* stmt, const clang::VarDecl* vd) {
    if (!stmt || !vd) return false;
    const clang::Decl* canon = vd->getCanonicalDecl();
    auto refersToVd = [&](const clang::Expr* e) {
        if (!e) return false;
        const auto* dre =
            llvm::dyn_cast<clang::DeclRefExpr>(e->IgnoreParenImpCasts());
        return dre && dre->getDecl()->getCanonicalDecl() == canon;
    };
    bool wrote = false;
    std::function<void(const clang::Stmt*)> walk = [&](const clang::Stmt* s) {
        if (!s || wrote) return;
        if (const auto* bo = llvm::dyn_cast<clang::BinaryOperator>(s)) {
            if (bo->isAssignmentOp() && refersToVd(bo->getLHS())) {
                wrote = true;
                return;
            }
        } else if (const auto* uo = llvm::dyn_cast<clang::UnaryOperator>(s)) {
            if ((uo->isIncrementDecrementOp() ||
                 uo->getOpcode() == clang::UO_AddrOf) &&
                refersToVd(uo->getSubExpr())) {
                wrote = true;
                return;
            }
        } else if (const auto* call = llvm::dyn_cast<clang::CallExpr>(s)) {
            const clang::FunctionDecl* fd = call->getDirectCallee();
            const clang::FunctionProtoType* proto = nullptr;
            if (!fd) {
                clang::QualType ct =
                    call->getCallee()->IgnoreParenImpCasts()->getType();
                if (ct->isPointerType()) ct = ct->getPointeeType();
                proto = ct->getAs<clang::FunctionProtoType>();
            }
            for (unsigned i = 0; i < call->getNumArgs(); ++i) {
                if (!refersToVd(call->getArg(i))) continue;
                clang::QualType pt;
                if (fd) {
                    if (i < fd->getNumParams())
                        pt = fd->getParamDecl(i)->getType();
                    else if (fd->isVariadic())
                        continue;  // variadic tail: by value, cannot rebind
                } else if (proto) {
                    if (i < proto->getNumParams())
                        pt = proto->getParamType(i);
                    else if (proto->isVariadic())
                        continue;
                }
                if (pt.isNull()) { wrote = true; return; }  // unseeable
                if (const auto* ref =
                        pt->getAs<clang::LValueReferenceType>()) {
                    if (!ref->getPointeeType().isConstQualified()) {
                        wrote = true;
                        return;
                    }
                }
            }
        } else if (llvm::isa<clang::AsmStmt>(s)) {
            bool mentions = false;
            std::function<void(const clang::Stmt*)> scan =
                [&](const clang::Stmt* t) {
                    if (!t || mentions) return;
                    if (const auto* e = llvm::dyn_cast<clang::Expr>(t))
                        if (refersToVd(e)) { mentions = true; return; }
                    for (const clang::Stmt* c : t->children()) scan(c);
                };
            scan(s);
            if (mentions) { wrote = true; return; }
        }
        for (const clang::Stmt* c : s->children()) walk(c);
    };
    walk(stmt);
    return wrote;
}

} // anonymous namespace

// --- Public configuration -------------------------------------------

void setAssertRecoveryEnabled(bool enabled) { g_enabled = enabled; }
bool assertRecoveryEnabled() { return g_enabled; }

void setExtraAssertMacros(std::set<std::string> names) {
    extraNames() = std::move(names);
}
const std::set<std::string>& extraAssertMacros() { return extraNames(); }

bool isAssertMacroName(const std::string& name) {
    // An explicitly declared name wins outright: there the USER supplies
    // the meaning, and the spelling stops being evidence about it.
    if (extraNames().count(name)) return true;
    std::string lower;
    lower.reserve(name.size());
    for (char c : name)
        lower.push_back(
            static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower.find("assert") == std::string::npos) return false;
    // The substring rule reads a NAME as evidence of a MEANING, so a
    // name that announces a NEGATIVE claim must never be read as the
    // positive one. cmocka's assert_null, Unity's TEST_ASSERT_NULL,
    // CUnit's CU_ASSERT_PTR_NULL and Criterion's cr_assert_null all
    // assert that the pointer IS null; believing one backwards
    // suppressed a *definitely-null* finding — inverting a proven fact,
    // not merely losing a maybe. Vetoed by spelling. This also refuses
    // assert_non_null and ASSERT_NOT_NULL, which really are non-null
    // assertions: guessing right on those is not worth guessing wrong
    // on their opposites, and --assert-macros recovers them by
    // declaration.
    for (const char* negative : {"null", "false", "zero", "not", "fail"})
        if (lower.find(negative) != std::string::npos) return false;
    return true;
}

void installAssertRecovery(clang::CompilerInstance& ci) {
    records().clear();
    g_recordOwner = &ci.getSourceManager();
    if (!g_enabled) return;
    clang::Preprocessor& pp = ci.getPreprocessor();
    pp.addPPCallbacks(std::make_unique<AssertPPCallbacks>(pp));
}

unsigned recordedVanishedAssertCount() {
    return static_cast<unsigned>(records().size());
}

// --- The cache -------------------------------------------------------

AssertGuardCache& AssertGuardCache::instance() {
    static AssertGuardCache cache;
    return cache;
}

void AssertGuardCache::clear() { cache_.clear(); }

const AssertGuardMap& AssertGuardCache::get(const clang::FunctionDecl* func,
                                            clang::ASTContext& ctx) {
    if (!g_enabled || !func || !func->hasBody()) return empty_;

    auto hit = cache_.find(func);
    if (hit != cache_.end()) return hit->second;

    AssertGuardMap map;
    // Build once regardless of outcome — an empty result is a cached
    // answer too, and most functions produce one.
    auto finish = [&]() -> const AssertGuardMap& {
        return cache_.emplace(func, std::move(map)).first->second;
    };

    const clang::SourceManager& sm = ctx.getSourceManager();
    if (records().empty() || g_recordOwner != &sm) return finish();

    const clang::Stmt* body = func->getBody();
    auto [fid, bodyLo] = sm.getDecomposedExpansionLoc(body->getBeginLoc());
    auto bodyHiOpt = offsetIn(sm, fid, body->getEndLoc());
    if (!bodyHiOpt) return finish();
    const unsigned bodyHi = *bodyHiOpt;

    // Cheap pre-filter: does any record even land in this function?
    bool any = false;
    for (const auto& r : records()) {
        auto off = offsetIn(sm, fid, r.begin);
        if (off && *off >= bodyLo && *off <= bodyHi) { any = true; break; }
    }
    if (!any) return finish();

    if (hasJumpHazard(body)) return finish();

    clang::CFG* cfg = CfgCache::instance().get(func, ctx);
    if (!cfg) return finish();

    auto byName = collectVarsByName(func);

    for (const auto& rec : records()) {
        auto beginOff = offsetIn(sm, fid, rec.begin);
        auto endOff = offsetIn(sm, fid, rec.end);
        if (!beginOff || !endOff) continue;
        if (*beginOff < bodyLo || *beginOff > bodyHi) continue;

        const clang::CompoundStmt* scope =
            innermostCompound(body, sm, fid, *beginOff);
        if (!scope) continue;

        // A `case` label inside this very block would let control land
        // between the assert and its target. (Nested blocks are fine —
        // they are entered as a whole.)
        if (containsSwitchCase(scope)) continue;

        // Find the next real statement of the block. The macro must sit
        // in the GAP BETWEEN two children: every child is required to
        // be entirely before the expansion, entirely after it, or
        // entirely INSIDE it (the macro's own leftover statement). A
        // child that overlaps the expansion while reaching outside it
        // STRADDLES: the assert vanished from inside a larger statement
        // — `while (c) DEBUGASSERT(p);`, `if (c) assert(p);` — where it
        // may execute zero times and dominates nothing.
        //
        // The comparison has to be written this way round. A location
        // inside a macro body decomposes to the EXPANSION POINT, so the
        // enclosing IfStmt's end lands at the macro's own begin offset,
        // not past its end: testing `childEnd > macroEnd` would silently
        // never fire and every braceless guard would be believed.
        const clang::Stmt* next = nullptr;
        bool straddled = false;
        for (const clang::Stmt* child : scope->body()) {
            auto cb = offsetIn(sm, fid, child->getBeginLoc());
            auto ce = offsetIn(sm, fid, child->getEndLoc());
            if (!cb || !ce) { straddled = true; break; }  // unplaceable
            if (*ce < *beginOff) continue;                // entirely before
            if (*cb > *endOff) {
                // An empty statement is the macro's own leftover `;`
                // (or just noise); it has no CFG element to fire on.
                if (llvm::isa<clang::NullStmt>(child)) continue;
                next = child;
                break;
            }
            if (*cb < *beginOff || *ce > *endOff) { straddled = true; break; }
            // Fully contained: this is the expansion itself. Skip it.
        }
        if (straddled || !next) continue;

        auto nb = offsetIn(sm, fid, next->getBeginLoc());
        auto ne = offsetIn(sm, fid, next->getEndLoc());
        if (!nb || !ne) continue;

        const clang::Stmt* target = firstElementIn(cfg, sm, fid, *nb, *ne);
        if (!target) continue;

        // A target inside a LOOP is a question about the VARIABLE, not
        // about the loop. A guard is attached to a statement and
        // re-applied every time the engine transfers it; an assert
        // placed BEFORE a loop executed once, dominating loop ENTRY
        // only. Attaching it inside the loop makes the condition fire
        // again on the back edge — unsound when the body REBINDS the
        // pointer, because the second iteration's value never met the
        // assert:
        //
        //     assert(p != NULL);
        //     while (n-- > 0) { total += *p; p = malloc(4); }
        //
        // and perfectly sound when the body never writes it: the fact
        // re-fired is the same fact, true on every iteration. sqlite
        // measured the difference (convertToWithoutRowidTable): a
        // blanket loop rejection did not remove the pPk finding, it
        // MOVED it onto a deref sitting directly under the assert.
        //
        // This is asked of the TARGET, not of `next`: the guard lands
        // on the target, and a wrapper — a loop pragma, a bare block —
        // puts a non-loop statement in `next` while the target stays a
        // loop condition. And it is asked PER NAME below: one assert
        // can cover several variables, and the loop may write only one
        // of them.
        const clang::Stmt* enclosingLoop = nullptr;
        if (!locateTarget(next, target, enclosingLoop)) continue;

        for (const std::string& name : rec.names) {
            auto it = byName.find(name);
            if (it == byName.end() || !it->second) continue;  // unknown
            const clang::VarDecl* vd = it->second;
            if (!vd->getType()->isPointerType()) continue;   // v1: pointers
            if (enclosingLoop && writesVar(enclosingLoop, vd))
                continue;  // back edge would re-assert a rebound pointer
            map[target].push_back({AssertGuard::Kind::NonNull, vd});
        }
    }

    return finish();
}

} // namespace codeskeptic
