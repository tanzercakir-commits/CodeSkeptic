#include "engine/IntervalEval.h"

#include "engine/AllocFunctions.h"
#include "engine/CallRefArgs.h"
#include "engine/ConditionWalk.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/Type.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

using namespace clang;

namespace codeskeptic {

namespace {

// Bitwise AND with a non-negative mask: `x & c` (c >= 0) has every bit a
// subset of c's bits, so the result is in [0, c] for ANY x (the sign bit
// is masked off -> non-negative). Mask may be on either side. When both
// operands are known non-negative finite intervals with no constant, the
// result is bounded by the smaller upper bound. Sound over-approximation;
// unknown -> top.
Interval bitAnd(const Interval& l, const Interval& r) {
    int64_t c;
    if (r.isSingleton(&c) && c >= 0) return Interval::range(0, c);
    if (l.isSingleton(&c) && c >= 0) return Interval::range(0, c);
    const bool lNonNeg = !l.loIsInf() && l.lo() >= 0;
    const bool rNonNeg = !r.loIsInf() && r.lo() >= 0;
    if (lNonNeg && rNonNeg && !l.hiIsInf() && !r.hiIsInf())
        return Interval::range(0, std::min(l.hi(), r.hi()));
    if (lNonNeg && !l.hiIsInf()) return Interval::range(0, l.hi());
    if (rNonNeg && !r.hiIsInf()) return Interval::range(0, r.hi());
    return Interval::top();
}

// Remainder by a constant divisor: C truncates toward zero, so `x % c`
// has the sign of x and magnitude < |c|. Result in [-(|c|-1), |c|-1],
// tightened to [0, |c|-1] when x is known non-negative. Divisor unknown
// or zero -> top (a zero divisor is UB; the div-by-zero rule owns it).
Interval intRem(const Interval& l, const Interval& r) {
    int64_t d;
    if (!r.isSingleton(&d) || d == 0) return Interval::top();
    // |d| - 1, guarding the INT64_MIN abs-overflow (|INT64_MIN|-1 fits).
    const int64_t bound =
        d == INT64_MIN ? INT64_MAX : (d < 0 ? -d : d) - 1;
    if (!l.loIsInf() && l.lo() >= 0) return Interval::range(0, bound);
    return Interval::range(-bound, bound);
}

// The value range of an integer type, as a finite interval — [INT_MIN,
// INT_MAX] for a 32-bit signed int, [0, UINT_MAX] for 32-bit unsigned,
// and so on. Finite (not top()), which is the point: a full-but-BOUNDED
// range multiplies into a provably-overflowing product, whereas top()
// collapses any product straight back to top() and reports nothing.
// A width outside (0, 64] or a 64-bit unsigned (whose top does not fit
// int64) yields nullopt.
std::optional<Interval> intTypeRange(QualType t, const ASTContext& ctx) {
    if (t.isNull() || !t->isIntegerType()) return std::nullopt;
    const unsigned width = ctx.getIntWidth(t);
    if (width == 0 || width > 64) return std::nullopt;
    if (t->isSignedIntegerOrEnumerationType()) {
        const int64_t hi =
            width == 64 ? INT64_MAX : (int64_t(1) << (width - 1)) - 1;
        const int64_t lo =
            width == 64 ? INT64_MIN : -(int64_t(1) << (width - 1));
        return Interval::range(lo, hi);
    }
    if (width >= 64) return std::nullopt;  // uint64 max exceeds int64
    return Interval::range(0, (int64_t(1) << width) - 1);
}

// An intrinsic untrusted-integer source: a library call that parses
// external text (the atoi/strtol family). The callee's contract puts NO
// bound on the value beyond its return type — `atoi("2000000000")` is a
// valid full-magnitude int — so the sound-and-useful model is the whole
// representable range of the return type. This is an INTRINSIC signal (a
// property of the callee, never of the caller's data), the same
// discipline as the unchecked-allocation (malloc) and div-by-zero
// (atoi/strtol) recall rules: precision holds because a caller who
// validated the value re-narrows the range on the guard's own edge.
//
// rand()/random() are DELIBERATELY EXCLUDED here even though the
// div-by-zero rule treats them as untrusted ZERO sources. Their range is
// [0, RAND_MAX], and RAND_MAX is implementation-defined (as small as
// 32767); over-approximating it to the full int range would report a
// false overflow on `rand() * k` that cannot occur on a small-RAND_MAX
// target. The exclusion costs no measured recall — Juliet's rand family
// reaches the multiply through the RAND32() bit-shuffle macro, which the
// interval evaluator cannot fold regardless (a documented known FN).
bool isUntrustedIntSource(const CallExpr* call) {
    const FunctionDecl* fd = call->getDirectCallee();
    if (!fd) return false;
    const IdentifierInfo* id = fd->getIdentifier();
    if (!id) return false;
    const llvm::StringRef n = id->getName();
    static constexpr llvm::StringRef kNames[] = {
        "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    };
    for (const auto& k : kNames)
        if (n == k) return true;
    // Project-declared untrusted-length sources (--untrusted-int-sources):
    // empty by default, so this is a no-op unless a project opts in.
    const auto& extra = untrustedIntSourceNames();
    if (!extra.empty() && extra.count(n.str())) return true;
    return false;
}

const VarDecl* asIntVar(const Expr* e) {
    if (!e) return nullptr;
    e = e->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e))
        if (const auto* vd = dyn_cast<VarDecl>(ref->getDecl()))
            if (vd->getType()->isIntegerType()) return vd;
    return nullptr;
}

// A formatted-input call that fills its arguments from external text.
// scanf/fscanf/sscanf and their v-forms deliver an untrusted value the
// same way atoi does, only through an output POINTER (`&n`) instead of a
// return. Same intrinsic-source discipline as isUntrustedIntSource.
bool isScanfFamily(const CallExpr* call) {
    const FunctionDecl* fd = call->getDirectCallee();
    if (!fd) return false;
    const IdentifierInfo* id = fd->getIdentifier();
    if (!id) return false;
    const llvm::StringRef n = id->getName();
    return n == "scanf" || n == "fscanf" || n == "sscanf" || n == "vscanf" ||
           n == "vfscanf" || n == "vsscanf";
}

// Index of the format-string argument for a scanf-family callee:
// scanf(fmt, ...) -> 0; fscanf(f, fmt, ...) / sscanf(s, fmt, ...) -> 1.
unsigned scanfFormatArgIndex(const CallExpr* call) {
    const llvm::StringRef n =
        call->getDirectCallee()->getIdentifier()->getName();
    return (n == "scanf" || n == "vscanf") ? 0 : 1;
}

// One conversion specification of a scanf format string, as far as the
// interval model cares: assignment suppression (`%*d` consumes input
// but NO argument — pairing must skip none), the maximum field width,
// and the conversion character (length modifiers hh/h/l/ll/j/z/t/L are
// skipped — the ARGUMENT's declared type already carries the width).
struct ScanfConv {
    bool suppressed = false;
    uint64_t width = 0;  // 0 = no explicit field width
    char conv = 0;
};

// Parse the conversions of a scanf format literal, in argument order.
// `%%` consumes no argument and is not emitted. A scanset (`%[...]`)
// is parsed to its closing bracket (leading `]` is literal per C11).
// Returns false for a malformed format (trailing '%', unterminated
// scanset) — the caller then falls back to the widthless model.
bool parseScanfFormat(llvm::StringRef fmt, std::vector<ScanfConv>& out) {
    for (size_t i = 0; i < fmt.size(); ++i) {
        if (fmt[i] != '%') continue;
        if (++i >= fmt.size()) return false;
        if (fmt[i] == '%') continue;  // literal %
        ScanfConv c;
        if (fmt[i] == '*') {
            c.suppressed = true;
            if (++i >= fmt.size()) return false;
        }
        while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9') {
            c.width = c.width * 10 + (uint64_t)(fmt[i] - '0');
            if (c.width > 1000000) c.width = 1000000;  // clamp, keep sane
            ++i;
        }
        while (i < fmt.size() &&
               (fmt[i] == 'h' || fmt[i] == 'l' || fmt[i] == 'j' ||
                fmt[i] == 'z' || fmt[i] == 't' || fmt[i] == 'L' ||
                fmt[i] == 'q'))
            ++i;
        if (i >= fmt.size()) return false;
        c.conv = fmt[i];
        if (c.conv == '[') {
            size_t j = i + 1;
            if (j < fmt.size() && fmt[j] == '^') ++j;
            if (j < fmt.size() && fmt[j] == ']') ++j;  // literal ] first
            while (j < fmt.size() && fmt[j] != ']') ++j;
            if (j >= fmt.size()) return false;
            i = j;
        }
        out.push_back(c);
    }
    return true;
}

// base^exp as int64 with an overflow ceiling; nullopt past the ceiling
// (the caller then uses the plain type range).
std::optional<int64_t> powCapped(int64_t base, uint64_t exp) {
    int64_t r = 1;
    for (uint64_t k = 0; k < exp; ++k) {
        if (r > INT64_MAX / base) return std::nullopt;
        r *= base;
    }
    return r;
}

// The value range an EXPLICIT FIELD WIDTH imposes on a numeric scanf
// conversion — the piece the untrusted-source model was missing (the
// rtp2httpd timezone FP family, 2026-07-22): `%2d` reads at most two
// characters, so the parsed value is in [-9, 99] no matter what the
// input holds; treating it as a full-range int manufactured a finite
// "overflow witness" out of a bound that cannot occur. A sign, when
// the conversion accepts one, consumes one of the width characters —
// hence the asymmetric negative bound (10^(w-1) - 1). `%i` accepts
// hex with a 0x prefix, so its magnitude ceiling is 16^w (covers the
// decimal and octal cases too); conservative but finite and small.
// No width, or a width too large for int64 -> nullopt (the existing
// full-type-range model applies).
std::optional<Interval> scanfWidthBound(const ScanfConv& c) {
    if (c.width == 0) return std::nullopt;
    const uint64_t w = c.width;
    switch (c.conv) {
        case 'd': case 'u': {
            auto hi = powCapped(10, w);
            if (!hi) return std::nullopt;
            if (c.conv == 'u') return Interval::range(0, *hi - 1);
            auto mag = powCapped(10, w - 1);
            if (!mag) return std::nullopt;
            return Interval::range(-(*mag - 1), *hi - 1);
        }
        case 'x': case 'X': {
            auto hi = powCapped(16, w);
            if (!hi) return std::nullopt;
            return Interval::range(0, *hi - 1);
        }
        case 'o': {
            auto hi = powCapped(8, w);
            if (!hi) return std::nullopt;
            return Interval::range(0, *hi - 1);
        }
        case 'i': {
            auto hi = powCapped(16, w);
            auto mag = powCapped(16, w > 0 ? w - 1 : 0);
            if (!hi || !mag) return std::nullopt;
            return Interval::range(-(*mag - 1), *hi - 1);
        }
        default:
            return std::nullopt;
    }
}

// Whether a conversion character consumes a pointer argument that the
// numeric-interval model should seed at all. %n yields the number of
// characters consumed so far — non-negative by definition, unbounded
// above (input-length dependent).
bool isNumericScanfConv(char conv) {
    return conv == 'd' || conv == 'i' || conv == 'u' || conv == 'o' ||
           conv == 'x' || conv == 'X' || conv == 'n';
}

// The format string literal of a scanf-family call, if it is one.
const clang::StringLiteral* scanfFormatLiteral(const CallExpr* call) {
    const unsigned idx = scanfFormatArgIndex(call);
    if (idx >= call->getNumArgs()) return nullptr;
    const Expr* fmt = call->getArg(idx)->IgnoreParenImpCasts();
    const auto* lit = dyn_cast<clang::StringLiteral>(fmt);
    if (!lit || lit->getCharByteWidth() != 1) return nullptr;
    return lit;
}

// `&x` where x is a tracked integer variable — the shape a scanf output
// argument takes. Returns x, or null.
const VarDecl* addrOfIntVar(const Expr* e) {
    if (!e) return nullptr;
    e = e->IgnoreParenImpCasts();
    if (const auto* u = dyn_cast<UnaryOperator>(e))
        if (u->getOpcode() == UO_AddrOf)
            return asIntVar(u->getSubExpr());
    return nullptr;
}

std::optional<int64_t> constInt(const Expr* e) {
    if (!e) return std::nullopt;
    e = e->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(e)) {
        // isSignedIntN(64), not significantBits>63: INT64_MAX needs 64
        // significant bits as a signed quantity yet fits int64 exactly.
        // Interval arithmetic overflow-guards itself (-> top()), so
        // boundary constants are safe to model (Juliet int64_t_max_*).
        if (!lit->getValue().isSignedIntN(64)) return std::nullopt;
        return lit->getValue().getSExtValue();
    }
    if (const auto* u = dyn_cast<UnaryOperator>(e))
        if (u->getOpcode() == UO_Minus)
            if (auto v = constInt(u->getSubExpr())) return -*v;
    return std::nullopt;
}

// Fold `e` to a signed 64-bit constant. The literal path (constInt) is
// tried first — it needs no context and covers the common case. With a
// context, Clang's own constant evaluator folds full constant
// expressions: `INT_MAX/2`, `SIZE_MAX-1`, `1 << 30`, a sizeof, an enum
// constant. Only genuinely constant expressions fold — anything with a
// runtime operand (`abs(x)`, `sqrt(MAX)`) fails and yields nullopt, so
// no unsound refinement can slip in. Values outside int64 are dropped.
std::optional<int64_t> foldConstInt(const Expr* e, const ASTContext* ctx) {
    if (auto v = constInt(e)) return v;
    if (!ctx || !e) return std::nullopt;
    if (e->isValueDependent() || e->isTypeDependent()) return std::nullopt;
    if (!e->getType()->isIntegralOrEnumerationType()) return std::nullopt;
    clang::Expr::EvalResult res;
    if (!e->EvaluateAsInt(res, *ctx) || !res.Val.isInt())
        return std::nullopt;
    const llvm::APSInt& ap = res.Val.getInt();
    if (ap.isSigned()) {
        if (!ap.isSignedIntN(64)) return std::nullopt;  // see constInt
        return ap.getSExtValue();
    }
    if (ap.getActiveBits() > 63) return std::nullopt;
    return static_cast<int64_t>(ap.getZExtValue());
}

// Negation of a comparison operator (for the false edge).
BinaryOperatorKind negateCmp(BinaryOperatorKind op) {
    switch (op) {
        case BO_LT: return BO_GE;
        case BO_LE: return BO_GT;
        case BO_GT: return BO_LE;
        case BO_GE: return BO_LT;
        case BO_EQ: return BO_NE;
        case BO_NE: return BO_EQ;
        default:    return op;
    }
}

Interval constrainBy(const Interval& iv, BinaryOperatorKind op, int64_t c) {
    switch (op) {
        case BO_LT: return iv.constrainLt(c);
        case BO_LE: return iv.constrainLe(c);
        case BO_GT: return iv.constrainGt(c);
        case BO_GE: return iv.constrainGe(c);
        case BO_EQ: return iv.constrainEq(c);
        case BO_NE: return iv.constrainNe(c);
        default:    return iv;
    }
}

} // namespace

std::optional<int64_t> boundedTypeSizeInChars(ASTContext& ctx,
                                              QualType type) {
    if (type.isNull()) return std::nullopt;
    // getTypeInfo's stack usage scales with type NESTING DEPTH (array
    // element / field / base chains), not breadth, so the budget is a
    // depth cap plus a total-node runaway guard. 128 is far beyond any
    // hand-written type and far below what threatens even a default
    // stack; wide (but shallow) generated structs stay well inside the
    // node budget because shared canonical types are visited once.
    constexpr unsigned kMaxDepth = 128;
    constexpr unsigned kMaxNodes = 4096;

    llvm::SmallVector<std::pair<const clang::Type*, unsigned>, 32> work;
    llvm::SmallPtrSet<const clang::Type*, 32> seen;
    work.push_back({type.getCanonicalType().getTypePtr(), 0});
    unsigned nodes = 0;

    auto push = [&](QualType t, unsigned depth) {
        const clang::Type* ty = t.getCanonicalType().getTypePtr();
        if (seen.insert(ty).second) work.push_back({ty, depth});
    };

    while (!work.empty()) {
        auto [ty, depth] = work.pop_back_val();
        if (!ty) return std::nullopt;
        if (depth > kMaxDepth || ++nodes > kMaxNodes) return std::nullopt;
        if (ty->isIncompleteType() || ty->isDependentType())
            return std::nullopt;

        if (const auto* arr = dyn_cast<clang::ConstantArrayType>(ty)) {
            push(arr->getElementType(), depth + 1);
        } else if (const auto* vec = dyn_cast<clang::VectorType>(ty)) {
            push(vec->getElementType(), depth + 1);
        } else if (const auto* cx = dyn_cast<clang::ComplexType>(ty)) {
            push(cx->getElementType(), depth + 1);
        } else if (const auto* at = dyn_cast<clang::AtomicType>(ty)) {
            push(at->getValueType(), depth + 1);
        } else if (const auto* rec = ty->getAs<clang::RecordType>()) {
            const clang::RecordDecl* rd = rec->getDecl()->getDefinition();
            if (!rd) return std::nullopt;
            if (const auto* cxx = dyn_cast<clang::CXXRecordDecl>(rd))
                for (const auto& base : cxx->bases())
                    push(base.getType(), depth + 1);
            for (const auto* field : rd->fields())
                push(field->getType(), depth + 1);
        }
        // Pointers, references, builtins, enums: leaves — their size
        // does not depend on any pointee's layout.
    }
    return ctx.getTypeSizeInChars(type).getQuantity();
}

Interval evalInterval(const Expr* expr, const IntervalMap& state,
                      const clang::ASTContext* ctx) {
    if (!expr) return Interval::top();
    expr = expr->IgnoreParens();

    // Casts: only the value-preserving ones are transparent. A narrowing
    // integral cast can WRAP (`(char)300 == 44`), so its value set is
    // not a subset of the source's — passing it through TYPE-blind
    // would be UNSOUND (miss values). With an ASTContext available the
    // check is VALUE-based instead: if the operand's interval already
    // FITS the destination type's representable range, no value can
    // wrap and the cast preserves the interval exactly (the picojpeg
    // `tableIndex = ((index>>3)&2)+(index&1)` shape — an int expression
    // in [0,3] assigned to uint8). No context → old conservative top.
    if (const auto* cast = dyn_cast<ImplicitCastExpr>(expr)) {
        const CastKind k = cast->getCastKind();
        if (k == CK_LValueToRValue || k == CK_NoOp)
            return evalInterval(cast->getSubExpr(), state, ctx);
        if (k == CK_IntegralCast && ctx) {
            Interval v = evalInterval(cast->getSubExpr(), state, ctx);
            if (v.isEmpty() || v.loIsInf() || v.hiIsInf())
                return Interval::top();
            QualType to = cast->getType();
            const unsigned width = ctx->getIntWidth(to);
            if (width == 0 || width > 64) return Interval::top();
            int64_t tmin, tmax;
            if (to->isSignedIntegerOrEnumerationType()) {
                if (width == 64) {
                    tmin = INT64_MIN;
                    tmax = INT64_MAX;
                } else {
                    tmin = -(int64_t(1) << (width - 1));
                    tmax = (int64_t(1) << (width - 1)) - 1;
                }
            } else {
                tmin = 0;
                // uint64's full range does not fit int64; only the
                // int64-representable part can be certified.
                tmax = (width >= 64) ? INT64_MAX
                                     : (int64_t(1) << width) - 1;
            }
            if (v.lo() >= tmin && v.hi() <= tmax) return v;
            return Interval::top();
        }
        return Interval::top();
    }

    if (const auto* lit = dyn_cast<IntegerLiteral>(expr)) {
        if (!lit->getValue().isSignedIntN(64)) return Interval::top();
        return Interval::constant(lit->getValue().getSExtValue());
    }
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
        if (const auto* vd = dyn_cast<VarDecl>(ref->getDecl())) {
            auto it = state.find(vd);
            if (it != state.end()) return it->second;
        }
        return Interval::top();
    }
    if (const auto* u = dyn_cast<UnaryOperator>(expr)) {
        if (u->getOpcode() == UO_Minus)
            return Interval::negate(
                evalInterval(u->getSubExpr(), state, ctx));
        if (u->getOpcode() == UO_Plus)
            return evalInterval(u->getSubExpr(), state, ctx);
        return Interval::top();
    }
    if (const auto* bin = dyn_cast<BinaryOperator>(expr)) {
        Interval l = evalInterval(bin->getLHS(), state, ctx);
        Interval r = evalInterval(bin->getRHS(), state, ctx);
        switch (bin->getOpcode()) {
            case BO_Add: return Interval::add(l, r);
            case BO_Sub: return Interval::sub(l, r);
            case BO_Mul: return Interval::mul(l, r);
            case BO_And: return bitAnd(l, r);
            case BO_Rem: return intRem(l, r);
            default:     return Interval::top();
        }
    }
    // An intrinsic untrusted source (the atoi/strtol family) evaluates to
    // its return type's full FINITE range — the seed the overflow rule needs
    // to prove `atoi(s) * k` escapes the type. Needs a context for the
    // type width; without one it stays top() (the old behavior).
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        if (ctx && isUntrustedIntSource(call))
            if (auto iv = intTypeRange(call->getType(), *ctx)) return *iv;
        return Interval::top();
    }
    return Interval::top();
}

Interval evalInterval(const Expr* expr, const IntervalMap& state) {
    return evalInterval(expr, state, nullptr);
}

bool exprDerivesFromUntrusted(const Expr* e,
                              const std::set<const VarDecl*>& untrusted) {
    if (!e) return false;
    // Casts are transparent for PROVENANCE: (size_t)n is still n's
    // value. Range soundness is evalSizeInterval's job, not this one's.
    e = e->IgnoreParenCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e)) {
        const auto* vd = dyn_cast<VarDecl>(ref->getDecl());
        return vd && untrusted.count(vd) > 0;
    }
    if (const auto* call = dyn_cast<CallExpr>(e))
        return isUntrustedIntSource(call);
    if (const auto* u = dyn_cast<UnaryOperator>(e))
        return exprDerivesFromUntrusted(u->getSubExpr(), untrusted);
    if (const auto* bin = dyn_cast<BinaryOperator>(e))
        return exprDerivesFromUntrusted(bin->getLHS(), untrusted) ||
               exprDerivesFromUntrusted(bin->getRHS(), untrusted);
    if (const auto* c = dyn_cast<ConditionalOperator>(e))
        return exprDerivesFromUntrusted(c->getTrueExpr(), untrusted) ||
               exprDerivesFromUntrusted(c->getFalseExpr(), untrusted);
    return false;
}

void applyIntervalAssign(IntervalMap& state, const Stmt* stmt,
                         const std::set<const VarDecl*>& vars,
                         const ASTContext* ctx,
                         std::set<const VarDecl*>* untrusted) {
    auto set = [&](const VarDecl* v, Interval iv) {
        if (vars.count(v)) state[v] = iv;
    };
    // Recompute untrusted-origin membership on a plain (re)definition:
    // derivation is a property of the NEW value, so stale membership
    // dies exactly where the old value does.
    auto setOrigin = [&](const VarDecl* v, const Expr* rhs) {
        if (!untrusted || !vars.count(v)) return;
        const bool derived =
            rhs && (exprDerivesFromUntrusted(rhs, *untrusted));
        if (derived)
            untrusted->insert(v);
        else
            untrusted->erase(v);
    };

    if (const auto* ds = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* d : ds->decls())
            if (const auto* vd = dyn_cast<VarDecl>(d))
                if (vars.count(vd)) {
                    state[vd] = vd->hasInit()
                                    ? evalInterval(vd->getInit(), state, ctx)
                                    : Interval::top();
                    setOrigin(vd, vd->hasInit() ? vd->getInit() : nullptr);
                }
        return;
    }
    if (const auto* bin = dyn_cast<BinaryOperator>(stmt)) {
        if (bin->getOpcode() == BO_Assign)
            if (const VarDecl* v = asIntVar(bin->getLHS())) {
                set(v, evalInterval(bin->getRHS(), state, ctx));
                setOrigin(v, bin->getRHS());
            }
        // Compound assignment (`x += ...`) not modeled yet → top.
        // Origin membership stays as-is: with a top() interval the
        // possible-overflow consumer (finite-bound bar) cannot report.
        if (bin->isCompoundAssignmentOp())
            if (const VarDecl* v = asIntVar(bin->getLHS()))
                set(v, Interval::top());
        return;
    }
    if (const auto* u = dyn_cast<UnaryOperator>(stmt)) {
        // ++/-- and &x both put the value out of our precise reach.
        if (u->isIncrementDecrementOp() || u->getOpcode() == UO_AddrOf)
            if (const VarDecl* v = asIntVar(u->getSubExpr()))
                set(v, Interval::top());
        return;
    }
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        // scanf(&n): n is filled from external text — the untrusted
        // source delivered by pointer. Seed its type's FULL FINITE range
        // (not top()), the same model as an atoi return, so a downstream
        // `n * k` proves overflow and a guard re-narrows on its edge.
        //
        // Width-aware refinement (2026-07-22, the rtp2httpd timezone FP
        // family): when the format string is a literal, conversions are
        // PAIRED with their arguments (`%*d` consumes no argument — a
        // blind per-arg sweep would misalign and seed the wrong
        // variable) and an explicit field width bounds the value the
        // conversion can produce: `%2d` cannot exceed 99 no matter the
        // input, so the full-type-range model — whose finite endpoints
        // double as overflow witnesses downstream — would claim a bound
        // the parse cannot reach. Widthless conversions keep the
        // full-range untrusted-source model unchanged; %n is
        // non-negative by definition. Non-literal formats fall back to
        // the old per-arg sweep (sound: full type range).
        if (ctx && isScanfFamily(call)) {
            std::vector<ScanfConv> convs;
            const clang::StringLiteral* fmt = scanfFormatLiteral(call);
            if (fmt && parseScanfFormat(fmt->getString(), convs)) {
                unsigned argIdx = scanfFormatArgIndex(call) + 1;
                for (const ScanfConv& c : convs) {
                    if (c.suppressed) continue;
                    if (argIdx >= call->getNumArgs()) break;
                    const Expr* arg = call->getArg(argIdx++);
                    const VarDecl* v = addrOfIntVar(arg);
                    if (!v || !isNumericScanfConv(c.conv)) continue;
                    auto tr = intTypeRange(v->getType(), *ctx);
                    if (!tr) continue;
                    Interval seed = *tr;
                    if (c.conv == 'n') {
                        seed = Interval::meet(
                            seed, Interval::atLeast(0));
                    } else if (auto wb = scanfWidthBound(c)) {
                        seed = Interval::meet(seed, *wb);
                    }
                    if (!seed.isEmpty()) {
                        set(v, seed);
                        // scanf-filled = externally chosen, even when a
                        // field width narrows the RANGE (%2d still lets
                        // the input pick any value in it).
                        if (untrusted && vars.count(v) && c.conv != 'n')
                            untrusted->insert(v);
                    }
                }
                return;
            }
            for (const Expr* arg : call->arguments())
                if (const VarDecl* v = addrOfIntVar(arg))
                    if (auto iv = intTypeRange(v->getType(), *ctx)) {
                        set(v, *iv);
                        if (untrusted && vars.count(v)) untrusted->insert(v);
                    }
            return;
        }
        // An int passed by non-const reference may be rewritten.
        forEachNonConstRefArg(call, [&](const Expr* arg) {
            if (const VarDecl* v = asIntVar(arg)) {
                set(v, Interval::top());
                // Rewritten by an unknown callee: no longer of proven
                // untrusted origin (and top() blocks reporting anyway).
                if (untrusted) untrusted->erase(v);
            }
        });
    }
}

void refineIntervalOnEdge(IntervalMap& state, const Expr* cond, bool isTrue,
                          const std::set<const VarDecl*>& vars,
                          const ASTContext* ctx) {
    walkCondition(
        cond, isTrue,
        // `if (x)`: true → x != 0; false → x == 0.
        [&](const VarDecl* var, bool truthy) {
            if (!vars.count(var)) return;
            auto it = state.find(var);
            if (it == state.end()) return;
            it->second = truthy ? it->second.constrainNe(0)
                                : it->second.constrainEq(0);
        },
        // `x OPC other`: refine when `other` folds to a constant. opc
        // arrives variable-on-the-left; on the false edge the negation
        // holds.
        [&](const VarDecl* var, BinaryOperatorKind opc, const Expr* other,
            bool edgeTrue) {
            if (!vars.count(var)) return;
            auto c = foldConstInt(other, ctx);
            if (!c) return;
            auto it = state.find(var);
            if (it == state.end()) return;
            BinaryOperatorKind eff = edgeTrue ? opc : negateCmp(opc);
            it->second = constrainBy(it->second, eff, *c);
        });
}

Interval evalSizeInterval(const Expr* e, ASTContext& ctx,
                          const IntervalMap& state) {
    if (!e) return Interval::top();
    e = e->IgnoreParens();

    // Value-preserving casts are transparent; a narrowing cast stops here
    // so the size can never be over-estimated into a false overflow.
    if (const auto* cast = dyn_cast<ImplicitCastExpr>(e)) {
        const CastKind k = cast->getCastKind();
        if (k == CK_LValueToRValue || k == CK_NoOp)
            return evalSizeInterval(cast->getSubExpr(), ctx, state);
        if (k == CK_IntegralCast &&
            cast->getType()->isIntegerType() &&
            cast->getSubExpr()->getType()->isIntegerType() &&
            ctx.getIntWidth(cast->getType()) >=
                ctx.getIntWidth(cast->getSubExpr()->getType()))
            return evalSizeInterval(cast->getSubExpr(), ctx, state);
        return Interval::top();
    }

    // sizeof(T) / sizeof(expr) — a compile-time byte constant.
    if (const auto* uett = dyn_cast<UnaryExprOrTypeTraitExpr>(e)) {
        if (uett->getKind() == UETT_SizeOf && !uett->isValueDependent()) {
            QualType t = uett->getTypeOfArgument();
            if (auto sz = boundedTypeSizeInChars(ctx, t))
                return Interval::constant(*sz);
        }
        return Interval::top();
    }

    // Constant arithmetic over sizes: count * sizeof(T), etc.
    if (const auto* bo = dyn_cast<BinaryOperator>(e)) {
        Interval l = evalSizeInterval(bo->getLHS(), ctx, state);
        Interval r = evalSizeInterval(bo->getRHS(), ctx, state);
        switch (bo->getOpcode()) {
            case BO_Mul: return Interval::mul(l, r);
            case BO_Add: return Interval::add(l, r);
            case BO_Sub: return Interval::sub(l, r);
            default:     return Interval::top();
        }
    }

    // Literals and tracked variables — the plain evaluator, same state.
    return evalInterval(e, state);
}

IntervalMap soleDefIntervals(const clang::FunctionDecl* fn,
                             clang::ASTContext& ctx) {
    IntervalMap result;
    if (!fn || !fn->hasBody()) return result;

    // Pass 1: initializers, plain assignments, and disqualifying
    // writes, in one traversal.
    struct Scan : clang::RecursiveASTVisitor<Scan> {
        std::map<const clang::VarDecl*, const clang::Expr*> inits;
        std::map<const clang::VarDecl*, std::vector<const clang::Expr*>>
            assigns;
        std::set<const clang::VarDecl*> otherWrites;

        static const clang::VarDecl* asVar(const clang::Expr* e) {
            if (!e) return nullptr;
            e = e->IgnoreParenImpCasts();
            if (const auto* ref = dyn_cast<clang::DeclRefExpr>(e))
                return dyn_cast<clang::VarDecl>(ref->getDecl());
            return nullptr;
        }
        bool VisitVarDecl(clang::VarDecl* vd) {
            if (vd->isLocalVarDecl() && vd->hasLocalStorage() &&
                vd->getType()->isIntegerType() && vd->hasInit())
                inits[vd] = vd->getInit();
            return true;
        }
        bool VisitBinaryOperator(clang::BinaryOperator* bin) {
            if (!bin->isAssignmentOp()) return true;
            const auto* var = asVar(bin->getLHS());
            if (!var) return true;
            if (bin->getOpcode() == clang::BO_Assign)
                assigns[var].push_back(bin->getRHS());
            else
                otherWrites.insert(var);  // compound: += etc.
            return true;
        }
        bool VisitUnaryOperator(clang::UnaryOperator* un) {
            if (un->isIncrementDecrementOp() ||
                un->getOpcode() == clang::UO_AddrOf)
                if (const auto* var = asVar(un->getSubExpr()))
                    otherWrites.insert(var);
            return true;
        }
        // A non-const reference argument can write the local from the
        // callee — same treatment as a direct write.
        bool VisitCallExpr(clang::CallExpr* call) {
            codeskeptic::forEachNonConstRefArg(
                call, [&](const clang::Expr* refArg) {
                    if (const auto* var = asVar(refArg))
                        otherWrites.insert(var);
                });
            return true;
        }
    };
    Scan scan;
    scan.TraverseStmt(fn->getBody());

    // Pass 2: a local qualifies with EITHER an initializer and no
    // assignments, OR no initializer and exactly ONE plain assignment
    // (the picojpeg `uint8 tableIndex; ... tableIndex = expr;` shape —
    // any read before that single write is UB and the uninit domain's
    // business). Evaluate the sole defining expression against the
    // empty state.
    const IntervalMap empty;
    auto record = [&](const clang::VarDecl* var, const clang::Expr* def) {
        Interval v = evalInterval(def, empty, &ctx);
        if (!v.isTop() && !v.isEmpty()) result[var] = v;
    };
    for (const auto& [var, init] : scan.inits) {
        if (scan.otherWrites.count(var) || scan.assigns.count(var))
            continue;
        record(var, init);
    }
    for (const auto& [var, rhss] : scan.assigns) {
        if (scan.otherWrites.count(var) || scan.inits.count(var)) continue;
        if (rhss.size() != 1) continue;
        if (!var->isLocalVarDecl() || !var->hasLocalStorage() ||
            !var->getType()->isIntegerType())
            continue;
        record(var, rhss.front());
    }
    return result;
}

} // namespace codeskeptic
