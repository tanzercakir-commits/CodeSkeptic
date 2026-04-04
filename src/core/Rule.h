#ifndef ZERODEFECT_RULE_H
#define ZERODEFECT_RULE_H

#include "core/Diagnostic.h"

#include <string>

namespace clang {
class ASTContext;
}

namespace zerodefect {

class Rule {
public:
    virtual ~Rule() = default;

    virtual std::string id() const = 0;
    virtual std::string description() const = 0;
    virtual Severity defaultSeverity() const { return Severity::Warning; }

    virtual void check(clang::ASTContext& ctx, DiagnosticList& results) = 0;

    void setEnabled(bool enabled) { enabled_ = enabled; }
    bool isEnabled() const { return enabled_; }

private:
    bool enabled_ = true;
};

} // namespace zerodefect

#endif // ZERODEFECT_RULE_H
