#ifndef ZERODEFECT_MEMORY_LEAK_RULE_H
#define ZERODEFECT_MEMORY_LEAK_RULE_H

#include "core/Rule.h"

namespace zerodefect {

class MemoryLeakRule : public Rule {
public:
    std::string id() const override;
    std::string description() const override;

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace zerodefect

#endif // ZERODEFECT_MEMORY_LEAK_RULE_H
