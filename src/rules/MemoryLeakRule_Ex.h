#ifndef CODESKEPTIC_MEMORY_LEAK_RULE_EX_H
#define CODESKEPTIC_MEMORY_LEAK_RULE_EX_H

#include "core/Rule.h"

namespace codeskeptic {

class MemoryLeakRule_Ex : public Rule {
public:
    std::string id() const override;
    std::string description() const override;

    void check(clang::ASTContext& ctx, DiagnosticList& results) override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_MEMORY_LEAK_RULE_EX_H
