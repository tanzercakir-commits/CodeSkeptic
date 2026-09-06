#ifndef CODESKEPTIC_BUILTIN_RULES_H
#define CODESKEPTIC_BUILTIN_RULES_H

#include "rules/UninitPointerRule_Ex.h"
#include "rules/UninitScalarRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/FdResourceRule.h"
#include "rules/DivByZeroRule.h"
#include "rules/IntOverflowRule.h"
#include "rules/SignConversionRule.h"
#include "rules/AllocSizeOverflowRule.h"
#include "rules/BoundsRule.h"
#include "rules/AssumptionRule.h"
#include "rules/NullDerefRule.h"
#include "rules/ContractRule.h"
#include "rules/PolicyRule.h"

namespace codeskeptic {

// Preserve the production producer ordering; public finding-family selection
// remains independent. This helper is shared by main and the same-build child.
#define CODESKEPTIC_BUILTIN_TYPES(APPLY) \
    APPLY(UninitPointerRule_Ex) APPLY(UninitScalarRule) APPLY(MemoryLeakRule_Ex) \
    APPLY(FdResourceRule) APPLY(DivByZeroRule) APPLY(IntOverflowRule) \
    APPLY(SignConversionRule) APPLY(AllocSizeOverflowRule) APPLY(BoundsRule) \
    APPLY(AssumptionRule) APPLY(NullDerefRule) APPLY(ContractRule) APPLY(PolicyRule)

template <typename Engine>
void addBuiltinRules(Engine& engine) {
#define ADD_BUILTIN(Type) engine.template addRule<Type>();
    CODESKEPTIC_BUILTIN_TYPES(ADD_BUILTIN)
#undef ADD_BUILTIN
}

template <typename Engine>
bool addBuiltinRule(Engine& engine, const std::string& id) {
#define MATCH_BUILTIN(Type) if (id == Type().id()) { engine.template addRule<Type>(); return true; }
    CODESKEPTIC_BUILTIN_TYPES(MATCH_BUILTIN)
#undef MATCH_BUILTIN
    return false;
}

#undef CODESKEPTIC_BUILTIN_TYPES
} // namespace codeskeptic
#endif
