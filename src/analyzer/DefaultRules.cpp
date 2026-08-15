#include "analyzer/DefaultRules.h"

#include "analyzer/StaticAnalyzer.h"
#include "rules/AllocSizeOverflowRule.h"
#include "rules/AssumptionRule.h"
#include "rules/BoundsRule.h"
#include "rules/ContractRule.h"
#include "rules/DivByZeroRule.h"
#include "rules/FdResourceRule.h"
#include "rules/IntOverflowRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"
#include "rules/PolicyRule.h"
#include "rules/SignConversionRule.h"
#include "rules/UninitPointerRule_Ex.h"

namespace codeskeptic {

void registerDefaultRules(StaticAnalyzer& analyzer) {
    analyzer.addRule<UninitPointerRule_Ex>();
    analyzer.addRule<MemoryLeakRule_Ex>();
    analyzer.addRule<FdResourceRule>();
    analyzer.addRule<DivByZeroRule>();
    analyzer.addRule<IntOverflowRule>();
    analyzer.addRule<SignConversionRule>();
    analyzer.addRule<AllocSizeOverflowRule>();
    analyzer.addRule<BoundsRule>();
    analyzer.addRule<AssumptionRule>();
    analyzer.addRule<NullDerefRule>();
    analyzer.addRule<ContractRule>();
    analyzer.addRule<PolicyRule>();
}

} // namespace codeskeptic
