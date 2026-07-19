#ifndef CODESKEPTIC_ASSUMPTION_MODE_H
#define CODESKEPTIC_ASSUMPTION_MODE_H

// Assumption-extraction is OPT-IN (--assumptions). It is an intent-debt
// report, not a bug hunt: it surfaces the implicit preconditions a
// function relies on but never states, which is inherently high-volume
// (every unguarded pointer deref). Default findings are Info-severity
// and the default min-severity is Info, so leaving it on by default
// would flood the normal finding stream and perturb the corpus/Juliet
// referees. This process-global switch (set from Config in
// StaticAnalyzer, like the allocator/fatal-call name sets) keeps the
// AssumptionRule silent unless the user explicitly asks for the report.

namespace codeskeptic {

void setAssumptionMode(bool enabled);
bool assumptionMode();

} // namespace codeskeptic

#endif // CODESKEPTIC_ASSUMPTION_MODE_H
