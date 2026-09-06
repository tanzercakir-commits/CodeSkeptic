#ifndef CODESKEPTIC_ANALYSIS_STATE_H
#define CODESKEPTIC_ANALYSIS_STATE_H

namespace codeskeptic {
class Config;
// Shared initialization for the explicit in-process API and a fresh child.
// No input discovery, compilation, report writing or worker recursion here.
void initializeAnalysisState(const Config& config);
void clearAnalysisState();
}
#endif
