#include "engine/SummaryDiff.h"

#include <algorithm>
#include <ostream>
#include <sstream>

namespace {

using RN = codeskeptic::SummaryRegistry::ReturnNullness;
using RZ = codeskeptic::SummaryRegistry::ReturnZeroness;
using PE = codeskeptic::SummaryRegistry::ParamEffect;
using FunctionSummary = codeskeptic::SummaryRegistry::FunctionSummary;

const char* rnName(RN v) {
    switch (v) {
        case RN::NeverNull: return "NeverNull";
        case RN::MaybeNull: return "MaybeNull";
        case RN::Unknown:   break;
    }
    return "Unknown";
}

const char* rzName(RZ v) {
    switch (v) {
        case RZ::NeverZero: return "NeverZero";
        case RZ::MaybeZero: return "MaybeZero";
        case RZ::Unknown:   break;
    }
    return "Unknown";
}

const char* peName(PE v) {
    switch (v) {
        case PE::ReadsOnly: return "ReadsOnly";
        case PE::Frees:     return "Frees";
        case PE::Stores:    return "Stores";
        case PE::Opaque:    break;
    }
    return "Opaque";
}

// "Strong" claims: guarantees that change analysis results on the
// caller side. Their loss/change is a weakening — callers leaning on
// the claim must be re-examined.
bool rnStrong(RN v) { return v == RN::NeverNull; }
bool rzStrong(RZ v) { return v == RZ::NeverZero; }
bool peStrong(PE v) { return v == PE::ReadsOnly || v == PE::Frees; }

struct FieldVerdict {
    bool weakened = false;
    bool strengthened = false;
    bool changed = false;
};

template <typename T, typename StrongFn, typename NameFn>
void classifyField(T oldV, T newV, StrongFn isStrong, NameFn name,
                   const std::string& label, FieldVerdict& verdict,
                   std::string& detail) {
    if (oldV == newV) return;
    if (isStrong(oldV))
        verdict.weakened = true;
    else if (isStrong(newV))
        verdict.strengthened = true;
    else
        verdict.changed = true;
    if (!detail.empty()) detail += "; ";
    detail += label + ": " + name(oldV) + " -> " + name(newV);
}

} // anonymous namespace

namespace codeskeptic {

SummaryDiffResult diffSummaries(const SummaryMap& oldMap,
                                const SummaryMap& newMap) {
    SummaryDiffResult result;
    std::vector<SummaryChange> nonWeakened;

    for (const auto& [key, oldSum] : oldMap) {
        auto it = newMap.find(key);
        if (it == newMap.end()) {
            ++result.removed;
            nonWeakened.push_back({ChangeKind::Removed, key, ""});
            continue;
        }
        const FunctionSummary& newSum = it->second;

        FieldVerdict verdict;
        std::string detail;
        classifyField(oldSum.returnNullness, newSum.returnNullness,
                      rnStrong, rnName, "returnNullness", verdict, detail);
        classifyField(oldSum.returnZeroness, newSum.returnZeroness,
                      rzStrong, rzName, "returnZeroness", verdict, detail);

        // Parameters are compared by index; vector sizes may differ
        // (the conservative merge may have emptied one) — paramEffect()
        // treats the missing ones as Opaque
        const size_t numParams =
            std::max(oldSum.params.size(), newSum.params.size());
        for (size_t i = 0; i < numParams; ++i) {
            classifyField(oldSum.paramEffect(static_cast<unsigned>(i)),
                          newSum.paramEffect(static_cast<unsigned>(i)),
                          peStrong, peName,
                          "param#" + std::to_string(i), verdict, detail);
        }

        if (detail.empty()) continue;  // contract unchanged

        // Function-level verdict: if any field weakened, the whole is
        // WEAKENED (the worst direction wins)
        if (verdict.weakened) {
            ++result.weakened;
            result.changes.push_back(
                {ChangeKind::Weakened, key, detail});
        } else if (verdict.strengthened) {
            ++result.strengthened;
            nonWeakened.push_back(
                {ChangeKind::Strengthened, key, detail});
        } else {
            ++result.changed;
            nonWeakened.push_back({ChangeKind::Changed, key, detail});
        }
    }

    for (const auto& [key, newSum] : newMap) {
        if (!oldMap.count(key)) {
            ++result.added;
            nonWeakened.push_back({ChangeKind::Added, key, ""});
        }
    }

    // Weakened is already in front (map walked in order); rest go after
    result.changes.insert(result.changes.end(), nonWeakened.begin(),
                          nonWeakened.end());
    return result;
}

namespace {

const char* kindName(ChangeKind kind) {
    switch (kind) {
        case ChangeKind::Added:        return "ADDED";
        case ChangeKind::Removed:      return "REMOVED";
        case ChangeKind::Weakened:     return "WEAKENED";
        case ChangeKind::Strengthened: return "STRENGTHENED";
        case ChangeKind::Changed:      return "CHANGED";
    }
    return "?";
}

} // anonymous namespace

int reportSummaryDiff(const std::string& oldPath,
                      const std::string& newPath, std::ostream& out,
                      bool gateWeakened) {
    SummaryMap oldMap;
    SummaryMap newMap;
    if (!SummaryRegistry::parseSummaryFile(oldPath, oldMap)) {
        out << "[CodeSkeptic] cannot read summary file: " << oldPath
            << "\n";
        return 2;
    }
    if (!SummaryRegistry::parseSummaryFile(newPath, newMap)) {
        out << "[CodeSkeptic] cannot read summary file: " << newPath
            << "\n";
        return 2;
    }

    SummaryDiffResult result = diffSummaries(oldMap, newMap);

    out << "[CodeSkeptic] summary diff: " << oldPath << " -> " << newPath
        << " (" << newMap.size() << " functions)\n";
    for (const auto& change : result.changes) {
        out << "SUMMARY_DIFF " << kindName(change.kind) << " "
            << change.key;
        if (!change.detail.empty()) out << " " << change.detail;
        out << "\n";
    }
    out << "[CodeSkeptic] " << result.weakened << " weakened, "
        << result.strengthened << " strengthened, " << result.changed
        << " changed, " << result.added << " added, " << result.removed
        << " removed\n";
    if (result.weakened > 0) {
        out << "[CodeSkeptic] weakened contracts: callers relying on "
               "them must be re-checked\n";
        return gateWeakened ? 1 : 0;
    }
    return 0;
}

} // namespace codeskeptic
