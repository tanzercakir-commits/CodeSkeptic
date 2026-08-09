#include "engine/SummaryDiff.h"

#include <algorithm>
#include <ostream>
#include <sstream>

namespace {

using RN = codeskeptic::SummaryRegistry::ReturnNullness;
using RZ = codeskeptic::SummaryRegistry::ReturnZeroness;
using RO = codeskeptic::SummaryRegistry::ReturnOwnership;
using PE = codeskeptic::SummaryRegistry::ParamEffect;
using PA = codeskeptic::SummaryRegistry::ParamAccess;
using PO = codeskeptic::SummaryRegistry::ParamOwnership;
using PPre = codeskeptic::SummaryRegistry::ParamPrecondition;
using PPost = codeskeptic::SummaryRegistry::ParamPostcondition;
using PAS = codeskeptic::SummaryRegistry::ParamAllocatorSize;
using FieldWriteSet = codeskeptic::SummaryRegistry::FieldWriteSet;
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
        case RZ::AlwaysZero: return "AlwaysZero";
        case RZ::NeverZero: return "NeverZero";
        case RZ::MaybeZero: return "MaybeZero";
        case RZ::Unknown:   break;
    }
    return "Unknown";
}

const char* roName(RO value) {
    switch (value) {
        case RO::Owned: return "Owned";
        case RO::Borrowed: return "Borrowed";
        case RO::Unknown: break;
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

const char* accessName(PA value) {
    switch (value) {
        case PA::None: return "None";
        case PA::Reads: return "Reads";
        case PA::Writes: return "Writes";
        case PA::ReadsWrites: return "ReadsWrites";
        case PA::Unknown: break;
    }
    return "Unknown";
}

const char* ownershipName(PO value) {
    switch (value) {
        case PO::Borrowed: return "Borrowed";
        case PO::Consumed: return "Consumed";
        case PO::Transferred: return "Transferred";
        case PO::Unknown: break;
    }
    return "Unknown";
}

const char* preName(PPre v) {
    switch (v) {
        case PPre::NonNullCrash: return "NonNullCrash";
        case PPre::NonNullRejected: return "NonNullRejected";
        case PPre::None: break;
    }
    return "None";
}

const char* postName(PPost v) {
    switch (v) {
        case PPost::Null: return "Null";
        case PPost::NonNull: return "NonNull";
        case PPost::Unknown: break;
    }
    return "Unknown";
}

const char* allocatorSizeName(PAS value) {
    switch (value) {
        case PAS::None: return "None";
        case PAS::Sink: return "Sink";
        case PAS::Unknown: break;
    }
    return "Unknown";
}

std::string aliasName(int v) {
    return v < 0 ? "none" : "param#" + std::to_string(v);
}

// "Strong" claims: guarantees that change analysis results on the
// caller side. Their loss/change is a weakening — callers leaning on
// the claim must be re-examined.
bool rnStrong(RN v) { return v == RN::NeverNull; }
bool roStrong(RO value) { return value != RO::Unknown; }
bool rzStrong(RZ v) {
    return v == RZ::AlwaysZero || v == RZ::NeverZero;
}
bool peStrong(PE v) { return v == PE::ReadsOnly || v == PE::Frees; }
bool accessStrong(PA value) { return value != PA::Unknown; }
bool ownershipStrong(PO value) { return value != PO::Unknown; }
bool allocatorSizeStrong(PAS value) { return value == PAS::Sink; }
bool aliasStrong(int v) { return v >= 0; }

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

void appendDetail(std::string& detail, const std::string& label,
                  const char* oldName, const char* newName) {
    if (!detail.empty()) detail += "; ";
    detail += label + ": " + oldName + " -> " + newName;
}

void classifyPrecondition(PPre oldV, PPre newV,
                          const std::string& label,
                          FieldVerdict& verdict, std::string& detail) {
    if (oldV == newV) return;
    // A new caller obligation is a compatibility weakening. Changing a
    // rejection into a crash is also a worsening; the reverse directions
    // relax or make the contract safer.
    if (oldV == PPre::None ||
        (oldV == PPre::NonNullRejected &&
         newV == PPre::NonNullCrash))
        verdict.weakened = true;
    else
        verdict.strengthened = true;
    appendDetail(detail, label, preName(oldV), preName(newV));
}

void classifyPostcondition(PPost oldV, PPost newV,
                           const std::string& label,
                           FieldVerdict& verdict, std::string& detail) {
    if (oldV == newV) return;
    if (oldV != PPost::Unknown)
        verdict.weakened = true;
    else
        verdict.strengthened = true;
    appendDetail(detail, label, postName(oldV), postName(newV));
}

std::string fieldWriteName(const FieldWriteSet* value) {
    if (!value) return "unknown";
    std::string out = "{";
    bool first = true;
    for (const std::string& field : value->fields) {
        if (!first) out += ',';
        out += field;
        first = false;
    }
    out += '}';
    return out;
}

void classifyFieldWrites(const FunctionSummary& oldSum,
                         const FunctionSummary& newSum, unsigned index,
                         const std::string& label, FieldVerdict& verdict,
                         std::string& detail) {
    const FieldWriteSet* oldValue = oldSum.exactParamFieldWrites(index);
    const FieldWriteSet* newValue = newSum.exactParamFieldWrites(index);
    if ((!oldValue && !newValue) ||
        (oldValue && newValue && oldValue->fields == newValue->fields))
        return;

    if (!oldValue) {
        verdict.strengthened = true;
    } else if (!newValue) {
        verdict.weakened = true;
    } else {
        const bool oldContainsNew = std::includes(
            oldValue->fields.begin(), oldValue->fields.end(),
            newValue->fields.begin(), newValue->fields.end());
        const bool newContainsOld = std::includes(
            newValue->fields.begin(), newValue->fields.end(),
            oldValue->fields.begin(), oldValue->fields.end());
        if (newContainsOld || !oldContainsNew)
            verdict.weakened = true;
        else
            verdict.strengthened = true;
    }
    if (!detail.empty()) detail += "; ";
    detail += label + ": " + fieldWriteName(oldValue) + " -> " +
              fieldWriteName(newValue);
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
        classifyField(oldSum.returnOwnership, newSum.returnOwnership,
                      roStrong, roName, "returnOwnership", verdict, detail);
        classifyField(oldSum.returnAliasParam, newSum.returnAliasParam,
                      aliasStrong, aliasName, "returnAliasParam",
                      verdict, detail);

        // Parameters are compared by index; vector sizes may differ
        // (the conservative merge may have emptied one) — paramEffect()
        // treats the missing ones as Opaque
        const size_t numParams = std::max(
            {oldSum.params.size(), newSum.params.size(),
             oldSum.paramPreconditions.size(),
             newSum.paramPreconditions.size(),
             oldSum.paramPostconditions.size(),
             newSum.paramPostconditions.size(), oldSum.paramAccesses.size(),
             newSum.paramAccesses.size(), oldSum.paramOwnerships.size(),
             newSum.paramOwnerships.size(), oldSum.paramFieldWrites.size(),
             newSum.paramFieldWrites.size(),
             oldSum.paramAllocatorSizes.size(),
             newSum.paramAllocatorSizes.size()});
        for (size_t i = 0; i < numParams; ++i) {
            classifyField(oldSum.paramEffect(static_cast<unsigned>(i)),
                          newSum.paramEffect(static_cast<unsigned>(i)),
                          peStrong, peName,
                          "param#" + std::to_string(i), verdict, detail);
            classifyPrecondition(
                oldSum.paramPrecondition(static_cast<unsigned>(i)),
                newSum.paramPrecondition(static_cast<unsigned>(i)),
                "param#" + std::to_string(i) + ".precondition",
                verdict, detail);
            classifyPostcondition(
                oldSum.paramPostcondition(static_cast<unsigned>(i)),
                newSum.paramPostcondition(static_cast<unsigned>(i)),
                "param#" + std::to_string(i) + ".postcondition",
                verdict, detail);
            classifyField(
                oldSum.paramAccess(static_cast<unsigned>(i)),
                newSum.paramAccess(static_cast<unsigned>(i)),
                accessStrong, accessName,
                "param#" + std::to_string(i) + ".access", verdict, detail);
            classifyField(
                oldSum.paramOwnership(static_cast<unsigned>(i)),
                newSum.paramOwnership(static_cast<unsigned>(i)),
                ownershipStrong, ownershipName,
                "param#" + std::to_string(i) + ".ownership", verdict,
                detail);
            classifyFieldWrites(
                oldSum, newSum, static_cast<unsigned>(i),
                "param#" + std::to_string(i) + ".fieldWrites", verdict,
                detail);
            classifyField(
                oldSum.paramAllocatorSize(static_cast<unsigned>(i)),
                newSum.paramAllocatorSize(static_cast<unsigned>(i)),
                allocatorSizeStrong, allocatorSizeName,
                "param#" + std::to_string(i) + ".allocatorSize", verdict,
                detail);
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
