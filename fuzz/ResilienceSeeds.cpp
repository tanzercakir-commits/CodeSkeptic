// Deterministic bounded mutation of real parsers/codecs. Never executes source,
// starts an analysis worker or follows a path decoded from a mutated input.
#include "analyzer/RuntimeIdentity.h"
#include "analyzer/WorkerProtocol.h"
#include "contracts/ContractParser.h"
#include "contracts/Sidecar.h"
#include "source_manager/InputIdentity.h"
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace codeskeptic;
namespace {
void require(bool value, const char* why) { if (!value) throw std::runtime_error(why); }
void field(std::string& out, const std::string& value) {
    out += std::to_string(value.size()) + ':' + value;
}
template<class T> void number(std::string& out, T value) {
    field(out, std::to_string(static_cast<long long>(value)));
}
void operand(std::string& out, const ContractOperand& value) {
    require(value.kind >= ContractOperandKind::Return && value.kind <= ContractOperandKind::Null,
            "invalid operand enum");
    number(out, value.kind); field(out, value.param); number(out, value.value);
}
void predicate(std::string& out, const ContractPred& value) {
    require(value.kind >= ContractPred::Cmp && value.kind <= ContractPred::Truth, "invalid predicate enum");
    require(value.op >= ContractCmpOp::EQ && value.op <= ContractCmpOp::GE, "invalid comparison enum");
    require(value.kind == ContractPred::Not ? value.children.size() == 1 :
            value.kind == ContractPred::And || value.kind == ContractPred::Or ? value.children.size() >= 2 :
            value.children.empty(), "invalid predicate shape");
    number(out, value.kind); number(out, value.op); operand(out, value.lhs); operand(out, value.rhs);
    number(out, value.children.size());
    for (const auto& child : value.children) predicate(out, child);
}
std::string clause(const ContractClause& value) {
    require(value.kind >= ContractClauseKind::Requires && value.kind <= ContractClauseKind::Policy,
            "invalid clause enum");
    std::string out;
    number(out, value.kind); number(out, value.machineProposed); field(out, value.text);
    number(out, value.line); number(out, value.hasGuard); field(out, value.paramName);
    field(out, value.policyName); predicate(out, value.pred); predicate(out, value.guard);
    return out;
}
void issues(std::string& out, const std::vector<ContractSyntaxIssue>& values) {
    number(out, values.size());
    for (const auto& value : values) { number(out, value.line); field(out, value.text); }
}
std::string comment(const ParsedContracts& value) {
    std::string out;
    number(out, value.clauses.size());
    for (const auto& item : value.clauses) field(out, clause(item));
    issues(out, value.syntaxErrors);
    return out;
}
std::string sidecar(const std::string& input) {
    std::vector<SidecarEntry> entries;
    std::vector<ContractSyntaxIssue> errors;
    parseSidecarText(input, entries, errors);
    std::string out;
    number(out, entries.size());
    for (const auto& item : entries) {
        number(out, item.line); field(out, item.anchor); field(out, item.clause);
        // Framing entries need not contain valid clause grammar. This is NOT
        // the AST loader's all-or-nothing publication check.
        const auto parsed = parseContractClause(item.clause);
        number(out, parsed.has_value());
        if (parsed) field(out, clause(*parsed));
    }
    issues(out, errors);
    return out;
}
struct Counts { std::uint64_t executions = 0, accepted = 0, rejected = 0, boundaries = 0; };
Counts counts;
void contractInput(const std::string& input) {
    const auto first = parseContractClause(input), second = parseContractClause(input);
    require(first.has_value() == second.has_value(), "clause acceptance nondeterministic");
    if (first) {
        require(first->line == 0 && clause(*first) == clause(*second), "clause value nondeterministic");
        ++counts.accepted;
    } else ++counts.rejected;
    require(comment(parseContractComment(input)) == comment(parseContractComment(input)),
            "comment nondeterministic");
    require(sidecar(input) == sidecar(input), "sidecar nondeterministic");
}
WorkerRequest request() {
    WorkerRequest value;
    value.ordinal = 7; value.source = "/resilience/source.cpp"; value.build_directory = "/resilience";
    value.commands.emplace_back(value.build_directory, value.source,
        std::vector<std::string>{"clang++", "-std=c++17", "-c", value.source}, "source.o");
    value.producers = {"null-deref"}; value.selected_families = {"null-deref"};
    return value;
}
WorkerResponse response(const WorkerRequest& req) {
    WorkerResponse value;
    value.request_digest = workerRequestDigest(encodeWorkerRequest(req));
    value.ordinal = req.ordinal; value.phase = req.phase;
    value.coverage.file = req.source; value.coverage.status = SourceStatus::Analyzed;
    value.coverage.reason = "analyzed";
    value.coverage.commands = value.coverage.analyzed_commands = req.commands.size();
    return value;
}
void workerInput(const std::string& input) {
    const auto req = request(); const auto reply = response(req);
    auto decoded = req; decoded.ordinal = 19;
    const auto unchanged = encodeWorkerRequest(decoded);
    std::string error;
    if (decodeWorkerRequest(input, decoded, error)) {
        const auto encoded = encodeWorkerRequest(decoded);
        WorkerRequest again;
        require(decodeWorkerRequest(encoded, again, error) && encodeWorkerRequest(again) == encoded,
                "request accepted without stable roundtrip");
        ++counts.accepted;
    } else { require(encodeWorkerRequest(decoded) == unchanged, "partial request publication"); ++counts.rejected; }
    auto decoded_reply = reply; decoded_reply.ordinal = 19;
    const auto unchanged_reply = encodeWorkerResponse(decoded_reply);
    if (decodeWorkerResponse(input, req, reply.request_digest, decoded_reply, error)) {
        const auto encoded = encodeWorkerResponse(decoded_reply);
        WorkerResponse again;
        require(decodeWorkerResponse(encoded, req, reply.request_digest, again, error) &&
                encodeWorkerResponse(again) == encoded, "response accepted without bound roundtrip");
        ++counts.accepted;
    } else { require(encodeWorkerResponse(decoded_reply) == unchanged_reply, "partial response publication"); ++counts.rejected; }
}
InputIdentity identity() {
    InputIdentity value;
    value.reusable = true; value.context = inputDigest("request"); value.environment = inputDigest("environment");
    value.reason.clear();
    value.observations = {{InputObservationKind::TextBuffer, "/resilience/source.cpp", "source bytes"},
                         {InputObservationKind::Frontend, "frontend", inputDigest("frontend")}};
    return value;
}
std::string mapping(const std::vector<RuntimeMapping>& values) {
    std::string out;
    number(out, values.size());
    for (const auto& value : values) {
        field(out, value.path); field(out, std::to_string(value.device_major));
        field(out, std::to_string(value.device_minor)); field(out, std::to_string(value.inode));
        number(out, value.ranges.size());
        for (const auto& range : value.ranges) {
            field(out, std::to_string(range.first)); field(out, std::to_string(range.second));
        }
    }
    return out;
}
void identityInput(const std::string& input) {
    auto decoded = identity(); decoded.reason = "sentinel";
    const auto unchanged = encodeInputIdentity(decoded);
    if (decodeInputIdentity(input, decoded)) {
        const auto encoded = encodeInputIdentity(decoded);
        InputIdentity again;
        require(decoded.reusable && decoded.reason.empty() && decodeInputIdentity(encoded, again) &&
                encodeInputIdentity(again) == encoded, "identity accepted without stable roundtrip");
        ++counts.accepted;
    } else {
        require(decoded.reusable && decoded.reason == "sentinel" && encodeInputIdentity(decoded) == unchanged,
                "partial input identity publication"); ++counts.rejected;
    }
    std::vector<RuntimeMapping> mappings{{"sentinel", 1, 2, 3, {{4, 5}}}};
    const auto saved = mapping(mappings);
    std::string error;
    if (parseRuntimeMappings(input, mappings, error)) {
        std::vector<RuntimeMapping> again;
        require(error.empty() && parseRuntimeMappings(input, again, error) && mapping(again) == mapping(mappings),
                "runtime mapping nondeterministic"); ++counts.accepted;
    } else { require(mapping(mappings) == saved, "partial mapping publication"); ++counts.rejected; }
}
void contractBoundaries() {
    for (const auto* text : {"requires p != null || n == 0", "ai ensures return != null if n != 0",
                            "owns(fd)", "borrows(name)", "returns owned", "policy no-absolute-paths",
                            "requires n >= -9223372036854775808", "requires n <= 9223372036854775807"})
        { require(parseContractClause(text).has_value(), "positive grammar seed rejected"); ++counts.boundaries; }
    for (const auto* text : {"requires n !=", "requires p != null extra",
                            "requires n < -9223372036854775809", "requires n > 9223372036854775808"})
        { require(!parseContractClause(text), "negative grammar seed accepted"); ++counts.boundaries; }
    for (unsigned size : {64u, 65u}) {
        require(parseContractClause("requires " + std::string(size, '!') + "p").has_value() == (size == 64),
                "unary boundary changed");
        require(parseContractClause("requires " + std::string(size, '(') + "p" + std::string(size, ')')).has_value()
                == (size == 64), "parenthesis boundary changed"); counts.boundaries += 2;
    }
    std::string line = "requires p"; line.resize(16384, ' ');
    require(parseContractClause(line).has_value() && !parseContractClause(line + " "), "clause byte boundary changed");
    counts.boundaries += 2;
    const auto mixed = parseContractComment("// cs: requires p != null\n// cs: ensures return !=\nordinary prose\n");
    require(mixed.clauses.size() == 1 && mixed.syntaxErrors.size() == 1, "ordinary errors lost valid clauses");
    ++counts.boundaries;
    for (unsigned maximum : {1024u, 4096u}) {
        const bool inline_comment = maximum == 1024;
        const std::string record = inline_comment ? "// cs: requires p\n" : "f: requires p\n";
        std::string text;
        for (unsigned i = 0; i < maximum; ++i) text += record;
        for (bool over : {false, true}) {
            if (over) text += record;
            if (inline_comment) {
                const auto result = parseContractComment(text);
                require(result.clauses.size() == (over ? 0u : maximum) && result.syntaxErrors.size() == (over ? 1u : 0u),
                        "comment count boundary changed");
            } else {
                std::vector<SidecarEntry> entries; std::vector<ContractSyntaxIssue> errors;
                parseSidecarText(text, entries, errors);
                require(entries.size() == maximum && errors.size() == (over ? 1u : 0u), "sidecar count boundary changed");
            }
            ++counts.boundaries;
        }
    }
    for (bool inline_comment : {false, true}) {
        std::string text = inline_comment ? "// cs: requires p\n" : "f: requires p\n";
        const std::string pad = (inline_comment ? "//" : "#") + std::string(16000, 'x') + '\n';
        while (1024 * 1024 - text.size() > pad.size() + 2) text += pad;
        text += inline_comment ? "//" : "#"; text.resize(1024 * 1024, 'x');
        for (bool over : {false, true}) {
            if (over) text += '\n';
            if (inline_comment) {
                const auto result = parseContractComment(text);
                require(result.clauses.size() == (over ? 0u : 1u) && result.syntaxErrors.size() == (over ? 1u : 0u),
                        "comment byte boundary changed");
            } else {
                std::vector<SidecarEntry> entries; std::vector<ContractSyntaxIssue> errors;
                parseSidecarText(text, entries, errors);
                require(entries.size() == (over ? 0u : 1u) && errors.size() == (over ? 1u : 0u), "sidecar byte boundary changed");
            }
            ++counts.boundaries;
        }
    }
}
std::uint64_t random(std::uint64_t& state) { state ^= state << 13; state ^= state >> 7; return state ^= state << 17; }
std::uint64_t integer(const std::string& text) {
    require(!text.empty() && text.find_first_not_of("0123456789") == std::string::npos, "invalid integer argument");
    std::size_t end = 0; const auto value = std::stoull(text, &end);
    require(end == text.size(), "invalid integer argument"); return value;
}
} // namespace
int main(int argc, char** argv) {
    try {
        require(argc == 7 && std::string(argv[1]) == "--target" && std::string(argv[3]) == "--seed" &&
                std::string(argv[5]) == "--iterations", "usage: --target contract|worker|identity --seed N --iterations N");
        const std::string target = argv[2]; const auto seed = integer(argv[4]), iterations = integer(argv[6]);
        require(seed && iterations && iterations <= 10000, "seed/iteration budget invalid");
        void (*check)(const std::string&) = nullptr;
        std::vector<std::string> seeds{"", "\xff", std::string("\0\r\n", 3)};
        if (target == "contract") {
            check = contractInput; contractBoundaries();
            for (const auto* text : {"requires p != null || n == 0", "ai ensures return != null if n != 0",
                    "owns(fd)", "borrows(name)", "returns owned", "policy no-absolute-paths",
                    "requires n !=", "requires p != null extra", "requires n >= -9223372036854775808",
                    "requires n <= 9223372036854775807", "// cs: requires p\n// cs: ensures return !=\n",
                    "ns::parse/1: requires p != null\nother/2: borrows(name)\n", "other: requires n !=\n"})
                seeds.emplace_back(text);
        } else if (target == "worker") {
            check = workerInput; seeds.push_back(encodeWorkerRequest(request()));
            seeds.push_back(encodeWorkerResponse(response(request())));
            WorkerRequest untouched = request(); std::string error;
            require(!decodeWorkerRequest(std::string(kWorkerPacketLimit + 1, 'x'), untouched, error), "packet cap ignored");
            ++counts.boundaries;
        } else if (target == "identity") {
            check = identityInput; seeds.push_back(encodeInputIdentity(identity()));
            seeds.emplace_back("1000-2000 r-xp 0000 08:01 42 /resilience/library.so\n2000-3000 r--p 1000 08:01 42 /resilience/library.so\n");
            seeds.emplace_back("1000-2000 rwxp 0000 08:01 42 /resilience/library.so\n");
            InputIdentity untouched = identity();
            require(!decodeInputIdentity(std::string(kInputIdentityLimit + 1, 'x'), untouched), "identity cap ignored");
            ++counts.boundaries;
        } else throw std::runtime_error("unknown target");
        std::string seed_bytes;
        std::size_t prefixes = 0;
        for (const auto& input : seeds) { field(seed_bytes, input); prefixes += input.size(); }
        const auto started = std::chrono::steady_clock::now();
        auto execute = [&](const std::string& input) {
            require(std::chrono::steady_clock::now() - started < std::chrono::seconds(30), "mutation time budget exceeded");
            check(input); ++counts.executions;
        };
        for (const auto& input : seeds) {
            execute(input);
            for (std::size_t n = 0; n < input.size(); ++n) execute(input.substr(0, n));
        }
        auto state = seed;
        for (std::uint64_t i = 0; i < iterations; ++i) {
            std::string input = seeds[random(state) % seeds.size()];
            const auto position = random(state) % (input.size() + 1);
            const char byte = static_cast<char>(random(state) & 255);
            switch (i % 5) {
            case 0: if (!input.empty()) input[position % input.size()] = byte; break;
            case 1: input.insert(position, 1, byte); break;
            case 2: if (!input.empty()) input.erase(position % input.size(), 1); break;
            case 3: input.resize(position); break;
            default: input.append(1 + random(state) % 128, byte); break;
            }
            require(input.size() <= 65536, "mutation size budget exceeded"); execute(input);
        }
        require(counts.accepted && counts.rejected, "decoder branches not exercised");
        std::cout << "{\"schema\":\"codeskeptic-resilience-seeds/v1\",\"target\":\"" << target
                  << "\",\"version\":\"" << CODESKEPTIC_VERSION << "\",\"seed\":" << seed << ",\"iterations\":" << iterations
                  << ",\"seed_sha256\":\"" << inputDigest(seed_bytes) << "\",\"seed_cases\":" << seeds.size()
                  << ",\"prefix_executions\":" << prefixes << ",\"executions\":" << counts.executions << ",\"accepted\":" << counts.accepted
                  << ",\"rejected\":" << counts.rejected << ",\"boundaries\":" << counts.boundaries << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "RESILIENCE_FAIL: " << error.what() << '\n'; return 2;
    }
}
