#ifndef CODESKEPTIC_MCP_SERVER_H
#define CODESKEPTIC_MCP_SERVER_H

#include <string>

namespace codeskeptic {
class Config;

// MCP (Model Context Protocol) server — line-delimited JSON-RPC 2.0
// over stdio. Agents such as Claude Code start the `codeskeptic --serve`
// process and call the `analyze` tool after every edit; findings are
// returned as structured JSON together with their dataflow traces.
//
// Supported methods:
//   initialize, notifications/* (no response), ping, tools/list,
//   tools/call { name: "analyze",
//                arguments: { path, build_path?, functions?, lines?, disable_rules? } }
// disable_rules is a comma list of diagnostic IDs, adding request-local
// exclusions to immutable server selection defaults. Omission adds none.

// Handles one JSON-RPC 2.0 object, at most 1 MiB and 64 nested containers.
// IDs are strings or representable signed/unsigned 64-bit integers, never
// null. Invalid envelopes/budgets produce -32600 with id:null; invalid JSON
// produces -32700. Valid notifications (no id) are ignored without executing
// analyze or writing a response. Recoverable C++ request failures produce
// -32603, not a partial/clean analysis. Fatal signals and resource exhaustion
// are not contained by this in-process interface.
std::string handleMcpMessage(const std::string& line);
std::string handleMcpMessage(const std::string& line, const Config& defaults);

// Bounded newline-framed stdio loop. Limit excludes LF and optional preceding
// CR. Oversized frames are drained through the delimiter without retaining
// their remainder, then one error is sent. A final EOF-delimited frame is
// accepted. Returns 0 on normal EOF, 2 on transport I/O failure; never retries
// requests or continues after a failed response write.
int runMcpServer();
int runMcpServer(const Config& defaults);

} // namespace codeskeptic

#endif // CODESKEPTIC_MCP_SERVER_H
