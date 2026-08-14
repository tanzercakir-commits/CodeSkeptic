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
//                arguments: { path, build_path?, functions?, lines? } }

// Handles a single JSON-RPC message. Returns an empty string for
// notifications (no id) — no response is written. Kept separate from
// I/O so it can be unit tested.
// The no-config overload remains useful for protocol discovery/validation,
// but analyze calls fail closed because no isolated worker executable is
// bound. Production servers must pass the Config prepared by main().
std::string handleMcpMessage(const std::string& line);
std::string handleMcpMessage(const std::string& line,
                             const Config& base_config);

// Parses and schema-validates one message through the same production path,
// but never performs analysis or filesystem discovery. Used by deterministic
// parser fuzzing so arbitrary valid JSON-RPC cannot trigger an unbounded scan.
std::string validateMcpMessage(const std::string& line);
std::string validateMcpMessage(const std::string& line,
                               const Config& base_config);

// Server loop reading line by line from stdin. Returns 0 on EOF.
// The no-config loop likewise serves protocol methods but rejects analysis.
int runMcpServer();
int runMcpServer(const Config& base_config);

} // namespace codeskeptic

#endif // CODESKEPTIC_MCP_SERVER_H
