#ifndef CODESKEPTIC_MCP_SERVER_H
#define CODESKEPTIC_MCP_SERVER_H

#include <string>

namespace codeskeptic {

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
std::string handleMcpMessage(const std::string& line);

// Server loop reading line by line from stdin. Returns 0 on EOF.
int runMcpServer();

} // namespace codeskeptic

#endif // CODESKEPTIC_MCP_SERVER_H
