#ifndef ZERODEFECT_MCP_SERVER_H
#define ZERODEFECT_MCP_SERVER_H

#include <string>

namespace zerodefect {

// MCP (Model Context Protocol) sunucusu — stdio uzerinden satir-ayrimli
// JSON-RPC 2.0. Claude Code gibi ajanlar `zerodefect --serve` surecini
// baslatir ve her duzenleme sonrasi `analyze` aracini cagirir; bulgular
// dataflow izleriyle birlikte yapisal JSON olarak doner.
//
// Desteklenen metodlar:
//   initialize, notifications/* (yanit yok), ping, tools/list,
//   tools/call { name: "analyze",
//                arguments: { path, build_path?, functions?, lines? } }

// Tek bir JSON-RPC mesajini isler. Bildirimlerde (id'siz) bos dize
// doner — yanit yazilmaz. I/O'dan ayri tutulur ki birim test edilebilsin.
std::string handleMcpMessage(const std::string& line);

// stdin'den satir satir okuyan sunucu dongusu. EOF'ta 0 doner.
int runMcpServer();

} // namespace zerodefect

#endif // ZERODEFECT_MCP_SERVER_H
