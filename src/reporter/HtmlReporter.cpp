#include "reporter/HtmlReporter.h"

#include "core/Messages.h"

#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

namespace {

std::string escapeHtml(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;        break;
        }
    }
    return out;
}

std::string toLower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// Per-file line cache: the source is read once for the context
// excerpts. Embedded at report generation time — the context is not
// lost when the report is moved to another machine.
using LineCache = std::map<std::string, std::vector<std::string>>;

const std::vector<std::string>& fileLines(LineCache& cache,
                                          const std::string& path) {
    auto it = cache.find(path);
    if (it != cache.end()) return it->second;
    std::vector<std::string> lines;
    std::ifstream in(path);
    std::string l;
    while (std::getline(in, l)) lines.push_back(l);
    return cache.emplace(path, std::move(lines)).first->second;
}

// target line highlighted, ±2 lines of context; returns empty if the
// source cannot be read
std::string sourceContext(LineCache& cache, const std::string& path,
                          unsigned line) {
    const auto& lines = fileLines(cache, path);
    if (line == 0 || line > lines.size()) return {};

    const unsigned from = line > 2 ? line - 2 : 1;
    const unsigned to =
        std::min<unsigned>(line + 2, static_cast<unsigned>(lines.size()));

    std::ostringstream out;
    out << "<pre class=\"ctx\">";
    for (unsigned n = from; n <= to; ++n) {
        out << "<span class=\"cl" << (n == line ? " hit" : "") << "\">"
            << n << "</span>" << escapeHtml(lines[n - 1])
            << (n < to ? "\n" : "");
    }
    out << "</pre>";
    return out.str();
}

std::string baseName(const std::string& path) {
    auto pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

const char* kStyle = R"css(
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a202c;--muted:#64748b;--line:#e2e8f0;
--err:#dc2626;--warn:#d97706;--info:#2563eb;--hit:#fde68a;--code:#f1f5f9}
@media(prefers-color-scheme:dark){:root{--bg:#0f172a;--card:#1e293b;
--fg:#e2e8f0;--muted:#94a3b8;--line:#334155;--err:#f87171;--warn:#fbbf24;
--info:#60a5fa;--hit:#78350f;--code:#0b1220}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px 16px}
header h1{margin:0;font-size:22px}header .sub{color:var(--muted);margin:4px 0 0}
.cards{display:flex;flex-wrap:wrap;gap:8px;margin:20px 0 8px}
.chip{border:1px solid var(--line);background:var(--card);border-radius:999px;
padding:6px 14px;cursor:pointer;font-size:14px;user-select:none}
.chip .n{font-weight:700;margin-left:6px}
.chip.active{outline:2px solid var(--info)}
.chip.err .n{color:var(--err)}.chip.warn .n{color:var(--warn)}
.chip.info .n{color:var(--info)}
#q{width:100%;margin:12px 0 20px;padding:10px 14px;border-radius:10px;
border:1px solid var(--line);background:var(--card);color:var(--fg);font-size:15px}
.finding{background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:14px 16px;margin-bottom:12px}
.head{display:flex;flex-wrap:wrap;gap:10px;align-items:baseline}
.badge{font-size:12px;font-weight:700;text-transform:uppercase;
border-radius:6px;padding:2px 8px;color:#fff}
.badge.error{background:var(--err)}.badge.warning{background:var(--warn)}
.badge.info{background:var(--info)}
.rule{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--muted)}
.loc{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.fn{color:var(--muted);font-size:13px}
.msg{margin:8px 0 0;font-size:15px}
details{margin-top:10px}summary{cursor:pointer;color:var(--muted);font-size:14px}
.step{margin:10px 0 0;font-size:14px}
.ctx{background:var(--code);border:1px solid var(--line);border-radius:8px;
padding:8px 10px;overflow-x:auto;font:12.5px/1.6 ui-monospace,Menlo,Consolas,monospace;
margin:6px 0 0}
.cl{display:inline-block;width:3.5em;color:var(--muted);user-select:none}
.cl.hit{color:inherit;font-weight:700;background:var(--hit);border-radius:4px}
.empty{color:var(--muted);text-align:center;padding:40px 0}
footer{color:var(--muted);font-size:13px;margin-top:28px}
)css";

const char* kScript = R"js(
var state={sev:null,rule:null,q:''};
function apply(){
  var shown=0;
  document.querySelectorAll('.finding').forEach(function(f){
    var ok=(!state.sev||f.dataset.sev===state.sev)&&
           (!state.rule||f.dataset.rule===state.rule)&&
           (!state.q||f.dataset.text.indexOf(state.q)>=0);
    f.style.display=ok?'':'none';if(ok)shown++;
  });
  var c=document.getElementById('shown');if(c)c.textContent=shown;
  document.querySelectorAll('.chip[data-sev]').forEach(function(ch){
    ch.classList.toggle('active',state.sev===ch.dataset.sev);});
  document.querySelectorAll('.chip[data-rule]').forEach(function(ch){
    ch.classList.toggle('active',state.rule===ch.dataset.rule);});
}
document.addEventListener('click',function(e){
  var ch=e.target.closest('.chip');if(!ch)return;
  if(ch.dataset.sev!==undefined)
    state.sev=state.sev===ch.dataset.sev?null:ch.dataset.sev;
  if(ch.dataset.rule!==undefined)
    state.rule=state.rule===ch.dataset.rule?null:ch.dataset.rule;
  apply();
});
document.getElementById('q').addEventListener('input',function(e){
  state.q=e.target.value.toLowerCase();apply();
});
)js";

} // anonymous namespace

namespace zerodefect {

HtmlReporter::HtmlReporter(const std::string& output_path)
    : output_path_(output_path) {}

void HtmlReporter::report(const DiagnosticList& diagnostics) {
    std::ofstream file(output_path_);
    if (!file.is_open()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return;
    }

    // Summary counts
    std::map<std::string, size_t> bySeverity;
    std::map<std::string, size_t> byRule;
    for (const auto& d : diagnostics) {
        ++bySeverity[d.severityToString()];
        ++byRule[d.rule_id];
    }

    char stamp[32] = "";
    std::time_t now = std::time(nullptr);
    if (std::tm* tm = std::localtime(&now))
        std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M", tm);

    file << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
         << "<meta charset=\"utf-8\">\n"
         << "<meta name=\"viewport\" content=\"width=device-width, "
            "initial-scale=1\">\n"
         << "<title>ZeroDefect Report</title>\n"
         << "<style>" << kStyle << "</style>\n</head>\n<body>\n"
         << "<div class=\"wrap\">\n<header>\n<h1>ZeroDefect Report</h1>\n"
         << "<p class=\"sub\"><span id=\"shown\">" << diagnostics.size()
         << "</span> / " << diagnostics.size()
         << " finding(s) &middot; generated " << stamp << "</p>\n"
         << "</header>\n";

    // Cards = filters: a severity row + a rule row
    file << "<div class=\"cards\">\n";
    const char* sevs[] = {"error", "warning", "info"};
    const char* cls[] = {"err", "warn", "info"};
    for (int i = 0; i < 3; ++i) {
        auto it = bySeverity.find(sevs[i]);
        if (it == bySeverity.end()) continue;
        file << "<span class=\"chip " << cls[i] << "\" data-sev=\""
             << sevs[i] << "\">" << sevs[i] << "<span class=\"n\">"
             << it->second << "</span></span>\n";
    }
    file << "</div>\n<div class=\"cards\">\n";
    for (const auto& [rule, count] : byRule) {
        file << "<span class=\"chip\" data-rule=\"" << escapeHtml(rule)
             << "\">" << escapeHtml(rule) << "<span class=\"n\">" << count
             << "</span></span>\n";
    }
    file << "</div>\n";

    file << "<input id=\"q\" type=\"search\" placeholder=\"Filter by "
            "file, function or message&hellip;\">\n<main>\n";

    if (diagnostics.empty()) {
        file << "<p class=\"empty\">Clean! No issues found.</p>\n";
    }

    LineCache cache;
    for (const auto& d : diagnostics) {
        const std::string sev = d.severityToString();
        std::string haystack = toLower(d.file + " " + d.function + " " +
                                       d.message + " " + d.rule_id);

        file << "<article class=\"finding\" data-sev=\"" << sev
             << "\" data-rule=\"" << escapeHtml(d.rule_id)
             << "\" data-text=\"" << escapeHtml(haystack) << "\">\n"
             << "<div class=\"head\"><span class=\"badge " << sev << "\">"
             << sev << "</span><span class=\"rule\">" << escapeHtml(d.rule_id)
             << "</span><span class=\"loc\">" << escapeHtml(d.file) << ":"
             << d.line << ":" << d.column << "</span>";
        if (!d.function.empty())
            file << "<span class=\"fn\">in " << escapeHtml(d.function)
                 << "()</span>";
        file << "</div>\n<p class=\"msg\">" << escapeHtml(d.message)
             << "</p>\n";

        // Trace + finding point, with source context
        std::string findingCtx = sourceContext(cache, d.file, d.line);
        if (!d.notes.empty() || !findingCtx.empty()) {
            file << "<details><summary>Dataflow trace";
            if (!d.notes.empty())
                file << " (" << d.notes.size() << " step"
                     << (d.notes.size() > 1 ? "s" : "") << ")";
            file << "</summary>\n";
            for (const auto& note : d.notes) {
                file << "<div class=\"step\">&rarr; <span class=\"loc\">"
                     << escapeHtml(baseName(note.file)) << ":" << note.line
                     << "</span> " << escapeHtml(note.message)
                     << sourceContext(cache, note.file, note.line)
                     << "</div>\n";
            }
            file << "<div class=\"step\">&#9679; <span class=\"loc\">"
                 << escapeHtml(baseName(d.file)) << ":" << d.line
                 << "</span> " << escapeHtml(d.message) << findingCtx
                 << "</div>\n</details>\n";
        }
        file << "</article>\n";
    }

    file << "</main>\n<footer>ZeroDefect &middot; self-contained report "
            "&mdash; works offline</footer>\n</div>\n"
         << "<script>" << kScript << "</script>\n</body>\n</html>\n";
}

std::string HtmlReporter::format() const {
    return "html";
}

} // namespace zerodefect
