#!/usr/bin/env python3
"""CodeSkeptic diff-review assembler (the c1 "semantic PR review" core).

Two subcommands, both invoked by scripts/review_diff.sh:

  remap-db   Rewrite a compile_commands.json so the HEAD tree's compile
             commands apply to the BASE worktree: every occurrence of the
             head root path (as a path prefix) in directory/file/command
             is rewritten to the base worktree root. This deliberately
             assumes the head revision's compile flags apply to the base
             revision — true for typical PR deltas, and the same
             pragmatic assumption CodeChecker-style local diffs make.

  assemble   Compute the finding DELTA between the base and head runs,
             fold in the contract diff (SUMMARY_DIFF lines) and the
             coverage honesty data, render a markdown review, and exit
             with the gate verdict.

Delta semantics — a faithful port of Baseline v2 (src/analyzer/
Baseline.cpp), because that file's keying is the project's one tested
definition of "the same finding":

  key = rule_id | repo-relative path | fnv1a64(trimmed line content) | message

The one deliberate difference: the file component is the REPO-RELATIVE
path (the C++ key uses the canonical absolute path, which can never
match across two checkouts of the same project). Renamed files map their
base path to the head path before keying, so a pure rename introduces no
"new" findings. Identical keys carry multiset COUNTS, and the filter
consumes budget exactly like Baseline::filter does. The end-to-end
fixture test (scripts/test_review_diff.sh) pins this parity — a finding
that merely SHIFTS lines must not resurface, and one whose line CHANGES
must (that is a feature: a changed line deserves re-review).

Soundness posture (matches the analyzer's discipline): definite findings
(error) gate; "may"-findings (warning) are reported but do not gate
unless --strict; everything not analyzed is LISTED, never silently
dropped.
"""

import argparse
import fnmatch
import json
import ntpath
import os
import posixpath
import re
import shlex
import sys
from collections import Counter
from pathlib import PurePosixPath

# ---------------------------------------------------------------------------
# Baseline-v2 key parity (see src/analyzer/Baseline.cpp)
# ---------------------------------------------------------------------------

TRIM_BYTES = b" \t\r\n"


def fnv1a64_hex(data: bytes) -> str:
    """FNV-1a 64 over raw bytes — the same constants and byte-wise walk
    as Baseline.cpp's fnv1a64Hex (stable across platforms)."""
    h = 0xCBF29CE484222325  # 1469598103934665603
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF  # 1099511628211
    return "%016x" % h


class LineCache:
    """Per-file line table, split on '\\n' only (std::getline parity;
    '\\r' survives into the line and is removed by trimming)."""

    def __init__(self):
        self._files = {}

    def line(self, path: str, lineno: int) -> bytes:
        lines = self._files.get(path)
        if lines is None:
            try:
                with open(path, "rb") as f:
                    lines = f.read().split(b"\n")
            except OSError:
                lines = []
            self._files[path] = lines
        if lineno < 1 or lineno > len(lines):
            return b""
        return lines[lineno - 1]


def finding_key(diag: dict, relpath: str, cache: LineCache) -> str:
    content = cache.line(diag["file"], diag["line"]).strip(TRIM_BYTES)
    return "%s|%s|%s|%s" % (
        diag["rule_id"], relpath, fnv1a64_hex(content), diag["message"])


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def load_diags(path):
    """The analyzer's --json output; a missing/empty path is an empty run
    (e.g. a PR that only adds files has no base side)."""
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f).get("diagnostics", [])


def rel_to_root(abs_path: str, root: str) -> str:
    """Strip `root` as a path prefix; realpath both sides first (the
    analyzer canonicalizes diagnostic paths, and mktemp roots may be
    symlinked). A path outside the root stays absolute — visible, not
    wrong."""
    p = os.path.realpath(abs_path)
    r = os.path.realpath(root).rstrip(os.sep)
    if p == r:
        return ""
    if p.startswith(r + os.sep):
        # Git diffs and rename maps always use '/'. Native Windows relative
        # paths must use the same spelling or the honesty report says a TU was
        # both analyzed and not analyzed.
        return p[len(r) + 1:].replace(os.sep, "/")
    return p


def load_renames(path):
    """old<TAB>new relative paths (git --find-renames R entries)."""
    renames = {}
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 2 and parts[0] and parts[1]:
                    renames[parts[0]] = parts[1]
    return renames


def parse_added_lines(diff_path):
    """Head-side added-line numbers per repo-relative path, from a
    unified diff (-U0 or otherwise; only +start,count of @@ headers is
    read). Used solely to MARK findings/trace steps that sit on changed
    lines — never to filter."""
    added = {}
    if not diff_path or not os.path.exists(diff_path):
        return added
    current = None
    hunk = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
    with open(diff_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("+++ "):
                target = line[4:].rstrip("\n").split("\t")[0]
                if target == "/dev/null":
                    current = None
                else:
                    current = target[2:] if target.startswith("b/") else target
            elif current is not None:
                m = hunk.match(line)
                if m:
                    start = int(m.group(1))
                    count = 1 if m.group(2) is None else int(m.group(2))
                    if count > 0:
                        added.setdefault(current, set()).update(
                            range(start, start + count))
    return added


def parse_summary_diff(path):
    """SUMMARY_DIFF <KIND> <key> <detail...> lines from the captured
    --summary-diff output. Returns (list of (kind, rest), available)."""
    if not path or not os.path.exists(path):
        return [], False
    changes = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("SUMMARY_DIFF "):
                parts = line.rstrip("\n").split(" ", 2)
                if len(parts) >= 2:
                    changes.append((parts[1], parts[2] if len(parts) > 2 else ""))
    return changes, True


def parse_head_stderr(path):
    """Coverage honesty from the head run's stderr: processed-file count
    and the iteration-cap function list (CoverageIncomplete block)."""
    processed = 0
    capped = []
    if path and os.path.exists(path):
        in_coverage = False
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "Processing file" in line:
                    processed += 1
                    in_coverage = False
                elif "analysis coverage:" in line:
                    in_coverage = True
                elif in_coverage and line.startswith("  - "):
                    capped.append(line[4:].rstrip("\n"))
                else:
                    in_coverage = False
    return processed, capped


def parse_name_status(path):
    """git diff --name-status entries: (status, old_path, new_path)."""
    entries = []
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if not parts or not parts[0]:
                    continue
                st = parts[0]
                if st[0] in ("R", "C") and len(parts) >= 3:
                    entries.append((st, parts[1], parts[2]))
                elif len(parts) >= 2:
                    entries.append((st, parts[1], parts[1]))
    return entries


SRC_EXT = (".c", ".cpp", ".cc", ".cxx")
HDR_EXT = (".h", ".hpp", ".hh", ".hxx", ".inl")


# ---------------------------------------------------------------------------
# Delta — Baseline::filter's consume-budget algorithm over two runs
# ---------------------------------------------------------------------------

def compute_delta(base_diags, head_diags, base_root, head_root, renames):
    cache = LineCache()

    base_keys = Counter()
    for d in base_diags:
        rel = rel_to_root(d["file"], base_root)
        rel = renames.get(rel, rel)  # align a renamed file with its head path
        base_keys[finding_key(d, rel, cache)] += 1

    budget = Counter(base_keys)
    new = []
    for d in head_diags:
        rel = rel_to_root(d["file"], head_root)
        k = finding_key(d, rel, cache)
        if budget[k] > 0:
            budget[k] -= 1
        else:
            new.append((d, rel))
    fixed = sum(budget.values())  # base findings nothing at head consumed
    return new, fixed


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_finding(diag, rel, head_root, added_lines):
    mark = " *(on changed line)*" if diag["line"] in added_lines.get(rel, ()) else ""
    tier_mark = (
        " *(experimental, report-only)*"
        if not diag.get("blocks_verdict", True) else ""
    )
    lines = ["- **[%s] %s** `%s:%d` in `%s` — %s%s" % (
        diag["severity"], diag["rule_id"], rel, diag["line"],
        diag.get("function", "?"), diag["message"], mark + tier_mark)]
    for note in diag.get("notes", []):
        nrel = rel_to_root(note["file"], head_root)
        nmark = " *(changed)*" if note["line"] in added_lines.get(nrel, ()) else ""
        lines.append("  - `%s:%d` %s%s" % (nrel, note["line"], note["message"], nmark))
    return lines


def cmd_assemble(args):
    base_diags = load_diags(args.base_json)
    head_diags = load_diags(args.head_json)
    renames = load_renames(args.renames)
    added_lines = parse_added_lines(args.diff)
    sum_changes, sum_available = parse_summary_diff(args.summary_diff)
    processed, capped = parse_head_stderr(args.head_stderr)
    name_status = parse_name_status(args.name_status)

    analyzed_rel = set()
    if args.head_files and os.path.exists(args.head_files):
        with open(args.head_files, "r", encoding="utf-8") as f:
            for line in f:
                p = line.strip()
                if p:
                    analyzed_rel.add(rel_to_root(p, args.head_root))

    new, fixed = compute_delta(base_diags, head_diags, args.base_root,
                               args.head_root, renames)
    new_errors = [(d, r) for d, r in new if d["severity"] == "error"]
    new_warnings = [(d, r) for d, r in new if d["severity"] != "error"]
    blocking = [(d, r) for d, r in new
                if d.get("blocks_verdict", True)]
    blocking_errors = [(d, r) for d, r in blocking
                       if d["severity"] == "error"]
    blocking_warnings = [(d, r) for d, r in blocking
                         if d["severity"] != "error"]
    report_only = [(d, r) for d, r in new
                   if not d.get("blocks_verdict", True)]

    # Human label counts by ACTUAL severity (an assumption finding is
    # info, not warning); the REVIEW_RESULT machine line keeps its
    # stable two-bucket schema (new_warnings = everything non-error).
    # Verdict gating is independently determined by blocks_verdict.
    sev_counts = Counter(d["severity"] for d, _ in new)
    sev_label = ", ".join(
        "%d %s" % (sev_counts[s], s)
        for s in ("error", "warning", "info") if s in sev_counts) or "none"
    for s in sev_counts:
        if s not in ("error", "warning", "info"):
            sev_label += ", %d %s" % (sev_counts[s], s)

    weakened = [rest for kind, rest in sum_changes if kind == "WEAKENED"]
    other_changes = [(k, rest) for k, rest in sum_changes if k != "WEAKENED"]

    gate_fail = bool(blocking_errors) or bool(weakened) or \
        (args.strict and bool(blocking_warnings))

    # --- render -----------------------------------------------------------
    md = []
    md.append("# CodeSkeptic diff review")
    md.append("")
    md.append("Base `%s` -> head `%s`." % (args.base_label, args.head_label))
    if gate_fail:
        reasons = []
        if blocking_errors:
            reasons.append("%d new blocking error(s)" % len(blocking_errors))
        if args.strict and blocking_warnings:
            reasons.append("%d new blocking warning(s) (--strict)" %
                           len(blocking_warnings))
        if weakened:
            reasons.append("%d weakened contract(s)" % len(weakened))
        md.append("**Verdict: FAIL** — " + ", ".join(reasons))
    else:
        md.append("**Verdict: PASS** — no new blocking findings, "
                  "no weakened contracts")

    md.append("")
    md.append("## New findings (%s)" % sev_label)
    if new:
        for d, rel in new_errors + new_warnings:
            md.extend(render_finding(d, rel, args.head_root, added_lines))
    else:
        md.append("None — the change introduces no findings in the "
                  "analyzed files.")

    md.append("")
    md.append("## Fixed findings")
    md.append("%d finding(s) present at base are gone at head." % fixed
              if fixed else "None.")

    md.append("")
    md.append("## Contract changes")
    if not sum_available:
        md.append("Contract diff skipped (no base-side functions to "
                  "compare — e.g. an added-files-only change).")
    elif not sum_changes:
        md.append("None — inferred function contracts are unchanged.")
    else:
        # WEAKENED is the gate signal: always in full. The rest is
        # informational and easily macro-flooded (each gtest TEST()
        # expands to several generated symbols) — cap it, but SAY how
        # much was capped: hidden-but-counted, never silently dropped.
        for rest in weakened:
            md.append("- **WEAKENED** %s" % rest)
        cap = 8
        for kind, rest in other_changes[:cap]:
            md.append("- %s %s" % (kind, rest))
        if len(other_changes) > cap:
            md.append("- … and %d more non-gating contract change(s)" %
                      (len(other_changes) - cap))

    md.append("")
    md.append("## Coverage")
    src_changed = [e for e in name_status
                   if e[2].endswith(SRC_EXT) or e[1].endswith(SRC_EXT)]
    md.append("- Changed files: %d total, %d C/C++ source; analyzed %d "
              "(head side, whole file — not just hunks)." %
              (len(name_status), len(src_changed), len(analyzed_rel)))
    excludes = args.exclude or []

    def excluded(rel):
        return any(fnmatch.fnmatch(rel, pat) for pat in excludes)

    not_analyzed = []
    for st, old, new_p in name_status:
        if st.startswith("D"):
            not_analyzed.append("`%s` (deleted — base-only findings in it "
                                "are not counted as fixed)" % old)
        elif new_p.endswith(HDR_EXT):
            not_analyzed.append("`%s` (header — its own TU impact is only "
                                "seen through changed .c/.cpp files that "
                                "include it)" % new_p)
        elif not new_p.endswith(SRC_EXT):
            not_analyzed.append("`%s` (not a C/C++ source)" % new_p)
        elif excluded(new_p):
            not_analyzed.append("`%s` (excluded by --exclude)" % new_p)
        elif new_p not in analyzed_rel and not st.startswith("D"):
            not_analyzed.append("`%s` (not analyzed)" % new_p)
    if not_analyzed:
        md.append("- Not analyzed (\"no warning\" here means NOT CHECKED, "
                  "not \"correct\"):")
        for item in not_analyzed:
            md.append("  - %s" % item)
    if capped:
        md.append("- Functions that hit the iteration cap at head "
                  "(findings may be incomplete): %s" %
                  ", ".join("`%s`" % f for f in capped))
    else:
        md.append("- All analyzed head functions reached a dataflow "
                  "fixpoint.")
    if blocking_warnings and not args.strict:
        md.append("- New supported warnings are reported but do not gate; "
                  "pass --strict to gate them.")
    if report_only:
        md.append(
            "- %d experimental finding(s) are report-only and never gate, "
            "including under --strict." % len(report_only)
        )

    result_line = ("REVIEW_RESULT new_errors=%d new_warnings=%d fixed=%d "
                   "weakened=%d gate=%s" %
                   (len(new_errors), len(new_warnings), fixed,
                    len(weakened), "fail" if gate_fail else "pass"))
    md.append("")
    md.append("---")
    md.append("`%s`" % result_line)
    text = "\n".join(md) + "\n"

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(result_line)
    else:
        sys.stdout.write(text)

    if gate_fail and args.gate == "error":
        return 1
    return 0


# ---------------------------------------------------------------------------
# remap-db
# ---------------------------------------------------------------------------

def _is_windows_path(path):
    return (re.match(r"^[A-Za-z]:[/\\]", path) is not None or
            path.startswith("\\\\") or path.startswith("//"))


def _path_pattern_body(path):
    """Return a regex body with the path spelling's separator semantics."""
    path = path.rstrip("/\\")
    if not path:
        raise ValueError("path prefix must not be empty")
    separator = r"[/\\]+" if _is_windows_path(path) else r"/+"
    split_pattern = r"([/\\]+)" if _is_windows_path(path) else r"(/+)"
    pieces = re.split(split_pattern, path)
    return "".join(
        separator if re.fullmatch(split_pattern, piece) else re.escape(piece)
        for piece in pieces
        if piece
    )


_ATTACHED_PATH_OPTIONS = (
    "-isysroot", "-iframework", "-idirafter", "-include", "-imacros",
    "-isystem", "-iquote", "-MF", "-MJ", "-I", "/I", "-F", "-o",
)
_ASSIGNED_PATH_OPTIONS = (
    "--sysroot=", "--gcc-toolchain=", "--serialize-diagnostics=",
    "-resource-dir=", "-fmodule-map-file=", "-fmodules-cache-path=",
    "-fprofile-instr-use=", "-fprofile-sample-use=",
)


def _path_option_pattern():
    options = sorted(_ATTACHED_PATH_OPTIONS + _ASSIGNED_PATH_OPTIONS,
                     key=len, reverse=True)
    return "(?:" + "|".join(re.escape(value) for value in options) + ")?"


def _path_regex_flags(path):
    """Match host-independent path semantics, not the current test host."""
    return re.IGNORECASE if _is_windows_path(path) else 0


def _path_prefix_pattern(path):
    # A repository path is a command/JSON token, never a suffix embedded in
    # another path. Keep attached compiler options (-I/path, -isystem/path,
    # /IC:\\path, etc.) working while refusing `/cache` + `/repo/path` false
    # matches that would silently retarget an external dependency.
    option = _path_option_pattern()
    boundary = r"(?=[/\\\"']|$)" if _is_windows_path(path) \
        else r"(?=[/\"']|$)"
    return re.compile(r"\A(?P<prefix>[\"']?" + option + r"[\"']?)" +
                      r"(?P<path>" +
                      _path_pattern_body(path) +
                      r")" + boundary, _path_regex_flags(path))


def _replace_bounded_path(pattern, value, replacement):
    """Replace the path capture while preserving an attached option."""
    return pattern.sub(
        lambda match: match.group(0)[:match.start("path") - match.start(0)] +
        replacement,
        value,
    )


def _map_command_tokens(value, transform, windows=False):
    """Transform shell-like tokens without losing their original quoting."""
    def decode_token(raw):
        decoded = []
        quote = None
        index = 0
        while index < len(raw):
            char = raw[index]
            if quote == "'":
                if char == "'":
                    quote = None
                else:
                    decoded.append(char)
                index += 1
                continue
            if char in ("'", '"'):
                if quote is None:
                    quote = char
                    index += 1
                    continue
                if quote == char:
                    quote = None
                    index += 1
                    continue
            if char == "\\" and index + 1 < len(raw):
                following = raw[index + 1]
                # Decode POSIX quoting where it is unambiguous for a path,
                # while preserving Windows separators such as C:\\Projects.
                if quote == '"':
                    # Inside double quotes POSIX preserves backslash unless
                    # it escapes one of the shell-special double-quote bytes.
                    escapable = following in '\\"$`\n'
                elif windows:
                    escapable = following.isspace() or following in "\\\"'"
                else:
                    # POSIX quote-free backslash escapes the next byte.
                    escapable = True
                if escapable:
                    decoded.append(following)
                    index += 2
                    continue
            decoded.append(char)
            index += 1
        if quote is not None:
            return None
        return "".join(decoded)

    def transform_raw(raw):
        if not raw:
            return raw
        decoded = decode_token(raw)
        if decoded is None:
            return raw
        rewritten = transform(decoded)
        if rewritten == decoded:
            return raw
        return shlex.quote(rewritten)

    pieces = []
    start = 0
    quote = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char.isspace():
            pieces.append(transform_raw(value[start:index]))
            pieces.append(char)
            start = index + 1
    pieces.append(transform_raw(value[start:]))
    return "".join(pieces)


def _rewrite_compile_paths(value, src_roots, dst_root, protect_roots=(),
                           command=True):
    """Rewrite equivalent source-root spellings, preserving build paths."""
    src_roots = tuple(dict.fromkeys(
        root.rstrip("/\\") for root in src_roots if root.rstrip("/\\")))
    protect_roots = tuple(dict.fromkeys(
        root.rstrip("/\\") for root in protect_roots
        if root.rstrip("/\\") and all(
            os.path.normcase(root.rstrip("/\\")) != os.path.normcase(source)
            for source in src_roots)))
    def rewrite_token(token_value):
        hidden = []

        def hide(match):
            marker = f"\x00CS_PROTECTED_{len(hidden)}\x00"
            hidden.append((marker, match.group("path")))
            return marker

        for protect in sorted(protect_roots, key=len, reverse=True):
            pattern = _path_prefix_pattern(protect)
            token_value = pattern.sub(
                lambda match: match.group("prefix") + hide(match),
                token_value)

        # A compile DB may reuse dependencies from an older sibling build.
        # Preserve those HEAD paths in the source-only base worktree.
        for src_root in sorted(src_roots, key=len, reverse=True):
            option = _path_option_pattern()
            separator = r"[/\\]+" if _is_windows_path(src_root) else r"/+"
            boundary = r"(?=[/\\\"']|$)" if _is_windows_path(src_root) \
                else r"(?=[/\"']|$)"
            build_root = re.compile(
                r"\A(?P<prefix>[\"']?" + option + r"[\"']?)" +
                r"(?P<path>" + _path_pattern_body(src_root)
                + separator +
                r"(?:build|cmake-build)(?:[-_.][^/\\\s\"\']*)?"
                + r")" + boundary, _path_regex_flags(src_root))
            token_value = build_root.sub(
                lambda match: match.group("prefix") + hide(match),
                token_value)
        for src_root in sorted(src_roots, key=len, reverse=True):
            token_value = _replace_bounded_path(
                _path_prefix_pattern(src_root), token_value, dst_root)
        for marker, original in hidden:
            token_value = token_value.replace(marker, original)
        return token_value

    if command:
        return _map_command_tokens(
            value, rewrite_token,
            windows=any(_is_windows_path(root) for root in src_roots))
    return rewrite_token(value)


def _rewrite_compile_path(value, src_root, dst_root, protect=None,
                          command=True):
    """Rewrite one source-root spelling while preserving build paths."""
    protects = () if protect is None else (protect,)
    return _rewrite_compile_paths(
        value, (src_root,), dst_root, protects, command=command)


def _rewrite_compile_renames(value, dst_root, renames, command=True):
    """Map head-side renamed paths onto their old base-side paths."""
    path_module = ntpath if _is_windows_path(dst_root) else posixpath
    pairs = []
    for old, new in renames:
        old_path = path_module.join(dst_root, old)
        new_path = path_module.join(dst_root, new)
        pairs.append((new_path, old_path))
    def rewrite_token(token_value):
        for new_path, old_path in sorted(
                pairs, key=lambda pair: len(pair[0]), reverse=True):
            token_value = _replace_bounded_path(
                _path_prefix_pattern(new_path), token_value, old_path)
        return token_value

    if command:
        return _map_command_tokens(
            value, rewrite_token, windows=_is_windows_path(dst_root))
    return rewrite_token(value)


def _rewrite_relative_renames(value, directory, dst_root, renames,
                              command=True):
    """Map directory-relative compile inputs by exact repository path."""
    windows = _is_windows_path(dst_root) or _is_windows_path(directory)
    path_module = ntpath if windows else posixpath

    def norm(path):
        normalized = path_module.normpath(path)
        return normalized.casefold() if windows else normalized

    pairs = tuple(
        (norm(path_module.join(dst_root, new)),
         path_module.normpath(path_module.join(dst_root, old)))
        for old, new in renames)

    def rewrite_token(token_value):
        if not token_value or path_module.isabs(token_value):
            return token_value
        candidate = norm(path_module.join(directory, token_value))
        for new_absolute, old_absolute in pairs:
            if candidate == new_absolute:
                return path_module.relpath(old_absolute, directory)
        return token_value

    if command:
        return _map_command_tokens(value, rewrite_token, windows=windows)
    return rewrite_token(value)


def cmd_remap_db(args):
    source_spellings = tuple(dict.fromkeys(
        candidate.rstrip(os.sep) for candidate in (
            os.path.abspath(args.from_root),
            os.path.realpath(args.from_root),
        ) if candidate.rstrip(os.sep)))
    src_root = source_spellings[0] if source_spellings else ""
    dst_root = os.path.realpath(args.to_root).rstrip(os.sep)
    if not src_root or src_root == os.sep:
        print("[review] refusing to remap from root '%s'" % src_root,
              file=sys.stderr)
        return 2
    # The BUILD directory is typically inside the repo root but is NOT in
    # git — a worktree has no build/. Paths under it (generated headers,
    # -Ibuild/_deps/...) must keep pointing at the HEAD build: protect
    # them with a sentinel through the root rewrite. Head build outputs
    # applied to base sources is the same pragmatic assumption as
    # reusing head compile flags at all.
    protect_spellings = ()
    if args.protect:
        candidates = tuple(dict.fromkeys(
            candidate.rstrip(os.sep) for candidate in (
                os.path.abspath(args.protect),
                os.path.realpath(args.protect),
            ) if candidate.rstrip(os.sep)))
        accepted = []
        for protect in candidates:
            for source in source_spellings:
                try:
                    common = os.path.commonpath((source, protect))
                except ValueError:
                    continue
                if (os.path.normcase(common) == os.path.normcase(source) and
                        os.path.normcase(protect) != os.path.normcase(source)):
                    accepted.append(protect)
                    break
        protect_spellings = tuple(dict.fromkeys(accepted))

    renames = []
    if args.renames:
        with open(args.renames, "r", encoding="utf-8") as stream:
            for line_number, raw in enumerate(stream, 1):
                line = raw.rstrip("\n")
                if not line:
                    continue
                fields = line.split("\t")
                if len(fields) != 2:
                    raise ValueError(
                        f"malformed rename map at line {line_number}")
                old, new = fields
                for path in (old, new):
                    if (not path or os.path.isabs(path) or
                            ".." in PurePosixPath(path).parts):
                        raise ValueError(
                            f"unsafe rename path at line {line_number}")
                renames.append((old, new))

    def rw(s, command=False):
        rewritten = _rewrite_compile_paths(
            s, source_spellings, dst_root, protect_spellings, command=command)
        return _rewrite_compile_renames(
            rewritten, dst_root, renames, command=command)

    with open(args.src, "r", encoding="utf-8") as f:
        entries = json.load(f)
    for e in entries:
        if isinstance(e.get("directory"), str):
            e["directory"] = rw(e["directory"])
        directory = e.get("directory")
        if not isinstance(directory, str) or not os.path.isabs(directory):
            directory = dst_root
        if isinstance(e.get("file"), str):
            e["file"] = _rewrite_relative_renames(
                rw(e["file"]), directory, dst_root, renames, command=False)
        if isinstance(e.get("output"), str):
            e["output"] = rw(e["output"])
        if isinstance(e.get("command"), str):
            e["command"] = _rewrite_relative_renames(
                rw(e["command"], command=True), directory, dst_root,
                renames, command=True)
        if isinstance(e.get("arguments"), list):
            e["arguments"] = [
                _rewrite_relative_renames(
                    rw(value), directory, dst_root, renames, command=False)
                if isinstance(value, str) else value
                for value in e["arguments"]
            ]
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=1)
    return 0


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_remap = sub.add_parser("remap-db")
    p_remap.add_argument("--src", required=True)
    p_remap.add_argument("--from-root", required=True)
    p_remap.add_argument("--to-root", required=True)
    p_remap.add_argument("--protect", help="path prefix to keep un-remapped "
                         "(the head build dir — absent from a worktree)")
    p_remap.add_argument("--renames", help="tab-separated old/new paths from "
                         "the Git rename map")
    p_remap.add_argument("--out", required=True)

    p_asm = sub.add_parser("assemble")
    p_asm.add_argument("--base-json")
    p_asm.add_argument("--head-json")
    p_asm.add_argument("--base-root", required=True)
    p_asm.add_argument("--head-root", required=True)
    p_asm.add_argument("--renames")
    p_asm.add_argument("--diff")
    p_asm.add_argument("--name-status")
    p_asm.add_argument("--head-files")
    p_asm.add_argument("--head-stderr")
    p_asm.add_argument("--summary-diff")
    p_asm.add_argument("--gate", choices=["error", "warn"], default="error")
    p_asm.add_argument("--strict", action="store_true")
    p_asm.add_argument("--exclude", action="append",
                       help="glob over repo-relative paths whose changed "
                            "files were skipped (labeling only; the "
                            "actual skip happens in review_diff.sh)")
    p_asm.add_argument("--base-label", default="base")
    p_asm.add_argument("--head-label", default="head")
    p_asm.add_argument("--out")

    args = parser.parse_args()
    if args.cmd == "remap-db":
        return cmd_remap_db(args)
    return cmd_assemble(args)


if __name__ == "__main__":
    sys.exit(main())
