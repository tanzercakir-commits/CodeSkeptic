#!/usr/bin/env python3
"""Prove the runtime rule registry, README, and rule docs agree."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "src" / "core" / "RuleCapabilities.def"
CAPABILITIES_CPP = ROOT / "src" / "core" / "Capabilities.cpp"
DOCS = (ROOT / "README.md", ROOT / "docs" / "capabilities.md")

ENTRY = re.compile(
    r'^CODESKEPTIC_RULE_CAPABILITY\("([^"]+)", '
    r'(Supported|Experimental), (true|false), (true|false), '
    r'(true|false), "([^"]*)"\)$'
)
ROW_ID = re.compile(r'^`([^`]+)`$')

PRODUCT_ARRAY = re.compile(
    r"const std::vector<TieredCapability> (k\w+) = \{(.*?)\n\};",
    re.DOTALL,
)
PRODUCT_ENTRY = re.compile(
    r'^\s*\{"([^"]+)", CapabilityTier::'
    r'(Supported|Experimental|OutOfScope)\},\s*$'
)
PRODUCT_GROUPS = {
    "kLanguages": "Language", "kFrontends": "Frontend",
    "kOutputs": "Output", "kModes": "Mode", "kOutOfScope": "Non-goal",
}

def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


entries: dict[str, tuple[str, bool, bool, bool]] = {}
for line_no, raw in enumerate(REGISTRY.read_text(encoding="utf-8").splitlines(), 1):
    if not raw.startswith("CODESKEPTIC_RULE_CAPABILITY"):
        continue
    match = ENTRY.fullmatch(raw)
    if not match:
        fail(f"unparseable registry entry at {REGISTRY}:{line_no}")
    rule_id, tier_name, default, quality, blocking, _ = match.groups()
    tier = tier_name.lower()
    values = (tier, default == "true", quality == "true", blocking == "true")
    if rule_id in entries:
        fail(f"duplicate registry id: {rule_id}")
    entries[rule_id] = values

if len(entries) != 14:
    fail(f"expected 14 public rule capabilities, got {len(entries)}")

for rule_id, (tier, default, quality, blocking) in entries.items():
    if tier == "supported" and not (default and quality and blocking):
        fail(f"supported invariant violated by {rule_id}")
    if tier == "experimental" and blocking:
        fail(f"experimental rule blocks verdict: {rule_id}")

product_entries: dict[str, tuple[str, str]] = {}
source = CAPABILITIES_CPP.read_text(encoding="utf-8")
arrays = {name: body for name, body in PRODUCT_ARRAY.findall(source)}
if set(arrays) != set(PRODUCT_GROUPS):
    fail(
        "runtime product capability groups differ: "
        f"expected={sorted(PRODUCT_GROUPS)} got={sorted(arrays)}"
    )
for array_name, group in PRODUCT_GROUPS.items():
    for raw in arrays[array_name].splitlines():
        if not raw.strip():
            continue
        match = PRODUCT_ENTRY.fullmatch(raw)
        if not match:
            fail(f"unparseable runtime product capability: {raw.strip()}")
        capability_id, tier_name = match.groups()
        tier = re.sub(r"(?<!^)(?=[A-Z])", "-", tier_name).lower()
        if capability_id in product_entries:
            fail(f"duplicate product capability id: {capability_id}")
        product_entries[capability_id] = (group, tier)

capability_text = (ROOT / "docs" / "capabilities.md").read_text(
    encoding="utf-8"
)
product_section = capability_text.split("## Product surfaces", 1)[1].split(
    "## Finding rules", 1
)[0]
documented_products: dict[str, tuple[str, str]] = {}
for line in product_section.splitlines():
    if not line.startswith("|"):
        continue
    cells = [cell.strip() for cell in line.strip("|").split("|")]
    if len(cells) != 4:
        continue
    match = ROW_ID.fullmatch(cells[2])
    if match:
        documented_products[match.group(1)] = (cells[0], cells[3])
if documented_products != product_entries:
    fail(
        "docs/capabilities.md product capabilities differ: "
        f"expected={product_entries} got={documented_products}"
    )

for document in DOCS:
    rows: dict[str, tuple[str, str]] = {}
    text = document.read_text(encoding="utf-8")
    if document.name == "capabilities.md":
        text = text.split("## Finding rules", 1)[1]
    else:
        text = text.split("## Rules", 1)[1].split("## The numbers", 1)[0]
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        for index, cell in enumerate(cells):
            match = ROW_ID.fullmatch(cell)
            if not match or index + 1 >= len(cells):
                continue
            tier = cells[index + 1]
            if tier not in {"supported", "experimental"}:
                continue
            verdicts = [
                value for value in cells[index + 2 :]
                if value in {"blocking", "report-only"}
            ]
            if len(verdicts) != 1:
                fail(
                    f"{document.relative_to(ROOT)} has ambiguous verdict "
                    f"for {match.group(1)}"
                )
            rows[match.group(1)] = (tier, verdicts[0])
    if set(rows) != set(entries):
        fail(
            f"{document.relative_to(ROOT)} rule ids differ: "
            f"missing={sorted(set(entries) - set(rows))} "
            f"extra={sorted(set(rows) - set(entries))}"
        )
    for rule_id, (tier, _, _, blocking) in entries.items():
        expected = (tier, "blocking" if blocking else "report-only")
        if rows[rule_id] != expected:
            fail(
                f"{document.relative_to(ROOT)} {rule_id}: "
                f"expected={expected} got={rows[rule_id]}"
            )

out_of_scope = {
    capability_id for capability_id, (_, tier) in product_entries.items()
    if tier == "out-of-scope"
}
for document in DOCS:
    text = document.read_text(encoding="utf-8")
    for capability in out_of_scope:
        if capability not in text:
            fail(f"{document.relative_to(ROOT)} omits non-goal {capability}")
if "CWE count" not in capability_text or "not a success" not in capability_text:
    fail("docs/capabilities.md omits the CWE-count non-metric contract")
if "CWE count is not a success metric" not in (ROOT / "README.md").read_text(
    encoding="utf-8"
):
    fail("README.md omits the CWE-count non-metric contract")

print("ok: capability registry, README, and rule docs are in sync")
