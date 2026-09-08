#!/usr/bin/env python3
"""Offline, unsigned inventory/provenance for a trusted Linux x86_64 package.

Never executes the archive, recipe, downloads, or a signing tool. Producer-owned
build evidence is a trust input, not a cryptographic attestation. See the release
checklist for the evidence schema and the deliberately limited inventory profile.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile

from action_acquire import extract_package, verified_snapshot


REPO = Path(__file__).resolve().parents[1]
MAX_DOCUMENT = 10 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}")
SOURCE = re.compile(r"[0-9a-f]{40}")


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def text(value):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 8192
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def digest(value):
    require(isinstance(value, str) and HEX.fullmatch(value), "invalid SHA-256")
    return value


def fields(value, names, label):
    require(isinstance(value, dict) and set(value) == set(names.split()),
            "invalid " + label + " fields")


def read_regular(path, limit=MAX_DOCUMENT):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                "input must be a nonempty bounded regular file")
        data = stream.read(limit + 1)
        require(len(data) == info.st_size, "input size changed or exceeds bound")
        return data


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(_):
        raise EvidenceError("non-finite JSON number")

    return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)


def checked_file(record):
    fields(record, "path sha256", "evidence file")
    require(text(record["path"]), "invalid evidence path")
    data = read_regular(record["path"])
    require(sha(data) == digest(record["sha256"]), "evidence file checksum mismatch")
    return data


def git(repo, *args):
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    require(result.returncode == 0, "source Git lookup failed")
    require(len(result.stdout) <= MAX_DOCUMENT, "source Git output exceeds bound")
    return result.stdout


def source_identity(repo, source, version):
    require(isinstance(source, str) and SOURCE.fullmatch(source), "full source SHA required")
    require(git(repo, "rev-parse", source + "^{commit}").decode().strip() == source,
            "source SHA is not a commit")
    cmake = git(repo, "show", source + ":CMakeLists.txt")
    bases = re.findall(rb"(?m)^project\(CodeSkeptic VERSION ([0-9]+\.[0-9]+\.[0-9]+) LANGUAGES C CXX\)$", cmake)
    require(len(bases) == 1, "single authored CMake version missing")
    base = bases[0].decode()
    major, minor, patch = map(int, base.split("."))
    short = git(repo, "rev-parse", "--short=12", source).decode().strip()
    development = f"{major}.{minor}.{patch + 1}-dev+g{short}"
    if version == base:
        require(git(repo, "rev-parse", "refs/tags/v" + base + "^{commit}").decode().strip() == source,
                "release version lacks matching exact source tag")
    else:
        require(version == development, "package/source version mismatch (dirty or arbitrary overrides unsupported)")
    contract = git(repo, "show", source + ":src/reporter/ReportContract.h")
    schemas = re.findall(rb'reportSchema = "([^"]+)";', contract)
    require(len(schemas) == 1, "source report schema missing or ambiguous")
    capabilities = git(repo, "show", source + ":src/core/Capabilities.cpp")
    capability_schemas = re.findall(rb'\\"schema_version\\": ([0-9]+),', capabilities)
    require(len(capability_schemas) == 1, "source capabilities schema missing or ambiguous")
    return {"sha": source, "authored_version": base,
            "cmake_sha256": sha(cmake), "report_contract_sha256": sha(contract),
            "report_schema": schemas[0].decode(), "tool_version": version,
            "capabilities_schema": int(capability_schemas[0]),
            "capabilities_source_sha256": sha(capabilities)}


def validate_evidence(evidence, version, repo):
    fields(evidence, "schema source_sha archive_sha256 binary_sha256 report capabilities recipe", "build evidence")
    require(evidence["schema"] == "codeskeptic-build-evidence/v1", "unknown build evidence schema")
    digest(evidence["archive_sha256"])
    digest(evidence["binary_sha256"])
    source = source_identity(repo, evidence["source_sha"], version)
    report = parse_json(checked_file(evidence["report"]))
    require(isinstance(report, dict) and report.get("tool") == "CodeSkeptic"
            and report.get("tool_version") == version
            and report.get("schema") == source["report_schema"],
            "native report/source identity mismatch")
    capabilities = parse_json(checked_file(evidence["capabilities"]))
    require(isinstance(capabilities, dict) and capabilities.get("product") == "CodeSkeptic"
            and capabilities.get("version") == version
            and type(capabilities.get("schema_version")) is int
            and capabilities["schema_version"] == source["capabilities_schema"],
            "native capabilities/source identity mismatch")
    # This checks identity only. It does not re-qualify the report's verdict.
    recipe = evidence["recipe"]
    fields(recipe, "source_sha toolchain commands inputs", "recipe")
    require(recipe["source_sha"] == source["sha"], "recipe source mismatch")
    tools = recipe["toolchain"]
    require(isinstance(tools, dict) and 1 <= len(tools) <= 32
            and all(text(k) and text(v) for k, v in tools.items()), "invalid toolchain record")
    commands = recipe["commands"]
    require(isinstance(commands, list) and 1 <= len(commands) <= 32
            and all(text(command) for command in commands), "recorded reproduction commands required")
    inputs = recipe["inputs"]
    require(isinstance(inputs, list) and 1 <= len(inputs) <= 32, "bounded build evidence inputs required")
    records, names = [], set()
    for item in inputs:
        fields(item, "name path sha256", "recipe input")
        name = item["name"]
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name)
                and name not in names, "invalid or duplicate recipe input name")
        names.add(name)
        data = checked_file({"path": item["path"], "sha256": item["sha256"]})
        records.append({"name": name, "sha256": sha(data), "size": len(data)})
    return source, {"source_sha": source["sha"], "toolchain": tools, "commands": commands,
                    "inputs": sorted(records, key=lambda row: row["name"])}


def file_hash(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inventory(root, version):
    files = {str(path.relative_to(root)): path for path in root.rglob("*") if path.is_file()}
    rows = [{"path": name, "size": path.stat().st_size, "sha256": file_hash(path)}
            for name, path in sorted(files.items())]
    headers = {str(path.relative_to(root)) for path in root.glob("lib/clang/*/include") if path.is_dir()}
    require(len(headers) == 1, "one Clang resource tree required")
    header = next(iter(headers))
    require(re.fullmatch(r"lib/clang/[0-9]+/include", header), "invalid Clang resource tree")
    libraries = {name for name in files if re.fullmatch(r"lib/[^/]+", name)}
    require(libraries and all(re.fullmatch(r"lib/lib[^/]+\.so(?:\.[A-Za-z0-9_.+-]+)?", name)
                              for name in libraries), "unsupported bundled library layout")
    llvm_majors = set()
    for name in libraries:
        match = re.fullmatch(r"lib/lib(?:LLVM|clang-cpp)(?:\.so\.|-)([0-9]+)(?:[.\w-]*)", name)
        if match:
            llvm_majors.add(match[1])
    require(llvm_majors == {header.split("/")[2]}, "LLVM/resource major mismatch")
    index = read_regular(root / "licenses/INDEX.tsv").decode().splitlines()
    require(index and index[0] == "component\tpackage\tversion\tnotice", "invalid license index header")
    components, notices, seen, versions = [], set(), set(), {}
    for line in index[1:]:
        cells = line.split("\t")
        require(len(cells) == 4, "invalid license index row")
        component, package, package_version, notice = cells
        require(component in libraries | {header} and component not in seen,
                "missing, extra or duplicate licensed component")
        require(re.fullmatch(r"[a-z0-9][a-z0-9+.:\-]*", package)
                and text(package_version) and notice == f"licenses/{package}/copyright",
                "invalid package/version/notice mapping")
        require(package not in versions or versions[package] == package_version, "conflicting package versions")
        versions[package] = package_version
        notice_data = read_regular(root / notice)
        notices.add(notice)
        seen.add(component)
        components.append({"component": component, "package": package, "version": package_version,
                           "notice": notice, "notice_sha256": sha(notice_data)})
    require(seen == libraries | {header}, "license index does not cover exact bundled closure")
    required = {"bin/codeskeptic", "LICENSE", "README.md", "DEPENDENCIES.txt", "licenses/INDEX.tsv"}
    allowed = required | libraries | notices | {name for name in files if name.startswith(header + "/")}
    # Distribution copyright notices can reference installed common license texts.
    pending = list(notices)
    while pending:
        notice = pending.pop()
        for name in re.findall(r"/usr/share/common-licenses/([A-Za-z0-9.+-]+)",
                               read_regular(root / notice).decode()):
            target = "licenses/common/" + name.rstrip(".")
            if target not in allowed:
                require(target in files, "referenced common license missing")
                allowed.add(target)
                pending.append(target)
    require(set(files) == allowed, "unclassified or missing package files/licenses")
    description = read_regular(root / "DEPENDENCIES.txt").decode().splitlines()
    require(description[:2] == ["CodeSkeptic " + version, "Clang resource major: " + header.split("/")[2]],
            "dependency metadata identity mismatch")
    require("" in description, "dependency list boundary missing")
    entries = description[description.index("") + 1:]
    bundled, host = set(), set()
    for entry in entries:
        if entry.startswith("bundled "):
            name = entry.removeprefix("bundled ")
            require(name in libraries and name not in bundled, "invalid or duplicate bundled dependency")
            bundled.add(name)
        else:
            require(entry.startswith("host "), "unclassified dependency")
            name = entry.removeprefix("host ")
            require(re.fullmatch(r"[A-Za-z0-9_.+-]+", name) and name not in host,
                    "invalid or duplicate host dependency")
            require("lib/" + name not in libraries, "bundled dependency also declared as host")
            host.add(name)
    require(bundled == libraries and host, "dependency closure mismatch")
    return rows, sorted(components, key=lambda row: row["component"]), sorted(host)


def license_object(root, path):
    # Relative to the unpacked artifact root. The complete original notice and
    # common-license texts remain in the archive, bound by provenance file hashes.
    # Do not misclassify distribution copyright bundles as a single SPDX license.
    return {"license": {"name": "Unclassified distribution notice: " + path, "url": path}}


def documents(root, version, archive_name, evidence, source, recipe):
    rows, indexed, host = inventory(root, version)
    binary_hash = next(row["sha256"] for row in rows if row["path"] == "bin/codeskeptic")
    require(binary_hash == evidence["binary_sha256"], "packaged binary checksum mismatch")
    components = []
    for item in indexed:
        component = {"type": "library", "bom-ref": item["component"], "name": item["package"],
                     "version": item["version"], "scope": "required",
                     "licenses": [license_object(root, item["notice"])],
                     "properties": [{"name": "codeskeptic:package-path", "value": item["component"]},
                                    {"name": "codeskeptic:notice-sha256", "value": item["notice_sha256"]}]}
        selected = [row for row in rows if row["path"] == item["component"]
                    or row["path"].startswith(item["component"] + "/")]
        if len(selected) == 1 and selected[0]["path"] == item["component"]:
            component["hashes"] = [{"alg": "SHA-256", "content": selected[0]["sha256"]}]
        components.append(component)
    for name in host:
        components.append({"type": "library", "bom-ref": "host:" + name, "name": name,
                           "scope": "required", "properties": [
                               {"name": "codeskeptic:redistributed", "value": "false"},
                               {"name": "codeskeptic:version-license-status", "value": "unknown; supplied by target host"}]})
    application = {"type": "application", "bom-ref": "bin/codeskeptic", "name": "CodeSkeptic",
                   "version": version, "hashes": [{"alg": "SHA-256", "content": binary_hash}],
                   "licenses": [license_object(root, "LICENSE")]}
    sbom = {"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", "bomFormat": "CycloneDX",
            "specVersion": "1.6", "version": 1, "metadata": {"component": application},
            "components": components,
            "dependencies": [{"ref": "bin/codeskeptic", "dependsOn": [c["bom-ref"] for c in components]}],
            "compositions": [{"aggregate": "incomplete"}],
            "properties": [{"name": "codeskeptic:source-sha", "value": source["sha"]},
                           {"name": "codeskeptic:archive-sha256", "value": evidence["archive_sha256"]},
                           {"name": "codeskeptic:inventory-profile", "value":
                            "Linux x86_64 packaged files and dpkg notices; static source dependencies and target-host versions not resolved"}]}
    provenance = {"schema": "codeskeptic-provenance/v1", "signed": False,
                  "trust": "Producer-supplied build records; no signature, SLSA attestation, verdict qualification or byte-reproducibility claim",
                  "artifact": {"name": archive_name, "sha256": evidence["archive_sha256"],
                               "binary_sha256": binary_hash}, "source": source,
                  "native_identity_report_sha256": evidence["report"]["sha256"],
                  "native_capabilities_sha256": evidence["capabilities"]["sha256"],
                  "recipe": recipe, "files": rows, "licenses": indexed, "host_dependencies": host}
    return sbom, provenance


def generator_identity(repo):
    generator_head = git(repo, "rev-parse", "HEAD").decode().strip()
    generator_files = {}
    for name in ("generate_sbom.py", "action_acquire.py", "action_run.py"):
        data = read_regular(Path(__file__).with_name(name))
        require(data == git(repo, "show", generator_head + ":scripts/" + name),
                "generator/helper bytes are not committed at generator HEAD")
        generator_files["scripts/" + name] = sha(data)
    return {"head": generator_head, "files": generator_files}


def generate(archive, build_evidence, output, repo=REPO):
    output = Path(output).absolute()
    require(not os.path.lexists(output), "output exists; use a fresh evidence directory")
    require(output.parent.is_dir(), "output parent must already exist")
    raw_evidence = read_regular(build_evidence)
    evidence = parse_json(raw_evidence)
    fields(evidence, "schema source_sha archive_sha256 binary_sha256 report capabilities recipe", "build evidence")
    archive = Path(archive)
    require(re.fullmatch(r"codeskeptic-v[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*-linux-x86_64\.tar\.gz", archive.name),
            "qualified profile requires a versioned Linux x86_64 archive")
    with tempfile.TemporaryDirectory(prefix="codeskeptic-provenance-") as temporary:
        working = Path(temporary)
        snapshot = working / "snapshot.tar.gz"
        verified_snapshot(archive, digest(evidence["archive_sha256"]), snapshot)
        root, version = extract_package(snapshot, working, "")
        require(archive.name == root.name + ".tar.gz", "archive filename/root mismatch")
        source, recipe = validate_evidence(evidence, version, repo)
        require(read_regular(root / "LICENSE") == git(repo, "show", source["sha"] + ":LICENSE"),
                "project LICENSE/source mismatch")
        sbom, provenance = documents(root, version, archive.name, evidence, source, recipe)
    provenance["generator"] = generator_identity(repo)
    provenance["build_evidence_sha256"] = sha(raw_evidence)
    sbom_name = archive.name + ".sbom.json"
    sbom_data = canonical(sbom)
    provenance["sbom"] = {"name": sbom_name, "sha256": sha(sbom_data)}
    provenance_name = archive.name + ".provenance.json"
    provenance_data = canonical(provenance)
    require(len(sbom_data) <= MAX_DOCUMENT and len(provenance_data) <= MAX_DOCUMENT,
            "sidecar exceeds document bound")
    # New-only publication. A write failure may leave partial owned evidence,
    # never a success marker; preserve it and retry in a fresh directory.
    output.mkdir()
    for name, data in ((sbom_name, sbom_data), (provenance_name, provenance_data)):
        with (output / name).open("xb") as stream:
            stream.write(data)
    sums = (f"{evidence['archive_sha256']}  {archive.name}\n"
            f"{sha(sbom_data)}  {sbom_name}\n{sha(provenance_data)}  {provenance_name}\n").encode()
    with (output / "sha256sums.txt").open("xb") as stream:
        stream.write(sums)
    print(f"PROVENANCE_OK source={source['sha']} generator={provenance['generator']['head']} files={len(provenance['files'])} bundled={len(provenance['licenses'])} signed=false")
    return sbom, provenance


def verify_sidecars(archive, directory, expected_source, expected_version, repo=REPO):
    """Release aggregation check, not independent build/producer attestation."""
    archive, directory = Path(archive), Path(directory)
    provenance_name = archive.name + ".provenance.json"
    sbom_name = archive.name + ".sbom.json"
    provenance_data = read_regular(directory / provenance_name)
    sbom_data = read_regular(directory / sbom_name)
    provenance = parse_json(provenance_data)
    bom = parse_json(sbom_data)
    require(provenance_data == canonical(provenance) and sbom_data == canonical(bom),
            "noncanonical sidecar")
    require(isinstance(provenance, dict) and provenance.get("schema") == "codeskeptic-provenance/v1"
            and provenance.get("signed") is False, "unknown or signed provenance claim")
    fields(provenance, "schema signed trust artifact source native_identity_report_sha256 native_capabilities_sha256 recipe files licenses host_dependencies generator build_evidence_sha256 sbom", "provenance")
    for name in ("native_identity_report_sha256", "native_capabilities_sha256", "build_evidence_sha256"):
        digest(provenance[name])
    source = source_identity(repo, expected_source, expected_version)
    require(provenance.get("source") == source, "sidecar source/version mismatch")
    recipe = provenance["recipe"]
    fields(recipe, "source_sha toolchain commands inputs", "published recipe")
    require(recipe["source_sha"] == expected_source, "published recipe source mismatch")
    require(isinstance(recipe["toolchain"], dict) and 1 <= len(recipe["toolchain"]) <= 32
            and all(text(k) and text(v) for k, v in recipe["toolchain"].items()), "invalid published toolchain")
    require(isinstance(recipe["commands"], list) and 1 <= len(recipe["commands"]) <= 32
            and all(text(c) for c in recipe["commands"]), "invalid published commands")
    require(isinstance(recipe["inputs"], list) and 1 <= len(recipe["inputs"]) <= 32, "invalid published inputs")
    names = set()
    for item in recipe["inputs"]:
        fields(item, "name sha256 size", "published input")
        require(text(item["name"]) and item["name"] not in names
                and type(item["size"]) is int and 0 < item["size"] <= MAX_DOCUMENT,
                "invalid or duplicate published input")
        names.add(item["name"])
        digest(item["sha256"])
    generator = provenance["generator"]
    fields(generator, "head files", "generator identity")
    require(isinstance(generator["head"], str) and SOURCE.fullmatch(generator["head"]), "invalid generator head")
    paths = {"scripts/generate_sbom.py", "scripts/action_acquire.py", "scripts/action_run.py"}
    require(isinstance(generator["files"], dict) and set(generator["files"]) == paths, "generator closure mismatch")
    for path, checksum in generator["files"].items():
        require(sha(git(repo, "show", generator["head"] + ":" + path)) == digest(checksum),
                "generator source checksum mismatch")
    require(provenance.get("sbom") == {"name": sbom_name, "sha256": sha(sbom_data)}, "SBOM checksum mismatch")
    artifact = provenance.get("artifact")
    fields(artifact, "name sha256 binary_sha256", "provenance artifact")
    require(artifact["name"] == archive.name, "sidecar archive name mismatch")
    # Reconcile actual archived files, license text and dependency closure, not
    # merely the sidecar's own internally consistent checksums.
    with tempfile.TemporaryDirectory(prefix="codeskeptic-verify-provenance-") as temporary:
        working = Path(temporary)
        snapshot = working / "snapshot.tar.gz"
        verified_snapshot(archive, digest(artifact["sha256"]), snapshot)
        root, version = extract_package(snapshot, working, "v" + expected_version)
        require(archive.name == root.name + ".tar.gz", "archive filename/root mismatch")
        rows, licenses, host = inventory(root, version)
        require(provenance.get("files") == rows and provenance.get("licenses") == licenses
                and provenance.get("host_dependencies") == host, "sidecar inventory mismatch")
        require(read_regular(root / "LICENSE") == git(repo, "show", expected_source + ":LICENSE"),
                "project LICENSE/source mismatch")
        require(artifact["binary_sha256"] == file_hash(root / "bin/codeskeptic"), "sidecar binary mismatch")
        evidence = {"archive_sha256": artifact["sha256"], "binary_sha256": artifact["binary_sha256"],
                    "report": {"sha256": provenance.get("native_identity_report_sha256")},
                    "capabilities": {"sha256": provenance.get("native_capabilities_sha256")}}
        regenerated, _ = documents(root, version, archive.name, evidence, source, provenance.get("recipe"))
        require(bom == regenerated, "SBOM content does not match archived inventory")
    print("PROVENANCE_VERIFY_OK source=" + expected_source + " signed=false")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    create = modes.add_parser("generate")
    create.add_argument("archive", type=Path)
    create.add_argument("build_evidence", type=Path)
    create.add_argument("output", type=Path)
    verify = modes.add_parser("verify")
    verify.add_argument("archive", type=Path)
    verify.add_argument("sidecars", type=Path)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "generate":
            generate(args.archive, args.build_evidence, args.output)
        else:
            verify_sidecars(args.archive, args.sidecars, args.source_sha, args.version)
    except (OSError, ValueError, RuntimeError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f"PROVENANCE_FAIL {error}\n")


if __name__ == "__main__":
    main()
