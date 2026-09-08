#!/usr/bin/env python3
"""Relocatable Linux package assembly from a trusted local build.

Build-host profile: Debian/Ubuntu dpkg metadata and installed license texts.
Nothing is downloaded. Runtime needs no Python, compiler or package manager;
analyzing a target still requires that target's headers and compilation flags.
"""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile


REPO = Path(__file__).resolve().parents[1]
CORE = re.compile(r"(?:ld-linux[\w.-]*|ld64\.so\.\d+|"
                  r"lib(?:c|m|pthread|dl|rt|resolv|util|gcc_s|stdc\+\+)\.so[.\d]*)")
VERSION = re.compile(r"CodeSkeptic ([0-9]+\.[0-9]+\.[0-9]+"
                     r"(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?)\n?")


class PackageError(RuntimeError):
    pass


def command(*args):
    try:
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30,
                                env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PackageError(f"{args[0]} failed: {error}") from error
    if result.returncode:
        raise PackageError(f"{args[0]} exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def dependencies(binary):
    """ldd includes transitive dependencies; unknown/unresolved lines fail closed."""
    found = {}
    for line in command("ldd", str(binary)).splitlines():
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r"linux-vdso\.so\.\d+ \(0x[0-9a-f]+\)", line):
            continue
        match = re.fullmatch(r"(\S+) => (/.+) \(0x[0-9a-f]+\)", line)
        if match:
            name, path = match.groups()
        else:
            loader = re.fullmatch(r"(/\S+) \(0x[0-9a-f]+\)", line)
            if not loader or not CORE.fullmatch(Path(loader[1]).name):
                raise PackageError(f"unresolved or unknown ldd dependency: {line}")
            path = loader[1]
            name = Path(path).name
        if Path(name).name != name or name in (".", ".."):
            raise PackageError(f"invalid dependency name: {name}")
        if name in found and found[name] != Path(path):
            raise PackageError(f"conflicting dependency: {name}")
        found[name] = Path(path)
    if not found:
        raise PackageError("ldd returned no dynamic dependencies; this profile requires dynamic LLVM")
    return found


def owner_of(path):
    # dpkg databases may use the pre-merged-/usr name rather than realpath.
    candidates = [path, path.resolve()]
    for candidate in tuple(candidates):
        value = str(candidate)
        if value.startswith("/usr/lib/"):
            candidates.append(Path(value[4:]))
        elif value.startswith("/lib/"):
            candidates.append(Path("/usr" + value))
    for candidate in dict.fromkeys(candidates):
        try:
            output = command("dpkg-query", "-S", str(candidate))
        except PackageError:
            continue
        owners = []
        for line in output.splitlines():
            package, sep, reported = line.rpartition(": ")
            if sep and reported == str(candidate) and re.fullmatch(r"[a-z0-9][a-z0-9+.:\-]*", package):
                owners.append(package)
        if len(set(owners)) == 1:
            return owners[0]
    raise PackageError(f"no unambiguous installed dpkg owner/copyright for {path}")


def copy_licenses(inputs, stage):
    """Retain distribution copyright notices plus referenced common license texts."""
    destination = stage / "licenses"
    destination.mkdir()
    records = []
    copied = set()
    common_copied = set()

    def common_licenses(text):
        for name in re.findall(r"/usr/share/common-licenses/([A-Za-z0-9.+-]+)", text):
            name = name.rstrip(".")
            if name in common_copied:
                continue
            source = Path("/usr/share/common-licenses") / name
            if not source.is_file() or source.stat().st_size == 0:
                raise PackageError(f"missing referenced common license: {source}")
            common_copied.add(name)
            target = destination / "common" / name
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(source, target)
            common_licenses(source.read_text())

    for component, source in inputs:
        package = owner_of(source)
        metadata = command("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n", package).strip()
        fields = metadata.split("\t")
        if len(fields) != 2 or fields[0] != package or not fields[1]:
            raise PackageError(f"invalid package metadata: {package}")
        records.append(f"{component}\t{package}\t{fields[1]}\tlicenses/{package}/copyright")
        if package in copied:
            continue
        short = package.split(":")[0]
        suffix = f"/share/doc/{short}/copyright"
        paths = [Path(p) for p in command("dpkg-query", "-L", package).splitlines()
                 if p.startswith("/") and p.endswith(suffix)]
        # Some packages only list a symlink for their whole documentation dir.
        paths.append(Path("/usr/share/doc") / short / "copyright")
        copyright_file = next((p for p in paths if p.is_file() and p.stat().st_size), None)
        if copyright_file is None:
            raise PackageError(f"missing installed copyright: {package}")
        target = destination / package / "copyright"
        target.parent.mkdir()
        shutil.copyfile(copyright_file, target)
        common_licenses(copyright_file.read_text())
        copied.add(package)
    (destination / "INDEX.tsv").write_text("component\tpackage\tversion\tnotice\n" + "\n".join(records) + "\n")


def assemble(binary, output, clang):
    binary = Path(binary).resolve(strict=True)
    output = Path(output).absolute()
    match = VERSION.fullmatch(command(str(binary), "--version"))
    if not match:
        raise PackageError("could not parse complete CodeSkeptic --version identity")
    version = match[1]
    name = f"codeskeptic-v{version}-linux-{platform.machine()}"
    archive_name = name + ".tar.gz"
    # Keep the expanded directory: Dockerfile consumes it directly.
    output.mkdir(parents=True, exist_ok=True)
    for target in (output / name, output / archive_name):
        if os.path.lexists(target):
            raise PackageError(f"destination exists; use a fresh output directory: {target}")
    resources = Path(command(clang, "-print-resource-dir").strip()).resolve(strict=True)
    if not resources.name.isdecimal() or not (resources / "include/stddef.h").is_file():
        raise PackageError("resource major/include/stddef.h is missing or invalid")
    major = int(resources.name)
    clang_version = re.search(r"\bclang version (\d+)\.", command(clang, "--version"))
    linked = dependencies(binary)
    llvm_majors = set()
    for library in linked:
        llvm = re.fullmatch(r"lib(?:LLVM|clang-cpp)(?:\.so\.|-)(\d+)(?:[.\w-]*)", library)
        if llvm:
            llvm_majors.add(int(llvm[1]))
    if not clang_version or int(clang_version[1]) != major or llvm_majors != {major}:
        raise PackageError("resource, clang and linked LLVM major must agree (dynamic LLVM profile)")
    dynamic = command("readelf", "-d", str(binary))
    rpath = re.search(r"\(RPATH\).*?\[([^]]+)\]", dynamic)
    if not rpath or "$ORIGIN/../lib" not in rpath[1].split(":"):
        raise PackageError("binary needs transitive RPATH $ORIGIN/../lib")

    with tempfile.TemporaryDirectory(prefix=".codeskeptic-package-", dir=output) as temporary:
        stage = Path(temporary) / name
        (stage / "bin").mkdir(parents=True)
        shutil.copy2(binary, stage / "bin/codeskeptic")
        headers = stage / "lib/clang" / resources.name / "include"
        shutil.copytree(resources / "include", headers)
        for document in ("LICENSE", "README.md"):
            shutil.copy2(REPO / document, stage / document)
        license_inputs = [("lib/clang/" + resources.name + "/include", resources / "include/stddef.h")]
        bundled = {}
        for library, source in sorted(linked.items()):
            if CORE.fullmatch(library):
                continue
            if not source.is_file():
                raise PackageError(f"missing dependency file: {library}: {source}")
            target = stage / "lib" / library
            shutil.copy2(source, target)
            bundled[library] = target.resolve()
            license_inputs.append(("lib/" + library, source.resolve()))
        copy_licenses(license_inputs, stage)
        relocated = dependencies(stage / "bin/codeskeptic")
        if relocated.keys() != linked.keys():
            raise PackageError("staged dependency closure differs from source")
        for library, target in bundled.items():
            if relocated[library].resolve() != target:
                raise PackageError(f"dependency escaped staged package: {library}")
        description = [f"CodeSkeptic {version}", f"Clang resource major: {major}",
                       "Linux dynamic-LLVM tarball; no release/signature claim.",
                       "Host supplies the ELF loader, glibc, libstdc++ and libgcc_s as linked below.",
                       "Target development headers and compilation flags are required for analysis.",
                       "Do not remove lib/ or licenses/. See licenses/INDEX.tsv for bundled notices.", ""]
        for library in sorted(linked):
            description.append(f"{'bundled lib/' + library if library in bundled else 'host ' + library}")
        (stage / "DEPENDENCIES.txt").write_text("\n".join(description) + "\n")
        archive = Path(temporary) / archive_name
        with tarfile.open(archive, "w:gz") as packed:
            packed.add(stage, arcname=name)
        checksum = hashlib.sha256()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(block)
        digest = checksum.hexdigest()
        # Exclusive publication: never replace an existing archive or tree.
        # On a later failure leave any published artifact intact, with no success marker.
        os.link(archive, output / archive_name)
        destination = output / name
        destination.mkdir()  # exclusive even if another process creates the path
        for child in stage.iterdir():
            child.rename(destination / child.name)
        sums = output / "sha256sums.txt"
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(sums, flags, 0o644)
        with os.fdopen(descriptor, "a") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise PackageError("checksum destination must be a regular file")
            stream.write(f"{digest}  {archive_name}\n")
        print(f"PACKAGE_RESULT name={archive_name} version={version} resource_major={major}")
    return output / archive_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("output", nargs="?", default="dist")
    parser.add_argument("clang", nargs="?", default="")
    args = parser.parse_args()
    clang = args.clang or next((c for c in ("clang-20", "clang-19", "clang-18", "clang") if shutil.which(c)), "")
    try:
        if not clang:
            raise PackageError("no clang found for resource headers")
        assemble(args.binary, args.output, clang)
    except (PackageError, OSError, ValueError) as error:
        parser.exit(1, f"PACKAGE_FAIL {error}\n")


if __name__ == "__main__":
    main()
