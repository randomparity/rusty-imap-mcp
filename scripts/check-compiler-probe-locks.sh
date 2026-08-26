#!/usr/bin/env bash
set -euo pipefail

python3 - "$@" <<'PY'
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

USAGE = "usage: check-compiler-probe-locks.sh [--fix] [--repo-root PATH]"
COMPILER_SUBCOMMANDS = {"bench", "build", "check", "clippy", "fix", "run", "rustc", "test"}
NON_CHECK_SUBCOMMANDS = COMPILER_SUBCOMMANDS - {"check"}
REQUIRED_FIXTURE_FILES = ("Cargo.toml", "Cargo.lock", "src/main.rs")


class GuardError(Exception):
    pass


@dataclass(frozen=True)
class FunctionBody:
    name: str
    source: str
    masked: str


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    source: str | None
    checksum: str | None
    dependencies: tuple[str, ...]

    def identity(self) -> str:
        identity = f"{self.name} {self.version}"
        if self.source is not None:
            identity += f" ({self.source})"
        return identity


@dataclass(frozen=True)
class Probe:
    source_path: Path
    fixture: Path
    invocation_count: int


def parse_args(argv: list[str]) -> tuple[bool, Path]:
    fix = False
    repo_root: Path | None = None
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--fix":
            if fix:
                raise GuardError(f"duplicate --fix\n{USAGE}")
            fix = True
            index += 1
        elif argument == "--repo-root":
            if repo_root is not None:
                raise GuardError(f"duplicate --repo-root\n{USAGE}")
            if index + 1 >= len(argv):
                raise GuardError(f"--repo-root requires a path\n{USAGE}")
            repo_root = Path(argv[index + 1])
            index += 2
        else:
            raise GuardError(f"unknown argument: {argument}\n{USAGE}")

    if repo_root is None:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or "git rev-parse failed"
            raise GuardError(f"cannot resolve repository root: {detail}")
        repo_root = Path(result.stdout.strip())
    repo_root = repo_root.resolve()
    if not repo_root.is_dir():
        raise GuardError(f"repository root is not a directory: {repo_root}")
    return fix, repo_root


def tracked_paths(repo: Path) -> set[Path]:
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip() or "git ls-files failed"
        raise GuardError(f"cannot enumerate tracked files under {repo}: {detail}")
    return {Path(raw.decode()) for raw in result.stdout.split(b"\0") if raw}


def source_candidates(paths: set[Path]) -> list[Path]:
    candidates = []
    for path in paths:
        parts = path.parts
        if (
            len(parts) >= 4
            and parts[0] == "crates"
            and parts[2] == "tests"
            and path.suffix == ".rs"
        ):
            candidates.append(path)
    return sorted(candidates)


def char_literal_match(source: str, index: int) -> re.Match[str] | None:
    return re.match(
        r"'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])'",
        source[index:],
    )


def strip_comments(source: str) -> str:
    output = list(source)
    index = 0
    block_depth = 0
    state = "code"
    raw_hashes = 0
    while index < len(source):
        if state == "line":
            if source[index] == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        if state == "block":
            if source.startswith("/*", index):
                output[index : index + 2] = "  "
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                output[index : index + 2] = "  "
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                if source[index] != "\n":
                    output[index] = " "
                index += 1
            continue
        if state == "string":
            if source[index] == "\\":
                index += min(2, len(source) - index)
            elif source[index] == '"':
                state = "code"
                index += 1
            else:
                index += 1
            continue
        if state == "char":
            if source[index] == "\\":
                index += min(2, len(source) - index)
            elif source[index] == "'":
                state = "code"
                index += 1
            else:
                index += 1
            continue
        if state == "raw":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                index += len(terminator)
                state = "code"
            else:
                index += 1
            continue

        if source.startswith("//", index):
            output[index : index + 2] = "  "
            state = "line"
            index += 2
        elif source.startswith("/*", index):
            output[index : index + 2] = "  "
            state = "block"
            block_depth = 1
            index += 2
        else:
            raw_match = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", source[index:])
            if raw_match is not None:
                raw_hashes = len(raw_match.group("hashes"))
                index += raw_match.end()
                state = "raw"
            elif source[index] == '"':
                state = "string"
                index += 1
            elif char_literal_match(source, index) is not None:
                state = "char"
                index += 1
            else:
                index += 1
    if state == "block":
        raise GuardError("unterminated Rust block comment")
    return "".join(output)


def mask_literals(source: str) -> str:
    output = list(source)
    index = 0
    while index < len(source):
        raw_match = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", source[index:])
        if raw_match is not None:
            end_marker = '"' + raw_match.group("hashes")
            end = source.find(end_marker, index + raw_match.end())
            if end == -1:
                end = len(source) - len(end_marker)
            for offset in range(index, min(len(source), end + len(end_marker))):
                if source[offset] != "\n":
                    output[offset] = " "
            index = end + len(end_marker)
        elif source[index] == '"':
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            for offset in range(index, min(len(source), end)):
                if source[offset] != "\n":
                    output[offset] = " "
            index = end
        else:
            char_match = char_literal_match(source, index)
            if char_match is None:
                index += 1
                continue
            end = index + char_match.end()
            for offset in range(index, end):
                output[offset] = " "
            index = end
    return "".join(output)


def matching_delimiter(masked: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(masked)):
        if masked[index] == opening:
            depth += 1
        elif masked[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    raise GuardError(f"unmatched {opening} in Rust source")


def extract_function_bodies(source: str) -> list[FunctionBody]:
    comments_removed = strip_comments(source)
    masked = mask_literals(comments_removed)
    bodies = []
    pattern = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b[^;{]*\{")
    for match in pattern.finditer(masked):
        opening = match.end() - 1
        closing = matching_delimiter(masked, opening, "{", "}")
        bodies.append(
            FunctionBody(
                match.group(1),
                comments_removed[match.start() : closing + 1],
                masked[match.start() : closing + 1],
            )
        )
    return bodies


def process_constructors(source: str) -> set[str]:
    stripped = strip_comments(source)
    names = set()
    for match in re.finditer(
        r"\buse\s+(?:std|tokio)::process::Command(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;",
        stripped,
    ):
        names.add(match.group(1) or "Command")
    for match in re.finditer(
        r"\buse\s+(?:std|tokio)::process(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;",
        stripped,
    ):
        names.add(f"{match.group(1) or 'process'}::Command")
    for match in re.finditer(
        r"\buse\s+(?:std|tokio)::process::\{([^{}]*)\}\s*;", stripped
    ):
        for item in match.group(1).split(","):
            command = re.fullmatch(
                r"\s*Command(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*", item
            )
            if command is not None:
                names.add(command.group(1) or "Command")
    for match in re.finditer(r"\buse\s+(?:std|tokio)::\{([^{}]*)\}\s*;", stripped):
        for item in match.group(1).split(","):
            command = re.fullmatch(
                r"\s*process::Command(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*",
                item,
            )
            if command is not None:
                names.add(command.group(1) or "Command")
    return names


def constructor_matches(body: FunctionBody, imported: set[str]) -> list[re.Match[str]]:
    alternatives = [r"std::process::Command", r"tokio::process::Command"]
    alternatives.extend(re.escape(name) for name in sorted(imported))
    pattern = re.compile(r"\b(?:" + "|".join(alternatives) + r")::new\s*\(")
    return list(pattern.finditer(body.masked))


def rust_strings(source: str) -> list[str]:
    strings = []
    for match in re.finditer(r'"((?:\\.|[^"\\])*)"', source):
        try:
            strings.append(bytes(match.group(1), "utf-8").decode("unicode_escape"))
        except UnicodeDecodeError:
            strings.append(match.group(1))
    return strings

def cargo_arguments(chain: str) -> list[str] | None:
    stripped = strip_comments(chain)
    masked = mask_literals(stripped)
    arguments = []
    string_literal = r'"(?:\\.|[^"\\])*"'
    for match in re.finditer(r"\.(arg|args)\s*\(", masked):
        opening = match.end() - 1
        closing = matching_delimiter(masked, opening, "(", ")")
        operand = stripped[opening + 1 : closing].strip()
        if match.group(1) == "arg":
            if re.fullmatch(string_literal, operand) is None:
                return None
            arguments.extend(rust_strings(operand))
            continue
        if operand.startswith("&"):
            operand = operand[1:].strip()
        if not operand.startswith("[") or not operand.endswith("]"):
            return None
        elements = operand[1:-1]
        remainder = re.sub(string_literal, "", elements)
        if re.fullmatch(r"[\s,]*", remainder) is None:
            return None
        arguments.extend(rust_strings(elements))
    return arguments


def cargo_helper_is_canonical(source: str) -> bool:
    for body in extract_function_bodies(source):
        if body.name != "cargo_bin":
            continue
        if (
            re.search(r"fn\s+cargo_bin\s*\(\s*\)\s*->\s*PathBuf", body.source)
            and 'std::env::var("CARGO")' in body.source
            and 'PathBuf::from("cargo")' in body.source
        ):
            return True
    return False


def is_cargo_executable(expression: str, source: str) -> bool:
    compact = re.sub(r"\s+", "", expression)
    if compact == '"cargo"' or compact == 'PathBuf::from("cargo")':
        return True
    return compact == "cargo_bin()" and cargo_helper_is_canonical(source)


def body_has_temporary_project(body: FunctionBody) -> bool:
    return any(
        marker in body.source
        for marker in (
            "new_probe_root(&fixture)",
            "TempDir::new()",
            "tempdir()",
            "tempdir_in(",
            'join("Cargo.toml")',
        )
    )


def validate_registration(
    repo: Path, relative_source: Path, source: str, tracked: set[Path]
) -> Path:
    registrations = re.findall(
        r'\bconst\s+COMPILER_PROBE_FIXTURE\s*:\s*&str\s*=\s*"([^"]*)"\s*;', source
    )
    if len(registrations) != 1:
        raise GuardError(
            f"{relative_source}: expected exactly one COMPILER_PROBE_FIXTURE registration"
        )
    registration = Path(registrations[0])
    if registration.is_absolute():
        raise GuardError(f"{relative_source}: COMPILER_PROBE_FIXTURE must be a relative path")
    if ".." in registration.parts:
        raise GuardError(f"{relative_source}: COMPILER_PROBE_FIXTURE must not escape its crate")

    crate_relative = Path(*relative_source.parts[:2])
    crate_root = (repo / crate_relative).resolve()
    fixture = (crate_root / registration).resolve()
    try:
        fixture.relative_to(crate_root)
    except ValueError as error:
        raise GuardError(
            f"{relative_source}: COMPILER_PROBE_FIXTURE must not escape {crate_root}"
        ) from error

    for name in REQUIRED_FIXTURE_FILES:
        relative = fixture.joinpath(name).relative_to(repo)
        if relative not in tracked or not (repo / relative).is_file():
            raise GuardError(f"{relative_source}: missing tracked fixture file {relative}")
    return fixture


def validate_canonical_helpers(relative_source: Path, source: str) -> None:
    compact = re.sub(r"\s+", " ", strip_comments(source))
    if not re.search(
        r"fn fixture_root\s*\(\s*\)\s*->\s*PathBuf\s*\{[^}]*\.join\(COMPILER_PROBE_FIXTURE\)",
        compact,
    ):
        raise GuardError(
            f"{relative_source}: fixture_root() must join the crate root with "
            "COMPILER_PROBE_FIXTURE"
        )
    copy_helpers = [
        body for body in extract_function_bodies(source) if body.name == "copy_fixture_file"
    ]
    if len(copy_helpers) != 1:
        raise GuardError(
            f"{relative_source}: expected exactly one copy_fixture_file helper"
        )
    copy_body = re.sub(r"\s+", " ", copy_helpers[0].source)
    canonical_copy = re.search(
        r"let source = fixture\.join\(name\); "
        r"let destination = root\.join\(name\); "
        r"std::fs::copy\(&source, &destination\)",
        copy_body,
    )
    if canonical_copy is None or copy_body.count("std::fs::copy(") != 1:
        raise GuardError(
            f"{relative_source}: copy_fixture_file must byte-copy its canonical source "
            "and destination"
        )


def validate_check_body(relative_source: Path, body: FunctionBody) -> None:
    if body.name != "check_probe":
        raise GuardError(
            f"{relative_source}: direct temporary Cargo check must be in check_probe; "
            "rewrite to canonical probe shape"
        )
    compact = re.sub(r"\s+", " ", body.source)
    if "let fixture = fixture_root();" not in compact:
        raise GuardError(
            f"{relative_source}: check_probe must bind the canonical fixture root; "
            "rewrite to canonical probe shape"
        )
    if "let dir = new_probe_root(&fixture);" not in compact:
        raise GuardError(
            f"{relative_source}: check_probe must create the canonical temporary root; "
            "rewrite to canonical probe shape"
        )
    copies = re.search(
        r'for name in \[\s*"Cargo\.toml"\s*,\s*"Cargo\.lock"\s*\]\s*\{'
        r".*?copy_fixture_file\(\s*&fixture\s*,\s*dir\.path\(\)\s*,\s*name\s*\)",
        body.source,
        re.DOTALL,
    )
    if copies is None:
        raise GuardError(
            f"{relative_source}: check_probe must copy Cargo.toml and Cargo.lock to the same "
            "temporary root"
        )


def validate_check_chain(relative_source: Path, chain: str) -> None:
    terminal = re.search(
        r"\.(?:output|status|spawn)\s*\(\s*\)(?:\s*\.await)?"
        r'(?:\s*\.expect\(\s*"[^"]*"\s*\))?\s*;\s*$',
        chain,
    )
    if terminal is None:
        raise GuardError(
            f"{relative_source}: Cargo builder must be one fluent expression through a terminal "
            "call; rewrite to canonical probe shape"
        )
    arguments = cargo_arguments(chain)
    if arguments is None:
        raise GuardError(
            f"{relative_source}: Cargo builder requires direct literal Cargo arguments; "
            "rewrite to canonical probe shape"
        )
    if not arguments or arguments[0] != "check":
        raise GuardError(
            f"{relative_source}: direct Cargo builder has no literal check subcommand; "
            "the first Cargo argument must be a literal subcommand"
        )
    argv = arguments
    separator = argv.index("--") if "--" in argv else len(argv)
    prefix = argv[:separator]
    for flag in ("--locked", "--offline"):
        if flag not in argv:
            raise GuardError(f"{relative_source}: Cargo check is missing {flag}")
        if flag not in prefix:
            raise GuardError(
                f"{relative_source}: {flag} must appear before Cargo argument separator --"
            )
    for argument in argv:
        if argument in ("--manifest-path", "--lockfile-path") or argument.startswith(
            ("--manifest-path=", "--lockfile-path=")
        ):
            raise GuardError(
                f"{relative_source}: Cargo check has a graph-selection override"
            )
        if argument == "--target-dir" or argument.startswith("--target-dir="):
            raise GuardError(
                f"{relative_source}: Cargo check has a target-directory override"
            )
    target_env = re.compile(
        r'\.env\(\s*"CARGO_TARGET_DIR"\s*,\s*'
        r'dir\.path\(\)\.join\(\s*"target"\s*\)\s*\)'
    )
    if chain.count('"CARGO_TARGET_DIR"') != 1 or target_env.search(chain) is None:
        raise GuardError(
            f"{relative_source}: Cargo check must use the canonical temporary target directory"
        )
    if re.search(r"\.current_dir\(\s*dir\.path\(\)\s*\)", chain) is None:
        raise GuardError(
            f"{relative_source}: Cargo check and fixture copies must use the same temporary root"
        )


def inspect_source(repo: Path, relative_source: Path, tracked: set[Path]) -> Probe | None:
    source = (repo / relative_source).read_text()
    imported = process_constructors(source)
    try:
        function_bodies = extract_function_bodies(source)
    except GuardError as error:
        raise GuardError(f"{relative_source}: {error}") from error
    candidates: list[tuple[FunctionBody, re.Match[str]]] = []
    for body in function_bodies:
        candidates.extend((body, match) for match in constructor_matches(body, imported))
    source_has_temporary_project = any(
        body_has_temporary_project(body) for body in function_bodies
    )

    checks: list[tuple[FunctionBody, str]] = []
    saw_temporary_compiler = False
    for body, constructor in candidates:
        opening = constructor.end() - 1
        closing = matching_delimiter(body.masked, opening, "(", ")")
        semicolon = body.masked.find(";", closing)
        if semicolon == -1:
            semicolon = len(body.masked) - 1
        executable = body.source[opening + 1 : closing]
        chain = body.source[constructor.start() : semicolon + 1]
        chain_arguments = cargo_arguments(chain)
        temporary = body_has_temporary_project(body)
        cargo_executable = is_cargo_executable(executable, source)
        if chain_arguments is None:
            if temporary and cargo_executable:
                raise GuardError(
                    f"{relative_source}: Cargo builder requires direct literal Cargo "
                    "arguments; rewrite to canonical probe shape"
                )
            continue
        subcommand = chain_arguments[0] if chain_arguments else None
        if subcommand == "metadata":
            continue
        if subcommand is not None and subcommand not in COMPILER_SUBCOMMANDS:
            if temporary and cargo_executable:
                raise GuardError(
                    f"{relative_source}: direct Cargo builder has no literal check "
                    "subcommand; the first Cargo argument must be a literal subcommand"
                )
            continue
        if subcommand is None:
            body_arguments = rust_strings(body.source)
            body_subcommand = next(
                (argument for argument in body_arguments if argument in COMPILER_SUBCOMMANDS), None
            )
            if temporary and (cargo_executable or body_subcommand is not None):
                if re.search(r"\.(?:arg|args)\s*\(", chain):
                    raise GuardError(
                        f"{relative_source}: direct Cargo builder has no literal check "
                        "subcommand; rewrite to canonical probe shape"
                    )
                raise GuardError(
                    f"{relative_source}: temporary Cargo builder is split or indirect; "
                    "rewrite to canonical probe shape"
                )
            continue
        if not temporary:
            if (
                cargo_executable
                and subcommand in COMPILER_SUBCOMMANDS
                and source_has_temporary_project
            ):
                raise GuardError(
                    f"{relative_source}: temporary Cargo setup is outside the builder body; "
                    "rewrite to canonical probe shape"
                )
            continue
        saw_temporary_compiler = True
        if not cargo_executable:
            raise GuardError(
                f"{relative_source}: Cargo executable is indirect; rewrite to canonical probe shape"
            )
        if subcommand in NON_CHECK_SUBCOMMANDS:
            raise GuardError(
                f"{relative_source}: temporary cargo {subcommand} is outside the focused check "
                "contract; extend the focused guard before adding this probe"
            )
        checks.append((body, chain))

    if not checks:
        if saw_temporary_compiler:
            raise GuardError(f"{relative_source}: no canonical temporary Cargo check found")
        return None

    fixture = validate_registration(repo, relative_source, source, tracked)
    validate_canonical_helpers(relative_source, source)
    for body, chain in checks:
        validate_check_body(relative_source, body)
        validate_check_chain(relative_source, chain)
    return Probe(relative_source, fixture, len(checks))


def load_manifest_identity(path: Path) -> tuple[str, str]:
    text = path.read_text()
    match = re.search(r"(?ms)^\[package\]\s*$\n(?P<body>.*?)(?=^\[|\Z)", text)
    if match is None:
        raise GuardError(f"{path}: missing [package] table")
    body = match.group("body")
    names = re.findall(r'^name\s*=\s*"([^"]+)"\s*$', body, re.MULTILINE)
    versions = re.findall(r'^version\s*=\s*"([^"]+)"\s*$', body, re.MULTILINE)
    if len(names) != 1 or len(versions) != 1:
        raise GuardError(f"{path}: package must have exactly one literal name and version")
    return names[0], versions[0]


def one_field(block: str, field: str, required: bool) -> str | None:
    values = re.findall(rf'^{field}\s*=\s*"([^"]*)"\s*$', block, re.MULTILINE)
    expected = "exactly one" if required else "at most one"
    if (required and len(values) != 1) or (not required and len(values) > 1):
        raise GuardError(f"package block must contain {expected} {field}")
    return values[0] if values else None


def load_lock(path: Path) -> list[Package]:
    try:
        text = path.read_text()
    except OSError as error:
        raise GuardError(f"{path}: cannot read lockfile: {error}") from error
    if re.search(r"^version\s*=\s*4\s*$", text, re.MULTILINE) is None:
        raise GuardError(f"{path}: cannot parse canonical Cargo.lock version 4")
    raw_blocks = re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]
    if not raw_blocks:
        raise GuardError(f"{path}: no [[package]] blocks")
    packages = []
    for number, block in enumerate(raw_blocks, start=1):
        try:
            name = one_field(block, "name", True)
            version = one_field(block, "version", True)
            source = one_field(block, "source", False)
            checksum = one_field(block, "checksum", False)
            dependency_sections = re.findall(
                r"(?ms)^dependencies\s*=\s*\[(.*?)\]\s*$", block
            )
            if len(dependency_sections) > 1:
                raise GuardError("package block has multiple dependency arrays")
            dependencies: tuple[str, ...] = ()
            if dependency_sections:
                raw_dependencies = dependency_sections[0]
                without_strings = re.sub(r'"(?:\\.|[^"\\])*"\s*,?', "", raw_dependencies)
                if without_strings.strip():
                    raise GuardError("dependency array must contain only strings")
                dependencies = tuple(rust_strings(raw_dependencies))
            assert name is not None and version is not None
            packages.append(Package(name, version, source, checksum, dependencies))
        except GuardError as error:
            raise GuardError(f"{path}: cannot parse package block {number}: {error}") from error
    return packages


def resolve_dependency(reference: str, packages: list[Package], lock_path: Path) -> Package:
    match = re.fullmatch(r"([^ ]+)(?: ([^ ]+))?(?: \((.+)\))?", reference)
    if match is None:
        raise GuardError(f"{lock_path}: malformed dependency reference {reference!r}")
    name, version, source = match.groups()
    matches = [package for package in packages if package.name == name]
    if version is not None:
        matches = [package for package in matches if package.version == version]
    if source is not None:
        matches = [package for package in matches if package.source == source]
    if len(matches) == 0:
        raise GuardError(f"{lock_path}: unresolved dependency {reference!r}")
    if len(matches) > 1:
        raise GuardError(f"{lock_path}: ambiguous dependency {reference!r}")
    return matches[0]


def reachable_packages(root: Package, packages: list[Package], lock_path: Path) -> set[Package]:
    reachable: set[Package] = set()
    pending = [root]
    while pending:
        package = pending.pop()
        if package in reachable:
            continue
        reachable.add(package)
        for reference in package.dependencies:
            pending.append(resolve_dependency(reference, packages, lock_path))
    return reachable


def verify_fixture_lock(root_lock: Path, fixture_manifest: Path, fixture_lock: Path) -> None:
    manifest_identity = load_manifest_identity(fixture_manifest)
    fixture_packages = load_lock(fixture_lock)
    roots = [
        package
        for package in fixture_packages
        if (package.name, package.version) == manifest_identity
    ]
    if len(roots) == 0:
        raise GuardError(
            f"{fixture_lock}: missing fixture package identity "
            f"{manifest_identity[0]} {manifest_identity[1]}"
        )
    if len(roots) != 1:
        raise GuardError(
            f"{fixture_lock}: expected exactly one fixture package "
            f"{manifest_identity[0]} {manifest_identity[1]}"
        )
    reachable = reachable_packages(roots[0], fixture_packages, fixture_lock)
    unreachable = sorted(
        (package for package in fixture_packages if package not in reachable),
        key=lambda package: (package.name, package.version, package.source or ""),
    )
    if unreachable:
        raise GuardError(
            f"{fixture_lock}: unreachable package {unreachable[0].identity()} from fixture root"
        )

    root_packages = load_lock(root_lock)
    registry_identities = {
        (package.name, package.version, package.source, package.checksum)
        for package in root_packages
        if package.source is not None and package.source.startswith("registry+")
    }
    for package in sorted(reachable, key=lambda item: (item.name, item.version)):
        if package.source is None or not package.source.startswith("registry+"):
            continue
        identity = (package.name, package.version, package.source, package.checksum)
        if identity not in registry_identities:
            raise GuardError(
                f"{fixture_lock}: registry identity {package.identity()} checksum="
                f"{package.checksum!r} is absent from root Cargo.lock"
            )


def realign_fixture(repo: Path, fixture: Path) -> None:
    stage_path: Path | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix=".e0639-lock-realign-", dir=fixture.parent
        ) as raw_work:
            work = Path(raw_work)
            shutil.copyfile(fixture / "Cargo.toml", work / "Cargo.toml")
            shutil.copytree(fixture / "src", work / "src")
            shutil.copyfile(repo / "Cargo.lock", work / "Cargo.lock")
            subprocess.run(
                [
                    os.environ.get("CARGO", "cargo"),
                    "metadata",
                    "--manifest-path",
                    str(work / "Cargo.toml"),
                    "--format-version",
                    "1",
                ],
                cwd=work,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            verify_fixture_lock(
                repo / "Cargo.lock", work / "Cargo.toml", work / "Cargo.lock"
            )
            with tempfile.NamedTemporaryFile(
                prefix=".Cargo.lock.", dir=fixture, delete=False
            ) as stage:
                stage_path = Path(stage.name)
                stage.write((work / "Cargo.lock").read_bytes())
                stage.flush()
                os.fsync(stage.fileno())
            os.replace(stage_path, fixture / "Cargo.lock")
            stage_path = None
    finally:
        if stage_path is not None:
            stage_path.unlink(missing_ok=True)


def main(argv: list[str]) -> None:
    fix, repo = parse_args(argv)
    tracked = tracked_paths(repo)
    probes = []
    for relative_source in source_candidates(tracked):
        probe = inspect_source(repo, relative_source, tracked)
        if probe is not None:
            probes.append(probe)
    if not probes:
        raise GuardError(
            "no direct temporary-downstream Cargo probes found under crates/*/tests/**/*.rs"
        )

    fixtures = sorted({probe.fixture for probe in probes})
    if fix:
        for fixture in fixtures:
            realign_fixture(repo, fixture)

    for fixture in fixtures:
        verify_fixture_lock(repo / "Cargo.lock", fixture / "Cargo.toml", fixture / "Cargo.lock")
    invocation_count = sum(probe.invocation_count for probe in probes)
    print(
        f"compiler probe locks verified: {invocation_count} canonical invocation(s), "
        f"{len(fixtures)} fixture(s)"
    )


try:
    main(sys.argv[1:])
except GuardError as error:
    print(f"check-compiler-probe-locks: {error}", file=sys.stderr)
    raise SystemExit(1)
except (OSError, subprocess.SubprocessError) as error:
    print(f"check-compiler-probe-locks: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
