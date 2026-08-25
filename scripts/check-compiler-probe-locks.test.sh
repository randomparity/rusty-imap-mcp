#!/usr/bin/env bash
# Contract tests for check-compiler-probe-locks.sh (#838).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
guard="${here}/check-compiler-probe-locks.sh"
tmp="$(mktemp -d)"
trap 'rm -r "$tmp"' EXIT

passed=0

replace() {
    python3 - "$1" "$2" "$3" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text()
if old not in text:
    raise SystemExit(f"missing replacement text in {path}: {old!r}")
path.write_text(text.replace(old, new, 1))
PY
}

expect_ok() {
    local name="$1"
    shift
    local output
    if ! output="$("$@" 2>&1)"; then
        printf 'not ok - %s\n%s\n' "$name" "$output" >&2
        return 1
    fi
    printf 'ok - %s\n' "$name"
    passed=$((passed + 1))
}

expect_fail() {
    local name="$1" expected="$2"
    shift 2
    local output
    if output="$("$@" 2>&1)"; then
        printf 'not ok - %s unexpectedly passed\n%s\n' "$name" "$output" >&2
        return 1
    fi
    if [[ "$output" != *"$expected"* ]]; then
        printf 'not ok - %s missing %q\n%s\n' "$name" "$expected" "$output" >&2
        return 1
    fi
    printf 'ok - %s\n' "$name"
    passed=$((passed + 1))
}

write_source() {
    local repo="$1"
    mkdir -p "$repo/crates/demo/tests"
    cat >"$repo/crates/demo/tests/probe.rs" <<'RS'
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const COMPILER_PROBE_FIXTURE: &str = "tests/fixtures/e0639-probe";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn cargo_bin() -> PathBuf {
    std::env::var("CARGO").map_or_else(|_| PathBuf::from("cargo"), PathBuf::from)
}

fn fixture_root() -> PathBuf {
    crate_root().join(COMPILER_PROBE_FIXTURE)
}

fn copy_fixture_file(fixture: &Path, root: &Path, name: &str) -> Result<(), String> {
    let source = fixture.join(name);
    let destination = root.join(name);
    std::fs::copy(&source, &destination)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn new_probe_root(fixture: &Path) -> TempDir {
    tempfile::Builder::new()
        .tempdir_in(fixture.parent().expect("parent"))
        .expect("temp")
}

fn check_probe() {
    let fixture = fixture_root();
    let dir = new_probe_root(&fixture);
    for name in ["Cargo.toml", "Cargo.lock"] {
        copy_fixture_file(&fixture, dir.path(), name)
            .unwrap_or_else(|error| panic!("{error}"));
    }
    let _ = Command::new(cargo_bin())
        .args(["check", "--locked", "--offline", "--message-format=short"])
        .current_dir(dir.path())
        .output();
}
RS
}

write_locks() {
    local repo="$1"
    cat >"$repo/Cargo.lock" <<'LOCK'
version = 4

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "root-only"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "def"
LOCK
    mkdir -p "$repo/crates/demo/tests/fixtures/e0639-probe/src"
    cat >"$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.toml" <<'TOML'
[package]
name = "probe-fixture"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
dep = "1"

[workspace]
TOML
    cat >"$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock" <<'LOCK'
version = 4

[[package]]
name = "probe-fixture"
version = "0.0.0"
dependencies = [
 "dep",
]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
LOCK
    printf 'fn main() {}\n' >"$repo/crates/demo/tests/fixtures/e0639-probe/src/main.rs"
}

new_repo() {
    local name="$1"
    local repo="$tmp/$name"
    mkdir -p "$repo"
    git -C "$repo" init -q
    git -C "$repo" config user.email test@example.invalid
    git -C "$repo" config user.name test
    write_source "$repo"
    write_locks "$repo"
    git -C "$repo" add .
    printf '%s\n' "$repo"
}

restage() {
    git -C "$1" add -A
}

case_good() {
    local repo
    repo="$(new_repo good)"
    expect_ok "canonical good" "$guard" --repo-root "$repo"
}

case_missing_flags() {
    local repo
    repo="$(new_repo missing-locked)"
    replace "$repo/crates/demo/tests/probe.rs" '"check", "--locked", "--offline"' '"check", "--offline"'
    restage "$repo"
    expect_fail "missing --locked" "missing --locked" "$guard" --repo-root "$repo"

    repo="$(new_repo missing-offline)"
    replace "$repo/crates/demo/tests/probe.rs" '"check", "--locked", "--offline"' '"check", "--locked"'
    restage "$repo"
    expect_fail "missing --offline" "missing --offline" "$guard" --repo-root "$repo"

    repo="$(new_repo flags-after-separator)"
    replace "$repo/crates/demo/tests/probe.rs" '"check", "--locked", "--offline"' '"check", "--", "--locked", "--offline"'
    restage "$repo"
    expect_fail "flags after --" "before Cargo argument separator" "$guard" --repo-root "$repo"
}

case_constructors() {
    local repo source
    repo="$(new_repo std-qualified)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'Command::new(cargo_bin())' 'std::process::Command::new(cargo_bin())'
    restage "$repo"
    expect_ok "qualified std Command" "$guard" --repo-root "$repo"

    repo="$(new_repo std-alias)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'use std::process::Command;' 'use std::process::Command as StdCommand;'
    replace "$source" 'Command::new(cargo_bin())' 'StdCommand::new(cargo_bin())'
    restage "$repo"
    expect_ok "aliased std Command" "$guard" --repo-root "$repo"

    repo="$(new_repo tokio-qualified)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'fn check_probe() {' 'async fn check_probe() {'
    replace "$source" 'Command::new(cargo_bin())' 'tokio::process::Command::new(cargo_bin())'
    replace "$source" '.output();' '.output().await;'
    restage "$repo"
    expect_ok "qualified awaited Tokio Command" "$guard" --repo-root "$repo"

    repo="$(new_repo tokio-imported)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'use std::process::Command;' 'use tokio::process::Command;'
    replace "$source" 'fn check_probe() {' 'async fn check_probe() {'
    replace "$source" '.output();' '.status().await;'
    restage "$repo"
    expect_ok "imported awaited Tokio Command" "$guard" --repo-root "$repo"

    repo="$(new_repo tokio-alias)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'use std::process::Command;' 'use tokio::process::Command as TokioCommand;'
    replace "$source" 'fn check_probe() {' 'async fn check_probe() {'
    replace "$source" 'Command::new(cargo_bin())' 'TokioCommand::new(cargo_bin())'
    replace "$source" '.output();' '.output().await;'
    restage "$repo"
    expect_ok "aliased awaited Tokio Command" "$guard" --repo-root "$repo"

    repo="$(new_repo cargo-literal)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'Command::new(cargo_bin())' 'Command::new("cargo")'
    restage "$repo"
    expect_ok "Cargo literal" "$guard" --repo-root "$repo"

    repo="$(new_repo cargo-pathbuf)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'Command::new(cargo_bin())' 'Command::new(PathBuf::from("cargo"))'
    restage "$repo"
    expect_ok "Cargo PathBuf" "$guard" --repo-root "$repo"
}

case_noncanonical() {
    local repo source subcommand
    repo="$(new_repo split-builder)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'let _ = Command::new(cargo_bin())
        .args(["check", "--locked", "--offline", "--message-format=short"])
        .current_dir(dir.path())
        .output();' 'let mut command = Command::new(cargo_bin());
    command.args(["check", "--locked", "--offline"]);
    command.current_dir(dir.path());
    let _ = command.output();'
    restage "$repo"
    expect_fail "split builder" "rewrite to canonical" "$guard" --repo-root "$repo"

    repo="$(new_repo arbitrary-helper)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'Command::new(cargo_bin())' 'Command::new(other_cargo())'
    restage "$repo"
    expect_fail "arbitrary Cargo helper" "rewrite to canonical" "$guard" --repo-root "$repo"

    repo="$(new_repo mismatched-root)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" '.current_dir(dir.path())' '.current_dir(other.path())'
    restage "$repo"
    expect_fail "mismatched command root" "same temporary root" "$guard" --repo-root "$repo"

    repo="$(new_repo mixed-builders)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" '    let _ = Command::new(cargo_bin())' '    let _second = Command::new(cargo_bin())
        .args(["check", "--locked"])
        .current_dir(dir.path())
        .output();
    let _ = Command::new(cargo_bin())'
    restage "$repo"
    expect_fail "mixed good and missing offline" "missing --offline" "$guard" --repo-root "$repo"

    repo="$(new_repo split-setup)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'let dir = new_probe_root(&fixture);' 'let dir = prepared_root();'
    restage "$repo"
    expect_fail "split setup" "rewrite to canonical" "$guard" --repo-root "$repo"

    for subcommand in build test bench run rustc clippy fix; do
        repo="$(new_repo "non-check-$subcommand")"
        source="$repo/crates/demo/tests/probe.rs"
        replace "$source" '"check", "--locked", "--offline"' "\"$subcommand\", \"--locked\", \"--offline\""
        restage "$repo"
        expect_fail "non-check $subcommand" "extend the focused guard" "$guard" --repo-root "$repo"
    done
}

case_metadata_exclusions() {
    local repo source
    repo="$(new_repo metadata-same-body)"
    source="$repo/crates/demo/tests/probe.rs"
    cat >>"$source" <<'RS'

fn metadata_probe() {
    let dir = tempfile::TempDir::new().expect("temp");
    std::fs::write(dir.path().join("Cargo.toml"), "[workspace]").expect("manifest");
    let _ = Command::new(cargo_bin())
        .args(["metadata", "--format-version", "1"])
        .current_dir(dir.path())
        .output();
}
RS
    restage "$repo"
    expect_ok "metadata excluded with same-body setup" "$guard" --repo-root "$repo"

    repo="$(new_repo metadata-other-body)"
    source="$repo/crates/demo/tests/probe.rs"
    cat >>"$source" <<'RS'

fn metadata_only() {
    let _ = Command::new(cargo_bin())
        .args(["metadata", "--format-version", "1"])
        .output();
}
RS
    restage "$repo"
    expect_ok "metadata excluded from other-body setup" "$guard" --repo-root "$repo"
}

case_discovery_exclusions() {
    local repo
    repo="$(new_repo discovery-exclusions)"
    mkdir -p "$repo/crates/demo/src"
    cat >"$repo/crates/demo/src/lib.rs" <<'RS'
fn excluded() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let _ = std::process::Command::new("cargo")
        .args(["build"])
        .current_dir(dir.path())
        .output();
}
RS
    cat >"$repo/crates/demo/build.rs" <<'RS'
fn main() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let _ = std::process::Command::new("cargo")
        .args(["test"])
        .current_dir(dir.path())
        .output();
}
RS
    restage "$repo"
    expect_ok "crate src and build.rs excluded" "$guard" --repo-root "$repo"
}

case_registration_and_files() {
    local repo source fixture
    repo="$(new_repo missing-registration)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'const COMPILER_PROBE_FIXTURE: &str = "tests/fixtures/e0639-probe";' ''
    restage "$repo"
    expect_fail "missing registration" "COMPILER_PROBE_FIXTURE" "$guard" --repo-root "$repo"

    repo="$(new_repo duplicate-registration)"
    source="$repo/crates/demo/tests/probe.rs"
    printf '\nconst COMPILER_PROBE_FIXTURE: &str = "tests/fixtures/other";\n' >>"$source"
    restage "$repo"
    expect_fail "duplicate registration" "exactly one COMPILER_PROBE_FIXTURE" "$guard" --repo-root "$repo"

    repo="$(new_repo absolute-registration)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'tests/fixtures/e0639-probe' '/tmp/probe'
    restage "$repo"
    expect_fail "absolute registration" "relative path" "$guard" --repo-root "$repo"

    repo="$(new_repo escaping-registration)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" 'tests/fixtures/e0639-probe' '../outside'
    restage "$repo"
    expect_fail "escaping registration" "must not escape" "$guard" --repo-root "$repo"

    repo="$(new_repo untracked-registration)"
    fixture="$repo/crates/demo/tests/fixtures/e0639-probe"
    git -C "$repo" rm -q --cached "$fixture/Cargo.toml" "$fixture/Cargo.lock" \
        "$fixture/src/main.rs"
    expect_fail "untracked registration" "missing tracked fixture file" "$guard" --repo-root "$repo"

    for name in Cargo.toml Cargo.lock src/main.rs; do
        repo="$(new_repo "missing-${name//\//-}")"
        fixture="$repo/crates/demo/tests/fixtures/e0639-probe"
        rm "$fixture/$name"
        restage "$repo"
        expect_fail "missing fixture $name" "missing tracked fixture file" "$guard" --repo-root "$repo"
    done

    repo="$(new_repo missing-manifest-copy)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" '["Cargo.toml", "Cargo.lock"]' '["Cargo.lock"]'
    restage "$repo"
    expect_fail "missing manifest copy" "copy Cargo.toml and Cargo.lock" "$guard" --repo-root "$repo"

    repo="$(new_repo missing-lock-copy)"
    source="$repo/crates/demo/tests/probe.rs"
    replace "$source" '["Cargo.toml", "Cargo.lock"]' '["Cargo.toml"]'
    restage "$repo"
    expect_fail "missing lock copy" "copy Cargo.toml and Cargo.lock" "$guard" --repo-root "$repo"
}

case_lock_graphs() {
    local repo lock root
    repo="$(new_repo malformed-lock)"
    lock="$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock"
    replace "$lock" 'name = "dep"' '# missing dep name'
    restage "$repo"
    expect_fail "malformed lock" "cannot parse" "$guard" --repo-root "$repo"

    repo="$(new_repo empty-lock)"
    lock="$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock"
    printf 'version = 4\n' >"$lock"
    restage "$repo"
    expect_fail "empty lock" "no [[package]]" "$guard" --repo-root "$repo"

    repo="$(new_repo missing-fixture-root)"
    lock="$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock"
    replace "$lock" 'name = "probe-fixture"' 'name = "other-fixture"'
    restage "$repo"
    expect_fail "missing fixture root" "fixture package identity" "$guard" --repo-root "$repo"

    repo="$(new_repo duplicate-fixture-root)"
    lock="$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock"
    cat >>"$lock" <<'LOCK'

[[package]]
name = "probe-fixture"
version = "0.0.0"
LOCK
    restage "$repo"
    expect_fail "duplicate fixture root" "exactly one fixture package" "$guard" --repo-root "$repo"

    repo="$(new_repo unresolved-edge)"
    lock="$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock"
    replace "$lock" '"dep",' '"missing",'
    restage "$repo"
    expect_fail "unresolved dependency edge" "unresolved dependency" "$guard" --repo-root "$repo"

    repo="$(new_repo unreachable-package)"
    lock="$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock"
    cat >>"$lock" <<'LOCK'

[[package]]
name = "orphan"
version = "9.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "orphan"
LOCK
    restage "$repo"
    expect_fail "unreachable package" "unreachable package" "$guard" --repo-root "$repo"

    repo="$(new_repo root-seed-plus-fixture)"
    lock="$repo/crates/demo/tests/fixtures/e0639-probe/Cargo.lock"
    cat "$repo/Cargo.lock" >"$lock"
    cat >>"$lock" <<'LOCK'

[[package]]
name = "probe-fixture"
version = "0.0.0"
dependencies = [
 "dep",
]
LOCK
    restage "$repo"
    expect_fail "root seed plus fixture block" "unreachable package" "$guard" --repo-root "$repo"

    repo="$(new_repo registry-missing)"
    root="$repo/Cargo.lock"
    replace "$root" 'name = "dep"' 'name = "different"'
    restage "$repo"
    expect_fail "registry identity absent" "absent from root Cargo.lock" "$guard" --repo-root "$repo"

    repo="$(new_repo registry-checksum)"
    root="$repo/Cargo.lock"
    replace "$root" 'checksum = "abc"' 'checksum = "changed"'
    restage "$repo"
    expect_fail "registry checksum drift" "absent from root Cargo.lock" "$guard" --repo-root "$repo"

    repo="$(new_repo root-extra-valid)"

    expect_ok "root-only package is valid" "$guard" --repo-root "$repo"
}
case_atomic_fix() {
    local repo fixture lock fake output before
    repo="$(new_repo atomic-fix-success)"
    fixture="$repo/crates/demo/tests/fixtures/e0639-probe"
    lock="$fixture/Cargo.lock"
    cat "$repo/Cargo.lock" >"$lock"
    cat >>"$lock" <<'LOCK'

[[package]]
name = "probe-fixture"
version = "0.0.0"
dependencies = [
 "dep",
]
LOCK
    restage "$repo"
    fake="$repo/fake-cargo-success"
    cat >"$fake" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
manifest=
while (($#)); do
  if [[ "$1" == "--manifest-path" ]]; then
    manifest="$2"
    shift 2
  else
    shift
  fi
done
cat >"$(dirname "$manifest")/Cargo.lock" <<'LOCK'
version = 4

[[package]]
name = "probe-fixture"
version = "0.0.0"
dependencies = [
 "dep",
]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
LOCK
SH
    chmod +x "$fake"
    expect_ok "atomic fix prunes root seed" env CARGO="$fake" "$guard" --fix --repo-root "$repo"
    if [[ "$(cat "$lock")" == *"root-only"* ]]; then
        printf 'not ok - atomic fix retained root-only package\n' >&2
        return 1
    fi

    repo="$(new_repo atomic-fix-cargo-failure)"
    fixture="$repo/crates/demo/tests/fixtures/e0639-probe"
    lock="$fixture/Cargo.lock"
    printf 'original cargo failure bytes\n' >"$lock"
    restage "$repo"
    before="$(shasum -a 256 "$lock")"
    fake="$repo/fake-cargo-failure"
    printf '#!/usr/bin/env bash\nexit 42\n' >"$fake"
    chmod +x "$fake"
    if output="$(CARGO="$fake" "$guard" --fix --repo-root "$repo" 2>&1)"; then
        printf 'not ok - Cargo failure unexpectedly passed\n%s\n' "$output" >&2
        return 1
    fi
    if [[ "$(shasum -a 256 "$lock")" != "$before" ]]; then
        printf 'not ok - Cargo failure changed original lock\n' >&2
        return 1
    fi
    printf 'ok - Cargo failure preserves original lock\n'
    passed=$((passed + 1))

    repo="$(new_repo atomic-fix-stage-failure)"
    fixture="$repo/crates/demo/tests/fixtures/e0639-probe"
    lock="$fixture/Cargo.lock"
    printf 'original stage failure bytes\n' >"$lock"
    restage "$repo"
    before="$(shasum -a 256 "$lock")"
    fake="$repo/fake-cargo-success"
    cp "$tmp/atomic-fix-success/fake-cargo-success" "$fake"
    chmod +x "$fake"
    chmod 500 "$fixture"
    if output="$(CARGO="$fake" "$guard" --fix --repo-root "$repo" 2>&1)"; then
        chmod 700 "$fixture"
        printf 'not ok - stage failure unexpectedly passed\n%s\n' "$output" >&2
        return 1
    fi
    chmod 700 "$fixture"
    if [[ "$(shasum -a 256 "$lock")" != "$before" ]]; then
        printf 'not ok - stage failure changed original lock\n' >&2
        return 1
    fi
    printf 'ok - stage failure preserves original lock\n'
    passed=$((passed + 1))
}

case_empty_discovery() {
    local repo
    repo="$tmp/empty-discovery"
    mkdir -p "$repo"
    git -C "$repo" init -q
    printf 'version = 4\n' >"$repo/Cargo.lock"
    git -C "$repo" add Cargo.lock
    expect_fail "empty discovery" "no direct temporary-downstream Cargo probes" "$guard" --repo-root "$repo"
}

case_good
case_missing_flags
case_constructors
case_noncanonical
case_metadata_exclusions
case_discovery_exclusions
case_registration_and_files
case_lock_graphs
case_atomic_fix
case_empty_discovery
printf 'all check-compiler-probe-locks.sh tests passed (%d cases)\n' "$passed"
