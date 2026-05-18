# ClusterFuzzLite Rust integration for rusty-imap-mcp.
#
# The base-builder-rust image ships nightly Rust + cargo-fuzz pre-installed.
# We copy the whole repo so build.sh can reach all path dependencies needed
# by both cargo-fuzz subcrates:
#   - `fuzz/`                       depends on `crates/rimap-content` and
#                                   `crates/rimap-audit`
#   - `crates/rimap-server/fuzz/`   depends on `crates/rimap-server`
#                                   (features = ["fuzzing"])

FROM gcr.io/oss-fuzz-base/base-builder-rust

# `crates/rimap-server/fuzz/` pulls in the workspace `keyring` crate's
# `linux-native-sync-persistent` backend (transitively, via rimap-server),
# which links against libdbus at build time. Without these packages the
# fuzz build fails with "pkg-config command could not be found" trying to
# resolve `dbus-1`. Same pattern as every Linux Rust job in `ci.yml`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libdbus-1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . $SRC/rusty-imap-mcp
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/rusty-imap-mcp
