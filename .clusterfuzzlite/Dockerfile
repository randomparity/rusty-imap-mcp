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

COPY . $SRC/rusty-imap-mcp
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/rusty-imap-mcp
