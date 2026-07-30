#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

manifest_file="$(mktemp)"
trap 'rm -f "${manifest_file}"' EXIT
cargo run --locked -q -p sql-connector -- manifests >"${manifest_file}"
test -s "${manifest_file}"
