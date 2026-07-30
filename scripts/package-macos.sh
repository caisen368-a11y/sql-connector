#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-}"
output_dir="${2:-dist}"
toolchain="${RUST_TOOLCHAIN:-1.96.1}"
host_arch="$(uname -m)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "package-macos.sh must run on macOS" >&2
  exit 2
fi

if [[ -z "$target" ]]; then
  case "$host_arch" in
    arm64) target="aarch64-apple-darwin" ;;
    x86_64) target="x86_64-apple-darwin" ;;
    *)
      echo "unsupported macOS architecture: $host_arch" >&2
      exit 2
      ;;
  esac
fi

case "$target:$host_arch" in
  aarch64-apple-darwin:arm64) package="sql-connector-macos-aarch64" ;;
  x86_64-apple-darwin:x86_64) package="sql-connector-macos-x86_64" ;;
  *)
    echo "target $target must be packaged on its native macOS architecture" >&2
    exit 2
    ;;
esac

if [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi

cd "$repo_root"
cargo "+$toolchain" build --release --locked --target "$target" -p sql-connector

binary="$repo_root/target/$target/release/sql-connector"
if [[ ! -x "$binary" ]]; then
  echo "release binary was not created: $binary" >&2
  exit 1
fi

mkdir -p "$output_dir"
staging_root="$(mktemp -d "${TMPDIR:-/tmp}/sql-connector-release.XXXXXX")"
trap 'rm -rf "$staging_root"' EXIT
staging_dir="$staging_root/$package"
mkdir "$staging_dir"

cp "$binary" "$staging_dir/sql-connector"
cp README.md SECURITY.md "$staging_dir/"
"$binary" manifests > "$staging_dir/connectors.json"

archive="$output_dir/$package.tar.gz"
tar -czf "$archive" -C "$staging_root" "$package"
archive_hash="$(shasum -a 256 "$archive" | awk '{print $1}')"
printf '%s  %s\n' "$archive_hash" "$package.tar.gz" > "$archive.sha256"

printf '%s\n' "$archive" "$archive.sha256"
