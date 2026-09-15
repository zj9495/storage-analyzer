#!/usr/bin/env bash
# Reproducible Rust/React dependency license and SBOM audit (M8).
#
# The report directory is intentionally explicit in the output.  The generated
# files are build artifacts, not source inputs; rerun this script in CI after
# changing either lock file.  No dependency resolver is allowed to update a
# lock file in this command.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${SBOM_OUTPUT_DIR:-$ROOT_DIR/artifacts/dependencies}"
SBOM_TARGET="${SBOM_TARGET:-x86_64-unknown-linux-gnu}"
SBOM_SOURCE_DATE_EPOCH="${SBOM_SOURCE_DATE_EPOCH:-0}"

cd "$ROOT_DIR"

command -v cargo-about >/dev/null 2>&1 || {
  echo >&2 'cargo-about 0.9.2 is required; install the pinned audit tool before running this target'
  exit 2
}
command -v cargo-cyclonedx >/dev/null 2>&1 || {
  echo >&2 'cargo-cyclonedx 0.5.9 is required; install the pinned audit tool before running this target'
  exit 2
}

case "$(cargo about --version)" in
  'cargo-about 0.9.2') ;;
  *) echo >&2 'cargo-about version must be exactly 0.9.2'; exit 2 ;;
esac
case "$(cargo cyclonedx --version)" in
  *' 0.5.9') ;;
  *) echo >&2 'cargo-cyclonedx version must be exactly 0.5.9'; exit 2 ;;
esac

mkdir -p "$OUTPUT_DIR"

# cargo-about has the SPDX/license-file resolution logic for the Rust graph.
# --frozen means --locked plus offline: this is an audit of the checked-in
# Cargo.lock and never a request to resolve a newer graph.
cargo about generate \
  --workspace \
  --format json \
  --config "$ROOT_DIR/about.toml" \
  --frozen \
  --fail \
  --output-file "$OUTPUT_DIR/rust-licenses.json"

# pnpm reports the production dependency license set without machine-local
# node_modules paths in its tabular form.
pnpm --dir web licenses list --prod > "$OUTPUT_DIR/frontend-licenses.txt"

# cargo-cyclonedx writes one file beside each workspace member manifest.  A
# single workspace invocation with one temporary basename keeps the two
# generated files paired to the same dependency graph; move both known files
# into the requested report directory afterwards.
SOURCE_DATE_EPOCH="$SBOM_SOURCE_DATE_EPOCH" cargo cyclonedx \
  --manifest-path "$ROOT_DIR/crates/nas-analyzer/Cargo.toml" \
  --format json \
  --spec-version 1.5 \
  --target "$SBOM_TARGET" \
  --override-filename rust-dependency-sbom \
  --quiet
mv -- "$ROOT_DIR/crates/fssecure/rust-dependency-sbom.json" "$OUTPUT_DIR/fssecure.cdx.json"
mv -- "$ROOT_DIR/crates/nas-analyzer/rust-dependency-sbom.json" "$OUTPUT_DIR/nas-analyzer.cdx.json"

printf 'dependency audit complete: %s (target=%s, source_date_epoch=%s)\n' \
  "$OUTPUT_DIR" "$SBOM_TARGET" "$SBOM_SOURCE_DATE_EPOCH"
