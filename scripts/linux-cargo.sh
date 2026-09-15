#!/usr/bin/env bash
# Run cargo inside a Linux container (dev/test parity with the deployment
# target; fssecure's openat2 path and all security tests are Linux-only).
# Usage: scripts/linux-cargo.sh test -p fssecure
set -euo pipefail

IMAGE="${NAS_DEV_IMAGE:-docker.m.daocloud.io/library/rust:1.98.1-bookworm}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

exec docker run --rm \
  -v "$ROOT:/work" \
  -v nas-cargo-registry:/usr/local/cargo/registry \
  -v nas-cargo-git:/usr/local/cargo/git \
  -v nas-target-linux:/work/target-linux \
  -e CARGO_TARGET_DIR=/work/target-linux \
  -w /work \
  "$IMAGE" /bin/sh -c \
  'for cargo_bin in /usr/local/rustup/toolchains/1.98.1-*/bin/cargo; do break; done; for rustc_bin in /usr/local/rustup/toolchains/1.98.1-*/bin/rustc; do break; done; export RUSTC="$rustc_bin"; exec "$cargo_bin" "$@"' \
  linux-cargo "$@"
