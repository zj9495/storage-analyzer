# Multi-stage build for NAS Storage Analyzer (spec 18.1).
# Use the same default registry mirror as Makefile. Base image digests remain
# pinned; override BASE_REGISTRY to change only the registry source.

ARG BASE_REGISTRY=docker.m.daocloud.io/library
ARG IMAGE_VERSION=local
ARG VCS_REF=unknown

FROM ${BASE_REGISTRY}/rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS rust-build
ARG CARGO_BUILD_JOBS=1
ARG CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=${CARGO_REGISTRIES_CRATES_IO_PROTOCOL}
# The amd64 build runs under QEMU on Apple Silicon. Rust's default lld can
# segfault in that environment; use Debian's GNU bfd linker instead.
ENV RUSTFLAGS="-C link-arg=-fuse-ld=bfd"
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
COPY docs/design/contracts ./docs/design/contracts
RUN --mount=type=cache,id=nas-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=nas-cargo-git,target=/usr/local/cargo/git \
    cargo +1.98.1 build \
      --config 'registries.crates-io.protocol="sparse"' \
      --release --locked -p nas-analyzer

FROM ${BASE_REGISTRY}/node:24.21.0-bookworm-slim@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553 AS web-build
WORKDIR /src
RUN npm install --global pnpm@10.8.0
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web ./
RUN pnpm run build

FROM ${BASE_REGISTRY}/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime
ARG IMAGE_VERSION
ARG VCS_REF
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 nasa && useradd -u 1000 -g nasa -M -s /usr/sbin/nologin nasa \
    && mkdir -p /data /config && chown nasa:nasa /data
COPY --from=rust-build /src/target/release/nas-analyzer /usr/local/bin/nas-analyzer
COPY --from=web-build /src/dist /app/web
LABEL org.opencontainers.image.title="NAS Storage Analyzer" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/nas-analyzer"]
CMD ["serve", "--config", "/config/config.yaml"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/nas-analyzer", "healthcheck", "--url", "http://127.0.0.1:8080/health/ready"]
