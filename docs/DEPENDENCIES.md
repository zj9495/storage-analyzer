# DEPENDENCIES

规格 15.1 要求记录工具链、依赖版本、基础镜像 digest 与许可证要点。锁文件（Cargo.lock、
web/pnpm-lock.yaml）是复现依据；本文件是人工可读摘要，随 M8 发布审计更新。

## 工具链

- Rust：1.98.1（rust-toolchain.toml 固定 channel + rustfmt/clippy）
- Node.js：v24.21.0（LTS；仅用于前端构建，运行镜像不含 Node）
- pnpm：10.8.0（web/package.json packageManager 固定）
- SQLite：rusqlite bundled（libsqlite3-sys 0.30.1 内嵌 C 源码，实际引擎版本见 Cargo.lock 对应绑定文档）

## 基础镜像（构建/运行）

本机 Docker Hub 直连被网络阻断，基础镜像通过镜像站核对后按规范名使用；
Dockerfile 使用下表的多架构索引 digest，避免浮动 tag。下方 digest 于 2026-09-10
在 arm64 主机上通过 `docker buildx imagetools inspect` 观察；生产发布仍需在可访问
官方仓库的 CI 中复核同一内容摘要。

| 用途 | Dockerfile 引用 | 多架构索引 digest | linux/amd64 子镜像 | linux/arm64 子镜像 |
| --- | --- | --- | --- | --- |
| Rust 构建 | `rust:1.98.1-bookworm` | `sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa` | `sha256:cdb2da72943ec036bf0c731ef5ac9e5fb2b1d17d3a9256a581bad64cf6fc093d` | `sha256:09e98f39fa15751de9476fefafe4be0e4ef92b292d608410595bbbde9ebdd375` |
| 前端构建 | `node:24.21.0-bookworm-slim` | `sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553` | `sha256:713cfbf4a0ac19f40e1bb9919893e126b74a5c8cf5d0623c9f89515c8f74c6fa` | `sha256:8d1405ad7696efa6941cb7745c2aa51d02549b900e4a40fdf212a1b5115dd1b9` |
| 运行基础 | `debian:bookworm-slim` | `sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171` | `sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867` | `sha256:6bd27d44e6c32a66bbd72d7cb2b76a8ae3497ec2e5274a81abd1b37f6013fa1f` |

M8 发布前需在可访问 Docker Hub 的 CI 上复验上述 `repo@sha256:...` 引用、构建两个
目标架构并执行启动冒烟；本地镜像加载或 OCI 归档不等同于仓库发布。

## 主要 Rust 依赖（节选，精确版本见 Cargo.lock）

axum 0.8 / tokio 1.53 / rusqlite 0.32(bundled) / rustix 1.1 / serde 1 / thiserror 2 /
tracing 0.1 / clap 4 / sha2 0.10 / argon2 0.5 / uuid 1 / jiff 0.2 / cron 0.15 /
lettre 0.11(rustls) / zip 2 / globset 0.4 / jsonschema 0.30 / crossbeam-channel 0.5 /
parking_lot 0.12 / ureq 3(rustls) / tempfile 3 / rand 0.9

## 前端依赖（节选，精确版本见 web/pnpm-lock.yaml）

react 19.2 / react-router-dom 7 / @tanstack/react-query 5 / antd 5.29 / echarts 5.6 /
vite 6 / typescript 5.8 / vitest 3 / playwright（见 web/package.json）

## 许可证与 SBOM

审计入口是 `make dependency-audit`（脚本：`scripts/dependency-audit.sh`）。它要求
`cargo-about 0.9.2`、`cargo-cyclonedx 0.5.9`，使用 `Cargo.lock`、`web/pnpm-lock.yaml`
和 `about.toml`，以 `--frozen`/无锁文件更新方式生成 Rust SPDX 许可证 JSON、前端生产
依赖许可证表，以及两个 CycloneDX 1.5 JSON。默认输出到被忽略的
`artifacts/dependencies/`；目标架构可通过 `SBOM_TARGET` 指定，生成时间基准通过
`SBOM_SOURCE_DATE_EPOCH` 指定。默认目标是 `x86_64-unknown-linux-gnu`，发布 CI 应分别
以 `x86_64-unknown-linux-gnu` 和 `aarch64-unknown-linux-gnu` 运行并保留对应构建归档。

2026-09-13 已在本机执行同等工具命令：`cargo-about 0.9.2` 的 `--frozen --fail`
许可证解析成功（Rust graph 367 crates、3 个 license groups），`pnpm --dir web
licenses list --prod` 成功；生成物为审计输出而非源码输入，当前主线仍需用
`make dependency-audit` 统一重跑并保存 CI artifact。许可证报告不代表漏洞扫描；
依赖漏洞、基础镜像和 bundled SQLite 仍需在发布 CI 另行审查。
