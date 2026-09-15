#!/usr/bin/env bash
# 从 api/openapi.yaml 生成前端 TypeScript 类型（唯一来源，不手写 API 类型）。
# 用法：api/gen-ts.sh（在仓库根目录或任意目录执行均可）
set -euo pipefail

cd "$(dirname "$0")/.."
pnpm dlx openapi-typescript@7.13.0 api/openapi.yaml -o web/src/api/schema.d.ts
