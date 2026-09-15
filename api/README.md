# API Contract

`openapi.yaml` (OpenAPI 3.1) 是 NAS Storage Analyzer HTTP API 的唯一权威来源（source of truth），
实现以 `docs/design/01_SPEC.md` 第 16、17 节及 `docs/design/contracts/` 为准；任何 API 变更必须先改本文件。

- 统一信封 `{data, meta, request_id}` / `{error:{code,message,details}, request_id}`；错误码见 `ErrorCode` schema。
- 大整数（字节数、inode/device id 等可能超过 2^53 的值）一律为十进制字符串，时间为 RFC3339 + sec/nsec 原始字段。
- OpenAPI 3.1 的可空值使用 JSON Schema 联合类型（`type: [T, 'null']`）或 `anyOf` 加 `type: 'null'` 表达；不得使用 OAS 3.0 的 `nullable` 字段。
- 前端 TypeScript 类型由本文件生成，不手写：

```sh
./gen-ts.sh   # pnpm dlx openapi-typescript api/openapi.yaml -o web/src/api/schema.d.ts
```

前端只从生成的 `web/src/api/schema.d.ts` 导入类型；契约测试以本文件校验后端响应。

契约检查与类型生成：

```sh
pnpm --package=@redocly/cli@1.34.0 dlx redocly lint api/openapi.yaml
./gen-ts.sh
```
