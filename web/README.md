# NAS 存储分析 — 前端（web/）

React 19 + TypeScript strict + Vite 的 SPA。React Router 管路由，TanStack Query 管服务端缓存，
Ant Design v5（zhCN locale）管交互，ECharts 管图表。无 Redux/Zustand，无 SSR。
依据：`docs/design/01_SPEC.md` 15.1 / 15.4 / 15.8 与 `04_STACK_DECISION.md`。

## 环境

- Node.js 24 LTS（开发机示例：`/Users/zj9495/.nvm/versions/node/v24.21.0`）
- pnpm `10.8.0`（`package.json` 的 `packageManager` 已固定；依赖锁为 `pnpm-lock.yaml`）

## 命令

```bash
pnpm install --frozen-lockfile   # 安装（复现锁文件）
pnpm dev                         # 开发服务器；/api 代理到 http://127.0.0.1:8080
pnpm typecheck                   # tsc -b（strict）
pnpm lint                        # eslint flat config（typescript-eslint + react-hooks）
pnpm test:unit                   # vitest run（jsdom + Testing Library）
pnpm test:e2e                    # 对已运行真实服务执行全部 E2E
pnpm test:e2e:real               # 创建临时源/数据目录，启动真实 Rust + Vite 后执行完整链路
pnpm build                       # tsc -b && vite build -> dist/
```

## 端到端测试说明

`pnpm test:e2e` 始终真实执行，不使用 mock；未设置 `E2E_BASE_URL` 时会显式失败。
默认登录和首次改密链路由启动脚本负责准备测试临时根目录：

```bash
pnpm exec playwright install chromium   # 首次需要下载浏览器
pnpm test:e2e:real
```

`tests/e2e/run-real-e2e.sh` 使用临时数据目录和临时批准挂载，调用 `serve` 启动真实后端，再启动 Vite。
它运行 `real-flow.spec.ts` 的默认登录、首次改密、数据源登记、报告任务、任务/报告等待、
报告详情和 CSV 下载链路；失败时保留临时运行根目录、后端日志和前端日志。可通过
`E2E_CHANGED_PASSWORD` 指定首次改密后的密码，未设置时由脚本随机生成，不会把秘密写入仓库。

## 目录结构（spec 15.4）

```text
src/app/          providers（QueryClient/antd zhCN）、router、RequireAuth 守卫、布局
src/features/     auth（login/change-password/useMe）、overview、sources、profiles、jobs、
                  reports（列表 + :id 详情）、cleanup、settings、diagnostics
src/api/          client.ts（同源 fetch 封装）、errors.ts（ApiError）、types.ts（契约 DTO）、
                  schema.d.ts（由 api/openapi.yaml 生成）
src/components/   QueryState（加载/错误/空状态）、PageHeader
src/lib/          format.ts（BigInt 安全的字节/数字格式化）、querySpec.ts（可复现
                  QuerySpec 序列化）、useECharts.ts（dispose + ResizeObserver 清理）
tests/e2e/        Playwright 用例
```

## 接口契约要点（spec 15.8）

- 同源 cookie 凭据；已建立会话后 mutation 自动携带 `nas_csrf` cookie 中的 CSRF 头。
  登录由服务端下发会话与 CSRF cookie。
- 每个请求生成并发送 `X-Request-ID`；错误响应解析统一错误信封
  `{ error: { code, message, details }, request_id }` 为 `ApiError`（稳定错误码）。
- 成功响应严格解析统一信封 `{ data, meta, request_id }`；列表 `data` 为数组，
  分页字段位于 `meta`。
- 401 全局跳转 `/login` 并清空用户查询缓存；首次登录改密由 `must_change_password` 状态驱动。
- QueryState 明确区分 401 / 403（权限/只读）/ 410（历史明细过期）/ 503（服务不可用），
  不会把错误渲染成“没有文件”。
- mutation 不自动重试；扫描/清理等只由显式用户动作触发。
- 字节数在 DTO 中为十进制字符串；格式化与比较使用 BigInt，不经过 `Number()`。

## 页面接线范围

- 登录和首次改密使用 OpenAPI 中定义的真实认证路径和 envelope DTO。
- 数据源支持批准挂载选择、登记和只读探测；报告任务支持创建与手动运行；任务中心支持
  状态刷新和 pause/resume/cancel/retry 控制。
- 报告、设置、诊断与审计、清理预览和隔离恢复均已接入对应 API。危险清理执行仍由服务端
  再认证、确认文本和幂等键约束。
- 当前 Rust 路由仍会对尚未实现的后端资源返回契约规定的稳定 404；前端不会以假数据或
  空成功响应掩盖该状态。
