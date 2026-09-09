# ADR-001：Rust + React 技术栈决策

状态：已采纳。日期：2026-09-09。适用规格：1.1；部署配置：v2。  
本文件固定技术选择与理由，不替代 `01_SPEC.md` 的业务、安全及接口契约。性能比较是工程判断，未进行同机同数据集 Rust/Go 对照测试。

## 1. 决策

后端使用 Rust stable + Axum + Tokio；前端使用 React + TypeScript strict + Vite；数据库使用本地 SQLite / rusqlite bundled；发布一个 Docker 服务，内含 API 主进程与受控扫描 worker 子进程。

不采用双语言后端，不同时维护两个 Web 框架或两个 SQLite 访问层，不使用 Next.js/SSR，也不把本项目拆成微服务。最终镜像无需 Node。

项目目前交付物是设计规格而不是已经投产的应用；本次属于开工前技术决策，不是假装完成对现有应用的代码迁移。

## 2. Rust 与 Go 的判断

两者均可实现完整产品。若唯一目标是尽快完成报告、调度、邮件、身份配额导入、部署和恢复的全功能闭环，在维护者熟悉程度相近的前提下，Go 是更保守的交付选择；这是对工程复杂度的判断，不是对某个编码模型能力的测评。

选择 Rust 的理由是维护者已明确希望采用 Rust，且扫描引擎长期需要精细控制缓冲、句柄、线程和索引生命周期。Rust 的所有权检查不依赖跟踪式 GC，Send/Sync 对线程间所有权提供编译期约束；这些特性适合作为系统实现的基础。[R1][R2]

代价是必须处理更多所有权、异步/同步边界和 C 依赖构建问题。编译器拒绝问题代码是反馈，不代表产品自动安全；测试、运行期资源控制及未来维护者能理解代码同样重要。

不采用“Rust 必然比 Go 快数倍/内存只有几分之一”的说法。原始目录遍历、stat、磁盘读取、SQLite 写入、索引以及缓存状态的影响必须通过基准拆分。Rust 无 GC 是语言实现事实；最终扫描耗时和总 RSS 是程序与环境的测量结果。

Go 使用并发 GC，并提供 GOMEMLIMIT 等软内存控制；不能把 Go 描述成需要长时间停顿或不能控制内存。该软限制不等于整个进程/容器 RSS 硬限制。[R3]

## 3. 为什么不是混用

第一版不采用“Go API + Rust 扫描器”。虽然技术上可行，但会增加工具链、IPC 契约、发布与错误追踪成本；本项目已经有进程内外边界，不需要再用两种语言表达相同业务类型。

React 与后端语言独立。界面通过 HTTP/SSE 和生成的 TypeScript 类型访问服务；不需要为 React 运行一台 Node 应用服务器。本项目选择 Vite SPA 是因为没有 SSR/SEO 需求，不是在宣称 SPA 对所有 React 项目都优于框架方案。[R7]

## 4. Rust 实施边界

### 4.1 主服务与扫描

Axum/Tokio 负责 HTTP、SSE、调度和 IPC。长期目录遍历、哈希、SQLite writer 采用固定专用线程；短期阻塞工作才进入有并发准入的 spawn_blocking。已开始的 spawn_blocking 不能通过 abort 强制终止，暂停/取消须合作检查。[R4][R5]

禁止每文件一个 task、无界 channel、整文件读入内存或将全部条目收集到 Vec/HashMap。目录 frontier 需要可落盘；有界队列本身不解决生产者互相等待的死锁。

### 4.2 SQLite

统一使用 rusqlite 与显式 SQL。数据库连接由所属工作线程独占；控制库一个 writer，有限读工作线程，扫描索引独立 writer。HTTP 请求只异步等待结果，不能直接执行同步 SQL。

bundled SQLite 需要编译/链接 C 源码。因此选择经过验证的 glibc 镜像作为默认运行基础，发布前分别验证 amd64/arm64 的 Rust/C/SQLite 组合。不将“Rust 可以跨编译”误写成“本项目全部依赖一条命令自动跨编译”。[R6]

### 4.3 文件安全

文件访问依然需要根目录 FD、no-follow/no-cross-mount、原始字节路径、身份验证、清理再认证和动作日志。Rust 能限制安全代码中的内存与部分并发错误，不能阻止另一个程序在核验后替换文件。

这也不是 Go 无法实现的能力；Go 官方已提供 os.Root 等防路径穿越 API。语言不是本项目安全清理的唯一决定因素。[R8]

### 4.4 前端

React Router 管 URL，TanStack Query 管服务端缓存，Ant Design 管交互，ECharts 管图表。业务层不默认增加 Redux/Zustand 或自建全局缓存。

所有 mutation 均由明确用户动作触发。SSE、图表与请求在组件卸载/登出时清理；StrictMode 测试不能导致重复扫描或危险操作。文件选择与 API 绑定 entry_id，不能回传有损展示路径作为权限依据。

## 5. 本次文档迁移清单

| 原设计点 | Rust/React 修订 |
| --- | --- |
| Go/Vue 工程目录与脚手架 | Cargo workspace、独立 fssecure crate、React feature 目录 |
| Go 标准库 HTTP 与 goroutine 思路 | Axum/Tokio + 受控 worker 进程/专用线程 |
| 纯 Go SQLite 驱动 | rusqlite bundled；说明 C 依赖、连接所有权、双架构验证 |
| Vue Router/Pinia/Element Plus | React Router/TanStack Query/Ant Design |
| Go embed 静态资源 | `/app/web` 只读资源由 Rust HTTP 服务提供 |
| Go 软内存 limit 字段 | v2 的 api_memory_budget_mib/worker_memory_budget_mib |
| Go 的构建与质量入口 | Cargo check/clippy/test/release、pnpm、Vitest、Playwright |
| 原 68 条业务/安全验收 | 保留，并新增 ACC-069–ACC-078 十条技术栈验收 |

功能 F01–F19、报告口径、SHA-256 判重、任务状态、只读默认和可写清理安全要求保持不变。没有因为换语言而把平台接口未知项改成已支持。

部署配置迁移：将 config_version 从 1 改为 2，资源项 api_memory_limit_mib 改为 api_memory_budget_mib，worker_memory_limit_mib 改为 worker_memory_budget_mib；值仍以 MiB 表达，但不再解释为 GC 参数。其他 metadata-import schema 版本保持不变。实现尚不存在，无已安装数据库迁移的承诺。

## 6. 性能与发布判断

基准保留原规格目标，不以选择 Rust 为理由自动降低内存数字或提前标记通过。记录主服务与 worker RSS、容器 memory.current、吞吐、数据库大小、队列等待、普通查询延迟与取消耗时。冷/热缓存、磁盘介质和并发设置必须一致。

优先优化扫描算法、索引、批写、缓冲与限速，再讨论底层优化。禁止自写 unsafe、SIMD 或内存分配器作为 M0 的默认目标；需要时以可复现瓶颈和 ADR 论证。

完整发布仍需完成 M0–M8 与 ACC-001–ACC-078。Linux 安全测试、最终双架构镜像启动和真实绿联 NAS 验证是不同层级的证据，不可相互冒充。

## 7. 本次变更验证

设计包交付时可验证 Markdown 引用、需求/验收编号、JSON/YAML 语法、Schema 与示例一致性和 ZIP 校验。它们不验证 Rust 应用已经编译、性能目标达成或 Docker 能直接启动；这些是 Codex 实现后的验收任务。

## 参考资料

核对日期：2026-09-09。下列链接用于核对外部事实；具体技术组合和边界为本项目决策。

- [R1] Rust Ownership：https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html
- [R2] Rust Send/Sync：https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html
- [R3] Go GC Guide：https://go.dev/doc/gc-guide
- [R4] Axum：https://docs.rs/axum/latest/axum/
- [R5] Tokio spawn_blocking：https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- [R6] rusqlite：https://github.com/rusqlite/rusqlite ，https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html
- [R7] React SPA/Vite：https://react.dev/learn/build-a-react-app-from-scratch
- [R8] Go traversal-resistant file APIs：https://go.dev/blog/osroot
