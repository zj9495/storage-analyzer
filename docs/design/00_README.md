# NAS Storage Analyzer — Codex 实施设计包

技术修订日期：2026-09-09；规格版本：1.1（Rust + React）；部署配置：v2。

用于独立实现群晖 Storage Analyzer 的公开分析与报告能力，并通过 Docker 部署到支持该功能的绿联 NAS。采用 Rust（Axum + Tokio）+ React / TypeScript + SQLite（rusqlite）的单容器方案。产品功能资料沿用 2026-09-08 对标基线。

**这是设计与验收输入，不是已经开发完成的软件。这里没有已发布镜像，也没有声称已在用户 NAS 上测试通过。**

## 文件导航

| 文件 | 用途 |
| --- | --- |
| `01_SPEC.md` | 主规格：19 项功能追踪、页面流程、统计口径、重复算法、清理、数据模型、接口、部署和运维 |
| `02_TASKS.md` | M0–M8 共 9 个阶段；每阶段任务、依赖和完成门槛 |
| `03_ACCEPTANCE.md` | 78 条验收用例（保留原 68 条并新增 10 条）、黄金夹具、端到端流程与基准模板 |
| `04_STACK_DECISION.md` | Rust/Go 取舍、Rust/React 实施边界、配置迁移与变更清单 |
| `AGENTS.md` | 放在仓库根目录，让 Codex 持续遵守安全与工程约束 |
| `CODEX_START.md` | 可以复制给 Codex 的首次、续作与验收指令 |
| `deploy/compose.example.yaml` | 实现完成后的安全部署模板，不是现成应用 |
| `deploy/config.example.yaml` | 容器内批准挂载、只读边界、资源和采样配置 |
| `deploy/.env.example` | 真实 NAS 路径、UID/GID、绑定地址、时区等输入 |
| `contracts/` | 部署/元数据导入 JSON Schema、领域枚举和请求示例 |

## 使用方法

把本目录全部文件放入项目仓库根部，保留 AGENTS.md；从 CODEX_START.md 复制首次指令，先实现 M0–M1，之后按阶段推进。完整 V1 是 M0–M8，而不是完成一个仪表盘页面。

开发前用户需要最终确定的环境参数是：NAS 架构和可用资源、真实共享目录路径、专用运行 UID/GID、应用数据目录与时区。没有这些参数不妨碍在本地实现与自动测试；部署时必须替换示例，不能猜测。

## 重要边界

默认只读原始数据；需要整理重复文件时，另行开启可写模式并完成安全验收。先隔离再决定永久清理；隔离不释放空间。备份仓库、硬链接、变化文件、分层占位文件不能被简单当成可删除副本。

系统账号、真实配额和分层存储依赖平台能力。V1 提供真实可用的导入与能力检测；不把人工预算说成系统配额，不声称通用容器天然获得全部 UGOS/DSM 原生接口。

报告容量分为文件逻辑量、已分配估算和卷用量。快照/共享块/预留空间会使这些数字不相等；相关口径已经写入主规格。

## 部署模板提示

`.env.example` 默认把服务绑定到 127.0.0.1。需要从电脑浏览器访问时，应改为 NAS 的实际局域网 IP；不要为省事直接暴露到公网。APP_UID/GID=1000 只是示例，必须确认实际权限。

`/replace/...` 是刻意设置的无效占位路径。模板使用 create_host_path=false，防止路径写错后 Docker 自动创建空目录，让程序误判成没有文件。生产配置须在真实目录准备好后部署。

`nas-storage-analyzer:local` 表示 Codex 实现并构建后的本地镜像。不得把这个名字当成已经存在的 Docker Hub 项目。

## 本设计包的核验范围

交付前检查 Markdown 文件和编号完整性、JSON/YAML 语法、两个 JSON Schema 与示例的一致性、黄金数据算术及 ZIP 文件完整性。这些检查只验证设计工件，不等于应用构建、Docker 部署、扫描正确性或 NAS 实机验收已经完成。

参考资料集中列于主规格第 22 节，来自群晖、绿联、Docker、Rust、React、Tokio、Node.js、SQLite、Linux man-pages 和 Btrfs 官方/维护者文档；Rust/Go 取舍另见 ADR 的来源。

## 规格 1.1 的使用提醒

此包替代原 Go/Vue 技术方案，不需要把两个版本混合交给 Codex。原始版本保留不变；这里仅修订设计和实现约束，没有应用代码迁移或构建结果。

请使用本包的 deploy/config.example.yaml：config_version=2，采用 api_memory_budget_mib 与 worker_memory_budget_mib。预算控制、监测与超限处置必须实现，不能把 Rust 不存在的 GC 参数当作资源保护。

新增 Rust/React 专项 ACC-069–ACC-078，仍需完成全部 F01–F19 和 M0–M8。锁定工具链、Cargo/Pnpm 锁文件、双架构编译和 NAS 实机验收均由后续实现阶段执行。

`VALIDATION.md` 记录本次设计工件检查结果，不是成品软件测试报告。
