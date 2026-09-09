# 交给 Codex 的启动指令

将本设计包完整放进新项目目录后，向 Codex 发送下面的文字。建议第一轮完成 M0–M1，以真实可运行基础为目标；后续按阶段继续，而不是让模型一次输出一堆无法验证的页面代码。

```text
请实现本目录设计的 NAS Storage Analyzer，用 Docker 部署在绿联 NAS 上。

先完整阅读 AGENTS.md、01_SPEC.md、02_TASKS.md、03_ACCEPTANCE.md、04_STACK_DECISION.md，以及 deploy/ 和 contracts/ 下的文件。以这些文档为功能、安全和验收规范；不要只实现页面，不要以 mock 数据充当真实分析。

先检查当前仓库状态。然后完成 M0 和 M1：锁定工具链和依赖、建立 Rust（Axum + Tokio）+ React + TypeScript + SQLite（rusqlite bundled）工程、完整 API 契约和数据迁移、安全临时测试夹具、初始化认证、批准挂载与数据源管理、非 root Docker 基础部署。

采用主规格第 15 节的线程、数据库、React 状态和构建边界；同步扫描/哈希/SQL 不得直接占用 Tokio 核心线程。固定 Cargo.lock、rust-toolchain.toml 和 pnpm-lock.yaml，部署配置采用 v2；不要自行更换技术栈。

默认只读原始目录。不要对真实 NAS 数据运行删除测试，不要使用 privileged、Docker socket、宿主机根挂载、递归 chown/chmod，也不要猜测 UGOS 私有 API。所有文件访问必须通过统一根内安全层。

每阶段必须运行实际测试与构建，记录命令和结果，更新 docs/IMPLEMENTATION_STATUS.md。无法在当前环境验证的硬件或内核能力如实标记，其他能实现和测试的部分继续完成。

最终完整 V1 需要 M0–M8。当前阶段结束时请报告真实完成项、测试结果、剩余工作和下一阶段入口，不要提前宣称全功能实现。
```

## 后续阶段指令

```text
继续按照 AGENTS.md 和设计规格实施。先读取 docs/IMPLEMENTATION_STATUS.md，核对上阶段实际代码与测试状态，再完成下一个未完成阶段。不要重建已有脚手架，不要省略阶段验收，也不要把尚未验证的平台能力写成已支持。
```

## 最后验收指令

```text
请对照 F01–F19 和 03_ACCEPTANCE.md 逐条审计实现。输出需求编号、代码位置、测试位置、实际执行结果和环境限制。重点复核统计口径、硬链接、源离线、报告不可变、完整哈希、清理重新校验、隔离恢复、只读模式、权限和备份恢复。

修复所有可在当前环境重现的阻断问题，重新运行测试和 Docker 冒烟。不得以删除测试、放宽安全边界、伪造通过记录或隐藏未实现功能作为修复。
```
