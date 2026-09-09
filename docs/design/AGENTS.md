# AGENTS.md — NAS Storage Analyzer 实施约束

## 先读文件

先完整阅读 `01_SPEC.md`、`02_TASKS.md`、`03_ACCEPTANCE.md`、`04_STACK_DECISION.md`，再查看 `deploy/` 和 `contracts/`。本目录是设计输入，不是已经实现好的应用。不要把模板文件存在当作功能已经完成。

目标是独立复现群晖 Storage Analyzer 的公开功能并通过 Docker 部署在绿联 NAS。以主规格的 F01–F19 为追踪对象。未获得真实设备信息时，使用可配置路径、UID/GID 和能力检测，不猜测绿联私有 API。

## 安全不变量

默认只读分析；不挂载 Docker socket，不要求 privileged，不扫描宿主机 `/`，不读取 `/etc/shadow`。不得对真实数据运行删除测试、递归 chown/chmod 或格式化命令。

测试写操作只能发生在测试创建的临时根目录。清理必须经过部署和源双开关、近期重新认证、预览计划、内容与身份重新校验。只处理批准范围内的普通文件。禁止跟随符号链接、跨挂载写操作、硬链接自动清理和跨设备复制后删除。

不信任来自浏览器的文件路径；用 entry_id 到服务器存储的原始路径映射。禁止 shell 拼接路径。创建文件、哈希、rename、恢复和 purge 必须经过统一 fssecure 层。

隔离不是释放空间。隔离恢复默认不得覆盖已有文件。不能依据报告旧哈希或抽样哈希删除。备份仓库、活动数据库与分层占位文件默认受保护。

## 数据与产品语义

区分逻辑字节、已分配估算、卷容量、配额与人工预算。无法取得的信息返回 null/unknown，不造假。硬链接多个路径不等于多份内容。最久未访问不代表一定无用；ctime 不等于创建时间。

扫描是时间窗口观察，不是原子快照。源离线或权限不足必须产生 unavailable/partial，不返回 0 冒充真实统计。应用管理员不等于 NAS 用户。

报告不可变，范围和分类规则版本化；通知独立 outbox。CSV、表格与图表使用同一 QuerySpec。大整数不经过 JavaScript number 丢精度。保留期结束的明细返回 DETAIL_EXPIRED，不假装空结果。

SQLite 使用本地磁盘和单实例；目录队列、读缓冲、写批次与事件流必须有界。不可把百万文件全装入内存，也不可整文件读取后哈希。

## 工作流程

1. 核对仓库现状。已有项目不能被覆盖成另一个脚手架；先列出差异与拟修改范围。
2. 从 M0 开始，按 `02_TASKS.md` 顺序实施。每阶段先列出关联需求与测试，再写代码。
3. 每个阶段交付真实可运行纵切功能，不能只实现页面和 mock API。
4. 修改数据模型同时补迁移，修改 API 同时补 OpenAPI 和契约测试，修改安全层同时补反例测试。
5. 每阶段运行相关测试、静态检查和构建。记录实际执行的命令、结果与未运行原因；不能说“测试通过”而没有执行。
6. 更新 `docs/IMPLEMENTATION_STATUS.md`：需求编号、实现路径、测试路径、通过情况、环境限制、下一阶段。
7. 不在完成只读阶段时宣称全功能完成。V1 必须覆盖 M0–M8；平台原生接口的未知能力必须如实标识。

## 工程要求

Rust 后端（Axum + Tokio）、React + TypeScript + Vite 前端、本地 SQLite（rusqlite bundled）、单容器。禁止自行退回原技术栈或混用第二种后端语言。固定 Rust 工具链、Cargo.lock、pnpm-lock.yaml 和基础镜像 digest；不依赖生产浮动 latest。

同步扫描、哈希与 SQL 不得直接运行在 Tokio 核心线程；长期工作使用专用线程，有界队列与合作取消；不得每文件一个 task。SQLite 连接单线程拥有；不通过 unsafe Send/Sync 消除编译错误。

路径按原始字节和根目录 FD 操作，展示字符串不能反向授权文件操作。release 下做明确溢出检查。所有权/类型检查不代替权限、TOCTOU、崩溃一致性和误删反例测试。

部署 schema 使用 config_version=2；api_memory_budget_mib/worker_memory_budget_mib 是软预算与超限处置阈值，不是 RSS 硬限制或语言级 GC 开关。

前端保持 SPA；Node 仅用于构建。查询缓存由 TanStack Query 管理，StrictMode/组件卸载不能引发重复任务或泄漏 SSE。后端和前端都使用主规格的状态/错误契约。

必要命令通过 Makefile/等价脚本统一暴露：format、lint、test-unit、test-integration、test-e2e、test-security、bench、build、docker-build、smoke。命令未实现时必须失败，不能空操作返回成功。

HTTP 错误码和任务状态必须统一；请求有 request_id，任务有 job_id。文件路径不写入不受限的逐文件日志；密钥、密码和 token 永不写普通日志。

任何偏离主规格的选择先记录 ADR：原约束、理由、代价、安全影响和测试，再同步规格与验收。不能通过删掉测试或降低断言把失败变成通过。

## 完成报告格式

说明当前完成阶段、对应需求、可运行命令、实际测试结果、真实环境尚未验证项和剩余任务。不能把导入型配额显示说成已实现 UGOS 原生配额同步，不能把 QEMU 构建成功说成所有 ARM NAS 均已验证。
