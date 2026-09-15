# IMPLEMENTATION_STATUS

## 2026-09-14 F03 内部通知分页游标修复与验证（最新）

- 当前写范围仅覆盖 F03 内部通知列表的分页回归与其必要质量修正；`crates/nas-analyzer/src/diagnostics.rs` 未修改，保留其既有差异。
- `crates/nas-analyzer/src/notify.rs::list_internal_notifications` 按 `(created_at DESC, id DESC)` 查询 `page_size + 1` 行，仅在存在下一页时截断为实际返回页，并用最后一条返回记录生成 `(created_at, id)` 游标。严格小于游标的下一页查询因此不会跳过 lookahead 行。
- 回归测试写入固定 ID `notification-c`、`notification-b`、`notification-a`，三行使用相同时间戳；page size 为 2 时第一页返回 `c,b` 并产生 `b` 游标，第二页返回 `a`。测试不依赖 UUID 创建先后。
- 现有 F03 纵切实现包含控制库内部通知迁移（0008/0009）、事件键幂等写入、报告部分成功/源不可用/存储空间不足消费者、认证分页 API、设置页列表、OpenAPI 和生成 TypeScript 类型；本轮只修正分页游标并收束通知消费者上下文参数以通过 clippy。
- 已验证：`cargo test -p nas-analyzer notify::tests --locked` 11/11，`cargo test -p nas-analyzer httpapi::handlers::internal_notification_query_tests --locked` 1/1，`cargo test -p nas-analyzer worker::tests --locked` 5/5，`cargo test -p nas-analyzer --locked` 308/308，workspace 为 `fssecure` 单元 2/2 + adversarial 15/15、`nas-analyzer` 308/308；React 设置页 11/11、typecheck、OpenAPI TypeScript 生成、fmt、check、clippy 和 `git diff --check` 均通过。
- 以上是源码与自动化证据，不等于完整 M0–M8、F01–F19 或 ACC-001–ACC-078 验收；真实 SMTP、真实 NAS/UGOS 和其他外部/实机能力继续单独保持未验证。

## 2026-09-14 F01 日容量汇总实现与聚焦验证（最新）

- `migrations/control/0007_daily_capacity_ranges.sql` 为 `volume_samples_daily` 增加 `total/free/available` 的 `min/max/last` 文本列，并已由控制库迁移序列注册。
- `crates/nas-analyzer/src/sampling.rs` 已将四项容量指标的 `min/max/last` 贯穿日聚合、事务写入、持久化读取和十进制字符串转换；`ok` 原始采样缺字段或违反容量关系时拒绝生成日汇总，迁移前历史行的新增列全空状态仍可读取。
- `crates/nas-analyzer/src/httpapi/handlers.rs` 的日采样 JSON 已将各指标的 `last` 输出到既有字节字段，并输出对应 `*_min_bytes` / `*_max_bytes` 字段；新增 handler 测试覆盖所有容量字段。
- 本次聚焦验证：`cargo test -p nas-analyzer sampling --locked` 为 10/10；`cargo test -p nas-analyzer httpapi::handlers::volume_sample_query_tests --locked` 为 2/2；`cargo fmt --all`、`cargo check --workspace --all-targets --locked` 和 `git diff --check` 均通过。
- 以上证明 F01 日容量汇总的代码链路和聚焦测试已完成；完整 F01 端到端/平台验收及 M0–M8、ACC-001–ACC-078 状态仍按严格矩阵保留，不能由本次聚焦测试替代。

## 2026-09-14 F03 迁移进展（历史记录；后续已完成）

- 新增 `0008_internal_notifications.sql`，建立内部通知表及创建时间索引，并注册控制库迁移。
- 初始记录仅完成持久化基础；后续列表 API、分页、React 页面和事件消费者已接通，见文档顶部最新记录。

## 2026-09-14 当前 F01 验证结果与 F03 执行状态（历史记录）

- F01 日容量汇总已通过 `cargo test -p nas-analyzer sampling::tests --locked`（8/8），并通过 Rust 全量回归 301/301；`total/free/available` 的 min/max/last 已接入聚合、持久化、查询和 API 输出。
- F01 Overview 已显示最新可用容量，React typecheck 与 unit 49/49 通过。
- F03 子代理执行窗口结束时的旧记录曾未产生代码修改或测试证据；后续 F03 实现和验证见文档顶部最新记录。

## 2026-09-14 F01 日汇总接入复核

- 已确认 `0007_daily_capacity_ranges.sql` 仅增加数据库列，尚未接入 `sampling.rs` 的聚合写入、查询结构、HTTP 序列化或专项测试。
- F01 当前仍为 `PARTIAL`；不能把迁移存在误记为日趋势能力完成。下一步必须一次性同步累加器、迁移写入、查询 DTO、React 展示和回归测试。

## 2026-09-14 F01/F06 当前实现进展

- F01 已新增报告输入阶段对关联卷的容量采样，并让 `/api/v1/volumes` 返回最新采样；`cargo check --workspace --all-targets --locked` 与格式检查通过。
- F06 已接通目录页面的当前目录文件查询、汇总、路径复制和目录导航；现有 `ReportDetailPage.test.ts` 2/2 与 typecheck 通过。
- F01 仍缺日趋势的 total/free/available min/max 字段、完整总览展示及独立回归覆盖；F03/F07/F10 尚未产生实现改动，F14/F18 仍需规格边界确认。

## 2026-09-14 用户停止确认（最新）

- 用户要求立即停止所有任务；当前 Goal 运行状态为 `PAUSED`，交付目标未完成，未将 Goal 标记为成功。
- 已向本次可见的 3 个子代理发送关闭请求；随后状态查询均返回 `not_found`，未继续保留子代理执行。未再启动实现、测试、构建、服务或浏览器任务。
- 本次仅更新进度文档；当前 `main` 分支既有 staged/unstaged/untracked 改动全部保留，未执行 reset、stash、回滚、删除或 push。
- 完成口径不变：F01/F03/F06/F07/F10/F14/F18 为明确 `PARTIAL` 或待规格决策；其余 F 项虽有实现面也没有完整验收证据；ACC-001–ACC-078 全部保持 `UNVERIFIED`。因此 M0–M8、F01–F19 和 ACC-001–ACC-078 均不能宣称完成。
- 本次没有新增测试、构建、Docker、真实 API、实机或浏览器证据；后续接续入口仍以本文件下方“停止执行后的差距审计”为准。
- 停止时尚未完整复核的设计包文件仍包括 `docs/design/contracts/deployment.schema.json`、`docs/design/contracts/metadata-import.schema.json`、`docs/design/contracts/*.example.json` 和 `docs/design/deploy/*`；它们不能记为已核对或通过。
- 待完成任务：先完成剩余契约/部署文档核对并明确 F14/F18 语义；再补齐 F01/F03/F06/F07/F10 及已确认范围内的 F14/F18；同步迁移、OpenAPI、生成类型、React 和测试；最后重跑受影响的 Rust/React/API/Smoke/E2E，并完成原生 amd64、NAS/UGOS、SMTP、故障注入、Btrfs/reflink/qgroup、规模/RSS、原生配额/Tiering 及 78 项验收。

## 2026-09-14 当前树 ARM64 Docker/真实链路复验（最新）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`、分支 `main`；工作树含既有 staged/unstaged/untracked 改动，本轮未执行 reset、stash、回滚、删除或 push。
- 修复 `crates/nas-analyzer/src/backup.rs:2238` 的 Linux 测试 needless borrow 后，固定 Rust 1.98.1 Linux 容器的 `cargo test --workspace --locked` exit 0：`nas-analyzer` 321/321、`fssecure` 单元 2/2 与对抗测试 16/16（合计 339 个通过测试，doc-tests/main 无测试）。`cargo fmt --all -- --check`、workspace check、`cargo clippy --workspace --all-targets --locked -- -D warnings` 及 `git diff --check` 均通过。
- 当前源码正式 ARM64 Dockerfile 构建已完成：`nas-storage-analyzer:local-goal-20260914-final`，`linux/arm64`，digest `sha256:e8f104b182bea17e6b1db6f924b147102db26df24d5d415df56875cb78ce34f8`，运行用户 `1000:1000`。`SMOKE_PORT=28400 bash deploy/smoke.sh nas-storage-analyzer:local-goal-20260914-final` exit 0，覆盖非 root、只读根/源、cap drop、健康检查、setup gate、SIGTERM 与 SQLite 重启持久化。
- 同一 ARM64 镜像的 `REAL_API_DOCKER_IMAGE=nas-storage-analyzer:local-goal-20260914-final REAL_API_PORT=28401 bash scripts/real-api-flow.sh` exit 0；覆盖双源扫描、metadata/quota、完整 SHA-256 重复与硬链接、分类历史、compare、幂等导出、备份/恢复、cleanup preview 与只读写保护。同一镜像的授权 Chromium E2E（端口 28402）exit 0，Playwright 1/1 通过，覆盖初始化、登录/重登、数据源、报告、CSV 下载及导出幂等。
- 前端既有当前树回归仍为 frozen install、typecheck、unit 49/49、build 通过，lint 0 errors/5 warnings；这些证据不替代完整逐项业务验收。当前 amd64 Dockerfile 重建已按停止指令中断，未记录为通过。
- 实现阶段仍为 `M0–M8 IN_PROGRESS`，本次执行已由用户暂停。静态审计确认 F01、F03、F06、F07、F10、F14、F18 存在明确实现缺口或未定语义，已在追踪文档标为 `PARTIAL`；其余 F 项仍按实现面与验证状态分开记录。ACC-001–ACC-078 继续逐项 `UNVERIFIED`，不得把局部证据当作通过。真实 NAS/UGOS、原生 amd64、真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink/qgroup、10 万/100 万规模与 RSS、原生配额/Tiering 及完整业务矩阵仍未闭合。

## 2026-09-14 停止执行后的差距审计（当前暂停点）

- 用户要求停止所有任务后，已向正在运行的 amd64 QEMU Dockerfile 构建发送中断；该命令 exit 130，阶段为 Rust 依赖编译，未生成新的 amd64 镜像，因此不计为构建或双架构交付通过。
- 子代理只读核对确认以下不是单纯“未运行测试”，而是当前生产链路的明确缺口：F01 报告完成后的补采样、`/volumes` 的 `last_sample` 与日趋势容量字段/总览展示不完整；F03 没有内部通知列表及其事件消费者；F06 目录页缺少当前目录文件汇总、面包屑、路径复制和目录文件查询接线；F07 报告 owners 缺少身份来源/显示名/配额快照；F10 排行接口未接统一筛选。
- F14 当前实现为配置备份/恢复，规格同时写有“可选完整数据备份”，完整备份范围尚未明确并未实现；F18 的 `io_priority` 只有校验、持久化、API 和表单接线，没有规格定义的 OS/I/O 消费者。两项需要规格确认或补齐实现，不能标为完整。
- 暂停时的下一接续入口：先确认/补齐上述 PARTIAL 项，再重新运行受影响的 Rust/React/API/Smoke/E2E；随后重建当前树 amd64，并在原生 amd64 runner、真实 NAS/UGOS、真实 SMTP、ENOSPC/崩溃、恶意归档、隔离新实例恢复和规模/RSS 环境执行剩余验收。Goal 保持 `IN_PROGRESS`。

## 2026-09-14 最终 Rust 与静态检查收尾（历史质量记录；最新差距见上方）

- 当前源码直接复验：macOS `cargo test -p nas-analyzer --locked` 为 301/301；Linux Rust 1.98.1 容器 `cargo test -p nas-analyzer --locked` 为 321/321，均 exit 0。
- `cargo clippy -p nas-analyzer --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均 exit 0。
- 以上只更新当前源码自动化证据；F01/F03/F06/F07/F10/F14/F18 的实现差距以暂停点审计为准，其余 F 项也未完成完整业务验收；ACC-001–ACC-078 继续逐项 `UNVERIFIED`。真实 NAS/UGOS、原生 amd64、真实 SMTP、故障注入、Btrfs/reflink/qgroup、规模/RSS 和完整业务验收仍未闭合。

## 2026-09-14 清理身份与调度队列缺口修复（本轮）

- 清理 operation supervisor 现在加载数据源的原始相对根、身份状态和已确认身份；打开批准根后重新探测文件系统身份，并在 `provisional/changed`、身份缺失或身份不一致时返回 `SOURCE_IDENTITY_CHANGED`，在任何源文件写入前阻断清理/恢复流程。
- 调度器 `schedule_once` 现在使用 `config.resources.max_queued_scans` 入队上限，不再使用固定值 20；新增配置上限为 1 时拒绝第二个到期扫描的测试。
- 当前新增回归：`cargo test -p nas-analyzer cleanup::tests --locked` 为 25/25，`cargo test -p nas-analyzer runtime::tests --locked` 为 9/9，`cargo test -p nas-analyzer --locked` 为 301/301；`cargo fmt --all -- --check` 与 `git diff --check` 通过。
- 以上是当前源码的聚焦实现证据，不提升完整 F01–F19 或 ACC-001–ACC-078 验证状态；真实设备替换、进程崩溃/ENOSPC、NAS/UGOS、规模/RSS 和完整业务验收仍未闭合。

## 2026-09-14 当前树交付收尾审计（历史快照；停止点见上方）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`、分支 `main`；工作树仍含既有 staged/unstaged/untracked 改动，本轮未执行 reset、stash、回滚、删除或 push。
- 已独立核对 scheduler 子代理本轮实际 diff：新增 `crates/nas-analyzer/src/scheduler/schedule/tests.rs` 的边界测试（当前聚焦 scheduler 15/15 通过）；工作树中既有的 scheduler 生产代码变化未被测试摘要冒充为验收证据。`io_priority` 仍只有契约、持久化、UI 和 Profile 快照传递；主规格没有定义 Linux 映射、作用对象或权限失败语义，因此不擅自加入 `nice/ionice` 或 fallback。
- 当前源码回归记录：macOS Rust `nas-analyzer` 299、`fssecure` 2 个单元 + 15 个对抗测试；Linux Rust 1.98.1 容器 workspace 共 337 个测试通过（`nas-analyzer` 319、`fssecure` 2 个单元 + 16 个对抗测试）。前端 frozen install、typecheck、unit 49/49、build 通过，lint 为 0 errors/5 warnings。
- 当前正式 ARM64 镜像 `nas-storage-analyzer:local-goal-20260914` 已核实为 `linux/arm64`，digest `sha256:d74cab6b1fe5f50049deb27770da7fb5eb660cf9fc83509ca78d0a35a72f259b`；其 Smoke 使用端口 28314、真实 API flow 使用端口 28315、Docker Chromium E2E 使用端口 28316，均已通过。macOS host flow 使用端口 28317，因缺少 `openat2` 写能力得到 `UNSUPPORTED_CAPABILITY`/fail-closed，不能记为产品 E2E PASS。
- amd64 当前树 QEMU 构建已成功：`docker buildx build --platform linux/amd64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-goal-20260914-amd64-retry --load --progress=plain .`；`docker image inspect` 核实为 `linux/amd64`，digest `sha256:a82f61150108da1509de1fd5f83dad812f6cce16de6002d044c08e576695900e`。第一次当前树尝试在 `ring v0.17.14` 的 `p256.c` 编译阶段出现 GCC `cc1` segmentation fault、exit 1，已保留为失败尝试；重试最终越过该点并完成。
- amd64 QEMU 镜像 Smoke 使用端口 28318 已通过；同一镜像的 Chromium E2E 使用端口 28319 实际 exit 1，任务最终状态为 `FAILED`。随后 `REAL_API_DOCKER_IMAGE=nas-storage-analyzer:local-goal-20260914-amd64-retry REAL_API_PORT=28320 bash scripts/real-api-flow.sh` 复现为 `phase=PUBLISH`、`error.code=UNSUPPORTED_CAPABILITY`，消息为“报告 artifact 写入需要 openat2 安全解析能力”，按设计 fail-closed，不计为产品 E2E PASS。失败临时目录 `.nas-storage-analyzer-e2e.hNnhQn` 和 `.nas-storage-analyzer-real-api.SA0zFd` 保留用于审计，未包含凭据。
- 当时阶段判断为 `M0–M8 IN_PROGRESS`；停止后的差距审计已将 F01/F03/F06/F07/F10/F14/F18 明确为 `PARTIAL` 或待规格决策，不能继续按本节旧措辞解释为完整实现。ACC-001–ACC-078 继续逐项 `UNVERIFIED`，外部平台、故障、规模和完整业务验收仍未闭合。

## 2026-09-14 Profile/runtime 只读复核（本轮）

- 已确认 `cli::serve_with` 在启动 runtime supervisor 前先执行 `jobs::mark_interrupted` 和 `cleanup::recover_pending`；cleanup 恢复失败会阻止继续绑定 HTTP 端口和启动 supervisor。对应 `cli::tests::serve_with_stops_before_supervisors_when_cleanup_recovery_fails` 通过。
- 已确认 Profile 的 Daily/Weekly/Monthly/Cron 调度、`include_future_registered` 的源快照、`file_kind_policy` 扫描行为、`owner_ids_to_list` 报告附加快照、Profile 级 `metadata_workers`/`hash_workers`/`read_limit_mib_s` 均有 Rust runtime 消费者，并保留对应 OpenAPI/生成类型/React 表单接线。
- 当前唯一未确认生效的 Profile 资源字段是 `resources.io_priority`：当前实现仅做 `low|normal` 校验、API 类型和表单传递，源码没有将其应用到 worker 进程或 I/O 调度。主规格只说明 `nice/ionice` 是能力允许时的补充，没有给出具体优先级映射、跨平台能力检测或失败语义；在该契约明确前不擅自实现任意映射，也不把它记为已生效。
- 本轮只读复核聚焦测试通过：Profile 5/5、scheduler 15/15、CLI 4/4、runtime 7/7、worker 5/5、scanner 3/3、report 6/6。未提升 F01–F19 或 ACC-001–ACC-078 的完整验证状态。

## 2026-09-14 all_metadata / owner_list_snapshot 可见性审计（本轮）

- 已核对主规格 5.1、7.1、8.3、10.4、16.2–16.3 与当前报告发布/查询实现。规格要求 `all_metadata` 保留特殊条目元数据，但没有定义独立的特殊条目 ReportDetail 字段或专用 API/UI；因此本轮不扩张公开契约。特殊条目仍保留在发布的 `index.sqlite` 明细 artifact 中，当前普通文件明细查询不将其误当普通文件。
- 规格要求 `owner_ids_to_list` 作为附加用户明细，8.3 的消费语义是按 UID 查看文件列表；现有 `/api/v1/reports/{id}/files?owner_uids=...` 与报告页 UID 筛选承载该文件列表。`owner_list_snapshot` 是报告摘要库内部的选定 UID 聚合快照，规格未要求按该内部表名新增 ReportDetail/API/UI 字段，本轮仅验证其落库隔离于全量 `owner_aggregates`。
- 新增真实报告/扫描测试：`report::tests::publication_contains_folder_and_owner_category_snapshots` 验证选定 UID 快照与全量 owner 聚合边界及已发布明细中的特殊条目元数据；`scanner::tests::all_metadata_indexes_special_entry_metadata_without_reading_content` 验证 symlink 以非普通条目保留且不被跟随读取。
- 当前准确缺口：没有对 `owner_list_snapshot` 的公开消费接口；若后续产品要求展示“附加 UID 聚合快照”本身，需另行明确 DTO/页面语义后再改 OpenAPI。当前 `all_metadata` 也没有规格定义的特殊条目独立列表页面；这不影响本轮已验证的报告 artifact 保留结论。本轮未修改 Profile/runtime 文件；工作树中的其他改动予以保留。

## 2026-09-14 Goal 接管与 Profile 语义补全（进行中）

- 已重新核对 `CODEX_GOAL.md`、`docs/design/AGENTS.md`、Profile 调度/扫描/报告规格以及当前工作树；保留既有 staged/unstaged/untracked 改动，未执行 reset、stash、回滚、删除或 push。
- 本轮复核后，Daily/Weekly/Monthly 表达、`include_future_registered` 的运行时源选择、`file_kind_policy` 的扫描统计语义、`owner_ids_to_list` 的附加报告分组，以及 Profile 级 `metadata_workers`/`hash_workers`/`read_limit_mib_s` 已确认接线；`io_priority` 仍只有校验和 UI/API 接线，因规格未定义具体 OS 映射而保持未闭合。
- 已要求 Profile 子任务直接修改共享工作树并运行聚焦回归；主任务负责审查其实际 diff、补齐契约/界面并独立复验。前端设置与容量卷管理改动已在当前树，仍需随本轮后端语义变更复验。
- 当前阶段判断：M0–M8 继续 `IN_PROGRESS`；F01–F19 保持 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 不因既有单元测试、历史镜像或子任务摘要提升为完整通过。
- 接续入口：审查 Profile 实现 diff → 同步 `api/openapi.yaml` 与生成类型/React 表单 → 运行 Rust/React/OpenAPI/交付合同检查 → 重新构建当前 Dockerfile 镜像并执行 Smoke、真实 API 和已授权浏览器 E2E；外部 NAS/UGOS、原生 amd64、真实 SMTP、Btrfs/reflink/qgroup、故障注入和百万级规模证据仍需分别保留 `UNVERIFIED`。

## 2026-09-13 23:20 当前源码 Linux 回归与真实 API 流（最新）

- 当前 checkout 仍为 `/Users/zj9495/code/nas-storage-analyzer`；既有 staged/unstaged/untracked 工作树全部保留，未执行 reset、stash、回滚、删除无关文件或 push。
- 当前稳定源码上的 Linux 回归已实际通过：固定 `rust:1.98.1-bookworm` 容器中 workspace `cargo test --workspace --locked` 为 `311 passed / 0 failed / 0 ignored`（`fssecure` 2 个 lib + 16 个 adversarial、`nas-analyzer` 293、main/doc-test 0），并在同一最终源码 hash `f765a86…` 上复跑 `cleanup` `47/47`、`jobs` `19/19`、`duplicates` `10/10`、`report` `25/25`，各命令 exit 0。此前 doc-test 阶段的 rustup 下载停滞由同一最终 hash 的后续成功重跑取代，不再作为当前全量结果。
- 当前源码 Linux release 二进制在隔离 Docker volume 中以 Rust 1.98.1、锁文件和离线 Cargo registry 编译成功：`cargo +1.98.1 build --release --locked -p nas-analyzer` exit 0。随后仅为真实 HTTP 验证将该二进制放入临时 ARM64 运行镜像 `nas-storage-analyzer:real-api-current`，该临时镜像 digest 为 `sha256:01dfcb697501220ae2097c6297173ac72ba586d4f4725527d272fb8b95a64e3f`。
- `REAL_API_DOCKER_IMAGE=nas-storage-analyzer:real-api-current bash scripts/real-api-flow.sh` exit 0；实际覆盖双源扫描与黄金数据、身份/配额预览及应用、SHA-256 重复组和硬链接语义、分类历史不可变、compare、幂等导出下载、备份/恢复、cleanup preview 和只读写保护。该流使用临时验证镜像，不等同正式 `deploy/Dockerfile` 重建或浏览器 E2E。
- 当前源码正式 ARM64 Dockerfile 重建 `docker buildx build --builder colima --network=host --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-goal-20260913-2255 --load --progress=plain .` 在 `Updating crates.io index` 长时间无进展后人工取消，exit 130，目标 tag 未生成；不得把临时验证镜像或旧正式镜像冒充本次 Dockerfile 交付结果。
- Linux 全量 `scripts/linux-cargo.sh test --workspace --locked` 曾有一次在 `Doc-tests fssecure` 前因 rustup 下载 clippy 停滞的中间尝试；随后在同一最终源码 hash `f765a86…` 直接重跑成功，exit 0，汇总为 `311 passed / 0 failed / 0 ignored`。中间阻塞作为环境观察保留在测试报告，不影响最终成功命令的实际 exit 0。
- 19:01 的 `sha256:0e3db311...` ARM64 镜像、Smoke 和 Chromium E2E 因晚于该镜像的源码变更降为下方历史快照；它们仍是已观察到的结果，但不再代表当前源码。
- 状态继续严格区分：F01–F19 为 `IMPLEMENTED / UNVERIFIED`；ACC-001–ACC-078 逐项为 `UNVERIFIED`；真实 NAS/UGOS、原生 amd64、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、10 万/100 万规模与 RSS、原生配额/Tiering 及完整逐项验收仍未闭合。Goal 保持 `IN_PROGRESS`。

## 2026-09-13 19:01 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；后续源码变更和验证见上方）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；保留既有 dirty/staged 工作树，未执行 reset、stash、回滚、删除或 push。
- 为解决固定 Rust 基础镜像没有 Cargo 缓存且默认 registry 更新停滞的问题，`deploy/Dockerfile` 现在显式设置 `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse`；没有改变依赖版本、锁文件或运行时安全门槛。
- 当前源码 ARM64 镜像构建成功：`docker buildx build --builder colima --network=host --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-current-20260913-1845 --load --progress=plain .` exit 0。`docker image inspect`：`sha256:0e3db311a550d66e3e153006b601758268bcb858845e003a6912e77454ad6c6c arm64/linux 2026-09-13T19:01:05.309335896+08:00`。
- 当前源码镜像 Smoke：`SMOKE_PORT=28220 bash deploy/smoke.sh nas-storage-analyzer:local-current-20260913-1845` exit 0；覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- 当前源码镜像 Docker-backed Chromium E2E：`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-current-20260913-1845 E2E_DOCKER_HOST_PORT=28222 bash web/tests/e2e/run-real-e2e.sh` exit 0，Playwright 1/1 通过（8.0 秒）；覆盖初始化、登录/退出/重新登录、登记数据源、创建并运行报告任务、报告查看、CSV 导出下载及相同 `Idempotency-Key` 的重复导出请求。E2E 后端容器现复现 Compose 的 read-only、cap-drop、no-new-privileges、tmpfs、资源限制和显式 non-root；浏览器调用已获用户授权，成功运行后临时根目录已清理。
- 当前源码自动化回归：macOS arm64 `cargo fmt --all -- --check`、workspace check、clippy、debug/release workspace test 和 release build 均 exit 0；`nas-analyzer` 265/265，`fssecure` 2 个单元测试 + 15 个对抗测试。Linux 固定 `rust:1.98.1-bookworm` 容器的 fssecure adversarial 为 16/16、exit 0。前端 frozen install、typecheck、lint、unit 46/46、build 均 exit 0；lint 为 0 errors/3 warnings，build 保留大 chunk warning。OpenAPI lint/bundle、`make compose-config`、`make verify-delivery` 和 `make bench` 均 exit 0；基准为 30,000 行、69 ms、432,993 rows/s，RSS 为 `None`。
- `git diff --check` exit 0；`git diff --cached --check` 和 `git diff HEAD --check` 仍因既有 staged 内容的 EOF 空行/尾随空格 exit 2，具体位置已在测试报告记录，未擅自覆盖用户 staged 内容。
- 上述 ARM64 证据只覆盖当前镜像的交付安全边界和局部主链路，不提升完整 F01–F19 或 ACC-001–ACC-078 的逐项验证状态。amd64 当前构建结果若来自本机 ARM64 QEMU，只能作为仿真记录，不能替代原生 amd64；真实 NAS/UGOS、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、10 万/100 万规模与 RSS、原生配额/Tiering 及完整逐项 ACC 仍未验证。
- Goal 保持 `IN_PROGRESS`；旧 `sha256:0f42333a...` ARM64 记录已降为下方历史快照，不能与当前源码混用。

## 2026-09-13 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；镜像早于当前 Dockerfile/E2E 复验）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；保留既有 dirty/staged 工作树，未执行 reset、stash、回滚、删除或 push。
- 当前源码 ARM64 镜像构建成功：`docker buildx build --builder colima --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-aggregate-20260913 --load --progress=plain .` exit 0；`docker image inspect` 为 `sha256:0f42333ad0e866b5923d9af506a1d719e7ecd168f3038f99f670ecade9e3fc30 arm64/linux 2026-09-13T16:59:04.75707736+08:00`。
- 当前源码镜像 Smoke：`SMOKE_PORT=28210 bash deploy/smoke.sh nas-storage-analyzer:local-aggregate-20260913` exit 0；覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- 当前源码镜像真实 E2E：`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-aggregate-20260913 E2E_DOCKER_HOST_PORT=28211 bash web/tests/e2e/run-real-e2e.sh` exit 0，Chromium 1/1 通过（10.3 秒）；覆盖初始化、登录/退出/重新登录、登记数据源、创建并运行报告任务、报告查看、CSV 导出下载及相同 `Idempotency-Key` 的重复导出请求。浏览器调用已获用户授权，成功运行后临时根目录已清理。
- 本次 ARM64 证据只覆盖当前镜像的交付安全边界和局部主链路，不提升完整 F01–F19 或 ACC-001–ACC-078 的逐项验证状态。amd64 仍只有 QEMU 证据；此前 QEMU Docker E2E 在 `PUBLISH` 因 `openat2` 能力不可用按设计 fail-closed，不能替代原生 amd64。
- Goal 保持 `IN_PROGRESS`；仍未验证真实 NAS/UGOS、原生 amd64、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、10 万/100 万规模与 RSS、原生配额/Tiering 及完整逐项 ACC 验收。

## 2026-09-13 聚合修复后当前进度（历史快照；以顶部 Docker/E2E 记录为准）

- 本次文档子任务完整阅读了 `CODEX_GOAL.md`、`docs/design/AGENTS.md`、`docs/IMPLEMENTATION_STATUS.md` 和 `docs/TEST_REPORT.md`；只修改这两份进度文档，未修改源码、测试、OpenAPI、部署文件或其他文档。当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`，既有 dirty/staged 工作树保持不变，未执行 reset、stash、回滚、删除或 push。
- `crates/nas-analyzer/src/scanner/index_aggregates.rs` 的目录聚合已修复为按 `dfs_right` 升序处理，并使用 keyset `>` 分页，保证子目录先于父目录聚合。
- 新增真实临时 fixture 黄金链路测试 `scanner::tests::golden_fixture_scans_aggregates_and_confirms_duplicates` 已通过：8 个文件、4 个目录、逻辑字节 50、去重后的逻辑字节 44、7 个物理对象、1 个重复组；硬链接别名识别正确。
- 最新 Rust 证据：macOS arm64 的 `nas-analyzer` 为 263/263，`fssecure` 为 2 个单元测试 + 15 个对抗测试；Linux Rust 1.98.1 容器 workspace 的 `nas-analyzer` 为 282/282，`fssecure` 为 2 个单元测试 + 16 个对抗测试。
- 最新前端证据：unit 46/46、typecheck、lint、build 均通过；既有 lint Fast Refresh warning 和构建大 chunk warning 保留为提示，不据此扩大验证结论。
- 本次实际复核：`make verify-delivery` exit 0，输出 `DELIVERY CONTRACT PASS`；`make compose-config` exit 0；`git diff --check` exit 0（无输出）。
- 最新 ARM64 Docker 重建命令 `docker buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-aggregate-20260913 --load .` 在 `Updating crates.io index` 无进展后人工取消，exit 130，未生成当前源码镜像。旧 `sha256:c93d492b...` ARM64 digest 属于聚合修复前镜像，不能作为当前源码、Smoke 或 E2E 证据。
- 状态边界保持不变：M0–M8/F01–F19 的现有实现标记与验证标记继续分离；ACC-001–ACC-078 不因黄金链路、局部回归、交付合同或旧镜像而记为完整通过，逐项验证仍未闭合；Goal 保持 `IN_PROGRESS`。
- 当前未验证/阻塞包括：聚合修复后的 ARM64 Docker Smoke 与 Docker-backed E2E、原生 amd64、NAS/UGOS 实机、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、10 万/100 万规模与 RSS、原生配额/Tiering，以及完整逐项 ACC 验收。本轮未调用浏览器。

## 2026-09-13 进度文档一致性审计（历史快照；当前记录见上方）

- 本次只核对并修正文档快照的状态标注与历史计数，未修改 Rust、React、OpenAPI、测试、部署脚本或配置；当前 checkout `/Users/zj9495/code/nas-storage-analyzer` 的既有 dirty/staged 工作树保持不变。
- 已复核 `CODEX_GOAL.md`、`docs/design/AGENTS.md` 以及四份进度/验收文档；子代理只读审计发现的旧计数和“当前”措辞矛盾已在下方历史章节明确标注，历史证据没有删除。
- 本次执行了设计包清单校验：在仓库根误用 `sha256sum -c docs/design/MANIFEST.sha256` 为 exit 1（清单路径相对 `docs/design`）；改在 `docs/design` 执行 `sha256sum -c MANIFEST.sha256` 为 exit 0，所有条目 OK。`make compose-config`、`make verify-delivery` 和 `git diff --check` 均 exit 0；本轮未重跑 Rust/React 测试。Goal 仍为 `IN_PROGRESS`，F01–F19 为 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 逐项为 `UNVERIFIED`。

## 2026-09-13 当前源码回归（历史快照；聚合修复后计数见上方）

- 本次继续核对当前源码并同步文档；当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`，既有 dirty/staged 工作树保持不变，未执行 reset、stash、回滚、删除或 push。
- 当时 Rust 回归证据：macOS arm64 的 fmt/check/clippy、debug/release workspace test 和 release build 均 exit 0，`nas-analyzer` 262/262、`fssecure` 2 个单元测试 + 15 个对抗测试；Linux 固定 Rust 1.98.1 容器 workspace test exit 0，`nas-analyzer` 281/281、`fssecure` 2 个单元测试 + 16 个对抗测试。
- 当时前端 typecheck、lint、build、unit 均 exit 0，unit 回归为 46/46；lint 保留 3 个既有 Fast Refresh warning，build 保留大 chunk warning。
- `preview_metadata_import` 现在返回已计算的 `diff_summary`；`metadata_import.rs` 与 `httpapi/handlers.rs` 的回归测试覆盖该响应数据。Profile 数据源选择器现在按 `next_cursor` 分页读取全部已登记数据源；`ProfilesPage.test.ts` 的回归测试覆盖多页读取及后续请求游标。
- 以上是当时源码与自动化回归证据；当前证据以顶部聚合修复后记录为准。F01–F19 继续为 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 继续逐项为 `UNVERIFIED`，不将局部回归扩展为完整验收。

## 2026-09-13 当前源码 arm64 Docker/E2E 复验（历史快照；镜像早于聚合修复）

- 当时镜像 `nas-storage-analyzer:local-arm64-current-20260913` 的 `docker image inspect` 为 `sha256:c93d492b5137faf3e966f825e81a0c99fb087919dfce1b34941b8864b8839178 arm64/linux 2026-09-13T15:23:39.380224054+08:00`；该镜像构建早于目录聚合修复。
- 该旧镜像的 Smoke 与 Docker-backed Chromium E2E 曾 exit 0；它们只证明聚合修复前镜像的局部交付/主链路，不能继承为当前源码证据。
- 当前源码对应的新 ARM64 镜像因 crates.io index 阶段无进展并被取消，尚未形成聚合修复后的 Smoke/E2E 证据；F01–F19 继续为 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 继续逐项保持未验证，amd64 QEMU 也不等同原生 amd64 证据。

## 2026-09-13 当前源码 arm64 Docker/E2E 与交付回归（历史快照；回归计数见上方）

- 当前实际 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；保留既有 dirty/staged 工作树，未执行 reset、stash、回滚、删除或 push。
- ARM64 构建命令 `docker buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local --load .` exit 0。
- 当前源码 ARM64 Docker 构建实际完成；`docker image inspect --format '{{.Id}} {{.Architecture}}/{{.Os}} {{.Created}}' nas-storage-analyzer:local` 输出 `sha256:4ff090449edb08ca666ad54704a51ab35ee87cd20076ec9d4833f7a7a437eb3b arm64/linux 2026-09-13T12:34:40.342583539+08:00`。
- `SMOKE_PORT=28190 bash deploy/smoke.sh nas-storage-analyzer:local` exit 0；通过 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local E2E_DOCKER_HOST_PORT=28191 bash web/tests/e2e/run-real-e2e.sh` exit 0；Docker-backed Chromium 1/1 通过，覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载及同一 `Idempotency-Key` 的导出幂等验证。
- `make bench` exit 0；当前输出为 `export_rows=30000 elapsed_ms=64 rows_per_sec=463953 api_rss_bytes=None worker_rss_bytes=None`。这是 30,000 行导出小基准，不构成 10 万/100 万条目或 RSS 验收。
- `make compose-config` 与 `make verify-delivery` 均 exit 0；后者输出 `DELIVERY CONTRACT PASS`。这些证据只覆盖当前 ARM64 交付与局部主链路，不提升完整 F01–F19 或任何 ACC 条目的验证状态。
- `./api/gen-ts.sh`、Redocly lint/bundle 和 `pnpm --dir web run typecheck` 均 exit 0；lint 保留 4 个 warning，未将 warning 隐去或记为无条件完整契约通过；当前 `pnpm --dir web run test:unit` 为 45/45。
- amd64 仍只有 macOS arm64 主机上的 QEMU 证据；其 Docker E2E 在 `openat2` 能力门控处按设计 fail-closed。当前没有原生 amd64、NAS/UGOS、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃、规模/RSS 或完整逐项业务验收证据。
- F01–F19 仍为 `IMPLEMENTED / UNVERIFIED`；ACC-001–ACC-078 仍逐项 `UNVERIFIED`。ACC-014 的 Btrfs 能力实现为 `IMPLEMENTED / UNVERIFIED`，不是 reflink/快照/qgroup 实机通过；Goal 仍保持 `IN_PROGRESS`。

## 2026-09-13 cleanup 恢复/重试修复与当前源码回归（历史快照；已由上方 Docker/E2E 记录更新）

- 当前实际 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；保留既有 dirty/staged 工作树，未执行 reset、stash、回滚、删除或 push。
- cleanup 重试现在只接受已由受控隔离路径、完整 `before_move/after_move` 日志、对应 `journal_seq` 和文件身份共同证明的 `QUARANTINED` 条目；已完成的条目会跳过，后续条目继续使用动作日志尾部的新序号。修复了重试动作已有其他条目日志时，尚未移动条目在 `VALIDATING` 状态写入其他条目序号的崩溃窗口；该条目现在保留自身序号（未移动时为 0），恢复为 `FAILED`。
- cleanup supervisor 的错误路径由 cleanup 负责文件/条目恢复核对，由 `runtime` 统一处理中断任务收尾；部分移动失败由 cleanup 以 `PARTIAL` 完成，不会再次进入 runtime 错误收尾。非 `scan` 任务不再暴露或接受 pause/resume 控制。
- 当前源码 macOS arm64：fmt、workspace check、clippy、debug/release workspace test 和 release build 均 exit 0；`nas-analyzer` 261/261，`fssecure` 2 个单元测试 + 15 个对抗测试。
- 当前源码 Linux 容器：cleanup 定向回归 26/26，`fssecure` adversarial 16/16，均 exit 0；受限容器中的 mount permission denied 是测试覆盖的能力不可用场景。
- 当前源码前端：frozen install、typecheck、lint、unit 45/45、build 均 exit 0；lint 保留 3 个 Fast Refresh warning，Vite 保留大 chunk warning。`bash deploy/verify-delivery.sh` 输出 `DELIVERY CONTRACT PASS`，Compose config 通过。
- `make bench` exit 0，30,000 行导出约 65 ms / 461,124 rows/s，`api_rss_bytes=None`、`worker_rss_bytes=None`；不构成 10 万/100 万规模或 RSS 验收。
- 本轮以 `make docker-build IMAGE=nas-storage-analyzer:local-cleanup-20260913` 重建当前源码，在容器 Rust build 的 `Updating crates.io index` 阶段无进展后取消，exit 130；该 tag 未生成。未复用旧镜像作为当前源码证据，Docker Smoke 和真实浏览器 E2E 继续为 `UNVERIFIED`。本轮未调用浏览器，因未获得授权。
- F01–F19 仍为 `IMPLEMENTED / UNVERIFIED`；ACC-001–ACC-078 仍逐项 `UNVERIFIED`。真实 SMTP、ENOSPC/故障注入、Btrfs/reflink/qgroup、UGOS/NAS、原生 amd64、10 万/100 万规模及完整业务矩阵仍未验证；Goal 仍不能标记完成。

## 2026-09-13 amd64 QEMU Docker E2E 复验（历史快照；cleanup/job-control 记录见上方）

- 当前工作树的 `make docker-build-amd64` 已实际完成；`nas-storage-analyzer:local-amd64-current` 为 `sha256:1d7606b4a25a787649eff5d0cbd2c7a373186f5e6171226c44c6ac2f86a56b32`，架构为 `amd64/linux`。
- `SMOKE_PORT=28188 bash deploy/smoke.sh nas-storage-analyzer:local-amd64-current` exit 0；覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。该构建/运行是在 macOS arm64 主机上的 QEMU 模拟，不是原生 amd64 runner。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-amd64-current E2E_DOCKER_HOST_PORT=28189 bash web/tests/e2e/run-real-e2e.sh` exit 1，失败于 `web/tests/e2e/real-flow.spec.ts:192`：任务状态为 `FAILED`，未进入报告/导出断言。保留证据目录为 `.nas-storage-analyzer-e2e.poFmBn`；手工复现的任务 `77c58451-e03f-4656-9ca3-669504e3dd91` 的 API `error` 为 `UNSUPPORTED_CAPABILITY`，消息为“报告 artifact 写入需要 openat2 安全解析能力”。
- 该失败来自当前安全实现的 fail-closed 行为：amd64 QEMU 容器内的 `fssecure` openat2 能力探测不可用，扫描索引已完成但报告发布被拒绝；不能通过安全 fallback、放宽校验或修改 E2E 断言处理。当前没有原生 amd64 runner 证据，因此 amd64 QEMU Smoke 不能替代原生 amd64 完整 E2E。
- 当前 arm64 镜像仍有直接证据：`sha256:8376ac714d038355ca9d2eefbd49f89ac11a86367d6e5c7842de072a2c57afc9`、`arm64/linux`；Smoke 与 Docker-backed Chromium E2E（1/1）通过。该证据只覆盖局部主链路。
- `ACC-001`–`ACC-078` 的逐项验证状态继续全部为 `UNVERIFIED`；`ACC-014` 为 `BLOCKED / UNVERIFIED`，`ACC-061`、`ACC-077` 为 `IMPLEMENTED / UNVERIFIED`，M8 为 `IMPLEMENTED / PARTIAL / UNVERIFIED`。Goal 仍不能标记完成；下一接续点是取得原生 amd64 或具备 openat2 的等价 Linux runner 后重跑 Docker E2E，并继续保留外部平台、故障和规模缺口。

## 2026-09-13 当前源码 Docker/E2E 复验（历史快照；已由上方 amd64 复验记录更新）

- WAL checkpoint 修复后的当前工作树已完成 `make docker-build`；`docker image inspect` 为 `sha256:8376ac714d038355ca9d2eefbd49f89ac11a86367d6e5c7842de072a2c57afc9`、`arm64/linux`。
- `SMOKE_PORT=18086 bash deploy/smoke.sh nas-storage-analyzer:local` 首次因端口已被本机 SSH 占用而 exit 125；脚本临时容器已由 trap 清理。改用 `SMOKE_PORT=28186` 后 Smoke exit 0，覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local E2E_DOCKER_HOST_PORT=28187 bash web/tests/e2e/run-real-e2e.sh` exit 0，Chromium 1/1 通过；完成初始化、登录/重登、登记源、扫描、报告、CSV 下载和相同 `Idempotency-Key` 的导出幂等验证。
- 该 Smoke/E2E 使用包含本次 WAL 修复的当前 arm64 镜像；仍是局部主链路证据，不提升完整 F01–F19 或 ACC-001–ACC-078 验收，也未验证启用重复检测的完整发布闭环。

## 2026-09-13 WAL checkpoint 修复与定向回归（历史快照；已由上方 Docker/E2E 记录更新）

- `duplicates::process_index()` 现已在构建重复组后、返回 `HashStageResult` 前显式执行 `PRAGMA wal_checkpoint(TRUNCATE)`；新增回归测试验证存在未 checkpoint WAL 时返回前已截断 WAL。
- macOS arm64：`cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked`、`cargo test --workspace --release --locked` 和 `cargo build --release --locked -p nas-analyzer` 均 exit 0；`nas-analyzer` 250/250，`fssecure` 2 个单元 + 15 个对抗测试。
- Linux 固定 `rust:1.98.1-bookworm`、显式 `cargo +1.98.1`：`duplicates::tests` 1/1、`report::tests` 6/6 均 exit 0；其中包含 WAL checkpoint 与 immutable 报告读取测试。
- 当时 arm64 镜像上的 Smoke/E2E 证据早于本次 WAL 源码修改；“当前代码对应镜像正在重建、需重跑”是历史快照，当前结果以顶部 Docker/E2E 记录为准。
- `IMPLEMENTED`、`VERIFIED`、`UNVERIFIED` 继续分离；真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS 实机、原生 amd64、10 万/100 万规模及 RSS、原生配额/Tiering，以及完整逐项 ACC 仍未验证。

## 2026-09-13 当前树 Docker/Linux/E2E 续记（历史快照；已由上方 Docker/E2E 记录更新）

- 本次仅更新进度文档；当前 dirty worktree 中既有代码改动继续保留，未修改 Rust、React、脚本或配置文件。macOS arm64 的 `cargo fmt --all -- --check`、workspace check、clippy、debug/release test 和 release build 均 exit 0；最新计数为 `nas-analyzer` 249/249，`fssecure` 2 个单元测试 + 15 个对抗测试。
- Linux 固定 `rust:1.98.1-bookworm` 容器中，`scripts/linux-cargo.sh` 显式使用 `cargo +1.98.1` 的 `fssecure` adversarial 测试 16/16、exit 0。受限容器中的 mount permission denied 属于测试覆盖的能力不可用场景，不提升为平台实机能力。
- 当前树 arm64 Docker build 和 Smoke 已通过：Smoke 使用 `SMOKE_PORT=18084`，覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- Docker-backed Chromium E2E 已在当前 arm64 镜像上 exit 0（1/1），使用 `E2E_DOCKER_HOST_PORT=18087`，完成初始化、登录/重登、登记源、扫描、报告、CSV 下载及相同 `Idempotency-Key` 的导出幂等验证。这是当前 arm64 镜像的主链路证据，不是完整 F01–F19 或 ACC-001–ACC-078 验收。
- `web/tests/e2e/run-real-e2e.sh` 本轮新增 `E2E_DOCKER_HOST_PORT` 可配置能力；本轮 E2E 诊断日志已清理，无诊断日志残留。
- `make docker-build-amd64` 的既有 QEMU `ring` C 编译 `cc` SIGSEGV 是失败尝试；随后串行重试已形成当前 amd64 镜像和 Smoke 证据，但 QEMU 不等同原生 amd64，当前 Docker E2E 仍按顶部记录为失败。
- `duplicates::process_index()` 返回前的 WAL checkpoint 修复已由顶部回归记录确认；本历史条中的“实施中、尚待回归”不代表当前状态。

当前仍明确 `UNVERIFIED`：真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS 实机、原生 amd64、10 万/100 万规模及 RSS、原生配额/Tiering，以及完整逐项 ACC 验收。`IMPLEMENTED`、`VERIFIED`、`UNVERIFIED` 继续分离，Goal 仍不能据此标记完成。

## 2026-09-13 Rust 全量回归（历史快照；已由上方 Docker/E2E 记录更新）

- 主任务独立复跑 `cargo fmt --all -- --check`、workspace check、clippy、debug/release test 和 release build，均 exit 0。
- 当前计数为 `nas-analyzer` 249/249、`fssecure` 2 个单元 + 15 个对抗测试；cleanup 生命周期修复后的 Rust 证据已闭合。Docker、Linux 固定工具链、真实 E2E 与外部平台状态仍按未验证边界保留。
- Linux `fssecure` 已用 `rust:1.98.1-bookworm` 显式 `cargo +1.98.1` 重跑，16/16 通过；此前 rustup 组件下载停滞不再阻断该安全测试。该历史快照中的“Docker 镜像构建仍未完成”已由顶部记录更新。
- 当前树 arm64 Docker 构建和 Smoke 已通过；amd64 QEMU 构建在 `ring` C 编译时 `cc` SIGSEGV 失败，未运行 amd64 Smoke。Docker E2E 尚待 arm64 镜像实跑。

## 2026-09-13 full-report/export 回归与 release 验证（历史快照；回归计数以顶部最新记录为准）

- 当前仍保留既有 dirty worktree；本轮没有 reset、stash、回滚、覆盖或 push。full-report 已覆盖十个栏目：合并 CSV/JSON/HTML 行带 `section`，ZIP 包含 `full_report.html` 及每个栏目独立的 CSV/JSON 成员；栏目 JSON manifest 和成员文件名提供栏目身份。
- 导出创建与 worker 执行共用明细判断；默认 full-report 会打开 `index.sqlite`。对 full-report 无法由所有栏目表达的筛选直接返回校验错误，不静默忽略 QuerySpec 字段。超大配额/容量字节保持十进制字符串，超过 SQLite `i64` 的查询值显式拒绝。
- 本轮新增的 full-report 格式、ZIP 成员、目录直系/后代、分类目录范围、所有者分类粒度、超大字节值和导出筛选/溢出测试均随当前 workspace debug/release 回归通过；`delete_report` 先提交控制库删除事务，再清理 artifact。
- 当时源码验证：`cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked`（nas-analyzer 248；fssecure 2 单元 + 15 对抗）、`cargo test --workspace --release --locked`（同上）和 `cargo build --release --locked -p nas-analyzer` 均 exit 0。浏览器、Docker、真实 NAS/UGOS、Linux 固定工具链和外部平台证据的当前状态以顶部记录为准。

## 2026-09-12 cleanup supervisor 回归补充

- cleanup 测试的 `DbWriterGuard` shutdown 生命周期已修复；当前 cleanup supervisor 不再存在该测试挂起阻塞。
- 子代理报告 host/Linux cleanup、jobs、fssecure adversarial 及 workspace debug/release、clippy/check/release build 通过；主任务尚未独立复跑全量命令，不把该摘要提升为最终全量证据。Docker 网络阻塞和外部平台缺口不变。

## 2026-09-12 最新编译阻塞修复

- 修复恢复幂等测试闭包对 `admin.id` 的异步借用错误（E0373/E0505），只调整测试夹具所有权。
- 修复后已通过 `cargo fmt --all`、`cargo check -p nas-analyzer --all-targets --locked` 和 `cargo test -p nas-analyzer cleanup::tests --locked`（12/12）。

## 2026-09-12 当前工作树状态（历史快照；已由 2026-09-13 记录更新）

- 该节记录当时的 `IN_PROGRESS` 状态和既有 dirty worktree；本轮未执行 reset、stash、回滚或删除无关改动。当前证据以 2026-09-13 顶部记录为准。
- 本轮已完成报告 artifact 安全边界收敛：报告查询、导出入队/worker、清理预览和比较均绑定配置 `data_dir/reports/{report_id}`，固定 `report.sqlite/index.sqlite` 名称，并经 `fssecure` 打开后使用已验证 FD；新增目录符号链接/路径替换测试。排队后直接取消的秘密备份会释放进程内临时口令，运行中取消仍等待 worker 消费。
- 当前源码验证已通过：`cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked`（nas-analyzer 248；fssecure 2 单元 + 15 对抗）、`cargo test --workspace --release --locked`（同上）、`cargo build --release --locked -p nas-analyzer`；前端 frozen install/typecheck/lint/unit(40)/build；OpenAPI 生成、Redocly lint（4 warnings）和 bundle；`make verify-delivery`、Compose config、30,000 行 benchmark。
- 当前小 benchmark 为 74ms、405,004 rows/s，RSS 指标为 `None`，不构成 10 万/100 万条目或 RSS 验收。前端 lint 的 3 个 Fast Refresh warning、Vite 大 chunk warning 和 Redocly 4 个契约 warning 已保留，未通过虚构响应/删除 schema 掩盖。
- 该历史快照当时记录 Linux `fssecure` 未进入测试；当前源码回归已补充 Linux adversarial 16/16 通过，当前证据以顶部 2026-09-13 记录为准。
- 本轮 `make docker-build` 已实际执行但未完成：Rust build stage 在 `Updating crates.io index` 后无新增输出，确认无有效构建进展后取消，exit 130（`context canceled`）。因此不采信旧镜像；本轮 Docker smoke、真实 Playwright E2E 以及 amd64 构建均保持 `UNVERIFIED`。
- 已将 Dockerfile Rust release 命令显式绑定到基础镜像已安装的 `cargo +1.98.1`，消除无关的 clippy 在线安装步骤；host-network 重试仍在 crates.io index 阶段停滞并取消，未形成镜像证据。
- 仍明确 `UNVERIFIED`：真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS 实机、原生 amd64 runner、10 万/100 万规模与 RSS、原生配额/Tiering，以及完整 ACC-001–ACC-078 逐项业务矩阵。

## 2026-09-12 API 契约 lint 回归（本轮）

- 本轮严格限定为 API 契约文件：修订 `api/openapi.yaml` 的 OAS 3.1 可空值表达，补齐 license 标识与 tag description；未修改 Rust、React 业务实现、backup/cleanup/runtime/worker。
- `nullable: true` 已按字段语义改为 OAS 3.1 JSON Schema 联合类型或 `anyOf` null 分支；生成类型保持对应的 `| null`。
- `pnpm --package=@redocly/cli@1.34.0 dlx redocly lint api/openapi.yaml --max-problems 200`：exit 0；93 个 nullable 错误已清除，license/tag 规则已通过。仍保留 4 个非阻断 warning：初始化状态/健康探针没有人为添加 4xx 响应，以及 `JobEvent` 是供生成类型使用但未被路径直接引用的可复用 schema；添加虚构响应或删除该 schema 都会降低实际契约准确性。
- `./api/gen-ts.sh`：exit 0；`pnpm --dir web run typecheck`：exit 0；`pnpm --package=@redocly/cli@1.34.0 dlx redocly bundle api/openapi.yaml --output /tmp/nas-storage-analyzer-openapi-after-null.yaml`：exit 0；`git diff --check -- api/openapi.yaml web/src/api/schema.d.ts`：exit 0。
- 本节结果仅代表契约 lint/生成回归，不提升未执行的业务、平台或实机验收状态。

## 2026-09-12 Goal 接续实施记录（实时）

- 已按 Goal 要求先核对当前 dirty worktree、设计包和既有证据；未执行 reset、stash、回滚或删除无关改动。
- 本轮关键清理幂等回归已实际通过：`cargo test -p nas-analyzer purge_reservation_does_not_consume_a_second_token_on_retry --locked`，1/1。
- 当前继续处理的发布前缺口：秘密备份/恢复 HTTP 链路、恢复任务幂等与异步执行、报告数据库 FD/路径 TOCTOU，以及 React 的实际 API 契约对齐。代码和测试完成前不提升对应验收状态。
- 当前明确保持未完成：ACC-014 的 Btrfs/reflink 实机能力、真实 SMTP、ENOSPC/崩溃恢复、10 万/100 万规模与 RSS、UGOS/NAS 实机、原生 amd64 runner，以及 Redocly lint 全通过。

## 2026-09-12 当前回归与交付验证（实时）

- 当前仍为 **IN_PROGRESS**；本节只记录本轮实际运行结果，历史段落中的“待执行”以当时工作树为准。
- 修复 `export.rs` 在格式化后暴露的 5 个 Rust 编译错误：行计数显式使用 `u64`，`Write::write` 保留 `usize` 返回值并单独累计 `u64` 字节数；未改变导出协议或安全边界。
- 修复 `web/src/features/sources/SourcesPage.test.ts` 的 `SourceForm` 夹具，使其提供当前契约要求的 `volume_id/storage_kind/protected` 字段，并断言 PATCH payload 仅包含后端接受的字段。
- compare/export handler 当前已读取、校验并持久化 `Idempotency-Key`；`api/openapi.yaml` 两个 endpoint 均引用必填 `IdempotencyKey`，并已重新生成 `web/src/api/schema.d.ts`。真实 Docker E2E 已验证重复导出请求复用同一 export/job。
- 已通过：`cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked`（macOS：nas-analyzer 206、fssecure 对抗 15）、`cargo test --workspace --release --locked`（206、15）、`cargo build --release --locked -p nas-analyzer`。
- 已通过：`scripts/linux-cargo.sh test -p fssecure --test adversarial --locked`（Linux 容器 16/16）；其中受限容器不能执行真实 mount 的场景验证了能力不可用时的失败闭合路径。
- 已通过：`pnpm --dir web install --frozen-lockfile`、`typecheck`、`lint`、`test:unit`（33/33）、`build`；`./api/gen-ts.sh` 退出 0；OpenAPI bundle 通过。Redocly lint 仍为既有 nullable/license/tag 规则失败，未记为完整契约 PASS。
- `make verify-delivery` 与 `make compose-config` 已通过；当前工作树的交付脚本可执行且没有假成功入口。
- `make bench` 已通过当前树的小基准：30,000 行导出，65 ms、456,271 rows/s；RSS 指标为 `None`，不能外推到 10 万/100 万条目扫描。
- 最终 Dockerfile（Rust build stage `CARGO_BUILD_JOBS=1`）已完成两架构构建：`make docker-build` 为原生 Docker linux/arm64，`make docker-build-amd64` 为本机 arm64 上的 linux/amd64 QEMU 模拟；两次均 exit 0。
- 最终镜像冒烟均已通过：`SMOKE_PORT=18084 bash deploy/smoke.sh nas-storage-analyzer:local`（arm64）与 `SMOKE_PORT=18085 bash deploy/smoke.sh nas-storage-analyzer:local-amd64`（amd64/QEMU）。覆盖 non-root、只读根/源、cap drop、healthcheck、setup gate、SIGTERM、SQLite 重启持久化。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local bash web/tests/e2e/run-real-e2e.sh` 已 exit 0；Chromium 1/1 通过，完成初始化、登录/重登、登记数据源、扫描、报告查看、CSV 下载，并断言重复导出幂等。
- `E2E_BACKEND_BINARY=target/release/nas-analyzer bash web/tests/e2e/run-real-e2e.sh` 仍 exit 1；导出得到 `SOURCE_UNAVAILABLE`，后端日志明确为 macOS 缺少 `openat2` 写能力。这是预期 fail-closed 安全结果，不绕过，也不计为 host 全链路 PASS。

### 当前未完成/未验证

- 10 万/100 万条目、Linux RSS/索引体积、崩溃恢复/ENOSPC、真实 SMTP、Btrfs/reflink、UGOS/NAS 实机、原生配额/Tiering 和原生 amd64 runner 仍未提供证据。
- ACC-001–ACC-078 的逐项业务/平台验收仍需保持 `IMPLEMENTED`、`VERIFIED`、`UNVERIFIED` 分离；Docker 双架构 QEMU/native 证据、unit test 或一次 E2E 不能代替未执行的场景。
- OpenAPI bundle/type generation 通过，但 Redocly lint 仍失败；报告、清理、备份恢复、慢导出和资源超预算的专门故障注入仍未全部实测。

## 2026-09-11 OpenAPI/生成类型契约对齐（本轮）

- 本轮限定为 API 契约同步；未修改 Rust、React UI 组件或其他业务实现，保留既有 staged/unstaged/untracked dirty worktree。
- `api/openapi.yaml`：初始化完成补充 401；分类接口改为实际后端使用的扁平范围参数并补齐 `cursor/page_size`、列表 meta 与 410；SSE 改为 `id/event/data` 传输帧并登记当前实际事件名；owners/categories 增加 `source_id` 维度；报告聚合 `file_count/subdirectory_count` 改为十进制字符串。
- compare/export 的 `Idempotency-Key` 未加入契约：当前后端创建这两类任务时没有读取或持久化该 header，不能仅因 React 当前发送 header 就宣称幂等能力。
- 已执行 `./api/gen-ts.sh`（exit 0）重新生成 `web/src/api/schema.d.ts`；`pnpm --dir web run typecheck`（exit 0）通过；目标文件 `git diff --check`（exit 0）通过。
- `redocly lint` 仍被仓库既有的 OAS 3.1 `nullable` 规则错误及通用 license/tag 警告阻断（exit 1）；本轮未扩大范围重写全文件的既有 nullable 表达。
- `redocly bundle api/openapi.yaml --output /tmp/nas-storage-analyzer-openapi.yaml`（exit 0）通过，确认 OpenAPI 引用可解析；临时 bundle 不属于仓库交付物。

## 2026-09-11 安全阻断修复接续点（实时）

- 本轮继续执行 M0–M8 发布前差距审计；工作树保留既有 staged/unstaged/untracked 改动，未执行 reset、stash、回滚或删除无关文件。
- 已落地、待主线回归确认：CLI 管理命令在整个数据库写操作期间持有实例锁，锁竞争直接失败且不迁移数据库；配置恢复改为持有 `fssecure` 创建的 staging FD，并用 `rusqlite::serialize` 写入该 FD，移除 staging 路径重开窗口。
- 当前仍未记为发布通过：报告 artifact 的安全递归删除迁移、amd64 镜像启动冒烟、修改后完整 workspace/release/前端/真实 E2E 回归，以及最终 F01–F19/ACC-001–ACC-078 矩阵更新。
- 安全修复合入后，旧测试数字只作为修复前基线；凡受影响的 CLI、backup、fssecure、retention、HTTP、Docker 和浏览器证据必须在本轮重新执行后才能更新为 `VERIFIED`。

## 2026-09-10 继续实施检查点（实时）

- 当前 Goal 仍为 **IN_PROGRESS**，未将 M0–M8、F01–F19 或 ACC-001–ACC-078 标记为全部完成。
- 已复核根目标、`docs/design/01_SPEC.md`、`02_TASKS.md`、`03_ACCEPTANCE.md`、`04_STACK_DECISION.md`、设计包 `deploy/` 与 `contracts/`；现有实现是广泛 dirty worktree，未执行 reset/stash/回滚。
- 现有 Rust 工程包含扫描、索引/聚合、报告、重复检测、任务调度、容量采样、通知 outbox、备份/恢复、清理、诊断、OpenAPI 和 HTTP/React 页面；这些“代码存在”不等于逐项验收通过。
- 本次修复了资源预算模块之间的编译契约：统一使用 `MemoryBudgetController`，补齐后台采样循环，并使终态任务不会被迟到的进度 relay 覆盖；`cargo check --workspace --all-targets --locked` 已重新通过。
- 本次全量 debug workspace 测试实际结果为 `201 nas-analyzer + 12 fssecure` 通过；此前新增的压力测试首轮因测试值仅超过 API 预算而未超过 worker 预算失败，修正测试输入后已重跑通过。完整 release、前端、浏览器、Docker 与 Linux/目标架构证据仍需本轮继续重验。
- 已对临时目录 `/tmp/nas-analyzer-e2e.gow92q` 的真实服务结果做只读核查：报告索引包含 3 个普通文件且总量为 18 字节，但旧运行记录的进度曾显示 `files_seen=1`；代码已改为终态提交前写入最终进度，需用新二进制重启服务复验。临时目录仍只含测试数据，不作为发布或 NAS 实机证据。
- 子任务中有模型容量/上游 503 错误；未把其未完成结果计为通过，主任务继续直接审查和验证。

### 当前阶段与接续入口

- 阶段：M0–M8 纵向实现后的发布前差距审计（重点 M7/M8 资源预算、基准、真实 E2E、Docker 和验收矩阵）。
- 已实际确认：Rust debug workspace check/test；前端既有摘要显示 typecheck/lint/unit/build 通过，但修改后必须重跑；arm64 镜像与容器链路曾通过，amd64 构建曾被 crates.io `yoke-derive` 下载超时阻断，须重试并如实记录。
- 未确认：新二进制的真实浏览器闭环、M6 全部攻击/崩溃边界、10 万/100 万条目基准、amd64 镜像、绿联 NAS/UGOS 原生配额与 Tiering、真实 SMTP。
- 下一步：重启专用临时服务复验进度与路径；审查/修复 release/clippy；执行前端与真实 Playwright；运行 benchmark、`make verify-delivery`、Compose/Docker 冒烟；最后逐项填写追踪和验收文档。

## 当前阶段：M0 完成（基线绿）→ M1 接线中

- 关联需求：M1 的 F04/F05/F13/F16/F18；同时预建 M4 哈希核心与 M5 调度语义。

## 已实现（代码存在，测试状态见 TEST_REPORT）

- 环境：Rust 1.98.1（rust-toolchain.toml 固定）、Node v24.21.0、pnpm 10.8.0（web/package.json packageManager 固定）、Docker(colima) 29.x；Docker Hub 被网络阻断，基础镜像经 docker.m.daocloud.io 拉取并重打规范 tag；digest 记录于 docs/DEPENDENCIES.md。
- Cargo workspace：`crates/nas-analyzer` + `crates/fssecure`，Cargo.lock 锁定；release overflow-checks；两 crate forbid unsafe。
- fssecure：完整实现 + Linux 容器对抗测试 12/12（含特权 tmpfs 跨挂载用例）+ macOS 11/11；修复 stat 越界漏洞（中间组件不再被跟随）。ADR-0001 记录平台门控。
- 迁移：control/index/report 0001 + 校验和运行器（防篡改/防超前版本）。
- store：单写线程（有界 256）+ 4 槽读池。
- config：v2 严格校验，14 单测。
- auth：Argon2id(64MiB/3/1) 参数持久化、原子 setup（单次令牌）、会话（双过期）、再认证令牌、登录限速（5/10min）、最后管理员保护——29 单测。
- source/volume：登记/重叠拒绝/写开关矩阵/probe（mountinfo 只读探测）/身份 epoch/容量采样（fstatvfs、分钟去重、错误行非零化）/防重复计数——31 单测。
- scheduler：daily/weekly/monthly/cron + IANA 时区 + DST（回拨去重、前跳跳过）+ 月末跳过 + misfire skip/run_once(6h)——9 单测；cron crate DOW 编号差异已处理（用户层 0/7=周日 → crate 1=周日）。
- category：九类映射、最长多段匹配、扩展名校验/冲突拒绝、不可变版本派生——5 单测。
- duplicates::hashing：三段抽样指纹（仅预筛）、全量 SHA-256 流式（1MiB 缓冲、前后 fstat 身份校验、变化→Unstable、协作取消）、缓存键、令牌桶限速——8 单测。
- jobs：状态机/队列/幂等——子代理实现中。
- httpapi：M1 路由（setup/auth/admins/mounts/sources/volumes/health）+ 中间件 + serve CLI——子代理实现中。
- api/openapi.yaml：60 路径/76 操作；web/src/api/schema.d.ts 已生成。
- web/：前端工程全绿（17 单测）；deploy/Dockerfile、smoke.sh、.dockerignore、README.md 已就位。

## 已运行命令及结果（全部实际执行）

- cargo check / clippy -D warnings / fmt --check / test --workspace --locked：全部 exit 0（101 lib + 11 fssecure 测试）。
- scripts/linux-cargo.sh test -p fssecure：12/12（Linux，含 openat2 真实路径）。
- pnpm install --frozen-lockfile / typecheck / lint / test:unit(17) / build：通过。

## 已知待对齐

- error.rs HTTP 映射与 openapi.yaml 描述差异（409/422/429/503 归属）：由 httpapi 子代理统一并回报选择。
- 前端 2.3MB 单 chunk：后续 manualChunks 优化，非阻断。
- auth 有一个时间敏感测试在全套件下偶发（隔离运行通过）：待观察，必要时修。
- Linux 容器内全量 nas-analyzer 测试尚未运行（M8 前必须跑）。

## 下一步

1. httpapi + jobs 子代理完成复验 → M1 收尾（Dockerfile 构建验证、ACC-001~010 集成证据）。
2. M2 扫描引擎（有界遍历管线 + frontier 落盘 + 批写索引 + 取消/暂停）。
3. fixture 百万级生成与 ACC-021/071 资源边界测试。

## 2026-09-11 当前接续（17:30 CST）

- 修复后端 HTTP handler 的参数命名编译阻断；`cargo check --workspace --all-targets --locked` exit 0。
- 执行 `cargo fmt --all` 后，`cargo fmt --all -- --check` exit 0。
- 性能子任务复核确认先前 10k 导出 benchmark 属于源码变更前结果，不能作为当前树证据；当前源码 benchmark 需待本轮回归后重跑。
- 当前仍未将 Rust release、前端全量、真实 Playwright、Linux 文件安全回归、amd64/arm64 重新构建与最终验收矩阵标记为通过。
- 下一步：等待并审查 HTTP/React/fssecure 子任务改动，运行 debug/release/clippy/前端回归，再执行真实 E2E、benchmark、Docker 冒烟及最终交付审计。
- 2026-09-14 F01：报告输入准备阶段现在对报告范围内的每个关联卷执行一次容量采样，再读取最新样本写入不可变报告快照；仅修改 `crates/nas-analyzer/src/worker.rs`。待补：`/volumes` 的 `last_sample` 返回与日汇总完整容量字段及其前端展示，需继续实现和验证。
## 2026-09-14 当前接续回归

- 本轮未宣称 Goal 完成；继续保留 `M0–M8 IN_PROGRESS`、`ACC-001–ACC-078 UNVERIFIED`。
- 当前工作树 Rust workspace 回归已启动并通过 fssecure 17 项；nas-analyzer 全量结果正在完成中。F03/F07/F10/F14/F18 的实现缺口仍未闭合。
- 真实 NAS/UGOS 与 SMTP 按用户要求不纳入本轮工程验证，但原生 amd64、故障注入、Btrfs/reflink/qgroup、规模/RSS 及完整逐项验收仍需外部或专门环境。
## 2026-09-14 最新接续记录

- 已按要求使用 `gpt-5.6-luna`/`max` 委派 F03 只读/简单实施任务；执行窗口结束时未产生可审查代码差异或测试证据。
- 当前实际工作树 `cargo check --workspace --all-targets --locked` 通过；F03 仍只有迁移基础，列表 API、前端展示、事件消费者、契约同步和测试未完成。
- M0–M8、F01–F19 与 ACC-001–ACC-078 继续保持未完成/未验证状态；真实 NAS/UGOS 与 SMTP 按用户要求不纳入本轮。
## 2026-09-14 静态交付检查

- `cargo fmt --all`、`git diff --check` 与 `bash deploy/verify-delivery.sh` 均通过；交付合同输出 `DELIVERY CONTRACT PASS`。
- 前端生产构建通过；Vite 保留大 chunk warning。该证据不改变 F03 及完整验收矩阵的未完成状态。
## 2026-09-14 F01 聚焦验证

- `cargo test -p nas-analyzer sampling::tests --locked`：8/8 通过，覆盖日汇总、分页、窗口、十进制容量字段及报告快照。
- 该证据仅覆盖 F01 sampling 模块；F03/F07/F10/F14/F18 与完整 ACC 矩阵仍未闭合。
## 2026-09-14 F03 契约同步

- 已新增 `/api/v1/notifications` OpenAPI path、分页参数、响应及 `InternalNotification` schema，并由 `api/gen-ts.sh` 同步 TypeScript 类型。
- `./api/gen-ts.sh`、OpenAPI lint/bundle、web typecheck 和 `git diff --check` 均通过。React 通知页面与事件消费者仍未完成。
## 2026-09-14 F03 React 接入

- Settings 页面已接入 `/api/v1/notifications`，展示通知级别、标题、正文、类型、创建时间、读取状态及分页/空状态。
- Settings 页面测试由 5 项增至 6 项；前端 unit 总计 50/50，typecheck 通过。事件消费者与完整 F03 集成链路仍待完成。
## 2026-09-14 F03 事件消费者验证

- 已确认 runtime/worker 已接入幂等内部通知消费者，覆盖报告部分成功、源不可用、存储不足和清理冲突；新增 event_key 迁移与去重测试。
- `cargo test -p nas-analyzer notify::tests --locked`：11/11 通过。F03 仍需 API 集成测试和完整端到端通知流程验证。
# 2026-09-14 当前 Goal 接续回归（最新）

- 复核当前工作树后继续执行；保留所有既有 staged/unstaged/untracked 改动，未 reset、stash、回滚、删除或 push。
- 当前源码执行 `cargo test --workspace --locked`：308 passed / 0 failed / 0 ignored，Rust workspace 回归通过。
- 当前没有可用的 subagent 委派接口，因此本轮未虚构子任务结果；F07/F10/F14/F18 及完整 F03 集成/E2E 仍需继续处理。
- Goal 仍为 `IN_PROGRESS`；F01–F19 与 ACC-001–ACC-078 不因本轮回归提升为完整验收。真实 NAS/UGOS、真实 SMTP按用户要求保留为手工验证项，其余工程缺口仍未闭合。
# 2026-09-14 前端回归补充（最新）

- 当前源码执行 `pnpm --dir web run test:unit -- --runInBand`：10 files / 55 tests passed。
- 当前源码执行 `pnpm --dir web run typecheck`：exit 0。
- 该回归仅证明前端单元与类型检查，不扩大 F07/F10/F14/F18 或 ACC-001–ACC-078 的验收状态；Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 设计包完整性复核（最新）

- 在 `docs/design` 目录执行 `sha256sum -c MANIFEST.sha256`：exit 0，设计包清单全部 OK。
- `git diff --check`：exit 0。
- 该结果仅证明设计输入与当前文件格式无误，不证明 F01–F19、M0–M8 或 ACC-001–ACC-078 已完成；Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 Rust 静态质量门复核（最新）

- 当前源码 Clippy 严格检查通过；该结果不替代业务集成、Docker、平台及逐项 ACC 验收。
# 2026-09-14 Rust 发布构建（最新）

- `cargo build --release --locked -p nas-analyzer`：exit 0，耗时约 1m43s。
- 该结果证明当前源码可生成发布二进制；不替代 Docker、浏览器、平台和完整验收证据。Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 交付合同复核（最新）

- `bash deploy/verify-delivery.sh`：exit 0，输出 `DELIVERY CONTRACT PASS`；包含 config-check、前端 typecheck 与 production build。
- Vite 保留既有大 chunk warning。该检查不覆盖完整业务验收；Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 Compose 配置复核（最新）

- `make compose-config`：exit 0，Compose 配置成功渲染；确认只读根、cap drop、非 root、健康检查、资源限制和持久化挂载配置存在。
- 该结果不替代镜像启动 Smoke 或目标设备验证；Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 发布前格式复核（最新）

- `cargo fmt --all -- --check` 与 `git diff --check` 均 exit 0。
- 当前代码无格式或差异空白错误；功能缺口及完整验收状态不变，Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 OpenAPI 类型同步复核（最新）

- `./api/gen-ts.sh` 与 `pnpm --dir web run typecheck` 均 exit 0；当前契约可生成 TypeScript 类型且前端类型检查通过。
- 该结果不扩大未完成功能或 ACC 验收状态，Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 OpenAPI 发布检查（最新）

- Redocly lint 与 bundle 均成功；lint 保留 6 条既有 warning，bundle 输出到临时文件。
- 契约可解析但 warning 尚未清理；不将其视为完整验收，Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 依赖审计（最新）

- 依赖审计脚本执行成功并生成当前审计产物；该结果不替代完整功能与平台验收，Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 Release workspace 回归（最新）

- `cargo test --workspace --release --locked`：exit 0，308 passed / 0 failed / 0 ignored，耗时约 2m01s。
- 该结果不替代完整业务、Docker、平台和 ACC 验收；Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 F10 契约边界复核（最新）

- 复核确认文件明细接口已有统一 `QuerySpec` 的完整解析与筛选实现；排行接口当前 `ReportRankingsQuery` 仅声明 `cursor`、`page_size`，OpenAPI 对 `/reports/{id}/rankings/{kind}` 也未声明其余筛选参数。
- 因此不能在当前契约未定义时猜测或单方面扩展排行筛选字段；F10 继续为 `PARTIAL`，需要先完成规格/契约同步，再实现排行查询与游标哈希联动。
# 2026-09-14 Makefile 单元测试入口回归（最新）

- `make test-unit`：exit 0；Rust lib 308 passed，React 10 files / 55 tests passed。
- 该结果验证统一测试入口有效，不替代完整业务与平台验收；Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 Makefile 安全测试入口回归（最新）

- `make test-security`：exit 0；fssecure adversarial 15 passed / 0 failed。
- 该结果验证安全测试入口与当前实现，不替代完整平台故障注入和 ACC 验收；Goal 仍为 `IN_PROGRESS`。
# 2026-09-14 Workspace 全目标检查（最新）

- `cargo check --workspace --all-targets --locked`：exit 0，当前 workspace 全目标编译通过。
- 该结果不替代完整业务、Docker、平台和 ACC 验收；Goal 仍为 `IN_PROGRESS`。
