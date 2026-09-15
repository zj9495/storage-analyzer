# REQUIREMENTS_TRACEABILITY

## 2026-09-14 F03 内部通知分页游标修复（最新）

- `notify.rs::list_internal_notifications` 使用 `(created_at, id)` 稳定 keyset 排序；读取 `page_size + 1` 只用于判断是否有下一页，返回页截断后由最后返回行生成游标。
- 固定三行同 timestamp 测试使用 `notification-c/b/a`，第一页 `c,b`、第二页 `a`，不依赖 UUID 创建顺序；`notify` 11/11、内部通知 handler 游标 1/1、workspace Rust 通过。
- F03 当前实现面包括内部通知迁移/幂等事件键、报告/源/存储事件消费者、认证分页 API、React 设置页和 OpenAPI/生成类型；自动化证据已补齐，但真实 SMTP、真实 NAS/UGOS、完整浏览器业务链路和 ACC-057 逐场景验收仍保持 `UNVERIFIED`。

## 2026-09-14 F01 日容量汇总实现证据（最新）

- F01 的日容量数据链路已完成：`total/free/available/used` 的 `min/max/last` 已在迁移、采样聚合、持久化读写和 HTTP JSON 输出中保持一致；聚焦测试为 sampling 10/10、容量 handler 2/2。
- F01 总体仍保持 `PARTIAL / UNVERIFIED`，因为本条证据不覆盖完整页面、报告生命周期、平台和逐项 ACC 验收；ACC-001–ACC-078 继续保持 `UNVERIFIED`。

## 2026-09-14 F03 迁移进展（历史记录；后续已完成）

- 初始迁移阶段只有内部通知表基础；后续 API、React、事件消费者和分页回归见文档顶部最新记录。

## 2026-09-14 当前 F01 回归与 F03 状态（历史记录）

- F01：日容量聚合、持久化、查询和 API 输出已通过聚焦测试；Overview 展示已接线，完整端到端验收仍待执行。
- F03 旧记录中的缺失项已由后续实现补齐；当前实现/验证边界见文档顶部最新记录及 F03 行。

## 2026-09-14 F01 日汇总接入复核

- F01 的日趋势新增列尚未形成完整数据链路；迁移存在不等于实现完成，当前继续保持 `PARTIAL / UNVERIFIED`。

## 2026-09-14 F01/F06 实现进展

- F01：报告输入阶段采样和 `/volumes` 最新采样已接线，日趋势完整容量字段与专项测试仍缺失。
- F06：报告目录页面已接入当前目录文件查询、汇总、路径复制和导航，现有页面测试通过；完整验收仍未验证。

## 2026-09-14 用户停止确认（最新；矩阵未改变）

- 用户要求立即停止所有任务；Goal 当前为 `PAUSED`，未完成。本次只写入进度记录，未修改 Rust、React、OpenAPI、测试或部署实现。
- 3 个可见子代理已关闭，后续状态查询均为 `not_found`；未新增测试、构建、Docker、真实 API、实机或浏览器证据。
- F01/F03/F06/F07/F10/F14/F18 继续按顶部暂停点审计为 `PARTIAL` 或待规格决策；其余 F 项仍需完整业务证据；ACC-001–ACC-078 逐项保持 `UNVERIFIED`。
- 本次停止不改变既有矩阵，也不允许把局部自动化、ARM64 镜像、QEMU Smoke 或单次 E2E 扩大为完整 M0–M8 交付结论。
- 待完成顺序为：复核剩余 contracts/deploy 文件；确认 F14/F18 契约；补齐明确的 F 缺口并同步 API/前端/迁移/测试；再逐项补充 ACC-001–ACC-078 的可复查执行证据。

## 2026-09-14 当前树 ARM64 运行证据（最新）

- 当前源码的 Linux 固定 Rust 1.98.1 workspace 回归为 `nas-analyzer` 321/321、`fssecure` 2 个单元 + 16 个对抗测试，合计 339 个通过测试；fmt、check、clippy 和 `git diff --check` 均通过。
- 当前正式 ARM64 镜像 `nas-storage-analyzer:local-goal-20260914-final` 已构建并核实为 `linux/arm64`，digest `sha256:e8f104b182bea17e6b1db6f924b147102db26df24d5d415df56875cb78ce34f8`。该镜像的 Smoke（28400）、真实 API flow（28401）和授权 Chromium E2E（28402，1/1）均 exit 0。
- 运行证据补强 F02/F06/F07/F08/F09/F11/F12/F14/F15/F18/F19 及认证、只读边界、备份/恢复和导出幂等链路，但不等同完整功能验收。F01/F03/F06/F07/F10/F14/F18 为明确 `PARTIAL` 或待规格决策，其余 F 项仍按实现面与验证状态分开记录；ACC-001–ACC-078 仍逐项 `UNVERIFIED`。
- 当前 amd64 Dockerfile 重建已按用户停止指令中断，exit 130，未生成新的 amd64 镜像；因此不把 amd64 写成当前通过。静态审计还确认 F01、F03、F06、F07、F10 存在明确实现缺口，F14/F18 存在范围或语义未闭合，均不能仅以 `UNVERIFIED` 掩盖。原生 amd64 runner、NAS/UGOS、真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink/qgroup、规模/RSS、原生配额/Tiering 和完整逐项业务矩阵仍缺证据。

## 2026-09-14 停止执行后的实现差距审计

- F01 `PARTIAL`：报告完成链路未补采样；`/volumes` DTO 缺少 OpenAPI 已定义的 `last_sample`；日趋势固定将 total/free/available/reserved 置空；总览未展示 available/reserved 差额和口径。
- F03 `PARTIAL`：已有 SMTP outbox 不等于规格要求的内部通知列表；当前没有通知表、分页 API、页面或源不可用/部分报告/存储不足/清理冲突事件消费者。
- F06 `PARTIAL`：目录接口存在，但页面没有当前目录文件汇总、面包屑、路径复制，文件列表没有接收当前目录 ID 的完整钻取消费。
- F07 `PARTIAL`：报告 owners 返回缺少 `display_name`、`identity_source` 和报告时配额快照；当前身份/配额快照不足以完成规格要求。
- F10 `PARTIAL`：排行查询参数只有游标/分页，handler 使用默认 QuerySpec 直接读取预计算排行，未接通源、目录、类别、UID、大小、时间和名称等统一筛选。
- F14 `PARTIAL / SPEC-DECISION-REQUIRED`：当前接通的是配置备份/恢复；主规格与任务表对“可选完整数据备份”的范围表述不一致，控制库、报告、索引、隔离区等是否必须进入 V1 尚未确认。
- F18 `PARTIAL / SPEC-DECISION-REQUIRED`：`io_priority` 仅完成 `low|normal` 校验、持久化、OpenAPI/TypeScript 和表单传递；主规格没有定义 OS 映射、目标对象和能力失败语义，不能擅自写 `nice/ionice` 或 fallback。
- 上述差距来自子代理只读代码审计，本轮未修改源码、测试或契约；需先完成实现/规格决策，再更新对应 F/ACC 状态并重跑验证。

## 2026-09-14 最终 Rust 与静态检查收尾（历史质量记录；最新差距见上方）

- 当前源码直接复验：macOS `cargo test -p nas-analyzer --locked` 为 301/301；Linux Rust 1.98.1 容器同命令为 321/321，均 exit 0。
- clippy（`--all-targets -D warnings`）、fmt check 和 `git diff --check` 均通过；这些结果只证明当前自动化与静态质量门，不替代 F01–F19 或 ACC-001–ACC-078 的逐项业务、平台和故障验收。
- 状态保持：ACC-001–ACC-078 逐项为 `UNVERIFIED`；F01/F03/F06/F07/F10/F14/F18 的实现状态以停止后的差距审计为 `PARTIAL`，其余 F 项虽有实现面也仍未完成完整验收。

## 2026-09-14 清理身份与调度队列追踪（本轮）

- F15 / ACC-009：`crates/nas-analyzer/src/cleanup.rs` 的 cleanup runtime 加载 source 身份字段，并在批准根打开后重新探测当前文件系统身份；`provisional/changed`、缺失身份和不一致身份均阻断写操作并返回稳定错误码。聚焦测试已通过，真实替换设备和崩溃恢复仍未验证。
- F02 / ACC-048/ACC-049：`crates/nas-analyzer/src/runtime.rs::schedule_once` 将 `DeploymentConfig.resources.max_queued_scans` 传入扫描任务创建；新增队列上限回归已通过。完整生产调度与重启验收仍未验证。
- 本轮未提升任何完整功能或验收状态：F01–F19 仍为 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 仍按逐项矩阵保持 `UNVERIFIED`。

## 2026-09-14 当前树交付收尾追踪（本轮）

- F01–F19 的实现状态仍全部为 `IMPLEMENTED`，验证状态仍全部为 `UNVERIFIED`。当前 Rust/React 回归、正式 ARM64 Smoke、真实 API flow 和 Docker Chromium 1/1 只为代码路径提供可复查证据，不能代替每项完整业务、故障和平台验收。
- ACC-001–ACC-078 仍逐项保持 `UNVERIFIED`。当前新增/复核证据包括：macOS Rust `nas-analyzer` 299、`fssecure` 2+15；Linux Rust 1.98.1 容器总计 337；前端 unit 49/49；正式 ARM64 镜像 `sha256:d74cab6b1fe5f50049deb27770da7fb5eb660cf9fc83509ca78d0a35a72f259b` 的 Smoke、真实 API flow 和 Chromium E2E；amd64 QEMU 镜像 `sha256:a82f61150108da1509de1fd5f83dad812f6cce16de6002d044c08e576695900e` 的 Smoke。
- `io_priority` 仅完成 `low|normal` 契约/持久化/UI/快照传递；主规格未定义 Linux OS 映射、目标执行对象和权限失败语义，故没有虚构 `nice/ionice` 实现或 fallback。该项继续按当前实现与验证边界记录。
- macOS host 的真实 API flow 在缺少 `openat2` 写能力时按设计返回 `UNSUPPORTED_CAPABILITY`/fail-closed；amd64 当前树 QEMU 镜像已构建并通过 Smoke，但 Chromium E2E 实际 exit 1、最终 job 为 `FAILED`，同一镜像的真实 API flow 进一步明确为 `phase=PUBLISH`/`error.code=UNSUPPORTED_CAPABILITY`。首次当前树构建在 `ring/p256.c` 的 GCC `cc1` segmentation fault 失败，重试成功；这些均不能作为原生 amd64 或产品 E2E 通过证据。
- 仍缺真实 NAS/UGOS、原生 amd64 runner、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、10 万/100 万规模与 RSS、原生配额/Tiering，以及 ACC 逐项业务闭环；这些缺口不会因本轮质量命令或临时镜像改变状态。

## 2026-09-14 Profile/runtime 只读复核（本轮）

- F02/F03：`profile.rs` 将 Daily/Weekly/Monthly/Cron 转为经过校验的 `ScheduleSpec`；`scheduler/schedule.rs` 负责时区、DST、月末、misfire 和 overlap 语义；`runtime.rs::schedule_once` 持久化 next run、触发幂等记录并保存 Profile/source/ruleset 快照。Profile、scheduler、runtime 聚焦测试已实际通过。
- F02/F16：`ProfileConfig::source_ids` 在 `all` 范围按 Profile 创建时间过滤未来登记源，`include_future_registered=true` 才纳入；`run_profile` 和 `schedule_once` 都在入队时生成 source_ids 快照。`profile::tests` 与 `runtime::tests::scheduler_persists_profile_creation_scoped_source_snapshot` 已通过。
- F07/F18：`file_kind_policy` 由 `load_scan_config` 传到 `ScanConfig`，扫描器在 `RegularOnly` 与 `AllMetadata` 分支中决定条目保留和统计；`owner_ids_to_list` 进入 `ReportSnapshot` 并由报告发布写入附加快照。相关 scanner/report 测试已通过。
- F18：Profile 级 metadata/hash worker 数量和 hash 读取速率已进入 worker runtime；`io_priority` 目前只有校验、OpenAPI/TypeScript 和 React 表单接线，没有 OS/I/O 调度消费者。由于主规格未定义 `low/normal` 的具体映射及能力失败语义，本轮标记为未闭合实现，不作猜测性修改。
- 启动恢复：`serve_with` 的 cleanup 恢复顺序和失败阻断已由 CLI 测试覆盖；本轮未执行真实崩溃/ENOSPC/目标 NAS 验收。

## 2026-09-14 all_metadata / owner_list_snapshot 可见性审计（本轮）

- F07 / ACC-023：主规格 8.3 要求指定 UID 的附加文件明细；当前文件查询 API `/api/v1/reports/{id}/files` 的 `owner_uids` 过滤和 `ReportDetailPage.tsx` 的 UID 筛选提供该消费路径。`owner_list_snapshot` 不是主规格公开 DTO；本轮在 `report.rs` 以真实发布测试验证它仅保存选定 UID 聚合，不改变全量 owner 聚合。ACC-023 仍为 `IMPLEMENTED / UNVERIFIED`，因为完整黄金数据集验收未执行。
- F07 / F18 / ACC-065：主规格 5.1、10.4、16.2 要求特殊条目不读内容并保留元数据；`scanner/walk.rs` 的 `FileKindPolicy::AllMetadata` 与 `report.rs` 的发布明细 artifact 保留该数据。本轮新增 symlink 临时 fixture 测试，证明 `entry_kind`、UID、mode 保留且 size 不伪造。未新增特殊条目公开列表 API/UI，因规格未定义该消费契约；ACC-065 仍为 `IMPLEMENTED / UNVERIFIED`。
- 本轮未修改 OpenAPI 或 React 查询契约；若需求变为展示内部 `owner_list_snapshot` 聚合，缺少明确 DTO、分页和空/过期语义，当前列为待产品规格输入而非推测实现。

## 2026-09-14 当前审计口径（进行中）

- Profile 相关追踪正在重新闭合：调度输入、动态源选择、文件类型统计、指定 UID 附加分组和资源限制必须同时有 Rust 运行时消费者、OpenAPI/生成类型、React 表单和聚焦测试；仅有落库字段或历史前端测试不算闭合。
- 本轮未提升任何 F01–F19 或 ACC-001–ACC-078 的验证状态。既有实现、自动化测试、ARM64 镜像和局部 E2E 证据继续与 `VERIFIED` 分离；修改后的相关证据需在本轮后续命令完成后更新。
- 接续证据入口：`crates/nas-analyzer/src/profile.rs`、`crates/nas-analyzer/src/scheduler/`、`crates/nas-analyzer/src/scanner/`、`crates/nas-analyzer/src/worker.rs`、`api/openapi.yaml`、`web/src/api/schema.d.ts`、`web/src/features/profiles/ProfilesPage.tsx` 及对应测试。

## 2026-09-13 23:20 当前源码 Linux 回归与真实 API 流（最新）

- 当前源码 Linux 全量回归实际通过：固定 Rust 1.98.1 容器 workspace `311 passed / 0 failed / 0 ignored`（`fssecure` 2 + 16、`nas-analyzer` 293、main/doc-test 0）；同一最终 hash `f765a86…` 的定向回归为 `fssecure` `16/16`、`cleanup` `47/47`、`jobs` `19/19`、`duplicates` `10/10`、`report` `25/25`。此前一次 doc-test 前 rustup 下载停滞已由成功重跑取代。
- 当前源码 release 二进制在 Rust 1.98.1 Linux 容器中构建成功，并通过临时 ARM64 镜像运行 `scripts/real-api-flow.sh`；该 HTTP 流 exit 0，补强 F06/F07/F08/F09/F11/F12/F14/F15/F19 及认证、只读写保护的真实接口追踪：覆盖双源扫描、metadata/quota、SHA-256 重复与硬链接、分类历史、compare、幂等导出、备份/恢复和 cleanup preview。
- 上述镜像是临时二进制验证镜像 `sha256:01dfcb697501220ae2097c6297173ac72ba586d4f4725527d272fb8b95a64e3f`，不是当前 `deploy/Dockerfile` 正式构建；正式 ARM64 重建在 crates.io index 阶段 exit 130，未生成目标 tag。19:01 的正式 ARM64 镜像记录因此降为历史快照。
- 该证据只增加可核对的实现/接口链路，不把任何 F01–F19 提升为 `VERIFIED`；ACC-001–ACC-078 仍逐项 `UNVERIFIED`。Linux 全量 doc-test 的最终 exit、正式 Dockerfile 当前源码镜像、原生 amd64、NAS/UGOS、SMTP、故障/规模和完整逐项验收仍未闭合。

## 2026-09-13 19:01 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；后续源码变更和验证见上方）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；当前源码 ARM64 镜像构建成功，命令使用 `deploy/Dockerfile` 的显式 Cargo sparse registry 设置：`docker buildx build --builder colima --network=host --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-current-20260913-1845 --load --progress=plain .` exit 0；digest `sha256:0e3db311a550d66e3e153006b601758268bcb858845e003a6912e77454ad6c6c`，架构 `arm64/linux`。
- `SMOKE_PORT=28220 bash deploy/smoke.sh nas-storage-analyzer:local-current-20260913-1845` exit 0；`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-current-20260913-1845 E2E_DOCKER_HOST_PORT=28222 bash web/tests/e2e/run-real-e2e.sh` exit 0，Chromium 1/1 通过。该局部链路覆盖初始化、认证重登、数据源登记、报告任务、报告、CSV 下载和重复导出幂等请求；E2E 后端同时使用 Compose 等价的 read-only、cap-drop、no-new-privileges、tmpfs、资源限制和显式 non-root 约束。
- Dockerfile 的 sparse 设置只修复构建依赖解析路径，不改变安全边界；Smoke 继续验证 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。浏览器调用已获用户授权。
- 该证据补强 F06/F12/F18/F19 及认证/可操作性链路的当前运行追踪，但只覆盖 ARM64 镜像的局部主链路；F01–F19 仍保持 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 仍逐项 `UNVERIFIED`。旧 `sha256:0f42333a...` 镜像记录已降为历史快照。
- amd64 若在本机 ARM64 上构建只能记为 QEMU 仿真，不能替代原生 amd64；真实 NAS/UGOS、SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃、规模/RSS、原生配额/Tiering 和完整逐项验收仍无证据。

## 2026-09-13 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；镜像早于当前 Dockerfile/E2E 复验）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；当前源码 ARM64 镜像 `nas-storage-analyzer:local-aggregate-20260913` 构建成功，digest 为 `sha256:0f42333ad0e866b5923d9af506a1d719e7ecd168f3038f99f670ecade9e3fc30`，架构为 `arm64/linux`。
- `SMOKE_PORT=28210 bash deploy/smoke.sh nas-storage-analyzer:local-aggregate-20260913` exit 0；`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-aggregate-20260913 E2E_DOCKER_HOST_PORT=28211 bash web/tests/e2e/run-real-e2e.sh` exit 0，Chromium 1/1 通过，覆盖初始化、认证重登、数据源登记、报告任务、报告、CSV 下载及重复导出幂等请求。
- 该证据补强 F06/F12/F18/F19 的当前可运行主链路追踪，但只覆盖当前 ARM64 镜像的局部链路；F01–F19 仍保持 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 仍逐项 `UNVERIFIED`。浏览器调用已获授权。
- amd64 QEMU Docker E2E 的 `PUBLISH` 阶段仍因 `openat2` 不可用按安全契约 fail-closed，不能替代原生 amd64；真实 NAS/UGOS、SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃、规模/RSS、原生配额/Tiering 和完整逐项验收仍无证据。

## 2026-09-13 当前源码聚合修复与回归（历史快照；以顶部 Docker/E2E 记录为准）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；本条只记录已实际复核的当前源码与交付检查，不改变既有 dirty/staged 工作树，也未修改代码、测试、OpenAPI 或部署文件。
- `crates/nas-analyzer/src/scanner/index_aggregates.rs` 已修复目录聚合顺序：按 `dfs_right ASC` 遍历，并使用 keyset `>`，保证子目录先于父目录完成聚合。
- 真实临时 fixture 黄金链路通过：8 files、4 dirs、50 logical bytes、44 unique logical bytes、7 physical objects、1 duplicate group；hard-link alias 统计正确。该链路覆盖扫描、SQLite 聚合、分类、硬链接和 SHA-256 重复组，但不等同完整逐项验收。
- macOS arm64：`nas-analyzer` 263/263，`fssecure` 2 个单元测试 + 15 个对抗测试；fmt/check/clippy、debug/release workspace tests 和 release build 均通过。Linux Rust 1.98.1 容器：`nas-analyzer` 282/282，`fssecure` 2 个单元测试 + 16 个对抗测试通过。
- 前端 unit 46/46；前端 typecheck/lint/build、`make verify-delivery`、`make compose-config` 和 `git diff --check` 均通过。
- 当前源码 ARM64 重建命令 `docker buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-aggregate-20260913 --load .` 已命中基础镜像/上下文缓存，但仍卡在 `Updating crates.io index`；约 60 秒无进展后人工取消，exit 130，未生成新镜像。旧 arm64 digest `sha256:c93d492b...` 早于本次聚合修复，不能作为当前源码 Docker/Smoke/E2E 证据。
- 当前状态口径保持不变：F01–F19 全部为 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 全部逐项为 `UNVERIFIED`；黄金 fixture 与局部质量命令不能替代完整业务、安全、平台、故障和实机验收。

## 2026-09-13 进度文档一致性审计（历史快照；由上方当前源码记录校正）

- 本次只核对并修正文档快照的状态标注、旧计数和 amd64 QEMU 结果表述，未修改 Rust、React、OpenAPI、测试、部署脚本或配置；当前 checkout `/Users/zj9495/code/nas-storage-analyzer` 的既有 dirty/staged 工作树保持不变。
- 已复核 `CODEX_GOAL.md`、`docs/design/AGENTS.md` 以及四份进度/验收文档；追踪矩阵继续保持 F01–F19 为 `IMPLEMENTED / UNVERIFIED`、ACC-001–ACC-078 逐项 `UNVERIFIED`，历史证据没有删除。
- 设计包清单校验改在其基准目录 `docs/design` 执行后所有条目 OK（exit 0）；`make compose-config`、`make verify-delivery` 和 `git diff --check` 均 exit 0。本轮未重跑 Rust/React 测试。

## 2026-09-13 当前源码回归（历史快照；计数由上方当前源码记录校正）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；本次仅同步文档，未修改源码或测试，既有 dirty/staged 工作树保持不变。
- 当前 Rust 回归证据：macOS arm64 fmt/check/clippy、debug/release workspace test 和 release build 均 exit 0（`nas-analyzer` 262/262，`fssecure` 2 个单元 + 15 个对抗）；Linux 固定 Rust 1.98.1 容器 workspace test exit 0（`nas-analyzer` 281/281，`fssecure` 2 个单元 + 16 个对抗）。当前前端 typecheck/lint/build/unit 均 exit 0，unit 46/46。
- `preview_metadata_import` 已返回计算得到的 `diff_summary`，对应 `metadata_import.rs`/`httpapi/handlers.rs` 回归测试通过；Profile 数据源读取已按 `next_cursor` 分页读取全部已登记数据源，对应 `ProfilesPage.test.ts` 多页读取与后续游标回归测试通过。
- 这些证据只更新当前源码实现追踪，不改变状态口径：F01–F19 继续为 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 继续逐项为 `UNVERIFIED`。

## 2026-09-13 当前源码 arm64 Docker/E2E 复验（历史快照；旧镜像早于聚合修复）

- 历史 ARM64 镜像 `nas-storage-analyzer:local-arm64-current-20260913` 的 digest 为 `sha256:c93d492b5137faf3e966f825e81a0c99fb087919dfce1b34941b8864b8839178`；该镜像早于本次 `index_aggregates.rs` 聚合修复，不能作为当前源码证据。
- `SMOKE_PORT=28200 make smoke IMAGE=nas-storage-analyzer:local-arm64-current-20260913` 和 `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-arm64-current-20260913 E2E_DOCKER_HOST_PORT=28201 bash web/tests/e2e/run-real-e2e.sh` 的结果保留为旧镜像历史证据，不继承到当前源码。
- 当前源码 ARM64 重建因 `Updating crates.io index` 停滞而以 exit 130 取消，未生成新镜像；因此不能据此主张当前 ARM64 Smoke/E2E 通过，amd64 QEMU 也不能替代原生 amd64。

## 2026-09-13 当前源码 arm64 Docker/E2E 与交付回归（历史快照；回归计数见上方）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`，保留既有 dirty/staged 工作树。当前源码 ARM64 镜像 `nas-storage-analyzer:local` 的 `docker image inspect` 输出为 `sha256:4ff090449edb08ca666ad54704a51ab35ee87cd20076ec9d4833f7a7a437eb3b arm64/linux 2026-09-13T12:34:40.342583539+08:00`。
- `SMOKE_PORT=28190 bash deploy/smoke.sh nas-storage-analyzer:local` exit 0；Docker 安全边界和 SQLite 重启持久化通过。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local E2E_DOCKER_HOST_PORT=28191 bash web/tests/e2e/run-real-e2e.sh` exit 0；Docker-backed Chromium 1/1 通过，完成初始化、登录/重登、登记源、扫描、报告、CSV 下载及同一 `Idempotency-Key` 的导出幂等验证。
- `make bench`、`make compose-config`、`make verify-delivery` 均 exit 0；benchmark 为 30,000 行导出、`elapsed_ms=64`、`rows_per_sec=463953`，`api_rss_bytes=None`、`worker_rss_bytes=None`。这些结果支持当前 ARM64 交付和局部主链路，不替代 F01–F19 或 ACC-001–ACC-078 的逐项验收。
- `./api/gen-ts.sh`、Redocly lint/bundle、`pnpm --dir web run typecheck`、`pnpm --dir web run lint`、`pnpm --dir web run build` 和当前前端 unit 46/46 均已通过；Redocly lint 保留 4 个 warning、前端 lint 保留 3 个 Fast Refresh warning，不能写成无条件完整契约通过。
- amd64 仍只有 QEMU 证据，Docker E2E 在 `openat2` 能力门控处 fail-closed；原生 amd64、NAS/UGOS、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃、规模/RSS 和完整业务/平台验收继续为 `UNVERIFIED`。F01–F19 全部 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 逐项仍为 `UNVERIFIED`。

## 2026-09-13 当前源码 cleanup/job-control 回归（历史快照；已由上方 Docker/E2E 记录更新）

- M6/F15 的当前实现补齐了 supervisor 重试与恢复边界：`crates/nas-analyzer/src/cleanup.rs` 校验受控隔离路径、完整移动日志、条目序号和隔离文件身份；已隔离条目可在合法重试中跳过，未移动条目保持自己的 `journal_seq`。`crates/nas-analyzer/src/runtime.rs` 只负责合法 cleanup 任务的统一错误收尾；`crates/nas-analyzer/src/jobs.rs` 与 `web/src/features/jobs/JobsPage.tsx` 将 pause/resume 限制为 scan。
- 直接自动化证据：macOS cleanup 17/17、jobs 18/18、workspace debug/release（nas-analyzer 261/261；fssecure 2 + 15）、Linux cleanup 26/26、Linux fssecure 16/16，均通过；前端 unit 45/45、typecheck/lint/build、交付契约和 Compose config 通过。
- 这些测试覆盖 cleanup/job-control 的实现边界，但没有完成 ACC-033–047 所要求的完整竞态、崩溃注入、真实 API/浏览器和 NAS 平台矩阵，因此相关 F/ACC 验证状态不变，仍为 `UNVERIFIED`。
- 当前源码 Docker 重建命令 `make docker-build IMAGE=nas-storage-analyzer:local-cleanup-20260913` 在容器 Rust build 的 `Updating crates.io index` 阶段无进展后以 exit 130 取消；未把旧镜像 Smoke/E2E 结果继承给当前源码。本轮未调用浏览器，因未获得授权。
- 其余 F01–F19 保持 `IMPLEMENTED / UNVERIFIED`；ACC-001–ACC-078 继续逐项 `UNVERIFIED`。外部平台、真实 SMTP、故障注入、规模和原生 amd64 缺口保持原记录。

## 2026-09-13 amd64 QEMU Docker E2E 复验（历史快照；cleanup/job-control 记录见上方）

- 当前工作树 `make docker-build-amd64` exit 0；镜像 `sha256:1d7606b4a25a787649eff5d0cbd2c7a373186f5e6171226c44c6ac2f86a56b32` 为 `amd64/linux`。构建/运行在 macOS arm64 主机上通过 QEMU 完成，不是原生 amd64 runner。
- `SMOKE_PORT=28188 bash deploy/smoke.sh nas-storage-analyzer:local-amd64-current` exit 0；Docker 安全边界和 SQLite 重启持久化通过。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-amd64-current E2E_DOCKER_HOST_PORT=28189 bash web/tests/e2e/run-real-e2e.sh` exit 1，失败于 `real-flow.spec.ts:192`。保留目录 `.nas-storage-analyzer-e2e.poFmBn`；手工任务 `77c58451-e03f-4656-9ca3-669504e3dd91` 的 `/api/v1/jobs/{job_id}` 为 `FAILED/PUBLISH`，错误为 `UNSUPPORTED_CAPABILITY`：“报告 artifact 写入需要 openat2 安全解析能力”。
- 该失败是当前 `fssecure` 的安全 fail-closed 结果：amd64 QEMU 容器未提供 openat2 能力，不能改用未授权 fallback、放宽校验或修改 E2E 断言。当前 arm64 镜像 `sha256:8376ac714d038355ca9d2eefbd49f89ac11a86367d6e5c7842de072a2c57afc9` 的 Smoke 和 Docker-backed Chromium E2E（1/1）仍通过，但只证明局部主链路。
- `ACC-001`–`ACC-078` 继续全部 `UNVERIFIED`；`ACC-014` 的 Btrfs 能力实现已补齐，但仍为 `IMPLEMENTED / UNVERIFIED`，`ACC-061`、`ACC-077` 为 `IMPLEMENTED / UNVERIFIED`，M8 为 `IMPLEMENTED / PARTIAL / UNVERIFIED`。当前没有真实 Btrfs/reflink/qgroup 实机证据，不得声称 ACC-014 通过。Goal 仍不能标记完成。

## 2026-09-13 当前源码 arm64 Docker/E2E 复验（历史快照；已由上方 amd64 复验记录更新）

- 当前工作树 `make docker-build` exit 0，镜像检查为 `arm64/linux`；Smoke 改用空闲端口 `28186` 后 exit 0，验证 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- 当前镜像 Docker-backed Chromium E2E 使用 `E2E_DOCKER_HOST_PORT=28187`，exit 0、1/1，覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载及相同 `Idempotency-Key` 的导出幂等。该证据补充 F12 及相关认证/可操作性链路，但不覆盖完整功能矩阵。
- 本轮新增 `duplicates::process_index()` 返回前的 WAL checkpoint；macOS 定向测试 1/1、Linux 固定 Rust 1.98.1 定向测试 1/1，报告 FD/WAL 测试 6/6 通过。该证据补强 F09 的发布一致性实现，但不等同完整黄金重复组验收。
- `ACC-001`–`ACC-078` 仍保持逐项 `UNVERIFIED`；真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS、原生 amd64、10 万/100 万规模及 RSS、原生配额/Tiering 等外部或专项条件未满足。

## 2026-09-13 WAL checkpoint 修复与回归（历史快照；已由上方 Docker/E2E 记录更新）

- `duplicates::process_index()` 在构建重复组后、返回前显式执行 `PRAGMA wal_checkpoint(TRUNCATE)`；对应测试为 `duplicates::tests::process_index_checkpoints_wal_before_return`，macOS 1/1、Linux 固定 Rust 1.98.1 容器 1/1 通过。
- 当前 macOS arm64 workspace 的 fmt/check/clippy/debug/release test/release build 均 exit 0，`nas-analyzer` 250/250；Linux `report::tests` 6/6 通过。该证据补强 F09/ACC-028–032 的索引发布一致性实现，但不等同完整黄金重复组验收。
- 当时 arm64 Docker Smoke/E2E 证据早于本次 WAL 修改；“当前树镜像正在重建、尚待复跑”是历史快照，当前结果见顶部记录。F01–F19 与 ACC-001–ACC-078 仍严格分离实现状态和验证状态，不因定向测试提升为完整 `VERIFIED`。
- 真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS 实机、原生 amd64、10 万/100 万规模及 RSS、原生配额/Tiering 及完整逐项业务验收继续为 `UNVERIFIED`。

## 2026-09-13 当前树 Docker/Linux/E2E 续记（历史快照；已由上方 Docker/E2E 记录更新）

- 当前 Goal 仍为 `IN_PROGRESS`；F01–F19 的实现状态与验证状态继续分开，当前矩阵不因局部运行证据把任何 F 或 ACC 条目提升为完整 `VERIFIED`。
- 当前直接证据已补齐到：macOS arm64 Rust fmt/check/clippy、debug/release test、release build exit 0（`nas-analyzer` 249/249，`fssecure` 2 个单元 + 15 个对抗）；Linux 固定 `rust:1.98.1-bookworm` 容器显式 `cargo +1.98.1` 的 `fssecure` adversarial 16/16、exit 0。
- 当前树 arm64 Docker build + Smoke 通过，Smoke 使用 `SMOKE_PORT=18084`，覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。当前 arm64 镜像 Docker-backed Chromium E2E 使用 `E2E_DOCKER_HOST_PORT=18087`，exit 0、1/1，覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载和同一 `Idempotency-Key` 的导出幂等验证。
- 上述 Docker/E2E 证据可补充 F12（报告导出）及相关认证/可操作性链路的当前实现追踪，但不覆盖 F01–F19 的完整业务范围，也不改变 ACC-001–ACC-078 逐项 `UNVERIFIED`。`run-real-e2e.sh` 的端口可配置能力已用于本次运行，临时诊断日志无残留。
- amd64 既有 QEMU `ring` C 编译 `cc` SIGSEGV 是失败尝试；串行重试后的当前镜像/Smoke 见顶部记录，但 Docker E2E 仍失败，且不等同原生 amd64 runner。`duplicates::process_index()` 返回前的 WAL checkpoint 修复已由顶部回归记录确认。
- 仍 `UNVERIFIED`：真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS 实机、原生 amd64、10 万/100 万规模及 RSS、原生配额/Tiering，以及完整逐项 ACC。下方旧记录中相反的“未运行”描述保留为历史，不删除。

## 2026-09-13 full-report/export 回归与契约复核（历史快照；已由上方 Docker/E2E 记录更新）

- 当前 Goal 仍为 `IN_PROGRESS`；本节是最新证据，继续将 `IMPLEMENTED`、`VERIFIED` 与 `UNVERIFIED` 分开。full-report 已实现十个栏目输出，合并 CSV/JSON/HTML 行带 `section`，ZIP 通过独立栏目成员名和 JSON manifest 区分栏目。
- 导出创建与 worker 执行复用同一 `export_section_needs_detail` 判断；不适用于某个 full-report 子栏目的 QuerySpec 筛选直接拒绝，避免页面/导出出现静默不一致。超大字节仍按十进制字符串传输，超出 SQLite `i64` 的查询值显式报错。
- 当前自动化基线：Rust debug/release workspace（nas-analyzer 248；fssecure 2 单元 + 15 对抗）、release build、既有前端/OpenAPI/交付合同/Compose/小 benchmark 证据均保留。Docker、真实 Playwright、Linux 固定工具链、真实 SMTP、故障注入、UGOS/NAS、原生 amd64 与 10 万/100 万规模仍为 `UNVERIFIED`。

## 2026-09-12 当前工作树基线（历史快照；已由 2026-09-13 记录更新）

- 该节记录当时的 `IN_PROGRESS` 状态和既有 dirty 改动；当前证据以 2026-09-13 顶部记录为准。
- F01–F19 均有对应代码/API/页面实现面，但完整验证仍为 `UNVERIFIED`；ACC-001–ACC-078 继续逐项区分实现与验证，不以 workspace 测试、单次 E2E 或子代理摘要代替场景证据。
- 本轮新增/修复的报告查询、导出、清理预览和比较路径均绑定配置报告根并使用 `fssecure`；F14/ACC-058 的秘密备份/恢复 HTTP wiring 已实现，秘密不写入 job/audit，排队后直接取消会释放临时口令，但跨实例和故障场景仍未验证。
- 该历史快照当时记录 Linux `fssecure` 未进入测试；当前源码回归已补充 Linux adversarial 16/16 通过。其余历史 Docker 阻塞、真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS、原生 amd64、10 万/100 万规模与 RSS 仍按未验证边界保留。

## 2026-09-12 Goal 接续实施增量（实时）

- 聚焦证据：`cargo test -p nas-analyzer purge_reservation_does_not_consume_a_second_token_on_retry --locked` exit 0（1/1）。该证据只覆盖 re-auth token 在相同 purge 幂等重试中不重复消费，不覆盖完整清理链路。
- 继续按 `IMPLEMENTED`、`VERIFIED`、`UNVERIFIED`、`BLOCKED` 分离记录；当前尚未把任何 F01–F19 或 ACC-001–ACC-078 提升为完整验证通过。
- 当前重点实现缺口保持可见：ACC-058 秘密备份/恢复 HTTP 接线、M6/M7 清理 supervisor/恢复边界、报告数据库 FD/路径 TOCTOU；对应矩阵行将在代码和主任务回归后更新。

审计日期：2026-09-12。审计输入：`CODEX_GOAL.md`、`docs/design/` 设计包、`docs/IMPLEMENTATION_STATUS.md`、`docs/TEST_REPORT.md`，以及当前源码和测试文件。

状态口径：

- `实现状态=IMPLEMENTED`：当前工作树存在对应代码/API/页面实现面；不表示完整业务链路或平台能力已验收。
- `实现状态=PARTIAL`：存在部分实现，但设计要求仍有明确缺口。
- `实现状态=BLOCKED`：已核对出当前实现缺少该条目要求的必要路径；不能以已有局部代码或测试替代。
- `验证状态=VERIFIED`：当前工作树有与该条目直接对应、可复查且未被后续代码变更淘汰的通过证据。
- `验证状态=UNVERIFIED`：未执行、执行失败、仅有旧基线/子任务摘要，或需要未提供的平台环境；不能当作通过。

本轮没有保留任何 `VERIFIED` 状态：`docs/ACCEPTANCE_RESULTS.md` 的最新校正指出 Docker 镜像/冒烟/E2E 早于最后一次 `worker.rs` 修改，故 ACC-061 也只能为 `UNVERIFIED`。ACC-069 的质量命令虽有记录，但未声明依赖变更/锁文件拒绝场景没有证据，因此保持 `UNVERIFIED`。F01-F19 仍需各自真实业务链路证据，不能由全量编译、unit test 或一次 E2E 代替。下方较早的测试结果保留为历史记录，不自动继承为最后代码变更后的当前树证据。

| 需求 | 标题 | 实现位置 | API / 页面 | 测试或现有证据 | 实现状态 | 验证状态 |
| --- | --- | --- | --- | --- | --- | --- |
| F01 | 卷容量和使用趋势 | `crates/nas-analyzer/src/volume.rs`、`sampling.rs`、`worker.rs` | `/api/v1/volumes`、`/samples`；`web/src/features/overview/OverviewPage.tsx` | 报告完成补采样、`last_sample`、日趋势容量字段及总览 available/reserved 展示存在明确缺口 | PARTIAL | UNVERIFIED |
| F02 | 报告任务 | `profile.rs`、`jobs.rs`、`worker.rs` | `/api/v1/profiles`、`/run`；`ProfilesPage.tsx`、`JobsPage.tsx` | profile/jobs 测试随当前 Rust 回归执行；Profile 数据源分页读取回归测试通过；真实任务创建、排队、状态和页面流程未验证 | IMPLEMENTED | UNVERIFIED |
| F03 | 周期报告与通知 | `scheduler/`、`notify.rs`、`worker.rs`、`jobs.rs` | `/api/v1/notifications`；`SettingsPage.tsx` | 内部通知迁移、稳定 keyset 分页、事件消费者、设置页、OpenAPI/生成类型和聚焦测试已存在；真实 SMTP、完整浏览器链路和逐场景验收未执行 | IMPLEMENTED | PARTIAL |
| F04 | 分析范围 | `profile.rs`、`scanner/rules.rs` | profile scope；`ProfilesPage.tsx` | rules/profile 测试随当前 Rust 回归执行；范围组合和页面流程未验证 | IMPLEMENTED | UNVERIFIED |
| F05 | 加密目录适配 | `source.rs`、`httpapi/handlers.rs` | source availability/read policy；`SourcesPage.tsx` | source availability 代码存在；无真实加密共享环境证据 | IMPLEMENTED | UNVERIFIED |
| F06 | 目录用量与钻取 | `scanner/`、`report.rs`、`worker.rs` | `/reports/{id}/folders`；`ReportDetailPage.tsx` | 聚合和目录接口存在，但当前页面缺少当前目录文件汇总、面包屑、路径复制及目录文件查询接线 | PARTIAL | UNVERIFIED |
| F07 | 用户与配额 | `metadata_import.rs`、`report.rs` | `/reports/{id}/owners`、`/metadata/import`；报告详情页 | 导入和聚合存在，但 owners DTO/报告快照缺少 `display_name`、`identity_source` 和报告时配额快照 | PARTIAL | UNVERIFIED |
| F08 | 文件分类 | `category.rs`、`scanner/rules.rs` | `/settings/categories`；`SettingsPage.tsx` | category/rules 测试和黄金 fixture 分类链路通过；分类规则修改后的真实报告/历史稳定性未验证 | IMPLEMENTED | UNVERIFIED |
| F09 | 重复文件 | `duplicates/`、`report.rs`、`worker.rs` | `/reports/{id}/duplicates`；`ReportDetailPage.tsx` | 真实临时 fixture 的 SHA-256 重复链路通过：7 physical objects、1 duplicate group，hard-link alias 正确；预算、变化文件和完整报告 API 场景未验证 | IMPLEMENTED | UNVERIFIED |
| F10 | 排行 | `report.rs`、`worker.rs` | `/reports/{id}/rankings/{kind}`；`ReportDetailPage.tsx` | 当前 handler 仅使用默认 QuerySpec 读取预计算排行，未接通规格要求的源/目录/类别/UID/大小/时间/名称筛选 | PARTIAL | UNVERIFIED |
| F11 | 历史报告 | `report.rs`、`retention.rs`、`worker.rs` | `/api/v1/reports`；`ReportsPage.tsx` | report/retention 测试存在；发布/重启闭环未验证 | IMPLEMENTED | UNVERIFIED |
| F12 | 报告保存与 CSV | `export.rs`、`report.rs` | `/reports/{id}/exports`、`/exports/{id}/download`；报告页 | 当前源码 ARM64 Docker/Chromium E2E 1/1 通过，已下载 CSV 并验证相同 `Idempotency-Key` 的重复导出请求；大导出、慢客户端和权限矩阵仍未验证 | IMPLEMENTED | UNVERIFIED |
| F13 | 管理权限 | `auth/`、`httpapi.rs`、`handlers.rs` | `/setup`、`/auth`、`/admins`；`LoginPage.tsx`、`SettingsPage.tsx` | auth 单测随当前 Rust 回归执行，middleware 代码存在；攻击、禁用账号和会话失效矩阵未验证 | IMPLEMENTED | UNVERIFIED |
| F14 | 配置备份恢复 | `backup.rs`、`httpapi/handlers.rs`、`retention.rs` | `/settings/backup`、`/settings/restore/*`；`SettingsPage.tsx` | 普通/秘密配置备份、恢复预览和应用 HTTP 路径已接通；完整数据备份范围在规格中未闭合且当前未实现，跨新实例/故障场景也未验证 | PARTIAL | UNVERIFIED |
| F15 | 安全整理 | `cleanup.rs`、`fssecure/` | `/cleanup/*`；`CleanupPage.tsx` | 当前 Linux `fssecure` 对抗测试 16/16、cleanup 定向测试 26/26 已通过；cleanup 崩溃恢复接入、竞态和真实可写链路仍未验证 | IMPLEMENTED | UNVERIFIED |
| F16 | 外接卷 | `source.rs`、`volume.rs` | `/sources`、`/volumes`；`SourcesPage.tsx` | source/volume 测试存在；外接设备实机未验证 | IMPLEMENTED | UNVERIFIED |
| F17 | 分层/占位文件 | `source.rs`、`duplicates/`、`scanner/` | `storage_kind/read_policy`；`SourcesPage.tsx` | storage/read-policy 代码存在；tiered/remote 平台行为未验证 | IMPLEMENTED | UNVERIFIED |
| F18 | 可操作性增强 | `jobs.rs`、`diagnostics.rs`、`audit.rs`、`httpapi.rs` | `/jobs`、`/diagnostics`、`/audit`；`JobsPage.tsx`、`DiagnosticsPage.tsx` | 任务/诊断/审计实现面和 ARM64 主链路存在，但 `io_priority` 没有已定义的 OS/I/O 消费者；诊断、取消、SSE 重连、视图卸载和故障边界也未专项验收 | PARTIAL | UNVERIFIED |
| F19 | 报告对比 | `report.rs`、`httpapi/handlers.rs`、`web/src/features/reports/ComparisonResultPanel.tsx` | `/reports/{id}/compare`；`ReportsPage.tsx` | compare 代码、类型和必填幂等 header 存在；黄金 fixture 只证明基础聚合/报告数据链路，比较可比性、离线范围和重复提交的真实场景仍未验收 | IMPLEMENTED | UNVERIFIED |

## 证据缺口

- 该历史快照当时的证据缺口包含 Linux `fssecure` 对抗测试未执行；当前源码回归已补充 Linux adversarial 16/16 通过。10 万/100 万规模与峰值 RSS 证据仍待补齐。
- 旧 ARM64 Docker 镜像曾完成 Smoke 与 Docker-backed Chromium E2E，但其 digest `sha256:c93d492b...` 早于本次聚合修复；当前源码 ARM64 重建在 `Updating crates.io index` 停滞后 exit 130，未生成新镜像，因此旧镜像结果不能作为当前源码证据。amd64 仍仅有 QEMU 历史证据，不能替代原生 amd64。
- 历史 Dockerfile 记录过 arm64 原生镜像和 amd64 QEMU 镜像及 smoke，但这些镜像早于后续源码变更；amd64 结果也不是原生 amd64 runner 证据。ACC-061/ACC-077 当前不能标记为 `VERIFIED`。
- 真实 SMTP、崩溃恢复、ENOSPC、10 万/100 万条目规模测试、绿联/UGOS 实机、原生配额和 Tiering、原生 amd64 runner 均没有当前证据。导入型身份/配额代码不等于平台原生同步。
- 本轮 `redocly lint` exit 0 但保留 4 个 warning；仅 `redocly bundle` 成功和 typecheck 成功不能把 warning 未清零写成无条件的完整契约验收。
- compare/export 的 `Idempotency-Key` 已加入 OpenAPI、生成类型，并在 Rust handler 中读取、校验、持久化和复用原 job；相关验收保持 `IMPLEMENTED/UNVERIFIED`，直到重复提交/冲突集成场景实际执行。

本轮此前由子代理修改了本文件和 `docs/ACCEPTANCE_RESULTS.md`；主任务已另行更新 `docs/IMPLEMENTATION_STATUS.md` 与 `docs/TEST_REPORT.md`，并修正已过时的 compare/export 幂等描述。停止执行后新增的 F01/F03/F06/F07/F10/F14/F18 差距见本文件顶部，不能被下方历史段落的“全部 IMPLEMENTED”措辞覆盖。

## 2026-09-12 本轮逐项审计追加

本节在保留上述历史记录的基础上，依据当前工作树源码、测试文件、`docs/IMPLEMENTATION_STATUS.md`、`docs/TEST_REPORT.md`、`docs/ACCEPTANCE_RESULTS.md` 及 `docs/design/03_ACCEPTANCE.md` 追加。当前 F01–F19 的结论仍为：19 项均有代码/API/页面实现面（`实现状态=IMPLEMENTED`），但没有足以覆盖各自完整业务验收的直接证据（`验证状态=UNVERIFIED`）。F14 的秘密扩展 HTTP wiring 已实现但尚未完成跨实例与故障场景验证。

状态口径：`IMPLEMENTED` 只表示实现面存在；`VERIFIED` 只表示当前工作树存在与该条目直接对应的可复查通过证据；`UNVERIFIED` 表示未执行、失败、证据不完整或依赖未提供环境；`BLOCKED` 表示已核对出当前实现存在明确缺口，不能以测试或平台缺失替代。缺少 UGOS/NAS 实机、原生 amd64 runner、真实 SMTP、规模/RSS、ENOSPC 或崩溃注入证据的条目不写成 PASS；若只有局部代码则不能掩盖必要路径缺失。本轮没有把 QEMU amd64 结果表述为原生 amd64 通过，也没有把 macOS host 的 fail-closed E2E 失败改写为成功。

### F01–F19 复核摘要

| 范围 | 实现状态 | 验证状态 | 依据 |
| --- | --- | --- | --- |
| F01/F03/F06/F07/F10/F14/F18 | `PARTIAL` | `UNVERIFIED` | 停止后的静态审计确认存在明确实现缺口或未定语义，见本文件顶部逐项记录。 |
| F02/F04/F05/F08/F09/F11/F12/F13/F15/F16/F17/F19 | `IMPLEMENTED` | `UNVERIFIED` | 存在对应代码/API/页面实现面，但 Docker/React/Rust 局部证据不能替代各自完整业务、平台和故障验收。 |

### ACC-001–ACC-078 当前追踪矩阵

| 编号 | 实现状态 | 验证状态 | 代码/测试证据与当前缺口 |
| --- | --- | --- | --- |
| ACC-001 | IMPLEMENTED | UNVERIFIED | `auth/setup.rs`、`httpapi/handlers.rs` 及当前 Rust 回归存在；双客户端并发、日志脱敏、token 重用/过期矩阵未执行。 |
| ACC-002 | IMPLEMENTED | UNVERIFIED | `auth/admin.rs`、`auth/session.rs`、`auth/ratelimit.rs` 存在并随回归执行；禁用账号、最后管理员、登出后 cookie 复用的完整矩阵未执行。 |
| ACC-003 | IMPLEMENTED | UNVERIFIED | `httpapi.rs` 的 CSRF、Origin、代理头处理存在；无 CSRF、跨 Origin、伪造代理头攻击用例未执行。 |
| ACC-004 | IMPLEMENTED | UNVERIFIED | `crates/fssecure/tests/adversarial.rs` 的 macOS 15/15、Linux adversarial 16/16 均通过；HTTP 双重编码及完整 Source API 场景未执行。 |
| ACC-005 | IMPLEMENTED | UNVERIFIED | `config.rs`、`httpapi/handlers.rs`、Compose 示例存在；默认 Compose 的全部写端点矩阵未执行。 |
| ACC-006 | IMPLEMENTED | UNVERIFIED | `source.rs`、`report.rs` 有 offline/permission/partial 状态；缺失挂载和部分在线的服务集成未验证。 |
| ACC-007 | IMPLEMENTED | UNVERIFIED | `source.rs`、`httpapi/handlers.rs` 有 unavailable→online 状态面；真实加密共享恢复流程未执行。 |
| ACC-008 | IMPLEMENTED | UNVERIFIED | `volume.rs`、`source.rs` 及测试有容量源/重叠校验；同卷黄金数据集未验证。 |
| ACC-009 | IMPLEMENTED | UNVERIFIED | `source.rs`、`httpapi/handlers.rs` 有 identity epoch/确认接口；设备替换、断连重接和清理阻断未执行。 |
| ACC-010 | IMPLEMENTED | UNVERIFIED | `fssecure` no-follow/挂载边界代码及对抗测试存在；macOS 15/15、Linux adversarial 16/16 均通过，真实嵌套 bind mount 场景未执行，受限容器 mount 能力不可用。 |
| ACC-011 | IMPLEMENTED | UNVERIFIED | `scanner/`、`worker.rs`、`report.rs` 有黄金扫描链路；真实临时 fixture 黄金链路通过 8 files、4 dirs、50 logical bytes、44 unique logical bytes、7 physical objects、1 duplicate group，但不替代完整扫描 API/报告验收。 |
| ACC-012 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`index_writer.rs` 有身份/硬链接字段；跨范围硬链接和同对象挂载未执行。 |
| ACC-013 | IMPLEMENTED | UNVERIFIED | `index_writer.rs`、`index_aggregates.rs` 已按 `dfs_right ASC`、keyset `>` 让子目录先于父目录聚合；黄金 fixture 聚合通过，但 64 MiB 稀疏文件实测未执行。 |
| ACC-014 | IMPLEMENTED | UNVERIFIED | `source.rs` 解析 mountinfo 文件系统类型并提供 `BtrfsSharedBlockRisk`/`SourceProbe` 能力字段；`api/openapi.yaml`、`web/src/api/types.ts`、`web/src/api/schema.d.ts` 已同步，`source/tests.rs` 覆盖 Btrfs 类型解析和风险映射。实现只提示共享块可能影响 allocated-byte 解读，不测量 qgroup referenced/exclusive，不实现 reflink/快照操作，也不保证释放字节；没有真实 Btrfs/reflink/qgroup 实机证据。 |
| ACC-015 | IMPLEMENTED | UNVERIFIED | `source.rs`、`scanner/` 有 atime quality/排序面；noatime/relatime 实测未执行。 |
| ACC-016 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`report.rs` 有 mtime/atime/ctime/birthtime 数据面；时间排序夹具未执行。 |
| ACC-017 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`report.rs`、`fssecure/` 有原始路径与展示转换；非 UTF-8/超长路径未验证。 |
| ACC-018 | IMPLEMENTED | UNVERIFIED | `scanner/rules.rs` 的 glob/排除测试存在；数据库、报告、隔离区排除集成未执行。 |
| ACC-019 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`report.rs` 分离 stat/read 错误；权限夹具未执行。 |
| ACC-020 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs` 有 vanished/unstable 处理；枚举期间删除、重命名、追加测试未执行。 |
| ACC-021 | IMPLEMENTED | UNVERIFIED | `benches/resource_budget.rs` 和有界扫描管线存在；10 万/100 万条目、超大目录、峰值 RSS/索引体积未执行。 |
| ACC-022 | IMPLEMENTED | UNVERIFIED | `category.rs`、`scanner/rules.rs` 分类和最长匹配测试存在，黄金 fixture 分类链路通过；完整扩展名冲突夹具未专项执行。 |
| ACC-023 | IMPLEMENTED | UNVERIFIED | `report.rs`、`metadata_import.rs` 有 owner 聚合/UID 导入；指定 UID 黄金数据集未执行。 |
| ACC-024 | IMPLEMENTED | UNVERIFIED | `metadata_import.rs`、`httpapi/handlers.rs` 有配额/人工预算导入；真实系统配额和导入闭环未验证。 |
| ACC-025 | IMPLEMENTED | UNVERIFIED | `metadata_import.rs`、`report.rs` 有 known/unlimited/unknown/expired 结构；四态夹具未执行。 |
| ACC-026 | IMPLEMENTED | UNVERIFIED | `report.rs`、`worker.rs` 有排行上限/稳定排序；201 文件并列排行未执行。 |
| ACC-027 | IMPLEMENTED | UNVERIFIED | `export.rs`、QuerySpec 测试、`ReportDetailPage.test.ts` 存在；页面、总计和导出一致性未验证。 |
| ACC-028 | IMPLEMENTED | UNVERIFIED | `duplicates/hashing.rs`、`duplicates/mod.rs` 有全量 hash/硬链接区分；黄金 fixture 的 SHA-256 重复链路通过 7 physical objects、1 duplicate group，hard-link alias 正确，但不替代完整报告/API 场景。 |
| ACC-029 | IMPLEMENTED | UNVERIFIED | `duplicates/hashing.rs` 有流式 SHA-256 和变化校验；黄金 fixture 已覆盖全量 SHA-256 与硬链接区分，头中尾相同、内容中部不同夹具未执行。 |
| ACC-030 | IMPLEMENTED | UNVERIFIED | `profile.rs`、`duplicates/mod.rs` 有 name/mtime 候选约束；组合场景未执行。 |
| ACC-031 | IMPLEMENTED | UNVERIFIED | `duplicates/hashing.rs` 有缓存键/身份校验；内容、时间、源身份变化未执行。 |
| ACC-032 | IMPLEMENTED | UNVERIFIED | `duplicates/mod.rs`、`profile.rs` 有列表/读取预算字段；大组、预算耗尽、空文件组未执行。 |
| ACC-033 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`fssecure/` 存在安全门控；macOS `fssecure` 2+15、Linux adversarial 16/16 均通过，但清理双开关、崩溃/竞态和真实允许写链路未专项验收。 |
| ACC-034 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`CleanupPage.test.ts` 有 entry_id/保留副本校验；伪造 ID 场景未执行。 |
| ACC-035 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`jobs.rs`、handlers 有计划/再认证；过期/篡改/无再认证/重复提交集成场景未执行。 |
| ACC-036 | IMPLEMENTED | UNVERIFIED | `cleanup.rs` 有执行前重校验；内容变化和保留副本消失夹具未执行。 |
| ACC-037 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`fssecure/` 有根内安全移动/身份校验；替换路径和父目录竞争未执行。 |
| ACC-038 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`source.rs` 有 protected/tiered/特殊文件排除面；组合排除验收未执行。 |
| ACC-039 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`CleanupPage.tsx` 有 quarantine 状态和页面；真实允许文件隔离未执行。 |
| ACC-040 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`CleanupPage.test.ts` 有 restore 冲突处理；实际文件恢复未执行。 |
| ACC-041 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`runtime.rs` 有动作日志/恢复代码；写日志、rename、状态提交各边界崩溃测试未执行。 |
| ACC-042 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`fssecure/` 有同文件系统/EXDEV 检查；跨文件系统和链接替换未执行。 |
| ACC-043 | IMPLEMENTED | UNVERIFIED | `cleanup.rs` 有 purge 前保留副本重校验；最后副本变化场景未执行。 |
| ACC-044 | IMPLEMENTED | UNVERIFIED | `retention.rs`、`cleanup.rs` 有保留策略和显式 purge；批量 purge/隔离期边界未执行。 |
| ACC-045 | IMPLEMENTED | UNVERIFIED | `jobs.rs`、`profile.rs`、handlers 有任务状态/队列和幂等键持久化；手动/定时碰撞与冲突 key 集成场景未执行。 |
| ACC-046 | IMPLEMENTED | UNVERIFIED | `jobs.rs`、`worker.rs`、`JobsPage.tsx` 有 pause/resume/cancel；取消竞态和反馈时间未执行。 |
| ACC-047 | IMPLEMENTED | UNVERIFIED | `jobs.rs`、`runtime.rs` 有 INTERRUPTED/重跑关联；杀进程重启恢复未执行。 |
| ACC-048 | IMPLEMENTED | UNVERIFIED | `scheduler/`、`jobs.rs` 有 misfire/overlap 代码和测试；持久化重启场景未执行。 |
| ACC-049 | IMPLEMENTED | UNVERIFIED | `scheduler/schedule.rs` 测试覆盖 DST/月末规则；时区修改、持久化重启、预览与实际一致性未专项执行。 |
| ACC-050 | IMPLEMENTED | UNVERIFIED | `sampling.rs`、`volume.rs` 有采样、错误洞和分钟去重；与完整扫描并行的集成未执行。 |
| ACC-051 | IMPLEMENTED | UNVERIFIED | `report.rs`、`category.rs`、`metadata_import.rs` 有快照/版本字段；改分类后历史不变的真实闭环未执行。 |
| ACC-052 | IMPLEMENTED | UNVERIFIED | `report.rs`、`retention.rs`、`runtime.rs` 有 staging/publish 清理；各发布边界退出测试未执行。 |
| ACC-053 | IMPLEMENTED | UNVERIFIED | `report.rs`、handlers 有 compare 与范围/规则快照字段；不可比/离线报告场景未执行。 |
| ACC-054 | IMPLEMENTED | UNVERIFIED | `retention.rs`、`report.rs` 有 pin/明细保留/410；空间耗尽和下载租约未执行。 |
| ACC-055 | IMPLEMENTED | UNVERIFIED | `export.rs`、`ReportDetailPage.tsx` 有导出/转义面；公式注入和脚本名称夹具未执行。 |
| ACC-056 | IMPLEMENTED | UNVERIFIED | `export.rs`、handlers 有流式下载/导出并发控制；慢客户端下载、断开和权限矩阵未执行。 |
| ACC-057 | IMPLEMENTED | UNVERIFIED | `notify.rs`、`httpapi/handlers.rs`、`worker.rs` 有 SMTP/outbox 与内部通知列表/事件消费者；真实 SMTP 成功/失败/超时及完整逐场景验收未执行。 |
| ACC-058 | IMPLEMENTED | UNVERIFIED | `backup.rs`、`httpapi/handlers.rs` 已接通普通/秘密备份、恢复预览和应用；秘密口令仅保留在进程内临时存储，不写入 job/audit，排队后直接取消会释放。跨新实例恢复、秘密检查、崩溃/空间故障和完整 HTTP 集成尚未执行。 |
| ACC-059 | IMPLEMENTED | UNVERIFIED | `backup.rs`、`fssecure/` 有 ZIP/恢复安全校验；恶意归档夹具未执行。 |
| ACC-060 | IMPLEMENTED | UNVERIFIED | `store/`、`retention.rs`、`backup.rs` 有有界写入/发布失败路径；ENOSPC 和锁冲突回归未执行。 |
| ACC-061 | IMPLEMENTED | UNVERIFIED | 当前 ARM64 镜像 `sha256:d74cab6b...` 的 Smoke/API/Chromium 主链路证据已更新；amd64 当前树 QEMU 镜像 `sha256:a82f6115...` 构建和 Smoke 通过，但真实 API/Chromium 在 `PUBLISH` 因 openat2 能力不可用而 fail-closed，QEMU 不替代原生 amd64，完整双架构/部署验收仍未完成。 |
| ACC-062 | PARTIAL | UNVERIFIED | `deploy/`、`README.md` 有通用 UID/GID/只读部署说明；真实绿联型号、UGOS、内核和共享权限测试未执行。 |
| ACC-063 | IMPLEMENTED | UNVERIFIED | `audit.rs`、`diagnostics.rs`、`backup.rs` 有脱敏面；日志、HTML/ZIP 和设置 API 的全量秘密检视未执行。 |
| ACC-064 | IMPLEMENTED | UNVERIFIED | `source.rs`、`diagnostics.rs`、handlers 有身份/权限诊断；user namespace、补充组、未知用户环境未执行。 |
| ACC-065 | IMPLEMENTED | UNVERIFIED | `source.rs`、`duplicates/`、`scanner/` 有 metadata_only/tiered/unknown 策略；内容读取和平台适配测试未执行。 |
| ACC-066 | IMPLEMENTED | UNVERIFIED | `httpapi.rs`、`store/`、`config.rs` 有实例锁和配置存储；第二实例及网络文件系统阻断未执行。 |
| ACC-067 | IMPLEMENTED | UNVERIFIED | `export.rs`、`format.test.ts`、生成 TS 类型有十进制字符串面；API 超大整数往返和 SQL 溢出未专项执行。 |
| ACC-068 | IMPLEMENTED | UNVERIFIED | `source.rs`、`volume.rs`、`report.rs` 有列表/分页面；Profile 数据源已按游标读取全部分页，`ProfilesPage.test.ts` 多页回归通过；10 卷、5000 路径和未来宿主目录场景未执行。 |
| ACC-069 | IMPLEMENTED | UNVERIFIED | macOS arm64 `nas-analyzer` 263/263、`fssecure` 2+15，Linux Rust 1.98.1 容器 `nas-analyzer` 282/282、`fssecure` 2+16；fmt/check/clippy/release build 和前端 unit 46/46、typecheck/lint/build 均通过。未声明依赖变更/锁文件拒绝场景没有当前命令证据。 |
| ACC-070 | IMPLEMENTED | UNVERIFIED | `store/mod.rs`、`runtime.rs`、`worker.rs` 有专用线程/有界读池/RESOURCE_BUSY 面；延迟注入下的 live/API 并发测试未执行。 |
| ACC-071 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`store/mod.rs`、`resource_budget.rs` 有有界 frontier/队列面；百万级、慢消费者和取消不死锁未执行。 |
| ACC-072 | IMPLEMENTED | UNVERIFIED | `scanner/`、`jobs.rs`、`worker.rs` 有合作取消；块读、批事务、permit、慢 SQL 边界未执行。 |
| ACC-073 | IMPLEMENTED | UNVERIFIED | `fssecure/`、`scanner/walk.rs`、`export.rs` 有原始字节、entry_id、溢出检查；Linux 非 UTF-8、超大累计值和 release 专项验收未执行。 |
| ACC-074 | IMPLEMENTED | UNVERIFIED | `querySpec.ts`、`useECharts.ts`、`real-flow.spec.ts` 当前源码 ARM64 Docker/Chromium 主链路 E2E 1/1 通过；StrictMode 重复触发、SSE 重连和视图卸载边界仍未专项验收，amd64 QEMU 运行在 openat2 能力门控处 fail-closed。 |
| ACC-075 | IMPLEMENTED | UNVERIFIED | `export.rs`、handlers 有流式导出和并发槽；慢客户端下载、断开和并发浏览未执行。 |
| ACC-076 | IMPLEMENTED | UNVERIFIED | `runtime.rs`、`resource_budget.rs` 有 API/worker 预算处置面；持续超预算与恢复重试未执行，benchmark 的 RSS 为 `None`。 |
| ACC-077 | IMPLEMENTED | UNVERIFIED | 当前 ARM64 镜像 `sha256:d74cab6b...` 的 Smoke/API/Chromium 主链路证据已更新；amd64 QEMU 镜像 `sha256:a82f6115...` 的 Smoke 通过但真实 API/Chromium E2E 因 openat2 能力不可用按设计 fail-closed。仍缺原生 amd64 runner，以及 SQLite/证书/时区/hash/fssecure 的完整双架构运行断言。 |
| ACC-078 | IMPLEMENTED | UNVERIFIED | `config.rs`、`config/tests.rs`、deployment schema 有 v2/旧字段校验面；修改后完整 config/schema 回归及未知字段启动矩阵未专项执行。 |

### 本轮直接测试证据边界

- `docs/TEST_REPORT.md` 保留过 Rust debug/release 回归、clippy、release build、Linux `fssecure` 16/16、前端 33/33、`make verify-delivery`、Compose config、arm64 原生/amd64 QEMU smoke，以及 Docker Linux arm64 Chromium 1/1 主流程 E2E；这些较早 Docker/Linux 结果属于旧镜像或旧工具链环境，不能作为本轮当前树证据。
- 该历史审计节记录的 Docker 构建当时未完成，不能与历史容器结果合并为当前树无条件通过；当前 arm64/amd64 Docker 结果以顶部 2026-09-13 复验记录为准。
- `make bench` 只有 30,000 行导出小基准，`api_rss_bytes=None`、`worker_rss_bytes=None`；不支持 10 万/100 万条目或 RSS 验收。
- `redocly bundle` 和类型生成通过；本轮 `redocly lint` exit 0 但保留 4 个 warning，不能把 warning 未清零写成无条件的完整 OpenAPI 质量通过。
- 未提供当前证据的外部/故障项包括真实 SMTP、ENOSPC、崩溃恢复、10 万/100 万规模、Btrfs/reflink、UGOS/NAS 实机、原生配额/Tiering、原生 amd64 runner，以及完整 ACC 逐项业务闭环。因此本矩阵没有 `VERIFIED`，也没有将这些缺口写成 PASS。

## 2026-09-12 本轮审计校正记录（历史快照；已由上方 2026-09-13 状态更新）

- `docs/ACCEPTANCE_RESULTS.md` 的最新当前树校正为：最后一次 `crates/nas-analyzer/src/worker.rs` 修改发生在 Docker 镜像创建之后；因此之前 `docs/TEST_REPORT.md` 记录的 Docker smoke/E2E、以及依赖这些镜像的 ACC-061 通过结论不能继承到当前树。ACC-061 已在上方追踪矩阵改为 `IMPLEMENTED / UNVERIFIED`。
- 当前代码逐项核对确认：`backup.rs` 与 `httpapi/handlers.rs` 已提供普通/秘密备份及恢复预览、应用和幂等路径；秘密口令不写入 job/audit。跨新实例恢复、完整秘密检查、ENOSPC/崩溃注入仍未执行，故 ACC-058/F14 保持 `IMPLEMENTED / UNVERIFIED`。
- 本轮没有修改代码、测试、OpenAPI、进度报告或其它文件；只更新本文件。未调用浏览器，因本轮已有本地源码/文档/测试证据足以完成审计。
