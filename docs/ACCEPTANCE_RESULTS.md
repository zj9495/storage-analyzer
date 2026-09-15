# ACCEPTANCE_RESULTS

## 2026-09-14 F03 内部通知分页游标修复与自动化证据（最新）

- `notify.rs::list_internal_notifications` 已修复 lookahead 游标错误：查询 `page_size + 1` 后先截断返回页，再用最后返回行作为下一页 `(created_at, id)` 游标。
- 同一时间戳的固定 ID `notification-c/b/a` 跨页回归通过：第一页 `c,b`，第二页 `a`；不依赖 UUID 创建先后。
- 当前自动化证据：`notify` 11/11、内部通知 handler 游标 1/1、worker 5/5、`nas-analyzer` 308/308、workspace `fssecure` 2+15 与 `nas-analyzer` 308 全部通过；设置页 11/11、typecheck、OpenAPI 类型生成、fmt/check/clippy/diff-check 通过。
- 该证据只支持 F03 当前代码链路和分页修复，不把 F03 完整外部验收、ACC-057、M0–M8 或 ACC-001–ACC-078 记为完成；真实 SMTP 和真实 NAS/UGOS 仍按当前范围留待手动验证。

## 2026-09-14 F01 日容量汇总实现证据（最新）

- F01 日汇总已形成完整代码链路：迁移列、`sampling.rs` 聚合/写入/读取、handler JSON 输出和聚焦测试均已接通。
- 当前自动化证据为 sampling 10/10、容量 handler 2/2；该证据只支持 F01 日汇总实现，不提升 ACC-001–ACC-078 的逐项验证状态，也不替代完整 F01 页面、报告和平台验收。

## 2026-09-14 F03 迁移进展（历史记录；后续已完成）

- F03 初始迁移记录仅覆盖内部通知表；后续列表、分页、页面和事件消费者已实现，最新自动化证据见文档顶部。

## 2026-09-14 当前 F01 回归与 F03 状态

- F01 的日容量字段链路已有可复查测试证据，但完整页面和端到端验收仍未完成。
- F03 旧记录未产生实现或验收证据；后续实现与自动化证据见文档顶部，完整外部验收仍未完成。

## 2026-09-14 F01 日汇总接入复核

- F01 仍为 `PARTIAL / UNVERIFIED`。新增迁移未接入聚合、查询和页面，暂无新增验收证据。

## 2026-09-14 F01/F06 实现进展（未完成验收）

- F01 已接入报告阶段容量采样及 `/volumes` 最新采样返回；F06 已接入目录页面查询、汇总和路径导航。
- 编译、格式检查及现有 F06 页面测试通过，但不构成 F01/F06 完整验收；ACC 状态不变，仍需补日趋势字段、行为测试和端到端矩阵。

## 2026-09-14 用户停止确认（最新；未新增验收）

- 用户要求立即停止所有任务；Goal 当前为 `PAUSED`，不是成功完成状态。
- 本次已关闭 3 个可见子代理，未继续执行任何实现或验证；本次仅更新文档，没有新增验收命令或证据。
- F01/F03/F06/F07/F10/F14/F18 继续为明确 `PARTIAL` 或待规格决策；其余 F 项的局部实现/测试证据不等于完整验收；ACC-001–ACC-078 全部继续 `UNVERIFIED`。
- 因此不能把 M0–M8、F01–F19、Docker 双架构交付或 78 项验收记为完成。后续工作以本文件下方的差距审计和逐项矩阵为准。
- 待完成验收必须先补齐实现或规格决策，再重新执行受影响的自动化、当前源码 Docker 交付和真实环境矩阵；在此之前不得将任何局部结果提升为 `VERIFIED`。

## 2026-09-14 当前树 ARM64 Docker/真实链路证据（最新）

- 当前 Linux workspace 测试 exit 0：`nas-analyzer` 321/321、`fssecure` 单元 2/2 与 adversarial 16/16，共 339 个测试通过；fmt、check、clippy 及 `git diff --check` 通过。
- 当前正式 ARM64 镜像 `nas-storage-analyzer:local-goal-20260914-final` 已核实为 `linux/arm64`，digest `sha256:e8f104b182bea17e6b1db6f924b147102db26df24d5d415df56875cb78ce34f8`。Smoke（28400）、真实 API flow（28401）和授权 Chromium E2E（28402，Playwright 1/1）均 exit 0。
- 这些结果是当前源码的局部自动化、真实 HTTP、浏览器和 ARM64 交付证据，不替代 78 项逐条验收。ACC-001–ACC-078 继续逐项 `UNVERIFIED`；F01/F03/F06/F07/F10/F14/F18 为明确 `PARTIAL` 或待规格决策，其余 F 项仍按实现面与验证状态分开记录。
- 当前 amd64 Dockerfile 重建已按用户停止指令中断，exit 130，未生成新的 amd64 镜像；原生 amd64、NAS/UGOS、真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink/qgroup、10 万/100 万规模与 RSS、原生配额/Tiering 和完整业务矩阵仍未验证。实现阶段保持 `IN_PROGRESS`，当前 Goal 执行已暂停。

## 2026-09-14 停止执行后的实现差距审计

- F01：报告完成补采样、`last_sample`、日趋势容量字段和总览 available/reserved 展示不完整。
- F03：只有 SMTP outbox/设置，没有规格要求的内部通知表、分页 API、页面和事件消费者。
- F06：目录接口有实现，但目录页缺当前目录文件汇总、面包屑、路径复制和完整目录文件查询接线。
- F07：owners 返回/报告快照缺 `display_name`、`identity_source` 和报告时配额快照。
- F10：排行未接统一 QuerySpec 筛选，当前只读取预计算排行。
- F14：当前为配置备份/恢复；完整数据备份范围与 V1 必需性未决，不能宣称完整。
- F18：`io_priority` 只有契约和表单接线，没有规格定义的 OS/I/O 消费者；不能猜测 `nice/ionice` 映射。
- 上述项已在 `REQUIREMENTS_TRACEABILITY.md` 的 F 表标记 `PARTIAL`；ACC 矩阵仍逐项 `UNVERIFIED`，后续需先补实现/规格，再重跑验证。

## 2026-09-14 最终 Rust 与静态检查收尾（历史质量记录；最新差距见上方）

- 当前源码直接复验：macOS `nas-analyzer` 301/301、Linux Rust 1.98.1 容器 `nas-analyzer` 321/321，均 exit 0。
- `cargo clippy -p nas-analyzer --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均 exit 0。
- 这些是自动化回归证据，不提升完整验收状态：F01/F03/F06/F07/F10/F14/F18 的实现差距以停止后的审计为 `PARTIAL`，其余 F 项也未完成完整验收；ACC-001–ACC-078 仍逐项 `UNVERIFIED`。真实 NAS/UGOS、原生 amd64、真实 SMTP、故障注入、Btrfs/reflink/qgroup、规模/RSS 和完整业务矩阵仍未验证。

## 2026-09-14 清理身份与调度队列修复回归（本轮）

- `ACC-009`：清理运行时现已读取并核对 source filesystem identity；身份为 `changed`、缺少已确认身份或当前探测与记录不一致时，在打开运行上下文阶段返回 `SOURCE_IDENTITY_CHANGED`。新增 `cleanup::tests::runtime_cleanup_rejects_a_source_with_changed_filesystem_identity` 通过；真实设备替换/断连重接仍为 `UNVERIFIED`。
- `ACC-048/ACC-049`：`runtime::schedule_once` 已使用 `resources.max_queued_scans`，新增 `runtime::tests::scheduler_respects_configured_scan_queue_limit` 通过；完整重启、时区和生产调度验收仍为 `UNVERIFIED`。
- 本轮实际回归：cleanup 25/25、runtime 9/9、nas-analyzer 301/301，fmt 与 `git diff --check` 通过。F01–F19 和 ACC-001–ACC-078 的完整验证状态保持原矩阵，不因聚焦测试改为 `VERIFIED`。

## 2026-09-14 当前树交付收尾边界（本轮）

- 当前源码已有 macOS Rust `299 + (fssecure 2 个单元 + 15 个对抗)`、Linux Rust `337`、前端 unit `49/49`、正式 ARM64 Smoke、真实 API flow 和 Docker Chromium E2E 证据；这些证据只补强相应链路，不把局部结果扩大为完整验收。
- 正式 ARM64 镜像为 `nas-storage-analyzer:local-goal-20260914`，digest `sha256:d74cab6b1fe5f50049deb27770da7fb5eb660cf9fc83509ca78d0a35a72f259b`；amd64 当前树 QEMU 镜像也已构建成功，digest `sha256:a82f61150108da1509de1fd5f83dad812f6cce16de6002d044c08e576695900e`。第一次当前树 amd64 构建在 `ring/p256.c` 触发 GCC `cc1` segmentation fault、exit 1，重试成功；QEMU 不能替代原生 amd64 runner。
- amd64 QEMU Smoke（端口 28318）exit 0；amd64 Chromium E2E（端口 28319）实际 exit 1，任务最终为 `FAILED`。随后同一镜像的 `REAL_API_PORT=28320 bash scripts/real-api-flow.sh` 也 exit 1，首个扫描任务明确为 `phase=PUBLISH`、`error.code=UNSUPPORTED_CAPABILITY`，消息为“报告 artifact 写入需要 openat2 安全解析能力”，按安全契约 fail-closed，不是产品 E2E 通过。macOS host 真实 API flow 同样因缺少 `openat2` 写能力按安全契约 fail-closed。真实 NAS/UGOS、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、10 万/100 万规模与 RSS、原生配额/Tiering 仍未执行。
- 本轮权威状态不变：F01–F19 的实现状态为 `IMPLEMENTED`、验证状态为 `UNVERIFIED`；ACC-001–ACC-078 逐项验证状态均为 `UNVERIFIED`。单元测试、临时镜像、QEMU 和一次主流程 E2E 均不能替代逐项业务/平台验收。

## 2026-09-14 Profile/runtime 只读复核（本轮）

- ACC-041：启动路径已实际确认先标记活动任务为中断，再执行 cleanup journal 恢复；恢复失败不会启动 HTTP/runtime supervisor。CLI 启动恢复测试 4/4、runtime 相关测试 7/7 通过；真实进程崩溃注入仍为 `UNVERIFIED`。
- ACC-048/ACC-049：Daily/Weekly/Monthly/Cron、时区、DST、月末、misfire 和 overlap 的聚焦 scheduler 测试 15/15 通过；完整发布验收仍为 `IMPLEMENTED / UNVERIFIED`。
- ACC-068/ACC-071：未来登记源快照、文件类型策略和资源并发的实现链路已静态核对并由 Profile 5/5、runtime 1/1、scanner 3/3、worker 5/5 测试覆盖；百万级规模/RSS 仍为 `UNVERIFIED`。
- `io_priority` 不提升为已实现：现有规格未定义 `low/normal` 到 OS 调度的映射、能力检测和失败语义，当前仅有字段校验及 UI/API 接线。

## 2026-09-14 all_metadata / owner_list_snapshot 可见性审计（本轮）

- ACC-023：`owner_ids_to_list` 的附加文件列表消费由既有 UID 文件筛选 API/UI 承载；`owner_list_snapshot` 仅按报告内部摘要表保存。本轮报告发布测试证明选定 UID 快照为独立结构，未把内部表名扩张为未定义 API/UI。实现状态保持 `IMPLEMENTED`，验证状态保持 `UNVERIFIED`。
- ACC-065：`all_metadata` 的特殊条目元数据保留通过真实临时 symlink 扫描与发布明细测试；未宣称完成平台 `metadata_only/tiered/unknown` 全矩阵。实现状态保持 `IMPLEMENTED`，验证状态保持 `UNVERIFIED`。
- 本轮没有新增 OpenAPI/React 文件；公开契约未改变。完整 F01–F19 与 ACC-001–ACC-078 状态不因本轮聚焦测试改变。

## 2026-09-14 当前验收边界（进行中）

- 本轮复核确认 Profile 配置中的 Daily/Weekly/Monthly、未来登记源、文件类型策略、指定 UID 附加分组和 `metadata_workers`/`hash_workers`/`read_limit_mib_s` 已完成运行时接线；`io_priority` 仍未闭合，相关 ACC 条目继续保持 `IMPLEMENTED / UNVERIFIED` 或原有未闭合状态。
- 不把字段可保存、单元测试、历史 Docker 镜像、QEMU 或子任务报告记为完整验收通过。待后端实现和契约同步后，必须重跑受影响的自动化、真实 API、Docker Smoke/浏览器 E2E，并更新逐项命令与证据。
- Goal 仍为 `IN_PROGRESS`；外部 NAS/UGOS、原生 amd64、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、规模/RSS 等环境缺口继续单独记录。


## 2026-09-13 23:20 当前源码 Linux 回归与真实 API 流（最新）

- 当前源码 Linux 全量回归实际通过：固定 Rust 1.98.1 容器 workspace `311 passed / 0 failed / 0 ignored`（`fssecure` 2 + 16、`nas-analyzer` 293、main/doc-test 0）；同一最终 hash `f765a86…` 定向回归为 `fssecure` `16/16`、`cleanup` `47/47`、`jobs` `19/19`、`duplicates` `10/10`、`report` `25/25`，各命令 exit 0。此前 doc-test 前 rustup 下载停滞的尝试未作为 PASS，已由成功重跑取代。
- 当前源码 Linux release 二进制被放入临时 ARM64 验证镜像 `nas-storage-analyzer:real-api-current`（digest `sha256:01dfcb697501220ae2097c6297173ac72ba586d4f4725527d272fb8b95a64e3f`），`REAL_API_DOCKER_IMAGE=nas-storage-analyzer:real-api-current bash scripts/real-api-flow.sh` exit 0。真实 HTTP 流覆盖双源扫描/黄金数据、metadata/quota、SHA-256 重复组和硬链接、分类历史、compare、幂等导出下载、备份/恢复、cleanup preview 和只读写保护。
- 该临时镜像不等同正式 `deploy/Dockerfile` 构建；当前源码正式 ARM64 重建在 `Updating crates.io index` 阶段人工取消，exit 130，目标 tag 未生成。19:01 的 ARM64 镜像/Smoke/Chromium E2E 证据已降为历史快照，不继承为当前源码验收。
- 真实 API 流和定向测试只增加局部证据，不改变严格状态：ACC-001–ACC-078 全部仍为 `UNVERIFIED`，F01–F19 全部仍为 `IMPLEMENTED / UNVERIFIED`。Linux workspace 全量 doc-test 最终 exit、正式 Dockerfile 当前镜像、原生 amd64、NAS/UGOS、SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃、规模/RSS 和完整业务矩阵仍未完成。

## 2026-09-13 19:01 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；后续源码变更和验证见上方）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；当前源码 ARM64 镜像构建成功：`docker buildx build --builder colima --network=host --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-current-20260913-1845 --load --progress=plain .` exit 0；digest `sha256:0e3db311a550d66e3e153006b601758268bcb858845e003a6912e77454ad6c6c`，架构 `arm64/linux`。
- `SMOKE_PORT=28220 bash deploy/smoke.sh nas-storage-analyzer:local-current-20260913-1845` exit 0；Docker-backed Chromium `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-current-20260913-1845 E2E_DOCKER_HOST_PORT=28222 bash web/tests/e2e/run-real-e2e.sh` exit 0，Playwright 1/1 通过（约 8.0 秒）。
- 当前 E2E 覆盖初始化、认证/重新登录、数据源登记、报告任务、报告查看、CSV 导出下载及同一 `Idempotency-Key` 的重复导出；E2E 后端容器复现 Compose 的 read-only、cap-drop、no-new-privileges、tmpfs、资源限制和显式 non-root 约束，成功后临时运行根目录已清理。
- 该证据只支持当前 ARM64 镜像的局部主链路与交付 Smoke，不将任何 ACC 条目提升为 `VERIFIED`。ACC-001–ACC-078 仍全部为 `UNVERIFIED`，F01–F19 仍为 `IMPLEMENTED / UNVERIFIED`。amd64 QEMU 结果不能替代原生 amd64；真实 NAS/UGOS、真实 SMTP、Btrfs/reflink/qgroup、故障注入、规模/RSS、原生配额/Tiering 和完整逐项验收仍未验证。
- Dockerfile 新增的 Cargo sparse registry 设置只解决构建依赖解析停滞；未放宽安全门槛、未修改 E2E 断言，也未使用 fallback。Goal 保持 `IN_PROGRESS`。

## 2026-09-13 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；镜像早于当前 Dockerfile/E2E 复验）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；当前源码 ARM64 镜像 `nas-storage-analyzer:local-aggregate-20260913` 构建成功，digest 为 `sha256:0f42333ad0e866b5923d9af506a1d719e7ecd168f3038f99f670ecade9e3fc30`，架构为 `arm64/linux`。
- `SMOKE_PORT=28210 bash deploy/smoke.sh nas-storage-analyzer:local-aggregate-20260913` exit 0；Docker-backed Chromium `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-aggregate-20260913 E2E_DOCKER_HOST_PORT=28211 bash web/tests/e2e/run-real-e2e.sh` exit 0，Playwright 1/1 通过（10.3 秒）。
- 当前 E2E 覆盖初始化、认证/重新登录、数据源登记、报告任务、报告查看、CSV 导出下载及同一 `Idempotency-Key` 的重复导出；浏览器调用已获用户授权，成功后临时运行根目录已清理。
- 这只是当前 ARM64 镜像的局部主链路与交付 Smoke 证据；ACC-001–ACC-078 仍全部为 `UNVERIFIED`，F01–F19 仍为 `IMPLEMENTED / UNVERIFIED`。amd64 QEMU E2E 在 `PUBLISH` 因 `openat2` 能力不可用而 fail-closed，不能替代原生 amd64；其余外部平台、真实 SMTP、故障注入、规模/RSS 和完整逐项验收仍未验证。

## 2026-09-13 当前源码聚合修复与回归（历史快照；以顶部 Docker/E2E 记录为准）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；本条只记录已实际复核的当前源码与验收证据，不改变既有 dirty/staged 工作树，也未修改代码、测试、OpenAPI 或部署文件。
- `crates/nas-analyzer/src/scanner/index_aggregates.rs` 已修复目录聚合顺序：按 `dfs_right ASC` 遍历，并使用 keyset `>`，保证子目录先于父目录完成聚合。
- 真实临时 fixture 黄金链路通过：8 files、4 dirs、50 logical bytes、44 unique logical bytes、7 physical objects、1 duplicate group；hard-link alias 统计正确。该链路覆盖扫描、SQLite 聚合、分类、硬链接和 SHA-256 重复组，但不等同完整逐项验收。
- macOS arm64：`nas-analyzer` 263/263，`fssecure` 2 个单元测试 + 15 个对抗测试；fmt/check/clippy、debug/release workspace tests 和 release build 均通过。Linux Rust 1.98.1 容器：`nas-analyzer` 282/282，`fssecure` 2 个单元测试 + 16 个对抗测试通过。
- 前端 unit 46/46；前端 typecheck/lint/build、`make verify-delivery`、`make compose-config` 和 `git diff --check` 均通过。
- 当前源码 ARM64 重建命令 `docker buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-aggregate-20260913 --load .` 已命中基础镜像/上下文缓存，但仍卡在 `Updating crates.io index`；约 60 秒无进展后人工取消，exit 130，未生成新镜像。旧 arm64 digest `sha256:c93d492b...` 早于本次聚合修复，不能作为当前源码 Docker/Smoke/E2E 证据。
- 验收状态保持严格口径：ACC-001–ACC-078 全部逐项为 `UNVERIFIED`；F01–F19 继续为 `IMPLEMENTED / UNVERIFIED`。黄金 fixture 与局部质量命令不能替代完整业务、安全、平台、故障和实机验收。

## 2026-09-13 进度文档一致性审计（历史快照；由上方当前源码记录校正）

- 本次只核对并修正文档快照的状态标注、旧计数和 amd64 QEMU 结果表述，未修改 Rust、React、OpenAPI、测试、部署脚本或配置；当前 checkout `/Users/zj9495/code/nas-storage-analyzer` 的既有 dirty/staged 工作树保持不变。
- 已复核 `CODEX_GOAL.md`、`docs/design/AGENTS.md` 以及四份进度/验收文档；历史证据保留，当前状态继续严格区分 `IMPLEMENTED`、`VERIFIED` 和 `UNVERIFIED`。
- 设计包清单校验在仓库根的错误相对路径调用为 exit 1；改在 `docs/design` 执行 `sha256sum -c MANIFEST.sha256` 为 exit 0，所有条目 OK。`make compose-config`、`make verify-delivery`、`git diff --check` 均 exit 0；本轮未重跑 Rust/React 测试。Goal 仍为 `IN_PROGRESS`，ACC-001–ACC-078 逐项为 `UNVERIFIED`。

## 2026-09-13 当前源码回归（历史快照；计数由上方当前源码记录校正）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；本次仅同步文档，未修改源码或测试，既有 dirty/staged 工作树保持不变。
- Rust 当前回归：macOS arm64 fmt/check/clippy、debug/release workspace test 和 release build 均 exit 0（`nas-analyzer` 262/262，`fssecure` 2 个单元 + 15 个对抗）；Linux 固定 Rust 1.98.1 容器 workspace test exit 0（`nas-analyzer` 281/281，`fssecure` 2 个单元 + 16 个对抗）。前端 typecheck/lint/build/unit 均 exit 0，unit 46/46。
- `preview_metadata_import` 现在返回计算得到的 `diff_summary`，对应 `metadata_import.rs`/`httpapi/handlers.rs` 回归测试通过；Profile 数据源读取现在按 `next_cursor` 分页读取全部已登记数据源，对应 `ProfilesPage.test.ts` 多页读取与后续游标回归测试通过。
- 完整 F01–F19 仍按 `IMPLEMENTED / UNVERIFIED` 记录；ACC-001–ACC-078 仍逐项为 `UNVERIFIED`。本节回归证据不等同完整业务、安全、平台或外部环境验收。

## 2026-09-13 当前源码 arm64 Docker/E2E 复验（历史快照；旧镜像早于聚合修复）

- 历史 ARM64 镜像 `nas-storage-analyzer:local-arm64-current-20260913` 的 digest 为 `sha256:c93d492b5137faf3e966f825e81a0c99fb087919dfce1b34941b8864b8839178`；该镜像早于本次 `index_aggregates.rs` 聚合修复，不能作为当前源码证据。
- `SMOKE_PORT=28200 make smoke IMAGE=nas-storage-analyzer:local-arm64-current-20260913` 和 `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-arm64-current-20260913 E2E_DOCKER_HOST_PORT=28201 bash web/tests/e2e/run-real-e2e.sh` 的结果保留为旧镜像历史证据，不继承到当前源码。
- 当前源码 ARM64 重建因 `Updating crates.io index` 停滞而以 exit 130 取消，未生成新镜像；因此不能据此主张当前 ARM64 Smoke/E2E 通过，amd64 QEMU 也不能替代原生 amd64。

## 2026-09-13 当前源码 arm64 Docker/E2E 与交付回归（历史快照；回归计数见上方）

- 当前 checkout 为 `/Users/zj9495/code/nas-storage-analyzer`；保留既有 dirty/staged 工作树，未执行 reset、stash、回滚、删除或 push。
- 当前源码 ARM64 镜像 `nas-storage-analyzer:local` 的 `docker image inspect` 输出为 `sha256:4ff090449edb08ca666ad54704a51ab35ee87cd20076ec9d4833f7a7a437eb3b arm64/linux 2026-09-13T12:34:40.342583539+08:00`。
- `SMOKE_PORT=28190 bash deploy/smoke.sh nas-storage-analyzer:local` exit 0；通过 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local E2E_DOCKER_HOST_PORT=28191 bash web/tests/e2e/run-real-e2e.sh` exit 0；Docker-backed Chromium 1/1 通过，覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载及同一 `Idempotency-Key` 的导出幂等验证。
- `make bench` exit 0，`export_rows=30000 elapsed_ms=64 rows_per_sec=463953 api_rss_bytes=None worker_rss_bytes=None`；`make compose-config`、`make verify-delivery` 均 exit 0，后者输出 `DELIVERY CONTRACT PASS`。这些只是当前 ARM64 交付/局部主链路证据。
- `./api/gen-ts.sh`、Redocly lint/bundle、`pnpm --dir web run typecheck`、`pnpm --dir web run lint`、`pnpm --dir web run build` 和当前前端 unit 46/46 均已通过；Redocly lint 保留 4 个 warning、前端 lint 保留 3 个 Fast Refresh warning，不能据此记为无条件完整契约验收。
- `ACC-001`–`ACC-078` 继续全部为 `UNVERIFIED`；F01–F19 继续为 `IMPLEMENTED / UNVERIFIED`。ACC-014 为 `IMPLEMENTED / UNVERIFIED`，当前实现仅提供 Btrfs 类型/共享块风险能力面，不测量 qgroup、不实现 reflink/快照操作，也没有真实 Btrfs/reflink/qgroup 实机证据。
- amd64 QEMU Docker E2E 仍在 `openat2` 能力门控处按设计 fail-closed；QEMU 不替代原生 amd64。真实 SMTP、ENOSPC/崩溃、NAS/UGOS、原生配额/Tiering、规模/RSS 和完整逐项业务/平台验收继续未验证，Goal 仍保持 `IN_PROGRESS`。

## 2026-09-13 当前源码 cleanup/job-control 验收边界（历史快照；已由上方 Docker/E2E 记录更新）

- 当前源码的 cleanup 重试、动作日志与恢复回归已通过：macOS `cleanup::tests` 17/17、`jobs::tests` 18/18；Linux 固定 Rust 1.98.1 容器 cleanup 26/26。新增覆盖已隔离条目合法跳过并继续日志序号、supervisor 错误返回、隔离完成日志缺失/伪造、恢复完成后残留隔离文件，以及尚未移动条目保留 `journal_seq=0` 的恢复语义。
- 当前源码 Rust workspace debug/release、fmt/check/clippy/release build 和前端 unit 45/45 均通过；这些是实现与自动化回归证据，不是完整业务验收。
- 因此 `ACC-033`–`ACC-047` 仅增加了当前定向测试证据，验证状态仍为 `UNVERIFIED`：真实 HTTP/浏览器清理链路、并发竞态、进程崩溃注入、ENOSPC、EXDEV、NAS/UGOS 及完整恢复矩阵尚未执行。`ACC-046` 的非 scan pause/resume 约束有当前 jobs/UI 实现，但不提升完整操作性验收。
- 当前源码 `make docker-build IMAGE=nas-storage-analyzer:local-cleanup-20260913` 在容器 `Updating crates.io index` 阶段停滞后 exit 130，未形成当前源码镜像；不继承旧镜像 Smoke/E2E。浏览器本轮未调用，因未获得授权。
- `ACC-001`–`ACC-078` 仍全部为 `UNVERIFIED`；`ACC-061`、`ACC-077` 不因旧镜像或 QEMU 结果改变。真实 SMTP、故障注入、规模、Btrfs/reflink/qgroup、UGOS/NAS 和原生 amd64 仍未验证。

## 2026-09-13 amd64 QEMU Docker E2E 复验（历史快照；cleanup/job-control 记录见上方）

- 当前工作树 `make docker-build-amd64` exit 0，`nas-storage-analyzer:local-amd64-current` 为 `sha256:1d7606b4a25a787649eff5d0cbd2c7a373186f5e6171226c44c6ac2f86a56b32`、`amd64/linux`；macOS arm64 主机上的 QEMU 模拟不等同原生 amd64 runner。
- `SMOKE_PORT=28188 bash deploy/smoke.sh nas-storage-analyzer:local-amd64-current` exit 0；Docker 安全边界和 SQLite 重启持久化 Smoke 通过。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-amd64-current E2E_DOCKER_HOST_PORT=28189 bash web/tests/e2e/run-real-e2e.sh` exit 1，失败于 `real-flow.spec.ts:192` 的任务终态断言。保留目录 `.nas-storage-analyzer-e2e.poFmBn`；手工 API 复现任务 `77c58451-e03f-4656-9ca3-669504e3dd91` 为 `FAILED/PUBLISH`，`error.code=UNSUPPORTED_CAPABILITY`，原因是 QEMU 容器缺少 openat2 安全解析能力，报告发布按设计 fail-closed。
- 当前 arm64 镜像 `sha256:8376ac714d038355ca9d2eefbd49f89ac11a86367d6e5c7842de072a2c57afc9` 的 Smoke 和 Docker-backed Chromium E2E（1/1）通过；两架构证据都只支持局部交付/主链路，不足以提升完整 F01–F19 或任何 ACC 条目的验证状态。
- `ACC-001`–`ACC-078` 逐项验证状态继续全部为 `UNVERIFIED`；`ACC-014` 的 Btrfs 能力实现已补齐，但仍为 `IMPLEMENTED / UNVERIFIED`，`ACC-061`、`ACC-077` 为 `IMPLEMENTED / UNVERIFIED`，M8 为 `IMPLEMENTED / PARTIAL / UNVERIFIED`。当前没有真实 Btrfs/reflink/qgroup 实机证据，不得声称 ACC-014 通过。

## 2026-09-13 当前源码 arm64 Docker/E2E 复验（历史快照；已由上方 amd64 复验记录更新）

- 当前树 `make docker-build` exit 0，镜像为 `arm64/linux`；包含 WAL checkpoint 修复。
- Smoke 首次使用 `SMOKE_PORT=18086` 因本机 SSH 占用端口 exit 125，换用 `SMOKE_PORT=28186` 后 exit 0；临时容器已清理，安全与 SQLite 重启持久化断言通过。
- 当前镜像 Docker-backed Chromium E2E 使用 `E2E_DOCKER_HOST_PORT=28187`，exit 0、1/1；覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载和同一 `Idempotency-Key` 导出幂等。
- 这些是当前 arm64 镜像的局部自动化证据；本轮没有将任何 ACC 条目标记为 `VERIFIED`。重复检测完整发布、SMTP、故障、NAS/UGOS、原生 amd64、规模及其余完整验收继续为 `UNVERIFIED`。

## 2026-09-13 WAL checkpoint 修复回归（历史快照；已由上方 Docker/E2E 记录更新）

- `duplicates::process_index()` 已在返回前显式执行 `PRAGMA wal_checkpoint(TRUNCATE)`；新增 `duplicates::tests::process_index_checkpoints_wal_before_return`，macOS 1/1、Linux 固定 Rust 1.98.1 容器 1/1 通过。
- 当前工作树 macOS arm64 Rust fmt/check/clippy/debug/release/build 全部 exit 0；`nas-analyzer` 250/250，`fssecure` 2 个单元 + 15 个对抗测试。Linux `report::tests` 6/6 通过。
- 当时旧 arm64 Docker Smoke/E2E 证据早于上述源码修复；“当前树 arm64 镜像正在重建、重建后需重跑”是历史快照，当前结果见顶部记录。
- 本节只记录实现与定向自动化证据，不把任何 ACC 条目提升为 `VERIFIED`；`ACC-001`–`ACC-078` 仍按矩阵保持 `UNVERIFIED`，外部平台/故障/规模缺口继续保留。

## 2026-09-13 当前树 Docker/Linux/E2E 续记（历史快照；已由上方 Docker/E2E 记录更新）

- 当前 Goal 仍为 `IN_PROGRESS`。本轮新增的是可复查的局部执行证据，不改变逐项验收的状态口径：`IMPLEMENTED` 表示实现面存在，`VERIFIED` 仅表示对应完整条目有当前直接通过证据，`UNVERIFIED` 表示证据未执行、失败、不完整或依赖环境未提供。
- macOS arm64 Rust 全量回归最新为 `nas-analyzer` 249/249，`fssecure` 2 个单元 + 15 个对抗测试；Linux 固定 `rust:1.98.1-bookworm` 容器显式 `cargo +1.98.1` 的 `fssecure` adversarial 为 16/16、exit 0。
- 当前树 arm64 Docker build + Smoke 已通过，Smoke 使用 `SMOKE_PORT=18084`，覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- 当前 arm64 镜像的 Docker-backed Chromium E2E 使用 `E2E_DOCKER_HOST_PORT=18087`，exit 0、1/1；覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载及同一 `Idempotency-Key` 的导出幂等验证。该证据只支持相关主链路的局部追踪，不能将完整 F01–F19 或任何 ACC 条目标记为 `VERIFIED`。
- `run-real-e2e.sh` 的端口可配置能力已在本轮使用；临时诊断日志无残留。既有 `make docker-build-amd64` QEMU 的 `ring` C 编译 `cc` SIGSEGV 是失败尝试；串行重试后的当前镜像和 Smoke 结果见顶部记录，但 QEMU 不等同原生 amd64，当前 Docker E2E 仍失败。
- 因此 `ACC-001`–`ACC-078` 的逐项验证状态继续全部为 `UNVERIFIED`；尤其 `ACC-061`、`ACC-077` 不因当前 arm64 smoke 或局部 E2E 证据改变。下方旧段落中“Linux 未进入测试”或“当前 Docker/E2E 未运行”的表述是历史快照，保留但由本节最新证据校正。
- `duplicates::process_index()` 返回前的 WAL checkpoint 修复已在顶部记录确认回归通过。

仍未验证：真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS 实机、原生 amd64、10 万/100 万规模及 RSS、原生配额/Tiering，以及完整逐项业务/平台/故障验收。

## 2026-09-13 Rust 全量回归确认（历史快照；计数以顶部最新记录为准）

- 主任务独立复跑 Rust fmt/check/clippy、debug/release workspace tests 和 release build 均通过：`nas-analyzer` 249/249，`fssecure` 2 个单元 + 15 个对抗测试。
- 该证据只提升 Rust 自动化回归可信度，不改变 Docker、真实浏览器、NAS/UGOS、SMTP、故障注入、规模和逐项业务验收的 `UNVERIFIED` 边界。
- Linux `fssecure` 对抗测试已在固定 1.98.1 容器中 16/16 通过；受限容器 mount 权限不足由测试按设计闭合。该证据不替代业务安全集成、Docker 或实机验收。
- 当时首次 amd64 QEMU 构建在 `ring` C 编译时 `cc` SIGSEGV 失败；随后串行重试已构建镜像并通过 Smoke，但 Docker E2E 在 `openat2` 能力门控处失败，且 QEMU 不等同原生 amd64。`ACC-061`、`ACC-077` 及 amd64 相关证据继续为 `UNVERIFIED`。

## 2026-09-13 full-report/export 回归与 release 验证（历史快照；已由上方当前源码/Docker 记录更新）

- 当前 Goal 仍为 `IN_PROGRESS`；Rust debug/release workspace 回归和 release build 已针对当前工作树通过：`nas-analyzer` 248/248，`fssecure` 2 个单元测试 + 15 个对抗测试。
- full-report 十个栏目、合并输出的 `section` 标记、ZIP 栏目成员、目录/分类/所有者粒度、超大十进制字节和超出 `i64` 查询拒绝均有当前单测证据；这不替代 ACC-001–ACC-078 的逐场景验收。
- 当时未运行 Docker、浏览器、Linux 固定工具链、真实 NAS/UGOS、真实 SMTP、故障注入或规模验收；当前 Docker、浏览器和 Linux 固定工具链证据以本文件上方最新章节为准，所有完整 ACC 条目仍保持 `UNVERIFIED`。

## 2026-09-12 cleanup supervisor 回归补充

- cleanup supervisor 的测试生命周期阻塞已修复；host/Linux cleanup、jobs、fssecure 及 workspace debug/release 回归已有通过证据。
- 该结果不提升 Docker、完整业务矩阵或外部实机验收；相关状态继续按 `IMPLEMENTED` / `VERIFIED` / `UNVERIFIED` 分离。

## 2026-09-12 最新回归增量

- 修复 `handlers.rs` 恢复幂等测试的异步闭包所有权错误；`cargo check -p nas-analyzer --all-targets --locked` 与 cleanup 测试 12/12 已通过。
- 该修复仅影响测试夹具，不提升任何 Docker、平台或完整业务验收状态；Goal 仍为 `IN_PROGRESS`。

## 2026-09-12 当前工作树基线（历史快照；已由 2026-09-13 记录更新）

- 该节记录当时的工作树和验收口径；当前权威状态以 2026-09-13 顶部记录为准。后续同日期及更早内容均为历史快照。
- 该历史快照当时记录 Linux `fssecure` 未进入测试；当前源码回归已补充 Linux adversarial 16/16 通过。该历史快照中的其他自动化结果只证明对应命令，不等同于 78 项逐场景验收。
- `ACC-058` 的秘密备份/恢复 HTTP 接线当前存在，状态应为 `IMPLEMENTED / UNVERIFIED`；本轮 6 个 handler 专项测试验证了口令不进入 job/audit、缺失临时口令会关闭 job/export、取消会释放暂存口令，但跨新实例、恢复安全边界和完整 HTTP 集成尚未验证。
- `ACC-061` 只有在本轮针对当前代码完成 Docker 镜像重建并运行 arm64 smoke 后才可改为 `VERIFIED`；amd64 QEMU 不等于原生 amd64。当前仍待本轮 Docker 结果。
- 当前不得将 `ACC-001`–`ACC-078` 的任何完整业务/平台场景仅凭单元测试、历史镜像或子代理摘要记为 PASS；真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS、原生 amd64、10 万/100 万规模与 RSS 等保持 `UNVERIFIED`。

## 2026-09-12 Docker 重建阻塞校正（历史快照；已由 2026-09-13 当前状态更新）

- 本轮 `make docker-build` 已实际执行，但在 Rust build stage 的 `Updating crates.io index` 后约 8 分钟无输出；确认构建进程无 CPU 使用后以 Ctrl-C 取消，exit 130（`context canceled`）。
- 当时因当前代码对应镜像尚未重建，`ACC-061`、`ACC-077` 及依赖 Docker 镜像的端到端证据继续为 `UNVERIFIED`；该历史判断已由 2026-09-13 当前状态更新，旧镜像结果仍不继承。
- 当前 Goal 仍为 `IN_PROGRESS`，不得把本次取消或旧镜像结果记为 Docker 交付完成。
- Dockerfile 已显式使用基础镜像已有的 `cargo +1.98.1`；host-network 重试仍在 Cargo index 阶段停滞并取消，故未改变 `ACC-061`、`ACC-077` 或 Docker E2E 的 `UNVERIFIED` 判定。

## 2026-09-12 Goal 接续实施增量（历史快照）

- 已实际通过 `cargo test -p nas-analyzer purge_reservation_does_not_consume_a_second_token_on_retry --locked`（1/1），仅作为清理 re-auth 幂等的聚焦证据；不扩展为 ACC-035/043/044 的完整场景通过。
- 当前 ACC-058 仍保持 `IMPLEMENTED / UNVERIFIED`；清理、恢复和报告发布的故障注入仍保持未验证，本轮不因子代理摘要或旧 Docker 镜像改变状态。

## 2026-09-12 早期当前树审计快照（已由上方最新状态校正）

本节记录 Docker 重建阻塞确认前的审计快照；上方“当前工作树基线”和“Docker 重建阻塞校正”是当前权威状态。

### 判定依据

- 该快照曾直接复核 `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo check --workspace --all-targets --locked`，并运行过局部 Rust 测试；这些结果只代表当时的局部检查，已由上方记录的当前 workspace debug/release 回归更新，均不构成 M0–M8 或任何完整业务场景的验收通过。
- `stat` 显示 `crates/nas-analyzer/src/worker.rs` 在 15:12:01 修改；`docker image inspect` 显示 `nas-storage-analyzer:local` 创建于 15:05:38，`nas-storage-analyzer:local-amd64` 创建于 13:06:59。因此 `docs/TEST_REPORT.md` 所记录的 Docker smoke 和 Docker-backed E2E 发生在当前 worker 修改之前，不能作为当前树证据。
- amd64 镜像即使重建，也只能在本机 arm64 上作为 QEMU 仿真证据；不能作为原生 amd64 runner 验证。当前没有本轮重建后镜像和 E2E 的直接证据，故不将旧镜像、QEMU 或未重跑 E2E 记为通过。
- 该快照时工作树包含大量既有 staged/unstaged/untracked 改动；本轮未执行 reset、stash、回滚或删除。

### M0–M8 阶段摘要

| 阶段 | 实现状态 | 自动化验证状态 | 实机/外部环境状态 | 本轮结论与证据 |
| --- | --- | --- | --- | --- |
| M0 | IMPLEMENTED | PARTIAL | UNVERIFIED | Rust/React、迁移、OpenAPI、锁文件和测试入口存在；当前 workspace debug/release 回归、fmt/check/clippy、前端 40 tests、OpenAPI lint/bundle、交付合同和 Compose config 已有直接记录，但逐项契约和完整业务验收仍未完成。 |
| M1 | IMPLEMENTED | PARTIAL | UNVERIFIED | 认证、配置、Source/Volume、fssecure 和部署边界代码存在；历史报告记录过单测/安全测试，未完成 ACC-001–010 的逐场景集成矩阵。 |
| M2 | IMPLEMENTED | PARTIAL | UNVERIFIED | 扫描、索引、进度和受控 worker IPC 实现存在；当前 workspace 回归已通过，但黄金数据集、权限/竞争和中断重跑未完成验收。 |
| M3 | IMPLEMENTED | PARTIAL | UNVERIFIED | 聚合、不可变报告、查询、导出和 React 页面存在；当前前端回归已通过，但 Docker E2E 镜像早于最后 worker 修改，当前完整闭环未重跑。 |
| M4 | IMPLEMENTED | PARTIAL | UNVERIFIED | 重复检测、SHA-256、缓存和预算代码/测试存在；黄金重复组、变化文件、预算耗尽和跨源语义没有当前专项证据。 |
| M5 | PARTIAL | PARTIAL | UNVERIFIED | Profile、调度、容量采样、身份/配额导入及 SMTP outbox 存在；内部通知列表/事件消费者缺失，真实 SMTP、重启/DST/月末和完整导入闭环未验证。 |
| M6 | PARTIAL | PARTIAL | UNVERIFIED | 清理/恢复和 fssecure 写边界实现存在，但 Btrfs/reflink 共享块能力、竞态、崩溃、ENOSPC、真实允许写链路等发布阻断场景未实测；无安全 fallback 通过证据。 |
| M7 | PARTIAL | PARTIAL | UNVERIFIED | 保留、诊断、配置备份/恢复、资源预算和故障路径存在；完整备份范围未闭合，大规模 RSS、恢复边界、恶意归档、慢下载和故障注入未完成。 |
| M8 | IMPLEMENTED | PARTIAL | UNVERIFIED | Dockerfile、Compose、smoke、交付合同和小基准入口存在；当前 ARM64 镜像的 Smoke/API/Chromium 证据已记录，较早 amd64 QEMU 镜像仅有 Smoke 且其 API/Chromium 在 openat2 能力门控处失败；本次当前树 amd64 重建已中断，UGOS/NAS、原生 amd64、10 万/100 万条目和升级回滚无证据。 |

### ACC-001–ACC-078 本轮摘要

本轮权威判定为：`ACC-001` 至 `ACC-078` 的验证状态全部为 `UNVERIFIED`。`ACC-014` 的实现状态为 `IMPLEMENTED`：当前树已具备 Btrfs 文件系统类型探测、共享块风险字段、OpenAPI/TS 契约和源测试；但这不是 reflink/快照/qgroup 实现，也没有真实 Btrfs/reflink/qgroup 实机证据。停止后的静态审计另确认 F01/F03/F06/F07/F10/F14/F18 对应实现面存在明确缺口或未定语义，不能用历史矩阵中的 `IMPLEMENTED` 掩盖；下方历史逐项说明保留，但最新 F 状态以 `REQUIREMENTS_TRACEABILITY.md` 顶部和 F 表为准。`IMPLEMENTED` 只表示源码存在完整对应实现面，不能替代自动化、实机或外部环境验证；`PARTIAL` 表示已有明确实现缺口。

阶段表中的“自动化验证状态”使用 `PARTIAL` 表示仅有部分命令或单元测试证据；“实机/外部环境状态”只有在对应环境实际执行并留存结果后才能改变。

该历史快照当时可确认的自动化基线为：Rust debug/release workspace 回归、fmt/check/clippy、前端 frozen install/typecheck/lint/unit/build、OpenAPI 生成/lint/bundle、交付合同、Compose config 和 30,000 行小 benchmark；当时 Linux `fssecure` 脚本因固定工具链下载停滞未进入测试，Docker smoke/E2E 也未针对当时源码完成。当前源码回归已补充 Linux adversarial 16/16，通过但仍不能替代 ACC-001–ACC-078 的逐场景验收。

当前未验证且不得计为通过的范围包括：ACC-001–010 的认证/源登记集成矩阵；ACC-011–032 的黄金扫描、聚合、重复和规模夹具；ACC-033–044 的安全整理、恢复、竞态和崩溃边界；ACC-045–060 的任务、调度、历史、导出、通知、备份、ENOSPC 与恢复；ACC-061–068 的部署、平台、诊断、身份映射、超大整数和规模限制；ACC-069–078 的 Rust/React、资源边界、双架构运行时和配置兼容性专项场景。下方逐项表仍是本轮审计的逐条实现/缺口明细。

## 2026-09-12 早期验证快照（已由上方最新状态校正）

- 以下结果来自较早的验证快照；其中 Docker/Linux 结果对应旧镜像或旧工具链，不能覆盖上方当前树证据。此前快照中的“已完成”不表示当前源码已重新验证。
- `compare_reports` 与 `create_export` 已读取并持久化 `Idempotency-Key`，OpenAPI 和生成 TypeScript 类型也已声明必填 header；ACC-035/045 不再因为这一点判为实现缺口，但重复请求/冲突场景仍需专门集成证据。
- 该快照曾记录 Dockerfile 的 linux/arm64 原生构建、linux/amd64 QEMU 构建和 smoke；这些结果发生在最后一次 `worker.rs` 修改前，且 amd64 不是原生 runner 证据，当前不继承为 `ACC-061`/`ACC-077` 通过。
- 该快照曾记录 macOS host 的 `SOURCE_UNAVAILABLE` fail-closed 结果和 Linux 容器 E2E 的 CSV 下载；两者均不是当前代码对应的 Docker/Playwright 验证，不能合并宣称当前树通过。

审计日期：2026-09-12。

状态口径：`实现状态=IMPLEMENTED` 表示当前源码有对应实现面，`PARTIAL` 表示有明确实现缺口；`验证状态=VERIFIED` 只允许当前工作树有直接、可复查且未被后续变更淘汰的通过证据，`UNVERIFIED` 表示未执行、执行失败、证据不完整、旧基线/子任务摘要或外部环境缺失。本轮没有 ACC 条目具备足以保留 `VERIFIED` 的当前完整证据；尤其不把未执行的硬件、原生 amd64、SMTP、崩溃恢复或规模测试写成 PASS。

`docs/TEST_REPORT.md` 的当前证据包括 2026-09-12 Rust debug/release 回归、clippy、release build、前端全量检查、交付合同、Compose config 和小 benchmark；Docker-backed E2E、旧 Linux 测试和旧日期数字仅作为历史基线，不替代当前证据。

| 编号 | 实现状态 | 验证状态 | 命令/测试文件 | 证据与缺口 |
| --- | --- | --- | --- | --- |
| ACC-001 | IMPLEMENTED | UNVERIFIED | `auth/setup.rs`、`httpapi/handlers.rs` | 初始化/token 代码和当前 Rust 回归测试存在；并发客户端、日志和 token 重用验收未执行。 |
| ACC-002 | IMPLEMENTED | UNVERIFIED | `auth/admin.rs`、`auth/session.rs`、`auth/ratelimit.rs` | 认证、限流和管理员保护代码/测试存在并随当前 Rust 回归执行；禁用账号、最后管理员和旧 cookie 的完整矩阵未执行。 |
| ACC-003 | IMPLEMENTED | UNVERIFIED | `httpapi.rs` middleware/tests | CSRF、Origin、代理头处理存在；攻击用例当前未执行。 |
| ACC-004 | IMPLEMENTED | UNVERIFIED | `crates/fssecure/tests/adversarial.rs` | 当前 macOS `fssecure` 对抗测试 15/15、Linux adversarial 16/16 均通过；`..`、绝对路径、符号链接、HTTP 双重编码及完整 source API 场景仍未形成完整集成验收。 |
| ACC-005 | IMPLEMENTED | UNVERIFIED | `config.rs`、`httpapi/handlers.rs`、`docs/design/deploy/compose.example.yaml` | 只读配置和写端点代码存在；默认 Compose 的完整写操作矩阵未执行。 |
| ACC-006 | IMPLEMENTED | UNVERIFIED | `source.rs`、`report.rs` | offline/permission/partial 状态有代码；缺失挂载与部分在线集成未验证。 |
| ACC-007 | IMPLEMENTED | UNVERIFIED | `source.rs`、`httpapi/handlers.rs` | unavailable→online 状态面存在；真实加密共享恢复流程未执行。 |
| ACC-008 | IMPLEMENTED | UNVERIFIED | `volume.rs`、`source.rs`、`volume/tests.rs` | 容量源和重叠校验代码/测试存在；同卷黄金数据集未验证。 |
| ACC-009 | IMPLEMENTED | UNVERIFIED | `source.rs`、`httpapi/handlers.rs` | identity epoch/确认接口存在；设备替换、断开重接和清理阻断未执行。 |
| ACC-010 | IMPLEMENTED | UNVERIFIED | `fssecure/tests/adversarial.rs`、`source.rs` | no-follow 和挂载边界代码/对抗测试存在；macOS 15/15、Linux adversarial 16/16 均通过，但真实嵌套 bind mount 及完整 mount 能力场景未执行，受限容器 mount 能力不可用。 |
| ACC-011 | IMPLEMENTED | UNVERIFIED | `scanner/`、`worker.rs`、`report.rs` | 真实临时 fixture 黄金链路通过：8 files、4 dirs、50 logical bytes、44 unique logical bytes、7 physical objects、1 duplicate group；该结果不替代完整扫描 API/报告验收。 |
| ACC-012 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`scanner/index_writer.rs` | 黄金 fixture 中 hard-link alias 统计正确；跨范围硬链接和同对象挂载未执行。 |
| ACC-013 | IMPLEMENTED | UNVERIFIED | `scanner/index_writer.rs`、`scanner/index_aggregates.rs` | `index_aggregates.rs` 已按 `dfs_right ASC`、keyset `>` 让子目录先于父目录聚合；黄金 fixture 聚合通过，但 64 MiB 稀疏文件实测未执行。 |
| ACC-014 | IMPLEMENTED | UNVERIFIED | `source.rs`、`api/openapi.yaml`、`web/src/api/types.ts`、`web/src/api/schema.d.ts`、`crates/nas-analyzer/src/source/tests.rs` | 已实现 mountinfo 文件系统类型探测、`BtrfsSharedBlockRisk`/`SourceProbe` 字段、OpenAPI/TS 契约及 Btrfs 解析/风险映射测试；仅提供共享块风险提示，不测量 qgroup referenced/exclusive，不实现 reflink/快照操作，也不保证释放字节。没有真实 Btrfs/reflink/qgroup 实机证据，因此验证保持 `UNVERIFIED`。 |
| ACC-015 | IMPLEMENTED | UNVERIFIED | `source.rs`、`scanner/` | atime quality 和排序面存在；noatime/relatime 实测未执行。 |
| ACC-016 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`report.rs` | mtime/atime/ctime/birthtime 数据面存在；时间排序夹具未执行。 |
| ACC-017 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`report.rs`、`fssecure/` | 原始字节路径和展示转换代码存在；非 UTF-8/超长路径当前未验证。 |
| ACC-018 | IMPLEMENTED | UNVERIFIED | `scanner/rules.rs` | glob/排除规则测试存在；数据库、报告、隔离目录排除集成未执行。 |
| ACC-019 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`report.rs` | stat/read 错误分离代码存在；权限夹具未执行。 |
| ACC-020 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs` | vanished/unstable 处理存在；枚举期间变更测试未执行。 |
| ACC-021 | IMPLEMENTED | UNVERIFIED | `crates/nas-analyzer/benches/resource_budget.rs`、`scanner/` | 有界管线代码和小规模 benchmark 文件存在；10 万/100 万条目和峰值 RSS 未执行。 |
| ACC-022 | IMPLEMENTED | UNVERIFIED | `category.rs`、`scanner/rules.rs` | 分类映射、最长匹配测试及黄金 fixture 分类链路通过；设计中的完整扩展名冲突夹具未专项执行。 |
| ACC-023 | IMPLEMENTED | UNVERIFIED | `report.rs`、`metadata_import.rs` | owner 聚合和 UID 导入代码存在；指定 UID 黄金数据集未执行。 |
| ACC-024 | IMPLEMENTED | UNVERIFIED | `metadata_import.rs`、`httpapi/handlers.rs` | 配额/人工预算导入代码存在；真实系统配额和当前导入闭环未验证。 |
| ACC-025 | IMPLEMENTED | UNVERIFIED | `metadata_import.rs`、`report.rs` | known/unlimited/unknown/expired 结构存在；四态夹具未执行。 |
| ACC-026 | IMPLEMENTED | UNVERIFIED | `report.rs`、`worker.rs` | 排行上限和稳定排序代码存在；201 文件排行未执行。 |
| ACC-027 | IMPLEMENTED | UNVERIFIED | `export.rs`、`web/src/lib/querySpec.test.ts`、`ReportDetailPage.test.ts` | QuerySpec 单测和导出路径存在；当前树页面/导出一致性未验证。 |
| ACC-028 | IMPLEMENTED | UNVERIFIED | `duplicates/hashing.rs`、`duplicates/mod.rs` | 黄金 fixture 的全量 SHA-256 重复链路通过：7 physical objects、1 duplicate group，hard-link alias 正确；仍未完成 ACC-028 的完整报告/API 场景。 |
| ACC-029 | IMPLEMENTED | UNVERIFIED | `duplicates/hashing.rs` | 黄金 fixture 已覆盖全量 SHA-256 与硬链接区分；头/中/尾抽样相同但内容不同的反例夹具未执行。 |
| ACC-030 | IMPLEMENTED | UNVERIFIED | `profile.rs`、`duplicates/mod.rs` | name/mtime 仅作候选约束的代码存在；组合场景未执行。 |
| ACC-031 | IMPLEMENTED | UNVERIFIED | `duplicates/hashing.rs` | hash cache key/身份校验存在；内容、时间、源身份变化未执行。 |
| ACC-032 | IMPLEMENTED | UNVERIFIED | `duplicates/mod.rs`、`profile.rs` | 列表/读取预算字段存在；大组、预算耗尽、空文件场景未执行。 |
| ACC-033 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`fssecure/` | 当前 macOS `fssecure` 2+15、Linux adversarial 16/16 均通过；清理双开关、崩溃/竞态和真实允许文件写链路仍未专项验收。 |
| ACC-034 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`CleanupPage.test.ts` | entry_id/保留副本校验存在；伪造 ID 场景未执行。 |
| ACC-035 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`jobs.rs`、`httpapi/handlers.rs` | 清理计划/再认证代码存在；compare/export 已读取并持久化 `Idempotency-Key`，但过期计划、参数篡改、无再认证与重复提交的专门集成场景仍未执行。 |
| ACC-036 | IMPLEMENTED | UNVERIFIED | `cleanup.rs` | 执行前重新校验代码存在；内容变化和保留副本消失夹具未执行。 |
| ACC-037 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`fssecure/` | 根内安全移动/身份校验代码存在；替换路径和父目录竞争未执行。 |
| ACC-038 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`source.rs` | protected/tiered/特殊文件排除面存在；组合排除验收未执行。 |
| ACC-039 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`CleanupPage.tsx` | quarantine 状态和页面存在；真实允许文件隔离未执行。 |
| ACC-040 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`CleanupPage.test.ts` | restore 冲突处理代码/请求测试存在；实际文件恢复未执行。 |
| ACC-041 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`runtime.rs` | 动作日志/恢复代码存在；崩溃边界测试明确未执行。 |
| ACC-042 | IMPLEMENTED | UNVERIFIED | `cleanup.rs`、`fssecure/` | 同文件系统和 EXDEV 检查代码存在；跨文件系统/链接替换未执行。 |
| ACC-043 | IMPLEMENTED | UNVERIFIED | `cleanup.rs` | purge 前保留副本重校验代码存在；最后副本变化场景未执行。 |
| ACC-044 | IMPLEMENTED | UNVERIFIED | `retention.rs`、`cleanup.rs` | 保留策略和显式 purge 代码存在；批量 purge/隔离期边界未执行。 |
| ACC-045 | IMPLEMENTED | UNVERIFIED | `jobs.rs`、`profile.rs`、`httpapi/handlers.rs` | 任务状态/队列代码存在；scan/compare/export handler 均持久化幂等键并复用原 job，手动/定时碰撞与重复请求的完整集成场景仍未执行。 |
| ACC-046 | IMPLEMENTED | UNVERIFIED | `jobs.rs`、`worker.rs`、`web/src/features/jobs/JobsPage.tsx` | pause/resume/cancel 状态面存在；取消竞态和反馈时间未执行。 |
| ACC-047 | IMPLEMENTED | UNVERIFIED | `jobs.rs`、`runtime.rs` | INTERRUPTED/重跑关联代码存在；杀进程重启恢复未执行。 |
| ACC-048 | IMPLEMENTED | UNVERIFIED | `scheduler/`、`jobs.rs` | misfire/overlap 调度代码和测试存在；持久化重启场景未执行。 |
| ACC-049 | IMPLEMENTED | UNVERIFIED | `scheduler/schedule.rs`、`scheduler/schedule/tests.rs` | DST/月末规则单测随当前 Rust 回归执行；时区修改、持久化重启及预览与实际触发的一致性未专项执行。 |
| ACC-050 | IMPLEMENTED | UNVERIFIED | `sampling.rs`、`volume.rs` | 容量采样与错误洞/分钟去重代码存在；扫描并行集成未执行。 |
| ACC-051 | IMPLEMENTED | UNVERIFIED | `report.rs`、`category.rs`、`metadata_import.rs` | 快照/版本字段存在；改分类后历史不变的真实闭环未执行。 |
| ACC-052 | IMPLEMENTED | UNVERIFIED | `report.rs`、`retention.rs`、`runtime.rs` | staging/publish 清理代码存在；各发布边界退出未执行。 |
| ACC-053 | IMPLEMENTED | UNVERIFIED | `report.rs`、`httpapi/handlers.rs` | compare 与范围/规则快照字段存在；不可比/离线报告场景未执行。 |
| ACC-054 | IMPLEMENTED | UNVERIFIED | `retention.rs`、`report.rs` | pin/明细保留/410 代码存在；空间耗尽和下载租约未执行。 |
| ACC-055 | IMPLEMENTED | UNVERIFIED | `export.rs`、`web/src/features/reports/ReportDetailPage.tsx` | CSV/HTML 转义代码存在；公式注入和脚本名称夹具未执行。 |
| ACC-056 | IMPLEMENTED | UNVERIFIED | `export.rs`、`httpapi/handlers.rs` | 流式下载/导出并发代码存在；慢客户端下载、断开和权限矩阵未执行。 |
| ACC-057 | IMPLEMENTED | UNVERIFIED | `notify.rs`、`httpapi/handlers.rs`、`worker.rs` | SMTP/outbox 与内部通知列表/事件消费者代码存在；真实 SMTP 成功/失败/超时及完整逐场景验收未执行。 |
| ACC-058 | IMPLEMENTED | UNVERIFIED | `backup.rs`、`httpapi/handlers.rs` | 配置导出/恢复代码存在；跨新实例恢复和秘密检查未执行。 |
| ACC-059 | IMPLEMENTED | UNVERIFIED | `backup.rs`、`fssecure/` | ZIP/恢复安全校验代码存在；恶意归档夹具当前未执行。 |
| ACC-060 | IMPLEMENTED | UNVERIFIED | `store/`、`retention.rs`、`backup.rs` | 有界写入/发布失败路径存在；ENOSPC/锁冲突回归未执行。 |
| ACC-061 | IMPLEMENTED | UNVERIFIED | `deploy/Dockerfile`、`deploy/compose.example.yaml`、`deploy/smoke.sh`、`web/tests/e2e/real-flow.spec.ts` | 当前 ARM64 镜像 `sha256:e8f104b1...` 的 Smoke/API/Chromium 主链路证据已更新；较早 amd64 QEMU 镜像 `sha256:a82f6115...` 的 Smoke 通过但真实 API/Chromium 在 `PUBLISH` 因 openat2 能力不可用而 fail-closed；本次当前树 amd64 重建被停止，QEMU 不替代原生 amd64，完整双架构/部署验收仍未完成。 |
| ACC-062 | PARTIAL | UNVERIFIED | `deploy/`、`README.md` | 通用 UID/GID/只读部署说明存在；真实绿联型号、UGOS、内核和权限测试未执行。 |
| ACC-063 | IMPLEMENTED | UNVERIFIED | `audit.rs`、`diagnostics.rs`、`backup.rs` | 脱敏诊断/审计代码存在；日志、HTML/ZIP 和设置 API 全量检视未执行。 |
| ACC-064 | IMPLEMENTED | UNVERIFIED | `source.rs`、`diagnostics.rs`、`httpapi/handlers.rs` | 身份/权限诊断面存在；user namespace、补充组和未知用户环境未执行。 |
| ACC-065 | IMPLEMENTED | UNVERIFIED | `source.rs`、`duplicates/`、`scanner/` | metadata_only/tiered/unknown 策略面存在；内容读取和平台适配测试未执行。 |
| ACC-066 | IMPLEMENTED | UNVERIFIED | `httpapi.rs`、`store/`、`config.rs` | 实例锁和配置存储代码存在；第二实例及网络文件系统阻断未执行。 |
| ACC-067 | IMPLEMENTED | UNVERIFIED | `export.rs`、`web/src/lib/format.test.ts`、`web/src/api/schema.d.ts` | 十进制字符串/BigInt 代码和相关单测存在；当前 Rust 全量回归已通过，但 API 超大整数往返和 SQL 溢出场景未专项执行。 |
| ACC-068 | IMPLEMENTED | UNVERIFIED | `source.rs`、`volume.rs`、`report.rs`、`web/src/features/profiles/ProfilesPage.tsx` | 列表/分页/未来源字段存在；Profile 数据源已按游标读取全部分页，`ProfilesPage.test.ts` 多页回归通过；10 卷、5000 路径和真实宿主目录场景未执行。 |
| ACC-069 | IMPLEMENTED | UNVERIFIED | `rust-toolchain.toml`、`Cargo.lock`、`web/pnpm-lock.yaml`、`docs/TEST_REPORT.md` | macOS arm64 `nas-analyzer` 263/263、`fssecure` 2+15，Linux Rust 1.98.1 容器 `nas-analyzer` 282/282、`fssecure` 2+16；fmt/check/clippy/release build 和前端 unit 46/46、typecheck/lint/build 均通过。未声明依赖变更/锁文件拒绝场景没有当前命令证据。 |
| ACC-070 | IMPLEMENTED | UNVERIFIED | `store/mod.rs`、`runtime.rs`、`worker.rs` | 专用线程/有界读池/RESOURCE_BUSY 代码存在；注入延迟与 live/API 并发测试未执行。 |
| ACC-071 | IMPLEMENTED | UNVERIFIED | `scanner/walk.rs`、`store/mod.rs`、`crates/nas-analyzer/benches/resource_budget.rs` | 有界 frontier/队列实现面存在；百万级、慢消费者和取消不死锁未执行。 |
| ACC-072 | IMPLEMENTED | UNVERIFIED | `scanner/`、`jobs.rs`、`worker.rs` | 合作取消代码存在；块读/事务/permit/慢 SQL 各边界未执行。 |
| ACC-073 | IMPLEMENTED | UNVERIFIED | `fssecure/`、`scanner/walk.rs`、`export.rs` | 原始字节、entry_id、溢出检查代码存在；Linux 非 UTF-8 和 release 回归未执行。 |
| ACC-074 | IMPLEMENTED | UNVERIFIED | `web/src/lib/querySpec.ts`、`web/src/lib/useECharts.ts`、`web/tests/e2e/real-flow.spec.ts` | 当前源码 ARM64 Docker/Chromium 主链路 E2E 1/1 通过；StrictMode 重复触发、SSE 重连和各视图卸载边界仍未专项验收，amd64 QEMU 运行在 openat2 能力门控处 fail-closed。 |
| ACC-075 | IMPLEMENTED | UNVERIFIED | `export.rs`、`httpapi/handlers.rs` | 流式导出和并发槽代码存在；慢客户端下载/断开/并发浏览未执行。 |
| ACC-076 | IMPLEMENTED | UNVERIFIED | `runtime.rs`、`crates/nas-analyzer/benches/resource_budget.rs` | API/worker 预算处置代码和 benchmark 入口存在；持续超预算与恢复重试未执行。 |
| ACC-077 | IMPLEMENTED | UNVERIFIED | `deploy/Dockerfile`、`deploy/smoke.sh`、`web/tests/e2e/real-flow.spec.ts` | 当前 ARM64 镜像 `sha256:e8f104b1...` 的 Smoke/API/Chromium 主链路证据已更新；较早 amd64 QEMU 镜像 `sha256:a82f6115...` 的 Smoke 通过但真实 API/Chromium E2E 因 openat2 能力不可用按设计 fail-closed，本次当前树 amd64 重建已中断。仍缺原生 amd64 runner，以及 SQLite/证书/时区/hash/fssecure 的完整双架构运行断言。 |
| ACC-078 | IMPLEMENTED | UNVERIFIED | `config.rs`、`config/tests.rs`、`docs/design/contracts/deployment.schema.json` | v2/旧字段校验代码和历史单测存在；修改后完整 config/schema 回归未执行。 |

## 不能宣称通过的缺口

- **当前未执行**：10 万/100 万条目完整 benchmark/规模验证，以及 ACC-001–ACC-068 的逐场景集成证据；当前 macOS `fssecure` 对抗测试 15/15、Linux adversarial 16/16 通过，但不能替代各业务、平台和清理链路验收。
- **平台/环境证据缺失**：真实绿联/UGOS、原生配额/Tiering、真实 SMTP、崩溃恢复/ENOSPC、10 万/100 万条目规模测试；这些不能由 Docker 或 unit test 代替。
- **已实现但未专项验收**：compare/export 创建任务已读取、校验并持久化 `Idempotency-Key`；ACC-035/045 仍为 `IMPLEMENTED/UNVERIFIED`，因为重复提交、参数冲突和手动/定时碰撞场景尚未执行。
- **真实 E2E**：当前 arm64 Docker Linux 真实流程 1/1 通过并下载 CSV、验证重复导出幂等；当前 amd64 QEMU Docker E2E 在报告发布的 openat2 能力门控处失败，且 QEMU 不替代原生 amd64 runner。历史 macOS host 导出因 openat2 fail-closed 的结果也不能与当前树合并宣称通过。
- **契约校验**：OpenAPI bundle 和生成类型通过，`redocly lint` exit 0 但保留 4 个 warning；不能把 bundle/typecheck 当成无条件的完整 OpenAPI PASS。

本轮此前由子代理修改了 `docs/ACCEPTANCE_RESULTS.md` 与 `docs/REQUIREMENTS_TRACEABILITY.md`；主任务已另行更新 `docs/IMPLEMENTATION_STATUS.md` 与 `docs/TEST_REPORT.md`，并在本节修正已过时的 compare/export 幂等描述。
