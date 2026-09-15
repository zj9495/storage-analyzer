# TEST_REPORT

## 2026-09-14 F03 内部通知分页回归（最新）

- `cargo test -p nas-analyzer notify::tests --locked`：11/11 通过；包含同一时间戳下固定 ID `notification-c/b/a` 的两页 keyset 分页回归，确认游标取最后返回行且第二页返回 `notification-a`。
- `cargo test -p nas-analyzer httpapi::handlers::internal_notification_query_tests --locked`：1/1 通过，覆盖内部通知列表游标签名和列表绑定。
- `cargo test -p nas-analyzer worker::tests --locked`：5/5 通过；`cargo test -p nas-analyzer --locked`：308/308 通过；`cargo test --workspace --locked`：`nas-analyzer` 308/308、`fssecure` 单元 2/2、adversarial 15/15 通过。
- `pnpm --dir web exec vitest run src/features/settings/SettingsPage.test.ts`：11/11 通过；`pnpm --dir web run typecheck`、`bash api/gen-ts.sh`、`cargo check --workspace --all-targets --locked`、`cargo fmt --all -- --check`、`cargo clippy -p nas-analyzer --all-targets --locked -- -D warnings`、`git diff --check` 均通过。
- 本轮只证明 F03 内部通知源码、分页回归、消费者编译质量和设置页契约测试；真实 SMTP、真实 NAS/UGOS、浏览器实机链路以及全量 ACC 验收仍未验证。

## 2026-09-14 F01 日容量汇总聚焦回归（最新）

- `cargo test -p nas-analyzer sampling --locked`：10/10 通过，覆盖四项容量指标的日聚合、min/max/last、分页读取、保留压缩历史、错误采样和不完整 `ok` 采样拒绝。
- `cargo test -p nas-analyzer httpapi::handlers::volume_sample_query_tests --locked`：2/2 通过，覆盖日容量 JSON 的 `total/free/available/used` last/min/max 字段以及原始采样分页边界。
- `cargo fmt --all`、`cargo check --workspace --all-targets --locked`、`git diff --check`：通过。
- 本次证据只覆盖 F01 日容量汇总实现；未将完整 F01、M0–M8 或 ACC-001–ACC-078 标记为完成。真实 NAS/UGOS 与真实 SMTP 仍按用户要求保留为手动验证项。

## 2026-09-14 F03 迁移进展（历史记录；后续已完成）

- 新增内部通知迁移后，`cargo fmt --all`、`cargo check --workspace --all-targets --locked`、`git diff --check` 均通过。
- 初始记录只证明迁移可编译；后续 F03 功能和自动化证据见文档顶部最新记录。

## 2026-09-14 当前 F01 回归与 F03 状态（历史记录）

- F01 聚焦测试 8/8、Rust `nas-analyzer` 全量测试 301/301、React typecheck 和 unit 49/49 已通过。
- F03 旧记录未产生代码或测试结果；后续内部通知列表实现与测试见文档顶部最新记录。

## 2026-09-14 F01 日汇总接入复核（非通过结果）

- 子代理复核确认新增日汇总迁移尚无生产消费者；本次未运行 F01 专项测试，也未产生新的测试通过证据。
- 既有 Rust check/test 结果保持有效，但不能覆盖尚未接入的 total/free/available 日趋势字段。

## 2026-09-14 F01/F06 实现进展

- 当前源码 `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked` 和 `git diff --check` 均通过。
- F01 的容量采样与 `/volumes` 最新采样接线已编译通过；F06 的报告目录页面现有测试 2/2、TypeScript typecheck 通过。
- 本条没有新增完整 F01/F06 验收结论；日趋势字段、独立行为测试及其余功能矩阵仍待完成。

## 2026-09-14 用户停止确认（最新；非测试结果）

- 用户要求立即停止所有任务；Goal 当前为 `PAUSED`，未完成。
- 已关闭本次可见的 3 个子代理，并确认其后续查询均为 `not_found`；未再启动任何测试、构建、服务或浏览器任务。
- 本次只更新文档，没有新增测试结果，也没有改变既有测试结果或验收状态。既有工作树改动保留，未执行 reset、stash、回滚、删除或 push。
- ACC-001–ACC-078 继续逐项 `UNVERIFIED`；F01/F03/F06/F07/F10/F14/F18 的实现差距继续按 `PARTIAL` 或待规格决策记录。完整 M0–M8 交付不能宣称完成。
- 待执行验证包括：完成差距实现后的 Rust/React/OpenAPI 回归、当前源码 Docker 重建与 Smoke/真实 API/浏览器 E2E；原生 amd64 runner、真实 NAS/UGOS、真实 SMTP、ENOSPC/崩溃恢复、恶意归档、Btrfs/reflink/qgroup、10 万/100 万规模与 RSS、原生配额/Tiering，以及 ACC-001–ACC-078 逐项验收。

## 2026-09-14 当前树 ARM64 Docker/真实链路复验（最新）

- 环境：macOS arm64 主机、Docker `colima` builder；当前 checkout `/Users/zj9495/code/nas-storage-analyzer`，既有 staged/unstaged/untracked 改动保留，未执行破坏性 Git 操作。
- `NAS_DEV_IMAGE=docker.m.daocloud.io/library/rust:1.98.1-bookworm bash scripts/linux-cargo.sh test --workspace --locked`：exit 0；`nas-analyzer` 321/321、`fssecure` lib 2/2 与 adversarial 16/16，共 339 个测试通过。此前误用 `+1.98.1` 作为脚本参数的命令 exit 101，未计入结果；随后按脚本实际用法成功重跑。
- 当前源码 `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked` 相关回归均为 exit 0；本轮 Linux 全量结果以本节固定容器命令为准。
- 当前 ARM64 镜像构建命令 `docker buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-goal-20260914-final --load --progress=plain .`：exit 0；`docker image inspect` 为 `linux/arm64`，digest `sha256:e8f104b182bea17e6b1db6f924b147102db26df24d5d415df56875cb78ce34f8`。
- `SMOKE_PORT=28400 bash deploy/smoke.sh nas-storage-analyzer:local-goal-20260914-final`：exit 0；`REAL_API_DOCKER_IMAGE=nas-storage-analyzer:local-goal-20260914-final REAL_API_PORT=28401 bash scripts/real-api-flow.sh`：exit 0；`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-goal-20260914-final E2E_DOCKER_HOST_PORT=28402 bash web/tests/e2e/run-real-e2e.sh`：exit 0，Chromium 1/1 通过。浏览器调用已获用户授权，三项均使用隔离临时数据；成功后临时运行根目录已清理。
- Smoke 覆盖非 root、只读根/源、cap drop、健康检查、setup gate、SIGTERM 和 SQLite 重启；API flow 覆盖双源扫描、metadata/quota、SHA-256 重复/硬链接、分类历史、compare、幂等导出、备份/恢复、cleanup preview 和只读写保护；E2E 覆盖初始化、认证重登、数据源、报告、CSV 下载和导出幂等。
- 当前 amd64 Dockerfile 重建已按用户停止指令中断：命令 exit 130，停在 Rust 依赖编译阶段，未生成新的 amd64 镜像，不计为构建或双架构交付通过。子代理静态审计确认 F01、F03、F06、F07、F10、F14、F18 存在明确实现缺口或未定语义；它们不能仅标为“未验证”，详见 `IMPLEMENTATION_STATUS.md` 与 `REQUIREMENTS_TRACEABILITY.md` 的暂停点记录。
- 真实 NAS/UGOS、原生 amd64、真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink/qgroup、10 万/100 万规模与 RSS、原生配额/Tiering 和 ACC-001–ACC-078 逐项业务验收继续为 `UNVERIFIED`；完整 F01–F19 不能宣称完成。实现阶段保持 `IN_PROGRESS`，当前 Goal 执行已暂停。

## 2026-09-14 停止执行后的审计记录

- 用户要求立即停止所有任务；已停止 amd64 QEMU 构建和子代理继续审计，未再启动命令、服务或浏览器任务。
- 明确实现缺口：容量报告完成采样/容量趋势字段和总览展示（F01）、内部通知列表与事件消费者（F03）、目录钻取完整 UI/API 消费（F06）、owners 身份/配额快照（F07）、统一排行筛选（F10）。规格边界待确认或未实现：F14 完整数据备份范围、F18 `io_priority` OS/I/O 语义。
- 以上差距已从“仅未验证”中分离；没有对这些项进行未经授权的猜测性代码修改。后续必须先完成实现/规格决策，再重跑受影响的测试和 Docker 交付验证。

## 2026-09-14 最终 Rust 与静态检查收尾（历史质量记录；最新差距见上方）

- macOS：`cargo test -p nas-analyzer --locked` 为 301/301，exit 0。
- Linux：`NAS_DEV_IMAGE=docker.m.daocloud.io/library/rust:1.98.1-bookworm scripts/linux-cargo.sh test -p nas-analyzer --locked` 为 321/321，exit 0。
- `cargo clippy -p nas-analyzer --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 均 exit 0。
- 本轮未调用浏览器；未新增 Docker、真实 NAS/UGOS、真实 SMTP、故障注入、Btrfs/reflink/qgroup 或规模/RSS 证据，相关验收继续为 `UNVERIFIED`。后续静态审计已确认 F01/F03/F06/F07/F10/F14/F18 还有明确实现缺口或未定语义，不能仅以质量命令覆盖。

## 2026-09-14 清理身份与调度队列修复回归（本轮）

- 环境：macOS arm64；当前 checkout `/Users/zj9495/code/nas-storage-analyzer`，既有 staged/unstaged/untracked 改动保留，未执行 reset、stash、回滚、删除或 push。
- `cargo fmt --all -- --check`：exit 0；`git diff --check`：exit 0。
- `cargo test -p nas-analyzer cleanup::tests --locked`：25/25，exit 0；`cargo test -p nas-analyzer runtime::tests --locked`：9/9，exit 0；`cargo test -p nas-analyzer --locked`：301/301，exit 0。
- 新增覆盖：`cleanup::tests::runtime_cleanup_rejects_a_source_with_changed_filesystem_identity`、`runtime::tests::scheduler_respects_configured_scan_queue_limit` 均通过。未运行浏览器、Docker、真实 NAS/SMTP、故障注入或规模/RSS 验收，相关状态保持 `UNVERIFIED`。

## 2026-09-14 当前树交付收尾回归（本轮）

- 环境：macOS arm64 主机；Linux 验证使用 Rust 1.98.1 容器；当前 checkout `/Users/zj9495/code/nas-storage-analyzer` 保留既有 staged/unstaged/untracked 改动，未执行破坏性 Git 操作。
- 当前 macOS Rust workspace 回归已通过：`nas-analyzer` 299 个测试、`fssecure` 2 个单元 + 15 个对抗测试；fmt/check/clippy、debug/release test 和 release build 均通过。Linux Rust 1.98.1 容器 workspace 回归已通过：总计 337 个测试（`nas-analyzer` 319、`fssecure` 2 个单元 + 16 个对抗测试）。
- 当前前端回归已通过：`pnpm --dir web install --frozen-lockfile`、typecheck、unit 49/49、build；lint 为 0 errors/5 warnings。`./api/gen-ts.sh`、OpenAPI bundle、Redocly lint（保留 4 个 warning）、`make verify-delivery`、Compose config、设计包 manifest 校验和依赖审计均已通过。
- `make bench` 已实际运行：30,000 行，约 60 ms、493247 rows/s；RSS 为 `None`，不构成 10 万/100 万规模或 RSS 验收证据。
- 当前正式 ARM64 镜像已核实：`nas-storage-analyzer:local-goal-20260914`，`linux/arm64`，digest `sha256:d74cab6b1fe5f50049deb27770da7fb5eb660cf9fc83509ca78d0a35a72f259b`。ARM64 Smoke（端口 28314）、真实 API flow（端口 28315）和 Docker Chromium E2E（端口 28316，1 passed）已通过。macOS host flow（端口 28317）因缺少 `openat2` 写能力按设计 fail-closed，exit 非 0，不是产品链路 PASS。
- amd64 当前树 QEMU 构建最终 exit 0：镜像 `nas-storage-analyzer:local-goal-20260914-amd64-retry`，`docker image inspect` 为 `linux/amd64`、digest `sha256:a82f61150108da1509de1fd5f83dad812f6cce16de6002d044c08e576695900e`；Rust release 阶段约耗时 56 分钟。第一次当前树尝试在 `ring v0.17.14`/`p256.c` 阶段出现 GCC `cc1` segmentation fault、exit 1，不能被抹掉；重试最终成功。
- `SMOKE_PORT=28318 bash deploy/smoke.sh nas-storage-analyzer:local-goal-20260914-amd64-retry`：exit 0，amd64 QEMU Smoke 通过。`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-goal-20260914-amd64-retry E2E_DOCKER_HOST_PORT=28319 bash web/tests/e2e/run-real-e2e.sh`：exit 1；Chromium 已实际启动，任务最终状态为 `FAILED`。随后 `REAL_API_DOCKER_IMAGE=nas-storage-analyzer:local-goal-20260914-amd64-retry REAL_API_PORT=28320 bash scripts/real-api-flow.sh`：exit 1；首个扫描任务响应为 `state=FAILED`、`phase=PUBLISH`、`error.code=UNSUPPORTED_CAPABILITY`，消息为“报告 artifact 写入需要 openat2 安全解析能力”。该失败是安全能力门控的 fail-closed 结果，不是产品 E2E PASS。
- 日志位置：本轮命令 stdout 位于当前任务执行记录；失败 E2E 临时目录为 `.nas-storage-analyzer-e2e.hNnhQn`，API flow 证据目录为 `.nas-storage-analyzer-real-api.SA0zFd`，其中只保留测试配置、测试源文件、响应和启动日志，未输出 token、cookie 或秘密。真实 API、Smoke 和成功的 E2E 使用隔离临时数据；真实 NAS/UGOS、原生 amd64 runner、SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃恢复、规模/RSS 等仍未执行。

## 2026-09-14 Profile/runtime 只读复核（本轮）

以下命令均在当前 checkout 执行，未修改源文件：

- `cargo test -p nas-analyzer --locked profile::tests`：5/5，exit 0。
- `cargo test -p nas-analyzer --locked scheduler::schedule::tests`：15/15，exit 0。
- `cargo test -p nas-analyzer --locked cli::tests`：4/4，exit 0。
- `cargo test -p nas-analyzer --locked runtime::tests`：7/7，exit 0；另执行 `runtime::tests::scheduler_persists_profile_creation_scoped_source_snapshot`：1/1，exit 0。
- `cargo test -p nas-analyzer --locked worker::tests`：5/5，exit 0。
- `cargo test -p nas-analyzer --locked scanner::tests`：3/3，exit 0。
- `cargo test -p nas-analyzer --locked report::tests`：6/6，exit 0。

本轮没有调用浏览器、没有执行 Docker/真实 NAS/SMTP/故障注入或规模验收；这些状态保持原记录。

## 2026-09-14 all_metadata / owner_list_snapshot 聚焦回归

- 环境：macOS arm64；共享工作树 `/Users/zj9495/code/nas-storage-analyzer` 保留既有 staged/unstaged/untracked 改动，未 reset、stash、回滚或删除无关文件。
- `cargo test -p nas-analyzer report::tests::publication_contains_folder_and_owner_category_snapshots --locked`：exit 0，1/1 通过；验证发布摘要中的全量 owner 聚合与 `owner_list_snapshot` 选定 UID 隔离，并验证发布明细 artifact 保留 symlink 的 `entry_kind`、UID、mode 与空 size 元数据。
- `cargo test -p nas-analyzer scanner::tests::all_metadata_indexes_special_entry_metadata_without_reading_content --locked`：exit 0，1/1 通过；验证 `all_metadata` 扫描索引 symlink 元数据且不跟随为普通文件。
- `cargo test -p nas-analyzer report::tests --locked`：exit 0，6/6 通过；`cargo test -p nas-analyzer scanner::tests --locked`：exit 0，3/3 通过。
- 早于上述成功回归的一次 `cargo test -p nas-analyzer report_query_tests --locked` 在共享工作树并发修改 `runtime.rs` 尚未完成时被 E0373 编译错误阻断；未将该次失败计为测试通过。并发任务随后修复其闭包所有权错误，主任务在修复后的源码上完成了上述聚焦测试。
- `cargo fmt --all -- --check`：exit 0；`pnpm --dir web typecheck`：exit 0。OpenAPI/React 本轮未增加 `owner_list_snapshot` 公开字段或查询，因此未把未定义消费写成已实现。
- 日志位置：上述命令 stdout 位于当前任务执行记录；测试仅使用临时目录，未输出凭据、token 或秘密。

## 2026-09-14 Goal 接管与缺口审计（进行中，非测试结果）

- 环境：macOS arm64；checkout `/Users/zj9495/code/nas-storage-analyzer`；工作树含既有 staged/unstaged/untracked 改动，未执行破坏性 Git 操作。
- 已执行只读核对：`git status --short --branch`、`rg` 定位 Profile/调度/扫描/资源字段、`sed`/`nl` 阅读 `CODEX_GOAL.md`、设计约束、当前 Profile/worker/scanner/React/OpenAPI 代码，以及 Goal/子任务状态读取；上述命令均 exit 0。该组命令不构成产品测试通过证据。
- 审计结论：Profile 的 Daily/Weekly/Monthly、未来登记源、文件类型策略、指定 UID 附加分组和 `metadata_workers`/`hash_workers`/`read_limit_mib_s` 已完成并通过本轮聚焦回归；`io_priority` 仍没有明确运行时语义。现有历史测试/镜像记录不覆盖本轮核对，因此本轮新增命令结果单独记录在文档顶部。
- 子任务正在共享工作树实施 Profile 语义；本节没有把子任务摘要当作测试结果，也没有在尚未运行的命令上记为通过。日志位置：本轮命令 stdout 位于当前任务执行记录；未输出 token、cookie 或秘密。

## 2026-09-13 23:20 当前源码 Linux 回归与真实 API 流（最新）

- 环境：macOS arm64 主机；Linux 验证使用 `docker.m.daocloud.io/library/rust:1.98.1-bookworm`，当前 checkout `/Users/zj9495/code/nas-storage-analyzer`，既有 dirty/staged 工作树保持不变。
- Linux 全量命令 `NAS_DEV_IMAGE=docker.m.daocloud.io/library/rust:1.98.1-bookworm scripts/linux-cargo.sh test --workspace --locked` 在最终源码 hash `f765a86…` 上 exit 0，汇总为 `311 passed / 0 failed / 0 ignored`：`fssecure` 2 个 lib + 16 个 adversarial、`nas-analyzer` 293，main/doc-test 0。此前同命令有一次在 `Doc-tests fssecure` 前因 rustup 下载 clippy 停滞；该次没有被记作 PASS，随后成功重跑才作为本条证据。
- Linux 定向命令均实际 exit 0且在上述最终 hash 上复跑：`... test -p fssecure --test adversarial` 为 `16/16`；`... test -p nas-analyzer cleanup` 为 `47 passed / 0 failed`；`... jobs` 为 `19 passed / 0 failed`；`... duplicates` 为 `10 passed / 0 failed`；`... report` 为 `25 passed / 0 failed`。每条命令前后源码 hash 未变。
- 当前源码 Linux release 编译：在隔离 Docker volume 中执行 `cargo +1.98.1 build --release --locked -p nas-analyzer`，exit 0；未把宿主机二进制或旧镜像作为替代。二进制随后被放入仅用于验证的 ARM64 临时镜像 `nas-storage-analyzer:real-api-current`，镜像 digest `sha256:01dfcb697501220ae2097c6297173ac72ba586d4f4725527d272fb8b95a64e3f`。
- 真实 HTTP 流：`REAL_API_DOCKER_IMAGE=nas-storage-analyzer:real-api-current bash scripts/real-api-flow.sh` exit 0。覆盖双源扫描/黄金结果、metadata/quota preview/apply、SHA-256 重复组与硬链接、分类历史、compare、导出幂等下载、备份/恢复、cleanup preview 和只读写保护；成功后临时运行根目录清理。它不是正式 `deploy/Dockerfile` 重建，也不是浏览器 E2E。
- 最新 Linux 全量命令最终 exit 0，汇总为 `311 passed / 0 failed / 0 ignored`（`fssecure` 2 + 16、`nas-analyzer` 293、main/doc-test 0）；此前一次 rustup 在 doc-test 前的停滞已由同一最终源码 hash 的成功重跑取代。
- 正式当前源码 ARM64 Dockerfile 重建：`docker buildx build --builder colima --network=host --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-goal-20260913-2255 --load --progress=plain .` 在 `Updating crates.io index` 无进展后人工取消，exit 130，未生成目标镜像；因此不对该 tag 运行 Smoke/E2E，也不继承旧镜像结果。
- 旧 19:01 ARM64 镜像的 build/Smoke/Chromium E2E 结果已改标为历史快照；它们不能覆盖本次源码变更。`git diff --check` 仍为 0；既有 `git diff --cached --check`/`git diff HEAD --check` 的 EOF/尾随空格问题未被本轮覆盖。
- 本轮不提升任何完整 ACC 状态：F01–F19 仍为 `IMPLEMENTED / UNVERIFIED`，ACC-001–ACC-078 仍逐项 `UNVERIFIED`。正式 Dockerfile build、Linux 全量最终 exit、原生 amd64、NAS/UGOS、SMTP、Btrfs/reflink/qgroup、故障注入、规模/RSS 和完整逐项业务验收仍是未闭合项。

## 2026-09-13 19:01 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；后续源码变更和验证见上方）

- 环境：macOS arm64 主机，Docker `colima` builder；当前 checkout `/Users/zj9495/code/nas-storage-analyzer`，既有 dirty/staged 工作树保持不变。
- Dockerfile 构建修正：`deploy/Dockerfile` 显式设置 `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse`，仅解决固定 Rust 基础镜像首次依赖解析停滞；未改变 `Cargo.lock`、基础镜像 digest、运行时用户或安全约束。
- ARM64 构建：`docker buildx build --builder colima --network=host --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-current-20260913-1845 --load --progress=plain .` exit 0；镜像 `sha256:0e3db311a550d66e3e153006b601758268bcb858845e003a6912e77454ad6c6c`，架构 `arm64/linux`，创建时间 `2026-09-13T19:01:05.309335896+08:00`。
- Smoke：`SMOKE_PORT=28220 bash deploy/smoke.sh nas-storage-analyzer:local-current-20260913-1845` exit 0；通过 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化检查。
- Docker-backed Chromium E2E：`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-current-20260913-1845 E2E_DOCKER_HOST_PORT=28222 bash web/tests/e2e/run-real-e2e.sh` exit 0；Playwright 1 passed，耗时约 8.0 秒，临时运行根目录已清理。流程覆盖初始化、登录/退出/重新登录、数据源登记、报告任务、报告查看、CSV 下载及同一 `Idempotency-Key` 的重复导出请求；后端 E2E 容器包含 Compose 等价的 read-only、cap-drop、no-new-privileges、tmpfs、资源限制和显式 non-root 约束。
- 当前源码质量门：fmt、workspace check、clippy、debug/release workspace tests 和 release build 均 exit 0；macOS `nas-analyzer` 265/265、`fssecure` 2+15。Linux 固定 Rust 1.98.1 容器 fssecure adversarial 16/16。前端 frozen install、typecheck、lint、unit 46/46、build 均 exit 0；lint 为 0 errors/3 warnings，构建保留大 chunk warning。
- 契约/交付：`./api/gen-ts.sh`、Redocly lint、Redocly bundle、`make compose-config`、`make verify-delivery` 和 `git diff --check` 均 exit 0；Redocly 保留 4 个 warning。`make bench` exit 0，`export_rows=30000 elapsed_ms=69 rows_per_sec=432993 api_rss_bytes=None worker_rss_bytes=None`，仅为小基准。
- `git diff --cached --check` 与 `git diff HEAD --check` exit 2，原因是既有 staged 内容：`CODEX_GOAL.md:147`、`crates/nas-analyzer/src/source/tests.rs:378`、三个迁移文件 EOF/尾随空格；未修改这些用户 staged 内容。
- 当前 ARM64 Docker/E2E 是局部主链路和交付安全证据，不等同完整 F01–F19/ACC-001–ACC-078 验收。amd64 QEMU、真实 NAS/UGOS、SMTP、Btrfs/reflink/qgroup、故障注入、规模/RSS、原生配额/Tiering 和完整逐项验收仍未验证；Goal 保持 `IN_PROGRESS`。

## 2026-09-13 当前源码 ARM64 Docker/真实 E2E 复验（历史快照；镜像早于当前 Dockerfile/E2E 复验）

- 环境：macOS arm64 主机，Docker `colima` builder；当前 checkout `/Users/zj9495/code/nas-storage-analyzer`，既有 dirty/staged 工作树保持不变。
- ARM64 构建：`docker buildx build --builder colima --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-aggregate-20260913 --load --progress=plain .` exit 0；镜像 `sha256:0f42333ad0e866b5923d9af506a1d719e7ecd168f3038f99f670ecade9e3fc30`，架构 `arm64/linux`。
- Smoke：`SMOKE_PORT=28210 bash deploy/smoke.sh nas-storage-analyzer:local-aggregate-20260913` exit 0；通过 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化检查。
- Docker-backed Chromium E2E：`E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-aggregate-20260913 E2E_DOCKER_HOST_PORT=28211 bash web/tests/e2e/run-real-e2e.sh` exit 0；Playwright `1 passed`，总耗时 10.3 秒，临时运行根目录已清理。流程实际覆盖初始化、认证重登、数据源登记、报告任务、报告查看、CSV 下载及同一 `Idempotency-Key` 的重复导出请求。
- 这次 E2E 使用当前聚合修复源码构建的 ARM64 镜像；它是局部主链路证据，不等同完整 F01–F19/ACC-001–ACC-078 验收。此前 amd64 QEMU E2E 在 `PUBLISH` 因 `openat2` 能力不可用而 `UNSUPPORTED_CAPABILITY`，该 fail-closed 结果保留，QEMU 不替代原生 amd64。
- 浏览器调用已获用户授权；本轮没有修改安全门槛、E2E 断言或使用 fallback。Goal 继续为 `IN_PROGRESS`。

## 2026-09-13 聚合修复后当前测试记录（历史快照；以顶部 Docker/E2E 记录为准）

- 环境：当前 checkout `/Users/zj9495/code/nas-storage-analyzer`；本次只更新 `docs/IMPLEMENTATION_STATUS.md` 和 `docs/TEST_REPORT.md`，未修改源码、测试、OpenAPI、部署文件或其他文档；既有 dirty/staged 工作树保持不变，未执行 reset、stash、回滚、删除或 push。
- 聚合修复：`index_aggregates.rs` 目录处理改为 `dfs_right` 升序并使用 keyset `>`，先处理子目录再处理父目录。
- 真实临时 fixture 黄金链路测试 `scanner::tests::golden_fixture_scans_aggregates_and_confirms_duplicates` 通过：8 个文件、4 个目录、50 字节逻辑总量、44 字节去重后逻辑总量、7 个物理对象、1 个重复组，硬链接别名正确。
- macOS arm64 当前 Rust 回归：`nas-analyzer` 263/263；`fssecure` 2 个单元测试 + 15 个对抗测试。Linux Rust 1.98.1 容器 workspace 回归：`nas-analyzer` 282/282；`fssecure` 2 个单元测试 + 16 个对抗测试。
- 前端当前回归：unit 46/46，typecheck、lint、build 均通过；lint 的既有 Fast Refresh warning 和构建大 chunk warning 均保留。
- 本次实际执行并复核：`make verify-delivery` exit 0，输出 `DELIVERY CONTRACT PASS`（过程中 `config-check`、前端 typecheck/build 均成功）；`make compose-config` exit 0，Compose 配置成功渲染；`git diff --check` exit 0，无输出。
- 当前 ARM64 Docker 重建尝试：`docker buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local-aggregate-20260913 --load .` 在 `Updating crates.io index` 无进展后人工取消，exit 130；未生成该 tag 的当前源码镜像。旧 `sha256:c93d492b...` digest 属于聚合修复前镜像，不能作为当前源码测试、Smoke 或 E2E 证据。
- 本轮未调用浏览器。聚合修复后的 ARM64 Docker Smoke/E2E、原生 amd64、NAS/UGOS、真实 SMTP、故障注入、10 万/100 万规模与 RSS，以及完整逐项 ACC-001–ACC-078 仍没有新的通过证据；保持 `IMPLEMENTED`、`VERIFIED`、`UNVERIFIED` 分离，Goal 仍为 `IN_PROGRESS`。

## 2026-09-13 进度文档一致性审计（历史快照；当前记录见上方）

- 本次只核对并修正文档快照的状态标注与历史计数，未修改 Rust、React、OpenAPI、测试、部署脚本或配置；当前 checkout `/Users/zj9495/code/nas-storage-analyzer` 的既有 dirty/staged 工作树保持不变。
- 已复核 `CODEX_GOAL.md`、`docs/design/AGENTS.md` 以及四份进度/验收文档；子代理只读审计发现的旧计数和“当前”措辞矛盾已明确改为历史快照，历史测试证据没有删除。
- 设计包清单校验首次在仓库根执行 `sha256sum -c docs/design/MANIFEST.sha256`：exit 1，原因是清单条目相对 `docs/design`，不是代码或设计文件内容失败；改在 `docs/design` 执行 `sha256sum -c MANIFEST.sha256`：exit 0，所有条目 OK。`make compose-config`、`make verify-delivery`、`git diff --check` 均 exit 0；本轮未重跑 Rust/React 测试。当前有效测试证据和未验证边界以本文件顶部聚合修复后记录为准。

## 2026-09-13 当前源码回归（历史快照；聚合修复后计数见上方）

- 环境：当前 checkout `/Users/zj9495/code/nas-storage-analyzer`；本次仅同步文档，未修改源码或测试，既有 dirty/staged 工作树保持不变。
- Rust 当时回归：macOS arm64 fmt/check/clippy、debug/release workspace test 和 release build 均 exit 0，`nas-analyzer` 262/262、`fssecure` 2 个单元测试 + 15 个对抗测试；Linux 固定 Rust 1.98.1 容器 workspace test exit 0，`nas-analyzer` 281/281、`fssecure` 2 个单元测试 + 16 个对抗测试，单独 adversarial 亦为 16/16。
- 前端当时 typecheck、lint、build、unit 回归均 exit 0，unit 46/46；lint 保留 3 个既有 Fast Refresh warning，build 保留大 chunk warning。
- `preview_metadata_import` 已修复为返回计算得到的 `diff_summary`，对应 `metadata_import.rs`/`httpapi/handlers.rs` 回归测试通过；Profile 数据源读取已修复为按分页游标读取全部数据源，对应 `ProfilesPage.test.ts` 多页游标回归测试通过。
- `./api/gen-ts.sh`、Redocly lint/bundle、`make compose-config`、`make verify-delivery` 和 `make bench` 也已在当前源码执行成功；benchmark 为 30,000 行、78 ms、381,421 rows/s，RSS 为 `None`。这些是当前源码自动化回归证据，不改变 F01–F19 的 `IMPLEMENTED / UNVERIFIED` 以及 ACC-001–ACC-078 的逐项 `UNVERIFIED` 状态。

## 2026-09-13 当前源码 arm64 Docker/E2E 复验（历史快照；镜像早于聚合修复）

- 当时 ARM64 镜像 `nas-storage-analyzer:local-arm64-current-20260913` 的 digest 为 `sha256:c93d492b5137faf3e966f825e81a0c99fb087919dfce1b34941b8864b8839178`，架构为 `arm64/linux`；该镜像早于目录聚合修复。
- 该旧镜像的 Smoke 与 Docker-backed Chromium E2E 曾 exit 0，覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载和导出幂等；结果仅是聚合修复前镜像的局部证据。
- 由于当前源码 ARM64 重建在 crates.io index 阶段被取消，以上旧镜像结果不能写作当前源码证据；聚合修复后的 Smoke/E2E 尚未执行。

## 2026-09-13 当前源码 arm64 Docker/E2E 与交付回归（历史快照；回归计数见上方）

- 环境：macOS arm64 主机；实际 checkout `/Users/zj9495/code/nas-storage-analyzer`，保留既有 dirty/staged 工作树。
- ARM64 构建命令 `docker buildx build --platform linux/arm64 --build-arg BASE_REGISTRY=docker.m.daocloud.io/library -f deploy/Dockerfile -t nas-storage-analyzer:local --load .`：exit 0。
- 当前源码 ARM64 Docker 构建实际完成；`docker image inspect --format '{{.Id}} {{.Architecture}}/{{.Os}} {{.Created}}' nas-storage-analyzer:local` 输出 `sha256:4ff090449edb08ca666ad54704a51ab35ee87cd20076ec9d4833f7a7a437eb3b arm64/linux 2026-09-13T12:34:40.342583539+08:00`。
- `SMOKE_PORT=28190 bash deploy/smoke.sh nas-storage-analyzer:local`：exit 0；通过 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local E2E_DOCKER_HOST_PORT=28191 bash web/tests/e2e/run-real-e2e.sh`：exit 0；Docker-backed Chromium 1/1 通过，覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载及同一 `Idempotency-Key` 的导出幂等验证。
- `make bench`：exit 0；`resource_budget export_rows=30000 elapsed_ms=64 rows_per_sec=463953 api_rss_bytes=None worker_rss_bytes=None`。该结果是 30,000 行导出小基准，不构成 10 万/100 万条目或 RSS 验收。
- `make compose-config`：exit 0；`make verify-delivery`：exit 0，输出 `DELIVERY CONTRACT PASS`。
- `./api/gen-ts.sh`：exit 0；`pnpm --package=@redocly/cli@1.34.0 dlx redocly lint api/openapi.yaml --max-problems 200`：exit 0，保留 4 个 warning；`pnpm --package=@redocly/cli@1.34.0 dlx redocly bundle api/openapi.yaml --output /tmp/nas-storage-analyzer-openapi-current.yaml`：exit 0；`pnpm --dir web run typecheck`、`pnpm --dir web run lint`、`pnpm --dir web run build`、`pnpm --dir web run test:unit`：均 exit 0，前端 unit 46/46，lint 保留 3 个 Fast Refresh warning，build 保留大 chunk warning。
- 本次 Docker/浏览器证据只覆盖当前 ARM64 镜像的交付安全边界和局部主链路；amd64 QEMU Docker E2E 仍因容器缺少 `openat2` 能力而 fail-closed，原生 amd64、NAS/UGOS、真实 SMTP、Btrfs/reflink/qgroup、ENOSPC/崩溃、规模/RSS 和完整逐项 ACC 仍未验证。

## 2026-09-13 当前源码 cleanup 修复回归（历史快照；已由上方 Docker/E2E 记录更新）

- 环境：macOS arm64；实际 checkout `/Users/zj9495/code/nas-storage-analyzer`，保留既有 dirty/staged 工作树。
- `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`：均 exit 0。
- `cargo test --workspace --locked`：exit 0；`nas-analyzer` 261/261，`fssecure` 2 个单元测试 + 15 个对抗测试全部通过。
- `cargo test --workspace --release --locked`：exit 0；同样 261/261 + 2 + 15 全部通过。
- `cargo build --release --locked -p nas-analyzer`：exit 0。
- cleanup 定向测试 `cargo test -p nas-analyzer cleanup::tests --locked`：17/17；jobs 定向测试 `cargo test -p nas-analyzer jobs::tests --locked`：18/18，均 exit 0。Linux 固定容器 cleanup 定向测试 26/26、`fssecure` adversarial 16/16，均 exit 0。
- 前端 `pnpm --dir web install --frozen-lockfile`、`typecheck`、`lint`、`test:unit`、`build`：均 exit 0；Vitest 10 files / 45 tests 全部通过，lint 为 0 errors / 3 个 Fast Refresh warnings，build 保留大 chunk warning。
- `bash deploy/verify-delivery.sh`：exit 0，输出 `DELIVERY CONTRACT PASS`；`docker compose --env-file deploy/.env.example -f deploy/compose.example.yaml config`：exit 0。
- `make bench`：exit 0；`resource_budget` 输出 `export_rows=30000 elapsed_ms=65 rows_per_sec=461124 api_rss_bytes=None worker_rss_bytes=None`。这只是小规模导出基准。
- `make docker-build IMAGE=nas-storage-analyzer:local-cleanup-20260913`：exit 130；Rust build stage 在 `Updating crates.io index` 后无进展，取消后为 `context canceled`，目标镜像 tag 未生成。未使用旧 `nas-storage-analyzer:local` 镜像作当前源码证据，未运行本轮 Docker Smoke 或浏览器 E2E；本轮未调用浏览器，因未获得授权。
- 本轮 cleanup 修复的直接覆盖包括：Linux 新增隔离重试/日志证据、supervisor 错误返回、恢复日志残留与不完整日志拒绝，以及 macOS/Linux 全量 Rust 回归。上述证据不等同完整 ACC 验收。

## 2026-09-13 amd64 QEMU Docker E2E 复验（历史快照；cleanup/job-control 记录见上方）

- 环境：macOS arm64 主机；Docker 运行架构为 `linux/amd64`，通过 QEMU 模拟，不是原生 amd64 runner。当前工作树保留既有 dirty worktree。
- `make docker-build-amd64`：exit 0；`docker image inspect --format '{{.Id}} {{.Architecture}}/{{.Os}} {{.Created}}' nas-storage-analyzer:local-amd64-current`：`sha256:1d7606b4a25a787649eff5d0cbd2c7a373186f5e6171226c44c6ac2f86a56b32 amd64/linux`。
- `SMOKE_PORT=28188 bash deploy/smoke.sh nas-storage-analyzer:local-amd64-current`：exit 0；通过 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local-amd64-current E2E_DOCKER_HOST_PORT=28189 bash web/tests/e2e/run-real-e2e.sh`：exit 1，失败于 `web/tests/e2e/real-flow.spec.ts:192`，任务最终状态为 `FAILED`。保留目录：`.nas-storage-analyzer-e2e.poFmBn`；手工复现任务 `77c58451-e03f-4656-9ca3-669504e3dd91` 的 `/api/v1/jobs/{job_id}` 返回 `error.code=UNSUPPORTED_CAPABILITY`、`error.message=报告 artifact 写入需要 openat2 安全解析能力`，阶段为 `PUBLISH`。手工诊断使用的配置、日志和 API 响应已在核对后清理，未保留 token/cookie。
- 该结果与当前代码安全契约一致：amd64 QEMU 容器的 openat2 能力探测不可用，报告 artifact 发布 fail-closed；未使用 fallback，也未放宽测试断言。该失败不能记为 Docker E2E 通过，也不能由 QEMU 结果替代原生 amd64 runner。
- 当前 arm64 镜像 `sha256:8376ac714d038355ca9d2eefbd49f89ac11a86367d6e5c7842de072a2c57afc9`（`arm64/linux`）的 Smoke 与 Docker-backed Chromium E2E 仍为通过（E2E 1/1）；这是局部主链路证据。`ACC-001`–`ACC-078` 继续全部 `UNVERIFIED`，`ACC-014` 为 `BLOCKED / UNVERIFIED`，`ACC-061`/`ACC-077` 为 `IMPLEMENTED / UNVERIFIED`，M8 为 `IMPLEMENTED / PARTIAL / UNVERIFIED`。

## 2026-09-13 当前源码 arm64 Docker/E2E 复验（历史快照；已由上方 amd64 复验记录更新）

- 环境：macOS arm64；Docker Server 为 linux/arm64；当前工作树保留既有 dirty 改动，镜像包含本次 WAL checkpoint 修复。
- `make docker-build`：exit 0；`docker image inspect --format '{{.Id}} {{.Architecture}}/{{.Os}} {{.Created}}' nas-storage-analyzer:local`：`sha256:8376ac714d038355ca9d2eefbd49f89ac11a86367d6e5c7842de072a2c57afc9 arm64/linux`。
- `SMOKE_PORT=18086 bash deploy/smoke.sh nas-storage-analyzer:local`：exit 125，原因是本机 SSH 已占用 `127.0.0.1:18086`；临时容器由脚本 trap 清理。`SMOKE_PORT=28186 bash deploy/smoke.sh nas-storage-analyzer:local`：exit 0，Smoke 覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local E2E_DOCKER_HOST_PORT=28187 bash web/tests/e2e/run-real-e2e.sh`：exit 0，Chromium 1/1 通过（约 11.3 秒）；覆盖初始化、登录/重登、登记源、扫描、报告、CSV 下载和相同 `Idempotency-Key` 的导出幂等验证。
- 本轮 E2E 不启用重复检测配置，因此不替代 `duplicates::process_index()` 的 Linux 定向 WAL 测试或完整重复发布验收；真实 SMTP、故障注入、NAS/UGOS、原生 amd64、规模和完整逐项 ACC 仍未验证。
- 日志位置：上述命令 stdout 位于当前任务执行记录；未输出 token、cookie 或秘密内容。

## 2026-09-13 WAL checkpoint 修复定向回归（历史快照；已由上方 Docker/E2E 记录更新）

- 环境：macOS arm64；当前工作树保留既有 dirty 改动。
- 已在 `duplicates::process_index()` 返回前加入 `PRAGMA wal_checkpoint(TRUNCATE)`；新增 `duplicates::tests::process_index_checkpoints_wal_before_return`，验证保持另一 SQLite 连接时 WAL 在返回前已截断。
- `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked`、`cargo test --workspace --release --locked`、`cargo build --release --locked -p nas-analyzer`：均 exit 0；Rust workspace 为 `nas-analyzer` 250/250、`fssecure` 2 个单元 + 15 个对抗测试。
- Linux 固定 `rust:1.98.1-bookworm` 容器，显式 `cargo +1.98.1`：`... test -p nas-analyzer duplicates::tests --locked` exit 0（1/1）；`... test -p nas-analyzer report::tests --locked` exit 0（6/6）。
- 当时 arm64 镜像的 Smoke/E2E 运行早于本次 WAL 修改；“当前代码对应镜像正在重建、重建后尚未记为通过”是历史快照，当前结果见顶部记录。
- 日志位置：上述命令 stdout 位于当前任务执行记录；未输出 token、cookie 或秘密内容。

## 2026-09-13 当前树 Docker/Linux/Chromium E2E 续记（历史快照；已由上方 Docker/E2E 记录更新）

- 当前工作树保留既有 dirty 改动；本条只补充本轮已确认的执行事实。
- Linux 固定容器回归：`NAS_DEV_IMAGE=docker.m.daocloud.io/library/rust:1.98.1-bookworm scripts/linux-cargo.sh +1.98.1 test -p fssecure --test adversarial --locked` exit 0，16/16 通过。受限容器 mount permission denied 输出属于能力不可用测试场景。
- 当前 arm64 Docker 交付：`make docker-build` exit 0；`SMOKE_PORT=18084 bash deploy/smoke.sh nas-storage-analyzer:local` exit 0。Smoke 覆盖 non-root、只读根/源、cap drop、health/setup gate、SIGTERM 和 SQLite 重启持久化。
- 当前 arm64 镜像 Docker-backed Chromium E2E：设置 `E2E_DOCKER_HOST_PORT=18087` 执行 `web/tests/e2e/run-real-e2e.sh`，exit 0，Chromium 1/1 通过；完成初始化、登录/重登、登记源、扫描、报告、CSV 下载及同一 `Idempotency-Key` 的导出幂等验证。该结果只证明当前 arm64 镜像的这条主链路，不是完整 ACC 验收。
- `run-real-e2e.sh` 新增的 `E2E_DOCKER_HOST_PORT` 可配置能力已用于本次运行；本轮临时诊断日志已移除，无诊断日志残留。
- amd64 的 `ring v0.17.14` C 编译 `cc` SIGSEGV 是失败尝试；随后串行重试已生成镜像并通过 Smoke，但该历史条不覆盖顶部记录的 E2E 失败，也不等同原生 amd64 runner。
- WAL checkpoint 修复已由顶部记录确认回归通过；本历史条中的“实施中、尚待回归”不代表当前状态。

上述当前树证据不改变真实 SMTP、ENOSPC/崩溃恢复、Btrfs/reflink、UGOS/NAS 实机、原生 amd64、10 万/100 万规模及 RSS、原生配额/Tiering 和完整逐项 ACC 的 `UNVERIFIED` 状态。

## 2026-09-13 Rust 全量回归（cleanup 生命周期修复后；历史快照，计数以顶部最新记录为准）

- 环境：macOS arm64；当前工作树保留既有 dirty 改动。
- `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`：均 exit 0。
- `cargo test --workspace --locked`：exit 0；`nas-analyzer` 249/249，`fssecure` 2 个单元测试 + 15 个对抗测试全部通过。
- `cargo test --workspace --release --locked`：exit 0；同样 249/249 + 2 + 15 全部通过。
- `cargo build --release --locked -p nas-analyzer`：exit 0。
- 本次回归覆盖 cleanup supervisor/恢复、full-report/export、报告 artifact 路径安全及秘密备份取消清理测试；不替代 Docker、Linux 固定工具链、真实 E2E、NAS/UGOS、SMTP、故障注入和规模验收。

## 2026-09-13 Linux fssecure 对抗回归

- 环境：Docker Linux 容器，`docker.m.daocloud.io/library/rust:1.98.1-bookworm`，显式 `cargo +1.98.1`，共享 Linux target/registry 缓存。
- `NAS_DEV_IMAGE=docker.m.daocloud.io/library/rust:1.98.1-bookworm scripts/linux-cargo.sh +1.98.1 test -p fssecure --test adversarial --locked`：exit 0，16/16 通过。受限容器的 mount permission denied 输出属于测试覆盖的能力不可用场景。

## 2026-09-13 Docker 当前树构建与 Smoke（历史快照；amd64 E2E 结果见顶部）

- `make docker-build`：exit 0；`docker image inspect` 确认 `arm64/linux`。`SMOKE_PORT=18084 bash deploy/smoke.sh nas-storage-analyzer:local`：exit 0，覆盖 non-root、只读根/源、cap drop、health、setup gate、SIGTERM 和 SQLite 重启持久化。
- `make docker-build-amd64` 的首次尝试 exit 1；linux/amd64 QEMU 编译在 `ring v0.17.14` 的 C 编译步骤触发 `cc` SIGSEGV（exit 101）。随后串行重试已构建当前 amd64 镜像并通过 Smoke；原生 amd64 runner 仍无证据，当前 Docker E2E 失败见顶部记录。

## 2026-09-13 full-report/export 回归与 release 验证（历史快照；已由上方 Docker/E2E 记录更新）

- 环境：macOS arm64；当前工作树保留既有 staged/unstaged 改动，未执行 reset、stash、回滚或覆盖。
- `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`：均 exit 0。
- `cargo test --workspace --locked`：exit 0；`nas-analyzer` 248/248，`fssecure` 2 个单元测试 + 15 个对抗测试全部通过。
- `cargo test --workspace --release --locked`：exit 0；`nas-analyzer` 248/248，`fssecure` 2 个单元测试 + 15 个对抗测试全部通过。
- `cargo build --release --locked -p nas-analyzer`：exit 0。
- 当前回归包含 full-report 十栏目 CSV/JSON/HTML/ZIP 输出、section 标记、导出筛选能力校验、目录直系/后代范围、分类目录范围、所有者分类粒度、十进制超大字节值和超出 `i64` 查询拒绝测试。ZIP 栏目成员以文件名区分，JSON 成员 manifest 记录对应 section；未增加重复的 section 列。
- 本节当时未运行浏览器/Docker 等交付验收；该历史状态已由顶部的当前 arm64/amd64 Docker 复验更新。真实 NAS/UGOS、真实 SMTP、故障注入和规模验收继续保持 `UNVERIFIED`。日志位置：本次命令 stdout 位于当前任务执行记录，未输出 token、cookie 或秘密内容。

## 2026-09-12 cleanup supervisor/Linux 回归补充

- 子代理在当前共享工作树修复 cleanup 测试中的 `DbWriterGuard` shutdown 挂起（显式释放 writer guard）；该修复限于测试生命周期。
- 子代理报告的 workspace debug/release `240 + 15` 是本节当时的旧计数；当前主任务的 248/248 回归见上方 2026-09-13 记录。host cleanup、Linux 固定 Rust 1.98.1 cleanup、Linux jobs、Linux fssecure adversarial 等摘要仍不替代当前 Linux/Docker/外部平台证据。
- 这些证据不替代 Docker 重建、真实 E2E、NAS/UGOS、SMTP、故障注入和规模验收。

## 2026-09-12 handler 测试闭包修复后回归

- 修复 `handlers.rs` 恢复幂等测试中 `admin.id` 被异步闭包借用导致的 E0373/E0505：克隆 ID 后由 `move` 闭包使用；未改变生产逻辑。
- `cargo fmt --all`：exit 0。
- `cargo check -p nas-analyzer --all-targets --locked`：exit 0。
- `cargo test -p nas-analyzer cleanup::tests --locked`：exit 0；12/12 通过。

## 2026-09-12 当前工作树续验（历史快照；当时 240 个 nas-analyzer 测试）

- 环境：macOS arm64；工作树保留既有 dirty 改动；本节命令在修复 `export.rs`/HTTP handler 编译阻断后执行。
- `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`：均 exit 0。
- `cargo test -p nas-analyzer backup_request_tests --locked`：exit 0，6/6 通过；覆盖秘密口令不持久化、缺失临时口令失败、取消释放暂存口令和恢复幂等摘要边界。
- `cargo test --workspace --locked`：exit 0；nas-analyzer 240/240，fssecure 2 单元 + 15 对抗测试，全部通过。
- `cargo test --workspace --release --locked`：exit 0；nas-analyzer 240/240，fssecure 2 单元 + 15 对抗测试，全部通过；`cargo build --release --locked -p nas-analyzer`：exit 0。
- `pnpm --dir web install --frozen-lockfile`、`typecheck`、`lint`、`test:unit`、`build`：均 exit 0；Vitest 10 files / 40 tests 全部通过，lint 为 0 errors/3 个 Fast Refresh warnings，build 保留大 chunk warning。
- `./api/gen-ts.sh`、Redocly lint、bundle：均 exit 0；lint 保留 4 个非阻断 warning。`make verify-delivery`：exit 0，输出 `DELIVERY CONTRACT PASS`；`make compose-config`：exit 0。
- `make bench`：exit 0；30,000 行导出、74ms、405,004 rows/s，RSS 指标为 `None`，不构成 10 万/100 万规模验收。
- 该历史快照当时记录 Linux `fssecure` 未进入测试；当前源码回归已补充 Linux adversarial 16/16 通过，当前证据以顶部 2026-09-13 记录为准。
- `make docker-build`：exit 130；固定 Rust 构建阶段在 `Updating crates.io index` 后无进展，取消并得到 `context canceled`。当前源码对应镜像未完成，Docker smoke、amd64 构建和真实 Playwright E2E 保持 `UNVERIFIED`。浏览器 E2E 未运行，也未获得浏览器授权。
- 文档和脚本修正：`deploy/verify-delivery.sh` 的 Dockerfile 命令检查已同步到固定 `cargo +1.98.1` 写法；未改变业务代码。

## 2026-09-12 当前工作树回归（报告 artifact 安全迁移与备份取消清理后）

- 环境：macOS arm64；工作树保留既有 dirty 改动；本节命令均在本次 Rust 代码修改后执行。
- `cargo fmt --all`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked`：exit 0；nas-analyzer 238、fssecure 对抗 15，全部通过。新增报告固定根/符号链接和秘密备份取消口令释放测试通过。
- `cargo test --workspace --release --locked`：exit 0；nas-analyzer 238、fssecure 对抗 15，全部通过。
- `cargo build --release --locked -p nas-analyzer`：exit 0。
- Linux：使用 `rust:1-bookworm`，显式选择已安装的 `1.98.1-aarch64-unknown-linux-gnu` toolchain 运行 `fssecure` 对抗测试：16/16 通过；受限容器的 mount permission denied 场景按测试设计闭合。
- `pnpm --dir web run typecheck`、`lint`、`test:unit`、`build`：均 exit 0；Vitest 10 files / 40 tests 全部通过；lint 仅 3 个既有 Fast Refresh warning，build 仅 bundle size warning。
- `./api/gen-ts.sh`、Redocly lint、bundle、目标文件 `git diff --check`：均 exit 0；lint 保留 4 个 warning（初始化/健康探针缺少 4xx、JobEvent 未被路径直接引用），未添加虚构响应或删除契约 schema。
- `make verify-delivery`、`make compose-config`、`make bench`：均 exit 0；交付合同通过；小基准 30,000 行、70ms、423,992 rows/s，RSS 为 `None`，不构成百万级规模验收。
- 报告 artifact 生产调用已统一为配置 `data_dir/reports/{report_id}`、固定 artifact 名和 `fssecure` FD；run index 仍是独立 mutable artifact，未扩大本节报告安全结论。
- 本节尚未记录 Docker 重建、smoke 和真实 Playwright 结果；它们必须在本次代码修改对应镜像重建后重新执行，历史镜像证据不继承。

## 2026-09-12 API 契约 lint 与生成类型回归（本轮）

- 环境：macOS arm64；当前工作树保留既有 staged/unstaged/untracked 改动。
- `pnpm --package=@redocly/cli@1.34.0 dlx redocly lint api/openapi.yaml --max-problems 200`：exit 0；OAS 3.1 nullable 错误为 0，license/tag 规则通过；保留 4 个非阻断 warning（初始化/健康探针无 4xx、未被路径直接引用但由前端生成类型使用的 `JobEvent` schema），未用虚构响应或删除 schema 消除提示。
- `./api/gen-ts.sh`：exit 0，重新生成 `web/src/api/schema.d.ts`；`pnpm --dir web run typecheck`：exit 0。
- `pnpm --package=@redocly/cli@1.34.0 dlx redocly bundle api/openapi.yaml --output /tmp/nas-storage-analyzer-openapi-after-null.yaml`：exit 0；`git diff --check -- api/openapi.yaml web/src/api/schema.d.ts`：exit 0。
- 本节只证明 OpenAPI lint、引用解析和生成类型一致性；未将其替代 Rust/React 业务测试或未验证的平台能力。

## 2026-09-12 Goal 接续聚焦回归（实时）

- 环境：macOS arm64；当前工作树保留既有 staged/unstaged/untracked 改动。
- `cargo test -p nas-analyzer purge_reservation_does_not_consume_a_second_token_on_retry --locked`：exit 0，1/1 通过；同时运行的 main binary 测试为 0/0，未失败。
- 本节只记录已实际执行的聚焦测试；秘密备份/恢复 HTTP、报告 TOCTOU、清理 supervisor、React 和 Docker 相关回归仍待代码合并后重跑。

每次测试运行追加一节，记录：时间、环境（OS/架构/容器）、代码版本或工作区状态、命令、退出码、结果摘要、日志位置。不得记录未执行的命令。

## 2026-09-12 Docker 重建尝试（当前树，未通过）

- 环境：macOS arm64 开发机；Docker Server 为 linux/arm64；当前工作树包含既有 dirty 改动和本轮报告 artifact 安全修复。
- 清理同仓库遗留的重复 `docker buildx` 进程后，串行执行 `make docker-build`。
- `make docker-build`：exit 130。Dockerfile/基础镜像/源码复制/前端构建层均完成或命中缓存，Rust release 阶段在 `Updating crates.io index` 后约 8 分钟无新增输出；确认宿主构建进程无 CPU 使用后以 Ctrl-C 取消，输出为 `#21 CANCELED` / `context canceled`。
- 当前镜像未完成重建，因此不采信旧 `nas-storage-analyzer:local` 镜像；本轮代码对应的 arm64/amd64 smoke 和 Docker-backed Playwright E2E 尚未执行，保持 `UNVERIFIED`。
- 日志/证据位置：本次命令 stdout 位于当前任务执行记录；未输出 token、cookie 或秘密内容。

## 2026-09-12 Docker toolchain/network 诊断（当前树，未通过）

- 为避免基础镜像因仓库 `rust-toolchain.toml` 的 clippy 组件声明而在线补装，`deploy/Dockerfile` 的 release 命令已显式使用已安装的 `cargo +1.98.1`；该修改不改变编译器版本或业务产物。
- 使用 `docker buildx build --network=host ...` 重试：仍在 `Updating crates.io index` 后无输出，约 3 分钟后取消，exit 130（`context canceled`）。普通 Docker 容器访问 `https://index.crates.io/config.json` 正常，但 buildx 构建阶段仍未取得 Cargo index 响应。
- 因此当前代码对应镜像仍未完成；arm64/amd64 smoke 与 Docker-backed Playwright E2E 继续保持 `UNVERIFIED`。

## 2026-09-12 当前树回归与 Docker/E2E 验证（实时）

- 环境：macOS arm64 开发机；Docker Server 为 linux/arm64；amd64 镜像在该 arm64 主机上通过 QEMU 模拟构建/运行；当前工作树包含既有 dirty 改动和本轮修复。
- `cargo fmt --all -- --check`、`cargo check --workspace --all-targets --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings`：均 exit 0。
- `cargo test --workspace --locked`：exit 0；`nas-analyzer` 206 tests、`fssecure` 对抗测试 15 tests，全部通过。
- `cargo test --workspace --release --locked`：exit 0；206 + 15，全部通过。
- `cargo build --release --locked -p nas-analyzer`：exit 0。
- `scripts/linux-cargo.sh test -p fssecure --test adversarial --locked`：exit 0；Linux 容器 16/16 通过。受限容器输出一次 mount permission denied，但对应测试验证了 mount 能力不可用时的失败闭合语义。
- `pnpm --dir web install --frozen-lockfile`、`pnpm --dir web run typecheck`、`lint`、`test:unit`、`build`：均 exit 0；Vitest 7 files / 33 tests 全部通过。
- `./api/gen-ts.sh`：exit 0；`api/openapi.yaml` 的 compare/export 均生成必填 `Idempotency-Key` header。OpenAPI bundle exit 0；Redocly lint exit 1，仍受 OAS 3.1 nullable 以及通用 license/tag 规则阻断，未记为完整契约通过。
- `make verify-delivery`：exit 0，输出 `DELIVERY CONTRACT PASS`；`make compose-config`：exit 0。
- `make bench`：exit 0；当前 `resource_budget` 小基准固定重复导出 30,000 行，`elapsed_ms=65`、`rows_per_sec=456271`，`api_rss_bytes=None`、`worker_rss_bytes=None`。这不是 10 万/100 万条目扫描或 RSS 验收证据。
- `make docker-build`（最终 Dockerfile，linux/arm64，Docker 主机原生架构）：exit 0；`docker image inspect` 显示 `arm64/linux`；随后 `SMOKE_PORT=18084 bash deploy/smoke.sh nas-storage-analyzer:local`：exit 0，验证 non-root、只读根/源、`cap_drop`、healthcheck、setup gate、SIGTERM、SQLite 重启持久化。
- `make docker-build-amd64`（最终 Dockerfile，linux/amd64，arm64 主机 QEMU 模拟）：exit 0；`docker image inspect` 显示 `amd64/linux`；随后 `SMOKE_PORT=18085 bash deploy/smoke.sh nas-storage-analyzer:local-amd64`：exit 0，验证同一交付安全与重启持久化链路。该结果不是原生 amd64 runner 证据。
- `E2E_BACKEND_BINARY=target/release/nas-analyzer bash web/tests/e2e/run-real-e2e.sh`：exit 1；初始化、登录、登记源、扫描和报告完成，导出 job 为 `FAILED/SOURCE_UNAVAILABLE`，后端日志明确为 macOS 缺少 `openat2` 且写操作 fail-closed。此失败是安全门控证据，不记作产品 E2E PASS。
- `E2E_BACKEND_DOCKER_IMAGE=nas-storage-analyzer:local bash web/tests/e2e/run-real-e2e.sh`：exit 0；Chromium 1/1 通过，完成初始化→登录/重登→登记源→扫描→报告→CSV 下载，并验证相同 `Idempotency-Key` 返回同一 export/job。该结果来自最终 Dockerfile 的 Linux arm64 镜像。
- amd64 首次并行 QEMU 构建的 `cc` SIGSEGV 是失败尝试；最终采用 `CARGO_BUILD_JOBS=1` 的构建已单独 exit 0，以上最终证据不掩盖该历史失败。

日志/证据位置：真实 host 失败临时目录 `/tmp/nas-storage-analyzer-e2e.oE3RCe`（仅测试数据，未作为发布数据）；Playwright 失败截图/trace 在 `web/test-results/e2e*`；Docker smoke/E2E 临时数据由脚本清理。未记录 token、cookie 或秘密。

## 2026-09-11 OpenAPI/生成类型契约同步

- 环境：macOS arm64 开发机；仓库为既有 dirty worktree，本轮未修改 Rust 或 React UI 组件。
- `./api/gen-ts.sh`：exit 0；`api/openapi.yaml` 成功生成 `web/src/api/schema.d.ts`。
- `pnpm --dir web run typecheck`：exit 0（`tsc -b`）。
- `git diff --check -- api/openapi.yaml api/gen-ts.sh web/src/api/schema.d.ts`：exit 0。
- `pnpm --package=@redocly/cli@1.34.0 dlx redocly bundle api/openapi.yaml --output /tmp/nas-storage-analyzer-openapi.yaml`：exit 0；OpenAPI 引用成功打包，临时输出不在仓库内。
- `pnpm --package=@redocly/cli@1.34.0 dlx redocly lint api/openapi.yaml`：exit 1；报告了仓库已有的 OAS 3.1 `nullable` 规则错误及 license/tag description 通用规则问题，未将其记为契约校验通过。
- 日志/证据位置：本次命令 stdout 位于当前任务执行记录；未输出 token、cookie 或秘密内容。

## 2026-09-11 安全修复后的待回归记录

- 环境：macOS arm64 开发机；工作树包含既有未提交改动。
- 已完成代码修复：CLI 实例锁生命周期、恢复 staging FD 安全写入；两项修复的子任务已报告聚焦测试通过，但主任务尚未重跑本轮完整回归，因此不把旧数字或子任务摘要记为最终发布证据。
- 待执行：报告 artifact 安全递归删除迁移后的 Linux 安全测试、debug/release workspace 回归、前端检查、amd64 Docker 构建/启动冒烟、真实 Docker-backed Playwright、benchmark、最终交付合同和验收矩阵审计。

## 2026-09-09 M0 启动

- 环境：macOS arm64（开发机），Node v24.21.0，pnpm 10.8.0，Docker 29.7.2，Rust 1.98.1（rustup 安装）。

## 2026-09-09 M0 基线

- `cargo metadata`：exit 0，Cargo.lock 生成（71517 字节）。
- `cargo check --workspace --all-targets --locked`：exit 0（第 4 轮；前 3 轮修复 fssecure 跨平台类型/Errno/OFlags 差异、lettre feature、jiff TimeZone、迁移冲突）。
- `cargo test --workspace --locked`：19 passed / 0 failed（第 2 轮；第 1 轮 2 个迁移测试失败，根因：迁移 SQL 内含重复 schema_migrations 建表，已从 3 个迁移文件移除）。
- web（子代理执行）：install --frozen-lockfile / typecheck / lint / test:unit(17) / build / test:e2e(skip) 全部通过。
- Linux 容器测试入口 scripts/linux-cargo.sh 已建，fssecure Linux 测试执行中。

## 2026-09-10 资源预算契约修复与 workspace 回归

- 环境：macOS arm64 开发机；Rust 工具链以 `rust-toolchain.toml` 为准；工作树包含既有未提交改动。
- `cargo check --workspace --all-targets --locked`：exit 0；修复前曾因 `MemoryBudgetMonitor`/`MemoryBudgetController` 接口漂移失败，修复后检查通过。
- `cargo fmt --all -- --check`：exit 0。
- `cargo test --workspace --locked`：exit 0；`fssecure` 12 tests、`nas-analyzer` 201 tests，0 failed；包括预算压力、通知、备份、清理、扫描/报告等当前已存在测试。
- 临时真实服务只读检查：`/tmp/nas-analyzer-e2e.gow92q` 报告 `8b4d2908-f5ea-40dc-b0a3-a833ee50063f` 的报告明细为 3 个普通文件、18 字节；其旧 job 进度曾为 1 个文件、6 字节，属于修复前的进度一致性问题，不将其旧进度视为通过证据。新二进制重启复验待执行。
- 日志/证据位置：本次命令 stdout 位于当前任务执行记录；临时报告与 SQLite 仅位于上述专用临时目录。未输出 token、cookie 或秘密内容。
- 尚未运行或尚未重验：`cargo clippy -D warnings`、release test/build、前端完整命令、Playwright 真实闭环、benchmark、amd64 Docker、最终 `make verify-delivery` 和绿联实机；不得据此标记发布通过。

## 2026-09-11 接续回归起点（17:30 CST）

- 环境：macOS arm64 开发机；当前工作树保留既有 dirty 改动。
- `cargo check --workspace --all-targets --locked`：exit 0；确认 HTTP handler 参数修复后当前 Rust workspace 可编译。
- `cargo fmt --all`：exit 0；随后 `cargo fmt --all -- --check`：exit 0。
- 性能代理报告的源码变更前 10k 导出数据未作为当前树结果；当前 benchmark、完整 Rust 回归、前端、真实 E2E、Docker 和最终交付审计尚未在本节记为通过。
- 日志/证据位置：命令 stdout 位于当前任务执行记录；未输出 token、cookie 或秘密内容。
- 2026-09-14 F01 实现进度：已接入报告完成前的关联卷补采样；本次尚未执行测试，不能记为验证通过。`last_sample`、日趋势总量/可用量字段和 Overview 展示仍待完成。
## 2026-09-14 接续回归

- `cargo check -p nas-analyzer --lib --locked`：exit 0。
- 诊断迁移版本断言已与控制库迁移版本 8 对齐；后续全量测试证据仍以实际命令输出为准。
## 2026-09-14 最新接续记录

- `cargo check --workspace --all-targets --locked`：exit 0。
- F03 subagent 未产生新的源码或测试证据；不得据此提升 F03 或验收项状态。
## 2026-09-14 前端回归

- `pnpm --dir web run typecheck`：exit 0。
- `pnpm --dir web run test:unit -- --runInBand`：10 files / 49 tests passed。
## 2026-09-14 静态交付检查

- `cargo fmt --all`：exit 0。
- `git diff --check`：exit 0。
- `bash deploy/verify-delivery.sh`：exit 0，`DELIVERY CONTRACT PASS`；前端 build exit 0，保留大 chunk warning。
## 2026-09-14 F01 聚焦验证

- `cargo test -p nas-analyzer sampling::tests --locked`：exit 0，8 passed / 0 failed。
## 2026-09-14 Rust 静态质量检查

- `cargo clippy --workspace --all-targets --locked -- -D warnings`：exit 0。
## 2026-09-14 Rust release 回归

- `cargo test --workspace --release --locked`：exit 0；nas-analyzer 303/303、fssecure 2 个单元测试和 15 个对抗测试通过；doc-tests 通过。
## 2026-09-14 迁移版本回归修复

- 将 diagnostics 测试断言从控制库版本 8 对齐到当前版本 9；`cargo test -p nas-analyzer diagnostics::tests --locked`：3 passed / 0 failed。
## 2026-09-14 F03 契约同步

- `./api/gen-ts.sh`：exit 0。
- OpenAPI lint/bundle：exit 0，保留既有 warning。
- `pnpm --dir web run typecheck`：exit 0；`git diff --check`：exit 0。
## 2026-09-14 F03 React 接入

- `pnpm --dir web run test:unit -- --runInBand`：10 files / 50 tests passed。
- `pnpm --dir web run typecheck`：exit 0。
## 2026-09-14 F03 事件消费者验证

- `cargo test -p nas-analyzer notify::tests --locked`：exit 0，11 passed / 0 failed；覆盖 event_key 幂等、分页、输入校验和 SMTP outbox 回归。
## 2026-09-14 F03 事件路径回归

- `cargo test -p nas-analyzer runtime::tests --locked`：9 passed / 0 failed。
- `cargo test -p nas-analyzer worker::tests --locked`：5 passed / 0 failed。
## 2026-09-14 F03 后端链路回归

- `cargo test --workspace --locked`：exit 0；308 passed / 0 failed，含 fssecure 对抗测试与 nas-analyzer 全量测试。
# 2026-09-14 当前 Goal 接续回归（最新）

- 命令：`cargo test --workspace --locked`
- 结果：exit 0，308 passed / 0 failed / 0 ignored；耗时约 11.70 秒。
- 范围：当前工作树 Rust workspace；该结果不覆盖 React、Docker、浏览器、原生 amd64、NAS/UGOS、SMTP、故障注入或规模/RSS 验证。
# 2026-09-14 前端回归补充（最新）

- `pnpm --dir web run test:unit -- --runInBand`：exit 0，10 files / 55 tests passed。
- `pnpm --dir web run typecheck`：exit 0。
- 未覆盖 Docker、浏览器 E2E、原生 amd64、NAS/UGOS、SMTP、故障注入和规模/RSS。
# 2026-09-14 设计包完整性复核（最新）

- `(cd docs/design && sha256sum -c MANIFEST.sha256)`：exit 0，全部清单项通过。
- `git diff --check`：exit 0。
- 本轮未执行 Docker、浏览器、NAS/UGOS 或 SMTP 验证。
# 2026-09-14 Rust 静态质量门复核（最新）

- `cargo clippy --workspace --all-targets --locked -- -D warnings`：exit 0。
# 2026-09-14 Rust 发布构建（最新）

- `cargo build --release --locked -p nas-analyzer`：exit 0，`Finished release profile`，耗时约 1m43s。
# 2026-09-14 交付合同复核（最新）

- `bash deploy/verify-delivery.sh`：exit 0，`DELIVERY CONTRACT PASS`。
- 包含配置检查、web typecheck 和 production build；构建保留大 chunk warning。
# 2026-09-14 Compose 配置复核（最新）

- `make compose-config`：exit 0，配置成功渲染。
- 本轮未启动容器；镜像运行、浏览器 E2E、原生 amd64、NAS/UGOS 与 SMTP 仍未验证。
# 2026-09-14 发布前格式复核（最新）

- `cargo fmt --all -- --check`：exit 0。
- `git diff --check`：exit 0。
# 2026-09-14 OpenAPI 类型同步复核（最新）

- `./api/gen-ts.sh`：exit 0。
- `pnpm --dir web run typecheck`：exit 0。
# 2026-09-14 OpenAPI 发布检查（最新）

- `npx --yes @redocly/cli lint api/openapi.yaml`：exit 0，6 warnings。
- `npx --yes @redocly/cli bundle api/openapi.yaml --output /tmp/nas-openapi-bundle.yaml`：exit 0。
# 2026-09-14 依赖审计（最新）

- `bash scripts/dependency-audit.sh`：exit 0，审计产物写入 `artifacts/dependencies`，目标为 `x86_64-unknown-linux-gnu`。
# 2026-09-14 Release workspace 回归（最新）

- `cargo test --workspace --release --locked`：exit 0，308 passed / 0 failed / 0 ignored，耗时约 2m01s。
# 2026-09-14 F10 契约边界复核（最新）

- 静态复核确认排行接口当前仅接收 `cursor`、`page_size`；文件明细接口才接入完整 `QuerySpec` 筛选。
- 未修改代码，未运行新的测试；F10 不计为完成。
# 2026-09-14 Makefile 单元测试入口回归（最新）

- `make test-unit`：exit 0；Rust lib 308 passed，React 10 files / 55 tests passed。
# 2026-09-14 Makefile 安全测试入口回归（最新）

- `make test-security`：exit 0，fssecure adversarial 15 passed / 0 failed。
# 2026-09-14 Workspace 全目标检查（最新）

- `cargo check --workspace --all-targets --locked`：exit 0，耗时约 2.99 秒。
