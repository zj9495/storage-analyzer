# NAS Storage Analyzer

面向绿联 NAS（Docker）的独立存储分析应用：卷容量趋势、目录/用户/分类统计、
重复文件检测、历史报告与导出、任务调度、通知，以及显式开启的安全清理
（隔离 → 恢复 → 永久删除）。Rust（Axum + Tokio）+ React/TypeScript + SQLite
单容器方案。

**状态**：开发中（M0–M8 逐阶段实施）。真实进度见
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md)；
验收矩阵见 [docs/ACCEPTANCE_RESULTS.md](docs/ACCEPTANCE_RESULTS.md)。
设计输入（只读）：[docs/design/](docs/design/00_README.md)。

镜像发布与 NAS 部署：[使用 publish-docker-image 发布并通过 Docker Compose 部署](docs/DOCKER_DEPLOYMENT.md)。

## 构建与质量入口

```bash
make format lint check          # cargo fmt --check / clippy -D warnings / check --locked
make test-unit test-integration # Rust 单元/集成 + Vitest
make test-security              # fssecure 与安全反例（Linux 语义在容器内验证）
make test-e2e E2E_BASE_URL=http://127.0.0.1:3010 # Playwright 真实服务验收
make build                      # release 后端 + 前端产物
make docker-build               # linux/arm64 本地镜像 nas-storage-analyzer:local
make docker-build-amd64         # linux/amd64（QEMU/交叉）
make docker-build-multiarch     # amd64+arm64 OCI 归档（默认写入 /tmp）
make smoke                      # 容器冒烟：非 root/只读/健康检查/重启持久化
make smoke-amd64                # 冒烟已构建的 nas-storage-analyzer:local-amd64
make compose-config             # 校验 Compose 展开结果
make verify-delivery            # 配置、Compose、Dockerfile 与前端真实构建审计
```

`make docker-build` 和 `make docker-build-amd64` 分别生成可在本机加载的单架构镜像；
`make docker-build-multiarch` 生成不自动加载到本地 daemon 的 OCI 多架构归档。发布到
镜像仓库时，使用已认证的 buildx builder，并将 `IMAGE` 改为完整仓库名后执行等价的
`docker buildx build --platform linux/amd64,linux/arm64 -f deploy/Dockerfile -t "$IMAGE" --push .`。
Dockerfile 与 Makefile 默认把 `BASE_REGISTRY` 设为 `docker.m.daocloud.io/library`；在
可访问 Docker Hub 的 CI/发布机上使用 `BASE_REGISTRY=docker.io/library make docker-build-multiarch`
或把同名 `--build-arg` 传给裸 `docker buildx build`。registry 只改变获取位置，
Dockerfile 中的基础镜像 digest 不变。未执行 push，也不把 OCI 归档当作已经发布的镜像。

`make bench` 在仓库没有 `crates/*/benches/*.rs` 时会明确失败，不把“没有基准目标”报告为
通过。`make test-integration` 当前执行真实的 `fssecure` 集成测试目标；`make test-security`
执行同一组安全反例。`make test-e2e` 必须提供 `E2E_BASE_URL`，没有运行中的真实服务时会失败，
不会把空测试集或跳过用例报告为通过。

Linux 语义测试（开发机为 macOS 时）：

```bash
scripts/linux-cargo.sh test -p fssecure     # 在 Linux 容器内跑 fssecure 全部测试
```

## 运行（开发）

```bash
cargo run -p nas-analyzer -- config-check --config deploy/config.example.yaml
cargo run -p nas-analyzer -- serve --config /path/to/config.yaml
```

配置采用 `config_version=2`（见 deploy/config.example.yaml 与
docs/design/contracts/deployment.schema.json）。部署模板：
[deploy/compose.example.yaml](deploy/compose.example.yaml)，环境变量模板：
[deploy/.env.example](deploy/.env.example)。生产部署必须替换 `deploy/.env` 中的
`/replace/...` 占位路径，并把 `APP_UID`/`APP_GID` 设为实际的非 root 运行身份；不得
直接使用示例值。

首次部署可按以下顺序准备文件并校验配置：

```bash
cp deploy/.env.example deploy/.env
cp deploy/config.example.yaml deploy/config.yaml
# 编辑 deploy/.env：APP_DATA_PATH、SOURCE_PATH、APP_UID、APP_GID 等必须是真实值
docker compose --env-file deploy/.env -f deploy/compose.example.yaml config
docker compose --env-file deploy/.env -f deploy/compose.example.yaml up -d
docker compose --env-file deploy/.env -f deploy/compose.example.yaml ps
```

Compose 明确启用只读 rootfs、丢弃全部 Linux capabilities、`no-new-privileges` 和
`/tmp` 独立 tmpfs；应用数据目录是唯一读写 bind mount，配置文件和扫描源均为只读
bind mount。不要把宿主机 `/`、Docker socket 或包含秘密的目录挂入容器。宿主机需要
提供 `docker compose`、`curl`（仅用于 `deploy/smoke.sh`）和能运行目标架构的
buildx/QEMU；示例不会自动创建或修正宿主机路径权限。

## 安全边界（摘要）

- 默认只读扫描源；写操作需部署开关 + 源级开关 + 内核安全能力 + 近期再认证。
- 所有源文件访问经 `crates/fssecure`（openat2 BENEATH|NO_SYMLINKS|NO_XDEV）。
- 详见 docs/design/01_SPEC.md 第 1.4、13、14 节与 docs/adr/。
