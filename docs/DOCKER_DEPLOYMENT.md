# 使用 publish-docker-image 发布并通过 Docker Compose 部署

本文使用仓库中的 `deploy/Dockerfile`、`deploy/compose.example.yaml`、
`deploy/.env.example` 和 `deploy/config.example.yaml`，部署单容器应用（后端与前端同镜像）。
示例镜像名为 `home/nas-storage-analyzer`，版本为 `v1.0.0`，发布时按实际版本替换。

## 1. 准备环境

发布机需要 Docker、可用的 Buildx builder，以及已加入 `PATH` 的自定义命令
`publish-docker-image`。它不是 Docker 自带命令，也未随本仓库分发；当前开发机安装于
`~/.local/bin/publish-docker-image`。换发布机时需先安装同一脚本。

```bash
command -v publish-docker-image
docker buildx inspect --bootstrap
```

当前脚本固定推送至 `docker-hub.zj9495.com:9495`，仅构建 `linux/amd64`，
同时推送指定版本和 `latest`，不加载镜像到发布机的本地 Docker 镜像列表。
脚本不执行登录；仓库要求认证时，需要提前配置 Docker 凭据。
在 ARM 发布机上构建需要 builder 支持 amd64 仿真或使用 amd64 构建节点。

NAS 需要 Linux、Docker Engine 与 Docker Compose v2，并能拉取上述仓库。
本流程生成的镜像用于 x86_64/amd64 NAS，不适用于 ARM NAS 的原生部署。

```bash
uname -m
docker version
docker compose version
```

## 2. 构建并发布镜像（发布机）

在仓库根目录执行：

```bash
publish-docker-image home/nas-storage-analyzer v1.0.0 -f deploy/Dockerfile .
```

`-f deploy/Dockerfile` 必须显式指定，脚本默认的 `docker/Dockerfile` 不适用于本项目。
最后的 `.` 是仓库根目录构建上下文；Dockerfile 会在构建阶段编译 Rust 后端和前端，
无需提前运行本地前端构建。

发布成功后得到：

```text
docker-hub.zj9495.com:9495/home/nas-storage-analyzer:v1.0.0
docker-hub.zj9495.com:9495/home/nas-storage-analyzer:latest
```

检查远端版本和平台：

```bash
docker buildx imagetools inspect docker-hub.zj9495.com:9495/home/nas-storage-analyzer:v1.0.0
```

当前脚本仅接受镜像路径、版本、`-f` 和构建上下文，不支持透传 `--build-arg`
或 `--platform`。Dockerfile 与 Makefile 默认均使用 `docker.m.daocloud.io/library`
获取基础镜像，版本和 digest 保持锁定。终端的 `useproxy` 不代表 Colima 内的 Docker
daemon 已配置代理；基础镜像元数据由 builder 拉取。镜像标签也不会自动写入 Dockerfile 的 `IMAGE_VERSION`
和 `VCS_REF` 参数；当前发布方式下对应标签元数据仍为默认值 `local`、`unknown`。

## 3. 准备部署文件（NAS）

将以下三个文件从仓库复制到 NAS 上同一个部署目录，并重命名：

| 仓库文件 | NAS 部署目录中的文件 |
| --- | --- |
| `deploy/compose.example.yaml` | `compose.yaml` |
| `deploy/.env.example` | `.env` |
| `deploy/config.example.yaml` | `config.yaml` |

后续 NAS 命令都在该部署目录执行。NAS 无需安装 Rust、Node.js 或完整源代码。

选择实际的非 root 运行账号，通过 `id <运行账号>` 查询 UID/GID。
创建专用的应用数据目录，使该账号可写；该账号还必须能读取配置文件、读取扫描文件
并遍历扫描目录。仅给应用数据目录设置所有权，不要递归修改原有共享文件夹的所有权。
扫描源、配置文件和数据目录必须提前存在，Compose 模板不会自动创建这些路径。
应用数据目录应位于扫描源之外，使用 NAS 本地存储保存 SQLite 和报告。

编辑 `.env`，将以下占位符全部替换成 NAS 的实际值：

```dotenv
ANALYZER_IMAGE=docker-hub.zj9495.com:9495/home/nas-storage-analyzer:v1.0.0
APP_DATA_PATH=/replace/with/local/app-data
APP_CONFIG_PATH=./config.yaml
SOURCE_PATH=/replace/with/actual/shared-folder
APP_UID=<实际非root账号UID>
APP_GID=<实际账号GID>
NAS_BIND_IP=<NAS局域网IP>
APP_PORT=3010
APP_TIMEZONE=Asia/Shanghai
APP_MEMORY_LIMIT=1024m
APP_CPUS=2.0
```

`APP_CONFIG_PATH=./config.yaml` 相对于 Compose 文件目录解析。含空格或特殊字符的
路径按 dotenv 语法加引号。需要附加组才能读取共享文件夹时，在 `compose.yaml`
的 `group_add` 中填写已授权的实际组 ID。

编辑 `config.yaml`，将 `server.default_timezone` 设为 `Asia/Shanghai`；
`.env` 中的 `APP_TIMEZONE` 不会替换 YAML 中的该字段。保留以下容器内路径和只读设置：

```yaml
storage:
  data_dir: /data
  # 此处仅展示相关字段，保留原文件中其余 storage 配置
approved_mounts:
  - key: main
    container_path: /sources/main
    writable: false
    allow_submounts: false
security:
  allow_write_operations: false
  # 保留原文件中其余 security 配置
```

宿主机 `SOURCE_PATH` 挂到容器 `/sources/main`，应用数据挂到 `/data`。
不要把 YAML 中的容器路径改成宿主机路径。模板默认允许局域网 HTTP，
使用 NAS 局域网 IP 绑定端口即可供局域网访问；只在宿主机访问时可保留 `127.0.0.1`。

## 4. 校验并启动（NAS）

```bash
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml pull analyzer
docker compose --env-file .env -f compose.yaml run --rm --no-deps analyzer config-check --config /config/config.yaml
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml logs --tail=100 analyzer
```

等待容器健康状态变为 `healthy`。将下面 URL 中的占位符替换为 `.env` 中的绑定 IP
和端口，检查就绪接口：

```bash
curl --fail http://<NAS局域网IP>:3010/health/ready
```

Compose 保留只读根文件系统、只读扫描源、非 root 用户和资源限制。
`APP_MEMORY_LIMIT` 是容器总内存硬限制，包含 API 和扫描 worker；配置文件中的
进程内存预算不等同于该硬限制。

## 5. 首次登录

服务首次启动时会自动创建默认管理员账号 `admin/admin`。
打开 `http://<NAS局域网IP>:3010` 登录后，系统会强制进入修改密码页面；
新密码至少 8 位，修改成功后需要使用新密码重新登录。

已经初始化的实例继续使用原有管理员账号和密码。

登录后在扫描源配置中使用已批准挂载 `main` 对应的容器路径 `/sources/main`，
先选择小目录执行扫描，确认文件读取、任务完成和报告展示正常。
此部署保留只读扫描设置，不启用清理写操作。

## 6. 更新版本与停止

发布机使用新版本重新执行第 2 节发布命令。更新 NAS 前先停止服务，
备份完整的 `APP_DATA_PATH` 目录以及 `.env`、`config.yaml`、`compose.yaml`，
再修改 `.env` 中的 `ANALYZER_IMAGE` 为新版本：

```bash
docker compose --env-file .env -f compose.yaml stop analyzer
# 完成上述数据与配置备份，并修改 .env 中的版本后继续
docker compose --env-file .env -f compose.yaml pull analyzer
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml logs --tail=100 analyzer
```

更新后重新检查健康接口和扫描报告。使用独立版本标签并保留旧版本镜像；
发生数据库迁移后，回退需要使用与旧版本匹配的升级前数据备份，不能只更换镜像标签。

日常停止服务使用 `docker compose --env-file .env -f compose.yaml stop`；
移除容器和 Compose 网络使用 `docker compose --env-file .env -f compose.yaml down`。
应用数据位于宿主机 bind mount，以上命令不会删除该目录。

## 7. 常见排查

| 现象 | 检查项 |
| --- | --- |
| 找不到 `publish-docker-image` | 发布机是否安装自定义脚本、脚本目录是否加入 `PATH` |
| 构建找不到 Dockerfile 或 Cargo 文件 | 是否在仓库根目录执行，是否指定 `-f deploy/Dockerfile .` |
| 基础镜像拉取失败 | builder 到 `docker.m.daocloud.io` 的网络；该脚本不透传构建参数，终端代理不等同于 Docker daemon 代理 |
| 推送或拉取失败 | 仓库地址、端口、TLS 和仓库认证要求 |
| `exec format error` | NAS 是否为 amd64；当前发布命令只生成 amd64 镜像 |
| 挂载失败或权限不足 | 路径是否存在、UID/GID/ACL 是否允许数据写入及扫描读取 |
| 页面无法访问 | 绑定 IP、端口、防火墙及容器健康状态；默认回环地址无法从其他机器访问 |
| 扫描遇到挂载边界或内核能力错误 | 扫描源布局、`allow_submounts` 配置及 NAS 的 Linux/openat2 能力 |

本文按当前发布脚本、Compose 模板和应用命令静态核对；编写文档不代表已经执行镜像发布、
NAS 部署或真实扫描验证。
