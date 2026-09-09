# 机器可读契约

`deployment.schema.json` 用于校验 `deploy/config.example.yaml` 解析后的对象；JSON Schema 为 2020-12。所有对象禁止未知字段。`metadata-import.schema.json` 校验身份、卷关联和配额导入；示例是人工演示数据，不是用户真实 NAS 信息。

`profile-create.example.json` 对应主规格第 17.3 节的创建任务请求。`domain-enums.json` 固定常用领域枚举。完整 OpenAPI、数据库迁移和请求/响应 DTO 应由 Codex 在 M0 创建，并与主规格第 16–17 节保持一致；本目录没有假装提供已经完成的服务端实现。

## JSON Schema 之外必须做的语义校验

已导入 source_id / volume_id 必须在应用中存在，且管理员有权修改关联；导入不能创建新的部署挂载或扩大文件访问范围。示例中的 UUID 和 UID 需换成真实登记值。

确认 IANA 时区存在、代理 CIDR 合法、listen 端口有效、源 key 唯一、路径绝对且位于批准边界、源之间不重叠、/data 与源不发生别名重叠。禁止符号链接逃逸和嵌套挂载写入。

`allow_submounts` 在 V1 固定 false；子挂载必须登记独立源。`max_running_scans` 在 V1 固定 1。`hash_read_limit_mib_s=0` 明确表示不限速；UI 不得把 0 理解为禁止读取。

Rust 修订使用部署 `config_version=2`，资源字段为 `api_memory_budget_mib` 与 `worker_memory_budget_mib`。它们约束缓冲/队列/cache 分配计划，并触发监测后的超限处置，不是语言级 GC 设置或 RSS 硬保证。主进程与 worker 分别统计；两者预算之和给 SQLite C 堆、临时文件、分配器和其他进程留余量。整体硬限制仍由 Compose/cgroup 提供，不能保证 RSS 采样先于 OOM 生效。

v1 的旧字段 api_memory_limit_mib/worker_memory_limit_mib 不再接受。检测旧 config_version 或未知 limit 字段时返回可操作的迁移提示；不能静默接受但不生效。JSON Schema 的版本与 metadata-import 格式版本互相独立，导入 schema 不因此升级。

APP_TIMEZONE 环境变量显式覆盖 server.default_timezone；TZ 用于运行时环境。Profile 仍保存独立时区。环境变量只覆盖已定义字段，不能用任意变量扩大批准挂载。

配额 known 必须有 bytes；unlimited/unknown 必须 bytes=null。bytes 解析需要范围检查。配额限制 0 是有效限制，但使用率不得除零，应显示零额度/已超额状态。used_bytes=null 表示提供者没有报告已用值，不是 0。

导入相同 namespace+UID 不得产生冲突显示名；同一作用域、主体和 metric 的多条有效配额按版本/来源明确解决，不能任意取最后一条。system_imported 是管理员声明的数据来源，导入功能不凭空证明它已由 UGOS 官方接口验证。

scope 不匹配时，不将部分扫描用量除以全卷 quota 作为真实系统使用率。源身份变更需要独立确认，不由一份 JSON 导入自动恢复清理权限。

所有 schema 和示例是规格工件；修改时同时更新主文档、API 类型与测试。
