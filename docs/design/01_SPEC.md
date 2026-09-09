# NAS Storage Analyzer：功能与技术设计规格

> 面向绿联 NAS / Docker 的独立存储分析应用；交付对象：Codex 与项目维护者。  
> 规格版本：1.1（Rust + React）；技术修订日期：2026-09-09；产品功能资料沿用 2026-09-08 基线。  
> 本文是待实现产品的规范，不表示已有可运行软件。文中的性能数字均为验收目标，而非实测结果。

## 0. 文档约定与交付目标

项目暂定名 `NAS Storage Analyzer`，程序名 `nas-analyzer`。独立实现群晖 Storage Analyzer 的公开功能，不使用群晖的程序包、私有代码、图标或品牌资源。界面采用中文管理后台，复现工作流程和信息能力，不以像素级复制 DSM 为目标。

**完整交付目标不是只做一个磁盘饼图或重复文件工具，而是形成闭环：接入目录 → 定时采样/扫描 → 分类与重复分析 → 历史报告 → 导出/通知 → 可选安全清理 → 配置备份恢复。**

规范用语：`必须`为发布阻断要求；`应`为默认实现方式；`可选`只指明确标注的增强项，不能用于跳过对标功能。需求编号用于关联任务、代码、测试和验收。除“后续增强”外，本文定义的 V1 功能均在交付范围内；写操作由管理员显式开启，不等于可以不实现。

本文与配套文件的优先级：安全不变量 > 本文业务语义 > `03_ACCEPTANCE.md` 的可验证场景 > `02_TASKS.md` 的实施顺序 > 配置示例。出现冲突必须记录架构决策并同步文档，不得静默修改口径。

## 1. 参考基线、环境假设与边界

### 1.1 对标基线

截至资料核对日，群晖套件页面及发行说明列出的版本为 Storage Analyzer `2.1.1-0644`。以 DSM 7 系列公开帮助、技术规格和发行说明为功能基线。[S1][S2][S3][S4][S5]

官方资料明确涉及：卷与共享文件夹使用量、用户/配额、文件分组、重复文件、大文件、最近修改文件、最久未访问文件；报告计划、历史记录、CSV 导出；配置备份恢复。发行说明还涉及子目录用量、重复文件删除，以及 Synology Tiering 的适配。[S1][S3][S4][S5]

必须区分以下三类能力：

| 类别 | 含义 | 本项目处理 |
| --- | --- | --- |
| B：基础对标 | 不依赖 DSM 专属服务的分析和报告功能 | V1 全部实现 |
| A：平台适配 | 系统共享列表、身份映射、真实配额、分层存储状态等 | 提供能力检测、导入契约与明确降级，不伪造数据 |
| E：增强功能 | 超出公开基础功能的改进 | 逐项注明；不能混称为群晖原有功能 |

这是一份公开功能对标规格，不是对未公开内部算法的还原。群晖重复判断算法、所有版本的界面细节和绿联未公开接口不作为已知事实。

### 1.2 部署假设

目标是支持 Docker 的绿联 NAS。尚未确定具体型号、UGOS 版本、CPU 架构、内存、内核版本和真实目录，因此不得硬编码宿主机路径、UID/GID 或固件接口。绿联官方资料提供 Docker / Compose 项目部署流程，但仍须以设备实际支持情况为准。[S6]

交付 `linux/amd64` 与 `linux/arm64` 两种镜像；两者构建成功不等于所有绿联机型均支持 Docker。常规配置以设备总内存至少 4 GiB、应用限制约 1 GiB 为设计起点；更低配置需运行基准后再决定扫描规模。数据库应放在 NAS 本地磁盘，优先考虑 SSD，但不能把 SSD 写成强制硬件要求。

业务扫描对象是管理员显式挂载并登记的本地共享目录。默认不扫描宿主机根目录，不挂载 Docker socket，不要求 `privileged`，不读取宿主机 `/etc/shadow`，不自动修改 NAS ACL。

### 1.3 不在本套件范围

不实现 RAID、存储池扩容、磁盘健康诊断、文件系统块级去重、快照创建/删除、SMB 服务管理、病毒扫描、媒体播放器或完整文件管理器。它们不能因名称相近而被算作 Storage Analyzer 的基础功能。

不接管 UGOS 登录，不声称管理界面的本地应用账号等同 NAS 账号。不通过猜测 UGOS API 或读取浏览器凭据来获取配额。

### 1.4 原始数据安全不变量

1. 默认对每个扫描源使用只读 bind mount；应用数据目录单独读写。扫描、统计和报告生成不修改用户内容、权限或时间戳。
2. 只打开普通文件做内容比较；符号链接、FIFO、socket、设备节点不读取内容，不跟随符号链接。
3. 删除功能必须同时通过部署开关、源级权限、应用授权、重新校验和确认计划；只读模式下服务端也必须拒绝写入。
4. 报告里的旧路径与旧哈希不能直接授权删除；不能提供接收任意绝对路径的删除接口。
5. 未知值用 `null` 与原因表达，不以 0、无限制、已释放等误导性值代替。
6. 对备份仓库、活动数据库、分层文件和虚拟机磁盘默认禁止自动清理。

## 2. 功能对标矩阵与范围追踪

| ID | 公开能力/用户目标 | V1 交付行为 | 类型 |
| --- | --- | --- | --- |
| F01 | 卷容量和使用趋势 | 已用/可用/总量，折线与列表，独立采样计划，启动与报告后采样 | B |
| F02 | 报告任务 | 创建、编辑、复制、停用、软删除、立即执行，保存参数版本 | B/E |
| F03 | 周期报告与收件人 | 每日/每周/每月/cron；多收件人；成功、部分成功、失败通知 | B |
| F04 | 分析范围 | 指定源或全部已登记及以后登记的源；记录本次范围快照 | B/A |
| F05 | 加密目录 | 仅分析已由 NAS 解锁并挂载的目录；不可用不视为空目录 | A |
| F06 | 共享目录/子目录用量 | 共享列表、目录树、逐层钻取、文件数与容量 | B |
| F07 | 用户与配额 | UID 归属统计、指定用户按类别清单；导入配额与预算区分 | B/A |
| F08 | 文件分类 | 九个内置分组、自定义扩展名映射、扩展名细分、规则版本 | B |
| F09 | 重复文件 | 可配置名称/修改时间约束；内容校验；跨源分组；数量上限 | B |
| F10 | 大文件与时间排行 | 大文件、最近修改、最久未访问，默认各 200 条；筛选与导出 | B |
| F11 | 历史报告 | 日期筛选、时间轴、报告切换、单页完整报告、保留策略 | B |
| F12 | 报告保存和 CSV | 可选择已挂载输出目录；全部报告栏目可导出；排除输出目录 | B |
| F13 | 管理权限 | 仅应用管理员可访问；报告文件不匿名公开 | B/A |
| F14 | 配置备份与恢复 | 导出/恢复设置、任务与映射；可选完整数据备份；不依赖 Hyper Backup | B/A |
| F15 | 重复文件整理/删除 | 预览、保留副本、移入隔离区、恢复、显式永久清理 | B/E |
| F16 | 外接卷与已移除卷 | 独立源登记，断连标注；历史卷不丢失；重新接入身份核对 | B/A |
| F17 | 分层/云占位文件 | 元数据模式、召回风险提示、适配器状态；默认不哈希占位内容 | A |
| F18 | 可操作性增强 | 任务进度、资源限制、完整性标识、审计、健康诊断 | E，V1 必须 |
| F19 | 报告对比 | 可比性校验、目录/用户/类别增量；保有明细时做文件差异 | E，V1 必须 |

群晖公开规格中的“大文件 200 条、重复文件最多 5,000 条、卷图最多展示 10 个”等属于原产品限制，不是本项目必须保留的缺陷。[S1] 本项目使用 200 / 5,000 作为兼容默认值，同时保留明确的分页、上限和截断标识；全局卷列表不人为限制为 10 个。

“全部未来共享目录”在容器中只表示**以后已挂载且已登记/批准的源**。新建宿主机共享目录不会天然出现在容器中。高级用户可配置已批准父目录的一层子目录发现，但新增项默认待批准，不会自动扩大访问权限。

## 3. 用户、页面与主流程

### 3.1 用户模型

V1 只开放本地应用管理员角色，支持一个初始管理员和后续新增管理员。每位管理员都能看到全部分析源；本应用不是多租户工具。最后一个管理员不能删除或停用。NAS 文件属主仅是被分析的维度，不自动拥有应用访问权限。

未来增加只读审计员或源级授权时，必须同时改造列表、搜索、统计、导出和通知，而不能只隐藏前端菜单。

### 3.2 信息架构

| 页面 | 主要内容 | 主要操作 |
| --- | --- | --- |
| 初始化向导 | 时区、管理员、源挂载诊断、输出目录 | 完成初始化、创建首个任务 |
| 总览 `/overview` | 容量卡片、趋势、数据时间、最近任务、异常 | 切换卷/时间范围、立即扫描 |
| 数据源 `/sources` | 源列表、身份、文件系统、权限、可用性 | 登记、探测、编辑、停用 |
| 报告任务 `/profiles` | 调度、状态、保留策略、最近结果 | 创建/复制/编辑/执行/删除 |
| 任务中心 `/jobs` | 队列、阶段、吞吐、错误、控制 | 暂停、继续、取消、重试 |
| 报告中心 `/reports` | 历史、时间轴、完整性、版本 | 打开、比较、导出、固定保留 |
| 报告详情 `/reports/:id` | 概览、目录、用户配额、类别、重复、排行 | 筛选、钻取、CSV、单页报告 |
| 清理中心 `/cleanup` | 清理计划、隔离文件、冲突和恢复 | 预演、确认、恢复、永久清理 |
| 设置 `/settings` | 分类、身份配额、邮件、存储、备份、账户 | 测试、导入导出、调整参数 |
| 诊断与审计 `/diagnostics` | 能力矩阵、版本、资源、失败记录 | 导出脱敏诊断、查看审计 |

### 3.3 初始化流程

容器启动后先进行配置和数据库自检。尚未初始化时，只开放健康检查、初始化状态和设置接口，普通业务接口返回 `SETUP_REQUIRED`。

初始化令牌由本地 CLI 命令生成，写到 `/data/setup-token`，文件权限 `0600`；不打印到常规日志。管理员通过容器终端读取，或使用部署时指定的秘密文件。令牌单次有效，默认 30 分钟；CLI 可重新生成。网页创建管理员时必须提交令牌并设置至少 12 字符密码。数据库和令牌状态的变更应原子完成，防止两个浏览器同时抢注。

向导探测每个源的挂载可见性、目录可遍历性、卷归属、预期只读状态、文件系统与时间戳能力。只读检查依据挂载信息，不在用户目录创建测试文件。数据目录的读写检查仅允许在 `/data` 下创建应用自有探测文件。

默认建议首个任务做元数据扫描；用户理解额外磁盘读取后再启用重复内容检测。

### 3.4 报告任务向导

步骤依次为：名称与描述 → 范围 → 报告栏目 → 重复检测参数 → 指定用户清单 → 调度 → 保存/通知与资源 → 预览。

预览必须显示：本次候选源、不可用源、排除规则、哈希读取策略、报告保存位置、明细保留数量、预计采用的资源限制。首次尚不知道文件数时不得编造预计耗时。

## 4. 数据源、卷与能力适配

### 4.1 三种不同对象

`Mount` 是部署层已经挂载进容器的目录。`Source` 是管理员登记的分析根目录，只能位于批准挂载范围内。`Volume` 是用于容量采样的逻辑文件系统标识，可以关联多个 Source。

宿主机路径只用于可选展示，不参与服务端文件操作。服务端操作只使用部署配置白名单中的容器路径与原始相对路径。

### 4.2 Source 字段

| 字段 | 类型/默认值 | 规则 |
| --- | --- | --- |
| `id` | UUID | 创建后不变；路径和名称不能当主键 |
| `name` | 1–80 字符 | 全局唯一显示名 |
| `mount_key` | 字符串 | 引用部署配置中的批准挂载 |
| `relative_root` | 原始相对路径，通常为空 | 不能是绝对路径，不能含越界组件 |
| `volume_id` | UUID / null | 未确认卷关系时不计入全局容量求和 |
| `storage_kind` | `local/remote/tiered/unknown` | 非 local 默认禁止内容读取 |
| `read_policy` | `metadata_only/content_allowed` | 与任务开关共同控制哈希 |
| `write_enabled` | false | 仅允许对部署明确可写的源开启 |
| `protected` | false | 备份、数据库等源应设 true；禁用内容清理 |
| `exclusions` | 规则数组 | 与系统强制排除、任务排除一起使用 |
| `identity_status` | `verified/provisional/changed` | 变化后要求管理员重新确认 |
| `availability` | `online/offline/permission_denied/unknown` | 不可用值不转换成零容量 |
| `atime_quality` | `reliable/relative/disabled/unknown` | 以运行环境探测和说明为依据 |

登记父子重叠源默认拒绝；同一目录的重复 bind mount 默认拒绝或只保留一个 canonical source。人工允许的逻辑视图不能参与全局不重叠合计，以免重复统计。

### 4.3 卷识别与防重复计数

每个 Volume 使用持久 UUID，由管理员确认其容量采样源 `capacity_source_id`。文件系统 ID、设备号、mountinfo 和导入的宿主 UUID 用于辅助识别，不能单独以挂载路径或一次启动的 `st_dev` 作为永久身份。

同一卷的多个共享文件夹不得把卷总容量累加多次。Btrfs 子卷、配额限制、远程挂载可能改变容量视图；检测到不同容量视图时要求管理员分别登记，或明确指定代表源，不自动合并。

能力不足以确认身份时，总览显示“已确认卷容量”与“未归属源数”，不能展示一个看似完整的 NAS 总容量。

外接盘断连后保留 Volume 与历史采样，但新采样为空洞。即使新设备用了旧路径，也不得自动继承旧设备身份。Docker 的挂载传播行为受配置影响，插入新盘可能需要重新部署；界面须给出诊断而非承诺热插拔自动发现。[S7]

### 4.4 NAS 身份与配额适配

V1 必须实现可版本化的 JSON 导入和管理界面，支持：UID/GID 映射、共享/卷关系、用户配额记录、数据来源、观察时间与有效期。配套 `metadata-import.schema.json` 定义契约。

身份映射优先级：显式导入映射 > 应用内手动映射 > `uid:<数字>`。不得把容器 `/etc/passwd` 的用户名直接当成 NAS 用户。发现 user namespace/remap 时，说明当前统计的是容器可见 UID；只有明确映射后才显示宿主身份。

配额分为三种：`system_imported`（导入的实际系统配额）、`advisory`（管理员设置的分析预算）、`unknown`。预算不会限制写入，不得显示成“系统配额已设置”。没有配额值不是“无限制”；必须用独立 `unlimited` 状态。

配额包含作用域、计量口径、限制值、已用值、采集时间、来源。只有分子和分母作用域一致且来源可解释时，才显示使用率；扫描只覆盖部分目录时，展示“已扫描范围用量”，不冒充整个卷的配额用量。

原生 UGOS 实时连接器不作为已验证能力。后续只有取得可授权、稳定的接口与真实环境测试后才实现。V1 的导入能力必须真实可用，不能用随机数字填充占位图表。

### 4.5 分层存储与内容召回

群晖较新版本增加了 Synology Tiering 支持，但通用容器不能据此获得相同的分层元数据接口。[S5] 本项目的 tiered/unknown 源默认只读元数据，不计算内容哈希。报告展示 `content_analysis=skipped_policy`。

管理员可显式确认内容读取可能触发远端下载后开启；如果适配器能识别 offline/stub 文件，则逐文件跳过。无法识别时必须显示风险，不能声称“绝不会召回”。

## 5. 统计口径：实现前必须统一

### 5.1 容量定义

| 指标 | 定义 | 使用场景 |
| --- | --- | --- |
| 文件逻辑大小 | 普通文件 `st_size` | 默认分类、排行和目录视图 |
| 条目逻辑总量 | 对范围内每个普通文件路径求和 | 体现路径视角；硬链接多个路径会重复计算 |
| 唯一文件逻辑量 | 对可靠文件身份去重后求和 | 解释硬链接影响；不可与条目口径混用 |
| 已分配字节估算 | Linux 上 `st_blocks × 512`，按可靠身份去重 | 稀疏文件/硬链接说明；不是独占物理块 |
| 卷总容量 | `f_blocks × f_frsize` | 容量采样 |
| 卷空闲容量 | `f_bfree × f_frsize` | 文件系统报告的空闲 |
| 当前身份可用 | `f_bavail × f_frsize` | 当前容器身份可用空间 |
| 卷已用 | 总容量 − 空闲容量 | 卷使用率分子 |
| 预留/不可用差额 | 空闲容量 − 当前身份可用 | 单独展示，不能并入已用后假装相等 |

Linux `st_blocks` 与逻辑大小并非相同概念；快照和共享数据块还会影响空间解释。[S9][S12] **本项目不提供未经证明的“精确物理占用”或“保证释放字节数”。**

分类、用户、目录合计的默认口径都是普通文件的条目逻辑大小。UI 切换口径后，图表、表格、CSV 和合计必须同步切换。无法计算另一口径时应禁用选项并说明原因。

文件数默认指普通文件路径数；目录、符号链接、特殊文件分别计数。目录对象本身的元数据块不计入默认文件容量。目录总量包括其子树所有纳入统计的普通文件；父子目录行不可再次相加。

### 5.2 硬链接与相同物理对象

当前扫描内使用已确认文件系统实例、设备号、inode 的组合识别同一对象，必要时加入子卷身份。远程文件系统或身份不可靠时标注 `identity_quality=unknown`，不能强行去重。

硬链接多个路径不是多份独立内容；它们不构成可安全释放容量的重复组。记录 `nlink` 与扫描范围内可见链接数。可见数少于 nlink 表示还有范围外引用；清理默认拒绝 nlink > 1 的文件。

同一底层文件被不同扩展名的硬链接引用时，条目分类可不同；唯一占用视图使用稳定 canonical 条目归属，并提示该分配只是统计约定。

### 5.3 文件时间

`mtime` 为内容修改时间，`atime` 为访问时间，`ctime` 为 inode 状态变化时间；不能把 ctime 显示成创建时间。创建时间仅在文件系统确实提供时显示，否则为 null。

最久未访问排序为 `atime` 升序；最近修改为 `mtime` 降序。noatime、relatime 等选项影响访问时间可信度。[S10] 页面必须显示质量说明，禁止依据“最久未访问”自动删除。

扫描先记录访问时间，再考虑内容读取。只读挂载之外，哈希操作应尝试不更新 atime 的打开方式；失败时不通过 utime 恢复原值，以免主动改写元数据，而应告知可能影响后续访问时间分析。

### 5.4 完整性与一致性

普通活跃目录扫描是一个时间窗口内的观察，不是原子快照。报告必须保存 `scan_started_at`、`scan_finished_at`、观察范围与一致性等级 `live_observation`。除非使用经验证的只读快照源，不得显示“某一瞬间全盘精确状态”。

状态与完整性分开：任务成功不必然代表每个文件可读。每个源和栏目记录 `complete/partial/skipped/unavailable`、错误数与原因。根目录不可用不能当成 0 文件；子目录拒绝访问不能当成空目录。全范围不可访问则任务失败；部分可访问可发布 PARTIAL 报告。

主动排除不是扫描错误，但必须记录排除规则和排除计数；不能声称知道被排除子树的真实字节量。扫描中消失的文件记为 `vanished`，变化中的文件记为 `unstable`。

## 6. 总览与卷历史（F01、F16）

总览显示已确认卷的总量、已用、当前身份可用、预留差额、使用率及采样时间；默认不把断连卷的旧数值加入当前合计。每个卡片可查看数据来源和容量口径。

容量采样与文件扫描必须解耦。默认间隔 60 分钟，可设 15 分钟至 24 小时，亦可每日固定时间。启动和完成包含卷栏目的报告后补采样；同一卷同一采样分钟去重。采样只使用容量接口，不为刷新总览而重新遍历所有文件。

支持最近 24 小时、7/30/90 天、自定义范围；折线图与列表切换。无历史显示当前容量柱/卡片；缺失点保留空洞，不能补成 0 或线性插值成已观测事实。

原始小时数据默认保留 180 天，按日压缩数据默认保留 5 年，均可配置。日汇总必须保留 min/max/last，默认趋势线使用 last，并在图例注明；不能用平均值掩盖曾经满盘。

可选的容量预警属于增强：默认关闭；启用后使用 80% / 90% 两级可编辑阈值、去抖和每日频率限制。增长预测只在样本充足时显示估算，不属于基础发布门槛。

## 7. 报告任务与调度（F02、F03、F04、F05）

### 7.1 Profile 核心参数

| 分组 | 必须保存的字段 |
| --- | --- |
| 标识 | id、name、description、enabled、version、created_at、updated_at |
| 范围 | scope_mode、source_ids、include_future_registered、include/exclude、file_kind_policy |
| 栏目 | volume、folders、owners、quota、categories、duplicates、largest、recently_modified、least_accessed |
| 用户清单 | owner_ids_to_list；这是附加分组清单，不默认过滤整个报告 |
| 重复 | enabled、match_name、match_mtime、min_size_bytes、max_size_bytes、max_listed_files、hash_budget_bytes、content_read_policy |
| 排行 | rank_limit 默认 200；范围 1–10,000 |
| 调度 | type、cron_expression、timezone、misfire_policy、overlap_policy、next_run_at |
| 保留 | report_keep_count 默认 30、detail_keep_count 默认 3、pinned 例外 |
| 通知 | recipients、notify_on、attach_summary、public_base_url |
| 资源 | metadata_workers、hash_workers、read_limit_mib_s、io_priority |

至少选择一个栏目；任何依赖文件明细的栏目自动启用元数据收集。创建/编辑需校验所有源存在、分类规则有效、排除语法可编译、通知格式有效。对已经运行的任务编辑参数，只作用于下一次；运行实例保存参数副本和版本。

删除 Profile 默认软删除并停止未来调度，保留已有报告。删除对话框必须分开询问是否清理历史；不能让“删除任务”隐式删除源数据。内部目录按 UUID 命名，因此旧任务重名不会与原产品的同名目录限制绑定。

### 7.2 调度语义

提供每日、每周多选、每月某日和高级五段 cron。每月 31 日在没有该日的月份默认跳过，UI 明示；高级表达式在服务端校验，并预览未来五次执行时间。

时区使用 IANA 名称。部署时区作为默认值；每个任务保存自己的时区，所有落库时间使用 UTC。夏令时重复小时只执行一次同一墙上时刻；不存在的本地时刻跳过并记录。必须测试，而不是完全依赖调度库默认行为。

默认同一 Profile 不重叠，全局同时只运行一个扫描任务。队列最大 20 个。重叠触发默认合并成至多一次后续执行；手动重复点击通过 Idempotency-Key 返回相同 job。

错过计划默认 `skip`；可选 `run_once`，最多补跑一次且默认只接受过去 6 小时内最近的一次，不重放一整晚或数月的任务。

调度去重键必须包含任务版本和逻辑触发点；对于夏令时策略，另外使用本地日期/时间 occurrence key 防止回拨造成重复。

### 7.3 运行状态

任务生命周期：`QUEUED → RUNNING → SUCCEEDED | PARTIAL | FAILED`；控制分支为 `RUNNING → PAUSING → PAUSED → RUNNING` 与 `QUEUED/RUNNING/PAUSED → CANCELLING → CANCELLED`。进程意外消失后未结束任务转为 `INTERRUPTED`。

RUNNING 内部阶段：`PRECHECK → ENUMERATE → HASH → AGGREGATE → PUBLISH → NOTIFY`。未开启重复分析时跳过 HASH。通知结果单独记录；邮件失败不把已完成的数据报告改成失败。

进度展示阶段、已访问目录数、文件数、错误数、已读取字节和耗时。枚举总量未知时使用不定进度；不得把已处理数除以上次扫描数量假装精确进度。哈希阶段可使用已确定候选字节数，并标注候选集合是否变化。

暂停在文件/分块边界响应。暂停期间保留当前 worker 和唯一扫描槽位，不允许无限累积暂停进程；继续操作直接恢复 RUNNING，其他扫描保持排队。V1 允许同一 worker 存活期间继续；应用重启后不承诺从任意目录游标精确续扫，必须标记中断并创建关联的新扫描重新遍历。复用可信哈希缓存可以提速，但不能把“从头重扫”显示为“精确断点续传”。

## 8. 文件分类、目录、用户与排行（F06、F07、F08、F10）

### 8.1 目录视图

共享目录列表显示名称、文件数、子目录数、逻辑大小、占比、扫描完整性和变化量。点击后进入逐层目录树；默认展示直接子目录和当前目录文件汇总，提供面包屑、路径复制、分页和按大小排序。

目录明细基于已保存扫描结果，不在用户每次展开树时重新读取源目录。完整路径过长时在表格截断，悬浮/详情可查看；复制保持原始可展示文本，不把展示截断写回后端。

### 8.2 分类规则

内置分类 ID 固定为：`audio`、`disk_images`、`documents`、`executables`、`pictures`、`videos`、`web_and_code`、`archives`、`other`。这是对标九类的独立默认配置；扩展名清单不要求逐字复制某个 DSM 版本。

初始常用映射至少覆盖：音频 mp3/flac/wav/m4a/ape/ogg/aac/dsf；镜像 iso/img/bin/dmg/vhd/vhdx/qcow2；文档 pdf/doc/docx/xls/xlsx/ppt/pptx/txt/md/rtf/odt；程序 exe/msi/apk/appimage；图片 jpg/jpeg/png/gif/webp/heic/heif/tif/tiff/svg/raw/dng/psd；视频 mp4/mkv/avi/mov/ts/m2ts/webm/rmvb；网页代码 html/css/js/ts/vue/json/xml/py/go/java/c/cpp；压缩 zip/7z/rar/tar/gz/bz2/xz/tar.gz/tar.xz。剩余归 other。

管理员可增删映射、重分类和恢复默认。多段扩展名最长匹配优先，如 tar.gz 优先于 gz；比较使用 ASCII 小写，但原文件名不改写。没有扩展名、点文件、未知扩展名必须有确定行为：例如 `.env` 默认无扩展名归 other，`.config.json` 按 json 分类。

扩展名规则禁止斜杠、反斜杠、控制字符和空白；允许小写字母、数字、`-`、`+`、`_` 及多段分隔点。一个扩展名只能属于一个类别，冲突在保存时拒绝。仅按扩展名分类，不执行文件、不解析宏、不批量解压、不默认 MIME 嗅探。

每份报告保存规则版本快照；修改映射不改写历史。需要重新分类时生成派生报告并保留来源关系，不能覆盖原报告。

### 8.3 用户与配额视图

按 UID 汇总文件数、条目逻辑大小、类别占比和各源分布。文件归属是扫描时的 uid，不表示最后上传者、最后修改者或商业上的所有者。未知 UID 仍须完整统计。

“指定用户按分组列文件”是附加明细：选择用户后可查看其各类文件列表，受报告/明细保留能力限制。必须与“仅扫描指定用户”分开；后者若实现，属于显式的范围过滤并改变 scope fingerprint。

真实配额、人工预算和扫描用量分别标识数据来源及时间。配额导入过期后显示 stale；历史报告固定其当时值，不能以今天的配额静默重算过去的使用率。

### 8.4 三种排行与统一筛选

大文件按 size 降序；最近修改按 mtime 降序；最久未访问按 atime 升序，未知 atime 默认不参与排序但计入提示数。排序相同时以 source_id 与原始路径字节序稳定排序。

支持源、目录子树、类别、扩展名、UID、大小范围、修改时间范围、访问时间范围、名称包含搜索。默认是字面量搜索，不把输入当正则或 SQL。

所有过滤条件在服务端执行；图表点击生成可见筛选标签；“清除筛选”恢复原范围。筛选后的合计和导出必须使用同一个 QuerySpec。明细保留已过期时，历史固定排行仍可查看，但不得假装能在全量明细上重新筛选。

表格默认 50 条/页，上限 200；使用稳定游标分页。最多渲染当前页/虚拟视口，禁止一次把百万条记录发到浏览器。

## 9. 重复文件引擎（F09）

### 9.1 判断语义

“候选重复”与“已确认内容重复”必须分开。文件名相同、长度相同、修改时间相同、抽样哈希相同均不足以单独确认内容重复。本项目独立选择 SHA-256 全文件哈希；不能把该选择写成对群晖内部算法的事实判断。

开启 `match_name` 表示候选文件还须具有完全相同的原始 basename；默认关闭。开启 `match_mtime` 表示还须具有相同的秒/纳秒修改时间；默认关闭。这两个选项是附加筛选，不代替内容比较。不同选项可能排除内容相同但名称/时间不同的文件，UI 必须解释。

零字节文件可作为重复组展示，但潜在内容节省量为 0，默认不加入清理建议。不同设备/源间的独立文件可参与同一重复组；相同 inode 的硬链接路径先折叠为一个物理对象。

### 9.2 分阶段算法

**阶段 A：候选分桶。** 对已完成枚举的普通文件，按逻辑大小分组；只处理至少两个独立文件对象的桶。应用任务的大小、名称、时间和保护规则。size-only 分桶在磁盘索引/SQL 中完成，不把所有文件放进 Rust HashMap 或 Vec。

**阶段 B：低成本抽样。** 对大于 192 KiB 的文件，读取首部、中部、尾部各最多 64 KiB 的不重叠片段；小文件直接进入全量哈希。抽样输入须包括算法版本、文件长度、片段偏移和片段内容。抽样一致仅用于减少全量读取，不产生可删除结论。

**阶段 C：完整哈希。** 对抽样相同的候选，以固定 1 MiB 缓冲顺序读取 SHA-256。每次最多打开受限数量文件，遵守全局读取限速。读取前后通过已打开 FD 检查 identity、size、mtime、ctime；变化则重试一次，仍变化记为 unstable 并排除确认组。

**阶段 D：确认与索引。** 按 size + 完整 SHA-256 分组，只保留至少两个独立对象。标记 `verification=full_hash`。哈希相同在工程上作为内容等同依据；进入实际清理前再进行新的完整比较，不能只依赖报告里的结果。

**阶段 E：报告。** 持久化分组总数、文件总数、可列出成员数、截断原因、内容读取量、跳过与不稳定数。列表默认最多 5,000 个成员，允许配置上限 1–100,000。不能为了凑满列表而截断组的一半并仍显示可自动清理；超限组可保留组摘要，并显示完整成员需要明细索引。

`max_listed_files` 只限制报告输出量，不应隐式停止扫描。真正限制计算的是独立 `hash_budget_bytes`、运行时长或用户取消。预算耗尽时 duplicate 栏目标为 PARTIAL；不能把已找到的局部重复量当成全范围总量。

### 9.3 缓存与缓存可信度

缓存键至少包含 source identity epoch、文件身份、size、mtime、ctime、算法与算法版本。文件系统身份不可靠、粗时间戳或远程源默认不跨扫描复用。

缓存命中是性能优化，不是永久内容证明。报告可标记 `verification=cache_reused`，并配置定期强制刷新。强一致模式每次重新读取全部候选；所有清理计划无条件重新校验，不能信任缓存。

inode 会被复用，不能只以 inode 或路径作为缓存键。源身份变化、挂载重绑、算法更新和关键元数据变化都必须失效。缓存采用容量上限和 LRU/时间淘汰，默认最多 2 GiB。

### 9.4 组信息与空间提示

重复组展示：共同长度、内容哈希摘要、独立副本数、路径成员、文件属主、修改时间、来源、是否受保护、是否硬链接、验证时间和验证方式。

若独立副本数为 n，逻辑冗余量为 `(n − 1) × size`。仅称“逻辑冗余量”，不能称“可保证释放空间”。分配块估算可另外展示，但 Btrfs reflink、压缩、快照、未纳入扫描的硬链接都可能影响实际释放。[S12]

默认建议保留规则：用户标记的保留目录 > 非临时目录 > 更短路径 > 原始路径字节序；默认不按“最新”武断判断哪个副本更重要。建议只预选，不自动执行。

### 9.5 必须禁止的实现捷径

不得只比较头尾就声称文件相同；不得把相同文件名当重复；不得整文件读入内存；不得 `find | xargs rm`；不得使用 shell 拼接用户路径；不得默认扫描备份仓库内容并给出自动删除建议。

## 10. 扫描引擎、过滤与异常（F18）

### 10.1 遍历和资源模型

采用有界目录队列和批量 readdir，不对百万文件目录一次性读取所有条目并排序。单个扫描 worker 负责一个运行实例，可使用有限并发元数据读取；默认每卷 1 个遍历并发、全局最多 2 个。哈希默认全局 1 个 worker，最大 4 个且受配置约束。

目录遍历队列可持久化为小批任务，但不能用不稳定的目录偏移承诺重启后的无遗漏续扫。所有路径写入以 `(run_id, source_id, raw_relative_path)` 幂等约束，避免重试产生重复行。

默认不跨 mount boundary。只比较 st_dev 不足以发现所有 bind mount；应结合 mountinfo 或 openat2 的 NO_XDEV 语义。[S11] 子挂载需要登记为独立批准源。符号链接只记录链接条目，不跟随，即使链接目标仍位于源内。

### 10.2 包含/排除规则

范围内首先应用不可覆盖的系统保护规则，再应用源规则、任务排除、任务包含和文件条件。排除优先于包含。glob 以源内相对路径匹配，`/` 为目录分隔，`**` 表示任意层级；字面文件名与模式输入分开，匹配语义必须有测试。

应用自己的数据、报告、缓存、临时文件、备份包与 `.nas-analyzer-quarantine` 永久排除，不能通过 UI 取消。若同一目录通过别名再次暴露，需要用身份/规范挂载关系检测，而不只做字符串前缀比较。

预置“跳过系统索引与回收站”规则可覆盖 `@eaDir`、`#recycle`、`$RECYCLE.BIN` 等常见名称，但这些不是绿联目录结构保证；界面展示规则，用户可调整普通规则。备份目录和活动数据库用独立 protected 策略，不能只靠扩展名防护。

包含条件只影响文件是否纳入统计，不得因为父目录名称不匹配就跳过其可能匹配的后代。`include_hidden` 默认 true，除明确排除外纳入隐藏普通文件。

### 10.3 原始文件名与安全路径

数据库保存原始相对路径字节 BLOB；API 使用 opaque entry_id 定位文件，另提供经过安全转义的展示字符串。无效 UTF-8 路径使用 replacement/转义展示并附 `path_encoding_warning`，可选 Base64 原始路径字段仅用于管理员导出，不用于前端回传构造删除路径。

文件名中的换行、逗号、引号、反斜杠、emoji、组合字符都必须正确处理；Linux 中反斜杠可为普通文件名字符，不能随意按 Windows 分隔符拆解。文件名不得做 Unicode 归一化后当作唯一键。

所有读取和写入由独立 `fssecure` crate 处理。使用 `rustix` 对根目录 FD、Linux openat2/openat 系列的封装；相对于已批准根解析时显式要求 BENEATH、NO_SYMLINKS 和默认 NO_XDEV。打开根目录本身、枚举、创建、rename、恢复和 purge 也必须接受同一安全模型审查，不是只给最终 open 加一个 flag。[S8][S11]

目录迭代必须从已经安全打开的目录 FD 出发；不能校验完字符串后再调用 `std::fs::read_dir` 重新按不受保护路径打开。普通文件内容只通过经安全层取得且核验为 regular file 的 FD 读取。Linux 路径用 OsStr/OsString 与原始字节表达；`to_string_lossy()` 只允许用于展示，不得用于数据库唯一键或文件操作。

Rust 的类型与所有权检查不证明路径仍指向原文件，也不保证外部进程不会修改内容。不得把“Rust 内存安全”当作免除第 13 节 TOCTOU、移动后身份核验及崩溃日志的理由。

对于没有所需内核能力的系统，可用经过测试的逐组件 no-follow 读取回退；可写清理模式必须失败关闭，不能降低安全标准后继续。

### 10.4 错误分类

| 错误 | 处理 | 报告影响 |
| --- | --- | --- |
| 根目录不存在/未解锁 | 标记源 unavailable，不当成空 | 全部失败则 FAILED，部分失败则 PARTIAL |
| 子目录 EACCES | 记录路径与 errno，继续其他目录 | 目录与依赖栏目 PARTIAL |
| 单文件哈希 EACCES | 保留元数据统计，跳过内容分析 | duplicate 栏目 PARTIAL |
| 文件在扫描中消失 | 记录 vanished，避免再次读取 | 增加不稳定计数 |
| 文件读取中变化 | 一次重试后排除确认重复 | 不生成清理候选 |
| 数据盘 ENOSPC | 停止写入，保留可恢复状态 | FAILED，不发布完整报告 |
| 网络/FUSE 长时间阻塞 | 隔离 worker，管理端保持可用 | 显示不可响应；不承诺硬实时终止 |
| 源身份变更 | 停止该源，清除缓存信任 | 需要重新确认，禁止清理 |
| 扫描预算耗尽 | 正常关闭句柄并发布部分结果 | 明示 PARTIAL 和截止阶段 |

错误明细默认最多保存 10,000 条，超出仍完整累加分类计数。日志不无界增长；支持下载错误 CSV。不要为了方便捕获异常而忽略所有错误并显示成功。

### 10.5 活跃文件与重试

元数据扫描允许记录某个观察时刻的活跃文件，但必须在内容校验中排除变化文件。目录本身在扫描中变化可导致快照不一致，因此所有 live report 均保留此性质说明；不能通过两次 stat 就宣称获得全文件系统快照。

重试创建新 job/run，并关联 `retry_of`；旧报告不可变。暂停/取消目标是在普通本地文件系统上 5 秒内反馈控制状态；阻塞内核 I/O 不受纯应用超时完全控制，诊断必须真实显示。

## 11. 报告、历史、比较与导出（F11、F12、F19）

### 11.1 不可变报告

每份报告保存 UUID、任务和配置版本、范围快照、分类版本、源身份、扫描起止时间、采样时间、各栏目完整性、统计口径、警告、聚合数据、默认排行和重复列表。

报告完成后不随设置、用户名映射、源重命名或实时删除操作而改变。用户执行清理只追加关联的操作事件，原报告仍表示当时观察结果。界面可以叠加“此条目之后已移入隔离区”的状态，但不得修改历史数值。

### 11.2 原子发布

运行输出写入 `/data/runs/<run_id>/staging`。完成聚合与校验后生成 manifest、摘要库、固定排行和静态报告。必须先完成落盘与文件校验，再通过同一文件系统内的原子 rename 发布目录，最后登记控制库中的可见状态。

目录发布与数据库提交不是一个跨文件原子事务：启动恢复任务必须对照 manifest 重建/回滚中间状态。未完整发布的报告不出现在正常列表。临时垃圾只在确认不被运行任务使用后清理。

外部报告输出目录只是发布成功后的导出副本；跨文件系统写出使用临时文件、校验和及同目标文件系统内 rename。外部输出失败不破坏 `/data` 中已成功发布的报告，单独通知。

### 11.3 历史与保留

默认保留最近 30 份摘要报告，最近 3 次运行的完整明细。摘要必须保留原有主要功能所需的目录/用户/分类汇总、固定排行、报告内重复列表、完整性和规则快照；不能因为清掉全量索引就让整份历史报告无法查看。

保留策略 UI 必须清楚区分“报告摘要”和“完整文件明细”。超出默认重复列表上限的组、任意条件全文细查、文件级差异，依赖明细保留。已过期能力用 `DETAIL_EXPIRED` 明确提示，不返回空列表冒充无数据。

固定保留的报告不被自动清理；其明细是否固定须单独选项。默认应用数据预算 20 GiB，可配置。达到预算先清理可删除缓存与过期导出，再按策略处理旧明细；不能自动删除被固定的数据或悄悄丢弃新扫描。空间不足时拒绝新任务并告警。

下载、查询和比较对明细获取有期限的使用租约；垃圾清理不得删掉正在使用的文件。导出副本采用登记清单，只删除应用自己生成且校验属于对应 report_id 的文件。

### 11.4 报告对比

默认只比较同一任务、同一统计口径、兼容源身份/范围/规则的报告。定义 `scope_fingerprint` 与 `classification_version`，不一致时展示“不完全可比”的横幅，不把排除规则变化造成的差异称为用户删除。

聚合差异包括目录、类别、用户文件数与字节增减。全量文件差异仅在两侧均有明细时计算：新增、消失、大小/mtime 等元数据变化。没有完整哈希时不能把元数据相同称作“内容完全相同”。

重命名只有在可靠文件身份或强内容证据支持时标记为“疑似重命名”；否则列为新增+消失。某侧不可访问的范围不得计为批量删除。

### 11.5 导出规格

所有报告栏目均提供 CSV。基础字段包括 report_id、source_name、relative_path_display、owner_uid、category、logical_size_bytes、allocated_size_estimate_bytes、mtime、atime、status；每类再加入对应聚合/分组字段。数值字节使用整数，不只有“1.2 GB”格式化文本。

CSV 使用 UTF-8，默认带 BOM，遵循标准引号转义和 CRLF 行结束。文件名中的换行必须保持在加引号字段内。文本字段在去掉前导空白后以 `= + - @` 或控制字符开头时，使用 spreadsheet-safe 前缀防止公式执行；原始忠实数据另通过 JSON 导出，不提供默认不安全 CSV。

支持当前筛选导出与整个栏目导出；导出清单说明筛选、截断、数据口径和时区。后台流式生成，返回 export job；不能在单个 HTTP 请求内把百万行拼成大字符串。

提供单页完整 HTML 报告与 ZIP 报告包，内含 manifest、HTML、各栏目 CSV/JSON、校验和。静态 HTML 不引用 CDN，不含脚本执行来源文件名的机会，不包含 SMTP 密钥和登录 token。打印使用浏览器打印样式；服务端 PDF 渲染不属于 V1 必须能力。

历史报告链接必须是经过认证的应用路由，而非公开目录路径。导出文件下载通过授权处理器，短期下载 URL 不能绕过应用管理员权限。

## 12. 邮件与通知（F03）

管理员配置 SMTP host、port、TLS 模式、用户名、密钥、From、默认收件人、主题前缀和应用可访问的 `public_base_url`。默认要求 TLS 并校验证书；明确的内网调试模式可允许非 TLS，但必须警告，且不得自动回退。

邮件包含任务名、扫描范围、起止时间、成功/部分/失败状态、主要容量、重复逻辑冗余、错误摘要和认证报告链接。默认不发送全量文件路径附件；只有管理员显式选择才附简要 CSV，默认上限 5 MiB。邮件正文对名称和路径转义。

收件人存数组，多个地址独立校验；不得把用户输入未经验证直接拼到邮件头，防止 CRLF 注入。点击“发送测试邮件”要真实发送并展示结果，不返回假成功。

通知使用持久 outbox，默认失败重试 1、5、30 分钟三次。按 report_id + recipient + notification_type 去重。SMTP 在“服务器可能已接收但客户端未收到确认”的边界无法保证绝不重复，记录 delivery_unknown，并避免无限重发；不能承诺 exactly-once 邮件。

内部通知列表至少显示源不可用、报告部分成功、存储不足和清理冲突。通用 webhook、企业微信、Telegram 等是后续增强，不阻塞基础对标。

## 13. 安全整理、隔离与永久清理（F15）

### 13.1 能力开关与保护边界

默认只读运行。开启清理必须同时满足：部署 `allow_write_operations=true`；特定 Source 的 mount 为 rw 且 `write_enabled=true`；源不是 protected；运行环境支持要求的安全文件操作；当前用户通过近期重新认证。

可写源应限制为真正允许整理的目录，不能为方便清理而把整个 NAS 根目录以 rw 挂入。严格只读分析时不应加载可写清理分支。

V1 只对已确认重复的普通文件提供内容清理。不提供大文件/冷文件的一键自动删除，不自动改成硬链接或 reflink，不递归删除目录。硬链接 nlink > 1、符号链接、范围外文件、备份仓库、分层占位文件和正在变化的文件一律拒绝。

### 13.2 清理计划

前端提交 report_id、duplicate_group_ids、选择保留的 entry_id、拟处理的 entry_id，不提交可执行路径。后端校验条目属于同一组且每组至少保留一份；保护目录优先，任何组不能全部选中。

`preview` 返回不可变 plan_id、选中数、逻辑总量、无法处理条目、保留副本、风险说明、预期动作 `quarantine`、校验版本、5 分钟到期时间。计划内容使用服务端持久记录/签名防篡改；用户修改选择后原计划作废。

提交执行需 plan_id、确认文本和重新认证 token。重复提交采用 Idempotency-Key，返回同一个 action job。确认之后源权限、挂载身份、分类保护、条目身份或内容发生变化都必须重新拒绝。

### 13.3 执行时重新确认

执行前在批准根目录 FD 下重新打开候选与保留副本，no-follow，验证 identity/size/mtime/ctime 与计划观察一致。新的内容比较至少完整读取并逐字节比较候选与保留副本，读取前后再次 fstat。文件变化就跳过，不能因为“哈希以前一样”继续。

建立同一文件系统、该源下专用的 `.nas-analyzer-quarantine/<action_id>/<item_id>`；目录 mode 0700，由专用应用 UID 持有。隔离区不是 UGOS 系统回收站，不声称能在 UGOS 原生回收站恢复。

通过 no-replace 原子 rename 移动候选；不允许跨设备 copy-then-delete 回退。移动后再次核验隔离目标的身份是否就是刚才打开的对象。若发生替换竞争，保留已移入对象并尝试安全回滚；原路径已被占用则标记 conflict，保留两者，不覆盖、不继续删除。

安全层必须使用根内约束与受控目录 FD；不能只在操作之前调用 realpath 再普通 rename。即使如此，应用也不能锁住其他 NAS 服务的全部写入行为：并发文件变化必须可检测、可停止、可恢复，不能宣传绝对消除所有外部并发风险。

### 13.4 状态、恢复与崩溃一致性

每个条目的状态为 `PLANNED → VALIDATING → MOVING → QUARANTINED → RESTORED | PURGED`，另有 SKIPPED、FAILED、CONFLICT。移动前写入动作日志并 fsync；移动后更新日志。重启后核对原路径、隔离路径和对象身份，不能仅看数据库状态重复执行。

恢复只能回到原 source_id 和原始相对路径；原位置已存在时默认拒绝，允许管理员选择新名称但不得覆盖。父目录已不存在时由受限安全层在根内创建，或明确失败；不能越过保护边界恢复。

移入隔离区仍占用同一文件系统空间，界面必须写“已隔离，尚未释放磁盘空间”。文件夹更名通常改变部分元数据，因此操作日志保存原始元数据，但不强制伪造 ctime。

### 13.5 永久清理

默认不自动永久清理。管理员可手动选择隔离条目、查看仍存在的保留副本并再次认证后清理。可选自动清理策略最短保留 7 天，默认关闭；启用时必须明确说明永久删除不可撤销。

永久清理只能处理应用独占隔离目录里、动作日志已确认的普通文件。清理前重新验证隔离文件身份与剩余副本；保留副本失效则停止并提示恢复。仅删除隔离文件，不接受源目录任意路径。

本应用不能保证 NAS 存在备份。首次启用写操作时要求确认已理解风险，并建议先在独立测试目录完成隔离/恢复/清理演练。清理后卷空间变化通过后续容量采样反映，不能简单把逻辑字节从仪表盘扣除。

## 14. 安全、隐私与应用配置

### 14.1 认证与会话

密码使用 Argon2id，参数持久记录并支持升级；生产默认内存成本 64 MiB、迭代 3、并行度 1，结合 NAS 基准调整，但不得低于经安全评审的下限。登录失败按 IP 和账号双重限速，默认 10 分钟内 5 次后短暂退避；不能永久锁死唯一管理员。

会话使用随机不可预测 token，数据库只保存摘要。Cookie 为 HttpOnly、SameSite=Lax；HTTPS 模式必须 Secure。默认空闲 30 分钟、绝对 24 小时，可配置。危险操作需要最近 5 分钟内的重新认证。

HTTP 局域网初次部署可用，但 UI 持续提示非加密访问；外网入口必须经受信反向代理 HTTPS 或安全网络。不得自动开放路由器端口。

所有状态修改请求需要 CSRF token 与 Origin 校验。CORS 默认关闭。反向代理头仅信任配置的代理网段，避免伪造协议/IP。

### 14.2 Web 与接口防护

前端不使用 `v-html` 渲染文件名。模板、CSV、邮件和 HTML 报告各自正确转义。启用限制性 CSP、nosniff、frame-ancestors；正式构建不需要 unsafe-eval，开发配置不得带进生产。

查询使用参数化 SQL，排序字段通过枚举白名单。输入限长、限制请求体、限制导入文件大小、限制分页和导出并发。来源错误不得泄漏密码、连接凭据或底层绝对数据目录。

SMTP/未来 webhook 配置只允许管理员编辑；拒绝不合规协议与云实例元数据地址。NAS 内网 SMTP 是合理用途，可显式配置，不能用简单“禁用所有私网地址”破坏内网部署。服务不得成为可任意探测内网 URL 的代理。

### 14.3 密钥与备份

SMTP 密钥使用受保护密钥文件或应用主密钥加密后存库。主密钥不通过普通 API 返回，不写日志；丢失时必须重新录入秘密，不能静默以固定默认 key 解密。

普通配置导出默认不含密码、会话、SMTP 秘密和主密钥。需要含秘密备份时，必须使用用户提供口令的标准认证加密格式/成熟库，不自创加密协议。管理员忘记应用密码可通过容器 CLI 本地重置，并撤销旧会话；不能通过公开网页绕过认证。

### 14.4 配置层次

部署配置 YAML 只定义安全边界：监听、数据目录、批准挂载、可写开关、资源上限、受信代理和默认时区。UI 不得扩大这些边界。

动态配置保存在控制数据库：已登记源、任务、分类、通知、身份映射、配额与保留策略。环境变量只覆盖明确列出的启动设置。优先级为显式 CLI > 已定义环境变量 > 部署 YAML > 安全默认值；未知配置字段启动失败并提示，不静默忽略拼写错误。

## 15. 技术架构与工程布局

### 15.1 固定架构决策

采用 **Rust 后端 + React / TypeScript 前端 + SQLite + 单 Docker 服务**。技术选型依据和取舍见 `04_STACK_DECISION.md`。不引入第二种后端语言，不以 Rust 调用一套另外维护的后端服务；不引入 Redis、Elasticsearch、Kafka 或外部数据库作为 V1 必须依赖。

Rust 使用 stable 工具链和 edition 2024。M0 在确认依赖的 MSRV 与双架构构建后，将精确工具链版本写入 `rust-toolchain.toml`，提交 `Cargo.lock`；不得在生产构建时浮动跟随 stable/nightly/latest。所有权模型不依赖跟踪式 GC，但这不代表程序不会泄漏、无限分配或 OOM。[S13][S20]

前端使用 React + TypeScript strict + Vite，采用 SPA；React Router 管路由，TanStack Query 管服务端查询缓存，Ant Design 管表格/表单/确认交互，ECharts 管图表。使用 Node.js 24 LTS 的受支持补丁版本构建，M0 固定 pnpm 的精确版本并提交 `pnpm-lock.yaml`。本产品没有服务端渲染需求，不引入 Next.js、RSC、SSR、模块联邦或运行时 Node 服务。[S14][S18]

后端固定选型：

| 职责 | 选型与约束 |
| --- | --- |
| HTTP / SSE | Axum + Tokio + Tower；认证、CSRF、限流和错误映射集中处理 |
| JSON / 类型 | Serde；DTO 明确区分未知值、字节数字符串、业务枚举；不把任意 JSON 作为领域模型 |
| SQLite | rusqlite，启用 bundled 与需要的 backup 能力；显式 SQL、受校验迁移、受限独立连接；不同时引入 SQLx 或 ORM |
| Linux 文件边界 | rustix 包装在 fssecure crate；优先安全 API，业务代码不能自行拼路径绕过 |
| 内容指纹 | RustCrypto sha2 的 SHA-256；固定块流式读取；不改用抽样哈希作为完整性判据 |
| 错误 / 日志 / CLI | thiserror 定义稳定业务错误；tracing 输出结构化日志；clap 提供管理子命令 |
| 调度 / 邮件 / 时间 | M0 选定受维护的 cron、IANA 时区与 SMTP 库；持久化、DST、去重、重试由应用契约控制，不交给默认行为猜测 |

Axum 建立在 Tokio/Tower 生态上；SQLite 使用同步连接时必须遵守后文的执行隔离。rusqlite 的 bundled 会编译并链接 SQLite C 实现，所以“Rust 后端”不是“所有依赖均为纯 Rust”，也不能承诺只换 Rust target 就自动完成跨架构发布。[S16][S17]

Vite 构建产物复制到镜像 `/app/web` 只读目录，由 Rust 服务提供。最终运行镜像不运行 Node、Vite 或额外 Nginx。`/api/v1/*`、`/health/*` 及静态资源缺失必须返回各自的真实错误；仅前端页面路由回退到 index.html，不能以 200 HTML 掩盖 API 404。

M0 将工具链、依赖版本、启用 features、传递依赖、SQLite 实际引擎版本、基础镜像 digest 和许可证写入 `docs/DEPENDENCIES.md`。锁文件用于复现，不代替后续安全升级流程。

### 15.2 运行进程与职责

一个容器内主进程运行 API、调度器、控制库 writer、通知 outbox 和容量采样；扫描由同一程序的 worker 子命令启动，使用受控 IPC 汇报进度。worker 写自己的运行索引，不直接随意写控制数据库。

默认最多一个扫描 worker 子进程。worker 普通崩溃、panic 或退出由主进程检测并登记，已完成报告靠不可变发布与持久化保护。子进程不等于独立容器/cgroup：容器整体 OOM 仍可能使 API 一起退出，因此不得声称进程隔离能保证 OOM 时 Web 一直可用。整容器被杀后的恢复按第 18 节执行。应用所有写入均限定到 `/data`、已批准输出目录或显式可写的隔离路径。

容器启动时取得 `/data` 单实例锁。对同一个数据目录启动第二个应用实例必须失败，不提供未经设计的多副本共享 SQLite 模式。

### 15.3 数据流

```text
Browser
  -> Authenticated HTTP API / SSE
  -> Application services
       -> Scheduler / durable jobs / notification outbox
       -> Source registry / capability detection
       -> Scan worker -> per-run file index
       -> Aggregator -> immutable report bundle
       -> Exporter / history / comparison
       -> Opt-in cleanup service -> protected quarantine

Approved read-only sources -> metadata and content reads only
/data                     -> control DB, run indexes, reports, cache
Approved report output    -> generated report copies only
```

### 15.4 仓库目录

```text
Cargo.toml / Cargo.lock             workspace, explicit features, exact resolution
rust-toolchain.toml                 pinned stable toolchain, rustfmt, clippy
crates/nas-analyzer/src/
  main.rs / lib.rs / cli.rs         serve, worker, healthcheck, config-check, admin
  auth/ / config/ / httpapi/        sessions, boundaries, Axum routes, DTOs
  source/ / scanner/               registry, capability checks, metadata pipeline
  duplicates/ / jobs/              hashing, cache, scheduler, worker supervisor
  report/ / cleanup/ / notify/     immutable output, safe cleanup, SMTP outbox
  store/                           rusqlite repositories and database workers
crates/nas-analyzer/tests/          Linux integration and contract tests
crates/fssecure/src/                descriptor-relative filesystem boundary
crates/fssecure/tests/              adversarial path and mutation tests
web/
  package.json / pnpm-lock.yaml     exact frontend dependency resolution
  src/app/                         providers, router, layout
  src/features/                    sources, jobs, reports, cleanup, settings
  src/api/                         generated TS contract and request wrapper
  src/components/ / src/lib/       shared UI, formatting, ECharts lifecycle
  tests/                           Vitest, Testing Library, Playwright
api/openapi.yaml                   maintained complete API contract
migrations/{control,index,report}/
tests/{fixtures,security,bench}/
deploy/                           Dockerfile, compose, config samples
docs/                             decisions, dependencies, operations, results
```

初始 workspace 只拆应用与高风险 FS 边界两个 crate，不为每个页面或数据表新建 crate。主 crate 的 lib.rs 供集成测试复用，main.rs 只做 CLI 分发与启动。禁止为了“架构完整”预建微服务、插件框架或运行时动态加载体系。

### 15.5 SQLite 并发与存储

控制库使用 WAL、本地文件系统和单写队列，读连接池默认 4；`busy_timeout`、foreign_keys、事务上限显式配置。SQLite WAL 存在单 writer 约束且不适用于普通网络文件系统共享，因此 `/data` 不能放 SMB/NFS 挂载上。[S15]

扫描索引按 1,000 行或约 1 秒一个事务批量写入。不要每个文件单独 fsync，也不要维持数小时的大事务。索引结束后做必要完整性校验、checkpoint，并转换为适合不可变读取的状态。

控制库 `synchronous=FULL` 用于任务、权限和清理日志；可重建索引可使用经过测试的 NORMAL 策略。应用被杀、NAS 重启和空间耗尽都要进行恢复测试。日志文件与 WAL 设置空间告警，不通过无限重试让整个 NAS 磁盘被写满。

### 15.6 Tokio 与阻塞工作边界

主进程 Tokio runtime 处理 HTTP、SSE、定时唤醒、IPC 和异步网络操作。同步 SQLite 查询、目录遍历、文件哈希、ZIP 压缩、大型聚合和密码哈希不得直接在 Axum handler 或 Tokio 核心任务上执行。

扫描子进程采用固定数量的专用线程执行元数据与哈希管线；长驻数据库 writer 使用专用线程。只对短时且会结束的阻塞工作使用有并发准入的 `spawn_blocking`。Tokio 官方说明，阻塞任务默认线程上限较大，CPU 工作应另外限并发；已经开始的 spawn_blocking 任务不能靠 abort 停止，长期工作更适合专用线程。[S19]

禁止每个文件创建一个 Tokio task、一个 OS 线程或一项无界 spawn_blocking。metadata_workers、hash_workers、max_open_files 均是真正的准入上限；打开文件的 permit 生命周期覆盖文件句柄的整个使用期。散列和密码计算不能共用一个无上限 CPU 队列。

线程之间只传递拥有所有权的工作项，通过有界 channel 实现背压。M0 固定内部默认上限：元数据结果队列 2,048 条且估算负载不超过 16 MiB；控制数据库待处理队列 256 项；IPC 单帧最多 1 MiB；全局读查询执行槽 4 个，含导出，不能每打开一个历史报告就额外开一套读池。超长路径须验证长度或单独报告错误，不得绕过字节预算。

待扫描目录可能随条目数增长，不能只把内存目录队列改成小 channel 就认为有界：溢出工作写入可重建运行索引的 frontier 表，内存仅保留一批；生产/消费关系必须有饱和测试，避免所有遍历线程都卡在向同一满队列发送子目录。

暂停/取消由共享取消标志、控制 IPC 与循环检查合作完成：每个文件、每个读取块、每个写入批次边界检查。等待 channel/permit 也必须能响应取消。数据库长查询使用经测试的 interrupt/progress 机制；事务、正在移动的文件和动作日志先完成一致性收尾，不能直接将中间态标为 CANCELLED。内核不可中断 I/O 仍受第 10.4 节限制。

### 15.7 rusqlite 连接和内存所有权

每个数据库写线程独占其 Connection、Statement 与 Transaction。请求侧通过异步 channel/oneshot 等待完成，不持有同步 MutexGuard 跨越 await，也不在 HTTP handler 内同步执行 SQL。读连接由受限数据库读工作线程独占，可缓存少量活跃报告连接，句柄总数必须有上限。rusqlite Connection 可 Send 但不可 Sync；不得用手写 unsafe impl 强行改变这一点。[S17]

扫描索引由所属 worker 的数据库写线程批量写；不能让每个 metadata/hash 线程各自随意写同一个 SQLite 文件。prepared statements 在拥有连接的线程内重用。大查询按游标/批次返回拥有所有权的 DTO；数据库行引用不得跨线程、跨 await 或穿过连接生命周期。

API 与前端仍遵守第 17 节无损数值协议。Rust 内部用明确整数类型并做 checked_add/checked_mul 和 TryFrom 检查；不能依赖 debug 构建的溢出行为。release profile 显式启用 overflow-checks，预期输入错误仍必须返回 Result，不能借 panic 处理用户请求。

业务 crate 禁止自行使用 unsafe；fssecure 默认也禁止，首先使用 rustix 安全封装。如确有不可替代系统接口，需要单独 ADR、安全不变量说明和反例测试才能调整该 crate 的 lint。禁止自定义 unsafe Send/Sync、为过编译大量 clone 整棵索引或将所有状态放入一个全局 Arc<Mutex<...>>。

### 15.8 React 状态、交互与接口契约

TypeScript 开启 strict。字节数在 DTO 中是 decimal string，显示格式化可以显式缩放，排序/相加用 BigInt 或后端结果，不能先 Number() 再存回业务数据。服务端查询状态只由 TanStack Query 管理；局部表单/交互使用 React state/context，V1 不默认再引入第二套全局状态库。[S21]

筛选、排序、报告 ID 与可复现 QuerySpec 写入路由 query 参数；翻页游标与筛选签名绑定，切换报告/筛选时重置游标与选择项。使用当前页表格/虚拟视口，行键使用 entry_id，不以展示路径或数组下标作为身份。

扫描、清理、导入和备份只从显式用户操作发送 mutation。不得在 useEffect 中自动发起不可逆 POST。StrictMode、路由返回、重复点击和请求重试都不能创建重复任务；危险操作不使用自动重试，服务端仍负责幂等和权限校验。

SSE effect 清理时关闭连接，重连拉取状态快照；组件销毁取消过期请求，退出登录清空用户查询缓存。图表在卸载时 dispose 并取消 ResizeObserver。长期打开与多次路由切换必须验证连接、监听器、图表实例不会持续增长。

默认 fetch 使用同源 cookie，统一 CSRF/request_id/错误码；401 进入登录，403 明确能力/只读限制，410 显示历史明细过期，不把这些错误转成“没有文件”。Ant Design 确认框不能代替服务端再认证或清理预览。

### 15.9 资源预算契约（部署配置 v2）

Rust 没有与 GOMEMLIMIT 等价的语言级 GC 软限制。本修订将资源字段改为 `api_memory_budget_mib` 与 `worker_memory_budget_mib`，部署 `config_version=2`；它们是预算与超限处置阈值，不是操作系统 RSS 硬限制。v1 的旧 limit 字段必须被严格校验拒绝并提示迁移，不能悄悄忽略。

实现先根据预算分配有界队列、文件缓冲、SQLite cache 和连接数量；默认每秒记录各进程 RSS，并记录容器可用时的 memory.current。持续超预算时，主服务停止接纳新扫描/大导出，返回 RESOURCE_BUDGET_EXCEEDED 或 RESOURCE_BUSY；worker 停止扩张新工作、收尾已提交批次并报告 PARTIAL，无法安全发布时 FAILED。处置不得跳过清理动作日志恢复。资源恢复后重新接纳，不形成无界等待。

RSS 监测不是瞬时分配保护，分配器缓存、SQLite C 堆、共享内存及文件缓存的计量也不同，不能保证先于 OOM 生效。真正的整体硬限制仍由 Compose mem_limit/cgroup 承担；主进程与 worker 的预算之和必须给临时文件、缓存和其他进程留余量。不可把两个预算都设成容器总内存。

预算名改变不降低第 19 节原有性能目标。基准同时记录主服务 RSS、worker RSS、总峰值 RSS 与容器 memory.current；不能拿不同指标宣称 Rust 比其他实现节省多少比例。

### 15.10 构建与质量门槛

必须在 M0 提供下列实际可执行入口；前端脚本由 package.json 明确定义，不能是空脚本。基础命令全部使用提交的依赖锁：

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --release --locked
cargo build --release --locked -p nas-analyzer

pnpm --dir web install --frozen-lockfile
pnpm --dir web run typecheck
pnpm --dir web run lint
pnpm --dir web run test:unit
pnpm --dir web run build
pnpm --dir web run test:e2e
```

CI 使用实际发布 feature 集合，不无条件开启所有依赖 feature。Rust 单元/集成测试、Vitest + Testing Library、Playwright 和基准夹具各负其责；Linux 安全场景不能在 macOS 上跳过后写为 PASS。依赖漏洞检查需同时覆盖 Rust、前端、基础镜像与 bundled SQLite，Cargo.lock 本身不是安全审计。

## 16. 数据模型与索引规范

采用控制库、运行明细库、不可变报告摘要库三类数据文件。跨库引用通过 UUID 和 manifest 校验，不声称 SQLite 的跨文件系统发布是单事务。

### 16.1 控制库核心表

| 表 | 必需字段/约束 |
| --- | --- |
| `app_settings` | key PK、value_json、version、updated_at；包含初始化状态 |
| `admin_users` | id PK、username unique、password_hash、enabled、created_at |
| `sessions` | token_hash unique、user_id FK、csrf_secret、created/expires/last_seen |
| `sources` | id PK、mount_key、raw_relative_root、name、volume_id、policy_json、identity_epoch、availability |
| `volumes` | id PK、name、capacity_source_id、identity_json、status |
| `identity_mappings` | id、namespace、uid、gid、display_name、source、observed_at；作用域唯一 |
| `quota_records` | principal、scope、metric、limit_state、limit_bytes、used_bytes、origin、observed/expires |
| `category_rulesets` | id、version unique、rules_json、created_at；历史不可变 |
| `profiles` | id、name、enabled、deleted_at、current_version |
| `profile_versions` | profile_id + version PK、config_json、created_at |
| `jobs` | id、type、state、phase、profile_version、requested_at、started/finished、heartbeat、retry_of、error_json |
| `schedule_occurrences` | profile/version/occurrence_key unique、job_id、planned_at |
| `job_events` | job_id、sequence、type、payload_json、created_at；用于 SSE 恢复 |
| `reports` | id PK、run_id unique、profile_id、manifest_path、status、detail_available、pinned、created_at |
| `volume_samples` | volume_id + sample_time unique、total/free/available/used、quality、error |
| `notification_outbox` | id、report_id、recipient、kind、attempts、next_attempt、state；逻辑发送键唯一 |
| `exports` | id、report_id、query_hash、state、path、expires_at、lease_count |
| `cleanup_plans` | id、report_id、immutable_payload、expires_at、actor_id、state |
| `cleanup_items` | id、plan_id、entry_ref、original/raw_quarantine_path、identity、state、journal_seq |
| `audit_events` | id、actor、action、resource、result、request_id、created_at、redacted_detail |
| `schema_migrations` | version PK、checksum、applied_at |

队列领取必须事务化并有唯一运行约束；状态更新使用期望旧状态/版本，防止取消与完成相互覆盖。jobs、notifications、exports、cleanup 均不得只保存在内存。

### 16.2 运行明细库

`entries` 必须包括：entry_id、source_id、parent_entry_id、raw_relative_path BLOB、display_name、entry_kind、file_identity_key、device_id、inode_id、nlink、uid、gid、mode、size_bytes、allocated_bytes_estimate、mtime_sec/nsec、atime_sec/nsec、ctime_sec/nsec、birthtime nullable、category_id、extension、scan_error、observation_time。

原始路径在 source 内唯一；source 根本身用一个目录 entry 表示，便于树查询。device/inode 用无损文本或二进制存储，不随意塞入会溢出的有符号整数。单文件大小用有符号 64 位检查后落库，聚合使用带溢出检测的 64 位或大整数；发生溢出返回明确错误，不允许 SQL SUM 静默异常。

其他表：`scan_errors`、`source_observations`、`duplicate_candidates`、`file_hashes`、`duplicate_groups`、`duplicate_members`、`directory_aggregates`、`owner_aggregates`、`category_aggregates`。

必要索引：`(source_id, raw_relative_path)` 唯一；`(parent_entry_id, entry_kind)`；`(size_bytes DESC, entry_id)`；`(uid, size_bytes DESC, entry_id)`；`(category_id, size_bytes DESC, entry_id)`；`(mtime_sec DESC, mtime_nsec DESC, entry_id)`；`(atime_sec, atime_nsec, entry_id)`；`(file_identity_key)`；重复候选 `(size_bytes, candidate_key)`。按实际 QueryPlan 再增索引，不能一开始为每列建索引拖垮写入。

子树查询使用物化 parent 关系/路径键范围或专用闭包/后序区间，不为百万目录建立不可控 N² 祖先表。一次扫描完毕后可生成 DFS 区间，以便 `left/right` 范围筛选。

### 16.3 报告摘要库

保存完整目录/用户/类别聚合、固定排行条目副本、受限重复组列表、卷采样快照、配额/身份/规则快照和各栏目状态。它独立于可能被回收的全量 entries 索引。

所有派生行带 metric 和 scope 信息。CSV 和 Web 通过相同 query service 访问，不分别重新计算一套结果。

### 16.4 文件布局

```text
/data/
  control.sqlite
  secrets/                       owner-only, never served
  config-backups/
  cache/hash-cache.sqlite
  runs/<run_id>/index.sqlite
  runs/<run_id>/staging/
  reports/<report_id>/manifest.json
  reports/<report_id>/report.sqlite
  reports/<report_id>/report.html
  exports/<export_id>/
  actions/<action_id>/journal.jsonl
  tmp/
```

manifest 含 schema_version、应用版本、profile/ruleset/scope fingerprints、文件大小和 SHA-256 清单。内容为内部契约，不能靠目录名称猜关联。

## 17. HTTP API 契约

### 17.1 通用约定

API 前缀 `/api/v1`，JSON UTF-8。同源 cookie 会话；除初始化、登录和最小健康检查外，全部接口需管理员身份。所有修改类请求要 CSRF；耗时操作返回 202 与 job_id，不阻塞 HTTP 直到扫描完成。

所有字节数、inode/device 标识、可能超过 JavaScript 安全整数的数值以十进制字符串传输。文件时间以 RFC3339 UTC 展示字段加秒/纳秒原始字段表达；无法表达的时间显示 null 与原因。普通受限计数可以 JSON number，但不得丢失精度。

统一成功响应为 `{data, meta, request_id}`；列表的 meta 含 next_cursor、page_size、total_known、truncated、detail_available。未知总数为 null，不通过慢 COUNT(*) 阻塞所有页面。

错误响应：

```json
{
  "error": {
    "code": "SOURCE_UNAVAILABLE",
    "message": "数据源不可访问，请检查挂载或解锁状态。",
    "details": {"source_id": "source-uuid", "reason": "not_mounted"}
  },
  "request_id": "request-uuid"
}
```

HTTP 400 格式错误；401 未登录；403 未授权/只读；404 不存在；409 状态/版本/身份冲突；410 明细或计划过期；422 业务校验失败；429 限流；503 容量/能力暂不可用。保留稳定错误码，前端不解析中文错误文本做逻辑判断。

需要的错误码至少包括：SETUP_REQUIRED、READ_ONLY_MODE、PATH_OUTSIDE_ROOT、SOURCE_IDENTITY_CHANGED、SOURCE_UNAVAILABLE、DETAIL_EXPIRED、REPORT_INCOMPATIBLE、FILE_CHANGED、HASH_INCOMPLETE、PLAN_EXPIRED、PROTECTED_FILE、HARDLINK_NOT_ALLOWED、NO_SURVIVING_COPY、QUARANTINE_CONFLICT、INSUFFICIENT_DATA_SPACE、UNSUPPORTED_CAPABILITY、JOB_STATE_CONFLICT、RESOURCE_BUSY、RESOURCE_BUDGET_EXCEEDED。

### 17.2 路由清单

| 路由（均省略 /api/v1） | 方法 | 请求/响应及行为 |
| --- | --- | --- |
| `/setup/status` | GET | 仅返回 initialized 和是否可初始化，不返回 token |
| `/setup/complete` | POST | setup_token、username、password、timezone；成功即撤销初始化令牌 |
| `/auth/login`、`/auth/logout` | POST | 登录限流；登出撤销服务端会话 |
| `/auth/me` | GET | 当前管理员、会话到期与功能能力 |
| `/auth/reauth` | POST | 验证密码，返回 5 分钟危险操作 token |
| `/admins`、`/admins/{id}` | GET/POST/PATCH/DELETE | 管理员管理；防止删除最后一人 |
| `/mounts` | GET | 部署批准根列表和权限能力，不遍历宿主机任意路径 |
| `/mounts/{key}/directories` | GET | 仅允许批准根内选择子目录；no-follow、分页 |
| `/sources`、`/sources/{id}` | GET/POST/PATCH/DELETE | 注册与配置；删除为停用/软删除，保留历史 |
| `/sources/{id}/probe` | POST | 触发只读诊断，返回状态及能力矩阵 |
| `/sources/{id}/confirm-identity` | POST | 新身份确认，增 identity epoch、失效缓存 |
| `/volumes`、`/volumes/{id}` | GET/POST/PATCH | 容量源选择与历史身份，不管理真实分区 |
| `/volumes/{id}/samples` | GET | from、to、resolution=raw/day，返回数据质量 |
| `/profiles`、`/profiles/{id}` | GET/POST/PATCH/DELETE | Profile 和版本；PATCH 使用 If-Match |
| `/profiles/{id}/clone` | POST | 新名称和新 UUID，不复制运行状态 |
| `/profiles/{id}/run` | POST | Idempotency-Key；返回 job_id、run_id |
| `/profiles/schedule-preview` | POST | 表达式/时区校验与未来五个触发点 |
| `/jobs`、`/jobs/{id}` | GET | 状态、阶段、计数、错误摘要 |
| `/jobs/{id}/control` | POST | action=pause/resume/cancel/retry；校验当前状态 |
| `/jobs/{id}/events` | GET SSE | 带 sequence 和 Last-Event-ID 的可恢复事件流 |
| `/reports`、`/reports/{id}` | GET | 条件历史列表、manifest 与摘要 |
| `/reports/{id}/pin` | POST | report/detail 两种保留标记 |
| `/reports/{id}` | DELETE | 只清理报告及受控生成物，不接触源文件 |
| `/reports/{id}/folders` | GET | parent_entry_id、metric、cursor、sort |
| `/reports/{id}/owners` | GET | source、uid、category；含身份/配额快照 |
| `/reports/{id}/categories` | GET | scope 与 metric，返回图表和表格共用数据 |
| `/reports/{id}/files` | GET | 统一 QuerySpec，全量明细过期返回 410 |
| `/reports/{id}/rankings/{kind}` | GET | kind=largest/recent/least_accessed；固定历史排行 |
| `/reports/{id}/duplicates` | GET | 完整/截断组、成员计数、verification |
| `/reports/{id}/duplicates/{group_id}` | GET | 组成员；完整成员不可用时说明截断 |
| `/reports/{id}/compare` | POST | other_report_id、mode=aggregate/files；返回 comparison job |
| `/reports/{id}/exports` | POST | section、format、QuerySpec、scope=current/all；返回 export_id/job_id |
| `/exports/{id}`、`/exports/{id}/download` | GET | 状态与经过身份检查的流式下载 |
| `/cleanup/plans` | POST | 预览；请求 entry IDs，不接收路径 |
| `/cleanup/plans/{id}/execute` | POST | reauth_token、confirmation、Idempotency-Key |
| `/cleanup/actions/{id}` | GET | 条目级日志与状态 |
| `/cleanup/quarantine` | GET | 隔离项、风险、关联计划 |
| `/cleanup/quarantine/{id}/restore` | POST | 原位置恢复/新名称；不覆盖 |
| `/cleanup/quarantine/{id}/purge` | POST | 重新认证和确认；安全检查后永久删除 |
| `/settings/categories` | GET/PUT | 校验并创建新规则集，不覆盖历史 |
| `/settings/notifications` | GET/PUT | 密钥回显始终打码 |
| `/settings/notifications/test` | POST | 真正发送测试邮件，记录审计 |
| `/settings/storage`、`/settings/retention` | GET/PUT | 在部署边界内修改默认策略 |
| `/metadata/import/preview` | POST | JSON schema/作用域/源匹配校验，不写入 |
| `/metadata/import/apply` | POST | preview_id + digest + 再确认，原子应用 |
| `/settings/backup` | POST | 创建不含秘密的配置导出 job |
| `/settings/restore/preview` | POST | 验证配置版本、差异和部署边界 |
| `/settings/restore/apply` | POST | 确认并备份现有配置后原子更新 |
| `/diagnostics`、`/audit` | GET | 分页脱敏输出，不泄露凭据 |

`/health/live`、`/health/ready` 不在 API 前缀下。live 只检查进程；ready 检查数据库和配置是否可服务，不因某一个扫描源离线就把整个应用判死。尚未初始化时 ready 可返回受限就绪状态，避免健康检查阻止管理员完成初始化。

### 17.3 创建任务请求样例

```json
{
  "name": "每周共享目录分析",
  "enabled": true,
  "scope": {
    "mode": "selected",
    "source_ids": ["11111111-1111-4111-8111-111111111111"],
    "include_future_registered": false,
    "exclude_globs": ["**/*.part", "**/*.tmp"]
  },
  "sections": ["volume", "folders", "owners", "quota", "categories", "duplicates", "largest", "recently_modified", "least_accessed"],
  "owner_ids_to_list": [],
  "duplicates": {
    "enabled": true,
    "match_name": false,
    "match_mtime": false,
    "min_size_bytes": "1",
    "max_size_bytes": null,
    "max_listed_files": 5000,
    "hash_budget_bytes": null
  },
  "rank_limit": 200,
  "schedule": {
    "type": "cron",
    "expression": "0 2 * * 0",
    "timezone": "UTC",
    "misfire_policy": "skip",
    "overlap_policy": "coalesce_once"
  },
  "retention": {"report_keep_count": 30, "detail_keep_count": 3},
  "notifications": {"recipients": [], "notify_on": ["succeeded", "partial", "failed"]}
}
```

本例是接口语义示例，不是已经存在的任务或用户实际时区。内容检测还需要 Source 的 read_policy 允许，后端应在提交前校验并提示冲突。

### 17.4 查询、分页和 SSE

QuerySpec 字段为 source_ids、directory_entry_id、include_descendants、category_ids、extensions、owner_uids、name_contains、min/max_size_bytes、mtime_from/to、atime_from/to、metric、sort。时间范围统一左闭右开，大小范围统一含边界。CSV 必须复用同一规范化 QuerySpec 与 query_hash。

cursor 包含 report_id、dataset_version、sort key、last_entry_id、query_hash，并经过服务端签名。请求改变筛选后旧 cursor 返回 409，而不是混入上一页的数据。默认 page_size=50，上限 200。

SSE 事件包括 job.state、job.progress、job.warning、job.completed、heartbeat。默认每秒最多推送一次进度；断线重连可从最近事件恢复，事件已过期则先发送 state snapshot。SSE 只负责显示，不能作为任务状态的唯一持久来源。

## 18. Docker、绿联部署与运维（F18）

### 18.1 镜像要求

多阶段构建：固定 Node/pnpm 构建 React → 固定 Rust/C 工具链编译应用及 bundled SQLite → 最终最小 Linux 运行镜像。默认采用经过双架构验证的 glibc 系运行镜像，构建与运行 libc ABI 必须匹配；不把 musl、scratch 或全静态链接当作默认前提。运行镜像只保留应用二进制、只读前端资源、必要运行库、CA 证书和时区数据，默认非 root。

优先在 amd64/arm64 对应构建节点原生编译；交叉编译或 QEMU 方案须同时验证 C 编译器/链接器、SQLite 和依赖，不只执行 rustup target add。最终镜像分别运行 healthcheck、真实 SQLite 迁移、扫描与安全能力冒烟；记录原生、仿真和实机验证的区别。选择无 shell 镜像时必须提供内置 healthcheck 与管理 CLI，不能写依赖不存在的 curl/bash 的健康检查。

镜像支持 SIGTERM 优雅退出，默认 60 秒停止窗口；容器 init 负责回收子进程。提供明确版本 tag 和构建提交信息；生产示例禁止浮动 latest。设计包中的 `nas-storage-analyzer:local` 仅表示未来本地构建产物，并不是已发布镜像。

### 18.2 Compose 契约

配套 `deploy/compose.example.yaml` 为实现后的部署模板，使用长格式 bind、`create_host_path: false`、显式 user、cap_drop、no-new-privileges、只读容器根文件系统、受控 tmpfs、healthcheck、日志轮转、资源限制。

Docker 默认 bind 可以写入源文件，因此必须明确为扫描目录设置只读。[S7] 递归只读子挂载还存在内核版本限制；不能把单个 ro 参数当作所有子挂载都只读的保证。[S7] 本应用默认不跨子挂载，并在诊断中核验扫描边界。

APP_UID/APP_GID 是 Compose user 的输入，不是仅仅写两个 PUID/PGID 环境变量就自动生效。宿主机必须事先为该身份授权读取扫描目录和写入应用数据目录；补充组通过 group_add 显式添加。不得对原始共享目录运行递归 chown/chmod 作为默认修复。

`/data` 只允许本地文件系统。扫描源可在独立挂载下；数据库不应置于正在扫描的目录中。额外输出目录必须另行挂载、加入批准输出清单并从扫描中排除。

### 18.3 部署步骤

1. 在绿联确认设备支持 Docker，并准备独立应用数据目录与待扫描目录的真实路径。路径从设备本身读取，不照抄示例 `/replace/...`。
2. 实现者先构建当前架构镜像，或提供经验证的多架构发布镜像。设计包不是应用，不能直接拉取一个尚不存在的镜像运行。
3. 复制 `.env.example` 为 `.env`，填写真实目录、运行 UID/GID、NAS 局域网绑定 IP、端口和时区。预创建数据目录，授权专用应用身份；不要扩大源目录权限。
4. 复制配置与 Compose 示例为生产配置。在 UGOS Docker 的 Project 中导入，或在项目目录使用 Docker Compose。UI 流程以设备版本为准；官方文档展示了 Project 部署途径。[S6]
5. 部署前运行配置校验和 Compose 展开检查；启动后检查健康状态、日志和源只读诊断。
6. 通过容器 CLI 获取初始化 token，完成管理员配置。先在小型测试源扫描，再接入真实大目录。
7. 验证容量与 NAS/系统工具的差异说明，验证导出、邮件、重启恢复后，才考虑开启可写整理模式。

实现后的 CLI 约定：

```bash
nas-analyzer config-check --config /config/config.yaml
nas-analyzer healthcheck --url http://127.0.0.1:8080/health/ready
nas-analyzer admin setup-token --data-dir /data
nas-analyzer admin reset-password --data-dir /data --username admin
nas-analyzer backup --data-dir /data --output /data/config-backups/backup.zip
nas-analyzer restore --data-dir /data --input /data/config-backups/backup.zip --dry-run
```

CLI 不把明文密码作为命令行参数，使用交互输入或秘密文件。重置密码和离线恢复需要本地目录访问权限并遵守单实例锁。

### 18.4 升级、备份与恢复

升级前记录镜像 digest、应用版本和数据库 schema；使用 SQLite backup API 或停写一致性备份，不能只复制正在 WAL 模式写入的主数据库文件。[S15]

配置备份至少覆盖任务、分类、源登记、身份/配额映射、通知非秘密设置和保留策略。完整备份另外包含控制库、报告及需要保留的明细，用户源文件和隔离区数据不在“配置备份”中。

恢复输入必须防 ZIP slip/路径穿越、符号链接、重复路径、解压炸弹和不支持的 schema；先预检、列出差异、生成恢复前备份，再离线原子替换。部署挂载白名单不能被导入文件扩大。

升级迁移需备份后执行，checksum 不一致时失败。旧程序遇到新 schema 应拒绝启动，而不是自动破坏数据。回滚方案为旧镜像 + 迁移前备份，不承诺任意数据库迁移可逆。

### 18.5 可观察性

结构化日志包含 timestamp、level、component、job_id、source_id、request_id、duration、error_code。文件路径只在管理员可见的错误/审计中按需保存；常规日志避免逐文件打印。

诊断页展示应用/SQLite/构建版本、架构、运行身份、内核能力、只读边界、数据目录剩余空间、扫描队列、进程资源和源状态。不自动上传任何数据；导出诊断包默认脱敏用户名、宿主路径和密钥。

## 19. 性能预算与规模目标

以下数字用于定义测试方法和工程取舍，不表示已在某款绿联设备上达成。

| 场景 | 验收目标 | 附加说明 |
| --- | --- | --- |
| 空闲运行 | 总 RSS 目标 ≤ 150 MiB | 包含主服务，不含浏览器；版本与驱动需实测 |
| 100 万条目元数据扫描 | 应用总峰值 RSS 目标 ≤ 768 MiB，限制 1 GiB 时不 OOM | 工作队列、目录读取、批写都必须有界 |
| 1,000 万条目扩展测试 | 不依赖全部条目驻留内存，建议 2 GiB 容器预算验证 | 不承诺相同磁盘上固定完成时间 |
| 总览与已聚合报告查询 | 热数据 p95 < 500 ms，普通明细页 p95 < 1 s | 明确测试硬件、索引、数据集；导出除外 |
| 前端大列表 | 单页最多 200 条，滚动无明显长任务 | 禁止全量 JSON 加载后再客户端分页 |
| 本地正常 I/O 下取消/暂停反馈 | 目标 ≤ 5 s | 内核阻塞情况单独标注 |
| 哈希读取 | 默认 30 MiB/s、1 worker，可配置关闭限速或设上限 | 与 NAS 媒体/备份任务共享磁盘 |
| 并行导出 | 默认最多 1 个，全局队列有界 | 避免多个大查询阻塞写入 |

扫描性能以 entries/s、metadata errors、read MiB/s、peak RSS、index size、API 延迟综合衡量。首轮不得宣传“百万文件几秒扫描”或“完全不影响 NAS”。硬盘寻道、目录结构、ACL、校验读取量都会改变耗时。

索引容量不以拍脑袋的每文件字节固定承诺。基准需用 10 万/100 万条目、短/长文件名测量实际索引和报告体积，据此在 UI 估计后续所需空间。磁盘预算估算需把每次完整明细副本和 WAL 峰值算进去。

限制 CPU/内存是上限，不保证 I/O 延迟；应用内部令牌桶限速与卷级并发共同控制。`nice/ionice` 只作为能力允许时的补充，不假设容器一定能设置。

## 20. 验收、发布门槛与实施约束

详细案例见 `03_ACCEPTANCE.md`。至少覆盖业务闭环、准确性、危险边界、故障恢复、两种架构和真实 NAS 小范围验证。

### 20.1 必须通过的闭环

从一个空 `/data` 开始，完成初始化、源诊断、创建计划、元数据扫描、分类报告、重复校验、历史查看、CSV/HTML 导出、SMTP 测试、配置备份恢复。可写模式另外在测试目录完成预演、隔离、恢复、重新隔离与永久清理。

直接关闭容器后重启，历史与任务配置保留；中断任务不假装成功；外接源缺失不引发全目录“已删除”统计；修改分类不改写旧报告；重复点击运行与清理不会重复执行。

### 20.2 质量门槛

功能不得依靠 mock 才能演示。运行时页面未实现按钮必须隐藏/禁用并说明，不能展示成功 toast 却没有真正写库或发送邮件。

发布前无阻断性 TODO；高风险 FS 层必须具有路径穿越、符号链接竞争、内容变化、隔离恢复冲突、故障中断测试。测试不能对真实 NAS 数据执行删除；所有破坏性场景限定到新建临时测试根。

完成 M0–M8 的全部对标任务并通过验收，才可称 V1 完整交付。只读阶段可提前演示，但必须标记阶段成果，不把安全整理或配额适配接口留为假实现后宣称全功能完成。

### 20.3 平台适配完成的判定

通用 Docker 版完整交付，要求能力检测和导入型适配真实可用。真实 UGOS 自动配额读取、系统账号自动同步、Tiering 精确状态属于依赖平台接口的单独验收维度。

这些维度未知时，产品必须明确显示 unsupported/unknown，且不能被验收报告写成“与 DSM 原生完全等价”。要取得原生级等价声明，必须另外提供对应 UGOS 版本、授权方式、接口证据与实机测试记录。

## 21. 后续增强，不得挤占基础对标

可在 V1 完整闭环之后实施：多角色源级授权；inotify/fanotify 增量索引配合定期全量校准；大规模外部数据库模式；通用 webhook；容量增长预测；服务端 PDF；智能保留目录规则；受支持的 UGOS 官方接口连接器。

不建议第一阶段实现相似照片识别、视频感知哈希、语义检索、AI 自动删除或全盘常驻文件监控。它们扩大资源和误删风险，也不是内容完全相同的重复检测。

## 22. 参考资料与事实来源

以下是外部事实依据；具体数据模型、流程、算法、参数和验收要求属于本项目设计选择。产品功能及未改动平台资料沿用 2026-09-08 核对基线；Rust/React、数据库绑定和构建资料于 2026-09-09 核对。链接用于实现者复核，不要求运行时联网。

- [S1] Synology：Storage Analyzer Technical Specifications，DSM 7.3/7.4 公开规格。https://www.synology.com/dsm/7.3/software_spec/storage_analyzer
- [S2] Synology：Manage Report Profiles，DSM 7 帮助。https://kb.synology.com/en-eu/DSM/help/StorageAnalyzer/manage_profiles?version=7
- [S3] Synology：View Usage and Reports，DSM 7 帮助。https://kb.synology.com/en-us/DSM/help/StorageAnalyzer/view_reports?version=7
- [S4] Synology：Storage Analyzer 概览、管理员限制和备份恢复。https://kb.synology.com/en-us/DSM/help/StorageAnalyzer/StorageAnalyzer_desc?version=7
- [S5] Synology：Storage Analyzer Release Notes。https://www.synology.com/releaseNote/StorageAnalyzer
- [S6] UGREEN：Docker 知识中心及 Compose 部署说明。https://support.ugnas.com/detail/article/en-US/236 ，https://ai.ugreen.com/blogs/knowledge/docker-docker-compose-ugreen-nas
- [S7] Docker：Bind mounts；Compose services。https://docs.docker.com/engine/storage/bind-mounts/ ，https://docs.docker.com/reference/compose-file/services/
- [S8] rustix：openat2 API。https://docs.rs/rustix/latest/rustix/fs/fn.openat2.html
- [S9] Linux man-pages：stat(2)。https://www.man7.org/linux/man-pages/man2/stat.2.html
- [S10] Linux man-pages / util-linux：mount(8)。https://www.man7.org/linux/man-pages/man8/mount.8.html
- [S11] Linux man-pages：openat2(2)。https://www.man7.org/linux/man-pages/man2/openat2.2.html
- [S12] Btrfs 官方文档：Quota groups，referenced/exclusive 与共享数据块。https://btrfs.readthedocs.io/en/latest/Qgroups.html
- [S13] Rust 官方书：Ownership；Send/Sync。https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html ，https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html
- [S14] Node.js：版本与 LTS 状态。https://nodejs.org/en/about/previous-releases
- [S15] SQLite：Write-Ahead Logging。https://sqlite.org/wal.html
- [S16] Axum 官方 API 文档。https://docs.rs/axum/latest/axum/
- [S17] rusqlite 维护者文档、bundled 构建与 Connection。https://github.com/rusqlite/rusqlite ，https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html
- [S18] React：Build a React app from Scratch。https://react.dev/learn/build-a-react-app-from-scratch
- [S19] Tokio：spawn_blocking、长期工作与取消语义。https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
- [S20] Cargo：锁文件与编译 profiles。https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html ，https://doc.rust-lang.org/cargo/reference/profiles.html
- [S21] TanStack Query、Ant Design 官方文档。https://tanstack.com/query/latest/docs/framework/react/overview ，https://ant.design/components/overview/

## 附录 A：Codex 不得自行改变的关键决策

Rust + React 单一实现；Tokio 不直接运行阻塞扫描/SQL；默认只读；源数据与应用数据库分离；真实配额未知就显示未知；JSON 字节数无损；硬链接不算独立副本；内容重复须全量读取确认；写操作再次校验；隔离不是释放空间；不跟随符号链接；活跃扫描不是快照；报告不可变；分类和范围版本化；导出和 UI 使用同一查询服务；源离线不是零文件；邮件独立 outbox；SQLite 单实例本地存储；新建宿主共享目录不会自动穿透容器挂载。

## 附录 B：开发完成时必须交付

源代码与锁文件、完整 OpenAPI、数据库迁移、双架构镜像构建流程、Dockerfile/Compose、示例配置、首次部署说明、权限与容量口径说明、备份恢复与升级回滚文档、自动化测试、基准报告、需求追踪矩阵、已知环境限制清单。
