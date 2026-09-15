# ADR-0001：fssecure 的平台门控与开发机回退

状态：已采纳。日期：2026-09-09。

## 背景

规格 10.3/15.7 要求 fssecure 使用 rustix 的 openat2（RESOLVE_BENEATH |
NO_SYMLINKS | NO_XDEV）。openat2 是 Linux 5.6+ 专有系统调用，开发机
macOS 上不存在该 API，crate 若在 macOS 直接引用将无法编译。

## 决策

- Linux（部署目标与 CI）：完整实现。openat2 可用性在打开根目录时探测；
  探测失败（ENOSYS）时读路径使用逐组件 O_NOFOLLOW + st_dev 校验回退，
  写操作（mkdir/rename/unlink）直接拒绝（MissingCapability，失败关闭）。
- 非 Linux（仅开发机）：openat2 能力固定为 false；只允许只读回退路径；
  所有写操作返回 MissingCapability。目录迭代在 Linux 用 getdents64
  （rustix::fs::Dir），开发机经 /dev/fd 重开同一目录仅用于本地开发自测。

## 理由与代价

- 不降低目标平台（Linux）的安全标准；写操作在缺少内核能力时失败关闭，
  符合规格 10.3「可写清理模式必须失败关闭」。
- 代价：macOS 上的 `cargo test` 不能覆盖 Linux 专属行为；ACC-010/033–044
  等安全验收必须在 Linux 容器（scripts/linux-cargo.sh，rust:1-bookworm）
  或目标 NAS 上运行并记录证据。这不把开发机结果冒充 Linux 结果。

## 测试

- crates/fssecure/tests：路径穿越、符号链接、EXDEV、rename no-replace、
  能力缺失失败关闭等反例测试，Linux 容器内执行。
