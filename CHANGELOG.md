# Changelog

## [Unreleased]

## [0.1.2] - 2026-09-21

### Added

- Added independent organization lifecycle, optional public registration, existing-account invitations, ownership transfer, and terminal invitation cleanup.
- Added published Agent identities and scoped execution-node registration, revocation, and exact receipt recovery.

### Changed

- Separated platform and organization roles; organization removal preserves account access while permanently revoking affected Agent and device grants.
- Issued 15-minute scoped Node tokens and kept device renewal independent of browser-session expiry, while retaining logout, password-change, and membership revocation.

### Fixed

- Serialized identity changes and invalidation events to prevent missed revocations under concurrent PostgreSQL writes.
- Enforced one active organization owner and preserved organization history, Agent identities, and invalidation cursors during database import.

## [0.1.1] - 2026-09-10

### 新增

- 增加 Deployment 下的 Organization 与组织成员关系；Principal 和成员目录携带当前组织，在线 Room 只能邀请同组织成员。
- 增加可撤销、限时、单次使用的 Organization 邀请链接；受邀者自行注册，成员管理只作用于当前组织。

- 提供在线 Room 邀请所需的最小成员目录，以及绑定管理员 Session 的对话式成员管理、显示名称修改、版本校验和部署访问撤销。
- 支持独立的 Relay 用户 Principal audience，隔离运行时与在线协作身份。
- 提供 Control SQLite 到空 PostgreSQL 的一次性迁移，保留账号和订阅权益并让旧 Session 失效。

## [0.1.0] - 2026-09-04

### 新增

- 建立独立 Control 服务，统一承接部署初始化、账号登录、会话、成员、订阅套餐和短期签名身份。
- 为 Nexus Web 提供同源登录、首次初始化和成员管理接口，并支持从现有 Nexus SQLite 保留用户编号迁移账号与订阅。
- 提供 SQLite、PostgreSQL `control` schema、Docker 镜像和 Control v1 OpenAPI 合同。
- 持久化身份与订阅变更事件，让多个 Nexus 副本按游标及时撤销旧身份并同步最新额度。

### 调整

- 将 Control 数据和滚动日志统一存放在 `~/.nexus/control`，启动时可读取当前目录或上级目录的 `.env`。
- 将浏览器账号写操作统一收口到 `/auth/v1`，内部服务凭据接口只保留验签和运行时准入所需的读取能力。
