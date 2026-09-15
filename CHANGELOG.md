# Changelog

## [Unreleased]

- Separate platform and organization roles; allow organization-less accounts, optional public registration, existing-account invitation acceptance, organization creation/rename/leave/ownership transfer/dissolution.
- Keep account sessions and deployment access on organization removal; revoke Agent publication and device authorization permanently, and serialize invitation authorization with identity changes.
- Enforce one active organization owner in SQLite/PostgreSQL and preserve multiple organizations, historical memberships and invitations during Control SQLite import.

- Allow organization owners and administrators to delete terminal invitation records without changing memberships.

### 新增

- 增加按部署、组织和所有者隔离的精确 Node 授权查询，供宿主恢复丢失的注册/撤销回执，不返回设备凭据。
- 取消未确认设备授权时保留不可复活的终止记录，支持先撤销后注册的到达顺序，防止用户取消后迟到注册重新获得能力。

- 增加限定 Agent 范围、绑定浏览器 Session 的 Node 注册与撤销；独立设备凭据只换取 60 秒 Relay Node 令牌，不能替代真人身份。SQLite/PostgreSQL 同步增加节点授权表。

- 组织撤权事件携带明确组织与撤权事实，Agent 目录和发布统一检查真人所有者资格；Control SQLite 导入保留失效事件原游标及 PostgreSQL 序列，避免 Relay 漏消费。
- 身份变更事务统一提交顺序，防止 PostgreSQL 并发写入时失效游标越过尚未提交的撤权事件。

- 增加组织内在线 Agent 身份发布、归属校验与 SQLite/PostgreSQL 持久化；Control 快照迁移同步保留 Agent 权威数据。

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
