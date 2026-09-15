# AGENTS.md

`nexus-control` 是 Nexus 的账号与部署控制面，独立于 Nexus Relay 消息面和 Agent 执行面。

## 边界

- User 独立于 Organization；一个账号最多一个 active 组织，无组织仍可登录和使用个人能力。`Principal.role` 仅表示平台/Deployment 角色，`organization_role` 表示组织角色，禁止互相推导。
- 新组织事件使用 `organization_changed`，必须携带 organization_id，移出时 membership_revoked=true；不复用历史上同时撤销平台访问的 principal_changed，避免错误保留旧平台授权或中断私人 Agent。
- `organization.go` 实现创建、改名、退出、移交、解散与已有账号接受邀请；`registration.go` 支持显式开启的普通账号注册。所有组织写入在身份事务锁内重验权限。唯一 active owner 由部分唯一索引保障，仅移交操作可更换。
- 退出/移出/解散仅撤销组织 Membership、Agent 发布和 Node 授权，不撤销平台 Membership 或浏览器 Session；重新加入必须接受新邀请，旧 Room/Node 授权不能复活。
- SQLite 导入按独立组织与成员关系复制，保留历史状态及邀请，不再从平台 Membership 推导组织关系；Session/Node 仍不迁移。

- 本仓唯一写入 User、密码凭据、浏览器 Session、Deployment、Organization、Membership、在线 Agent 身份与归属、订阅套餐及成员 entitlement；Deployment 是安装边界，Organization 是多人协作租户边界。
- `nexus` 与 `nexus-relay` 只消费本仓签发的短期 Principal，不得读取 Control 数据库。
- `nexus-control` 不依赖 `nexus-relay`；Agent 只保存公开身份、归属和发布状态，不保存本地配置、workspace、transcript 或产物。
- Runtime、Relay User 与 Relay Node 使用独立 Principal audience。Node 只由有效浏览器 Session 显式注册，绑定组织、真人所有者和最多 32 个自己发布的 Agent；Control 仅存凭据哈希，机器凭据只能换取 60 秒 Node 令牌，不能访问真人 API。
- Node 精确回执查询按 Deployment、Organization、Owner 三重限定，不依赖最近 100 条设备列表；登记记录不代表父 Session 仍有效，执行资格仍由机器令牌交换重新校验。
- 撤销未知 Node ID 也在身份写事务中保留终止记录（凭据哈希使用不可签发前缀），阻断迟到注册。已注册 Node 撤销才需要发布失效事件；不存在的 Node 不可能已有执行租约。
- `execution_nodes` 与浏览器父 Session 绑定，撤销节点写 `session_revoked`（`session_id=node:<node_id>`）；父 Session 撤销也使派生节点失效。普通 Principal exchange 不接受 Node audience。SQLite→PostgreSQL 导入不迁移 Session 或 Node 授权，设备必须重新授权。
- 浏览器登录、登出、资料、改密、初始化、Organization 邀请、成员目录、成员和订阅运营 API 固定在 `/auth/v1`，服务 API 固定在 `/api/control/v1`；邀请 token 只存哈希且单次消费，成员读取和变更只作用于当前 Organization，破坏性变更使用新主版本。
- 账号、Session 或 entitlement 写入必须在同一事务追加对应失效事件：单 Session 登出用 `session_revoked`，纯资料变更用 `profile_changed`，权限或账号状态变更用 `principal_changed`，套餐或成员额度变更用 `entitlement_changed`。
- 所有产生身份失效事件的事务先通过 `beginIdentityWrite` 锁定 Control 状态，再取业务锁；导入复用相同状态锁。不能仅依赖 PostgreSQL 自增 ID，否则晚提交的小 ID 会被消费游标越过。
- 组织撤权事件同时携带 `organization_id` 与 `membership_revoked`，供 Relay 同事务撤销 Room 真人/Agent 成员与执行资格；Agent 目录、归属校验和发布都要求其所有者当前仍有有效组织与部署访问。SQLite→PostgreSQL 导入必须保留失效事件原 ID 并推进目标序列，不能令已有 Relay 游标越过后续撤权。
- Control 不接收 Nexus token 用量，也不保存公共 Provider 或项目 ACL；前者是 Nexus 本地执行事实，后两者是 Nexus 运行资源。

## 目录

- `cmd/nexus-control/`：进程入口，以及 Nexus SQLite 导入和 Control SQLite 到 PostgreSQL 的一次性迁移命令。
- `internal/app/server/`：HTTP 服务装配与生命周期。
- `internal/handler/auth/`：浏览器与服务间认证 HTTP 边界。
- `internal/service/auth/`：账号、成员、Session、entitlement 与 Principal 业务规则。
- `internal/config/`：从 `./.env`、`../.env` 与进程环境加载配置；显式进程环境优先。
- `internal/infra/logx/`：与 Nexus Server 同构的结构化日志、终端渲染与滚动文件实现。
- `internal/storage/auth/`：认证与 entitlement 域查询及事务；`internal/storage/`、`db/` 管理 SQLite/PostgreSQL 连接、方言和迁移。
- `docs/openapi.yaml`：Control v1 HTTP 合同。

## 风格与验证

- Go 注释使用中文，保持短函数和明确事务边界。
- 默认运行 `go test ./...` 与 `go vet ./...`；PostgreSQL 契约测试使用全新的 `CONTROL_TEST_POSTGRES_URL`。
- 用户可见改动同步更新 `CHANGELOG.md` 的 `## [Unreleased]`。

`internal/handler/auth/member_management.go` 承载 Nexus 宿主的成员操作，要求服务凭据与有效管理员 Session；角色与 Deployment 从 Session 推导，更新使用成员快照版本校验，显示名称变更通知全部有效部署。
