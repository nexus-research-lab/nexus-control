# AGENTS.md

`nexus-control` 是 Nexus 的账号与部署控制面，独立于 Nexus Relay 消息面和 Agent 执行面。

## 边界

- 本仓唯一写入 User、密码凭据、浏览器 Session、Deployment、Membership、订阅套餐与成员 entitlement。
- `nexus` 与 `nexus-relay` 只消费本仓签发的短期 Principal，不得读取 Control 数据库。
- `nexus-control` 不依赖 `nexus-relay`，也不保存 Agent、workspace、transcript 或产物。
- Runtime 与 Relay User 使用不同 Principal audience；Relay Node 必须在其身份模型落地后使用独立 audience。
- 浏览器登录、登出、资料、改密、初始化、成员目录、成员和订阅运营 API 固定在 `/auth/v1`，服务 API 固定在 `/api/control/v1`；普通成员目录只暴露邀请所需身份字段，破坏性变更使用新主版本。
- 账号、Session 或 entitlement 写入必须在同一事务追加对应失效事件：单 Session 登出用 `session_revoked`，纯资料变更用 `profile_changed`，权限或账号状态变更用 `principal_changed`，套餐或成员额度变更用 `entitlement_changed`。
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
