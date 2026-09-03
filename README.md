# Nexus Control

Nexus Control 是 Nexus 的账号与部署权威。它管理真人用户、密码、浏览器 Session、Deployment 与 Membership，并向 Nexus Server 签发短期 Principal。

当前首个切片支持单 Deployment，以及 SQLite、PostgreSQL 两种数据库，足以把现有 Web 账号从执行服务中拆出；Hub、Device 和 OAuth 不在这一阶段。页面仍由 Nexus 的同一套 Web Shell 提供，浏览器把登录、首次初始化和成员管理请求直接发到同源 `/auth/v1`，Nexus Server 只验证 Control 签发的短期 Principal。

## 启动

在同级 `nexus` 仓运行 `make dev` 会一并启动 Control。单独启动时可参考 [`env.example`](./env.example) 后运行 `make run`，服务凭据、SQLite 数据库与签名密钥默认持久化在 `./data/`；生产部署应显式设置路径和服务凭据。

SQLite 是单机默认值。使用 PostgreSQL 时配置：

```env
CONTROL_DATABASE_DRIVER=postgres
CONTROL_DATABASE_URL=postgres://nexus_control:password@postgres:5432/nexus
```

PostgreSQL 表固定写入 `control` schema；连接会强制使用该 `search_path`。数据库账号需要能创建该 schema，或由管理员预先创建并授权。签名密钥和服务凭据仍由 `CONTROL_DATA_DIR` 指向的本地持久目录保存，不写入数据库。

首次 owner 可在 Nexus Web 的 `/setup` 页面创建，也可由安装器调用 `POST /api/control/v1/setup/owner`，或设置 `AUTH_INIT_OWNER_PASSWORD` 由服务启动时初始化。Web 初始化需额外设置至少 32 个字符的 `CONTROL_SETUP_TOKEN`；该 capability 不会保存在浏览器中。owner/admin 登录后可在 Nexus 设置页管理 Deployment 成员。

签名私钥默认生成到 `CONTROL_DATA_DIR` 下的 `control-signing.key`，公钥写入 `control-signing.pub`，供 Nexus Server 只读加载。生产网关只需同源转发 `/auth/v1/*` 到 Control、`/nexus/v1/*` 到 Nexus Server；`/api/control/v1/internal/*` 不应暴露到公网。

HTTP 合同位于 [`docs/openapi.yaml`](./docs/openapi.yaml)。浏览器登录、登出、资料、密码、初始化和成员管理位于 `/auth/v1`；服务间 API 位于 `/api/control/v1/internal`，只保留 Principal exchange、人类 Session 核验、角色读取和身份失效序列，并且只接受 `CONTROL_SERVICE_TOKEN`。Nexus Server 不再提供或代理账号写接口。

Control 在同一数据库事务中追加身份失效事件。成员角色或状态变更产生 `principal_changed`，使每个 Nexus 副本清除该 owner 的 Principal lease 并关闭 WebSocket/runtime；头像变更产生 `profile_changed`，只刷新身份连接；登出产生带 exact `session_id` 的 `session_revoked`，只关闭对应浏览器连接。同一用户的其他 Session 和正在执行的 Agent 不受单次登出影响，整个流程不依赖只命中单实例的 webhook。

## 从现有 Nexus 导入

先停止旧 Nexus Server，再执行：

```bash
go run ./cmd/nexus-control import-nexus \
  --source /path/to/.nexus/app/data/nexus.db
```

导入保留 User ID、资料、角色和 Argon2id 密码哈希；目标 Control 可以使用 SQLite 或 PostgreSQL。旧 Session 不导入，用户需重新登录。

如需对 PostgreSQL 运行同一套认证契约测试，请让 `CONTROL_TEST_POSTGRES_URL` 指向一个全新的临时数据库后运行 `go test ./internal/service/auth -run TestPostgresControlConformance -count=1`。

完整停机、验收和回滚步骤由 Nexus 仓的 `docs/operations/control-migration.md` 维护。
