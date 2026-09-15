# Nexus Control

Nexus Control 是 Nexus 的账号、组织、部署与服务额度权威。它管理真人用户、密码、浏览器 Session、Deployment、Organization Membership、订阅套餐与成员 entitlement，并向 Nexus Server 与 Nexus Relay 签发短期 Principal。Deployment 表示安装实例，Organization 表示多人协作租户。

当前支持单 Deployment 下多个 Organization，以及 SQLite、PostgreSQL 两种数据库；每个账号最多一个 active Organization，也可以无组织。成员目录只返回当前 Organization，Principal 的 role 是平台角色、organization_role 是组织角色，二者独立。受信 Nexus Gateway 在建群前通过 Control internal API 批量校验真人成员归属。Relay 的 Room/Message、Agent 执行和 OAuth 不在本仓实现。

Node 授权使用 `/auth/v1/nodes` 注册、列出（最近 100 条）与撤销；注册必须有浏览器 Cookie、同源 Origin，以及明确选择的本人 Agent ID（1–32 个）。宿主生成并安全保存 32 字节随机 base64url 凭据，Control 仅保存 SHA-256 哈希；相同 Node ID、凭据和完整范围可以重放，不能覆盖或复活已撤销授权。`POST /auth/v1/nodes/token` 仅接受该独立凭据的 Bearer header，返回 60 秒 `nexus-relay-node` Principal，不使用浏览器 Cookie或服务 token。令牌绑定父 Session，登出后不能继续换取；节点撤销与父 Session 撤销均通过持久身份事件通知 Relay。当前是授权后端，Nexus 设备启用界面和 runtime 消费器尚未接入。

## 启动

在同级 `nexus` 仓运行 `make dev` 会一并启动 Control。单独启动时可将 [`env.example`](./env.example) 复制为 `.env` 后运行 `make run`；程序依次尝试当前目录和上级目录的 `.env`，且不会覆盖已经存在的进程环境变量。SQLite 数据库默认位于 `~/.nexus/control/data/control.db`，服务凭据与签名密钥位于 `~/.nexus/control/`；生产部署应显式设置路径和服务凭据。

日志使用与 Nexus Server 相同的结构化输出、终端 pretty 模式和滚动策略。默认同时写入 stdout 与 `~/.nexus/control/logs/logger-YYYY-MM-DD.log`；可通过 `LOG_LEVEL`、`LOG_FORMAT`、`LOG_STDOUT`、`LOG_FILE_ENABLED`、`LOG_PATH`、`LOG_ROTATE_DAILY`、`LOG_MAX_SIZE_MB`、`LOG_MAX_AGE_DAYS`、`LOG_MAX_BACKUPS`、`LOG_COMPRESS` 与 `LOG_NO_COLOR` 调整。

SQLite 是单机默认值。使用 PostgreSQL 时配置：

```env
CONTROL_DATABASE_DRIVER=postgres
CONTROL_DATABASE_URL=postgres://nexus_control:password@postgres:5432/nexus
```

PostgreSQL 表固定写入 `control` schema；连接会强制使用该 `search_path`。数据库账号需要能创建该 schema，或由管理员预先创建并授权。签名密钥和服务凭据仍由 `CONTROL_DATA_DIR` 指向的本地持久目录保存，不写入数据库。

首次平台 owner 可在 Nexus Web 的 `/setup` 页面创建，也可由安装器调用 `POST /api/control/v1/setup/owner`，或设置 `AUTH_INIT_OWNER_PASSWORD` 由服务启动时初始化。Web 初始化需额外设置至少 32 个字符的 `CONTROL_SETUP_TOKEN`；该 capability 不会保存在浏览器中。所有远程用户通过「设置 → 账户 → 组织」创建或管理组织；无组织账号可自行创建，创建者只获得组织 owner，平台订阅运营仍由平台 owner/admin 管理。组织邀请默认七天过期、单次消费，只存 token 哈希；支持新账号注册和已有账号登录后加入。公开注册需显式设置 `CONTROL_REGISTRATION_ENABLED=true`，默认关闭。完整权限与退出/移交/解散规则见 [组织生命周期](docs/organization-lifecycle.md)。

签名私钥默认生成到 `CONTROL_DATA_DIR` 下的 `control-signing.key`，公钥写入 `control-signing.pub`，供 Nexus Server 与 Nexus Relay 只读加载。Runtime audience 默认为 `nexus-runtime`，Relay User audience 固定为 `nexus-relay-user`；Relay Node 凭据不属于本阶段。生产网关只需同源转发 `/auth/v1/*` 到 Control、`/nexus/v1/*` 到 Nexus Server；`/api/control/v1/internal/*` 不应暴露到公网。

HTTP 合同位于 [`docs/openapi.yaml`](./docs/openapi.yaml)。浏览器登录、登出、资料、密码、初始化、成员和订阅运营位于 `/auth/v1`；服务间 API 位于 `/api/control/v1/internal`，只保留 Principal exchange、人类 Session 核验、角色/有效额度读取和身份失效序列，并且只接受 `CONTROL_SERVICE_TOKEN`。Nexus Server 不再提供或代理账号、套餐或成员额度写接口。

Control 在同一数据库事务中追加身份失效事件。成员角色或状态变更产生 `principal_changed`，使每个 Nexus 副本清除该 owner 的 Principal lease 并关闭 WebSocket/runtime；头像变更产生 `profile_changed`，只刷新身份连接；套餐或成员额度变更产生 `entitlement_changed`，刷新 Nexus 的本地额度投影并从下一次 Agent 请求开始生效，不中断正在执行的 Agent；登出产生带 exact `session_id` 的 `session_revoked`，只关闭对应浏览器连接。整个流程不依赖只命中单实例的 webhook。

## 从现有 Nexus 导入

先停止旧 Nexus Server，再执行：

```bash
go run ./cmd/nexus-control import-nexus \
  --source /path/to/.nexus/app/data/nexus.db
```

导入保留 User ID、资料、角色、Argon2id 密码哈希、订阅套餐与成员额度；目标 Control 可以使用 SQLite 或 PostgreSQL。旧 Session 不导入，用户需重新登录。

如果账号已经通过不含订阅域的早期 Control 版本迁移，只需在停机窗口补导订阅数据：

```bash
go run ./cmd/nexus-control import-nexus-subscriptions \
  --source /path/to/.nexus/app/data/nexus.db
```

该命令不会改写账号或密码，只更新当前 Deployment 的套餐与成员额度，并为 active 成员追加 `entitlement_changed`，因此可在重新启动 Nexus 前安全重跑。

如需对 PostgreSQL 运行同一套认证契约测试，请让 `CONTROL_TEST_POSTGRES_URL` 指向一个全新的临时数据库后运行 `go test ./internal/service/auth -run TestPostgresControlConformance -count=1`。

完整停机、验收和回滚步骤由 Nexus 仓的 `docs/operations/control-migration.md` 维护。

## 从 Control SQLite 迁移到 PostgreSQL

先停止旧 Control 并备份 SQLite 文件，再让目标配置指向一个空的 PostgreSQL `control` schema：

```bash
CONTROL_DATABASE_DRIVER=postgres \
CONTROL_DATABASE_URL='postgres://nexus_control:password@postgres:5432/nexus' \
go run ./cmd/nexus-control import-control-sqlite \
  --source /path/to/control.db
```

命令以只读方式打开源 SQLite，并原样保留 Deployment、全部 Organization、User、账号资料与状态、密码哈希、独立的平台/组织 Membership、组织邀请、Agent 公开身份、订阅套餐、成员 entitlement 和身份失效事件原 ID；目标事件序列同步推进，已有 Relay 消费游标可以继续使用。Session、Node 授权和密码修改回执不迁移，切换后用户必须重新登录并重新授权设备。目标只要已有任何 Control 业务数据便拒绝导入，成功后重复执行也会拒绝，避免生成第二套身份。
源库必须已经由同版本 Control 完成 migration；未知的新旧 schema 会直接拒绝，避免静默漏字段。
