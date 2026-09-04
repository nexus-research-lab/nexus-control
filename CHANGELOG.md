# Changelog

## [Unreleased]

## [0.1.0] - 2026-09-04

### 新增

- 建立独立 Control 服务，统一承接部署初始化、账号登录、会话、成员、订阅套餐和短期签名身份。
- 为 Nexus Web 提供同源登录、首次初始化和成员管理接口，并支持从现有 Nexus SQLite 保留用户编号迁移账号与订阅。
- 提供 SQLite、PostgreSQL `control` schema、Docker 镜像和 Control v1 OpenAPI 合同。
- 持久化身份与订阅变更事件，让多个 Nexus 副本按游标及时撤销旧身份并同步最新额度。

### 调整

- 将 Control 数据和滚动日志统一存放在 `~/.nexus/control`，启动时可读取当前目录或上级目录的 `.env`。
- 将浏览器账号写操作统一收口到 `/auth/v1`，内部服务凭据接口只保留验签和运行时准入所需的读取能力。
