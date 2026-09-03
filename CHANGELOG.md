# Changelog

## [Unreleased]

- 建立独立 Control 服务，承接单部署 owner 初始化、密码登录、Session 与短期签名 Principal。
- 为 Nexus 的统一 Web Shell 提供同源登录、首次初始化和 Deployment 成员管理 API。
- 提供现有 Nexus SQLite 账号导入命令，保留 User ID 并统一失效旧 Session。
- 提供 Docker 镜像和 Control v1 OpenAPI 合同；内部 API 仅接受服务凭据。
- 按 Nexus 的 app/handler/service/storage 分层整理代码，并为 Control 增加固定 `control` schema 的 PostgreSQL 支持。
- 成员角色或状态变更与身份失效事件同事务提交，供所有 Nexus 副本按游标主动撤销 Principal lease。
- 浏览器资料、密码与回执写入统一进入 `/auth/v1`；登出和头像更新分别持久化 `session_revoked` 与 `profile_changed`，让 Nexus 精确刷新浏览器身份而不误杀同用户其他 Session 或 Agent runtime。
- 删除无消费者的内部登录、登出、资料和密码写接口；服务凭据面只保留 Nexus 验签与运行时准入所需的最小读取能力。
