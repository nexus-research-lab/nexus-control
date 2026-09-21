// Package auth 实现账号、会话、部署成员、entitlement 与持久失效序列的业务规则。
// organization.go 管理账号独立的组织生命周期；组织权限与平台角色分离，移出组织不撤销登录。
// import_organization.go 保留多组织、历史成员关系与邀请；import.go 复制独立平台账号。
// node.go 提供设备授权、租户隔离回执与 15 分钟 Node 令牌；续签独立于浏览器自然到期。
package auth
