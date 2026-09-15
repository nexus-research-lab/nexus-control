// Package auth 实现账号、会话、部署成员、entitlement 与持久失效序列的业务规则。
// 成员管理支持显示名称、角色、状态与 expected_version；访问撤销沿用 Session 与 Principal 失效链路。
// node.go 提供设备授权、租户隔离的精确回执与独立 Node 令牌交换。
package auth
