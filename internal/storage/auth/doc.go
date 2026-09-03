// Package auth 持有 Control 账号、部署成员、Session 与密码回执的 SQL 仓储。
//
// L2 | 父级: internal/storage（L1 见 AGENTS.md）
//
// 成员清单：
//   - repository.go / model.go：Repository、方言辅助与持久化记录。
//   - account.go：Control 状态、owner、用户资料与旧 Nexus 导入事务。
//   - session.go：登录凭据、Session 创建、解析、触达和撤销。
//   - member.go / identity_invalidation.go：Deployment 成员事务与同事务身份失效序列。
//   - entitlement.go：Deployment 套餐、成员有效额度与同事务额度失效事件。
//   - password.go：密码修改的 exact request 回执与 CAS 提交。
//
// [PROTOCOL]: 变更时更新此头部，然后检查父级入口 AGENTS.md（L1）
package auth
