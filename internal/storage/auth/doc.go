// Package auth 持有 Control 账号、部署成员、Session 与密码回执的 SQL 仓储。
//
// L2 | 父级: internal/storage（L1 见 AGENTS.md）
//
// 成员清单：
//   - repository.go / model.go：Repository、方言辅助与持久化记录。
//   - account.go：Control 状态、owner、用户资料与旧 Nexus 导入事务。
//   - organization.go / registration.go：事务内实时权限、组织生命周期与独立账号注册。
//   - session.go：登录凭据、Session 生命周期和设备所有者校验；保留设备注册来源而不延长 Cookie。
//   - node.go：浏览器绑定的设备授权、凭据哈希、精确回执与撤销事务。
//   - member.go / identity_invalidation.go：组织成员事务与按提交顺序可消费的身份失效序列；身份写入先锁 Control 状态再锁业务行。
//   - entitlement.go：Deployment 套餐、成员有效额度与同事务额度失效事件。
//   - password.go：密码修改的 exact request 回执、CAS 提交与设备撤权同事务完成。
//
// [PROTOCOL]: 变更时更新此头部，然后检查父级入口 AGENTS.md（L1）
package auth
