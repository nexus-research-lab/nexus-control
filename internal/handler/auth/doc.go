// Package auth 暴露 Control 的浏览器认证、订阅运营与服务间身份 HTTP API。
// web.go 分别暴露 deployment-members 平台用户与 members 组织成员端点。
// member_management.go 提供服务凭据与实时真人 Session 双重校验的内部部署用户管理入口（/internal/deployment-members/manage）。
// web_node.go 提供浏览器设备授权、精确回执、撤销与独立机器交换入口。
// web_organization.go 提供独立账号注册及组织创建、改名、退出、移交、解散。
package auth
