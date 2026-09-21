# 组织与账号生命周期

User 独立于 Organization 存在。Deployment membership 的 role 是平台角色；Organization membership 的 role 是组织角色。签名与状态同时输出 role、organization_role，禁止互相兜底。一个账号最多加入一个有效组织。无组织账号可登录、使用本地能力、创建组织或接受邀请，但不能获取 Relay Principal。

组织入口对所有远程登录用户开放。创建者成为唯一组织所有者，不获得平台运营权限。所有者可邀请普通成员或管理员、管理成员、原子移交所有权、解散组织；管理员只能邀请和管理普通成员；普通成员可看目录、主动退出。所有者必须移交或解散后才能退出。

邀请既支持新账号注册加入，也支持现有账号登录后加入。已有其他组织时明确冲突，不能自动退出旧组织。退出、移除和解散不删除账号、不撤销部署访问，只撤销对应组织的群聊、Agent、节点资格并发布持久失效事件；组织权限变更不改平台角色。重新加入不会恢复旧群成员和机器授权。

所有组织写事务先取得身份事件序列锁，再重新校验操作者的有效部署访问和组织角色，防止迟到的浏览器请求越权。创建/接受/退出/移交/解散均以数据库当前状态为准；失败不自动重放。迁移旧的多所有者组织时保留最早所有者，其他所有者降为组织管理员，不改变平台权限。

新组织事件为 `organization_changed`，包含 organization_id 和 membership_revoked。Relay 更新身份栅栏并撤销对应成员；Nexus 丢弃远程身份租约但不中断私人 Agent。历史 principal_changed 继续按原平台撤权语义处理，不能仅凭历史事件包含 organization_id 就跳过账号撤权。

公开注册由 CONTROL_REGISTRATION_ENABLED 显式开启，默认关闭；邀请注册不依赖公开注册开关。组织邀请不授予平台管理员权限。

## 页面与接口

组织成员资格与网页版工作台访问资格独立。登录成功不代表可以访问所有产品能力，客户端按服务端返回的资格展示可用入口；组织角色变更不改变网页版资格。

App/Web 都使用「设置 → 账户 → 组织」。本地身份仅显示远程登录引导；无组织显示创建入口和邀请链接说明；有组织显示目录及本角色允许的操作。创建/改名/退出/移交/解散调用同源 `/auth/v1/organization/{action}`；移交提交 target_user_id，创建/改名提交 name，其他提交空对象。已有账号接受邀请复用 `/organization-invitations/{token}/accept`，不提交密码。所有 mutation 要求同源 Origin。

## 数据与发布

迁移 10 为 SQLite/PostgreSQL 增加唯一 active 组织 owner 约束。Control SQLite 导入保留全部组织、历史成员和邀请，平台角色独立复制；Session 与 Node 授权不迁移，设备须重新授权。

Control、Nexus、Relay 需协调升级：先停止在线协作入口，备份数据库，升级 Control 并完成迁移，再升级 Nexus 与 Relay、恢复入口。旧 token 没有 organization_role，新 Relay 会拒绝；必须重新交换令牌，不做平台角色兜底。无需修改或迁移 App 用户数据目录。

解散组织是关闭协作权限，不物理清除历史消息；大数据清理和保留策略不在本次操作内。当前仅支持一个 active 组织，尚不提供多组织切换。公开注册若要开放，部署者显式设置 `CONTROL_REGISTRATION_ENABLED=true`；不开放时通过组织邀请注册或既有管理账号创建。
