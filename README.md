# NetOps Portal

网络设备运维平台:登录保护、设备导航、在线检测、审计日志、后台管理。
技术栈:Cloudflare Workers + D1,零第三方依赖。

## 部署(GitHub 自动部署)
1. `wrangler d1 create netops`,把 database_id 填进 `wrangler.toml` 并提交
2. `npm run db:init` 初始化表结构(旧版本升级用 `migration.sql`)
3. Cloudflare 控制台 → Workers & Pages → Create → Import a repository,选择本仓库
4. 项目名必须与 `wrangler.toml` 中的 `name` 一致(netops-portal)
5. Settings → Variables and Secrets 添加 Secret:`SESSION_SECRET`、`ADMIN_USER`、`ADMIN_PASS`
6. 之后每次 push 到 main 自动部署

**不要把任何密码、密钥提交到仓库。**
