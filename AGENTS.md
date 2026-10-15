# AGENTS.md — auth-server-go

> 维护本仓库前先读本文件。`README.md` 面向使用者；与本文冲突时以本文为准。
> 兼容性以旧仓库 `/root/proj/auth-server` 为功能权威：**行为对齐它是最高优先级**。

## 这个项目是什么

自建统一认证中心（SSO / OIDC Provider）的 Go 重写，登录入口。与旧 Node 实现并存，
读取同一份密钥、同一套 Redis 键空间、同一份 OIDC 契约。默认监听 `127.0.0.1:19260`。

## 技术栈与边界

- Go 1.26，HTTP 仅标准库 `net/http`；**唯一额外依赖** `github.com/redis/go-redis/v9`。
- JWS/ES256 自实现；TOTP 自实现（RFC 6238，HMAC-SHA1 / 6 位 / 30 秒 / ±1 步）；日志 `log/slog`。
- 不引 Web 框架，不引第三方 JWT 库，不引 SQL。
- 登录页与旧实现同源（`web/` 源码 → `public/` 产物），通过 `assets.go` 内嵌。

## 命令

```bash
go build -o bin/auth-server-go ./cmd/auth-server-go
go test ./... -count=1
go test ./... -count=1 -race
go vet ./...
gofmt -l .            # 必须无输出
make check            # 聚合门禁：gofmt + vet + test + 路由↔文档机检
```

## 路由注册（有坑，别乱动）

路由清单集中在 `internal/httpapi/routes.go` 的 `routeTable`，`routes()` 遍历它注册。
顺序即 Express 注册顺序；Go 1.22 起「更具体的模式优先」，精确路径自然压过模块兜底路由：

```
/config.js
POST /api/totp/reset|confirm   ← 自定义两阶段实现，先于模块路由
POST /api/login               ← 自定义登录，覆盖模块内置
POST /api/totp/setup|login、/api/setup、/api/reset   ← 旧模块路由
/api/verify /api/logout /api/sessions…
/api/internal/…
OIDC 端点（/authorize /token /jwks.json …，空 method = 任意动词，自行 405）
/assets/ 与 / 兜底
```

**新增路由必须同时登记到 `routeTable` 并写进 `docs/API.md`**，否则 `make check` 红灯。

## 环境变量

同名同默认对齐旧实现，例外（`PORT` / `HOST` / `ISSUER` 默认值）见 `docs/COMPAT.md` §2。
`ISSUER` 一律从环境变量取，**不得硬编码域名**。

## 安全红线

- `oidc-keys.json` / `totp-secret.json` / `totp-pending.json` / `jwt-secret` / `clients.json`
  **绝不入库**，由 `DATA_DIR` 注入；**绝不生成新密钥**（否则已签发 token 全废）。
- 两阶段重置：`reset` 只写 pending、绝不覆盖正式；`confirm` 必须 pending 验证通过才转正。
  对外与 `/api/internal/*` 共用同一实现，禁止复刻。
- 限速按真实客户端 IP（`X-Real-IP`，阶梯 60s → 300s → 900s）。
- `redirect_uri` 字符串精确相等；`id_token` / `access_token` 只准 ES256。
- 身份唯一来源 `SSO_SUBJECT`；`/api/internal/*` 只认 `X-Internal-Token`，令牌值不打印不返回。
- 源码 / 文档 / 提交信息不得出现真实域名、公私网 IP、邮箱、密钥、真实口令、TOTP secret、
  `clients.json` 内容。

## 已知坑

- **SSO 反向索引**：`EnsureSsoSession` 依赖 `ResolvedSession.Raw`（来源登录会话 token）写
  `oidc:sso-session:<会话哈希>`；`/api/logout`、`DELETE /api/sessions/:id`、同设备去重靠它
  连带删 `oidc:sso:<哈希>`。改会话解析时务必保留 `Raw`。
- **JSON 字节**：一律走 `internal/jsonx`（不转义 `<>&`）；多字段成功响应必须用有序结构体，
  不能用 `map`（Go map 会按键排序，破坏与旧实现一致的字段顺序）。
- **302 形状**：用 `redirectFound` 复刻 Express 的 `Vary` / 正文，不要直接 `http.Redirect`。
- **Redis 是会话唯一存储**：挂了等于全站登不上；启动时会做就绪探测。
- **`git`**：只本地小步提交，中文信息，沿用全局身份；禁止 push / 开分支 / rebase / reset --hard / merge。
