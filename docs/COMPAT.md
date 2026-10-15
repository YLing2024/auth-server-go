# 与旧 Node 实现的兼容性说明

本服务是旧 `auth-server`（Node 24 + Express 4）的后端重写，目标是**字节级兼容**：同一份
`DATA_DIR` 密钥、同一套 Redis 键空间、同一份 OIDC 契约、同一枚 TOTP secret，两个进程可以
并存甚至互认彼此签发的 token。下面把「必须一致」与「有意不同」分开列清。

## 1. 必须一致（已逐条验证）

- **密钥与密钥空间**：读取同一份 `oidc-keys.json` / `totp-secret.json` / `totp-pending.json` /
  `jwt-secret` / `clients.json`（由 `DATA_DIR` 决定）；**绝不生成新密钥**。
- **OIDC 契约**：`/.well-known/openid-configuration`、`/authorize`、`/token`、`/userinfo`、
  `/jwks.json`、`/introspect`、`/end_session`、`/revoke`；PKCE S256；`redirect_uri` 字符串精确匹配；
  refresh 轮换 + 重放整链作废。
- **令牌**：`id_token` 与 `access_token` 只签 ES256（P-256，`kid` = thumbprint）；撤销一律以
  Redis 哈希记录为准。
- **Redis 键空间**：`auth:session:*`、`auth:sessions`、`oidc:code:*`、`oidc:sso:*`、
  `oidc:sso-session:*`（来源会话语义反向索引）、`oidc:at:*`、`oidc:rt:*`、`oidc:rtchain:*`、
  `oidc:sid:*`。登出 / 踢下线同设备去重均连带删 `oidc:sso:<哈希>`。
- **`/api/internal/*`**：只认 `X-Internal-Token`；`sub` 必须等于 `SSO_SUBJECT`（缺 → 400，
  非本实例 → 404）；与对外两阶段重置共用同一实现。
- **限速**：按真实客户端 IP（`X-Real-IP`）阶梯 60s → 300s → 900s。
- **身份**：唯一来源 `SSO_SUBJECT`；历史标签 `HomeAuth` 读取时归一化。
- **JSON 与落库字节**：一律不转义 `<` `>` `&`（等价 JS `JSON.stringify`），多字段成功响应
  用有序结构体固定字段顺序。

## 2. 有意不同的默认值（不改环境变量即生效）

| 变量 | 旧实现默认（代码） | 新实现默认 | 原因 |
|---|---|---|---|
| `PORT` | `3200` | `19260` | 新旧并存，避免占用线上端口 |
| `HOST` | `0.0.0.0` | `127.0.0.1` | 新服务只监听回环，对外由网关/nginx 承接 |
| `ISSUER` | `http://127.0.0.1:3200` | `http://127.0.0.1:19260` | 随端口调整；仍只从环境变量取，绝不硬编码域名 |

> 线上旧服务由 systemd 显式设置这些变量（`HOST=0.0.0.0`、`PORT=3200` 等）。部署新版时按
> `deploy/` 里的样例同样显式注入，即可完全对齐。

## 3. 行为差异（逐条列明）

### 3.1 HTTP 方法不匹配

- 旧：Express 未注册的动词落到 `oidc.router` 兜底，返回 **404**。
- 新：注册了动词的方法不匹配时返回 **405** 并带 `Allow` 头（更符合 HTTP 语义）。
- 影响：仅影响错误路径的状态码，正常流程无差别。例：`POST /jwks.json` 旧 404 / 新 405。

### 3.2 畸形 JSON 请求体

- 旧：Express `express.json()` 直接报错，返回 **400** + Express 默认 HTML 错误页
  （正文含 `SyntaxError: ...`）。
- 新：`net/http` 侧宽容解析，坏 JSON 视为「没有 `code` 字段」，落到 **401
  `invalid_code`**（JSON）。
- 影响：仅影响畸形输入的错误形状；合法请求完全一致。

### 3.3 响应头

- 新实现不生成 Express 默认的 `ETag`；`Date` / `Content-Type` 等保持一致。
- 302 跳转复刻 Express 形状：`Location` + `Vary: Accept` + `text/plain; charset=utf-8`
  正文 `Found. Redirecting to <url>`。

### 3.4 启动期配置校验

- `ACCESS_TTL_SEC` 非法（非数字）时：旧实现静默回落到 900；新实现**启动即报错**。
  `ACCESS_TTL_SEC < 60` 时两者都回落 900。这是刻意的 fail-fast，避免带着错误配置上线。

### 3.5 登录页伺服方式

- 旧：`public/` 由部署期 nginx 直接伺服，auth-server 本身不发静态文件。
- 新：登录页与资源**内嵌进二进制**（`/auth` + `/assets/*`），单文件即可自洽运行；
  产物与旧 `public/` 同源同字节。生产仍建议由 nginx 伺服静态资源。

### 3.6 其它

- `/favicon.ico` 两者都返回 404（浏览器自动请求，非缺陷）。
- 根路径非 OIDC 请求两者都返回 404。

## 4. 已知风险与未覆盖

- **限速状态在进程内存**：重启即清空，与旧实现一致；多实例部署需在更外层统一限速。
- **GeoIP 解析**：异步、失败静默留空；测试环境用不可达地址避免外呼，与旧实现行为一致。
- **单进程**：`log/slog` 输出到 stdout，由 systemd / 容器收集；未内置日志轮转。
