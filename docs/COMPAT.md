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
- **限速（IP 维度）**：按真实客户端 IP（`X-Real-IP`）阶梯 60s → 300s → 900s；新增的设备维度
  属于有意差异，见 §3.7。
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

### 3.1 HTTP 方法回退与未匹配路由

- **已对齐**：动词不匹配、路径未匹配、HEAD 跟随 GET（POST-only 路径的 HEAD 落 404）、OPTIONS 两级
  回退（六个旧模块路径 200 + `Allow` + 正文 `POST`，其余含未知路径 204 + CORS）、Express 默认 404
  HTML 页（含 `encodeurl`/`escape-html`/`Content-Security-Policy`/`nosniff`）、尾斜杠容忍，全部逐行
  复刻旧实现。实测对照表见 `docs/API.md` §5「方法回退与未匹配路由」，实现见
  `internal/httpapi/legacy.go`。旧文档「新实现返回 405」的差异已消除。
- **仅剩**：畸形百分号转义（如 `/a%zz`、`/a%2zb`）由 Go `net/http` 请求解析层直接拒绝为
  `400 Bad Request`，旧实现在路由层回 `404`。这是 HTTP 解析层而非路由层的差异，改动前后一致。

### 3.2 畸形 JSON 请求体

- 旧：Express `express.json()` 直接报错，返回 **400** + Express 默认 HTML 错误页
  （正文含 `SyntaxError: ...`）。
- 新：`net/http` 侧宽容解析，坏 JSON 视为「没有 `code` 字段」，落到 **401
  `invalid_code`**（JSON）。
- 影响：仅影响畸形输入的错误形状；合法请求完全一致。

### 3.3 响应头

- 新实现不生成 Express 默认的 `ETag`；`Date` / `Content-Type` 等保持一致。
- `/auth` 的 `Content-Type` 字符集大小写不同：旧 `text/html; charset=UTF-8`、新
  `text/html; charset=utf-8`。仅大小写，语义等价。
- 302 跳转复刻 Express 形状：`Location` + `Vary: Accept` + `text/plain; charset=utf-8`
  正文 `Found. Redirecting to <url>`。

### 3.4 启动期配置校验

- `ACCESS_TTL_SEC` 非法（非数字）时：旧实现静默回落到 900；新实现**启动即报错**。
  `ACCESS_TTL_SEC < 60` 时两者都回落 900。这是刻意的 fail-fast，避免带着错误配置上线。
- `SSO_RL_IP_MAX` / `SSO_RL_DEVICE_MAX` / `SSO_RL_GLOBAL_MAX` 非正整数时新实现启动即报错
  （旧实现无这三个变量，始终按 IP 5 次）。属于同一套 fail-fast 策略。

### 3.5 登录页伺服方式

- 旧：`public/` 由部署期 nginx 直接伺服，auth-server 本身不发静态文件。
- 新：登录页与资源**内嵌进二进制**（`/auth` + `/assets/*`），单文件即可自洽运行；
  产物与旧 `public/` 同源同字节。生产仍建议由 nginx 伺服静态资源。
- `/assets/` 目录本身的 `HEAD`：旧由 nginx 语义回 404，新返回 200 目录响应；具体文件路径两者一致。

### 3.6 其它

- `/favicon.ico` 两者都返回 404（浏览器自动请求，非缺陷）。
- 根路径非 OIDC 请求两者都返回 404。

### 3.7 登录限速新增设备维度

旧实现只按 IP 计数，攻击者用 IP 池时每个地址只试几次即可绕过。新实现在保留 IP 维度
（5 次 → 60s/300s/900s）的同时，增加并行的设备维度：

- `/auth` 与登录提交接口下发 `__Host-ha_device`（128 位随机、`HttpOnly; Secure;
  SameSite=Lax; Path=/; Max-Age=31536000`），
  `deviceKey = sha256(Cookie + User-Agent + Sec-CH-UA + Accept-Language)`。
- 设备维度 10 次失败 → 300s/900s/3600s；任一维度锁定即 429，`retryAfter` 取较大者，
  响应不区分维度。成功登录清零两个维度。
- 全局失败计数（默认 60 次 / 5 分钟）只告警，不参与拒绝。阈值由 `SSO_RL_IP_MAX` /
  `SSO_RL_DEVICE_MAX` / `SSO_RL_GLOBAL_MAX` 调整。
- 隐私边界：不采集 canvas/字体/硬件信息；`deviceKey` 不落库，日志最多前 8 位。
- 429 文案统一为 `{"code":"rate_limited","message":"Too many attempts","retryAfter":N}`，
  仅 `code` 参与前端判断。
- 代价：清 Cookie 或换浏览器即视为新设备；不接收 Cookie 的客户端只受 IP 维度约束。

### 3.8 「记住我」与短会话

旧实现只有 7 天滑动会话，没有登录选项。新实现新增 `remember`（默认 `false`）：

- `remember=false`：会话 TTL 为 `SESSION_SHORT_TTL`（默认 900s），**绝对过期**；
  `touchSession()` 只更新 `lastSeenAt`，不做 `EXPIRE`；`HomeAuth` cookie 显式
  `Max-Age=900`，不依赖浏览器会话级 cookie。
- `remember=true`：保持旧行为，`SESSION_DAYS*86400` 滑动续期。
- 老会话（Redis hash 无 `remember` 字段）按 `remember=1` 读取，不会因升级突然掉线。
- `/token` 的 `expires_in` 改为 SSO 会话剩余有效期（供网关切站点 cookie），
  access/id token 自身 `exp` 仍是 `ACCESS_TTL_SEC`；`id_token` 新增布尔 claim `remember`。
- 新增 `SESSION_SHORT_TTL`，非正整数时启动失败（与其它 fail-fast 配置一致）。

## 4. 已知风险与未覆盖

- **限速状态在进程内存**：重启即清空，与旧实现一致；多实例部署需在更外层统一限速。
- **GeoIP 解析**：异步、失败静默留空；测试环境用不可达地址避免外呼，与旧实现行为一致。
- **单进程**：`log/slog` 输出到 stdout，由 systemd / 容器收集；未内置日志轮转。
