# auth-server-go HTTP API

本文件是 `/root/proj/auth-server-go`（自建认证中心 / OIDC Provider）的接口契约。路由清单在
`internal/httpapi/routes.go` 的 `routeTable` 中定义，`scripts/check-api-docs.mjs` 会把该表与本文件的
`### <METHOD> <path>` 端点标题逐个比对，缺一即 `make check` 失败。改路由必须同笔改本文件。

约定：本文所有 URL 用 `http://localhost:19260` 作占位（实际主机名与端口由部署环境通过 `PORT`/`HOST`/`ISSUER`
注入）；示例中的 token 均为占位串，不是真实凭据。

## 0. 认证模式

本服务只有一个身份来源：环境变量 `SSO_SUBJECT`（展示名 `SSO_DISPLAY_NAME`）。历史标签 `HomeAuth`
在读取时归一化为 `SSO_SUBJECT`。

| 通道 | 凭证 | 适用端点 | 失败响应 |
|---|---|---|---|
| 公开 | 无 | `/auth`、`/config.js`、`/api/login`、`/api/totp/setup`、OIDC discovery/jwks | 见各端点 |
| 会话令牌 | `?token=` / `X-Auth-Token` / `Authorization: Bearer <64 位十六进制会话令牌>` | `/api/verify`、`/api/logout`、`/api/sessions*`、`/api/totp/reset|confirm` | `401 {"code":"unauthorized"}` |
| 内部令牌 | `X-Internal-Token: <INTERNAL_TOKEN_FILE 内容>` | `/api/internal/*` | `401 {"code":"unauthorized"}` |
| OIDC | 客户端凭证 / PKCE / Bearer access_token | OIDC 端点 | OAuth 错误码，见各端点 |

- 会话令牌形如 `^[a-f0-9]{64}$`；`/api/verify` 额外兼容首方 SSO 令牌（43 字符）与接口令牌。
- `/api/internal/*` **只认**内部令牌；cookie / Bearer JWT / 会话令牌一律无效。
- 内部令牌首次启动自动生成到 `INTERNAL_TOKEN_FILE`（默认 `<DATA_DIR>/internal-token`，0600），值不打印、
  不返回；`INTERNAL_TOKEN` 可直接覆盖值。

环境变量（名称与默认值与旧 Node 实现一致，两处默认有意不同，见 `docs/COMPAT.md`）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `19260` / `127.0.0.1` | 监听地址（旧实现为 `3200` / `0.0.0.0`） |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` | `127.0.0.1` / `6379` / `0` | 会话存储；测试用独立库号隔离 |
| `DATA_DIR` | 当前工作目录 | 密钥 / 注册表目录 |
| `ISSUER` | `http://127.0.0.1:19260` | OIDC issuer，端点 URL 由它拼接；不得硬编码域名 |
| `SSO_SUBJECT` / `SSO_DISPLAY_NAME` | `linden` / = `SSO_SUBJECT` | 身份与展示名 |
| `SESSION_DAYS` | `7` | 会话滑动过期天数 |
| `JWT_SECRET` | 读 `<DATA_DIR>/jwt-secret` | 旧模块 HS256 密钥 |
| `INTERNAL_TOKEN_FILE` / `INTERNAL_TOKEN` | `<DATA_DIR>/internal-token` / 空 | 内部令牌文件与覆盖值 |
| `AUTH_GEOIP_URL` | `https://ip-api.com/json/{ip}?fields=status,country,regionName,city` | 登录来源解析模板 |
| `ALLOWED_REDIRECT_ROOTS` | 空（仅同源） | 登录页允许跨域回跳的域名根，逗号分隔 |
| `GATEWAY_BACKCHANNEL_URL` | `http://127.0.0.1:18920/_auth/backchannel-logout` | 全局登出 back-channel 目标 |
| `ACCESS_TTL_SEC` | `900` | access/id token 有效期（秒），`>=60` 才生效 |
| `SSO_RL_IP_MAX` | `5` | IP 维度每轮失败次数，阶梯 60s/300s/900s |
| `SSO_RL_DEVICE_MAX` | `10` | 设备维度每轮失败次数，阶梯 300s/900s/3600s |
| `SSO_RL_GLOBAL_MAX` | `60` | 全局失败告警阈值（5 分钟窗口，只告警不拒绝） |

### 登录限速与设备标识

`/api/login` 与 `/api/totp/login` 同时按 **IP**、**设备** 两个维度计数，并叠加
**指纹轮换检测**：

- 首次访问 `/auth` 或提交登录时，服务端下发 `__Host-ha_device` Cookie：128 位随机数的
  32 位小写十六进制，属性固定为 `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=31536000`
  （一年，无 `Domain`）。`__Host-` 前缀要求这三个属性同时成立。
- `deviceKey = sha256(Cookie 值 + User-Agent + Sec-CH-UA + Accept-Language + fp)`，只在进程内
  作为限速 key；不写 Redis、不写审计、日志最多出现其前 8 位。
- `fp` 来自登录页附带的两个请求头，二者必须同时满足才参与哈希，否则**整条忽略**：

  | 请求头 | 规则 |
  |---|---|
  | `X-Device-Fp` | 32 位小写十六进制（FingerprintJS `visitorId`）；超长（>64 字节）或格式不符即忽略 |
  | `X-Device-Fp-Conf` | `confidence.score`，取值 `[0.3, 1]`；缺失、非数字或低于 0.3 即忽略 |

  两个头只允许出现在 `POST /api/login`、`POST /api/totp/login` 的登录提交上，GET、静态资源与
  OIDC 跳转不得携带。服务端只收 visitorId 哈希，原始指纹特征全部在浏览器本地计算。
- 失败一次：IP 与设备各记一次；成功一次：两个维度都清零。
- 任一维度锁定即返回 `429`，`retryAfter` 取所有维度中较大的剩余秒数；响应体不区分维度。
- 客户端清 Cookie 或换浏览器视为新设备；拒绝 Cookie 的客户端仍受 IP 维度约束。
- 全局失败计数（默认 60 次 / 5 分钟）只写一条告警日志并保留计数指标，不参与拒绝判断，
  避免攻击者用垃圾请求把正常用户锁在门外。

**指纹轮换检测**（仅登录失败时记录，状态在进程内存）：

```text
key   = "fp:" + sha256(__Host-ha_device Cookie 值)[:16]
value = 该 Cookie 在 5 分钟窗口内见过的不同 visitorId（最多保留 8 个）
触发   = 不同 visitorId 数 > 3 → 该 Cookie 锁定 900 秒
```

- 成功登录只清 IP/设备锁，**不清**轮换集合，避免用正确动态码洗掉历史。
- 触发后同样返回 `429 {"code":"rate_limited","message":"Too many attempts","retryAfter":900}`，
  不暴露是轮换触发；日志只写 `deviceKey` 前 8 位，visitorId 与 Cookie 值不落日志。
- 内存上限 4096 个 Cookie 条目；达到上限后新 Cookie 不做轮换跟踪（fail-open），
  IP/设备两个维度仍然生效。

```bash
# 第 6 次错误码（同一 IP）返回：
curl -s -X POST http://localhost:19260/api/login \
  -H 'Content-Type: application/json' -d '{"code":"000000"}'
# {"code":"rate_limited","message":"Too many attempts","retryAfter":60}
```

## 1. 端点索引

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/config.js` | 公开 | 登录页运行期配置（仅回跳白名单域名根） |
| GET | `/auth` | 公开 | 登录页 |
| POST | `/api/login` | 公开 + IP/设备/指纹限速 | TOTP 校验并签发会话令牌 |
| GET | `/api/verify` | 会话令牌 | 校验令牌并返回身份，滑动续期 |
| POST | `/api/logout` | 会话令牌 | 删除会话（连带撤销 SSO/共享 cookie） |
| GET | `/api/sessions` | 会话令牌 | 登录设备列表 |
| PUT | `/api/sessions/{id}/name` | 会话令牌 | 重命名设备 |
| DELETE | `/api/sessions/{id}` | 会话令牌 | 踢下线 |
| POST | `/api/totp/reset` | 会话令牌 | 两阶段重置①：写 pending |
| POST | `/api/totp/confirm` | 会话令牌 | 两阶段重置②：pending 通过才转正 |
| POST | `/api/totp/setup` | 公开（仅首启） | 旧模块：首次生成 secret |
| POST | `/api/totp/login` | 公开 + IP/设备/指纹限速 | 旧模块：签发 HS256 JWT |
| POST | `/api/setup` | 公开（仅首启） | 旧模块别名 |
| POST | `/api/reset` | Bearer JWT | 旧模块别名 |
| GET | `/api/internal/sessions` | 内部令牌 | 按 `sub` 列出设备会话 |
| PUT | `/api/internal/sessions/{id}/name` | 内部令牌 | 重命名设备 |
| DELETE | `/api/internal/sessions/{id}` | 内部令牌 | 踢下线 |
| POST | `/api/internal/totp/reset` | 内部令牌 | 两阶段重置①（与对外共用实现） |
| POST | `/api/internal/totp/confirm` | 内部令牌 | 两阶段重置②（与对外共用实现） |
| GET | `/.well-known/openid-configuration` | 公开 | OIDC discovery |
| GET | `/jwks.json` | 公开 | ES256 公钥集 |
| GET | `/authorize` | 公开 | 授权端点（PKCE S256） |
| POST | `/token` | 客户端凭证 | 授权码 / refresh 交换 |
| GET | `/userinfo` | Bearer | 用户信息 |
| GET | `/introspect` | 公开（RFC 7662） | token 内省 |
| POST | `/revoke` | 客户端凭证 | token 撤销 |
| GET | `/end_session` | 公开 | RP-Initiated Logout |
| GET | `/assets/` | 公开 | 登录页构建产物静态资源 |
| ANY | `/` | 公开 | 兜底 404 |

> 说明：方法回退与未匹配路由**逐行复刻**旧 Express 实现，规则与实测对照表见 §5
> 「方法回退与未匹配路由」。简言之：HEAD 跟随 GET；动词错误或路径未匹配返回 Express 默认 404 HTML
> 页（不是 `405`）；OPTIONS 分两级回退（模块路由 200，其余 204）。

OIDC 错误统一为 `{"error":"<code>","error_description":"<中文说明>"}`，HTTP 状态见各端点。

## 2. 会话与 TOTP

### GET /config.js

登录页运行期配置。**只注入回跳白名单域名根**，永不包含凭据。

- 鉴权：无。参数：无。
- 响应：`200`，`Content-Type: application/javascript; charset=utf-8`，`Cache-Control: no-store`。

```bash
curl -s http://localhost:19260/config.js
# window.__AUTH_CONFIG__ = {"allowedRedirectRoots":["example.com"]};
```

`ALLOWED_REDIRECT_ROOTS` 为空时返回 `{"allowedRedirectRoots":[]}`（仅同源回跳，绝不放开为任意域）。

### GET /auth

返回内嵌的登录页 `index.html`（Ant Design 构建产物）。`?redirect=` 为登录后回跳地址，白名单语义与旧实现一致。

- 鉴权：无。参数：`redirect`（query，可选，字符串）。
- 响应：`200 text/html; charset=utf-8`，`Cache-Control: public, max-age=0`；首次访问（无有效
  `__Host-ha_device`）同时下发一年期设备 Cookie，该次响应改为 `Cache-Control: no-store`，
  避免共享缓存把某个访客的设备标识发给别人。

```bash
curl -s -o /dev/null -w '%{http_code}\n' 'http://localhost:19260/auth?redirect=%2F'
```

### POST /api/login

校验 TOTP 动态码，签发 Redis 会话令牌。身份恒为 `SSO_SUBJECT`。

- 鉴权：无。限速：IP 维度按真实客户端 IP（`X-Forwarded-For` 首段 → `X-Real-IP` → peer），
  每轮 5 次失败后按 60s/300s/900s 阶梯锁定；设备维度按 `__Host-ha_device` Cookie +
  `User-Agent` + `Sec-CH-UA` + `Accept-Language` + 可信指纹计算，每轮 10 次失败后按
  300s/900s/3600s 阶梯锁定；同一 Cookie 5 分钟内出现 >3 个不同 `visitorId` 时另锁 900 秒。
  任一维度锁定即 429，`retryAfter` 取较大者，成功登录时 IP/设备两个维度清零（轮换集合保留）。
  详见 §0「登录限速与设备标识」。
- 可选请求头：`X-Device-Fp`（32 位小写十六进制 visitorId）、`X-Device-Fp-Conf`
  （0~1 的置信度，低于 0.3 时忽略指纹）。缺失或非法时退化为不带指纹的四字段哈希。
- 请求体（JSON）：`code`（string，必填，6 位数字，允许空格）。

```bash
curl -s -X POST http://localhost:19260/api/login \
  -H 'Content-Type: application/json' -d '{"code":"123456"}'
# {"token":"<64 位十六进制>","expiresIn":604800}
```

- 成功：`200 {"token":"<64hex>","expiresIn":<SESSION_DAYS*86400>}`。
- 副作用：写会话键（滑动 7 天）、登记设备元数据、撤销同设备旧会话。

| 状态 | `code` | 语义 |
|---|---|---|
| 429 | `rate_limited` | IP、设备或指纹轮换维度处于锁定档位（不区分来源，附 `retryAfter` 秒） |
| 403 | `totp_setup_required` | 尚未配置 TOTP |
| 401 | `invalid_code` | 动态码错误（计入失败） |
| 500 | `redis_unavailable` | Redis 不可用，拒绝发会话 |

### GET /api/verify

兼容保留（旧探针场景）。按 `?token=` → `X-Auth-Token` → `Authorization: Bearer` 顺序取令牌，命中则滑动续期。

- 鉴权：会话令牌（也识别首方 SSO 令牌、接口令牌 `api:token:`）。
- 成功：`200 {"ok":true,"user":"<SSO_SUBJECT>","exp":<unix 秒>}`，同时写 `X-Auth-User` 响应头。

```bash
curl -s 'http://localhost:19260/api/verify?token=<session-token>'
```

| 状态 | `code` | 语义 |
|---|---|---|
| 401 | `unauthorized` | 未提供令牌 |
| 401 | `invalid_token` | 令牌无效或过期 |
| 503 | `redis_unavailable` | Redis 不可用 |

### POST /api/logout

删除会话令牌，并连带撤销该会话派生出的 SSO/共享 cookie，最后异步通知 Auth Gateway 的 back-channel。

- 鉴权：会话令牌。请求体：`token`（string，必填）。
- 成功：`200 {"ok":true}`。

```bash
curl -s -X POST http://localhost:19260/api/logout \
  -H 'Content-Type: application/json' -d '{"token":"<session-token>"}'
```

副作用：删除 `auth:session:*`、`oidc:sso:<hash>` 及其反向索引，并 POST back-channel。

### GET /api/sessions

列出本用户登录设备。鉴权：会话令牌。

```bash
curl -s http://localhost:19260/api/sessions -H 'Authorization: Bearer <session-token>'
# {"sessions":[{"id":"<64hex>","user":"<sub>","deviceName":"Chrome · Linux","ip":"...","location":"...","isLocal":"0","userAgent":"...","createdAt":1726000000000,"lastSeenAt":1726000000000,"current":true}]}
```

### PUT /api/sessions/{id}/name

重命名设备。鉴权：会话令牌。路径 `id` 必须匹配 `^[a-f0-9]{64}$`。
Body：`deviceName`（string，必填，截断 64 字符）。成功 `200 {"ok":true,"deviceName":"..."}`；`400 invalid_id` / `400 invalid_name` / `404 not_found`。

```bash
curl -s -X PUT http://localhost:19260/api/sessions/<id>/name \
  -H 'Authorization: Bearer <session-token>' -H 'Content-Type: application/json' \
  -d '{"deviceName":"My Laptop"}'
```

### DELETE /api/sessions/{id}

踢下线。鉴权：会话令牌。会撤销会话并连带撤销关联 SSO/共享 cookie（**不**触发 back-channel，与 `/api/logout` 的差异见 `docs/COMPAT.md`）。成功 `200 {"ok":true}`。

```bash
curl -s -X DELETE http://localhost:19260/api/sessions/<id> -H 'Authorization: Bearer <session-token>'
```

### POST /api/totp/reset

两阶段重置①。**只写 pending（5 分钟），绝不覆盖正式 secret。**

- 鉴权：会话令牌。成功：`200 {"secret":"<base32>","otpauthUri":"otpauth://...","expiresIn":300}`。

```bash
curl -s -X POST http://localhost:19260/api/totp/reset -H 'Authorization: Bearer <session-token>'
```

副作用：写 `<DATA_DIR>/totp-pending.json`（不写正式文件）。

### POST /api/totp/confirm

两阶段重置②。pending 验证码通过才把 pending 转正并删除 pending；失败即作废 pending，**保持正式 secret 不变**。

- 鉴权：会话令牌。Body：`code`（string，必填）。
- 成功：`200 {"ok":true}`。

```bash
curl -s -X POST http://localhost:19260/api/totp/confirm \
  -H 'Authorization: Bearer <session-token>' -H 'Content-Type: application/json' -d '{"code":"123456"}'
```

| 状态 | `code` | 语义 |
|---|---|---|
| 400 | `no_pending` | 没有待确认的重置 |
| 400 | `invalid_code` | pending 验证码错误（pending 已作废） |
| 401 | `unauthorized` | 未登录 |

### POST /api/totp/setup

旧 `totp-auth` 模块路由：仅当尚未配置正式 secret 时可用。成功 `200 {"secret":..,"otpauthUri":..}`；
已配置返回 `409 {"code":"totp_already_setup"}`。

### POST /api/setup

`/api/totp/setup` 的旧模块别名（挂载在 `/api` 下），语义一致。

### POST /api/totp/login

旧 `totp-auth` 模块路由：校验 TOTP 后签发 **HS256 JWT**（`expiresIn:"12h"`，字符串）。
IP 维度沿用模块原实现（按 peer IP，60s/300s/900s），并与 `/api/login` 共用同一个设备维度
（`__Host-ha_device`，10 次 → 300s/900s/3600s）、同一指纹轮换锁（5 分钟 >3 个 visitorId →
900 秒）和全局告警计数。可选请求头 `X-Device-Fp` / `X-Device-Fp-Conf`，规则见 §0。

### POST /api/reset

`/api/totp/reset` 的旧模块路由：需 Bearer JWT，重新生成正式 secret。

## 3. 内部接口（`X-Internal-Token`）

`/api/internal/*` 只认 `X-Internal-Token`，不走会话鉴权。`sub` 必须等于本实例 `SSO_SUBJECT`
（缺 `sub` → `400 invalid_sub`；非本实例用户 → `404 not_found`）。对外与内部共用同一重置实现。

### GET /api/internal/sessions?sub=&lt;sub&gt;

内部列出某用户设备会话，结构同 `GET /api/sessions`。缺 `sub` → `400 invalid_sub`。

```bash
curl -s 'http://localhost:19260/api/internal/sessions?sub=<SSO_SUBJECT>' \
  -H "X-Internal-Token: $(cat <INTERNAL_TOKEN_FILE>)"
# {"sessions":[...]}
```

### PUT /api/internal/sessions/{id}/name

内部重命名设备，body `deviceName`。语义与对外一致。

### DELETE /api/internal/sessions/{id}

内部踢下线。语义与对外一致，可带 `?sub=` 做强归属校验。

### POST /api/internal/totp/reset?sub=&lt;sub&gt;

两阶段重置①，响应形状与 `/api/totp/reset` 完全一致。

### POST /api/internal/totp/confirm?sub=&lt;sub&gt;

两阶段重置②，body `{code}`，响应形状与 `/api/totp/confirm` 完全一致。

## 4. OIDC 端点

所有 OIDC 路径共享 CORS 头 `Access-Control-Allow-Origin: *`，`OPTIONS` 返回 `204`。issuer 由 `ISSUER` 决定。

### GET /.well-known/openid-configuration

Discovery 文档。`Cache-Control: no-store`。字段与旧实现逐字段一致（`response_types_supported:["code"]`、
`id_token_signing_alg_values_supported:["ES256"]` 等）。

```bash
curl -s http://localhost:19260/.well-known/openid-configuration
```

### GET /jwks.json

ES256 公钥集（`kid` = RFC 7638 thumbprint）。`Cache-Control: public, max-age=300`。同一 `oidc-keys.json`
下与旧实现逐字节一致。

```bash
curl -s http://localhost:19260/jwks.json
```

### GET /authorize

授权端点。参数（query）：`client_id`、`redirect_uri`（**字符串精确匹配**注册值）、`response_type`
（必须 `code`）、`scope`（必须含 `openid`）、`state`、`nonce`、`code_challenge`（公开客户端必填，
方法仅 `S256`）、`code_challenge_method`、`prompt`（`login` 强制重登）、`max_age`、`token`（登录后回跳携带）。

- 无会话：`302` 到 `/auth?redirect=<本请求>`（回跳白名单校验）。
- 有会话：`302` 到 `redirect_uri?code=<43 字符>&state=...`，并下发首方 SSO cookie。
- 校验失败：`400` HTML 错误页（`invalid_request` / `unsupported_response_type` / `invalid_scope`）。

```bash
curl -s -o /dev/null -D - 'http://localhost:19260/authorize?response_type=code&client_id=example-app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fsso%2Fcallback&scope=openid+profile&state=abc&code_challenge=<S256>&code_challenge_method=S256'
```

### POST /token

授权码 / refresh 交换。`application/x-www-form-urlencoded`，客户端凭证走 `client_secret_post` / `client_secret_basic`。

- `grant_type=authorization_code`：`code`、`redirect_uri`、`client_id`、`code_verifier`（公开客户端）。
- `grant_type=refresh_token`：`refresh_token`、`client_id`。
- 成功：`200 {"access_token":"<ES256 JWT>","token_type":"Bearer","expires_in":900,"id_token":"<ES256 JWT>","refresh_token":"<32 字节随机>","scope":"..."}`。
- refresh 轮换：每次用后旧 refresh 作废；**重放旧 refresh 整链作废**。

```bash
curl -s -X POST http://localhost:19260/token \
  -d 'grant_type=authorization_code&code=<code>&redirect_uri=https://app.example.com/sso/callback&client_id=example-app&code_verifier=<verifier>'
```

| 状态 | `error` | 语义 |
|---|---|---|
| 400 | `invalid_grant` | 授权码无效/已用/过期，或 refresh 已用（整链作废） |
| 400 | `invalid_request` | 缺参数 / 参数不匹配 |
| 401 | `invalid_client` | 未知客户端或密钥错误 |
| 400 | `unsupported_grant_type` | 不支持的 grant_type |

### GET /userinfo

Bearer access_token（支持 ES256 JWT 与旧式不透明串）。以 Redis 哈希记录为准判断有效性。

```bash
curl -s http://localhost:19260/userinfo -H 'Authorization: Bearer <access_token>'
# {"sub":"<SSO_SUBJECT>","preferred_username":"<SSO_SUBJECT>","name":"<SSO_DISPLAY_NAME>","sid":"..."}
```

| 状态 | `error` | 语义 |
|---|---|---|
| 401 | `invalid_token` | 缺令牌或令牌无效/已撤销 |
| 503 | `temporarily_unavailable` | Redis 不可用 |

### GET /introspect

RFC 7662。接受 body `token` / query `token` / Bearer。无效一律 `200 {"active":false}`。

```bash
curl -s -X POST http://localhost:19260/introspect -d 'token=<access_token>'
# {"active":true,"sub":"<sub>","scope":"openid profile","client_id":"example-app","exp":1726000000,"token_type":"access_token"}
```

### POST /revoke

RFC 7009。需客户端凭证。撤销 access_token（删 `oidc:at:<hash>`）与 refresh（整链）、并撤销对应 SSO 会话、
旧会话键。始终 `200 {}`（未知客户端 `401 invalid_client`）。

```bash
curl -s -X POST http://localhost:19260/revoke -d 'client_id=example-app&token=<access_token>'
```

### GET /end_session

RP-Initiated Logout。参数：`id_token_hint`、`post_logout_redirect_uri`（需注册白名单）、`client_id`。
撤销当前 SSO 会话与该 `sid` 全部令牌，清共享 cookie，并异步通知 Auth Gateway back-channel。

- `post_logout_redirect_uri` 合法：`302` 回跳；未列入白名单：`400 invalid_request` HTML。
- 无 `post_logout_redirect_uri`：`200` “已退出” 页面。

```bash
curl -s -o /dev/null -D - 'http://localhost:19260/end_session?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F&client_id=example-app'
```

## 5. 静态与兜底

### GET /assets/

登录页构建产物（`web/` → `public/`，`//go:embed` 进二进制）。按路径返回静态文件。

### ANY /

兜底：未知路径返回 Express 默认 404 页；若路径属于 OIDC 端点则转交 OIDC 处理器并附加 CORS 头。

#### 方法回退与未匹配路由

本节是旧 Express 可观测行为的逐行复刻，对照表由隔离实例实测生成（旧实现 `127.0.0.1:19280`、
新实现 `127.0.0.1:19282`，共用同一只读密钥副本与 `REDIS_DB=15`）；实现集中在
`internal/httpapi/legacy.go`，单元测试见 `internal/httpapi/legacy_test.go`。

- **HEAD 跟随 GET**：Express `Route._handles_method` 把 HEAD 归一化为 GET。GET 路由接受 HEAD
  （net/http 自动去掉响应体、保留头与 `Content-Length`）；POST-only 路由的 HEAD 与其它错误动词一样
  落到 404 页。
- **OPTIONS 两级回退**：
  - 旧模块路由（`/api/login`、`/api/setup`、`/api/reset`、`/api/totp/setup`、`/api/totp/login`、
    `/api/totp/reset`）命中 Express 自动 OPTIONS：**200** + `Allow: POST` + 正文 `POST`（无 CORS 头）。
  - 其余任何路径（含未注册路径，如 `OPTIONS /api/verify`、`OPTIONS /api/totp/confirm`）落到 OIDC
    路由器的 CORS 中间件：**204**，空正文，带 `Access-Control-Allow-Origin: *`、
    `Access-Control-Allow-Headers: Authorization, Content-Type`、
    `Access-Control-Allow-Methods: GET, POST, OPTIONS`。
- **未匹配 / 动词错误 → finalhandler 404**：正文是 Express 默认 HTML 文档，头为
  `Content-Type: text/html; charset=utf-8`、`Content-Security-Policy: default-src 'none'`、
  `X-Content-Type-Options: nosniff`、`Access-Control-Allow-Origin: *`。请求目标先经 `encodeurl`
  再 `escape-html`（`& → &amp;`、`< → %3C`、`' → &#39;`、孤立 `%` → `%25`）。HEAD 保留
  `Content-Length` 但空正文。
- **尾斜杠容忍**：Express 默认 `strict=false`，`…/` 与无斜杠形式同义（`/assets/` 子树除外）。

| 请求 | 状态 | Content-Type | Allow | CORS | 正文（HEAD 为空） |
|---|---|---|---|---|---|
| `OPTIONS /api/login` | 200 | `text/html; charset=utf-8` | POST | 无 | `POST` |
| `OPTIONS /api/totp/reset` | 200 | `text/html; charset=utf-8` | POST | 无 | `POST` |
| `OPTIONS /api/totp/confirm` | 204 | — | — | `*` | 空 |
| `OPTIONS /api/verify` | 204 | — | — | `*` | 空 |
| `OPTIONS /definitely-nope` | 204 | — | — | `*` | 空 |
| `HEAD /api/verify` | 401 | `application/json; charset=utf-8` | — | 无 | 空（GET 处理器） |
| `HEAD /jwks.json` | 200 | `application/json; charset=utf-8` | — | `*` | 空（GET 处理器） |
| `HEAD /api/login` | 404 | `text/html; charset=utf-8` | — | `*` | 空（`Content-Length: 149`） |
| `GET /definitely-nope` | 404 | `text/html; charset=utf-8` | — | `*` | `Cannot GET /definitely-nope`（CL=154） |
| `PUT /api/login` | 404 | `text/html; charset=utf-8` | — | `*` | `Cannot PUT /api/login`（CL=148） |
| `PUT /jwks.json` | 404 | `text/html; charset=utf-8` | — | `*` | `Cannot PUT /jwks.json`（CL=148） |

> 残余差异（非本类问题，见 `docs/COMPAT.md` §3）：畸形百分号转义（如 `/a%zz`）由 Go `net/http`
> 请求解析层直接拒绝为 `400 Bad Request`，旧实现在路由层回 `404`，改动前后一致；`HEAD /assets/`
> 旧 404 / 新 200（静态目录语义）。

## 6. 数据模型约定

- **ID 类型**：会话 ID / 令牌均为 64 位小写十六进制字符串；设备 ID 用同一形态；`sid` 为 16 位十六进制字符串。
- **时间**：Redis 记录中的 `createdAt`/`lastSeenAt` 为 Unix 毫秒（字符串）；OIDC `exp`/`iat`/`auth_time` 为
  Unix 秒；HTTP `expiresIn` 为秒。时区无关（UTC 语义）。
- **TTL**：会话 `SESSION_DAYS*86400`（滑动）；access/id token `ACCESS_TTL_SEC`（默认 900s）；授权码 60s；
  refresh 30 天；sid 记录 `max(access,refresh)`；pending 重置 300s。
- **枚举**：`userinfo.token_type` ∈ {`access_token`,`refresh_token`}；`introspect` 同；
  `deviceName` 截断至 64 字符；`isLocal` ∈ {`"0"`,`"1"`}。
- **设备标识**：`__Host-ha_device` 只存在客户端 Cookie 中；派生的 `deviceKey` 只作为进程内限速
  key，不入 Redis、不入审计日志（日志最多前 8 位）。

### Redis 键空间

| 键 | 类型 | 语义 |
|---|---|---|
| `<64hex 会话令牌>` | string | 会话身份（值 = `SSO_SUBJECT`，旧值 `HomeAuth` 读取时归一化），滑动 TTL |
| `auth:sessions` | set | 已登记会话令牌索引 |
| `auth:session:<token>` | hash | 设备元数据（user/deviceName/ip/location/isLocal/userAgent/createdAt/lastSeenAt） |
| `oidc:code:<sha256>` | string | 授权码记录（60s） |
| `oidc:at:<sha256>` | string | access_token 记录（撤销判定的唯一依据） |
| `oidc:rt:<sha256>` | string | refresh 记录（含 `chain`、`used`） |
| `oidc:rtchain:<chain>` | set | 一条 refresh 链的全部哈希 |
| `oidc:sso:<sha256>` | string | 首方 SSO 会话（含 `session_hash`） |
| `oidc:sso-session:<会话哈希>` | set | 会话 → SSO 令牌反向索引 |
| `oidc:sid:<sid>` | set | 一次登录（sid）下发的全部令牌哈希 |
| `api:token:<sha256>` | string | 接口令牌元数据（固定过期，不滑动） |

登出 / 踢下线必须连带删除 `oidc:sso:<哈希>`（及反向索引与 sid 集合），使共享 cookie 立即失效。
