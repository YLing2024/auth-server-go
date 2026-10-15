# auth-server-go

自建统一认证中心（SSO / OIDC Provider）后端的 Go 重写版，与旧 `auth-server`（Node 24 +
Express）**字节级兼容**，可与旧服务并存甚至互认彼此签发的 token。

- TOTP 动态码登录（无账号、无静态密码；30 秒一变，±1 步容忍）
- Redis 滑动过期会话（默认 7 天）
- OIDC Provider：discovery / authorize / token / userinfo / jwks / introspect /
  end_session / revoke，ES256（P-256，`kid` = thumbprint）
- 登录设备会话管理（列表 / 改名 / 踢下线）+ 来源 GeoIP
- TOTP **两阶段重置**（pending 验证通过才转正，永不把已登录的人锁在外面）
- 按真实客户端 IP 阶梯限速（60s → 300s → 900s）

默认只监听 `127.0.0.1:19260`（旧服务 `3200` 不动，两个并存）。对外域名由部署决定，
不写进仓库。

## 构建与运行

```bash
go build -o bin/auth-server-go ./cmd/auth-server-go
DATA_DIR=/var/lib/auth-server-go REDIS_DB=15 ./bin/auth-server-go
```

依赖仅 `github.com/redis/go-redis/v9`；HTTP 用标准库 `net/http`，JWS/ES256 与 TOTP 均自实现。

## 环境变量

同名同默认对齐旧实现（例外见 [`docs/COMPAT.md`](docs/COMPAT.md) §2）。完整示例见
[`.env.example`](.env.example)。要点：

| 变量 | 默认 | 说明 |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `19260` | 新服务只监听回环 |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` | `127.0.0.1` / `6379` / `0` | 会话唯一存储 |
| `DATA_DIR` | 当前目录 | 密钥与注册表所在目录 |
| `ISSUER` | `http://127.0.0.1:19260` | 所有端点 URL 由它拼接；不硬编码域名 |
| `SSO_SUBJECT` / `SSO_DISPLAY_NAME` | `linden` / =subject | 身份唯一来源 |
| `SESSION_DAYS` | `7` | 会话滑动过期天数 |
| `INTERNAL_TOKEN_FILE` | `<DATA_DIR>/internal-token` | 0600 自动生成；值不打印不返回 |
| `ALLOWED_REDIRECT_ROOTS` | 空（仅同源） | 登录页跨域回跳白名单域名根，逗号分隔 |

## 文档

- [`docs/API.md`](docs/API.md)：全部 HTTP 端点的契约（鉴权 / 参数 / 示例 / 错误码 / 副作用）。
- [`docs/COMPAT.md`](docs/COMPAT.md)：与旧实现的一致性保证与**有意差异**清单。

## 质量门禁

```bash
make check        # gofmt + go vet + go test + 路由↔文档一致性机检
```

`make check` 等价于委托方要求的聚合检查，退出码须为 0。

## 目录结构

```
cmd/auth-server-go/   进程入口
internal/config/      环境变量与默认值
internal/jsonx/       无 HTML 转义的 JSON 序列化（对齐 JSON.stringify）
internal/jwt/         ES256 / HS256 JWS 与密钥库
internal/totp/        RFC 6238 TOTP、密钥存储、阶梯限速
internal/redis/       Redis 客户端与就绪探测
internal/oidc/        OIDC Provider 与各端点
internal/httpapi/     HTTP 路由表与会话/内部接口/登录页伺服
assets.go             内嵌登录页构建产物
public/ web/          登录页源码与产物（与旧实现同源）
docs/ scripts/        接口文档与机检脚本
deploy/               systemd 单元与环境样例（仅样例，不自动安装）
```

## 安全红线

- `oidc-keys.json` / `totp-secret.json` / `totp-pending.json` / `jwt-secret` / `clients.json`
  一律不入库，由 `DATA_DIR` 在部署期注入。
- 两阶段重置语义不可简化成「直接覆盖」。
- `redirect_uri` 必须与注册值字符串精确相等（无前缀 / 通配）。
- `id_token` 与 `access_token` 只准 ES256；撤销以 Redis 为准。
- 身份只有一个来源 `SSO_SUBJECT`；OIDC 路径与 `/api/verify` 给出的身份必须完全一致。
- 源码 / 文档 / 提交信息不得出现真实域名、公私网 IP、邮箱、密钥、真实口令、TOTP secret。
