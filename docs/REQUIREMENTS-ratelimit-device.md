# 需求：SSO 登录限速改为「IP + 浏览器指纹」双维度

日期：2026-10-20　用户原话：「SSO 的限速要根据浏览器指纹 + IP 双限速，避免出现 IP 池搞我」

## 现状（已核实）

`auth-server-go` 里已有 `internal/totp.RateLimiter`：**只按 IP** 计数，5 次失败后按
`60s → 300s → 900s` 阶梯锁定；`/login`（`appLimiter`）与 TOTP 校验（`moduleLimiter`）都用它。

问题：攻击者用 IP 池时，每个 IP 只试 4 次就换下一个，永远碰不到阈值。

## 目标

新增**设备维度**计数，与 IP 维度**并行**：

```text
失败一次 → ipLimiter.RecordFailure(ip)
         → deviceLimiter.RecordFailure(deviceKey)
锁定条件 → ipLimiter 锁定  或  deviceLimiter 锁定（任一命中即拒）
成功一次 → 两个 limiter 都清零
```

这样：换 IP 不变设备 → 设备维度仍会累加到锁定；换设备不变 IP → IP 维度兜住。

## 一、设备标识（deviceKey）怎么来

不用 JS 采集 canvas/WebGL（隐私敏感、也易被绕过），用**服务端可验证的两样东西**组合：

```text
deviceKey = sha256( __Host-ha_device Cookie 值 + UA + sec-ch-ua + Accept-Language )
```

1. **`__Host-ha_device` Cookie**：首次访问登录页时由服务端下发
   - 128-bit 随机（`crypto/rand` → hex）
   - 属性：`HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=31536000`（1 年）
   - **必须带 `__Host-` 前缀**（强制 Secure + Path=/ + 无 Domain），与现有站点 Cookie 命名一致
   - 用户清 Cookie 或换浏览器 → 视为新设备（这是可接受的代价）
2. **UA + `sec-ch-ua` + `Accept-Language`**：同一 Cookie 在不同 UA 下算不同设备，防止 Cookie 被复制到别的客户端复用
3. **不做侵入式指纹**（不采集 canvas / 字体列表 / 硬件并发数），避免隐私争议

`deviceKey` 只在内存里做 key，**不落库、不进日志**（日志只允许出现其前 8 位哈希用于排障）。

## 二、限速参数

| Limiter | key | 阈值 | 阶梯 | 说明 |
|---|---|---|---|---|
| `ipLimiter`（现有） | 客户端 IP | 5 次 | 60s → 300s → 900s | 保持现状不动 |
| `deviceLimiter`（新增） | deviceKey | **10 次** | 300s → 900s → 3600s | 比 IP 宽，因为同一设备可能多人共用（公司网络） |
| `globalLimiter`（新增） | 全局 | **60 次/5 分钟** | 只告警不锁定 | 用于发现"广撒网"攻击，写日志 + 计数指标 |

- 阈值通过环境变量可调：`SSO_RL_IP_MAX`、`SSO_RL_DEVICE_MAX`、`SSO_RL_GLOBAL_MAX`
- 全局限速**只告警不拒绝**（避免被人用垃圾请求把你锁在门外）

## 三、改动点（auth-server-go）

1. `internal/totp/ratelimit.go`：`RateLimiter` 已按 key 泛化（内部用 `map[key]entry`），确认 key 语义为字符串即可复用，不重写算法
2. `internal/httpapi/login.go` / `totp.go`：
   - 失败分支：`RecordFailure(ip)` + `RecordFailure(deviceKey)`
   - 成功分支：两个 `RecordSuccess`
   - 锁定判断：任一 `Status(...).Locked` 为真 → 429，`retryAfter` 取两者较大值
3. 新增中间件/辅助函数：`DeviceKeyFromRequest(r)` —— 负责下发 Cookie（不存在时）与计算 deviceKey
4. 登录页 `/auth` 与 TOTP 提交接口都必须先经过它（保证第一次失败时 Cookie 已存在）
5. 响应体：429 时返回 `{"code":"rate_limited","message":"Too many attempts","retryAfter":N}`（与现有格式一致，**不暴露是 IP 还是设备触发**）

## 四、隐私边界（硬要求）

1. `deviceKey` **不入库、不进日志**；日志最多出现 `deviceKey[:8]`
2. 不采集任何客户端硬件/画布信息；只用一个服务端生成的随机 Cookie + 请求自带的 3 个标准头
3. Cookie 值不写入任何审计记录
4. 不引第三方依赖

## 五、nginx 层（Hermes 负责，不在本次代码范围内）

在认证域名上补一层连接级限流，作为应用层之前的粗筛：

```nginx
limit_req_zone $binary_remote_addr zone=sso_auth:10m rate=20r/m;
limit_req_zone $binary_remote_addr zone=sso_totp:10m rate=10r/m;
# /auth 与 /authorize 用 sso_auth；/token、TOTP 提交用 sso_totp
limit_req_status 429;
```

## 六、验收

1. 单 IP 连续 6 次错误密码 → 第 6 次 429（IP 维度，现有行为不回退）
2. **换 IP 不换设备**：用两个不同出口 IP（或用 `X-Forwarded-For` 注入模拟）各错 5 次 → 第 10 次被设备维度锁定（即使 IP 每次不同）
3. **换设备不换 IP**：同一 IP 清 Cookie 后重试 → 仍受 IP 维度限制
4. 登录成功后：两个维度的失败计数都归零（再错一次不会立刻 429）
5. `deviceKey` 在日志里只出现前 8 位；grep 不到完整 Cookie 值
6. 429 响应体不区分是哪个维度触发
7. 全局计数达到阈值时只写日志 + 指标，不影响正常登录
8. `make check` 全绿（含新的 ratelimit 单元测试：IP/设备交替失败、成功清零、阶梯升级）
