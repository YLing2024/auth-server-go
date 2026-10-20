# 需求：SSO 登录限速接入 FingerprintJS（前端 visitorId + 服务端轮换检测）

日期：2026-10-20
用户决定：直接用 **FingerprintJS**（不自研指纹）。
已核实：`@fingerprintjs/fingerprintjs@5.3.0`，**MIT 许可**，`dist/fp.min.js` **37 KB / gzip 15.9 KB**，零运行时依赖。

## 一、前端（auth-server-go/web）

1. **依赖**：`npm i -E @fingerprintjs/fingerprintjs@5.3.0`
   - 必须 `-E` 锁死精确版本；这是唯一新增依赖，不许再加别的

2. **新增 `web/src/fingerprint.ts`**

```ts
import FingerprintJS from '@fingerprintjs/fingerprintjs'

// 整个页面会话只算一次，结果缓存在内存
let cached: { visitorId: string; confidence: number } | null | undefined

export async function deviceFingerprint(): Promise<{ visitorId: string; confidence: number } | null> {
  if (cached !== undefined) return cached
  try {
    const fp = await FingerprintJS.load({ monitoring: false })   // 关掉它的遥测
    const r = await fp.get()
    cached = { visitorId: r.visitorId, confidence: r.confidence?.score ?? 0 }
  } catch {
    cached = null            // 任何失败都降级为「不带指纹」，不得阻断登录
  }
  return cached
}
```

- `monitoring: false` 是硬要求：FingerprintJS 默认会往它自己的域名发匿名统计，本部署**禁止外联**
- 超时保护：`Promise.race` 加 1.5 秒上限，超时按 `null` 处理

3. **只在两个 POST 上带**（登录与 TOTP 提交处）：

```http
X-Device-Fp: <32 位小写 hex>
X-Device-Fp-Conf: <0.00~1.00>   # confidence.score，服务端 < 0.3 时忽略指纹
```

GET、静态资源、OIDC 跳转一概不带。

4. **不写入任何存储**：不进 localStorage / sessionStorage / cookie，只在内存。

## 二、后端（auth-server-go）

`internal/httpapi/device.go`：

1. **并入 deviceKey**

```go
sum := sha256.Sum256([]byte(id + UA + Sec-CH-UA + Accept-Language + fp))
```

`fp` 取值规则：

| 情况 | 处理 |
|---|---|
| 头 = 32 位小写 hex 且 `X-Device-Fp-Conf` ≥ 0.3 | 参与哈希 |
| 头格式非法 / 置信度缺失或 < 0.3 | **整条忽略**，退化为现有四项哈希 |
| 头超长（> 64 字节） | 忽略 |

2. **指纹轮换检测**

```text
key   = "fp:" + sha256(deviceCookieID)[:16]
value = 该 Cookie 在 5 分钟窗口内见过的不同 visitorId，最多记 8 个
触发   = 不同值 > 3  → 该 Cookie 锁 900 秒
```

- 只在**登录失败**时记录；成功登录清 IP/设备锁，但不清轮换集合
- 触发后 429，响应体与现有 `rate_limited` 完全一致，**不暴露是轮换触发**
- 状态在内存，与其它 limiter 一致

## 三、隐私与合规（硬要求，验收逐条查）

1. `monitoring: false`，页面**不得有任何指向 fingerprint.com / fpjs 域的请求**（用 DevTools Network 验）
2. visitorId **不入库、不进日志**（与 deviceKey 一样只允许前 8 位）
3. 不申请任何权限，不读麦克风/摄像头
4. 原始指纹特征由 FingerprintJS 在本地算，服务端只收 32 位哈希
5. MIT 许可，`LICENSE` 与第三方声明里登记该依赖

## 四、验收

1. `npm run build` 通过；**产物 gzip 增量 < 20 KB**
2. 同一浏览器刷新 3 次，`X-Device-Fp` 三次完全一致（打印比对）
3. 换 Chrome / Safari / 无痕窗口，visitorId 应不同
4. **无痕或禁用 canvas 时**：请求仍正常发出，不带该头，登录不失败
5. DevTools Network：**无任何 fingerprint.com / fpjs 域请求**
6. 服务端：合法 32 hex → deviceKey 与不带时不同；`../../etc` 等脏值 → 被忽略
7. 同一 Cookie 连造 4 个不同指纹 → 第 4 次锁 900 秒（单测覆盖）
8. 日志 grep 不到完整 visitorId 或 Cookie 值
9. `make check` 全绿

## 五、纪律

- 小步中文提交；禁止 push / rebase / reset --hard
- 前端构建 `--outDir /tmp/...`，绝不写 `/var/www`
- 只改本仓库
