# 第三方组件声明

本项目自身以 MIT 许可发布（见 `LICENSE`）。下表登记运行时引入的第三方组件。

| 组件 | 版本 | 许可 | 用途 | 备注 |
|---|---|---|---|---|
| `github.com/redis/go-redis/v9` | v9.23.0 | BSD-2-Clause | Redis 客户端 | 仅服务端 |
| `@fingerprintjs/fingerprintjs` | 5.3.0 | MIT | 浏览器端 visitorId 采集 | 仅登录页；`monitoring:false` 关闭遥测，不发起任何外联；原始特征在本地计算，服务端只收 32 位哈希。上游版权声明见 `web/node_modules/@fingerprintjs/fingerprintjs/LICENSE` 与发行包。 |

## FingerprintJS 许可全文获取方式

安装依赖后位于 `web/node_modules/@fingerprintjs/fingerprintjs/LICENSE`；上游仓库：
<https://github.com/fingerprintjs/fingerprintjs>（MIT License）。

## 隐私边界

- visitorId 只在浏览器内存中缓存，不写 localStorage / sessionStorage / cookie。
- 服务端不落库、不打日志；日志最多出现 deviceKey 前 8 位。
- 仅 `POST /api/login`、`POST /api/totp/login` 允许携带 `X-Device-Fp` / `X-Device-Fp-Conf`。
