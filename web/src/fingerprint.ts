import FingerprintJS from '@fingerprintjs/fingerprintjs';

/** 一次采集得到的浏览器指纹：visitorId 与平台给出的置信度。 */
export type DeviceFingerprint = {
  visitorId: string;
  confidence: number;
};

/** 采集上限：超时不阻断登录，按“无指纹”处理。 */
const FP_TIMEOUT_MS = 1500;

/** FingerprintJS 生成的 visitorId 固定为 32 位小写十六进制。 */
const VISITOR_ID_RE = /^[0-9a-f]{32}$/;

// 整个页面会话只采集一次：undefined 表示尚未开始，null 表示已判定为不可用。
let cached: DeviceFingerprint | null | undefined;

// 并发调用共享同一次采集，避免连续点击触发重复计算。
let pending: Promise<DeviceFingerprint | null> | undefined;

/**
 * 调用 FingerprintJS 在本地计算指纹。
 *
 * `monitoring: false` 关闭平台的匿名遥测，本部署不允许任何外联；
 * 采集失败（无痕模式、禁用 canvas 等）时返回 null，绝不抛给登录流程。
 */
async function collect(): Promise<DeviceFingerprint | null> {
  try {
    const agent = await FingerprintJS.load({ monitoring: false });
    const result = await agent.get();
    return {
      visitorId: result.visitorId,
      confidence: result.confidence?.score ?? 0,
    };
  } catch {
    return null;
  }
}

/**
 * 返回当前页面会话的指纹，只采集一次并缓存在内存中。
 *
 * 超过 1.5 秒、采集抛错或结果不是合法 visitorId 时返回 null；
 * 不使用 localStorage / sessionStorage / cookie，刷新页面即重新采集。
 */
export async function deviceFingerprint(): Promise<DeviceFingerprint | null> {
  if (cached !== undefined) return cached;
  if (!pending) {
    pending = Promise.race([
      collect(),
      new Promise<null>((resolve) => {
        window.setTimeout(() => resolve(null), FP_TIMEOUT_MS);
      }),
    ]).then((value) => {
      cached = value && VISITOR_ID_RE.test(value.visitorId) ? value : null;
      return cached;
    });
  }
  return pending;
}

/**
 * 登录类 POST 专用的附加请求头。
 *
 * 只在提交凭据时调用；GET、静态资源与 OIDC 跳转不得携带。
 * 无可用指纹时返回空对象，调用方直接展开即可。
 */
export async function deviceFingerprintHeaders(): Promise<Record<string, string>> {
  const fp = await deviceFingerprint();
  if (!fp) return {};
  return {
    'X-Device-Fp': fp.visitorId,
    'X-Device-Fp-Conf': fp.confidence.toFixed(2),
  };
}
