// 登录页纯逻辑：回跳白名单 + 设备名推导 + 裸访问状态页判定。
// 从 public/index.html（改造前）逐条照搬，语义不得改动；单独成模块便于验证。

declare global {
  interface Window {
    __AUTH_CONFIG__?: { allowedRedirectRoots?: string[] };
  }
}

export function allowedRedirectRoots(): string[] {
  const cfg = (typeof window !== 'undefined' && window.__AUTH_CONFIG__) || {};
  return Array.isArray(cfg.allowedRedirectRoots) ? cfg.allowedRedirectRoots : [];
}

export function isAllowedRedirect(u: unknown): boolean {
  if (typeof u !== 'string' || !u) return false;
  if (u.charAt(0) === '/') return u.charAt(1) !== '/' && u.charAt(1) !== '\\';
  let p: URL;
  try {
    p = new URL(u);
  } catch {
    return false;
  }
  if (p.protocol !== 'https:' && p.protocol !== 'http:') return false;
  const h = p.hostname.toLowerCase();
  if (p.origin === location.origin) return true;
  if (h === 'localhost' || h === '127.0.0.1' || h === '[::1]') return true;
  const roots = allowedRedirectRoots();
  for (let i = 0; i < roots.length; i++) {
    const root = String(roots[i] || '').toLowerCase();
    if (root && (h === root || h.slice(-(root.length + 1)) === '.' + root)) return true;
  }
  return false;
}

export function resolveRedirect(): { redirect: string; rejected: boolean } {
  const rawParam = new URLSearchParams(location.search).get('redirect');
  const raw = typeof rawParam === 'string' && rawParam ? rawParam : '/';
  if (!raw.startsWith('/') && !/^https?:\/\//i.test(raw)) return { redirect: '/', rejected: false };
  if (!isAllowedRedirect(raw)) return { redirect: '/', rejected: true };

  let url: URL;
  try {
    url = /^https?:\/\//i.test(raw) ? new URL(raw) : new URL(raw, 'http://placeholder.invalid');
  } catch {
    return { redirect: '/', rejected: false };
  }

  const pathname = url.pathname;
  if (!pathname.endsWith('/') && !/\.[^/]+$/.test(pathname)) {
    url.pathname = pathname + '/';
  }

  return {
    redirect: raw.startsWith('/') ? url.pathname + url.search + url.hash : url.href,
    rejected: false,
  };
}

// 从 User-Agent 推导设备名（浏览器 · 系统），与后端 deviceNameFromUA 同一套规则
export function deviceName(): string {
  const ua = navigator.userAgent || '';
  const name: string[] = [];
  let m: RegExpExecArray | null;
  if ((m = /Edg\/([\d.]+)/.exec(ua))) name.push('Edge ' + m[1]);
  else if (/OPR\//.test(ua) || /Opera/.test(ua)) name.push('Opera');
  else if ((m = /Firefox\/([\d.]+)/.exec(ua))) name.push('Firefox ' + m[1]);
  else if (/SamsungBrowser\//.test(ua)) name.push('Samsung Browser');
  else if (/MicroMessenger\//.test(ua)) name.push('WeChat');
  else if ((m = /CriOS\/([\d.]+)/.exec(ua))) name.push('Chrome ' + m[1]);
  else if ((m = /Chrome\/([\d.]+)/.exec(ua))) name.push('Chrome ' + m[1]);
  else if (/Safari\//.test(ua)) name.push('Safari');
  if (/Windows NT/.test(ua)) name.push('Windows');
  else if (/iPhone|iPad|iPod/.test(ua)) name.push('iOS');
  else if (/Mac OS X/.test(ua)) name.push('macOS');
  else if (/Android/.test(ua)) name.push('Android');
  else if (/CrOS/.test(ua)) name.push('ChromeOS');
  else if (/Linux/.test(ua)) name.push('Linux');
  return name.join(' · ').slice(0, 64);
}

/* ------------------------------------------------------------------ *
 * 裸访问状态页：只有不带 OIDC 参数时才探测会话
 * ------------------------------------------------------------------ */

// 这些参数出现即代表处于 OIDC 流程，必须原样保留现有登录/跳转行为。
// `redirect` 是 /authorize 未登录时下发的入口参数，也算流程参数。
const OIDC_QUERY_PARAMS = ['client_id', 'redirect_uri', 'state', 'redirect'];

export type MeInfo = {
  authenticated: boolean;
  subject?: string;
  displayName?: string;
  createdAt?: number;
  expiresAt?: number;
  remember?: boolean;
};

export type LandingView = 'checking' | 'login' | 'signed-in';

// hasOidcParams 先于任何渲染判断执行：带参数时绝不因为"已登录"短路流程。
export function hasOidcParams(search: string): boolean {
  const params = new URLSearchParams(search);
  return OIDC_QUERY_PARAMS.some((key) => params.has(key));
}

// landingView 是唯一决定渲染哪个视图的纯函数。
// authenticated 为 null/undefined 表示 /api/me 尚未返回。
export function landingView(
  search: string,
  authenticated: boolean | null | undefined
): LandingView {
  if (hasOidcParams(search)) return 'login';
  if (authenticated === null || authenticated === undefined) return 'checking';
  return authenticated ? 'signed-in' : 'login';
}

// formatDateTime 输出本地时区的 YYYY-MM-DD HH:mm；无效时间返回破折号。
export function formatDateTime(unixSeconds: number | undefined): string {
  if (!unixSeconds || !Number.isFinite(unixSeconds) || unixSeconds <= 0) return '—';
  const d = new Date(unixSeconds * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    d.getFullYear() +
    '-' +
    pad(d.getMonth() + 1) +
    '-' +
    pad(d.getDate()) +
    ' ' +
    pad(d.getHours()) +
    ':' +
    pad(d.getMinutes())
  );
}

// remainingMinutes 向上取整：还剩 11 分 30 秒时显示 12 分钟。
export function remainingMinutes(expiresAt: number | undefined, nowSeconds: number): number {
  if (!expiresAt || !Number.isFinite(expiresAt)) return 0;
  return Math.max(0, Math.ceil((expiresAt - nowSeconds) / 60));
}

// rememberDays 用于"记住我"会话：只显示天数，不显示倒计时。
export function rememberDays(expiresAt: number | undefined, nowSeconds: number): number {
  if (!expiresAt || !Number.isFinite(expiresAt)) return 0;
  return Math.max(0, Math.ceil((expiresAt - nowSeconds) / 86400));
}

// formatExpiry 生成"有效期至"右侧文案。
export function formatExpiry(
  expiresAt: number | undefined,
  remember: boolean,
  nowSeconds: number
): string {
  if (remember) {
    const days = rememberDays(expiresAt, nowSeconds);
    return days > 0 ? days + ' 天内免登录' : '已过期';
  }
  return formatDateTime(expiresAt) + '（还有 ' + remainingMinutes(expiresAt, nowSeconds) + ' 分钟）';
}

// isSessionExpired 只在拿到绝对到期时间时生效。
export function isSessionExpired(
  expiresAt: number | undefined,
  nowSeconds: number
): boolean {
  return !!expiresAt && Number.isFinite(expiresAt) && expiresAt <= nowSeconds;
}

