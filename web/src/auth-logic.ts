// 登录页纯逻辑：回跳白名单 + 设备名推导。
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
