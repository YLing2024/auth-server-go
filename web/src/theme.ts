// 登录页主题三态：auto | light | dark（规范见 docs/REQUIREMENTS-theme-switcher.md）。
// auto 跟随系统并实时监听 prefers-color-scheme；light/dark 强制。
// 持久化到 localStorage（键 theme_mode），读取失败/非法值一律回退 auto，绝不抛错、不白屏。
import { useEffect, useState } from 'react';

export type ThemeMode = 'auto' | 'light' | 'dark';
export type ResolvedTheme = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'theme_mode';
export const DEFAULT_THEME_MODE: ThemeMode = 'auto';

// 同页通知（setThemeMode → useThemeMode 重读）；跨页由 storage 事件兜底
const THEME_EVENT = 'auth-theme-change';
const DARK_QUERY = '(prefers-color-scheme: dark)';

export function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'auto' || value === 'light' || value === 'dark';
}

// 读取持久化：localStorage 不可用 / 值非法 → auto
export function readStoredMode(): ThemeMode {
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isThemeMode(raw) ? raw : DEFAULT_THEME_MODE;
  } catch {
    return DEFAULT_THEME_MODE;
  }
}

// 系统是否偏好深色；无 matchMedia 环境视为浅色
export function systemPrefersDark(): boolean {
  try {
    return (
      typeof window !== 'undefined' &&
      !!window.matchMedia &&
      window.matchMedia(DARK_QUERY).matches
    );
  } catch {
    return false;
  }
}

// auto → 跟随系统；light/dark → 强制
export function resolveTheme(mode: ThemeMode, prefersDark: boolean): ResolvedTheme {
  if (mode === 'light') return 'light';
  if (mode === 'dark') return 'dark';
  return prefersDark ? 'dark' : 'light';
}

// 给 <html> 打 data-theme 并同步 <meta name="color-scheme">
export function applyTheme(resolved: ResolvedTheme): void {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  root.setAttribute('data-theme', resolved);
  let meta = document.querySelector('meta[name="color-scheme"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'color-scheme');
    document.head.appendChild(meta);
  }
  meta.setAttribute('content', resolved);
}

// 写持久化 + 立即应用（不依赖 React），再通知订阅者
export function setThemeMode(mode: ThemeMode): void {
  const next = isThemeMode(mode) ? mode : DEFAULT_THEME_MODE;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch {
    // localStorage 不可用也要立即生效（仅本次会话）
  }
  applyTheme(resolveTheme(next, systemPrefersDark()));
  window.dispatchEvent(new Event(THEME_EVENT));
}

// 当前主题模式（订阅同页设置 / 跨页 storage 变化）
export function useThemeMode(): ThemeMode {
  const [mode, setMode] = useState<ThemeMode>(readStoredMode);

  useEffect(() => {
    const sync = () => setMode(readStoredMode());
    window.addEventListener(THEME_EVENT, sync);
    window.addEventListener('storage', sync);
    return () => {
      window.removeEventListener(THEME_EVENT, sync);
      window.removeEventListener('storage', sync);
    };
  }, []);

  return mode;
}

// 系统深色偏好（auto 时实时跟随）
export function useSystemDark(): boolean {
  const [dark, setDark] = useState<boolean>(systemPrefersDark);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia(DARK_QUERY);
    const onChange = (e: MediaQueryListEvent) => setDark(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  return dark;
}
