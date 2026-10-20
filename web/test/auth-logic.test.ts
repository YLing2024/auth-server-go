// 裸访问状态页纯逻辑单测：分支判定、时间文案、过期判定。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatDateTime,
  formatExpiry,
  hasOidcParams,
  isSessionExpired,
  landingView,
  remainingMinutes,
  rememberDays,
} from '../src/auth-logic.ts';

test('hasOidcParams：client_id / redirect_uri / state / redirect 任一出现即为 OIDC 流程', () => {
  assert.equal(hasOidcParams(''), false);
  assert.equal(hasOidcParams('?foo=bar'), false);
  assert.equal(hasOidcParams('?client_id=example-app'), true);
  assert.equal(hasOidcParams('?redirect_uri=https%3A%2F%2Fapp.example.com%2F'), true);
  assert.equal(hasOidcParams('?state=xyz'), true);
  assert.equal(hasOidcParams('?redirect=%2Fauthorize%3Fclient_id%3Dx'), true);
  // 空值同样算"出现过"，不能因空串误判成裸访问
  assert.equal(hasOidcParams('?state='), true);
});

test('landingView：先看参数，再按登录状态决定', () => {
  assert.equal(landingView('?client_id=x', true), 'login');
  assert.equal(landingView('?client_id=x', false), 'login');
  assert.equal(landingView('', null), 'checking');
  assert.equal(landingView('', undefined), 'checking');
  assert.equal(landingView('', false), 'login');
  assert.equal(landingView('', true), 'signed-in');
});

test('formatDateTime：固定补零，非法值回退破折号', () => {
  assert.equal(formatDateTime(0), '—');
  assert.equal(formatDateTime(undefined), '—');
  assert.equal(formatDateTime(Number.NaN), '—');
  const sec = 1792498323;
  const d = new Date(sec * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  assert.equal(
    formatDateTime(sec),
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
});

test('remainingMinutes / rememberDays：向上取整并夹到 0', () => {
  const now = 1_000_000;
  assert.equal(remainingMinutes(now + 720, now), 12);
  assert.equal(remainingMinutes(now + 690, now), 12);
  assert.equal(remainingMinutes(now + 30, now), 1);
  assert.equal(remainingMinutes(now - 1, now), 0);
  assert.equal(remainingMinutes(undefined, now), 0);

  assert.equal(rememberDays(now + 7 * 86400, now), 7);
  assert.equal(rememberDays(now + 6 * 86400 + 1, now), 7);
  assert.equal(rememberDays(now - 1, now), 0);
});

test('formatExpiry：短会话显示到点与剩余分钟，记住我只显示天数', () => {
  const now = 1_000_000;
  const expires = now + 720;
  const short = formatExpiry(expires, false, now);
  assert.ok(short.includes('（还有 12 分钟）'));
  assert.ok(short.startsWith(formatDateTime(expires)));

  assert.equal(formatExpiry(now + 7 * 86400, true, now), '7 天内免登录');
  assert.equal(formatExpiry(now - 1, true, now), '已过期');
});

test('isSessionExpired：只按绝对到期时间判断', () => {
  assert.equal(isSessionExpired(undefined, 100), false);
  assert.equal(isSessionExpired(101, 100), false);
  assert.equal(isSessionExpired(100, 100), true);
  assert.equal(isSessionExpired(99, 100), true);
});
