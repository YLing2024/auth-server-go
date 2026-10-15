// 主题模块单测：零依赖，node --test 直跑（TS 类型剥离）。
// 覆盖三态解析 / 非法回退 / data-theme 与 color-scheme 同步 / 持久化。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_THEME_MODE,
  THEME_STORAGE_KEY,
  applyTheme,
  isThemeMode,
  readStoredMode,
  resolveTheme,
  setThemeMode,
  systemPrefersDark,
  useThemeMode,
} from '../src/theme.ts';

// —— 极简 DOM / window 桩：只实现 theme.ts 用到的接口 ——
function makeMeta() {
  const attrs = {};
  return {
    setAttribute(k, v) {
      attrs[k] = String(v);
    },
    getAttribute(k) {
      return Object.prototype.hasOwnProperty.call(attrs, k) ? attrs[k] : null;
    },
  };
}

function makeDocument() {
  let existing = null;
  const head = {
    children: [],
    appendChild(el) {
      this.children.push(el);
      if (el.getAttribute('name') === 'color-scheme') existing = el;
    },
  };
  const documentElement = makeMeta();
  return {
    documentElement,
    head,
    createElement: () => makeMeta(),
    querySelector: (sel) => (sel === 'meta[name="color-scheme"]' ? existing : null),
    setExisting(el) {
      existing = el;
    },
  };
}

function makeWindow({ matches = false } = {}) {
  const store = new Map();
  return {
    _events: [],
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
    },
    matchMedia: () => ({ matches, addEventListener() {}, removeEventListener() {} }),
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent(e) {
      this._events.push(e.type);
      return true;
    },
  };
}

function withGlobals(fake, fn) {
  const prevWindow = globalThis.window;
  const prevDocument = globalThis.document;
  globalThis.window = fake.window;
  globalThis.document = fake.document;
  try {
    return fn();
  } finally {
    if (prevWindow === undefined) delete globalThis.window;
    else globalThis.window = prevWindow;
    if (prevDocument === undefined) delete globalThis.document;
    else globalThis.document = prevDocument;
  }
}

test('isThemeMode 只认 auto/light/dark', () => {
  assert.equal(isThemeMode('auto'), true);
  assert.equal(isThemeMode('light'), true);
  assert.equal(isThemeMode('dark'), true);
  assert.equal(isThemeMode('DARK'), false);
  assert.equal(isThemeMode(''), false);
  assert.equal(isThemeMode(null), false);
  assert.equal(isThemeMode(undefined), false);
  assert.equal(DEFAULT_THEME_MODE, 'auto');
  assert.equal(THEME_STORAGE_KEY, 'theme_mode');
});

test('readStoredMode：合法值直取，非法 / 缺失 / 抛错回退 auto', () => {
  const win = makeWindow();
  withGlobals({ window: win, document: makeDocument() }, () => {
    assert.equal(readStoredMode(), 'auto');
    win.localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    assert.equal(readStoredMode(), 'dark');
    win.localStorage.setItem(THEME_STORAGE_KEY, 'sepia');
    assert.equal(readStoredMode(), 'auto');
  });

  const throwing = {
    localStorage: {
      getItem() {
        throw new Error('denied');
      },
    },
  };
  withGlobals({ window: throwing, document: makeDocument() }, () => {
    assert.equal(readStoredMode(), 'auto');
  });
});

test('systemPrefersDark：跟随 matchMedia，无环境视为浅色', () => {
  withGlobals({ window: makeWindow({ matches: true }), document: makeDocument() }, () => {
    assert.equal(systemPrefersDark(), true);
  });
  withGlobals({ window: makeWindow({ matches: false }), document: makeDocument() }, () => {
    assert.equal(systemPrefersDark(), false);
  });
  assert.equal(systemPrefersDark(), false);
});

test('resolveTheme：auto 跟随系统，light/dark 强制', () => {
  assert.equal(resolveTheme('auto', true), 'dark');
  assert.equal(resolveTheme('auto', false), 'light');
  assert.equal(resolveTheme('light', true), 'light');
  assert.equal(resolveTheme('dark', false), 'dark');
});

test('applyTheme：写 html[data-theme] 并同步 meta[color-scheme]', () => {
  const document = makeDocument();
  withGlobals({ window: makeWindow(), document }, () => {
    applyTheme('dark');
    assert.equal(document.documentElement.getAttribute('data-theme'), 'dark');
    assert.equal(document.head.children.length, 1);
    assert.equal(document.head.children[0].getAttribute('name'), 'color-scheme');
    assert.equal(document.head.children[0].getAttribute('content'), 'dark');

    // 已有 meta 时复用，不重复插入
    applyTheme('light');
    assert.equal(document.documentElement.getAttribute('data-theme'), 'light');
    assert.equal(document.head.children.length, 1);
    assert.equal(document.head.children[0].getAttribute('content'), 'light');
  });
});

test('setThemeMode：写 localStorage + 立即改 data-theme + 发通知；auto 跟随系统', () => {
  const win = makeWindow({ matches: true });
  const document = makeDocument();
  withGlobals({ window: win, document }, () => {
    setThemeMode('light');
    assert.equal(win.localStorage.getItem(THEME_STORAGE_KEY), 'light');
    assert.equal(document.documentElement.getAttribute('data-theme'), 'light');

    setThemeMode('dark');
    assert.equal(document.documentElement.getAttribute('data-theme'), 'dark');

    // 系统深色 + auto → dark
    setThemeMode('auto');
    assert.equal(win.localStorage.getItem(THEME_STORAGE_KEY), 'auto');
    assert.equal(document.documentElement.getAttribute('data-theme'), 'dark');

    assert.ok(win._events.length >= 3);
  });
});

test('useThemeMode / setThemeMode 已导出', () => {
  assert.equal(typeof useThemeMode, 'function');
  assert.equal(typeof setThemeMode, 'function');
});
