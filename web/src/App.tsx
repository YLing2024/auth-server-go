/**
 * 认证中心的两个并列视图：登录表单与裸访问时的「已登录」状态页。
 *
 * 分流规则在 auth-logic.ts：URL 出现 client_id / redirect_uri / state /
 * redirect 任一参数时完全沿用登录视图，绝不探测会话；只有裸访问才请求
 * /api/me，已登录显示账号与时间，未登录显示登录表单。
 *
 * 状态页只展示用户名与时间，不展示 token、sessionId 或 Cookie 值。
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ComponentRef } from 'react';
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Checkbox,
  ConfigProvider,
  Form,
  Input,
  Popconfirm,
  Segmented,
  Spin,
  Steps,
  Typography,
  theme,
} from 'antd';
import type { ThemeConfig } from 'antd';
import { CheckCircleFilled } from '@ant-design/icons';
import zhCN from 'antd/locale/zh_CN';
import {
  deviceName,
  formatDateTime,
  formatExpiry,
  hasOidcParams,
  isSessionExpired,
  landingView,
  resolveRedirect,
} from './auth-logic';
import type { MeInfo } from './auth-logic';
import { deviceFingerprintHeaders } from './fingerprint';
import {
  applyTheme,
  resolveTheme,
  setThemeMode,
  useSystemDark,
  useThemeMode,
} from './theme';
import type { ThemeMode } from './theme';

// 回跳目标与是否被拒（页面加载时解析一次）
const { redirect: REDIRECT, rejected: REDIRECT_REJECTED } = resolveRedirect();

// 回跳用 URL query（?token=，OAuth2 风格）：fragment 经 nginx 301 重定向会被丢弃，query 不会
function redirectWithToken(token: string): void {
  const sep = REDIRECT.indexOf('?') === -1 ? '?' : '&';
  window.location.href = REDIRECT + sep + 'token=' + encodeURIComponent(token);
}

/* ------------------------------------------------------------------ *
 * 共用卡片头部
 * ------------------------------------------------------------------ */

/**
 * 品牌 + 主题切换。三个视图共用，不承载任何会话信息。
 *
 * @param mode 当前主题模式，仅用于 Segmented 受控值；切换写入 localStorage。
 */
function CardHeader({ mode }: { mode: ThemeMode }) {
  const { token } = theme.useToken();
  return (
    <div className="auth-head">
      <div className="auth-brand">
        <span
          style={{
            width: 10,
            height: 10,
            background: token.colorPrimary,
            transform: 'rotate(45deg)',
            flex: 'none',
          }}
        />
        <Typography.Title level={4} style={{ margin: 0 }}>
          HomeAuth
        </Typography.Title>
      </div>
      <Segmented
        className="auth-theme"
        size="small"
        value={mode}
        onChange={(value) => setThemeMode(value as ThemeMode)}
        options={[
          { label: '自动', value: 'auto' },
          { label: '亮色', value: 'light' },
          { label: '暗色', value: 'dark' },
        ]}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * 登录页
 * ------------------------------------------------------------------ */

type LoginData = { token?: string; code?: string; retryAfter?: number; message?: string };
type SetupData = { secret?: string; otpauthUri?: string; message?: string };

/**
 * 登录表单。URL 带 OIDC 参数时永远走这里，行为与改造前一致。
 *
 * @param mode 主题模式；登录成功后按 redirect 参数回跳，本组件不读取 Cookie。
 */
function LoginPage({ mode }: { mode: ThemeMode }) {
  const { token } = theme.useToken();
  const inputRef = useRef<ComponentRef<typeof Input.OTP>>(null);
  const [code, setCode] = useState('');
  const [otpKey, setOtpKey] = useState(0);
  const [remember, setRemember] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(
    REDIRECT_REJECTED ? '回跳地址不在允许范围内，登录后将留在本站' : ''
  );
  const [setup, setSetup] = useState<{ secret: string; otpauthUri?: string } | null>(null);

  // 自动聚焦第一格：挂载后、以及每次提交结束（loading 落回 false / 重挂载清空）后重新聚焦
  useEffect(() => {
    if (!loading) {
      inputRef.current?.focus();
    }
  }, [loading, otpKey]);

  async function setupInit(): Promise<void> {
    try {
      // 首次绑定只是生成 secret，不是凭据提交：按最小化原则不附带指纹头。
      const res = await fetch('/api/totp/setup', { method: 'POST' });
      const data = (await res.json()) as SetupData;
      if (!data.secret) {
        setError('初始化失败：' + (data.message || '未知错误'));
        return;
      }
      setSetup({ secret: data.secret, otpauthUri: data.otpauthUri });
    } catch {
      setError('初始化失败，请刷新重试');
    }
  }

  async function login(): Promise<void> {
    const value = code.replace(/\s/g, '');
    if (!/^\d{6}$/.test(value)) {
      setError('请输入 6 位数字验证码');
      return;
    }
    setError('');
    setLoading(true);
    try {
      // 指纹最多等待 1.5 秒；拿不到时不带这两个头，登录照常继续。
      const fpHeaders = await deviceFingerprintHeaders();
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...fpHeaders },
        body: JSON.stringify({ code: value, deviceName: deviceName(), remember }),
      });
      const data = (await res.json().catch(() => ({}))) as LoginData;
      if (data && data.token) {
        redirectWithToken(data.token);
        return;
      }
      if (res.status === 403 && data && data.code === 'totp_setup_required') {
        setError('首次使用：请先完成下方绑定，再输入动态码');
        await setupInit();
        return;
      }
      if (res.status === 429) {
        setError('尝试次数过多，请 ' + (data.retryAfter || 60) + ' 秒后重试');
        return;
      }
      setError('验证码错误，请重试');
    } catch {
      setError('网络错误，请重试');
    } finally {
      setLoading(false);
      setCode('');
      setOtpKey((k) => k + 1);
    }
  }

  return (
    <div
      className="auth-root"
      style={{ background: token.colorBgLayout, color: token.colorText }}
    >
      <Card className="auth-card" bordered>
        <CardHeader mode={mode} />
        <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 44 }}>
          Single Sign-On
        </Typography.Text>

        <Form.Item
          label="Authenticator Code"
          layout="vertical"
          style={{ marginBottom: 0 }}
        >
          <Input.OTP
            key={otpKey}
            ref={inputRef}
            // 空格是 OTP 内部空格的占位符，formatter 必须保留它，否则中间格的编辑位置会被压掉
            formatter={(value) => value.replace(/[^\d ]/g, '')}
            // onInput 每格变化都给 cells（onChange 只在填满时触发），用它同步 code 以支持回车校验
            onInput={(cells) => setCode(cells.join('').replace(/\s/g, ''))}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                login();
              }
            }}
            length={6}
            inputMode="numeric"
            disabled={loading}
            autoFocus
            size="large"
          />
        </Form.Item>

        <div className="auth-remember">
          <Checkbox checked={remember} onChange={(e) => setRemember(e.target.checked)}>
            记住我
          </Checkbox>
          <Typography.Text type="secondary" className="auth-remember-hint">
            不勾选：15 分钟后自动退出；勾选：7 天内免登录
          </Typography.Text>
        </div>

        {error ? (
          <Alert
            type="error"
            showIcon={false}
            closable={false}
            message={error}
            style={{ marginTop: 16 }}
          />
        ) : null}

        <Button
          type="primary"
          block
          loading={loading}
          onClick={login}
          style={{ marginTop: 32, height: 44 }}
        >
          Login
        </Button>

        {setup ? (
          <div
            style={{
              marginTop: 28,
              borderTop: `1px solid ${token.colorBorderSecondary}`,
              paddingTop: 22,
            }}
          >
            <Alert
              type="info"
              showIcon={false}
              message="首次使用 · 绑定身份验证器"
              style={{ marginBottom: 14 }}
            />
            <Steps
              direction="vertical"
              size="small"
              current={-1}
              items={[
                { title: '复制下方密钥，或点击 otpauth 链接添加' },
                { title: '在 Google Authenticator / Authy / 1Password 中新建条目' },
                { title: '回到本页输入 6 位动态码完成登录' },
              ]}
            />
            <Typography.Paragraph
              code
              copyable={{ text: setup.secret }}
              style={{ wordBreak: 'break-all', marginTop: 14, marginBottom: 10 }}
            >
              {setup.secret}
            </Typography.Paragraph>
            {setup.otpauthUri ? (
              <Typography.Link href={setup.otpauthUri} target="_blank" rel="noopener">
                添加 otpauth:// 条目
              </Typography.Link>
            ) : null}
          </div>
        ) : null}

        <Typography.Text
          type="secondary"
          style={{ display: 'block', textAlign: 'center', marginTop: 36 }}
        >
          Home Auth
        </Typography.Text>
      </Card>
    </div>
  );
}

/* ------------------------------------------------------------------ *
 * 裸访问：已登录状态页 / 会话探测
 * ------------------------------------------------------------------ */

type SignedInPageProps = {
  mode: ThemeMode;
  me: MeInfo;
  onLogout: () => Promise<boolean>;
  onExpired: () => void;
};

/**
 * 已登录状态页：账号、登录时间、有效期与主动退出。
 *
 * 只展示 subject / 时间，绝不展示 token、sessionId 或 Cookie 值。
 * 短会话到点后自动切回登录表单并提示过期；记住我会话只显示天数。
 *
 * @param mode 主题模式
 * @param me /api/me 返回的登录信息
 * @param onLogout 退出请求，返回 false 表示失败并保留当前页
 * @param onExpired 短会话到期回调，由父组件切回登录视图
 */
function SignedInPage({ mode, me, onLogout, onExpired }: SignedInPageProps) {
  const { token } = theme.useToken();
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [busy, setBusy] = useState(false);
  const remember = me.remember === true;
  const expiresAt = me.expiresAt;

  useEffect(() => {
    if (remember || !expiresAt) return;
    if (isSessionExpired(expiresAt, Math.floor(Date.now() / 1000))) {
      onExpired();
      return;
    }
    // 到点立即切回登录；间隔只负责刷新剩余分钟文案。
    const timer = window.setTimeout(onExpired, Math.max(0, expiresAt * 1000 - Date.now()));
    const tick = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 60_000);
    return () => {
      window.clearTimeout(timer);
      window.clearInterval(tick);
    };
  }, [expiresAt, remember, onExpired]);

  async function signOut(): Promise<void> {
    setBusy(true);
    const ok = await onLogout();
    if (!ok) setBusy(false);
  }

  return (
    <div
      className="auth-root"
      style={{ background: token.colorBgLayout, color: token.colorText }}
    >
      <Card className="auth-card" bordered>
        <CardHeader mode={mode} />

        <div className="auth-status">
          <span aria-hidden="true">
            <CheckCircleFilled
              className="auth-status-icon"
              style={{ color: token.colorSuccess }}
            />
          </span>
          <Typography.Title level={4} style={{ margin: '12px 0 4px' }}>
            已登录
          </Typography.Title>
          <Typography.Text type="secondary">Single Sign-On</Typography.Text>
        </div>

        <dl className="auth-facts">
          <div className="auth-fact">
            <dt>账号</dt>
            <dd>{me.subject || me.displayName || '—'}</dd>
          </div>
          <div className="auth-fact">
            <dt>登录时间</dt>
            <dd>{formatDateTime(me.createdAt)}</dd>
          </div>
          <div className="auth-fact">
            <dt>有效期至</dt>
            <dd>{formatExpiry(me.expiresAt, remember, now)}</dd>
          </div>
        </dl>

        <Popconfirm
          title="确定退出登录？"
          okText="退出"
          cancelText="取消"
          okButtonProps={{ danger: true }}
          onConfirm={signOut}
          disabled={busy}
        >
          <Button type="primary" danger block loading={busy} style={{ marginTop: 24, height: 44 }}>
            退出登录
          </Button>
        </Popconfirm>

        <Typography.Text type="secondary" className="auth-note">
          这个页面只在直接访问时出现；从站点跳转过来会自动完成登录。
        </Typography.Text>
      </Card>
    </div>
  );
}

/**
 * /api/me 返回前的占位卡片，避免裸访问先闪一下登录表单。
 *
 * @param mode 主题模式
 */
function CheckingPage({ mode }: { mode: ThemeMode }) {
  const { token } = theme.useToken();
  return (
    <div
      className="auth-root"
      style={{ background: token.colorBgLayout, color: token.colorText }}
    >
      <Card className="auth-card" bordered>
        <CardHeader mode={mode} />
        <div className="auth-loading">
          <Spin />
        </div>
      </Card>
    </div>
  );
}

/**
 * 视图分流：先按 URL 参数判定，再按会话状态渲染。
 *
 * @param mode 主题模式
 */
function AuthLanding({ mode }: { mode: ThemeMode }) {
  const { message } = AntApp.useApp();
  const [search] = useState(() => (typeof window === 'undefined' ? '' : window.location.search));
  const oidcFlow = hasOidcParams(search);
  const [me, setMe] = useState<MeInfo | undefined>(undefined);

  useEffect(() => {
    if (oidcFlow) return;
    let alive = true;
    const controller = new AbortController();
    fetch('/api/me', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    })
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as Partial<MeInfo>;
        if (!alive) return;
        setMe(res.ok && data.authenticated === true ? (data as MeInfo) : { authenticated: false });
      })
      .catch(() => {
        // Redis 异常也走 200 false；网络失败同样退回登录表单，不白屏。
        if (alive) setMe({ authenticated: false });
      });
    return () => {
      alive = false;
      controller.abort();
    };
  }, [oidcFlow]);

  const onExpired = useCallback(() => {
    setMe({ authenticated: false });
    message.warning('会话已过期');
  }, [message]);

  const onLogout = useCallback(async (): Promise<boolean> => {
    try {
      const res = await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
      if (!res.ok) {
        message.error('退出失败，请重试');
        return false;
      }
      setMe({ authenticated: false });
      message.success('已退出登录');
      return true;
    } catch {
      message.error('退出失败，请重试');
      return false;
    }
  }, [message]);

  const view = landingView(search, me ? me.authenticated === true : null);
  if (view === 'checking') return <CheckingPage mode={mode} />;
  if (view === 'signed-in' && me) {
    return <SignedInPage mode={mode} me={me} onLogout={onLogout} onExpired={onExpired} />;
  }
  return <LoginPage mode={mode} />;
}

export default function App() {
  const mode = useThemeMode();
  const systemDark = useSystemDark();
  const resolved = resolveTheme(mode, systemDark);

  // 首屏由 index.html 内联脚本先打 data-theme；这里在 React 侧保持同步（含 auto 跟随系统）
  useEffect(() => {
    applyTheme(resolved);
  }, [resolved]);

  // 一律使用 Ant Design 默认设计语言：只切算法，不覆盖任何自定义 token
  const themeConfig = useMemo<ThemeConfig>(
    () => ({
      algorithm: resolved === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
    }),
    [resolved]
  );

  return (
    <ConfigProvider locale={zhCN} theme={themeConfig}>
      <AntApp>
        <AuthLanding mode={mode} />
      </AntApp>
    </ConfigProvider>
  );
}
