import { useEffect, useMemo, useRef, useState } from 'react';
import type { ComponentRef } from 'react';
import {
  Alert,
  Button,
  Card,
  ConfigProvider,
  Form,
  Input,
  Segmented,
  Steps,
  Typography,
  theme,
} from 'antd';
import type { ThemeConfig } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { deviceName, resolveRedirect } from './auth-logic';
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
 * 登录页
 * ------------------------------------------------------------------ */

type LoginData = { token?: string; code?: string; retryAfter?: number; message?: string };
type SetupData = { secret?: string; otpauthUri?: string; message?: string };

function LoginPage({ mode }: { mode: ThemeMode }) {
  const { token } = theme.useToken();
  const inputRef = useRef<ComponentRef<typeof Input.OTP>>(null);
  const [code, setCode] = useState('');
  const [otpKey, setOtpKey] = useState(0);
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
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: value, deviceName: deviceName() }),
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
      <LoginPage mode={mode} />
    </ConfigProvider>
  );
}
