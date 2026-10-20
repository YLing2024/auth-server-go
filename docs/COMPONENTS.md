# 登录页组件登记

本文件登记 `web/src` 中可复用的页面组件。登录页单文件实现，不引入 Storybook；新增组件必须同笔登记。

| 组件 | 位置 | 用途 | 关键 props | 注意事项 |
|---|---|---|---|---|
| `AuthLanding` | `web/src/App.tsx` | 裸访问分流：带 OIDC 参数 → 登录视图；否则按 `/api/me` 决定登录 / 已登录 / 探测中 | `mode` | 分流必须发生在任何会话请求之前；参数存在时不得短路现有跳转流程 |
| `LoginPage` | `web/src/App.tsx` | TOTP 登录表单与首次绑定引导 | `mode` | 登录成功后按 `redirect` 回跳；不读取 Cookie、不展示会话信息 |
| `SignedInPage` | `web/src/App.tsx` | 已登录状态页：账号、登录时间、有效期、退出 | `mode`、`me`、`onLogout`、`onExpired` | 只展示 subject 与时间；短会话到点自动切回登录；记住我只显示天数；退出需二次确认 |
| `CheckingPage` | `web/src/App.tsx` | `/api/me` 返回前的占位 | `mode` | 仅用于裸访问，避免先闪登录表单 |
| `CardHeader` | `web/src/App.tsx` | 品牌与主题切换 | `mode` | 三个视图共用，不承载会话信息 |

## 最小示例

```tsx
<ConfigProvider locale={zhCN} theme={themeConfig}>
  <AntApp>
    <AuthLanding mode={mode} />
  </AntApp>
</ConfigProvider>
```

## 可访问性

- 状态页的成功图标为装饰性元素，带 `aria-hidden="true"`；「已登录」标题承担语义。
- 退出按钮使用 Ant Design `Popconfirm`，键盘可聚焦；确认按钮保持危险色与明确文案。
- 账号名与时间允许任意换行，390px 下无横向溢出。

## 文案约定

- 不显示 token、sessionId、Cookie 值；有效期只显示时间与剩余分钟/天数。
- 中文文案克制，不使用 emoji。
