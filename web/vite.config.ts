import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 构建产物落到仓库根的 public/（与部署期 nginx 直接伺服静态页的目录一致），
// base 用根路径，使 index.html 生成的资源引用为 /assets/*。
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: '../public',
    emptyOutDir: true,
  },
});
