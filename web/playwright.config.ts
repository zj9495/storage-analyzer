import { defineConfig, devices } from '@playwright/test'

// 端到端测试针对已运行的真实服务执行。设置 E2E_BASE_URL 后运行：
//   E2E_BASE_URL=http://127.0.0.1:4173 pnpm test:e2e
// 完整初始化到 CSV 链路由 tests/e2e/run-real-e2e.sh 启动真实 Rust + Vite 服务。
export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  retries: 0,
  expect: { timeout: 10_000 },
  outputDir: 'test-results/e2e',
  reporter: [['list'], ['html', { outputFolder: 'test-results/e2e-report', open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
