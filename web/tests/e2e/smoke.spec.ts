import { expect, test } from '@playwright/test'

// 端到端测试必须针对真实运行中的服务执行；缺少目标地址时显式失败，
// 不能以跳过用例返回成功。
if (!process.env.E2E_BASE_URL) {
  throw new Error('E2E_BASE_URL 必须指向已运行的真实服务')
}

test('未登录访问 / 会进入登录页', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveURL(/\/login/)
})
