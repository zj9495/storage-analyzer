import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import type { Download, Locator, Page, Response } from '@playwright/test'
import type { Job, ReportSummary } from '../../src/api/types'

const requiredEnv = (name: string): string => {
  const value = process.env[name]
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} 必须指向真实 E2E 服务的测试配置`)
  }
  return value
}

const setupTokenFile = requiredEnv('E2E_SETUP_TOKEN_FILE')
const adminUsername = requiredEnv('E2E_ADMIN_USERNAME')
const adminPassword = requiredEnv('E2E_ADMIN_PASSWORD')
const sourceName = `e2e-source-${process.pid}`
const profileName = `e2e-profile-${process.pid}`

interface SuccessEnvelope<T> {
  data: T
  meta: Record<string, unknown>
  request_id: string
}

interface RunResponse {
  job_id: string
  run_id: string
}

interface ExportResponse {
  export_id: string
  job_id: string
}

async function readApi<T>(page: Page, path: string): Promise<T> {
  const result = await page.evaluate(async (requestPath) => {
    const response = await fetch(requestPath, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    })
    return {
      status: response.status,
      body: (await response.json()) as unknown,
    }
  }, path)
  if (result.status !== 200) {
    throw new Error(`GET ${path} 返回 ${result.status}: ${JSON.stringify(result.body)}`)
  }
  const envelope = result.body as SuccessEnvelope<T>
  return envelope.data
}

async function responseEnvelope<T>(responsePromise: Promise<Response>): Promise<SuccessEnvelope<T>> {
  const response = await responsePromise
  expect(response.ok()).toBeTruthy()
  return (await response.json()) as SuccessEnvelope<T>
}

async function chooseOption(page: Page, root: Page | Locator, label: string, option: string): Promise<void> {
  await root.getByLabel(label).press('Enter')
  await page
    .locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content')
    .getByText(option, { exact: true })
    .click()
}

async function waitForJob(page: Page, jobId: string): Promise<Job> {
  let latest: Job | undefined
  await expect
    .poll(
      async () => {
        latest = await readApi<Job>(page, `/api/v1/jobs/${encodeURIComponent(jobId)}`)
        return latest.state
      },
      { timeout: 180_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toMatch(/^(SUCCEEDED|PARTIAL|FAILED|CANCELLED|INTERRUPTED)$/)
  if (latest === undefined) {
    throw new Error(`任务 ${jobId} 未返回最终状态`)
  }
  return latest
}

async function waitForReport(page: Page, runId: string): Promise<ReportSummary> {
  let report: ReportSummary | undefined
  await expect
    .poll(
      async () => {
        const reports = await readApi<ReportSummary[]>(page, '/api/v1/reports?page_size=50')
        report = reports.find((item) => item.run_id === runId)
        return report?.id ?? ''
      },
      { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
    )
    .not.toBe('')
  if (report === undefined) {
    throw new Error(`运行 ${runId} 未生成报告`)
  }
  return report
}

async function waitForExport(page: Page, exportId: string): Promise<string> {
  let state = ''
  await expect
    .poll(
      async () => {
        const record = await readApi<{ state: string }>(page, `/api/v1/exports/${encodeURIComponent(exportId)}`)
        state = record.state
        return state
      },
      { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toMatch(/^(ready|failed|expired)$/)
  return state
}

test.describe('真实初始化到报告 CSV 链路', () => {
  test('初始化、重新登录、登记数据源、运行报告并导出 CSV', async ({ page }) => {
    test.setTimeout(300_000)
    const setupToken = (await readFile(setupTokenFile, 'utf8')).trim()
    if (setupToken.length === 0) {
      throw new Error(`初始化令牌文件为空: ${setupTokenFile}`)
    }

    await page.goto('/')
    await expect(page).toHaveURL(/\/setup$/)
    await page.getByLabel('初始化令牌').fill(setupToken)
    await page.getByLabel('管理员用户名').fill(adminUsername)
    await page.getByLabel('管理员密码').fill(adminPassword)
    await page.getByLabel('确认密码').fill(adminPassword)
    await chooseOption(page, page, '时区', 'UTC')

    const setupResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/setup/complete') && response.request().method() === 'POST')
    await page.getByRole('button', { name: '完成初始化' }).click()
    expect((await responseEnvelope<{ username: string }>(setupResponse)).data.username).toBe(adminUsername)
    await expect(page).toHaveURL(/\/overview$/)
    await expect(page.getByRole('heading', { name: '总览' })).toBeVisible()

    const logoutResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/logout') && response.request().method() === 'POST')
    await page.getByRole('button', { name: '退出登录' }).click()
    expect((await responseEnvelope<Record<string, never>>(logoutResponse)).data).toEqual({})
    await expect(page).toHaveURL(/\/login$/)

    await page.getByLabel('用户名').fill(adminUsername)
    await page.getByLabel('密码').fill(adminPassword)
    const loginResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/login') && response.request().method() === 'POST')
    await page.locator('form button[type="submit"]').click()
    const loginData = (await responseEnvelope<{ admin: { username: string }; csrf_token: string }>(loginResponse)).data
    expect(loginData.admin.username).toBe(adminUsername)
    expect(loginData.csrf_token).toEqual(expect.any(String))
    await expect(page).toHaveURL(/\/overview$/)

    await page.getByRole('menuitem', { name: '数据源' }).click()
    await expect(page).toHaveURL(/\/sources$/)
    await expect(page.getByRole('heading', { name: '数据源' })).toBeVisible()
    await page.getByRole('button', { name: '登记数据源' }).click()
    const sourceDialog = page.getByRole('dialog', { name: '登记数据源' })
    await expect(sourceDialog).toBeVisible()
    await sourceDialog.getByLabel('名称').fill(sourceName)
    await chooseOption(page, sourceDialog, '批准挂载', 'main')
    await sourceDialog.getByLabel('挂载内相对路径').fill('')
    const sourceResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/sources') && response.request().method() === 'POST')
    await sourceDialog.getByRole('button', { name: /确\s*定/ }).click()
    const sourceData = (await responseEnvelope<{ id: string; name: string }>(sourceResponse)).data
    expect(sourceData.name).toBe(sourceName)
    await expect(page.getByRole('row', { name: new RegExp(sourceName) })).toBeVisible()

    await page.getByRole('menuitem', { name: '报告任务' }).click()
    await expect(page).toHaveURL(/\/profiles$/)
    await page.getByRole('button', { name: '新建报告任务' }).click()
    const profileDialog = page.getByRole('dialog', { name: '新建报告任务' })
    await expect(profileDialog).toBeVisible()
    await profileDialog.getByRole('textbox', { name: /^\*\s*名称$/ }).fill(profileName)
    const profileResponse = page.waitForResponse((response) => response.url().endsWith('/api/v1/profiles') && response.request().method() === 'POST')
    await profileDialog.getByRole('button', { name: /确\s*定/ }).click()
    const profileData = (await responseEnvelope<{ id: string; name: string }>(profileResponse)).data
    expect(profileData.name).toBe(profileName)
    const profileRow = page.getByRole('row', { name: new RegExp(profileName) })
    await expect(profileRow).toBeVisible()

    const runResponse = page.waitForResponse((response) => response.url().endsWith(`/api/v1/profiles/${profileData.id}/run`) && response.request().method() === 'POST')
    await profileRow.getByRole('button', { name: '立即运行' }).click()
    const runData = (await responseEnvelope<RunResponse>(runResponse)).data
    expect(runData.job_id).toEqual(expect.any(String))
    expect(runData.run_id).toEqual(expect.any(String))

    await page.getByRole('menuitem', { name: '任务中心' }).click()
    await expect(page).toHaveURL(/\/jobs$/)
    await expect(page.getByRole('heading', { name: '任务中心' })).toBeVisible()
    const finalJob = await waitForJob(page, runData.job_id)
    expect(['SUCCEEDED', 'PARTIAL']).toContain(finalJob.state)
    await expect(page.getByRole('row', { name: new RegExp(runData.job_id) })).toBeVisible()

    const report = await waitForReport(page, runData.run_id)
    expect(['succeeded', 'partial']).toContain(report.status)

    await page.getByRole('menuitem', { name: '报告中心' }).click()
    await expect(page).toHaveURL(/\/reports$/)
    await expect(page.getByRole('heading', { name: '报告中心' })).toBeVisible()
    const reportLink = page.getByRole('link', { name: report.id, exact: true })
    await expect(reportLink).toBeVisible({ timeout: 60_000 })
    await reportLink.click()
    await expect(page).toHaveURL(new RegExp(`/reports/${report.id}$`))
    await expect(page.getByRole('heading', { name: '报告详情' })).toBeVisible()
    await expect(page.getByText('栏目完整性')).toBeVisible()

    await page.getByRole('button', { name: '导出当前栏目' }).click()
    const exportDialog = page.getByRole('dialog', { name: '导出当前栏目' })
    await expect(exportDialog).toBeVisible()
    await chooseOption(page, exportDialog, '格式', 'csv')
    const exportRequest = page.waitForRequest((request) => request.url().endsWith(`/api/v1/reports/${report.id}/exports`) && request.method() === 'POST')
    const exportResponse = page.waitForResponse((response) => response.url().endsWith(`/api/v1/reports/${report.id}/exports`) && response.request().method() === 'POST')
    await exportDialog.getByRole('button', { name: /确\s*定/ }).click()
    const exportData = (await responseEnvelope<ExportResponse>(exportResponse)).data
    expect(exportData.export_id).toEqual(expect.any(String))
    expect(exportData.job_id).toEqual(expect.any(String))

    const originalExportRequest = await exportRequest
    const repeatedExport = await page.evaluate(async ({ body, headers, path }) => {
      const response = await fetch(path, {
        method: 'POST',
        credentials: 'same-origin',
        headers,
        body,
      })
      return { status: response.status, body: (await response.json()) as unknown }
    }, {
      body: originalExportRequest.postData(),
      headers: {
        'Content-Type': originalExportRequest.headers()['content-type'],
        'X-CSRF-Token': originalExportRequest.headers()['x-csrf-token'],
        'Idempotency-Key': originalExportRequest.headers()['idempotency-key'],
      },
      path: `/api/v1/reports/${report.id}/exports`,
    })
    expect(repeatedExport.status).toBe(202)
    expect((repeatedExport.body as SuccessEnvelope<ExportResponse>).data).toEqual(exportData)

    const exportState = await waitForExport(page, exportData.export_id)
    expect(exportState).toBe('ready')
    const downloadPromise: Promise<Download> = page.waitForEvent('download')
    await page.getByRole('button', { name: '下载导出文件' }).click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toMatch(/\.csv$/)
    const downloadPath = await download.path()
    if (downloadPath === null) {
      throw new Error('Playwright 未提供 CSV 下载文件路径')
    }
    const csv = await readFile(downloadPath, 'utf8')
    expect(csv).toContain('report_id')
  })
})
