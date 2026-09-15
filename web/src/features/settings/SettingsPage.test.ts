import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createElement } from 'react'
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { InternalNotification, Page } from '../../api/types'
import { adminUpdatePayload, backupPayload, InternalNotificationsSection, internalNotificationSeverityLabel, restoreApplyPayload, restorePreviewPayload } from './SettingsPage'

const originalMatchMedia = window.matchMedia
const originalGetComputedStyle = window.getComputedStyle

beforeEach(() => {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  })
  Object.defineProperty(window, 'getComputedStyle', {
    configurable: true,
    value: vi.fn((element: Element, pseudoElt?: string | null) => {
      if (pseudoElt !== undefined && pseudoElt !== null) return { width: '0px', height: '0px' } as CSSStyleDeclaration
      return originalGetComputedStyle.call(window, element, pseudoElt)
    }),
  })
})

afterAll(() => {
  Object.defineProperty(window, 'matchMedia', { configurable: true, value: originalMatchMedia })
  Object.defineProperty(window, 'getComputedStyle', { configurable: true, value: originalGetComputedStyle })
})

function notificationPage(data: InternalNotification[], next_cursor: string | null): Page<InternalNotification> {
  return {
    data,
    meta: {
      next_cursor,
      page_size: 20,
      total_known: null,
      truncated: false,
      detail_available: false,
    },
    request_id: 'request-1',
  }
}

function renderNotifications() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(createElement(QueryClientProvider, { client: queryClient }, createElement(InternalNotificationsSection)))
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('内部通知显示映射', () => {
  it('按接口枚举显示级别', () => {
    expect(internalNotificationSeverityLabel('info')).toBe('提示')
    expect(internalNotificationSeverityLabel('warning')).toBe('警告')
    expect(internalNotificationSeverityLabel('error')).toBe('错误')
  })
})

describe('设置页内部通知列表', () => {
  const firstNotification: InternalNotification = {
    id: 'notification-1',
    kind: 'source.unavailable',
    title: '数据源不可访问',
    body: '媒体共享暂时不可用',
    severity: 'warning',
    read_at: null,
    created_at: '2026-09-14T10:00:00Z',
  }

  it('加载并展示通知契约字段', async () => {
    const getPage = vi.spyOn(api, 'getPage').mockResolvedValue(notificationPage([firstNotification], 'cursor-2'))

    renderNotifications()

    expect(await screen.findByText(firstNotification.title)).toBeInTheDocument()
    expect(screen.getByText(firstNotification.body)).toBeInTheDocument()
    expect(screen.getByText(firstNotification.kind)).toBeInTheDocument()
    expect(screen.getByText('警告')).toBeInTheDocument()
    expect(screen.getByText('未读')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '加载下一页' })).toBeInTheDocument()
    expect(getPage).toHaveBeenCalledWith('/api/v1/notifications', expect.objectContaining({ query: { cursor: undefined, page_size: 20 } }))
  })

  it('展示加载状态', async () => {
    let resolveRequest!: (page: Page<InternalNotification>) => void
    const pending = new Promise<Page<InternalNotification>>((resolve) => {
      resolveRequest = resolve
    })
    vi.spyOn(api, 'getPage').mockReturnValue(pending)

    const { container } = renderNotifications()

    expect(container.querySelector('.ant-skeleton')).toBeInTheDocument()
    resolveRequest(notificationPage([], null))
    expect(await screen.findByText('暂无内部通知')).toBeInTheDocument()
  })

  it('展示请求错误状态', async () => {
    vi.spyOn(api, 'getPage').mockRejectedValue(new Error('notifications unavailable'))

    renderNotifications()

    expect(await screen.findByText('请求失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /重\s*试/ })).toBeInTheDocument()
  })

  it('展示空状态和末页状态', async () => {
    vi.spyOn(api, 'getPage').mockResolvedValue(notificationPage([], null))

    renderNotifications()

    expect(await screen.findByText('暂无内部通知')).toBeInTheDocument()
    expect(screen.getByText('已到末页')).toBeInTheDocument()
  })

  it('使用返回的分页游标加载下一页', async () => {
    const nextNotification: InternalNotification = {
      ...firstNotification,
      id: 'notification-2',
      title: '存储预算不足',
      body: '可用空间低于任务要求',
      severity: 'error',
      read_at: '2026-09-14T10:01:00Z',
    }
    const getPage = vi.spyOn(api, 'getPage')
      .mockResolvedValueOnce(notificationPage([firstNotification], 'cursor-2'))
      .mockResolvedValueOnce(notificationPage([nextNotification], null))

    renderNotifications()

    await screen.findByText(firstNotification.title)
    fireEvent.click(screen.getByRole('button', { name: '加载下一页' }))

    expect(await screen.findByText(nextNotification.title)).toBeInTheDocument()
    await waitFor(() => expect(getPage).toHaveBeenLastCalledWith('/api/v1/notifications', expect.objectContaining({ query: { cursor: 'cursor-2', page_size: 20 } })))
  })
})

describe('管理员 PATCH 请求体', () => {
  it('提交启用状态和新密码', () => {
    expect(adminUpdatePayload({ enabled: false, password: 'new-admin-password' })).toEqual({
      enabled: false,
      password: 'new-admin-password',
    })
  })

  it('未填写新密码时省略密码字段', () => {
    expect(adminUpdatePayload({ enabled: true, password: '' })).toEqual({ enabled: true })
  })
})

describe('设置页秘密备份/恢复请求体', () => {
  it('提交含秘密备份策略和口令', () => {
    const passphrase = 'test-secret-passphrase'
    const payload = backupPayload({ include_secrets: true, secrets_passphrase: passphrase })

    expect(payload).toEqual({ include_secrets: true, secrets_passphrase: passphrase })
    const jobParams = { export_id: 'export-1', include_secrets: payload.include_secrets }
    expect(jobParams).not.toHaveProperty('secrets_passphrase')
    expect(JSON.stringify(jobParams)).not.toContain(passphrase)
  })

  it('应用恢复时转发备份口令但不转发管理员密码', () => {
    const payload = restoreApplyPayload({
      preview_id: 'export-1',
      password: 'admin-password',
      confirmation: 'RESTORE',
      secrets_passphrase: 'test-secret-passphrase',
    }, 'reauth-1')

    expect(payload).toEqual({
      preview_id: 'export-1',
      reauth_token: 'reauth-1',
      confirmation: 'RESTORE',
      secrets_passphrase: 'test-secret-passphrase',
    })
    expect(payload).not.toHaveProperty('password')
    expect(JSON.stringify(payload)).not.toContain('admin-password')
  })

  it('未填写可选恢复口令时省略该字段', () => {
    expect(backupPayload({ include_secrets: false })).toEqual({ include_secrets: false })
    expect(restorePreviewPayload({ backup_export_id: 'export-1' })).toEqual({ backup_export_id: 'export-1' })
    expect(restorePreviewPayload({ backup_export_id: 'export-1', secrets_passphrase: '' })).toEqual({ backup_export_id: 'export-1' })
    expect(restoreApplyPayload({ preview_id: 'export-1', password: 'admin-password', confirmation: 'RESTORE' }, 'reauth-1')).toEqual({
      preview_id: 'export-1',
      reauth_token: 'reauth-1',
      confirmation: 'RESTORE',
    })
    expect(restoreApplyPayload({ preview_id: 'export-1', password: 'admin-password', confirmation: 'RESTORE', secrets_passphrase: '' }, 'reauth-1')).toEqual({
      preview_id: 'export-1',
      reauth_token: 'reauth-1',
      confirmation: 'RESTORE',
    })
  })
})
