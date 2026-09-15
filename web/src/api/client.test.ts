import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, buildUrl, parseLiveJobEvent } from './client'
import { ApiError } from './errors'
import type { CompareJobResponse, ComparisonResult } from './types'

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

describe('buildUrl', () => {
  it('查询参数按键排序，空值省略，数组重复', () => {
    const url = buildUrl('/api/v1/reports', {
      b: '2',
      a: '1',
      empty: '',
      none: undefined,
      multi: ['x', 'y'],
    })
    expect(url).toBe('/api/v1/reports?a=1&b=2&multi=x&multi=y')
  })
})

describe('api client 错误信封', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('解析稳定错误码与服务端 request_id', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(403, {
        error: {
          code: 'FORBIDDEN',
          message: '只读模式',
          details: {},
        },
        request_id: 'srv-1',
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const error = await api.get('/api/v1/sources').then(
      () => {
        throw new Error('应当拒绝')
      },
      (e: unknown) => e,
    )
    expect(error).toBeInstanceOf(ApiError)
    const apiError = error as ApiError
    expect(apiError.status).toBe(403)
    expect(apiError.code).toBe('FORBIDDEN')
    expect(apiError.message).toBe('只读模式')
    expect(apiError.requestId).toBe('srv-1')
  })

  it('保留明细过期稳定错误码 DETAIL_EXPIRED', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(410, {
      error: { code: 'DETAIL_EXPIRED', message: '报告明细已过期', details: {} },
      request_id: 'srv-410',
    })))
    const error = await api.get('/api/v1/reports/report-1/files').then(
      () => {
        throw new Error('应当拒绝过期明细请求')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error.status).toBe(410)
    expect(error.code).toBe('DETAIL_EXPIRED')
    expect(error.requestId).toBe('srv-410')
  })

  it('拒绝不符合错误信封契约的非 JSON 响应', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('bad gateway', { status: 502 })),
    )
    const error = await api.get('/api/v1/jobs').then(
      () => {
        throw new Error('应当拒绝')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error).toBeInstanceOf(ApiError)
    expect(error.code).toBe('INVALID_RESPONSE')
    expect(error.message).toBe('服务返回的错误响应不符合接口契约')
    expect(error.status).toBe(502)
  })

  it('拒绝缺少错误信封必填字段的 JSON 响应', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(502, { error: { code: 'INTERNAL' }, request_id: 'srv-1' })))
    const error = await api.get('/api/v1/jobs').then(
      () => {
        throw new Error('应当拒绝不完整错误信封')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error.code).toBe('INVALID_RESPONSE')
  })

  it('每个请求携带 X-Request-ID 头并以 cookie 同源凭据发送', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, { data: { ok: true }, meta: {}, request_id: 'srv-1' }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const response = await api.get<{ ok: boolean }>('/api/v1/auth/me')
    expect(response.data.ok).toBe(true)
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(init.credentials).toBe('same-origin')
    const headers = new Headers(init.headers)
    expect(headers.get('X-Request-ID')).toBeTruthy()
  })

  it('拒绝未包含成功信封的 2xx 响应', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, { ok: true })))
    const error = await api.get('/api/v1/auth/me').then(
      () => {
        throw new Error('应当拒绝裸响应')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error).toBeInstanceOf(ApiError)
    expect(error.code).toBe('INVALID_RESPONSE')
  })

  it('拒绝成功信封中错误的 meta 类型', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, { data: {}, meta: null, request_id: 'srv-1' })))
    const error = await api.get('/api/v1/auth/me').then(
      () => {
        throw new Error('应当拒绝错误的成功信封')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error.code).toBe('INVALID_RESPONSE')
  })

  it('拒绝分页响应中非数组 data 或不完整 meta', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, { data: {}, meta: {}, request_id: 'srv-1' })))
    const error = await api.getPage('/api/v1/jobs').then(
      () => {
        throw new Error('应当拒绝错误的分页响应')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error.code).toBe('INVALID_RESPONSE')
  })

  it('对象分页响应保留对象 data 并校验分页 meta', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, {
      data: { id: 'action-1', state: 'running' },
      meta: { next_cursor: 'next', page_size: 50, total_known: null, truncated: true, detail_available: true },
      request_id: 'srv-1',
    })))
    const response = await api.getObjectPage<{ id: string; state: string }>('/api/v1/cleanup/actions/action-1')
    expect(response.data).toEqual({ id: 'action-1', state: 'running' })
    expect(response.meta.next_cursor).toBe('next')
  })

  it('拒绝对象分页响应中不完整的 meta', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, {
      data: { id: 'action-1' },
      meta: {},
      request_id: 'srv-1',
    })))
    const error = await api.getObjectPage('/api/v1/cleanup/actions/action-1').then(
      () => {
        throw new Error('应当拒绝错误的对象分页响应')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error.code).toBe('INVALID_RESPONSE')
  })

  it('拒绝对象分页响应中非对象的 data', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, {
      data: [],
      meta: { next_cursor: null, page_size: 50, total_known: null, truncated: false, detail_available: true },
      request_id: 'srv-1',
    })))
    const error = await api.getObjectPage('/api/v1/cleanup/actions/action-1').then(
      () => {
        throw new Error('应当拒绝错误的对象 data')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error.code).toBe('INVALID_RESPONSE')
  })

  it('拒绝已截断但没有 next_cursor 的分页响应，避免静默丢页', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(200, {
      data: [],
      meta: { next_cursor: null, page_size: 50, total_known: null, truncated: true, detail_available: false },
      request_id: 'srv-1',
    })))
    const error = await api.getPage('/api/v1/profiles').then(
      () => {
        throw new Error('应当拒绝无游标的截断分页响应')
      },
      (e: unknown) => e as ApiError,
    )
    expect(error.code).toBe('INVALID_RESPONSE')
  })

  it('下载接口保留二进制响应与文件名，不要求 JSON 信封', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response('report-data', {
          status: 200,
          headers: { 'Content-Disposition': 'attachment; filename="report.csv"' },
        }),
      ),
    )
    const result = await api.download('/api/v1/exports/export-1/download')
    expect(result.filename).toBe('report.csv')
    expect(result.blob.size).toBe(11)
  })

  it('初始化提交同时保留 setup_token body 与显式 CSRF 头', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(201, { data: { id: 'admin-1' }, meta: {}, request_id: 'srv-1' }),
    )
    vi.stubGlobal('fetch', fetchMock)
    document.cookie = 'nas_csrf=cookie-token'

    try {
      await api.post('/api/v1/setup/complete', {
        setup_token: 'setup-token',
        username: 'admin',
        password: 'a very long password',
        timezone: 'UTC',
      }, { headers: { 'X-CSRF-Token': 'setup-token' } })
    } finally {
      document.cookie = 'nas_csrf=; Max-Age=0'
    }

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    const headers = new Headers(init.headers)
    expect(headers.get('X-CSRF-Token')).toBe('setup-token')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(JSON.parse(String(init.body))).toMatchObject({ setup_token: 'setup-token' })
  })
})

describe('SSE 事件帧', () => {
  it('从命名事件、Last-Event-ID 和 payload 组装完整实时事件', () => {
    const event = new MessageEvent<string>('scan.progress', {
      data: JSON.stringify({ files_seen: '3' }),
      lastEventId: '12',
    })

    expect(parseLiveJobEvent('job-1', event)).toEqual({
      job_id: 'job-1',
      sequence: 12,
      type: 'scan.progress',
      payload: { files_seen: '3' },
    })
  })

  it('拒绝无效 sequence 或非对象 payload', () => {
    expect(() => parseLiveJobEvent('job-1', new MessageEvent('job.finished', { data: '{}', lastEventId: '' }))).toThrow('任务事件序号无效')
    expect(() => parseLiveJobEvent('job-1', new MessageEvent('job.finished', { data: '[]', lastEventId: '1' }))).toThrow('任务事件 payload 不是对象')
  })
})

describe('comparison API contract', () => {
  it('requires the durable comparison_id and preserves result rows', () => {
    const accepted: CompareJobResponse = {
      comparison_id: 'comparison-1',
      job_id: 'job-1',
      comparable: true,
    }
    const result: ComparisonResult = {
      id: accepted.comparison_id,
      job_id: accepted.job_id,
      left_report_id: 'report-1',
      right_report_id: 'report-2',
      mode: 'aggregate',
      comparable: true,
      state: 'pending',
      summary: {},
      rows: [],
    }
    expect(result.id).toBe(accepted.comparison_id)
    expect(result.rows).toEqual([])
  })
})
