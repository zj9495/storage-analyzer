import { ApiError } from './errors'
import type { ApiEnvelope, LiveJobEvent, ListMeta, Page } from './types'

export type QueryValue =
  | string
  | number
  | boolean
  | ReadonlyArray<string | number | boolean>
  | null
  | undefined

export interface RequestOptions {
  query?: Record<string, QueryValue>
  body?: unknown
  signal?: AbortSignal
  headers?: Record<string, string>
}

const CSRF_COOKIE_NAME = 'nas_csrf'
const CSRF_HEADER = 'X-CSRF-Token'

/** 后端当前会发送的命名 SSE 事件；EventSource 的 onmessage 不会接收这些帧。 */
export const LIVE_JOB_EVENT_TYPES = [
  'scan.progress',
  'scan.completed',
  'scan.cancel_requested',
  'job.finished',
  'job.completed',
  'heartbeat',
  'job.state',
  'job.progress',
  'job.warning',
] as const

function readCsrfCookie(): string | null {
  if (typeof document === 'undefined') return null
  const match = document.cookie.match(
    new RegExp(`(?:^|;\\s*)${CSRF_COOKIE_NAME}=([^;]*)`),
  )
  return match ? decodeURIComponent(match[1]) : null
}

type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | null = null

/** 401 全局处理：由 app 层注册（跳转登录页并清空用户查询缓存）。 */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  onUnauthorized = handler
}

function newRequestId(): string {
  return crypto.randomUUID()
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * 将后端实际 SSE 帧（event + id + payload）还原为前端可消费的完整事件。
 * 当前 SSE 帧不携带 created_at，因此保留为可选字段，不生成伪造时间。
 */
export function parseLiveJobEvent(
  jobId: string,
  event: MessageEvent<string>,
): LiveJobEvent {
  if (event.lastEventId === '') {
    throw new Error('任务事件序号无效')
  }
  const sequence = Number(event.lastEventId)
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new Error('任务事件序号无效')
  }
  if (event.type === '') {
    throw new Error('任务事件类型为空')
  }

  let payload: unknown
  try {
    payload = JSON.parse(event.data)
  } catch {
    throw new Error('任务事件 payload 无法解析')
  }
  if (!isRecord(payload)) {
    throw new Error('任务事件 payload 不是对象')
  }

  return {
    job_id: jobId,
    sequence,
    type: event.type,
    payload,
  }
}

export function buildUrl(
  path: string,
  query?: Record<string, QueryValue>,
): string {
  const url = new URL(path, window.location.origin)
  if (query) {
    for (const key of Object.keys(query).sort()) {
      const value = query[key]
      if (value === undefined || value === null || value === '') continue
      if (Array.isArray(value)) {
        for (const item of value) {
          url.searchParams.append(key, String(item))
        }
      } else {
        url.searchParams.set(key, String(value))
      }
    }
  }
  return `${url.pathname}${url.search}`
}

interface ErrorEnvelope {
  error: {
    code: string
    message: string
    details: Record<string, unknown>
  }
  request_id: string
}

function isSuccessEnvelope(body: unknown): body is ApiEnvelope<unknown> {
  if (typeof body !== 'object' || body === null) return false
  if (!('data' in body) || !('meta' in body) || !('request_id' in body)) return false
  return typeof body.request_id === 'string' && body.request_id.length > 0 && typeof body.meta === 'object' && body.meta !== null
}

function isListMeta(meta: unknown): meta is ListMeta {
  if (typeof meta !== 'object' || meta === null) return false
  if (!('next_cursor' in meta) || !('page_size' in meta) || !('total_known' in meta) || !('truncated' in meta) || !('detail_available' in meta)) return false
  return (meta.next_cursor === null || typeof meta.next_cursor === 'string') && typeof meta.page_size === 'number' && (meta.total_known === null || typeof meta.total_known === 'number') && typeof meta.truncated === 'boolean' && typeof meta.detail_available === 'boolean' && !(meta.truncated && meta.next_cursor === null)
}

function isErrorEnvelope(body: unknown): body is ErrorEnvelope {
  if (typeof body !== 'object' || body === null || !('error' in body) || !('request_id' in body)) return false
  const error = body.error
  return typeof body.request_id === 'string' && body.request_id.length > 0 && typeof error === 'object' && error !== null && 'code' in error && 'message' in error && 'details' in error && typeof error.code === 'string' && error.code.length > 0 && typeof error.message === 'string' && error.message.length > 0 && typeof error.details === 'object' && error.details !== null
}

export async function parseErrorResponse(
  res: Response,
  requestId: string,
): Promise<ApiError> {
  let body: unknown
  try {
    body = await res.clone().json()
  } catch {
    return new ApiError({ status: res.status, code: 'INVALID_RESPONSE', message: '服务返回的错误响应不符合接口契约', requestId })
  }
  if (!isErrorEnvelope(body)) return new ApiError({ status: res.status, code: 'INVALID_RESPONSE', message: '服务返回的错误响应不符合接口契约', requestId })
  return new ApiError({ status: res.status, code: body.error.code, message: body.error.message, requestId: body.request_id, details: body.error.details })
}

function parseSuccessResponse<T>(
  text: string,
  status: number,
  requestId: string,
): ApiEnvelope<T> {
  let body: unknown
  try {
    body = JSON.parse(text)
  } catch {
    throw new ApiError({
      status,
      code: 'INVALID_RESPONSE',
      message: '服务返回了无法解析的响应',
      requestId,
    })
  }
  if (!isSuccessEnvelope(body)) {
    throw new ApiError({
      status,
      code: 'INVALID_RESPONSE',
      message: '服务返回的响应信封不符合接口契约',
      requestId,
    })
  }
  return body as ApiEnvelope<T>
}

/**
 * 同源 fetch 封装：cookie 凭据、CSRF 头、request_id 传播、错误信封解析。
 * mutation（非 GET/HEAD）不在此自动重试；危险操作的重试策略由调用方
 * （TanStack Query 默认 mutations.retry = false）与服务端幂等共同保证。
 */
export async function request<T>(
  method: string,
  path: string,
  options: RequestOptions = {},
): Promise<ApiEnvelope<T>> {
  const requestId = newRequestId()
  const isMutation = method !== 'GET' && method !== 'HEAD'
  const headers = new Headers({
    Accept: 'application/json',
    'X-Request-ID': requestId,
  })
  for (const [key, value] of Object.entries(options.headers ?? {})) {
    headers.set(key, value)
  }
  if (isMutation) {
    if (options.body !== undefined) {
      headers.set('Content-Type', 'application/json')
    }
    if (!headers.has(CSRF_HEADER)) {
      const token = readCsrfCookie()
      if (token) headers.set(CSRF_HEADER, token)
    }
  }

  let res: Response
  try {
    res = await fetch(buildUrl(path, options.query), {
      method,
      credentials: 'same-origin',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal ?? null,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError({
      status: 0,
      code: 'NETWORK_ERROR',
      message: '网络请求失败，请检查连接后重试',
      requestId,
    })
  }

  if (res.status === 401) {
    onUnauthorized?.()
  }
  if (!res.ok) {
    throw await parseErrorResponse(res, requestId)
  }

  if (res.status === 204) {
    throw new ApiError({
      status: res.status,
      code: 'INVALID_RESPONSE',
      message: '服务返回了不符合契约的空响应',
      requestId: res.headers.get('x-request-id') ?? requestId,
    })
  }
  const text = await res.text()
  if (!text) {
    throw new ApiError({
      status: res.status,
      code: 'INVALID_RESPONSE',
      message: '服务返回了空响应',
      requestId: res.headers.get('x-request-id') ?? requestId,
    })
  }
  return parseSuccessResponse<T>(
    text,
    res.status,
    res.headers.get('x-request-id') ?? requestId,
  )
}

export async function requestBlob(
  method: string,
  path: string,
  options: RequestOptions = {},
): Promise<{ blob: Blob; filename: string | null }> {
  const requestId = newRequestId()
  const headers = new Headers({
    Accept: 'application/octet-stream',
    'X-Request-ID': requestId,
  })
  for (const [key, value] of Object.entries(options.headers ?? {})) {
    headers.set(key, value)
  }
  let res: Response
  try {
    res = await fetch(buildUrl(path, options.query), {
      method,
      credentials: 'same-origin',
      headers,
      signal: options.signal ?? null,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError({ status: 0, code: 'NETWORK_ERROR', message: '网络请求失败，请检查连接后重试', requestId })
  }
  if (res.status === 401) onUnauthorized?.()
  if (!res.ok) throw await parseErrorResponse(res, requestId)
  const disposition = res.headers.get('content-disposition')
  const filenameMatch = disposition?.match(/filename="?([^";]+)"?/i)
  return { blob: await res.blob(), filename: filenameMatch?.[1] ?? null }
}

export function createIdempotencyKey(): string {
  return newRequestId()
}

export const api = {
  get: <T>(path: string, options?: Omit<RequestOptions, 'body'>) =>
    request<T>('GET', path, options),
  getPage: async <T>(path: string, options?: Omit<RequestOptions, 'body'>): Promise<Page<T>> => {
    const response = await request<T[]>('GET', path, options)
    if (!Array.isArray(response.data) || !isListMeta(response.meta)) {
      throw new ApiError({ status: 200, code: 'INVALID_RESPONSE', message: '服务返回的分页响应不符合接口契约', requestId: response.request_id })
    }
    return response as Page<T>
  },
  getObjectPage: async <T>(path: string, options?: Omit<RequestOptions, 'body'>): Promise<ApiEnvelope<T> & { meta: ListMeta }> => {
    const response = await request<T>('GET', path, options)
    if (!isRecord(response.data) || !isListMeta(response.meta)) {
      throw new ApiError({ status: 200, code: 'INVALID_RESPONSE', message: '服务返回的分页响应不符合接口契约', requestId: response.request_id })
    }
    return response as ApiEnvelope<T> & { meta: ListMeta }
  },
  post: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>('POST', path, { ...options, body }),
  put: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>('PUT', path, { ...options, body }),
  patch: <T>(path: string, body?: unknown, options?: RequestOptions) =>
    request<T>('PATCH', path, { ...options, body }),
  delete: <T>(path: string, options?: RequestOptions) =>
    request<T>('DELETE', path, options),
  download: (path: string, options?: Omit<RequestOptions, 'body'>) =>
    requestBlob('GET', path, options),
}
