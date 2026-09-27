export interface ApiErrorInit {
  status: number
  code: string
  message: string
  requestId?: string
  details?: unknown
}

/**
 * 统一 API 错误。code 来自后端错误信封的稳定错误码
 * （如 FORBIDDEN / DETAIL_EXPIRED / PASSWORD_CHANGE_REQUIRED）。
 * 非 JSON 或不完整错误响应统一报告为 INVALID_RESPONSE。
 */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId?: string
  readonly details?: unknown

  constructor(init: ApiErrorInit) {
    super(init.message)
    this.name = 'ApiError'
    this.status = init.status
    this.code = init.code
    this.requestId = init.requestId
    this.details = init.details
  }
}

export function isApiError(error: unknown, code?: string): error is ApiError {
  return (
    error instanceof ApiError && (code === undefined || error.code === code)
  )
}
