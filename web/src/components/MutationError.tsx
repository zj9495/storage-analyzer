import { Alert } from 'antd'
import { ApiError } from '../api/errors'

export function MutationError({ error }: { error: unknown }) {
  if (error === null || error === undefined) return null
  if (error instanceof ApiError) {
    return (
      <Alert
        type="error"
        showIcon
        message={error.message}
        description={`${error.code}${error.requestId ? ` · 请求 ID：${error.requestId}` : ''}`}
        style={{ marginBottom: 16 }}
      />
    )
  }
  return (
    <Alert
      type="error"
      showIcon
      message="操作失败"
      description={error instanceof Error ? error.message : String(error)}
      style={{ marginBottom: 16 }}
    />
  )
}
