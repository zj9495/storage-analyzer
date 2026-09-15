import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { Button, Result, Spin } from 'antd'
import { isApiError } from '../api/errors'
import { useMe } from '../features/auth/useMe'

/**
 * 认证守卫：通过 TanStack Query 查询 /auth/me。
 * - 401 → 跳转 /login
 * - 503 + SETUP_REQUIRED → 跳转 /setup 初始化向导
 * - 其他错误 → 明确呈现，不当作“未登录”静默处理
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const me = useMe()
  const location = useLocation()

  if (me.isPending) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Spin size="large" />
      </div>
    )
  }

  if (me.isError) {
    if (isApiError(me.error) && me.error.status === 401) {
      return <Navigate to="/login" state={{ from: location }} replace />
    }
    if (isApiError(me.error, 'SETUP_REQUIRED')) {
      return <Navigate to="/setup" replace />
    }
    return (
      <Result
        status="error"
        title="无法确认登录状态"
        subTitle={
          me.error instanceof Error ? me.error.message : String(me.error)
        }
        extra={<Button onClick={() => void me.refetch()}>重试</Button>}
      />
    )
  }

  return <>{children}</>
}
