import { Button, Result, Skeleton } from 'antd'
import type { UseQueryResult } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { ApiError } from '../api/errors'

function requestIdSuffix(error: ApiError): string {
  return error.requestId ? ` · 请求 ID：${error.requestId}` : ''
}

/**
 * 统一的查询状态渲染：加载骨架屏、空数据由调用方处理、错误按状态码区分
 * （spec 15.8：401 进登录、403 明确权限/只读限制、410 历史明细过期、503 服务不可用，
 * 不得把这些错误渲染成“没有文件”）。
 */
export function QueryState<T>({
  query,
  children,
}: {
  query: UseQueryResult<T, Error>
  children: (data: T) => ReactNode
}) {
  if (query.isPending) {
    return <Skeleton active paragraph={{ rows: 6 }} />
  }
  if (query.isError) {
    const error = query.error
    const retry = (
      <Button onClick={() => void query.refetch()}>重试</Button>
    )
    if (error instanceof ApiError) {
      if (error.status === 401) {
        return (
          <Result
            status="403"
            title="未登录或会话已过期"
            subTitle="正在跳转到登录页…"
          />
        )
      }
      if (error.status === 403) {
        return (
          <Result
            status="403"
            title="没有访问权限"
            subTitle={`当前账户无权访问该资源，或系统处于只读限制。（${error.code}${requestIdSuffix(error)}）`}
          />
        )
      }
      if (error.status === 410) {
        return (
          <Result
            status="404"
            title="内容已过期"
            subTitle="历史明细已过期或已按保留策略清理，请返回列表查看最新数据。"
          />
        )
      }
      if (error.status === 503) {
        return (
          <Result
            status="warning"
            title="服务暂不可用"
            subTitle={`后端正在初始化、维护或超出资源预算，请稍后重试。（${error.code}${requestIdSuffix(error)}）`}
            extra={retry}
          />
        )
      }
      return (
        <Result
          status="error"
          title="请求失败"
          subTitle={`${error.message}（${error.code}${requestIdSuffix(error)}）`}
          extra={retry}
        />
      )
    }
    return (
      <Result status="error" title="请求失败" subTitle={String(error)} extra={retry} />
    )
  }
  return <>{children(query.data)}</>
}
