import { useEffect } from 'react'
import { Outlet, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { setUnauthorizedHandler } from '../api/client'

/**
 * 路由根节点：注册全局 401 处理。
 * 受保护页面的请求返回 401 时清空用户查询缓存并跳转登录页；
 * 已在 /login 或 /setup 时由页面自身处理，不清空正在使用的查询。
 */
export function Root() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  useEffect(() => {
    setUnauthorizedHandler(() => {
      const path = window.location.pathname
      if (path === '/login' || path === '/setup') return
      queryClient.clear()
      navigate('/login', { replace: true })
    })
    return () => setUnauthorizedHandler(null)
  }, [navigate, queryClient])

  return <Outlet />
}
