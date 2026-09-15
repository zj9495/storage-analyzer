import { Layout, Menu, Button, Space, Typography } from 'antd'
import type { MenuProps } from 'antd'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { useMe } from '../features/auth/useMe'

const MENU_ITEMS: NonNullable<MenuProps['items']> = [
  { key: '/overview', label: '总览' },
  { key: '/sources', label: '数据源' },
  { key: '/profiles', label: '报告任务' },
  { key: '/jobs', label: '任务中心' },
  { key: '/reports', label: '报告中心' },
  { key: '/cleanup', label: '清理中心' },
  { key: '/settings', label: '设置' },
  { key: '/diagnostics', label: '诊断与审计' },
]

export function AppLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const me = useMe()

  const logout = useMutation({
    mutationFn: () => api.post('/api/v1/auth/logout'),
    // 即使后端不可达也清空本地会话缓存并回到登录页
    onSettled: () => {
      queryClient.clear()
      navigate('/login', { replace: true })
    },
  })

  const selectedKey =
    MENU_ITEMS.map((item) => String(item?.key))
      .filter((key) => location.pathname.startsWith(key))
      .sort((a, b) => b.length - a.length)[0] ?? '/overview'

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Layout.Sider width={208} theme="dark">
        <div
          style={{
            color: '#fff',
            padding: '16px',
            fontWeight: 600,
            fontSize: 16,
          }}
        >
          NAS 存储分析
        </div>
        <Menu
          theme="dark"
          mode="inline"
          items={MENU_ITEMS}
          selectedKeys={[selectedKey]}
          onClick={({ key }) => navigate(key)}
        />
      </Layout.Sider>
      <Layout>
        <Layout.Header
          style={{
            background: '#fff',
            display: 'flex',
            justifyContent: 'flex-end',
            alignItems: 'center',
            paddingInline: 24,
          }}
        >
          <Space>
            <Typography.Text type="secondary">
              {me.data?.admin.username}
            </Typography.Text>
            <Button
              size="small"
              onClick={() => logout.mutate()}
              loading={logout.isPending}
            >
              退出登录
            </Button>
          </Space>
        </Layout.Header>
        <Layout.Content style={{ padding: 24 }}>
          <Outlet />
        </Layout.Content>
      </Layout>
    </Layout>
  )
}
