import { Alert, Button, Card, Form, Input } from 'antd'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { ApiError } from '../../api/errors'
import type { AdminUser } from '../../api/types'
import { useMe } from './useMe'

interface LoginForm {
  username: string
  password: string
}

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const me = useMe()

  const from =
    (location.state as { from?: { pathname?: string } } | null)?.from
      ?.pathname ?? '/overview'

  const login = useMutation({
    mutationFn: (values: LoginForm) =>
      api.post<{ admin: AdminUser; csrf_token: string }>('/api/v1/auth/login', values),
    onSuccess: async (response) => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
      navigate(
        response.data.admin.must_change_password ? '/change-password' : from,
        { replace: true },
      )
    },
  })

  // 已登录用户访问 /login 时直接进入应用
  if (me.data) {
    return (
      <Navigate
        to={me.data.admin.must_change_password ? '/change-password' : '/overview'}
        replace
      />
    )
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Card title="登录 NAS 存储分析" style={{ width: 400 }}>
        <Form<LoginForm>
          layout="vertical"
          initialValues={{ username: 'admin', password: 'admin' }}
          onFinish={(values) => login.mutate(values)}
        >
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: true, message: '请输入用户名' }]}
          >
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item
            name="password"
            label="密码"
            rules={[{ required: true, message: '请输入密码' }]}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          {login.error instanceof ApiError ? (
            <Alert
              type="error"
              showIcon
              style={{ marginBottom: 16 }}
              message={
                login.error.status === 401
                  ? '用户名或密码错误'
                  : `登录失败：${login.error.message}`
              }
              description={`错误码：${login.error.code}`}
            />
          ) : null}
          <Button
            type="primary"
            htmlType="submit"
            block
            loading={login.isPending}
          >
            登录
          </Button>
        </Form>
      </Card>
    </div>
  )
}
