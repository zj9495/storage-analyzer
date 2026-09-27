import { Alert, Button, Card, Form, Input } from 'antd'
import { Navigate, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { ApiError } from '../../api/errors'
import { useMe } from './useMe'

interface ChangePasswordForm {
  new_password: string
  confirm_password: string
}

export function ChangePasswordPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const me = useMe()
  const changePassword = useMutation({
    mutationFn: (values: ChangePasswordForm) =>
      api.post('/api/v1/auth/change-password', {
        new_password: values.new_password,
      }),
    onSuccess: () => {
      queryClient.clear()
      navigate('/login', { replace: true })
    },
  })

  if (me.data && !me.data.admin.must_change_password) {
    return <Navigate to="/overview" replace />
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
      <Card title="首次登录请修改密码" style={{ width: 400 }}>
        <Form<ChangePasswordForm>
          layout="vertical"
          onFinish={(values) => changePassword.mutate(values)}
        >
          <Form.Item
            name="new_password"
            label="新密码"
            rules={[
              { required: true, message: '请输入新密码' },
              { min: 8, message: '密码至少 8 个字符' },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label="确认新密码"
            dependencies={['new_password']}
            rules={[
              { required: true, message: '请再次输入新密码' },
              ({ getFieldValue }) => ({
                validator: (_, value) =>
                  value === getFieldValue('new_password')
                    ? Promise.resolve()
                    : Promise.reject(new Error('两次输入的密码不一致')),
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          {changePassword.error instanceof ApiError ? (
            <Alert
              type="error"
              showIcon
              style={{ marginBottom: 16 }}
              message={`修改密码失败：${changePassword.error.message}`}
              description={`错误码：${changePassword.error.code}`}
            />
          ) : null}
          <Button
            type="primary"
            htmlType="submit"
            block
            loading={changePassword.isPending}
          >
            修改密码并重新登录
          </Button>
        </Form>
      </Card>
    </div>
  )
}
