import { Alert, Button, Card, Form, Input, Result, Select, Typography } from 'antd'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { ApiError } from '../../api/errors'
import type { SetupStatusResponse } from '../../api/types'
import { QueryState } from '../../components/QueryState'

const TIMEZONES = [
  'Asia/Shanghai',
  'Asia/Hong_Kong',
  'Asia/Taipei',
  'Asia/Tokyo',
  'Asia/Singapore',
  'UTC',
]

interface SetupForm {
  setup_token: string
  username: string
  password: string
  confirm_password: string
  timezone: string
}

function guessTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone
  } catch {
    return 'Asia/Shanghai'
  }
}

/**
 * 初始化向导：提交初始化令牌、管理员账号（密码至少 12 位）与时区。
 * 后端未就绪时提交会失败并显示真实错误，不预填任何假数据。
 */
export function SetupPage() {
  const navigate = useNavigate()
  const status = useQuery({
    queryKey: ['setup', 'status'],
    queryFn: async ({ signal }) =>
      (await api.get<SetupStatusResponse>('/api/v1/setup/status', { signal })).data,
    retry: false,
  })

  const setup = useMutation({
    mutationFn: (values: SetupForm) => {
      const { confirm_password: _confirm, ...payload } = values
      return api.post('/api/v1/setup/complete', payload, {
        headers: { 'X-CSRF-Token': values.setup_token },
      })
    },
    onSuccess: () => navigate('/overview', { replace: true }),
  })

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <QueryState query={status}>
        {(data) =>
          data.initialized || !data.can_initialize ? (
            <Result
              status="info"
              title="系统已完成初始化"
              subTitle="初始化令牌不可用，请使用登录页进入系统。"
              extra={
                <Button type="primary" onClick={() => navigate('/login')}>
                  前往登录
                </Button>
              }
            />
          ) : (
            <Card title="初始化向导" style={{ width: 480 }}>
              <Typography.Paragraph type="secondary">
                首次部署需要完成初始化。请从容器终端读取初始化令牌（/data/setup-token），
                并创建管理员账户。
              </Typography.Paragraph>
              <Form<SetupForm>
                layout="vertical"
                initialValues={{ timezone: guessTimezone() }}
                onFinish={(values) => setup.mutate(values)}
              >
          <Form.Item
            name="setup_token"
            label="初始化令牌"
            rules={[{ required: true, message: '请输入初始化令牌' }]}
          >
            <Input placeholder="单次有效，默认 30 分钟" />
          </Form.Item>
          <Form.Item
            name="username"
            label="管理员用户名"
            rules={[{ required: true, message: '请输入管理员用户名' }]}
          >
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item
            name="password"
            label="管理员密码"
            rules={[
              { required: true, message: '请输入密码' },
              { min: 12, message: '密码至少 12 个字符' },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label="确认密码"
            dependencies={['password']}
            rules={[
              { required: true, message: '请再次输入密码' },
              ({ getFieldValue }) => ({
                validator: (_, value) =>
                  value === getFieldValue('password')
                    ? Promise.resolve()
                    : Promise.reject(new Error('两次输入的密码不一致')),
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="timezone"
            label="时区"
            rules={[{ required: true, message: '请选择时区' }]}
          >
            <Select
              showSearch
              options={TIMEZONES.map((tz) => ({ value: tz, label: tz }))}
            />
          </Form.Item>
          {setup.error instanceof ApiError ? (
            <Alert
              type="error"
              showIcon
              style={{ marginBottom: 16 }}
              message={`初始化失败：${setup.error.message}`}
              description={`错误码：${setup.error.code}`}
            />
          ) : null}
                <Button
                  type="primary"
                  htmlType="submit"
                  block
                  loading={setup.isPending}
                >
                  完成初始化
                </Button>
              </Form>
            </Card>
          )
        }
      </QueryState>
    </div>
  )
}
