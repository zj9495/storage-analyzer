import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Descriptions, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag } from 'antd'
import { api, createIdempotencyKey } from '../../api/client'
import type { AdminUser, BackupRequest, CategoryRuleset, CategoryRulesetInput, ImportPreview, InternalNotification, MetadataImportPayload, NotificationConfig, NotificationConfigInput, ReauthResponse, RestoreApplyRequest, RestorePreview, RestorePreviewRequest, RetentionSettings, RetentionSettingsInput, StorageSettings, StorageSettingsInput } from '../../api/types'
import { MutationError } from '../../components/MutationError'
import { PageHeader } from '../../components/PageHeader'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'
import { formatBytes } from '../../lib/format'

interface NotificationForm { enabled: boolean; smtp_host: string; smtp_port: number; tls_mode: NotificationConfig['tls_mode']; username?: string | null; password?: string; from_address: string; default_recipients?: string; subject_prefix: string; public_base_url?: string | null }
export interface AdminUpdateForm { enabled: boolean; password?: string }
export interface SecretBackupForm { secrets_passphrase: string }
export interface RestoreApplyForm { preview_id: string; password: string; confirmation: string; secrets_passphrase?: string }
function rulesJson(data: CategoryRuleset) { return JSON.stringify(data.rules, null, 2) }

const INTERNAL_NOTIFICATION_SEVERITY_LABELS: Record<InternalNotification['severity'], string> = {
  info: '提示',
  warning: '警告',
  error: '错误',
}

const INTERNAL_NOTIFICATION_SEVERITY_COLORS: Record<InternalNotification['severity'], string> = {
  info: 'blue',
  warning: 'orange',
  error: 'red',
}

export function internalNotificationSeverityLabel(severity: InternalNotification['severity']): string {
  return INTERNAL_NOTIFICATION_SEVERITY_LABELS[severity]
}

type BackupPayloadInput =
  | { include_secrets: false }
  | { include_secrets: true; secrets_passphrase: string }

export function backupPayload(values: BackupPayloadInput): BackupRequest {
  return values.include_secrets
    ? { include_secrets: true, secrets_passphrase: values.secrets_passphrase }
    : { include_secrets: false }
}

export function restorePreviewPayload(values: RestorePreviewRequest): RestorePreviewRequest {
  const payload: RestorePreviewRequest = { backup_export_id: values.backup_export_id }
  if (values.secrets_passphrase !== undefined && values.secrets_passphrase.length > 0) payload.secrets_passphrase = values.secrets_passphrase
  return payload
}

export function restoreApplyPayload(values: RestoreApplyForm, reauthToken: string): RestoreApplyRequest {
  const payload: RestoreApplyRequest = {
    preview_id: values.preview_id,
    reauth_token: reauthToken,
    confirmation: values.confirmation,
  }
  if (values.secrets_passphrase !== undefined && values.secrets_passphrase.length > 0) payload.secrets_passphrase = values.secrets_passphrase
  return payload
}

export function adminUpdatePayload(values: AdminUpdateForm): { enabled: boolean; password?: string } {
  const payload: { enabled: boolean; password?: string } = { enabled: values.enabled }
  if (values.password !== undefined && values.password.length > 0) payload.password = values.password
  return payload
}

export function InternalNotificationsSection() {
  const [cursor, setCursor] = useState<string>()
  const query = useQuery({
    queryKey: ['settings', 'internal-notifications', cursor],
    queryFn: ({ signal }) => api.getPage<InternalNotification>('/api/v1/notifications', { signal, query: { cursor, page_size: 20 } }),
  })

  return <QueryState query={query}>{(page) => <Card title="内部通知" style={{ marginBottom: 16 }}><Table<InternalNotification> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '暂无内部通知' }} columns={[{ title: '级别', dataIndex: 'severity', render: (value: InternalNotification['severity']) => <Tag color={INTERNAL_NOTIFICATION_SEVERITY_COLORS[value]}>{internalNotificationSeverityLabel(value)}</Tag> }, { title: '标题', dataIndex: 'title' }, { title: '内容', dataIndex: 'body' }, { title: '类型', dataIndex: 'kind' }, { title: '创建时间', dataIndex: 'created_at' }, { title: '读取状态', dataIndex: 'read_at', render: (value: InternalNotification['read_at']) => value === null ? <Tag>未读</Tag> : <Tag color="green">已读</Tag> }]} /><PagePagination meta={page.meta} loading={query.isFetching} onNext={setCursor} /></Card>}</QueryState>
}

export function SettingsPage() {
  const queryClient = useQueryClient()
  const [categoryOpen, setCategoryOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [backupOpen, setBackupOpen] = useState(false)
  const [adminOpen, setAdminOpen] = useState(false)
  const [adminEditOpen, setAdminEditOpen] = useState(false)
  const [editingAdmin, setEditingAdmin] = useState<AdminUser>()
  const [adminCursor, setAdminCursor] = useState<string>()
  const [categoryText, setCategoryText] = useState('')
  const [importText, setImportText] = useState('')
  const [importConfirmation, setImportConfirmation] = useState('')
  const [restorePreview, setRestorePreview] = useState<RestorePreview>()
  const [categoryForm] = Form.useForm<{ rules: string }>()
  const [notificationForm] = Form.useForm<NotificationForm>()
  const [adminForm] = Form.useForm<{ username: string; password: string }>()
  const [adminEditForm] = Form.useForm<AdminUpdateForm>()
  const [backupForm] = Form.useForm<SecretBackupForm>()
  const categories = useQuery({ queryKey: ['settings', 'categories'], queryFn: async ({ signal }) => (await api.get<CategoryRuleset>('/api/v1/settings/categories', { signal })).data })
  const notifications = useQuery({ queryKey: ['settings', 'notifications'], queryFn: async ({ signal }) => (await api.get<NotificationConfig>('/api/v1/settings/notifications', { signal })).data })
  const storage = useQuery({ queryKey: ['settings', 'storage'], queryFn: async ({ signal }) => (await api.get<StorageSettings>('/api/v1/settings/storage', { signal })).data })
  const retention = useQuery({ queryKey: ['settings', 'retention'], queryFn: async ({ signal }) => (await api.get<RetentionSettings>('/api/v1/settings/retention', { signal })).data })
  const admins = useQuery({ queryKey: ['admins', adminCursor], queryFn: ({ signal }) => api.getPage<AdminUser>('/api/v1/admins', { signal, query: { cursor: adminCursor, page_size: 50 } }) })
  const saveCategories = useMutation({ mutationFn: (rules: string) => api.put<CategoryRuleset>('/api/v1/settings/categories', { rules: JSON.parse(rules) as CategoryRulesetInput['rules'] }), onSuccess: async () => { setCategoryOpen(false); await queryClient.invalidateQueries({ queryKey: ['settings', 'categories'] }) } })
  const saveNotifications = useMutation({ mutationFn: (values: NotificationForm) => { const payload: NotificationConfigInput = { enabled: values.enabled, smtp_host: values.smtp_host, smtp_port: values.smtp_port, tls_mode: values.tls_mode, username: values.username, password: values.password, from_address: values.from_address, default_recipients: values.default_recipients?.split(',').map((value) => value.trim()).filter((value) => value.length > 0), subject_prefix: values.subject_prefix, public_base_url: values.public_base_url }; return api.put<NotificationConfig>('/api/v1/settings/notifications', payload) }, onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['settings', 'notifications'] }) })
  const testNotification = useMutation({ mutationFn: (recipient: string | undefined) => api.post<{ delivered: boolean; detail: string }>('/api/v1/settings/notifications/test', recipient ? { recipient } : {}), onSuccess: () => undefined })
  const saveStorage = useMutation({ mutationFn: (values: StorageSettingsInput) => api.put<StorageSettings>('/api/v1/settings/storage', values), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['settings', 'storage'] }) })
  const saveRetention = useMutation({ mutationFn: (values: RetentionSettingsInput) => api.put<RetentionSettings>('/api/v1/settings/retention', values), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['settings', 'retention'] }) })
  const backup = useMutation({ mutationFn: (values: BackupRequest) => api.post<{ job_id: string; export_id?: string }>('/api/v1/settings/backup', values, { headers: { 'Idempotency-Key': createIdempotencyKey() } }), onSuccess: () => { setBackupOpen(false); backupForm.resetFields() } })
  const importPreview = useMutation({ mutationFn: (text: string) => api.post<ImportPreview>('/api/v1/metadata/import/preview', JSON.parse(text) as MetadataImportPayload) })
  const importApply = useMutation({ mutationFn: (values: { preview_id: string; digest: string; confirmation: string }) => api.post('/api/v1/metadata/import/apply', values) })
  const restore = useMutation({ mutationFn: (values: RestorePreviewRequest) => api.post<RestorePreview>('/api/v1/settings/restore/preview', values), onSuccess: (response) => setRestorePreview(response.data) })
  const restoreApply = useMutation({ mutationFn: async (values: RestoreApplyForm) => { const reauth = await api.post<ReauthResponse>('/api/v1/auth/reauth', { password: values.password }); return api.post('/api/v1/settings/restore/apply', restoreApplyPayload(values, reauth.data.reauth_token), { headers: { 'Idempotency-Key': createIdempotencyKey() } }) } })
  const createAdmin = useMutation({ mutationFn: (values: { username: string; password: string }) => api.post<AdminUser>('/api/v1/admins', values), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['admins'] }) })
  const updateAdmin = useMutation({ mutationFn: ({ admin, values }: { admin: AdminUser; values: AdminUpdateForm }) => api.patch<AdminUser>(`/api/v1/admins/${encodeURIComponent(admin.id)}`, adminUpdatePayload(values)), onSuccess: async () => { setAdminEditOpen(false); setEditingAdmin(undefined); await queryClient.invalidateQueries({ queryKey: ['admins'] }) } })
  const deleteAdmin = useMutation({ mutationFn: (id: string) => api.delete(`/api/v1/admins/${encodeURIComponent(id)}`), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['admins'] }) })

  return <div><PageHeader title="设置" description="分类、通知、存储预算、备份恢复与管理员" />
    <MutationError error={saveCategories.error} /><MutationError error={saveNotifications.error} /><MutationError error={testNotification.error} /><MutationError error={backup.error} /><MutationError error={importPreview.error} /><MutationError error={importApply.error} /><MutationError error={restore.error} /><MutationError error={restoreApply.error} /><MutationError error={createAdmin.error} /><MutationError error={updateAdmin.error} /><MutationError error={deleteAdmin.error} />
    {backup.data ? <Alert type="info" showIcon message={`备份任务已入队：${backup.data.data.job_id}`} description={backup.data.data.export_id ? `导出 ID：${backup.data.data.export_id}` : '请在任务中心查看任务状态。'} style={{ marginBottom: 16 }} /> : null}
    {testNotification.data ? <Alert type={testNotification.data.data.delivered ? 'success' : 'error'} showIcon message={testNotification.data.data.detail} style={{ marginBottom: 16 }} /> : null}
    <QueryState query={categories}>{(data) => <Card title={`分类规则集 v${data.version}`} style={{ marginBottom: 16 }} extra={<Button onClick={() => { setCategoryText(rulesJson(data)); categoryForm.setFieldsValue({ rules: rulesJson(data) }); setCategoryOpen(true) }}>编辑规则</Button>}><Space wrap>{Object.entries(data.rules).map(([category, extensions]) => <Tag key={category}>{category}：{extensions.length} 个扩展名</Tag>)}</Space><Descriptions size="small" column={1} style={{ marginTop: 16 }}><Descriptions.Item label="规则集 ID">{data.id}</Descriptions.Item><Descriptions.Item label="创建时间">{data.created_at}</Descriptions.Item></Descriptions></Card>}</QueryState>
    <QueryState query={notifications}>{(data) => <Card title="通知配置" style={{ marginBottom: 16 }}><Form<NotificationForm> form={notificationForm} layout="vertical" initialValues={{ ...data, default_recipients: data.default_recipients?.join(', ') }} onFinish={(values) => saveNotifications.mutate(values)}><Space align="start" wrap><Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item><Form.Item name="tls_mode" label="TLS 模式"><Select style={{ width: 140 }} options={['starttls', 'tls', 'none'].map((value) => ({ value, label: value }))} /></Form.Item><Form.Item name="smtp_port" label="SMTP 端口"><InputNumber min={1} max={65535} /></Form.Item></Space><Form.Item name="smtp_host" label="SMTP 主机"><Input /></Form.Item><Form.Item name="username" label="用户名"><Input /></Form.Item><Form.Item name="password" label="密码"><Input.Password placeholder="留空表示不修改" /></Form.Item><Form.Item name="from_address" label="发件地址"><Input /></Form.Item><Form.Item name="default_recipients" label="默认收件人（逗号分隔）"><Input /></Form.Item><Form.Item name="subject_prefix" label="主题前缀"><Input /></Form.Item><Form.Item name="public_base_url" label="报告链接基地址"><Input /></Form.Item><Space><Button type="primary" htmlType="submit" loading={saveNotifications.isPending}>保存通知配置</Button><Button onClick={() => testNotification.mutate(undefined)} loading={testNotification.isPending}>发送测试邮件</Button></Space></Form></Card>}</QueryState>
    <InternalNotificationsSection />
    <QueryState query={storage}>{(data) => <Card title="存储预算" style={{ marginBottom: 16 }}><Descriptions column={3} style={{ marginBottom: 16 }}><Descriptions.Item label="当前用量">{formatBytes(data.used_bytes)}</Descriptions.Item><Descriptions.Item label="部署上限">{data.deployment_max_budget_bytes === null || data.deployment_max_budget_bytes === undefined ? undefined : formatBytes(data.deployment_max_budget_bytes)}</Descriptions.Item></Descriptions><Form<StorageSettingsInput> layout="inline" initialValues={data} onFinish={(values) => saveStorage.mutate(values)}><Form.Item name="data_budget_bytes" label="数据预算（字节）" rules={[{ required: true }]}><Input /></Form.Item><Button type="primary" htmlType="submit" loading={saveStorage.isPending}>保存</Button></Form></Card>}</QueryState>
    <QueryState query={retention}>{(data) => <Card title="保留策略" style={{ marginBottom: 16 }}><Form<RetentionSettingsInput> layout="vertical" initialValues={data} onFinish={(values) => saveRetention.mutate(values)}><Space align="start" wrap><Form.Item name="default_report_keep_count" label="报告保留数量"><InputNumber min={1} /></Form.Item><Form.Item name="default_detail_keep_count" label="明细保留数量"><InputNumber min={1} /></Form.Item><Form.Item name={['quarantine_auto_purge', 'enabled']} label="自动永久清理" valuePropName="checked"><Switch /></Form.Item><Form.Item name={['quarantine_auto_purge', 'min_keep_days']} label="隔离最短保留天数"><InputNumber min={7} /></Form.Item></Space><Button type="primary" htmlType="submit" loading={saveRetention.isPending}>保存保留策略</Button></Form></Card>}</QueryState>
    <Card title="备份与恢复" style={{ marginBottom: 16 }}><Space wrap><Button onClick={() => backup.mutate(backupPayload({ include_secrets: false }))} loading={backup.isPending}>创建无秘密配置备份</Button><Button onClick={() => setBackupOpen(true)}>创建含秘密配置备份</Button><Button onClick={() => setRestoreOpen(true)}>恢复预览</Button><Button onClick={() => setImportOpen(true)}>导入身份/配额 JSON</Button></Space></Card>
    <QueryState query={admins}>{(page) => <Card title="管理员账户" extra={<Button onClick={() => setAdminOpen(true)}>新增管理员</Button>}><Table<AdminUser> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '暂无管理员' }} columns={[{ title: '用户名', dataIndex: 'username' }, { title: '启用', dataIndex: 'enabled', render: (value: boolean) => <Tag>{value ? '是' : '否'}</Tag> }, { title: '创建时间', dataIndex: 'created_at' }, { title: '操作', render: (_, admin) => <Space><Button size="small" onClick={() => { setEditingAdmin(admin); adminEditForm.resetFields(); adminEditForm.setFieldsValue({ enabled: admin.enabled }); setAdminEditOpen(true) }}>编辑</Button><Popconfirm title="删除管理员？" onConfirm={() => deleteAdmin.mutate(admin.id)} okText="删除" cancelText="取消"><Button danger size="small">删除</Button></Popconfirm></Space> }]} /><PagePagination meta={page.meta} loading={admins.isFetching} onNext={setAdminCursor} /></Card>}</QueryState>
    <Modal title="编辑分类规则" open={categoryOpen} onCancel={() => setCategoryOpen(false)} onOk={() => saveCategories.mutate(categoryText)} confirmLoading={saveCategories.isPending}><Input.TextArea rows={18} value={categoryText} onChange={(event) => setCategoryText(event.target.value)} /></Modal>
    <Modal title="元数据导入预览" open={importOpen} onCancel={() => setImportOpen(false)} footer={null}><Input.TextArea rows={14} value={importText} onChange={(event) => setImportText(event.target.value)} placeholder="粘贴符合 metadata-import.schema.json 的 JSON" /><Space style={{ marginTop: 16 }}><Button onClick={() => importPreview.mutate(importText)} loading={importPreview.isPending}>预览</Button>{importPreview.data ? <><Input value={importConfirmation} onChange={(event) => setImportConfirmation(event.target.value)} placeholder="输入服务端要求的确认文本" /><Button type="primary" onClick={() => importApply.mutate({ preview_id: importPreview.data.data.preview_id, digest: importPreview.data.data.digest, confirmation: importConfirmation })} loading={importApply.isPending}>应用预览</Button></> : null}</Space>{importPreview.data ? <Descriptions style={{ marginTop: 16 }} bordered column={1}><Descriptions.Item label="摘要">{importPreview.data.data.digest}</Descriptions.Item><Descriptions.Item label="有效">{importPreview.data.data.valid ? '是' : '否'}</Descriptions.Item><Descriptions.Item label="范围警告">{importPreview.data.data.scope_warnings?.join('；')}</Descriptions.Item></Descriptions> : null}</Modal>
    <Modal title="含秘密配置备份" open={backupOpen} onCancel={() => { setBackupOpen(false); backupForm.resetFields() }} onOk={() => backupForm.submit()} confirmLoading={backup.isPending} destroyOnClose><Form<SecretBackupForm> form={backupForm} layout="vertical" onFinish={(values) => backup.mutate(backupPayload({ include_secrets: true, secrets_passphrase: values.secrets_passphrase }))}><Form.Item name="secrets_passphrase" label="备份口令" rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item></Form></Modal>
    <Modal title="恢复配置预览" open={restoreOpen} onCancel={() => setRestoreOpen(false)} footer={null}><RestoreForm onPreview={(values) => restore.mutate(values)} loading={restore.isPending} preview={restorePreview} onApply={(values) => restoreApply.mutate(values)} applying={restoreApply.isPending} /></Modal>
    <Modal title="新建管理员" open={adminOpen} destroyOnClose onCancel={() => setAdminOpen(false)} onOk={() => adminForm.submit()} confirmLoading={createAdmin.isPending}><Form form={adminForm} layout="vertical" onFinish={(values: { username: string; password: string }) => { createAdmin.mutate(values); setAdminOpen(false) }}><Form.Item name="username" label="用户名" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="password" label="密码" rules={[{ required: true, min: 8 }]}><Input.Password /></Form.Item></Form></Modal>
    <Modal title="编辑管理员" open={adminEditOpen} destroyOnClose onCancel={() => { setAdminEditOpen(false); setEditingAdmin(undefined) }} onOk={() => adminEditForm.submit()} confirmLoading={updateAdmin.isPending}><Form<AdminUpdateForm> form={adminEditForm} layout="vertical" onFinish={(values) => { if (editingAdmin !== undefined) updateAdmin.mutate({ admin: editingAdmin, values }) }}><Form.Item label="用户名"><Input value={editingAdmin?.username} disabled /></Form.Item><Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item><Form.Item name="password" label="新密码" rules={[{ min: 8 }]}><Input.Password autoComplete="new-password" /></Form.Item></Form></Modal>
  </div>
}

function RestoreForm({ onPreview, loading, preview, onApply, applying }: { onPreview: (values: RestorePreviewRequest) => void; loading: boolean; preview?: RestorePreview; onApply: (values: RestoreApplyForm) => void; applying: boolean }) {
  const [form] = Form.useForm<{ backup_export_id: string; secrets_passphrase?: string; password: string; confirmation: string }>()
  return <Form form={form} layout="vertical" onFinish={(values) => onPreview(restorePreviewPayload({ backup_export_id: values.backup_export_id, secrets_passphrase: values.secrets_passphrase }))}><Form.Item name="backup_export_id" label="备份导出 ID" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="secrets_passphrase" label="备份口令"><Input.Password autoComplete="current-password" /></Form.Item><Button htmlType="submit" loading={loading}>预览恢复</Button>{preview ? <Card title="预览结果" style={{ marginTop: 16 }}><p>兼容：{preview.compatible ? '是' : '否'}</p><p>配置版本：{preview.config_version}</p><p>差异：{preview.differences?.map((item) => `${item.key}: ${item.change}`).join('；')}</p><Form.Item name="password" label="当前管理员密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item><Form.Item name="confirmation" label="确认文本" rules={[{ required: true }]}><Input /></Form.Item><Button type="primary" onClick={() => { const values = form.getFieldsValue(); onApply({ preview_id: preview.preview_id, password: values.password, confirmation: values.confirmation, secrets_passphrase: values.secrets_passphrase }) }} loading={applying}>应用恢复</Button></Card> : null}</Form>
}
