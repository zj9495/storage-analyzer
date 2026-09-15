import { useState } from 'react'
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Descriptions, Form, Input, Modal, Select, Space, Table, Tag } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { api, createIdempotencyKey } from '../../api/client'
import type { CleanupAction, CleanupActionRequestResult, CleanupPlan, CleanupPlanRequest, DuplicateGroup, DuplicateGroupDetail, QuarantineItem, ReauthResponse, ReportSummary } from '../../api/types'
import { MutationError } from '../../components/MutationError'
import { PageHeader } from '../../components/PageHeader'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'
import { formatBytes } from '../../lib/format'

export interface CleanupGroupForm { group_id: string; keep_entry_ids: string[]; target_entry_ids: string[] }
export interface CleanupForm { report_id: string; groups: CleanupGroupForm[] }
interface ExecuteForm { password: string; confirmation: string }
interface RestoreForm { password: string; new_name?: string }
interface PurgeForm { password: string; confirmation: string }

// eslint-disable-next-line react-refresh/only-export-components
export function cleanupPlanPayload(values: CleanupForm): CleanupPlanRequest {
  return { report_id: values.report_id, groups: values.groups.map((group) => ({ group_id: group.group_id, keep_entry_ids: group.keep_entry_ids, target_entry_ids: group.target_entry_ids })) }
}

// eslint-disable-next-line react-refresh/only-export-components
export function cleanupQuarantineQuery(cursor: string | null) {
  return { cursor: cursor ?? undefined, page_size: 50 }
}

// eslint-disable-next-line react-refresh/only-export-components
export function cleanupActionQuery(cursor: string | null) {
  return { cursor: cursor ?? undefined, page_size: 50 }
}

export function CleanupPage() {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [planOpen, setPlanOpen] = useState(false)
  const [executeOpen, setExecuteOpen] = useState(false)
  const [restoreItem, setRestoreItem] = useState<QuarantineItem>()
  const [purgeItem, setPurgeItem] = useState<QuarantineItem>()
  const [createdPlan, setCreatedPlan] = useState<CleanupPlan>()
  const [actionId, setActionId] = useState<string>()
  const [planForm] = Form.useForm<CleanupForm>()
  const [executeForm] = Form.useForm<ExecuteForm>()
  const [restoreForm] = Form.useForm<RestoreForm>()
  const [purgeForm] = Form.useForm<PurgeForm>()
  const reportId = Form.useWatch('report_id', planForm)
  const groupValues = Form.useWatch('groups', planForm)
  const actionCursor = searchParams.get('action_cursor')
  const reports = useQuery({
    queryKey: ['reports', 'cleanup-source'],
    queryFn: ({ signal }) => api.getPage<ReportSummary>('/api/v1/reports', { signal, query: { page_size: 200 } }),
  })
  const duplicateGroups = useQuery({
    queryKey: ['reports', reportId, 'duplicates', 'cleanup-source'],
    enabled: reportId !== undefined,
    queryFn: ({ signal }) => api.getPage<DuplicateGroup>(`/api/v1/reports/${encodeURIComponent(reportId as string)}/duplicates`, { signal, query: { page_size: 200 } }),
  })
  const duplicateDetails = useQueries({
    queries: groupValues === undefined ? [] : groupValues.map((group) => ({
      queryKey: ['reports', reportId, 'duplicates', group.group_id, 'cleanup-source'],
      enabled: reportId !== undefined && group.group_id.length > 0,
      queryFn: async ({ signal }: { signal: AbortSignal }) => (await api.get<DuplicateGroupDetail>(`/api/v1/reports/${encodeURIComponent(reportId as string)}/duplicates/${encodeURIComponent(group.group_id)}`, { signal })).data,
    })),
  })
  const quarantineCursor = searchParams.get('quarantine_cursor')
  const quarantine = useQuery({
    queryKey: ['cleanup', 'quarantine', { cursor: quarantineCursor }],
    queryFn: ({ signal }) => api.getPage<QuarantineItem>('/api/v1/cleanup/quarantine', { signal, query: cleanupQuarantineQuery(quarantineCursor) }),
  })
  const action = useQuery({
    queryKey: ['cleanup', 'actions', actionId, { cursor: actionCursor }],
    enabled: actionId !== undefined,
    queryFn: ({ signal }) => api.getObjectPage<CleanupAction>(`/api/v1/cleanup/actions/${encodeURIComponent(actionId as string)}`, { signal, query: cleanupActionQuery(actionCursor) }),
    refetchInterval: (query) => query.state.data?.data.state === 'running' ? 2_000 : false,
  })
  const createPlan = useMutation({
    mutationFn: (values: CleanupForm) => api.post<CleanupPlan>('/api/v1/cleanup/plans', cleanupPlanPayload(values)),
    onSuccess: (response) => { setCreatedPlan(response.data); setPlanOpen(false) },
  })
  const execute = useMutation({
    mutationFn: async (values: ExecuteForm) => {
      const reauth = await api.post<ReauthResponse>('/api/v1/auth/reauth', { password: values.password })
      return api.post<CleanupActionRequestResult>(`/api/v1/cleanup/plans/${encodeURIComponent(createdPlan?.id as string)}/execute`, { reauth_token: reauth.data.reauth_token, confirmation: values.confirmation }, { headers: { 'Idempotency-Key': createIdempotencyKey() } })
    },
    onSuccess: (response) => { setActionId(response.data.action_id); const next = new URLSearchParams(searchParams); next.delete('action_cursor'); setSearchParams(next); setExecuteOpen(false); void queryClient.invalidateQueries({ queryKey: ['cleanup', 'quarantine'] }) },
  })
  const restore = useMutation({
    mutationFn: async ({ item, values }: { item: QuarantineItem; values: RestoreForm }) => {
      const reauth = await api.post<ReauthResponse>('/api/v1/auth/reauth', { password: values.password })
      return api.post<{ job_id: string }>(`/api/v1/cleanup/quarantine/${encodeURIComponent(item.id)}/restore`, { reauth_token: reauth.data.reauth_token, new_name: values.new_name }, { headers: { 'Idempotency-Key': createIdempotencyKey() } })
    },
    onSuccess: () => { setRestoreItem(undefined); void queryClient.invalidateQueries({ queryKey: ['cleanup', 'quarantine'] }) },
  })
  const purge = useMutation({
    mutationFn: async (values: PurgeForm) => {
      const reauth = await api.post<ReauthResponse>('/api/v1/auth/reauth', { password: values.password })
      return api.post(`/api/v1/cleanup/quarantine/${encodeURIComponent(purgeItem?.id as string)}/purge`, { reauth_token: reauth.data.reauth_token, confirmation: values.confirmation }, { headers: { 'Idempotency-Key': createIdempotencyKey() } })
    },
    onSuccess: () => { setPurgeItem(undefined); void queryClient.invalidateQueries({ queryKey: ['cleanup', 'quarantine'] }) },
  })

  return <div>
    <PageHeader title="清理中心" description="清理预览、隔离、恢复与永久清理" extra={<Button type="primary" onClick={() => setPlanOpen(true)}>创建清理预览</Button>} />
    <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="隔离不是释放空间" description="预览和执行只提交报告中的 entry ID；执行与永久清理都要求近期重新认证和确认文本。" />
    <MutationError error={createPlan.error} /><MutationError error={execute.error} /><MutationError error={restore.error} /><MutationError error={purge.error} />
    {createdPlan ? <Card title="当前清理预览" style={{ marginBottom: 16 }} extra={<Button danger disabled={createdPlan.state !== 'preview'} onClick={() => setExecuteOpen(true)}>执行隔离</Button>}><Descriptions bordered column={2}><Descriptions.Item label="计划 ID">{createdPlan.id}</Descriptions.Item><Descriptions.Item label="状态"><Tag>{createdPlan.state}</Tag></Descriptions.Item><Descriptions.Item label="选中条目">{createdPlan.selected_count}</Descriptions.Item><Descriptions.Item label="逻辑容量">{formatBytes(createdPlan.logical_total_bytes)}</Descriptions.Item><Descriptions.Item label="确认文本">{createdPlan.confirmation_text}</Descriptions.Item><Descriptions.Item label="有效期">{createdPlan.expires_at}</Descriptions.Item></Descriptions>{createdPlan.blocked_entries?.length ? <Table rowKey="entry_id" style={{ marginTop: 16 }} dataSource={createdPlan.blocked_entries} pagination={false} columns={[{ title: '阻断条目', dataIndex: 'entry_id' }, { title: '原因', dataIndex: 'reason' }]} /> : null}</Card> : null}
    {action.data ? <Card title="清理动作" style={{ marginBottom: 16 }}><Descriptions bordered column={2}><Descriptions.Item label="动作 ID">{action.data.data.id}</Descriptions.Item><Descriptions.Item label="状态"><Tag>{action.data.data.state}</Tag></Descriptions.Item><Descriptions.Item label="任务 ID">{action.data.data.job_id}</Descriptions.Item></Descriptions><Table rowKey="id" dataSource={action.data.data.items} pagination={false} style={{ marginTop: 16 }} columns={[{ title: '条目 ID', dataIndex: 'entry_id' }, { title: '状态', dataIndex: 'state' }, { title: '原路径', dataIndex: 'original_display_path', ellipsis: true }, { title: '错误', dataIndex: 'error' }]} /><PagePagination meta={action.data.meta} loading={action.isFetching} onNext={(nextCursor) => { const next = new URLSearchParams(searchParams); next.set('action_cursor', nextCursor); setSearchParams(next) }} /></Card> : null}
    <QueryState query={quarantine}>{(page) => <Card title="隔离区"><Table<QuarantineItem> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '隔离区为空' }} columns={[{ title: '原路径', dataIndex: 'original_display_path', ellipsis: true }, { title: '状态', dataIndex: 'state', render: (state) => <Tag>{state}</Tag> }, { title: '大小', dataIndex: 'size_bytes', render: (value: string | undefined) => value === undefined ? undefined : formatBytes(value) }, { title: '隔离时间', dataIndex: 'quarantined_at' }, { title: '空间已释放', render: () => '否' }, { title: '操作', render: (_, item) => <Space><Button size="small" onClick={() => setRestoreItem(item)}>恢复</Button><Button danger size="small" onClick={() => setPurgeItem(item)}>永久删除</Button></Space> }]} /><PagePagination meta={page.meta} loading={quarantine.isFetching} onNext={(nextCursor) => { const next = new URLSearchParams(searchParams); next.set('quarantine_cursor', nextCursor); setSearchParams(next) }} /></Card>}</QueryState>
    <Modal title="创建清理预览" open={planOpen} onCancel={() => setPlanOpen(false)} onOk={() => planForm.submit()} confirmLoading={createPlan.isPending} destroyOnClose>
      <Form<CleanupForm> form={planForm} layout="vertical" onFinish={(values) => createPlan.mutate(values)}>
        <Form.Item name="report_id" label="报告" rules={[{ required: true }]}><Select allowClear loading={reports.isPending} onChange={() => { planForm.setFieldsValue({ groups: [] }) }} options={reports.data?.data.map((report) => ({ value: report.id, label: `${report.id}（${report.status}）` }))} /></Form.Item>
        <Form.List name="groups">
          {(fields, { add, remove }) => <>
            {fields.map((field, index) => {
              const selectedGroup = groupValues?.[index]
              const detail = duplicateDetails[index]?.data
              const detailPending = duplicateDetails[index]?.isPending ?? false
              const memberOptions = detail?.members.map((member) => ({ value: member.entry_id, label: `${member.entry_id}：${member.display_path}` }))
              return <Card key={field.key} size="small" title={`重复组 ${index + 1}`} extra={<Button type="link" danger onClick={() => remove(field.name)}>移除</Button>} style={{ marginBottom: 12 }}>
                <Form.Item name={[field.name, 'group_id']} label="重复组" rules={[{ required: true }]}><Select<string> allowClear loading={duplicateGroups.isPending} disabled={reportId === undefined} onChange={() => { const groups = planForm.getFieldValue('groups') as CleanupGroupForm[] | undefined; planForm.setFieldsValue({ groups: groups?.map((group, groupIndex) => groupIndex === field.name ? { ...group, keep_entry_ids: [], target_entry_ids: [] } : group) }) }} options={duplicateGroups.data?.data.map((group) => ({ value: group.group_id, label: `${group.group_id}：${group.member_count} 个成员` }))} /></Form.Item>
                <Form.Item name={[field.name, 'keep_entry_ids']} label="保留 entry_id" rules={[{ required: true, type: 'array', min: 1, message: '至少选择一个保留条目' }]}><Select mode="multiple" disabled={selectedGroup?.group_id === undefined || selectedGroup.group_id.length === 0 || detailPending} loading={detailPending} options={memberOptions} /></Form.Item>
                <Form.Item name={[field.name, 'target_entry_ids']} label="隔离 entry_id" rules={[{ required: true, type: 'array', min: 1, message: '至少选择一个隔离条目' }]}><Select mode="multiple" disabled={selectedGroup?.group_id === undefined || selectedGroup.group_id.length === 0 || detailPending} loading={detailPending} options={memberOptions} /></Form.Item>
              </Card>
            })}
            <Button type="dashed" block onClick={() => add({ group_id: '', keep_entry_ids: [], target_entry_ids: [] })}>添加重复组</Button>
          </>}
        </Form.List>
      </Form>
    </Modal>
    <Modal title="执行隔离" open={executeOpen} onCancel={() => setExecuteOpen(false)} onOk={() => executeForm.submit()} confirmLoading={execute.isPending} destroyOnClose><Form<ExecuteForm> form={executeForm} layout="vertical" onFinish={(values) => execute.mutate(values)}><Form.Item name="password" label="当前管理员密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item><Form.Item name="confirmation" label="确认文本" extra={createdPlan?.confirmation_text} rules={[{ required: true }]}><Input /></Form.Item></Form></Modal>
    <Modal title="恢复隔离项" open={restoreItem !== undefined} onCancel={() => setRestoreItem(undefined)} onOk={() => restoreForm.submit()} confirmLoading={restore.isPending} destroyOnClose><Form<RestoreForm> form={restoreForm} layout="vertical" onFinish={(values) => { if (restoreItem) restore.mutate({ item: restoreItem, values }) }}><Form.Item name="password" label="当前管理员密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item><Form.Item name="new_name" label="冲突时的新名称（可选）"><Input /></Form.Item></Form></Modal>
    <Modal title="永久删除隔离项" open={purgeItem !== undefined} onCancel={() => setPurgeItem(undefined)} onOk={() => purgeForm.submit()} confirmLoading={purge.isPending} destroyOnClose><Alert type="error" showIcon message="永久删除不可撤销" style={{ marginBottom: 16 }} /><Form<PurgeForm> form={purgeForm} layout="vertical" onFinish={(values) => purge.mutate(values)}><Form.Item name="password" label="当前管理员密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item><Form.Item name="confirmation" label="确认文本" rules={[{ required: true }]}><Input /></Form.Item></Form></Modal>
  </div>
}
