import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag } from 'antd'
import { api, createIdempotencyKey } from '../../api/client'
import { useSearchParams } from 'react-router-dom'
import type { Profile, ProfileConfig, Source } from '../../api/types'
import { MutationError } from '../../components/MutationError'
import { PageHeader } from '../../components/PageHeader'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'

const SECTION_OPTIONS: Array<{ value: ProfileConfig['sections'][number]; label: string }> = [
  { value: 'volume', label: '容量' }, { value: 'folders', label: '目录' }, { value: 'owners', label: '用户' }, { value: 'quota', label: '配额' }, { value: 'categories', label: '分类' }, { value: 'duplicates', label: '重复' }, { value: 'largest', label: '最大文件' }, { value: 'recently_modified', label: '最近修改' }, { value: 'least_accessed', label: '最少访问' },
]

export interface ProfileForm {
  name: string
  description?: string | null
  enabled: boolean
  scope_mode: ProfileConfig['scope']['mode']
  source_ids?: string[]
  include_future_registered: boolean
  include_globs?: string[]
  exclude_globs?: string[]
  file_kind_policy: ProfileConfig['scope']['file_kind_policy']
  sections: ProfileConfig['sections']
  owner_ids_to_list: string[]
  rank_limit: number
  duplicates_enabled: boolean
  duplicates_match_name: boolean
  duplicates_match_mtime: boolean
  duplicates_min_size_bytes: string
  duplicates_max_size_bytes?: string | null
  duplicates_max_listed_files: number
  duplicates_hash_budget_bytes?: string | null
  duplicates_content_read_policy: NonNullable<ProfileConfig['duplicates']>['content_read_policy']
  schedule_type: 'manual' | 'daily' | 'weekly' | 'monthly' | 'cron'
  schedule_time_of_day?: string
  schedule_days_of_week: number[]
  schedule_day_of_month?: number
  schedule_expression?: string
  schedule_timezone?: string
  misfire_policy: 'skip' | 'run_once'
  overlap_policy: 'skip' | 'coalesce_once'
  report_keep_count: number
  detail_keep_count: number
  notification_recipients: string[]
  notification_notify_on: NonNullable<ProfileConfig['notifications']>['notify_on']
  notification_attach_summary: boolean
  notification_public_base_url?: string | null
  metadata_workers?: number
  hash_workers?: number
  read_limit_mib_s?: number
  io_priority?: NonNullable<ProfileConfig['resources']>['io_priority']
}

// eslint-disable-next-line react-refresh/only-export-components
export async function listAllSources(signal: AbortSignal): Promise<Source[]> {
  const sources: Source[] = []
  let cursor: string | undefined
  while (true) {
    const page = await api.getPage<Source>('/api/v1/sources', {
      signal,
      query: { cursor, page_size: 200 },
    })
    sources.push(...page.data)
    if (page.meta.next_cursor === null) return sources
    cursor = page.meta.next_cursor
  }
}

function formFromProfile(profile: Profile): ProfileForm {
  const duplicates = profile.duplicates ?? {
    enabled: false,
    match_name: false,
    match_mtime: false,
    min_size_bytes: '1',
    max_size_bytes: null,
    max_listed_files: 5000,
    hash_budget_bytes: null,
    content_read_policy: 'respect_source_policy' as const,
  }
  const schedule = profile.schedule ?? {
    type: 'manual' as const,
    misfire_policy: 'skip' as const,
    overlap_policy: 'coalesce_once' as const,
  }
  const retention = profile.retention ?? { report_keep_count: 30, detail_keep_count: 3 }
  const notifications = profile.notifications ?? {
    recipients: [],
    notify_on: ['succeeded', 'partial', 'failed'] as const,
    attach_summary: false,
    public_base_url: null,
  }
  const resources = profile.resources ?? {}
  return {
    name: profile.name,
    description: profile.description,
    enabled: profile.enabled,
    scope_mode: profile.scope.mode,
    source_ids: profile.scope.source_ids,
    include_future_registered: profile.scope.include_future_registered,
    include_globs: profile.scope.include_globs,
    exclude_globs: profile.scope.exclude_globs,
    file_kind_policy: profile.scope.file_kind_policy,
    sections: profile.sections,
    owner_ids_to_list: (profile.owner_ids_to_list ?? []).map(String),
    rank_limit: profile.rank_limit,
    duplicates_enabled: duplicates.enabled,
    duplicates_match_name: duplicates.match_name,
    duplicates_match_mtime: duplicates.match_mtime,
    duplicates_min_size_bytes: duplicates.min_size_bytes,
    duplicates_max_size_bytes: duplicates.max_size_bytes,
    duplicates_max_listed_files: duplicates.max_listed_files,
    duplicates_hash_budget_bytes: duplicates.hash_budget_bytes,
    duplicates_content_read_policy: duplicates.content_read_policy,
    schedule_type: schedule.type,
    schedule_expression: schedule.expression,
    schedule_time_of_day: schedule.time_of_day,
    schedule_days_of_week: schedule.days_of_week ?? [],
    schedule_day_of_month: schedule.day_of_month,
    schedule_timezone: schedule.timezone,
    misfire_policy: schedule.misfire_policy,
    overlap_policy: schedule.overlap_policy,
    report_keep_count: retention.report_keep_count,
    detail_keep_count: retention.detail_keep_count,
    notification_recipients: notifications.recipients ?? [],
    notification_notify_on: notifications.notify_on ?? ['succeeded', 'partial', 'failed'],
    notification_attach_summary: notifications.attach_summary,
    notification_public_base_url: notifications.public_base_url,
    metadata_workers: resources.metadata_workers,
    hash_workers: resources.hash_workers,
    read_limit_mib_s: resources.read_limit_mib_s,
    io_priority: resources.io_priority,
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function profilePayload(values: ProfileForm): ProfileConfig {
  return {
    name: values.name,
    description: values.description,
    enabled: values.enabled,
    scope: { mode: values.scope_mode, source_ids: values.source_ids, include_future_registered: values.include_future_registered, include_globs: values.include_globs, exclude_globs: values.exclude_globs, file_kind_policy: values.file_kind_policy },
    sections: values.sections,
    owner_ids_to_list: values.owner_ids_to_list.map(Number),
    duplicates: { enabled: values.duplicates_enabled, match_name: values.duplicates_match_name, match_mtime: values.duplicates_match_mtime, min_size_bytes: values.duplicates_min_size_bytes, max_size_bytes: values.duplicates_max_size_bytes, max_listed_files: values.duplicates_max_listed_files, hash_budget_bytes: values.duplicates_hash_budget_bytes, content_read_policy: values.duplicates_content_read_policy },
    rank_limit: values.rank_limit,
    schedule: { type: values.schedule_type, expression: values.schedule_expression, time_of_day: values.schedule_time_of_day, days_of_week: values.schedule_days_of_week, day_of_month: values.schedule_day_of_month, timezone: values.schedule_timezone, misfire_policy: values.misfire_policy, overlap_policy: values.overlap_policy },
    retention: { report_keep_count: values.report_keep_count, detail_keep_count: values.detail_keep_count },
    notifications: { recipients: values.notification_recipients, notify_on: values.notification_notify_on, attach_summary: values.notification_attach_summary, public_base_url: values.notification_public_base_url },
    resources: { metadata_workers: values.metadata_workers, hash_workers: values.hash_workers, read_limit_mib_s: values.read_limit_mib_s, io_priority: values.io_priority },
  }
}

export function ProfilesPage() {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<Profile>()
  const [form] = Form.useForm<ProfileForm>()
  const [searchParams, setSearchParams] = useSearchParams()
  const cursor = searchParams.get('cursor') ?? undefined
  const profiles = useQuery({ queryKey: ['profiles', 'list', cursor], queryFn: ({ signal }) => api.getPage<Profile>('/api/v1/profiles', { signal, query: { cursor, page_size: 50 } }) })
  const sources = useQuery({ queryKey: ['sources', 'list', 'profile-form'], queryFn: ({ signal }) => listAllSources(signal) })
  const save = useMutation({
    mutationFn: (values: ProfileForm) => editing ? api.patch<Profile>(`/api/v1/profiles/${encodeURIComponent(editing.id)}`, profilePayload(values), { headers: { 'If-Match': String(editing.version) } }) : api.post<Profile>('/api/v1/profiles', profilePayload(values)),
    onSuccess: async () => { setOpen(false); setEditing(undefined); await queryClient.invalidateQueries({ queryKey: ['profiles'] }) },
  })
  const run = useMutation({ mutationFn: (id: string) => api.post<{ job_id: string; run_id: string }>(`/api/v1/profiles/${encodeURIComponent(id)}/run`, undefined, { headers: { 'Idempotency-Key': createIdempotencyKey() } }), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['jobs'] }) })
  const clone = useMutation({ mutationFn: ({ id, name }: { id: string; name: string }) => api.post<Profile>(`/api/v1/profiles/${encodeURIComponent(id)}/clone`, { name }), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['profiles'] }) })
  const remove = useMutation({ mutationFn: (id: string) => api.delete(`/api/v1/profiles/${encodeURIComponent(id)}`), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['profiles'] }) })
  const schedulePreview = useMutation({ mutationFn: (values: ProfileConfig['schedule']) => api.post<{ valid: boolean; next_runs: string[]; errors?: string[] }>('/api/v1/profiles/schedule-preview', values) })
  const openEditor = (profile?: Profile) => {
    setEditing(profile)
    form.resetFields()
    form.setFieldsValue(profile ? formFromProfile(profile) : {
      enabled: true,
      scope_mode: 'all',
      include_future_registered: false,
      file_kind_policy: 'regular_only',
      sections: ['volume', 'folders', 'categories'],
      owner_ids_to_list: [],
      rank_limit: 200,
      duplicates_enabled: false,
      duplicates_match_name: false,
      duplicates_match_mtime: false,
      duplicates_min_size_bytes: '1',
      duplicates_max_size_bytes: null,
      duplicates_max_listed_files: 5000,
      duplicates_hash_budget_bytes: null,
      duplicates_content_read_policy: 'respect_source_policy',
      schedule_type: 'manual',
      schedule_days_of_week: [],
      misfire_policy: 'skip',
      overlap_policy: 'coalesce_once',
      report_keep_count: 30,
      detail_keep_count: 3,
      notification_recipients: [],
      notification_notify_on: ['succeeded', 'partial', 'failed'],
      notification_attach_summary: false,
      notification_public_base_url: null,
      io_priority: 'normal',
    })
    setOpen(true)
  }

  return <div><PageHeader title="报告任务" description="扫描范围、栏目、调度与保留策略" extra={<Button type="primary" onClick={() => openEditor()}>新建报告任务</Button>} />
    <MutationError error={save.error} /><MutationError error={run.error} /><MutationError error={clone.error} /><MutationError error={remove.error} />
    {run.data ? <Alert type="success" showIcon message="报告任务已入队" description={`任务 ID：${run.data.data.job_id}，运行 ID：${run.data.data.run_id}`} style={{ marginBottom: 16 }} /> : null}
    <QueryState query={profiles}>{(page) => <><Table<Profile> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '尚未创建报告任务' }} columns={[{ title: '名称', dataIndex: 'name' }, { title: '版本', dataIndex: 'version' }, { title: '调度', render: (_, profile) => profile.schedule?.type }, { title: '启用', dataIndex: 'enabled', render: (value: boolean) => <Tag>{value ? '是' : '否'}</Tag> }, { title: '下次运行', dataIndex: 'next_run_at' }, { title: '操作', render: (_, profile) => <Space wrap><Button size="small" onClick={() => openEditor(profile)}>编辑</Button><Button size="small" onClick={() => { const name = window.prompt('请输入克隆后的任务名称', `${profile.name} 副本`); if (name !== null && name !== '') clone.mutate({ id: profile.id, name }) }}>复制</Button><Button size="small" loading={run.isPending && run.variables === profile.id} onClick={() => run.mutate(profile.id)}>立即运行</Button><Popconfirm title="停用此任务？已有报告会保留。" onConfirm={() => remove.mutate(profile.id)} okText="停用" cancelText="取消"><Button danger size="small" loading={remove.isPending && remove.variables === profile.id}>停用</Button></Popconfirm></Space> }]} /><PagePagination meta={page.meta} loading={profiles.isFetching} onNext={(nextCursor) => { const next = new URLSearchParams(searchParams); next.set('cursor', nextCursor); setSearchParams(next) }} /></>}</QueryState>
    <Modal title={editing ? '编辑报告任务' : '新建报告任务'} open={open} destroyOnClose onCancel={() => { setOpen(false); setEditing(undefined) }} onOk={() => form.submit()} confirmLoading={save.isPending} width={820}>
      <Form<ProfileForm> form={form} layout="vertical" onFinish={(values) => save.mutate(values)}>
        <Space align="start" wrap><Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item></Space>
        <Form.Item name="description" label="说明"><Input.TextArea rows={2} /></Form.Item>
        <Space align="start" wrap><Form.Item name="scope_mode" label="扫描范围" rules={[{ required: true }]}><Select options={[{ value: 'all', label: '全部已登记数据源' }, { value: 'selected', label: '选定数据源' }]} /></Form.Item><Form.Item name="file_kind_policy" label="文件类型"><Select options={[{ value: 'regular_only', label: '仅普通文件' }, { value: 'all_metadata', label: '全部元数据' }]} /></Form.Item><Form.Item name="include_future_registered" label="包含未来登记的数据源" valuePropName="checked"><Switch /></Form.Item></Space>
        <Form.Item name="source_ids" label="数据源"><Select mode="multiple" loading={sources.isPending} options={sources.data?.map((source) => ({ value: source.id, label: source.name }))} /></Form.Item>
        <Space direction="vertical" style={{ width: '100%' }}><Form.Item name="include_globs" label="包含规则"><Select mode="tags" tokenSeparators={[',']} options={[]} /></Form.Item><Form.Item name="exclude_globs" label="排除规则"><Select mode="tags" tokenSeparators={[',']} options={[]} /></Form.Item></Space>
        <Form.Item name="sections" label="报告栏目" rules={[{ required: true }]}><Select mode="multiple" options={SECTION_OPTIONS} /></Form.Item>
        <Space align="start" wrap><Form.Item name="owner_ids_to_list" label="附加 UID"><Select mode="tags" tokenSeparators={[',']} options={[]} /></Form.Item><Form.Item name="rank_limit" label="排行条数" rules={[{ required: true }]}><InputNumber min={1} max={10000} /></Form.Item></Space>
        <Space align="start" wrap><Form.Item name="duplicates_enabled" label="启用重复检测" valuePropName="checked"><Switch /></Form.Item><Form.Item name="duplicates_match_name" label="匹配名称" valuePropName="checked"><Switch /></Form.Item><Form.Item name="duplicates_match_mtime" label="匹配修改时间" valuePropName="checked"><Switch /></Form.Item></Space>
        <Space align="start" wrap><Form.Item name="duplicates_min_size_bytes" label="重复最小大小"><Input /></Form.Item><Form.Item name="duplicates_max_size_bytes" label="重复最大大小"><Input /></Form.Item><Form.Item name="duplicates_max_listed_files" label="重复列表上限"><InputNumber min={1} /></Form.Item><Form.Item name="duplicates_hash_budget_bytes" label="哈希读取预算"><Input /></Form.Item><Form.Item name="duplicates_content_read_policy" label="内容读取策略"><Select options={[{ value: 'respect_source_policy', label: '遵循数据源策略' }, { value: 'allow_remote_recall', label: '允许远程召回' }]} /></Form.Item></Space>
        <Space align="start" wrap><Form.Item name="schedule_type" label="调度类型"><Select options={[{ value: 'manual', label: '手动' }, { value: 'daily', label: '每天' }, { value: 'weekly', label: '每周' }, { value: 'monthly', label: '每月' }, { value: 'cron', label: 'Cron' }]} /></Form.Item><Form.Item name="schedule_expression" label="Cron 表达式"><Input placeholder="0 2 * * 0" /></Form.Item><Form.Item name="schedule_time_of_day" label="时间"><Input placeholder="02:00" /></Form.Item><Form.Item name="schedule_days_of_week" label="星期"><Select mode="multiple" options={[0,1,2,3,4,5,6].map(value => ({ value, label: String(value) }))} /></Form.Item><Form.Item name="schedule_day_of_month" label="每月日期"><InputNumber min={1} max={31} /></Form.Item><Form.Item name="schedule_timezone" label="时区"><Input placeholder="UTC" /></Form.Item><Button type="link" onClick={() => schedulePreview.mutate({ type: form.getFieldValue('schedule_type'), expression: form.getFieldValue('schedule_expression'), time_of_day: form.getFieldValue('schedule_time_of_day'), days_of_week: form.getFieldValue('schedule_days_of_week'), day_of_month: form.getFieldValue('schedule_day_of_month'), timezone: form.getFieldValue('schedule_timezone'), misfire_policy: form.getFieldValue('misfire_policy'), overlap_policy: form.getFieldValue('overlap_policy') })}>预览未来五次</Button></Space>
        {schedulePreview.error ? <MutationError error={schedulePreview.error} /> : null}{schedulePreview.data ? <Alert type={schedulePreview.data.data.valid ? 'success' : 'error'} showIcon message={schedulePreview.data.data.valid ? '调度表达式有效' : '调度表达式无效'} description={schedulePreview.data.data.valid ? schedulePreview.data.data.next_runs.join('；') : schedulePreview.data.data.errors?.join('；')} style={{ marginBottom: 16 }} /> : null}
        <Space align="start" wrap><Form.Item name="misfire_policy" label="错过调度"><Select options={[{ value: 'skip', label: '跳过' }, { value: 'run_once', label: '补跑一次' }]} /></Form.Item><Form.Item name="overlap_policy" label="重叠调度"><Select options={[{ value: 'skip', label: '跳过' }, { value: 'coalesce_once', label: '合并一次' }]} /></Form.Item><Form.Item name="report_keep_count" label="报告保留数"><InputNumber min={1} /></Form.Item><Form.Item name="detail_keep_count" label="明细保留数"><InputNumber min={1} /></Form.Item></Space>
        <Space align="start" wrap><Form.Item name="notification_recipients" label="通知收件人"><Select mode="tags" tokenSeparators={[',']} options={[]} /></Form.Item><Form.Item name="notification_notify_on" label="通知条件"><Select mode="multiple" options={[{ value: 'succeeded', label: '成功' }, { value: 'partial', label: '部分成功' }, { value: 'failed', label: '失败' }]} /></Form.Item><Form.Item name="notification_attach_summary" label="附加摘要" valuePropName="checked"><Switch /></Form.Item></Space>
        <Form.Item name="notification_public_base_url" label="报告链接基地址"><Input /></Form.Item>
        <Space align="start" wrap><Form.Item name="metadata_workers" label="元数据并发"><InputNumber min={1} /></Form.Item><Form.Item name="hash_workers" label="哈希并发"><InputNumber min={1} /></Form.Item><Form.Item name="read_limit_mib_s" label="读取速率上限 MiB/s"><InputNumber min={1} /></Form.Item><Form.Item name="io_priority" label="IO 优先级"><Select options={[{ value: 'low', label: '低' }, { value: 'normal', label: '普通' }]} /></Form.Item></Space>
      </Form>
    </Modal>
  </div>
}
