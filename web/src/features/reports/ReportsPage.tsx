import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
} from 'antd'
import { Link, useSearchParams } from 'react-router-dom'
import { api, createIdempotencyKey } from '../../api/client'
import type { CompareJobResponse, ExportJobResponse, ExportRecord, ExportRequest, Profile, QuerySpecContract, ReportSummary } from '../../api/types'
import { MutationError } from '../../components/MutationError'
import { PageHeader } from '../../components/PageHeader'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'
import { ComparisonResultPanel } from './ComparisonResultPanel'
import { formatBytes } from '../../lib/format'

interface CompareForm { other_report_id: string; mode: 'aggregate' | 'files' }
interface ExportForm { section: ExportRequest['section']; format: ExportRecord['format']; scope: 'all' }

// eslint-disable-next-line react-refresh/only-export-components
export const reportStatusLabels: Record<ReportSummary['status'], string> = { succeeded: '成功', partial: '部分成功', failed: '失败' }

export function ReportsPage() {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [compareOpen, setCompareOpen] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const [selectedReport, setSelectedReport] = useState<ReportSummary | null>(null)
  const [comparisonId, setComparisonId] = useState<string>()
  const [compareForm] = Form.useForm<CompareForm>()
  const [exportForm] = Form.useForm<ExportForm>()
  const [exportId, setExportId] = useState<string>()
  const cursor = searchParams.get('cursor')
  const profileId = searchParams.get('profile_id') ?? undefined
  const status = searchParams.get('status') as ReportSummary['status'] | null

  const profiles = useQuery({
    queryKey: ['profiles', 'list', 'report-filter'],
    queryFn: ({ signal }) => api.getPage<Profile>('/api/v1/profiles', { signal, query: { page_size: 200 } }),
  })
  const reports = useQuery({
    queryKey: ['reports', 'list', { cursor, profileId, status }],
    queryFn: ({ signal }) => api.getPage<ReportSummary>('/api/v1/reports', { signal, query: { cursor, profile_id: profileId, status: status ?? undefined, page_size: 50 } }),
  })
  const pin = useMutation({
    mutationFn: ({ id, report, detail }: { id: string; report: boolean; detail: boolean }) => api.post<ReportSummary>(`/api/v1/reports/${encodeURIComponent(id)}/pin`, { report_pinned: report, detail_pinned: detail }),
    onSuccess: () => { setSelectedReport(null); void queryClient.invalidateQueries({ queryKey: ['reports', 'list'] }) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/reports/${encodeURIComponent(id)}`),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['reports', 'list'] }),
  })
  const compare = useMutation({
    mutationFn: (values: CompareForm) => api.post<CompareJobResponse>(`/api/v1/reports/${encodeURIComponent(selectedReport?.id as string)}/compare`, values, { headers: { 'Idempotency-Key': createIdempotencyKey() } }),
    onSuccess: (response) => { setCompareOpen(false); setComparisonId(response.data.comparison_id) },
  })
  const createExport = useMutation({
    mutationFn: (values: ExportForm) => api.post<ExportJobResponse>(`/api/v1/reports/${encodeURIComponent(selectedReport?.id as string)}/exports`, { ...values, query: { include_descendants: true } satisfies QuerySpecContract }, { headers: { 'Idempotency-Key': createIdempotencyKey() } }),
    onSuccess: (response) => { setExportOpen(false); setExportId(response.data.export_id) },
  })
  const exportStatus = useQuery({
    queryKey: ['exports', exportId],
    enabled: exportId !== undefined,
    queryFn: async ({ signal }) => (await api.get<ExportRecord>(`/api/v1/exports/${encodeURIComponent(exportId as string)}`, { signal })).data,
    refetchInterval: (query) => query.state.data?.state === 'ready' || query.state.data?.state === 'failed' || query.state.data?.state === 'expired' ? false : 2_000,
  })
  const download = useMutation({
    mutationFn: (id: string) => api.download(`/api/v1/exports/${encodeURIComponent(id)}/download`),
    onSuccess: (result) => {
      const url = URL.createObjectURL(result.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      if (result.filename !== null) anchor.download = result.filename
      anchor.click()
      URL.revokeObjectURL(url)
    },
  })

  const setFilter = (key: string, value: string | undefined) => {
    const next = new URLSearchParams(searchParams)
    next.delete('cursor')
    if (value) next.set(key, value)
    else next.delete(key)
    setSearchParams(next)
  }

  return <div>
    <PageHeader title="报告中心" description="历史报告、时间轴、完整性与版本" extra={<Space wrap>
      <Select allowClear placeholder="按任务筛选" style={{ width: 220 }} value={profileId} loading={profiles.isPending} onChange={(value: string | undefined) => setFilter('profile_id', value)} options={profiles.data?.data.map((profile) => ({ value: profile.id, label: profile.name }))} />
      <Select allowClear placeholder="按状态筛选" style={{ width: 140 }} value={status ?? undefined} onChange={(value: ReportSummary['status'] | undefined) => setFilter('status', value)} options={Object.entries(reportStatusLabels).map(([value, label]) => ({ value, label }))} />
      <Button onClick={() => void reports.refetch()} loading={reports.isFetching}>刷新</Button>
    </Space>} />
    <MutationError error={remove.error} />
    <MutationError error={compare.error} />
    <MutationError error={createExport.error} />
    <MutationError error={download.error} />
    <MutationError error={exportStatus.error} />
    {exportStatus.data ? <Alert type={exportStatus.data.state === 'failed' || exportStatus.data.state === 'expired' ? 'error' : 'info'} showIcon style={{ marginBottom: 16 }} message={`导出 ${exportStatus.data.state}`} description={exportStatus.data.state === 'ready' ? <Button type="link" onClick={() => download.mutate(exportStatus.data.id)} loading={download.isPending}>下载导出文件</Button> : exportStatus.data.job_id ? `导出任务：${exportStatus.data.job_id}` : undefined} /> : null}
    <QueryState query={reports}>{(page) => <>
      <Table<ReportSummary> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '尚未生成任何报告' }} columns={[
        { title: '报告', dataIndex: 'id', render: (id: string) => <Link to={`/reports/${id}`}>{id}</Link> },
        { title: '任务 ID', dataIndex: 'profile_id' },
        { title: '版本', dataIndex: 'profile_version' },
        { title: '状态', dataIndex: 'status', render: (value: ReportSummary['status']) => <Tag>{reportStatusLabels[value]}</Tag> },
        { title: '文件数', render: (_, report) => report.totals?.file_count },
        { title: '逻辑容量', render: (_, report) => report.totals?.logical_bytes === undefined ? undefined : formatBytes(report.totals.logical_bytes) },
        { title: '生成时间', dataIndex: 'created_at' },
        { title: '明细', dataIndex: 'detail_available', render: (available: boolean) => <Tag>{available ? '可用' : '已过期'}</Tag> },
        { title: '操作', render: (_, report) => <Space wrap>
          <Button size="small" onClick={() => { setSelectedReport(report); setCompareOpen(true) }}>比较</Button>
          <Button size="small" onClick={() => { setSelectedReport(report); setExportOpen(true) }}>导出</Button>
          <Button size="small" onClick={() => { setSelectedReport(report); pin.mutate({ id: report.id, report: !report.pinned, detail: report.detail_pinned }) }} loading={pin.isPending && selectedReport?.id === report.id}>{report.pinned ? '取消固定' : '固定报告'}</Button>
          <Popconfirm title="删除报告及其受控生成物？" onConfirm={() => remove.mutate(report.id)} okText="删除" cancelText="取消"><Button danger size="small" loading={remove.isPending && remove.variables === report.id}>删除</Button></Popconfirm>
        </Space> },
      ]} />
      <PagePagination meta={page.meta} loading={reports.isFetching} onNext={(nextCursor) => { const next = new URLSearchParams(searchParams); next.set('cursor', nextCursor); setSearchParams(next) }} />
    </>}</QueryState>
    <Modal title="比较报告" open={compareOpen} onCancel={() => setCompareOpen(false)} onOk={() => compareForm.submit()} confirmLoading={compare.isPending} destroyOnClose>
      <MutationError error={compare.error} />
      <Form<CompareForm> form={compareForm} layout="vertical" onFinish={(values) => compare.mutate(values)}><Form.Item name="other_report_id" label="另一份报告 ID" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="mode" label="比较模式" initialValue="aggregate" rules={[{ required: true }]}><Select options={[{ value: 'aggregate', label: '目录/用户/分类聚合' }, { value: 'files', label: '文件差异（需要明细）' }]} /></Form.Item></Form>
    </Modal>
    <Modal title="创建导出" open={exportOpen} onCancel={() => setExportOpen(false)} onOk={() => exportForm.submit()} confirmLoading={createExport.isPending} destroyOnClose>
      <Form<ExportForm> form={exportForm} layout="vertical" onFinish={(values) => createExport.mutate(values)} initialValues={{ section: 'full_report', format: 'zip', scope: 'all' }}><Form.Item name="section" label="栏目" rules={[{ required: true }]}><Select options={['full_report', 'volume', 'folders', 'owners', 'quota', 'categories', 'duplicates', 'largest', 'recently_modified', 'least_accessed', 'files'].map((value) => ({ value, label: value }))} /></Form.Item><Form.Item name="format" label="格式" rules={[{ required: true }]}><Select options={['csv', 'json', 'html', 'zip'].map((value) => ({ value, label: value }))} /></Form.Item><Form.Item name="scope" label="范围" rules={[{ required: true }]}><Select options={[{ value: 'all', label: '整个栏目' }]} /></Form.Item></Form>
    </Modal>
    {comparisonId ? <ComparisonResultPanel comparisonId={comparisonId} onClose={() => setComparisonId(undefined)} /> : null}
  </div>
}
