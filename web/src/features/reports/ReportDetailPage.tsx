import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Descriptions, Form, Input, Modal, Select, Space, Table, Tabs, Tag } from 'antd'
import { useParams, useSearchParams } from 'react-router-dom'
import { api, createIdempotencyKey } from '../../api/client'
import { ApiError } from '../../api/errors'
import type { CategoryRow, CompareJobResponse, DuplicateGroup, DuplicateGroupDetail, ExportJobResponse, ExportRecord, ExportRequest, FileRow, FolderRow, Metric, OwnerRow, Page, QuerySpecContract, RankingRow, ReportDetail } from '../../api/types'
import { PageHeader } from '../../components/PageHeader'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'
import { ComparisonResultPanel } from './ComparisonResultPanel'
import { formatBytes } from '../../lib/format'

const metrics: Array<{ value: Metric; label: string }> = [
  { value: 'logical_bytes', label: '逻辑容量' },
  { value: 'allocated_estimate_bytes', label: '已分配估算' },
  { value: 'file_count', label: '文件数' },
]

function apiError(error: unknown) {
  return error instanceof ApiError ? <Alert type="error" showIcon message={error.message} description={error.code} style={{ marginBottom: 16 }} /> : null
}

function byteCell(value: string | undefined) {
  return value === undefined ? undefined : formatBytes(value)
}

// eslint-disable-next-line react-refresh/only-export-components
export function reportExportSection(activeTab: string, rankingKind: 'largest' | 'recent' | 'least_accessed'): ExportRequest['section'] {
  if (activeTab === 'folders' || activeTab === 'owners' || activeTab === 'categories' || activeTab === 'files' || activeTab === 'duplicates') return activeTab
  if (activeTab === 'rankings') {
    if (rankingKind === 'recent') return 'recently_modified'
    if (rankingKind === 'least_accessed') return 'least_accessed'
    return 'largest'
  }
  return 'full_report'
}

// eslint-disable-next-line react-refresh/only-export-components
export function currentReportQuerySpec({ activeTab, metric, parentEntryId, nameContains, ownerUid, rankingKind }: { activeTab: string; metric: Metric; parentEntryId?: string; nameContains?: string; ownerUid?: string; rankingKind: 'largest' | 'recent' | 'least_accessed' }): QuerySpecContract {
  const query: QuerySpecContract = { include_descendants: true }
  if (activeTab === 'folders' && parentEntryId !== undefined) query.directory_entry_id = parentEntryId
  if (activeTab === 'files') {
    query.name_contains = nameContains
    query.owner_uids = ownerUid === undefined ? undefined : [Number(ownerUid)]
    query.metric = 'logical_bytes'
    query.sort = 'size_desc'
  } else if (activeTab === 'folders' || activeTab === 'categories') {
    query.metric = metric
  } else if (activeTab === 'owners' && ownerUid !== undefined) {
    query.owner_uids = [Number(ownerUid)]
  } else if (activeTab === 'rankings') {
    query.sort = rankingKind === 'recent' ? 'mtime_desc' : rankingKind === 'least_accessed' ? 'atime_asc' : 'size_desc'
  }
  return query
}

export function ReportDetailPage() {
  const { id } = useParams<{ id: string }>()
  const reportId = id as string
  const [searchParams, setSearchParams] = useSearchParams()
  const [activeTab, setActiveTab] = useState('summary')
  const [rankingKind, setRankingKind] = useState<'largest' | 'recent' | 'least_accessed'>('largest')
  const [duplicateGroupId, setDuplicateGroupId] = useState<string>()
  const [comparisonId, setComparisonId] = useState<string>()
  const [exportOpen, setExportOpen] = useState(false)
  const [exportId, setExportId] = useState<string>()
  const [exportForm] = Form.useForm<{ section: ExportRequest['section']; format: ExportRecord['format']; scope: 'current' }>()
  const metric = (searchParams.get('metric') as Metric | null) ?? 'logical_bytes'
  const parentEntryId = searchParams.get('parent_entry_id') ?? undefined
  const cursor = searchParams.get('cursor') ?? undefined
  const nameContains = searchParams.get('name_contains') ?? undefined
  const ownerUid = searchParams.get('owner_uid') ?? undefined

  const detail = useQuery({
    queryKey: ['reports', reportId, 'detail'],
    queryFn: async ({ signal }) => (await api.get<ReportDetail>(`/api/v1/reports/${encodeURIComponent(reportId)}`, { signal })).data,
    enabled: id !== undefined,
  })
  const folders = useQuery({
    queryKey: ['reports', reportId, 'folders', { metric, parentEntryId, cursor }],
    enabled: activeTab === 'folders',
    queryFn: ({ signal }) => api.getPage<FolderRow>(`/api/v1/reports/${encodeURIComponent(reportId)}/folders`, { signal, query: { metric, parent_entry_id: parentEntryId, cursor, page_size: 50 } }),
  })
  const owners = useQuery({
    queryKey: ['reports', reportId, 'owners', { ownerUid, cursor }],
    enabled: activeTab === 'owners',
    queryFn: ({ signal }) => api.getPage<OwnerRow>(`/api/v1/reports/${encodeURIComponent(reportId)}/owners`, { signal, query: { uid: ownerUid, cursor, page_size: 50 } }),
  })
  const categories = useQuery({
    queryKey: ['reports', reportId, 'categories', { metric, cursor }],
    enabled: activeTab === 'categories',
    queryFn: ({ signal }) => api.getPage<CategoryRow>(`/api/v1/reports/${encodeURIComponent(reportId)}/categories`, { signal, query: { metric, cursor, page_size: 50 } }),
  })
  const files = useQuery({
    queryKey: ['reports', reportId, 'files', { nameContains, ownerUid, cursor }],
    enabled: activeTab === 'files',
    queryFn: ({ signal }) => api.getPage<FileRow>(`/api/v1/reports/${encodeURIComponent(reportId)}/files`, { signal, query: { directory_entry_id: parentEntryId, include_descendants: false, name_contains: nameContains, owner_uids: ownerUid === undefined ? undefined : [ownerUid], cursor, page_size: 50, metric: 'logical_bytes', sort: 'size_desc' } }),
  })
  const rankings = useQuery({
    queryKey: ['reports', reportId, 'ranking', rankingKind, cursor],
    enabled: activeTab === 'rankings',
    queryFn: ({ signal }) => api.getPage<RankingRow>(`/api/v1/reports/${encodeURIComponent(reportId)}/rankings/${rankingKind}`, { signal, query: { cursor, page_size: 50 } }),
  })
  const duplicates = useQuery({
    queryKey: ['reports', reportId, 'duplicates', cursor],
    enabled: activeTab === 'duplicates',
    queryFn: ({ signal }) => api.getPage<DuplicateGroup>(`/api/v1/reports/${encodeURIComponent(reportId)}/duplicates`, { signal, query: { cursor, page_size: 50 } }),
  })
  const duplicateDetail = useQuery({
    queryKey: ['reports', reportId, 'duplicate', duplicateGroupId],
    enabled: duplicateGroupId !== undefined,
    queryFn: async ({ signal }) => (await api.get<DuplicateGroupDetail>(`/api/v1/reports/${encodeURIComponent(reportId)}/duplicates/${encodeURIComponent(duplicateGroupId as string)}`, { signal })).data,
  })
  const compare = useMutation({
    mutationFn: (otherReportId: string) => api.post<CompareJobResponse>(`/api/v1/reports/${encodeURIComponent(reportId)}/compare`, { other_report_id: otherReportId, mode: 'aggregate' }, { headers: { 'Idempotency-Key': createIdempotencyKey() } }),
    onSuccess: (response) => setComparisonId(response.data.comparison_id),
  })
  const createExport = useMutation({
    mutationFn: (values: { section: ExportRequest['section']; format: ExportRecord['format']; scope: 'current' }) => api.post<ExportJobResponse>(`/api/v1/reports/${encodeURIComponent(reportId)}/exports`, { ...values, query: currentReportQuerySpec({ activeTab, metric, parentEntryId, nameContains, ownerUid, rankingKind }) }, { headers: { 'Idempotency-Key': createIdempotencyKey() } }),
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

  const setQuery = (key: string, value: string | undefined) => {
    const next = new URLSearchParams(searchParams)
    next.delete('cursor')
    if (value) next.set(key, value)
    else next.delete(key)
    setSearchParams(next)
  }
  const nextPage = (nextCursor: string) => {
    const next = new URLSearchParams(searchParams)
    next.set('cursor', nextCursor)
    setSearchParams(next)
  }

  return <div>
    <PageHeader title="报告详情" description={`报告 ID：${id}`} extra={<Space><Button onClick={() => void detail.refetch()}>刷新摘要</Button><Button onClick={() => { exportForm.setFieldsValue({ section: reportExportSection(activeTab, rankingKind), format: 'csv', scope: 'current' }); setExportOpen(true) }}>导出当前栏目</Button><Input.Search placeholder="输入另一报告 ID比较" onSearch={(value) => { if (value) compare.mutate(value) }} loading={compare.isPending} /></Space>} />
    {compare.error ? apiError(compare.error) : null}
    {createExport.error ? apiError(createExport.error) : null}
    {download.error ? apiError(download.error) : null}
    {exportStatus.error ? apiError(exportStatus.error) : null}
    {exportStatus.data ? <Alert type={exportStatus.data.state === 'failed' || exportStatus.data.state === 'expired' ? 'error' : 'info'} showIcon style={{ marginBottom: 16 }} message={`导出 ${exportStatus.data.state}`} description={exportStatus.data.state === 'ready' ? <Button type="link" onClick={() => download.mutate(exportStatus.data.id)} loading={download.isPending}>下载导出文件</Button> : exportStatus.data.job_id ? `导出任务：${exportStatus.data.job_id}` : undefined} /> : null}
    {compare.data ? <Alert type="info" showIcon message={`比较任务已入队：${compare.data.data.job_id}`} description={compare.data.data.comparable === false ? '两份报告不可直接比较，请检查范围指纹与分类规则版本。' : '请在任务中心查看进度。'} style={{ marginBottom: 16 }} /> : null}
    <Tabs activeKey={activeTab} onChange={(key) => { setActiveTab(key); const next = new URLSearchParams(searchParams); next.delete('cursor'); setSearchParams(next) }} items={[
      { key: 'summary', label: '摘要', children: <QueryState query={detail}>{(data) => <Summary data={data} />}</QueryState> },
      { key: 'folders', label: '目录', children: <Folders query={folders} metric={metric} setMetric={(value) => setQuery('metric', value)} parentEntryId={parentEntryId} openFolder={(value) => setQuery('parent_entry_id', value)} nextPage={nextPage} /> },
      { key: 'owners', label: '用户与配额', children: <Owners query={owners} ownerUid={ownerUid} setOwnerUid={(value) => setQuery('owner_uid', value)} nextPage={nextPage} /> },
      { key: 'categories', label: '分类', children: <Categories query={categories} metric={metric} setMetric={(value) => setQuery('metric', value)} nextPage={nextPage} /> },
      { key: 'files', label: '文件明细', children: <Files query={files} nameContains={nameContains} setNameContains={(value) => setQuery('name_contains', value)} ownerUid={ownerUid} setOwnerUid={(value) => setQuery('owner_uid', value)} nextPage={nextPage} /> },
      { key: 'rankings', label: '排行', children: <Rankings query={rankings} kind={rankingKind} setKind={(value) => { setRankingKind(value); const next = new URLSearchParams(searchParams); next.delete('cursor'); setSearchParams(next) }} nextPage={nextPage} /> },
      { key: 'duplicates', label: '重复文件', children: <Duplicates query={duplicates} detail={duplicateDetail} selectedId={duplicateGroupId} select={(value) => setDuplicateGroupId(value)} nextPage={nextPage} /> },
    ]} />
    <Modal title="导出当前栏目" open={exportOpen} onCancel={() => setExportOpen(false)} onOk={() => exportForm.submit()} confirmLoading={createExport.isPending} destroyOnClose>
      <Form form={exportForm} layout="vertical" onFinish={(values) => createExport.mutate(values)}>
        <Form.Item name="section" label="栏目" rules={[{ required: true }]}><Select options={['full_report', 'volume', 'folders', 'owners', 'quota', 'categories', 'duplicates', 'largest', 'recently_modified', 'least_accessed', 'files'].map((value) => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="format" label="格式" rules={[{ required: true }]}><Select options={['csv', 'json', 'html', 'zip'].map((value) => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="scope" label="范围" rules={[{ required: true }]}><Select options={[{ value: 'current', label: '当前筛选' }]} /></Form.Item>
      </Form>
    </Modal>
    {detail.data?.status === 'partial' ? <Alert type="warning" showIcon message="报告部分成功" description="请按栏目完整性查看可用数据；不可用源不等于零文件。" /> : null}
    {comparisonId ? <ComparisonResultPanel comparisonId={comparisonId} onClose={() => setComparisonId(undefined)} /> : null}
  </div>
}

function Summary({ data }: { data: ReportDetail }) {
  return <>
    <Descriptions bordered column={2}>
      <Descriptions.Item label="报告 ID">{data.id}</Descriptions.Item><Descriptions.Item label="运行 ID">{data.run_id}</Descriptions.Item>
      <Descriptions.Item label="任务 ID">{data.profile_id}</Descriptions.Item><Descriptions.Item label="任务版本">{data.profile_version}</Descriptions.Item>
      <Descriptions.Item label="状态"><Tag>{data.status}</Tag></Descriptions.Item><Descriptions.Item label="生成时间">{data.created_at}</Descriptions.Item>
      <Descriptions.Item label="文件数">{data.totals?.file_count}</Descriptions.Item><Descriptions.Item label="逻辑容量">{byteCell(data.totals?.logical_bytes)}</Descriptions.Item>
      <Descriptions.Item label="范围指纹">{data.scope_fingerprint}</Descriptions.Item><Descriptions.Item label="分类规则版本">{data.classification_version}</Descriptions.Item>
    </Descriptions>
    <Card title="栏目完整性" style={{ marginTop: 16 }}><Space wrap>{Object.entries(data.section_quality ?? {}).map(([name, quality]) => <Tag key={name}>{name}: {quality}</Tag>)}</Space></Card>
    <Card title="源身份快照" style={{ marginTop: 16 }}><Table rowKey="source_id" dataSource={data.source_identities} pagination={false} columns={[{ title: '数据源 ID', dataIndex: 'source_id' }, { title: '身份纪元', dataIndex: 'identity_epoch' }, { title: '可用性', dataIndex: 'availability' }]} /></Card>
    <Card title="发布清单" style={{ marginTop: 16 }}><Descriptions column={2}><Descriptions.Item label="Schema 版本">{data.manifest?.schema_version}</Descriptions.Item><Descriptions.Item label="应用版本">{data.manifest?.app_version}</Descriptions.Item></Descriptions><Table rowKey="path" dataSource={data.manifest?.files} pagination={false} columns={[{ title: '文件', dataIndex: 'path' }, { title: '大小', dataIndex: 'size_bytes', render: (value: string) => formatBytes(value) }, { title: 'SHA-256', dataIndex: 'sha256' }]} /></Card>
  </>
}

function Folders({ query, metric, setMetric, parentEntryId, openFolder, nextPage }: { query: ReturnType<typeof useQuery<Page<FolderRow>>>; metric: Metric; setMetric: (value: Metric) => void; parentEntryId?: string; openFolder: (value?: string) => void; nextPage: (cursor: string) => void }) {
  const copyPath = (path: string) => void navigator.clipboard.writeText(path)
  return <><Space style={{ marginBottom: 16 }}><Select value={metric} options={metrics} onChange={setMetric} /><Button disabled={parentEntryId === undefined} onClick={() => openFolder(undefined)}>返回根目录</Button></Space><QueryState query={query}>{(page) => { const summary = page.data.reduce((result, row) => ({ files: result.files + Number(row.file_count ?? 0), dirs: result.dirs + Number(row.subdirectory_count ?? 0), bytes: result.bytes + Number(row.logical_bytes ?? 0) }), { files: 0, dirs: 0, bytes: 0 }); const path = parentEntryId === undefined ? undefined : page.data.find((row) => row.entry_id === parentEntryId)?.display_path; return <><Space style={{ marginBottom: 16 }}><span>当前目录：{path ?? (parentEntryId ?? '根目录')}</span>{path ? <Button onClick={() => copyPath(path)}>复制路径</Button> : null}</Space><Card size="small" style={{ marginBottom: 16 }}><Space>文件数：{summary.files}</Space><Space>子目录数：{summary.dirs}</Space><Space>逻辑容量：{formatBytes(String(summary.bytes))}</Space></Card><Table<FolderRow> rowKey="entry_id" dataSource={page.data} pagination={false} locale={{ emptyText: '该层没有目录数据' }} columns={[{ title: '目录', dataIndex: 'name', render: (name: string, row) => <Button type="link" onClick={() => openFolder(row.entry_id)}>{name}</Button> }, { title: '路径', dataIndex: 'display_path', ellipsis: true, render: (value: string) => <Space>{value}<Button type="link" onClick={() => copyPath(value)}>复制</Button></Space> }, { title: '文件数', dataIndex: 'file_count' }, { title: '容量', dataIndex: 'logical_bytes', render: byteCell }, { title: '质量', dataIndex: 'quality' }]} /><PagePagination meta={page.meta} loading={query.isFetching} onNext={nextPage} /></> }}</QueryState></>
}

function Owners({ query, ownerUid, setOwnerUid, nextPage }: { query: ReturnType<typeof useQuery<Page<OwnerRow>>>; ownerUid?: string; setOwnerUid: (value: string | undefined) => void; nextPage: (cursor: string) => void }) {
  return <><Input.Search allowClear value={ownerUid} placeholder="按 UID 筛选" style={{ width: 260, marginBottom: 16 }} onChange={(event) => setOwnerUid(event.target.value === '' ? undefined : event.target.value)} onSearch={(value) => setOwnerUid(value === '' ? undefined : value)} /><QueryState query={query}>{(page) => <><Table<OwnerRow> rowKey="uid" dataSource={page.data} pagination={false} locale={{ emptyText: '暂无用户统计' }} columns={[{ title: 'UID', dataIndex: 'uid' }, { title: '显示名', dataIndex: 'display_name' }, { title: '身份来源', dataIndex: 'identity_source' }, { title: '文件数', dataIndex: 'file_count' }, { title: '逻辑容量', dataIndex: 'logical_bytes', render: byteCell }, { title: '配额来源', render: (_, row) => row.quota?.origin }, { title: '配额状态', render: (_, row) => row.quota?.limit.state }]} /><PagePagination meta={page.meta} loading={query.isFetching} onNext={nextPage} /></>}</QueryState></>
}

function Categories({ query, metric, setMetric, nextPage }: { query: ReturnType<typeof useQuery<Page<CategoryRow>>>; metric: Metric; setMetric: (value: Metric) => void; nextPage: (cursor: string) => void }) {
  return <><Select value={metric} options={metrics} onChange={setMetric} style={{ marginBottom: 16 }} /><QueryState query={query}>{(page) => <><Table<CategoryRow> rowKey="category_id" dataSource={page.data} pagination={false} locale={{ emptyText: '暂无分类统计' }} columns={[{ title: '分类', dataIndex: 'category_id' }, { title: '文件数', dataIndex: 'file_count' }, { title: '逻辑容量', dataIndex: 'logical_bytes', render: byteCell }, { title: '占比', dataIndex: 'share_of_scope', render: (value: number | null | undefined) => value === null || value === undefined ? undefined : `${(value * 100).toFixed(2)}%` }]} /><PagePagination meta={page.meta} loading={query.isFetching} onNext={nextPage} /></>}</QueryState></>
}

function Files({ query, nameContains, setNameContains, ownerUid, setOwnerUid, nextPage }: { query: ReturnType<typeof useQuery<Page<FileRow>>>; nameContains?: string; setNameContains: (value: string | undefined) => void; ownerUid?: string; setOwnerUid: (value: string | undefined) => void; nextPage: (cursor: string) => void }) {
  return <><Space style={{ marginBottom: 16 }}><Input placeholder="名称包含" value={nameContains} onChange={(event) => setNameContains(event.target.value === '' ? undefined : event.target.value)} /><Input placeholder="UID" value={ownerUid} onChange={(event) => setOwnerUid(event.target.value === '' ? undefined : event.target.value)} /></Space><QueryState query={query}>{(page) => <><Table<FileRow> rowKey="entry_id" dataSource={page.data} pagination={false} locale={{ emptyText: '没有符合筛选条件的文件' }} columns={[{ title: '名称', dataIndex: 'display_name', ellipsis: true }, { title: '路径', dataIndex: 'display_path', ellipsis: true }, { title: 'UID', dataIndex: 'uid' }, { title: '大小', dataIndex: 'size_bytes', render: byteCell }, { title: '分类', dataIndex: 'category_id' }, { title: '修改时间', render: (_, row) => row.mtime?.rfc3339 }, { title: '扫描错误', dataIndex: 'scan_error' }]} /><PagePagination meta={page.meta} loading={query.isFetching} onNext={nextPage} /></>}</QueryState></>
}

function Rankings({ query, kind, setKind, nextPage }: { query: ReturnType<typeof useQuery<Page<RankingRow>>>; kind: 'largest' | 'recent' | 'least_accessed'; setKind: (value: 'largest' | 'recent' | 'least_accessed') => void; nextPage: (cursor: string) => void }) {
  return <><Select value={kind} style={{ marginBottom: 16 }} onChange={setKind} options={[{ value: 'largest', label: '最大文件' }, { value: 'recent', label: '最近修改' }, { value: 'least_accessed', label: '最少访问' }]} /><QueryState query={query}>{(page) => <><Table<RankingRow> rowKey="entry_id" dataSource={page.data} pagination={false} locale={{ emptyText: '暂无排行数据' }} columns={[{ title: '排名', dataIndex: 'rank' }, { title: '名称', dataIndex: 'display_name', ellipsis: true }, { title: '路径', dataIndex: 'display_path', ellipsis: true }, { title: '大小', dataIndex: 'size_bytes', render: byteCell }, { title: '修改时间', render: (_, row) => row.mtime?.rfc3339 }, { title: '访问时间', render: (_, row) => row.atime?.rfc3339 }]} /><PagePagination meta={page.meta} loading={query.isFetching} onNext={nextPage} /></>}</QueryState></>
}

function Duplicates({ query, detail, selectedId, select, nextPage }: { query: ReturnType<typeof useQuery<Page<DuplicateGroup>>>; detail: ReturnType<typeof useQuery<DuplicateGroupDetail>>; selectedId?: string; select: (value: string | undefined) => void; nextPage: (cursor: string) => void }) {
  return <>
    <QueryState query={query}>{(page) => <>
      <Table<DuplicateGroup> rowKey="group_id" dataSource={page.data} pagination={false} locale={{ emptyText: '暂无已确认重复组' }} onRow={(row) => ({ onClick: () => select(row.group_id), style: { cursor: 'pointer' } })} columns={[{ title: '组 ID', dataIndex: 'group_id' }, { title: '成员数', dataIndex: 'member_count' }, { title: '列出数', dataIndex: 'listed_member_count' }, { title: '单文件大小', dataIndex: 'size_bytes', render: byteCell }, { title: '可回收估算', dataIndex: 'reclaimable_bytes', render: byteCell }, { title: '验证', dataIndex: 'verification' }, { title: '完整列出', dataIndex: 'complete', render: (value: boolean) => <Tag>{value ? '是' : '否'}</Tag> }]} />
      <PagePagination meta={page.meta} loading={query.isFetching} onNext={nextPage} />
    </>}</QueryState>
    {selectedId ? <Card title={`重复组 ${selectedId}`} style={{ marginTop: 16 }} extra={<Button onClick={() => select(undefined)}>关闭</Button>}><QueryState query={detail}>{(data) => <><Space wrap style={{ marginBottom: 16 }}><span>哈希：{data.group.hash}</span><span>截断：{data.truncated ? data.truncation_reason : '否'}</span></Space><Table rowKey="entry_id" dataSource={data.members} pagination={false} columns={[{ title: '条目 ID', dataIndex: 'entry_id' }, { title: '路径', dataIndex: 'display_path', ellipsis: true }, { title: '大小', dataIndex: 'size_bytes', render: byteCell }, { title: '硬链接数', dataIndex: 'nlink' }, { title: '受保护', dataIndex: 'protected', render: (value: boolean) => <Tag>{value ? '是' : '否'}</Tag> }, { title: '隔离时间', dataIndex: 'quarantined_since' }]} /></>}</QueryState></Card> : null}
  </>
}
