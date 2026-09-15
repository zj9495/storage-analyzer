import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Drawer, Progress, Select, Space, Table, Tag, Timeline } from 'antd'
import { useSearchParams } from 'react-router-dom'
import { api, LIVE_JOB_EVENT_TYPES, parseLiveJobEvent } from '../../api/client'
import type { Job, LiveJobEvent } from '../../api/types'
import { PageHeader } from '../../components/PageHeader'
import { MutationError } from '../../components/MutationError'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'
import { formatBytes } from '../../lib/format'

const stateLabels: Record<Job['state'], string> = { QUEUED: '排队中', RUNNING: '运行中', PAUSING: '暂停中', PAUSED: '已暂停', CANCELLING: '取消中', CANCELLED: '已取消', SUCCEEDED: '成功', PARTIAL: '部分成功', FAILED: '失败', INTERRUPTED: '已中断' }
const controlActions: Partial<Record<Job['state'], Array<'pause' | 'resume' | 'cancel' | 'retry'>>> = { QUEUED: ['cancel'], RUNNING: ['pause', 'cancel'], PAUSING: ['cancel'], PAUSED: ['resume', 'cancel'], FAILED: ['retry'], INTERRUPTED: ['retry'] }
const nonScanControlActions: Partial<Record<Job['state'], Array<'pause' | 'resume' | 'cancel' | 'retry'>>> = { QUEUED: ['cancel'], RUNNING: ['cancel'], PAUSING: ['cancel'], PAUSED: ['cancel'], FAILED: ['retry'], INTERRUPTED: ['retry'] }
const actionLabels = { pause: '暂停', resume: '继续', cancel: '取消', retry: '重试' } as const

function actionsForJob(job: Job) {
  return (job.type === 'scan' ? controlActions : nonScanControlActions)[job.state]
}

function progressText(job: Job): string {
  const progress = job.progress
  if (!progress) return '暂无进度数据'
  const parts: string[] = []
  if (progress.directories_visited !== undefined) parts.push(`目录 ${progress.directories_visited}`)
  if (progress.files_visited !== undefined) parts.push(`文件 ${progress.files_visited}`)
  if (progress.bytes_read !== undefined) parts.push(`读取 ${formatBytes(progress.bytes_read)}`)
  if (progress.errors !== undefined) parts.push(`错误 ${progress.errors}`)
  return parts.join(' · ')
}

function JobEvents({ jobId }: { jobId: string }) {
  const [events, setEvents] = useState<LiveJobEvent[]>([])
  const [streamError, setStreamError] = useState<string>()
  useEffect(() => {
    setEvents([])
    setStreamError(undefined)
    const source = new EventSource(`/api/v1/jobs/${encodeURIComponent(jobId)}/events`, { withCredentials: true })
    const handleEvent = (event: Event) => {
      try {
        const parsed = parseLiveJobEvent(jobId, event as MessageEvent<string>)
        setEvents((current) => [...current, parsed])
        setStreamError(undefined)
        if (parsed.type === 'job.finished' || parsed.type === 'job.completed') {
          source.close()
        }
      } catch {
        setStreamError('任务事件格式无法解析')
      }
    }
    for (const eventType of LIVE_JOB_EVENT_TYPES) {
      source.addEventListener(eventType, handleEvent)
    }
    source.onerror = () => setStreamError('任务事件流暂时不可用，持久任务状态仍以任务详情为准。')
    return () => {
      for (const eventType of LIVE_JOB_EVENT_TYPES) {
        source.removeEventListener(eventType, handleEvent)
      }
      source.close()
    }
  }, [jobId])
  return <>{streamError ? <Alert type="warning" message={streamError} style={{ marginBottom: 16 }} /> : null}<Timeline items={events.map((event) => ({ key: event.sequence, label: `序号 ${event.sequence}`, children: `${event.type} · ${JSON.stringify(event.payload)}` }))} /></>
}

export function JobsPage() {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedJobId, setSelectedJobId] = useState<string>()
  const type = searchParams.get('type') ?? undefined
  const state = searchParams.get('state') as Job['state'] | null
  const cursor = searchParams.get('cursor') ?? undefined
  const jobs = useQuery({
    queryKey: ['jobs', 'list', { type, state, cursor }],
    queryFn: ({ signal }) => api.getPage<Job>('/api/v1/jobs', { signal, query: { type, state: state ?? undefined, cursor, page_size: 50 } }),
    refetchInterval: (query) => query.state.data?.data.some((job) => job.state === 'RUNNING' || job.state === 'QUEUED') ? 5_000 : false,
  })
  const selectedJob = useQuery({
    queryKey: ['jobs', selectedJobId],
    enabled: selectedJobId !== undefined,
    queryFn: async ({ signal }) => (await api.get<Job>(`/api/v1/jobs/${encodeURIComponent(selectedJobId as string)}`, { signal })).data,
    refetchInterval: (query) => query.state.data?.state === 'RUNNING' || query.state.data?.state === 'QUEUED' ? 5_000 : false,
  })
  const control = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'pause' | 'resume' | 'cancel' | 'retry' }) => api.post<Job>(`/api/v1/jobs/${encodeURIComponent(id)}/control`, { action }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['jobs'] }); void selectedJob.refetch() },
  })
  const setFilter = (key: string, value: string | undefined) => { const next = new URLSearchParams(searchParams); next.delete('cursor'); if (value) next.set(key, value); else next.delete(key); setSearchParams(next) }

  return <div>
    <PageHeader title="任务中心" description="队列、阶段、吞吐、错误与控制" extra={<Space wrap><Select allowClear placeholder="任务类型" value={type} onChange={(value: string | undefined) => setFilter('type', value)} options={['scan', 'compare', 'export', 'cleanup', 'backup'].map((value) => ({ value, label: value }))} /><Select allowClear placeholder="状态" value={state ?? undefined} onChange={(value: Job['state'] | undefined) => setFilter('state', value)} options={Object.entries(stateLabels).map(([value, label]) => ({ value, label }))} /><Button onClick={() => void jobs.refetch()} loading={jobs.isFetching}>刷新</Button></Space>} />
    <MutationError error={control.error} />
    <QueryState query={jobs}>{(page) => <><Table<Job> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '当前没有任务' }} columns={[{ title: '任务 ID', dataIndex: 'id', ellipsis: true }, { title: '类型', dataIndex: 'type' }, { title: '状态', dataIndex: 'state', render: (value: Job['state']) => <Tag>{stateLabels[value]}</Tag> }, { title: '阶段', dataIndex: 'phase' }, { title: '进度', render: (_, job) => progressText(job) }, { title: '错误', render: (_, job) => job.error?.message }, { title: '操作', render: (_, job) => <Space wrap><Button size="small" onClick={() => setSelectedJobId(job.id)}>详情</Button>{actionsForJob(job)?.map((action) => <Button key={action} size="small" loading={control.isPending && control.variables?.id === job.id && control.variables.action === action} onClick={() => control.mutate({ id: job.id, action })}>{actionLabels[action]}</Button>)}</Space> }]} /><PagePagination meta={page.meta} loading={jobs.isFetching} onNext={(nextCursor) => { const next = new URLSearchParams(searchParams); next.set('cursor', nextCursor); setSearchParams(next) }} /></>}</QueryState>
    <Drawer title="任务详情" open={selectedJobId !== undefined} onClose={() => setSelectedJobId(undefined)} width={620}><MutationError error={selectedJob.error} /><QueryState query={selectedJob}>{(job) => <><Descriptions bordered column={1}><Descriptions.Item label="任务 ID">{job.id}</Descriptions.Item><Descriptions.Item label="类型">{job.type}</Descriptions.Item><Descriptions.Item label="状态"><Tag>{stateLabels[job.state]}</Tag></Descriptions.Item><Descriptions.Item label="阶段">{job.phase}</Descriptions.Item><Descriptions.Item label="进度">{progressText(job)}</Descriptions.Item><Descriptions.Item label="请求时间">{job.requested_at}</Descriptions.Item><Descriptions.Item label="完成时间">{job.finished_at}</Descriptions.Item></Descriptions><Progress percent={job.state === 'SUCCEEDED' || job.state === 'PARTIAL' ? 100 : undefined} status={job.state === 'FAILED' ? 'exception' : job.state === 'SUCCEEDED' ? 'success' : 'active'} showInfo={false} style={{ marginTop: 16 }} /><CardEvents jobId={job.id} /></>}</QueryState></Drawer>
  </div>
}

function CardEvents({ jobId }: { jobId: string }) { return <section style={{ marginTop: 24 }}><h3>实时事件</h3><JobEvents jobId={jobId} /></section> }
