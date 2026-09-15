import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import type { Dayjs } from 'dayjs'
import { Card, Col, DatePicker, Empty, Row, Select, Space, Statistic, Table, Tag } from 'antd'
import { api } from '../../api/client'
import type { Job, Volume, VolumeSample, VolumeSampleResolution } from '../../api/types'
import { PageHeader } from '../../components/PageHeader'
import { QueryState } from '../../components/QueryState'
import { formatBytes } from '../../lib/format'
import { useECharts } from '../../lib/useECharts'

export interface VolumeSamplesQuery {
  [key: string]: string | number | undefined
  from?: string
  to?: string
  resolution: VolumeSampleResolution
  page_size: number
}

// eslint-disable-next-line react-refresh/only-export-components
export function volumeSamplesQuery(from: string | undefined, to: string | undefined, resolution: VolumeSampleResolution): VolumeSamplesQuery {
  return { from, to, resolution, page_size: 100 }
}

function VolumeTrend({ samples }: { samples: VolumeSample[] }) {
  const option = useMemo(() => {
    const percent = (value: string | null | undefined, total: string | null | undefined) => {
      if (value === null || value === undefined || total === null || total === undefined) return null
      const totalBytes = BigInt(total)
      if (totalBytes === 0n) return null
      return Number((BigInt(value) * 10000n) / totalBytes) / 100
    }
    return { tooltip: { trigger: 'axis' as const }, legend: { data: ['使用率', '可用率'] }, xAxis: { type: 'category' as const, data: samples.map((sample) => sample.sample_time) }, yAxis: { type: 'value' as const, name: '%' }, series: [{ name: '使用率', type: 'line' as const, data: samples.map((sample) => percent(sample.used_bytes, sample.total_bytes)) }, { name: '可用率', type: 'line' as const, data: samples.map((sample) => percent(sample.available_bytes, sample.total_bytes)) }] }
  }, [samples])
  const ref = useECharts<HTMLDivElement>(option)
  return <div ref={ref} style={{ height: 280, width: '100%' }} />
}

export function OverviewPage() {
  const [volumeId, setVolumeId] = useState<string>()
  const [sampleRange, setSampleRange] = useState<[Dayjs | null, Dayjs | null] | null>(null)
  const [resolution, setResolution] = useState<VolumeSampleResolution>('day')
  const volumes = useQuery({ queryKey: ['volumes', 'list'], queryFn: ({ signal }) => api.getPage<Volume>('/api/v1/volumes', { signal, query: { page_size: 50 } }) })
  const jobs = useQuery({ queryKey: ['jobs', 'overview'], queryFn: ({ signal }) => api.getPage<Job>('/api/v1/jobs', { signal, query: { page_size: 10 } }) })
  const sampleQuery = volumeSamplesQuery(sampleRange?.[0]?.toISOString(), sampleRange?.[1]?.toISOString(), resolution)
  const samples = useQuery({ queryKey: ['volumes', volumeId, 'samples', sampleQuery], enabled: volumeId !== undefined, queryFn: ({ signal }) => api.getPage<VolumeSample>(`/api/v1/volumes/${encodeURIComponent(volumeId as string)}/samples`, { signal, query: sampleQuery }) })

  return <div><PageHeader title="总览" description="容量卡片、趋势、最近任务与异常" extra={<Select allowClear placeholder="选择卷查看趋势" style={{ width: 240 }} value={volumeId} onChange={setVolumeId} options={volumes.data?.data.map((volume) => ({ value: volume.id, label: volume.name }))} />} />
    <QueryState query={volumes}>{(page) => page.data.length === 0 ? <Empty description="暂无容量信息，请先登记卷和数据源" /> : <Row gutter={[16, 16]}>{page.data.map((volume) => <Col key={volume.id} xs={24} sm={12} lg={8}><Card title={volume.name} extra={<Tag>{volume.status}</Tag>}><Statistic title="已用 / 总容量" value={volume.last_sample?.used_bytes === undefined || volume.last_sample.used_bytes === null ? undefined : formatBytes(volume.last_sample.used_bytes)} suffix={volume.last_sample?.total_bytes === undefined || volume.last_sample.total_bytes === null ? undefined : `/ ${formatBytes(volume.last_sample.total_bytes)}`} /><div style={{ marginTop: 8 }}>可用容量：{volume.last_sample?.available_bytes == null ? '未知' : formatBytes(volume.last_sample.available_bytes)}</div><div>最近采样：{volume.last_sample?.sample_time}</div><div>采样质量：{volume.last_sample?.quality}</div></Card></Col>)}</Row>}</QueryState>
    {volumeId ? <Card title="容量趋势" style={{ marginTop: 16 }} extra={<Space wrap><DatePicker.RangePicker showTime value={sampleRange} onChange={setSampleRange} /><Select aria-label="采样分辨率" value={resolution} onChange={setResolution} options={[{ value: 'raw', label: '原始采样' }, { value: 'day', label: '按日汇总' }]} /></Space>}><QueryState query={samples}>{(page) => page.data.length === 0 ? <Empty description="所选时间范围暂无采样" /> : <VolumeTrend samples={page.data} />}</QueryState></Card> : null}
    <Card title="最近任务" style={{ marginTop: 16 }}><QueryState query={jobs}>{(page) => <Table<Job> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '暂无任务' }} columns={[{ title: '类型', dataIndex: 'type' }, { title: '状态', dataIndex: 'state' }, { title: '阶段', dataIndex: 'phase' }, { title: '请求时间', dataIndex: 'requested_at' }]} />}</QueryState></Card>
  </div>
}
